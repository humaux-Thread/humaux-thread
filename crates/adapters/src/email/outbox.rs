//! `adapters::email::outbox` — DB-backed queue + worker for `ops.email_outbox`
//!   (`migrations/0038_email_deliverability.sql`).
//! Depends-on: crates=[serde_json, sqlx]; services=[PostgreSQL(any) w=[ops.email_delivery_events, ops.email_outbox, ops.email_suppressions]]; env=[CARGO_MANIFEST_DIR]; modules=[adapters::email, adapters::postgres]
//! Called-by: [adapters::login_repo, tests]
//! Invariants: [enqueue_in_txn is the one INSERT INTO ops.email_outbox and never calls send, so a request handler
//!   never blocks on SMTP; a replayed idempotency_key inserts nothing; run_once claims QUEUED rows only, highest
//!   priority first, under the SendPolicy cap and allowlist, and durably marks a row SUBMISSION_UNKNOWN before the
//!   provider is called, so no crash or lost acknowledgement can make the same message go out twice]
//! Spec: Baseline §74.6
//!
//! Entry points:
//!
//! - [`enqueue_in_txn`] / [`enqueue`]: the request path (gateway handler, e.g. "send verification
//!   code"; M22 enqueues inside its own transaction). A suppression check plus one `INSERT`; it
//!   never holds a `dyn EmailProvider` and never calls `send`, which is what makes §74.6's "验证码
//!   HTTP handler 不直接阻塞 SMTP" true by construction rather than by convention.
//! - [`run_once`]: the background worker. Per row it claims (`SELECT ... FOR UPDATE SKIP LOCKED`,
//!   `ORDER BY priority, created_at`), writes the in-flight marker, commits, calls the injected
//!   `&dyn EmailProvider` with no lock held, then settles the outcome as an
//!   `ops.email_outbox.state` transition plus an `ops.email_delivery_events` row.

use sqlx::Row;
use sqlx::types::Uuid;

use crate::postgres::{PrivateWorkerDbPool, RuntimeDbPool};

use super::{
    DeliveryEventType, EmailError, EmailOutboxState, EmailPriority, EmailProvider, EmailStream,
    OutboundEmail, RecipientAllowlist, SendPolicy, SuppressionReason, SuppressionScope,
};

/// `last_error` of a row the allowlist turned away (M02 D10: `SUPPRESSED`, an operator-policy
/// reason rather than a provider signal).
pub const ALLOWLIST_SUPPRESSION_REASON: &str = "RECIPIENT_NOT_ALLOWLISTED";

/// `last_error` while a row sits in `SUBMISSION_UNKNOWN` because its send is in flight.
const IN_FLIGHT_MARKER: &str = "SUBMISSION_IN_FLIGHT";

/// DB-layer failure from any function in this module. Not one of the workspace's two frozen
/// domain error enums (§52) — same "adapter-local, not domain" reasoning as
/// [`super::EmailError`] and this crate's own `postgres::PoolInitError`.
#[derive(Debug)]
pub enum OutboxError {
    Db(sqlx::Error),
}

impl From<sqlx::Error> for OutboxError {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

impl std::fmt::Display for OutboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Db(e) => write!(f, "email outbox DB error: {e}"),
        }
    }
}

impl std::error::Error for OutboxError {}

/// Result of [`enqueue`]. §74.6 Suppression: "对已 suppression 邮箱需返回统一安全语义,
/// 不泄露账户存在状态" — the caller (a signup/reset handler) MUST treat every variant
/// identically in its HTTP response; this enum exists only so the caller's own logging/
/// metrics can tell them apart internally, never so it can vary the response shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueOutcome {
    /// Row inserted, `state = 'QUEUED'`.
    Queued,
    /// Not sent — `to` matched an `ops.email_suppressions` row whose `scope` blocks `stream`
    /// (§74.6: suppressed addresses "不入队", no row), or the recipient allowlist refused it
    /// (a `SUPPRESSED` row is kept for the owner to inspect).
    Suppressed,
    /// Nothing inserted — a row with the same `idempotency_key` already exists.
    Duplicate,
}

/// One email to enqueue. Deliberately narrower than [`OutboundEmail`] (which also carries
/// `from`/`body_*`, the SMTP-transport-facing shape) — the outbox row only needs
/// addressing/template identity; the actual rendered subject/body a provider sends is
/// [`OutboundEmail`], reconstructed by the worker from `template_id`/`payload` at send time
/// (out of this task's scope — the worker below takes a pre-rendered [`OutboundEmail`]
/// builder closure so template rendering stays the caller's concern, not this module's).
#[derive(Debug, Clone)]
pub struct EnqueueRequest {
    pub user_id: Uuid,
    pub to_email: String,
    pub from_email: String,
    pub stream: EmailStream,
    pub template_id: String,
    pub subject: String,
    pub payload: serde_json::Value,
    /// Drain order under load (storm guard, M22 D11).
    pub priority: EmailPriority,
    /// Replay protection: at most one row per key. `None` opts out.
    pub idempotency_key: Option<String>,
}

/// §74.6 Suppression check: does any `ops.email_suppressions` row for `email` (not expired)
/// have a `scope` that [`SuppressionScope::blocks`] `stream`? One `SELECT`, no write —
/// shared by [`enqueue_in_txn`] (pre-insert gate) and available to callers that want to surface
/// suppression state elsewhere (e.g. an admin view) without duplicating the query.
pub async fn is_suppressed(
    pool: &RuntimeDbPool,
    email: &str,
    stream: EmailStream,
) -> Result<bool, OutboxError> {
    // dep: PostgreSQL(any) — acquires a pooled connection
    let mut conn = pool.pool().acquire().await?;
    suppressed_on(&mut conn, email, stream).await
}

async fn suppressed_on(
    conn: &mut sqlx::PgConnection,
    email: &str,
    stream: EmailStream,
) -> Result<bool, OutboxError> {
    let rows = sqlx::query(
        "SELECT scope FROM ops.email_suppressions \
         WHERE email = $1 AND (expires_at IS NULL OR expires_at > now())",
    )
    .bind(email)
    // dep: PostgreSQL(any) — executes a query against the connection
    .fetch_all(&mut *conn)
    .await?;

    for row in rows {
        let scope_str: String = row.try_get("scope")?;
        let scope = parse_suppression_scope(&scope_str);
        if scope.is_some_and(|s| s.blocks(stream)) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// §74.6: "发信走 email_outbox, 验证码 HTTP handler 不直接阻塞 SMTP". The one `INSERT INTO
/// ops.email_outbox` in the workspace: checks suppression (one `SELECT`), then writes one row
/// inside the caller's transaction, so a producer's own state change and its mail commit or
/// roll back together. Never takes an `EmailProvider` argument: there is structurally nothing
/// here that can reach the network.
///
/// A recipient the `allowlist` refuses is stored `SUPPRESSED` (reason
/// [`ALLOWLIST_SUPPRESSION_REASON`]) and is never claimed. A repeated `idempotency_key` inserts
/// nothing (`ON CONFLICT DO NOTHING` — role_gateway holds INSERT only, no SELECT, 0201).
pub async fn enqueue_in_txn(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    req: &EnqueueRequest,
    allowlist: &RecipientAllowlist,
) -> Result<EnqueueOutcome, OutboxError> {
    if suppressed_on(txn, &req.to_email, req.stream).await? {
        return Ok(EnqueueOutcome::Suppressed);
    }
    let allowed = allowlist.permits(&req.to_email);
    let (state, last_error) = if allowed {
        (EmailOutboxState::Queued, None)
    } else {
        (
            EmailOutboxState::Suppressed,
            Some(ALLOWLIST_SUPPRESSION_REASON),
        )
    };

    let inserted = sqlx::query(
        "INSERT INTO ops.email_outbox \
         (user_id, to_email, from_email, stream, template_id, subject, payload, state, last_error, \
          priority, idempotency_key) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
         ON CONFLICT DO NOTHING",
    )
    .bind(req.user_id)
    .bind(&req.to_email)
    .bind(&req.from_email)
    .bind(req.stream.as_db_str())
    .bind(&req.template_id)
    .bind(&req.subject)
    .bind(&req.payload)
    .bind(state.as_db_str())
    .bind(last_error)
    .bind(req.priority.as_rank())
    .bind(req.idempotency_key.as_deref())
    // dep: PostgreSQL(any) — executes a query inside the caller's transaction
    .execute(&mut **txn)
    .await?
    .rows_affected();

    Ok(if inserted == 0 {
        EnqueueOutcome::Duplicate
    } else if allowed {
        EnqueueOutcome::Queued
    } else {
        EnqueueOutcome::Suppressed
    })
}

/// [`enqueue_in_txn`] in its own transaction, for a caller with no transaction of its own.
pub async fn enqueue(
    pool: &RuntimeDbPool,
    req: &EnqueueRequest,
    allowlist: &RecipientAllowlist,
) -> Result<EnqueueOutcome, OutboxError> {
    // dep: PostgreSQL(any) — opens a PostgreSQL transaction
    let mut txn = pool.pool().begin().await?;
    let outcome = enqueue_in_txn(&mut txn, req, allowlist).await?;
    txn.commit().await?;
    Ok(outcome)
}

/// Drains up to `limit` rows, highest priority first (`ORDER BY priority, created_at`, so a
/// login code never waits behind a digest backlog), and returns how many rows it handled.
///
/// Per row, in this order: (1) claim with `FOR UPDATE SKIP LOCKED`; (2) a recipient the
/// `policy.allowlist` refuses is settled `SUPPRESSED` and never sent; (3) otherwise the row is
/// durably moved to `SUBMISSION_UNKNOWN` and committed **before** `provider.send` is called;
/// (4) the outcome settles it — `SENT`, `FAILED` (a definite refusal, nothing left the box), or
/// stays `SUBMISSION_UNKNOWN` when the provider reports [`EmailError::SubmissionUnknown`]. A crash
/// between (3) and (4) therefore leaves `SUBMISSION_UNKNOWN`, never `QUEUED`, and only `QUEUED`
/// rows are ever claimed: the door never resends an unknown outcome (M02 D10, M22 D7). Resending
/// one is an explicit operator or M22 decision, not this loop's.
///
/// `policy.max_sends_per_minute` bounds the sends begun in any rolling minute across all
/// workers' rows (storm guard, M22 D11); rows that do not fit stay `QUEUED` for the next call.
///
/// `claim_user_id`: `None` in production — a real worker drains every tenant's rows,
/// queue-wide, which is the correct behavior. `Some(user_id)` narrows the claim to just that
/// user's rows, for tests sharing a dev DB with concurrent siblings (see
/// `tests/email_outbox.rs`'s module doc: without this, a queue-wide claim can sweep up and
/// drive to a terminal state rows this test never enqueued).
///
/// ponytail: the cap is read once per call, so two concurrent workers can overshoot it by one
/// batch; the deployment runs one worker. Upgrade path: take a transaction-level advisory lock
/// around the count and the in-flight marker.
pub async fn run_once(
    pool: &PrivateWorkerDbPool,
    provider: &dyn EmailProvider,
    policy: &SendPolicy,
    limit: i64,
    claim_user_id: Option<Uuid>,
) -> Result<usize, OutboxError> {
    let mut budget = limit.max(0);
    if let Some(cap) = policy.max_sends_per_minute {
        let recent: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM ops.email_outbox WHERE sent_at > now() - interval '1 minute'",
        )
        // dep: PostgreSQL(any) — executes a query against the pool
        .fetch_one(pool.pool())
        .await?;
        budget = budget.min((i64::from(cap) - recent).max(0));
    }

    let mut processed = 0usize;
    while budget > 0 {
        match drain_one(pool, provider, policy, claim_user_id).await? {
            Drained::Empty => break,
            Drained::Suppressed => {}
            Drained::Submitted => budget -= 1,
        }
        processed += 1;
    }
    Ok(processed)
}

/// What one [`drain_one`] call did to the head of the queue.
enum Drained {
    Empty,
    Suppressed,
    Submitted,
}

async fn drain_one(
    pool: &PrivateWorkerDbPool,
    provider: &dyn EmailProvider,
    policy: &SendPolicy,
    claim_user_id: Option<Uuid>,
) -> Result<Drained, OutboxError> {
    let provider_name = provider.name();
    // dep: PostgreSQL(any) — opens a PostgreSQL transaction
    let mut txn = pool.pool().begin().await?;
    let Some(row) = sqlx::query(
        "SELECT outbox_id, to_email, from_email, subject, stream \
         FROM ops.email_outbox \
         WHERE state = 'QUEUED' AND ($1::uuid IS NULL OR user_id = $1) \
         ORDER BY priority, created_at \
         FOR UPDATE SKIP LOCKED \
         LIMIT 1",
    )
    .bind(claim_user_id)
    .fetch_optional(&mut *txn)
    .await?
    else {
        txn.commit().await?;
        return Ok(Drained::Empty);
    };
    let outbox_id: Uuid = row.try_get("outbox_id")?;
    let to_email: String = row.try_get("to_email")?;
    let from_email: String = row.try_get("from_email")?;
    let subject: String = row.try_get("subject")?;
    let stream_str: String = row.try_get("stream")?;

    if !policy.allowlist.permits(&to_email) {
        settle(
            &mut txn,
            outbox_id,
            Settlement {
                state: EmailOutboxState::Suppressed,
                provider: provider_name,
                provider_message_id: None,
                last_error: Some(ALLOWLIST_SUPPRESSION_REASON.to_string()),
                event: DeliveryEventType::Suppressed,
            },
        )
        .await?;
        txn.commit().await?;
        return Ok(Drained::Suppressed);
    }

    sqlx::query(
        "UPDATE ops.email_outbox \
         SET state = 'SUBMISSION_UNKNOWN', provider = $2, attempt = attempt + 1, \
             last_error = $3, sent_at = now() \
         WHERE outbox_id = $1",
    )
    .bind(outbox_id)
    .bind(provider_name)
    .bind(IN_FLIGHT_MARKER)
    .execute(&mut *txn)
    .await?;
    txn.commit().await?;

    let message_id = message_id_for(outbox_id, &from_email);
    let mail = OutboundEmail {
        to: to_email,
        from: from_email,
        subject,
        // Template rendering is out of M02-4's scope (see EnqueueRequest's doc) — the body is a
        // placeholder until a rendering step is wired in.
        body_text: String::new(),
        body_html: None,
        stream: parse_stream(&stream_str),
        message_id,
    };
    let result = provider.send(mail).await;

    // dep: PostgreSQL(any) — opens a PostgreSQL transaction
    let mut txn = pool.pool().begin().await?;
    let settlement = match result {
        Ok(msg_id) => Settlement {
            state: EmailOutboxState::Sent,
            provider: provider_name,
            provider_message_id: Some(msg_id.0),
            last_error: None,
            event: DeliveryEventType::Sent,
        },
        Err(EmailError::SubmissionUnknown(m)) => Settlement {
            state: EmailOutboxState::SubmissionUnknown,
            provider: provider_name,
            provider_message_id: None,
            last_error: Some(m),
            event: DeliveryEventType::SubmissionUnknown,
        },
        Err(e) => Settlement {
            state: EmailOutboxState::Failed,
            provider: provider_name,
            provider_message_id: None,
            // sent_at stays: a refused attempt still counts against the per-minute cap (M22 D11).
            last_error: Some(e.to_string()),
            event: DeliveryEventType::Failed,
        },
    };
    settle(&mut txn, outbox_id, settlement).await?;
    txn.commit().await?;
    Ok(Drained::Submitted)
}

/// M02 D10: `<outbox_id@sender-domain>`, stable across resends of the same row.
fn message_id_for(outbox_id: Uuid, from_email: &str) -> String {
    let domain = from_email
        .rsplit_once('@')
        .map(|(_, d)| d.trim_end_matches('>'))
        .filter(|d| !d.is_empty())
        .unwrap_or("message-id.invalid");
    format!("<{outbox_id}@{domain}>")
}

/// Final state of one row plus the delivery event that records it.
struct Settlement<'a> {
    state: EmailOutboxState,
    provider: &'a str,
    provider_message_id: Option<String>,
    last_error: Option<String>,
    event: DeliveryEventType,
}

async fn settle(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    outbox_id: Uuid,
    s: Settlement<'_>,
) -> Result<(), OutboxError> {
    let last_error = s.last_error.as_deref();
    sqlx::query(
        "UPDATE ops.email_outbox \
         SET state = $2, provider = $3, provider_message_id = $4, last_error = $5 \
         WHERE outbox_id = $1",
    )
    .bind(outbox_id)
    .bind(s.state.as_db_str())
    .bind(s.provider)
    .bind(s.provider_message_id.as_deref())
    .bind(last_error)
    .execute(&mut **txn)
    .await?;
    record_event(
        txn,
        outbox_id,
        s.event,
        Some(s.provider),
        last_error
            .or(s.provider_message_id.as_deref())
            .unwrap_or(""),
    )
    .await
}

async fn record_event(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    outbox_id: Uuid,
    event_type: DeliveryEventType,
    provider: Option<&str>,
    detail_message: &str,
) -> Result<(), OutboxError> {
    let detail = serde_json::json!({ "message": detail_message });
    sqlx::query(
        "INSERT INTO ops.email_delivery_events (outbox_id, event_type, provider, detail) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(outbox_id)
    .bind(event_type.as_db_str())
    .bind(provider)
    .bind(detail)
    .execute(&mut **txn)
    .await?;
    Ok(())
}

/// Records a new suppression (e.g. from a provider bounce/complaint webhook, or a manual
/// operator action) — `ON CONFLICT (email, scope) DO UPDATE` so a repeated signal (a second
/// bounce for the same address/scope) refreshes `created_at`/`provider` instead of erroring.
pub async fn record_suppression(
    pool: &PrivateWorkerDbPool,
    email: &str,
    reason: SuppressionReason,
    scope: SuppressionScope,
    provider: Option<&str>,
    expires_at: Option<sqlx::types::time::OffsetDateTime>,
) -> Result<(), OutboxError> {
    sqlx::query(
        "INSERT INTO ops.email_suppressions (email, reason, scope, provider, expires_at) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (email, scope) DO UPDATE \
         SET reason = EXCLUDED.reason, provider = EXCLUDED.provider, \
             created_at = now(), expires_at = EXCLUDED.expires_at",
    )
    .bind(email)
    .bind(reason.as_db_str())
    .bind(scope.as_db_str())
    .bind(provider)
    .bind(expires_at)
    // dep: PostgreSQL(any) — executes a query against the pool
    .execute(pool.pool())
    .await?;
    Ok(())
}

fn parse_stream(s: &str) -> EmailStream {
    EmailStream::ALL
        .into_iter()
        .find(|v| v.as_db_str() == s)
        .unwrap_or(EmailStream::Transactional)
}

fn parse_suppression_scope(s: &str) -> Option<SuppressionScope> {
    SuppressionScope::ALL_VARIANTS
        .into_iter()
        .find(|v| v.as_db_str() == s)
}

/// §78.2 "DB enum 与 Rust enum 走 contract test 对账": every `CHECK (... IN (...))` list in
/// `migrations/0038_email_deliverability.sql` must contain exactly this module's Rust enum's
/// wire values, both directions. Runs against the real spec/migration file text — not a
/// live-DB fixture — so it always executes (no `HUMAUX_TEST_PG_DSN` skip needed) and fails
/// loud on any future edit to either side that drifts the other out of sync.
#[cfg(test)]
mod contract_tests {
    use super::*;

    const MIGRATION_SQL: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../migrations/0038_email_deliverability.sql"
    ));

    /// 0263 re-creates the `state` / `event_type` CHECKs and adds `priority`; a column it names
    /// takes its list from there, every other column from 0038.
    const DOOR_MIGRATION_SQL: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../migrations/0263_email_door.sql"
    ));

    /// Extracts the comma-separated quoted literal list out of the first
    /// `CHECK (<column> IN (...))` clause for `column` in the migration text.
    fn check_values(column: &str) -> Vec<String> {
        let needle = format!("CHECK ({column} IN (");
        let sql = if DOOR_MIGRATION_SQL.contains(&needle) {
            DOOR_MIGRATION_SQL
        } else {
            MIGRATION_SQL
        };
        let start = sql
            .find(&needle)
            .unwrap_or_else(|| panic!("migration SQL has no `CHECK ({column} IN (...))` clause"))
            + needle.len();
        let end = sql[start..]
            .find(')')
            .expect("unterminated CHECK IN (...) clause")
            + start;
        sql[start..end]
            .split(',')
            .map(|s| s.trim().trim_matches('\'').to_string())
            .collect()
    }

    #[test]
    fn outbox_state_matches_check_constraint() {
        let db: Vec<String> = check_values("state");
        let rust: Vec<String> = super::super::EmailOutboxState::ALL
            .iter()
            .map(|s| s.as_db_str().to_string())
            .collect();
        assert_eq!(
            db, rust,
            "EmailOutboxState::ALL must list every state in DB order"
        );
    }

    #[test]
    fn priority_matches_check_constraint() {
        let db: Vec<String> = check_values("priority");
        let rust: Vec<String> = EmailPriority::ALL
            .iter()
            .map(|p| p.as_rank().to_string())
            .collect();
        assert_eq!(
            db, rust,
            "EmailPriority::ALL ranks must equal the priority CHECK list in drain order"
        );
    }

    #[test]
    fn stream_matches_check_constraint() {
        let db: Vec<String> = check_values("stream");
        let rust: Vec<String> = EmailStream::ALL
            .iter()
            .map(|s| s.as_db_str().to_string())
            .collect();
        assert_eq!(
            db, rust,
            "EmailStream::ALL must list every stream in DB order"
        );
    }

    #[test]
    fn delivery_event_type_matches_check_constraint() {
        let db: Vec<String> = check_values("event_type");
        let rust: Vec<String> = DeliveryEventType::ALL
            .iter()
            .map(|s| s.as_db_str().to_string())
            .collect();
        assert_eq!(
            db, rust,
            "DeliveryEventType::ALL must list every event_type in DB order"
        );
    }

    #[test]
    fn suppression_reason_matches_check_constraint() {
        let db: Vec<String> = check_values("reason");
        let rust: Vec<String> = SuppressionReason::ALL
            .iter()
            .map(|s| s.as_db_str().to_string())
            .collect();
        assert_eq!(
            db, rust,
            "SuppressionReason::ALL must list every reason in DB order"
        );
    }

    #[test]
    fn suppression_scope_matches_check_constraint() {
        let db: Vec<String> = check_values("scope");
        let rust: Vec<String> = SuppressionScope::ALL_VARIANTS
            .iter()
            .map(|s| s.as_db_str().to_string())
            .collect();
        assert_eq!(
            db, rust,
            "SuppressionScope::ALL_VARIANTS must list every scope in DB order"
        );
    }
}

//! `adapters::tests::email_outbox` — H3 (§74.6) integration test — `email::outbox` against a real Postgres,
//!   exercising the three literal task-brief acceptance behaviors: enqueue never blocks on SMTP, a suppressed address
//!   never gets enqueued (same outcome type either way — unified safety semantics), and a provider failure lands the
//!   row in `FAILED` with a matching delivery event.
//! Depends-on: crates=[humaux-adapters, humaux-testkit, postgres, serde_json, sqlx, tokio]; services=[PostgreSQL(any)
//!   w=[control.users, ops.email_delivery_events, ops.email_outbox, ops.email_suppressions],
//!   PostgreSQL(role_gateway), PostgreSQL(role_private_worker)]; env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::email,
//!   adapters::email::outbox, adapters::email::test_double, adapters::postgres, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [runs on 0038's real tables and claims only its own user's rows; a suppressed address is never
//!   enqueued and a provider rejection is recorded as a delivery event; no DSN/DB/migration is a visible SKIP]
//! Spec: Baseline §79.2
//!
//! Runs against `migrations/0038_email_deliverability.sql`'s real tables (not a self-built
//! scratch schema like T1.5's `auth_scope_rls.rs`) — `email::outbox`'s SQL names
//! `ops.email_outbox`/`ops.email_suppressions`/`ops.email_delivery_events` directly, so
//! proving the actual code path requires the actual migration applied. Three-state skip
//! (§79.2): no DSN, unreachable DB, or the migration not yet applied all print a visible SKIP
//! and return rather than fail — `cargo xtask migrate` must have run first for these tests to
//! execute for real.
//!
//! [`run_once`](outbox::run_once) claims by `state = 'QUEUED'` queue-wide in production
//! (`claim_user_id: None` — a real worker drains every tenant's rows, not one caller's). This
//! file passes `Some(handle.user_id)` instead, so a test's claim never touches a real queued
//! row left behind by an unrelated concurrent test binary or wave sharing the same dev DB.
//! `SERIAL_GUARD` below is a second, belt-and-suspenders layer: it still serializes every test
//! in *this* file against each other (two tests calling `run_once` concurrently could
//! otherwise race even within their own scoped claims if they shared a `user_id`, which they
//! don't today, but the fixture makes no promise they never will), rather than depending on
//! callers remembering `--test-threads=1`.

use std::sync::Mutex;

use humaux_adapters::email::test_double::{
    EmailErrorKind, RecordingEmailProvider, ScriptedOutcome,
};
use humaux_adapters::email::{
    EmailMode, EmailPriority, EmailProvider, EmailStream, OutboundEmail, RecipientAllowlist,
    SendPolicy, SinkEmailProvider, SmtpConfig, outbox,
};
use humaux_adapters::postgres::{PrivateWorkerDbPool, RuntimeDbPool};
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use sqlx::types::Uuid;

static SERIAL_GUARD: Mutex<()> = Mutex::new(());

/// `options[role]=...` on the admin DSN performs a post-connect `SET ROLE` (same technique
/// `postgres.rs`'s own `#[cfg(test)]` fixtures use, reproduced here since that helper is
/// private to its defining module) — no separate per-role credentials needed in dev.
fn dsn_as_role(admin_dsn: &str, role: &str) -> String {
    // libpq-standard `options=-c role=X` (URL-encoded). The older `options[role]=X` form
    // is silently tolerated by sqlx but rejected outright by rust-postgres ("invalid
    // connection string") — which made every `Client::connect` role fixture skip, and a
    // skip is not a pass (§79.2). This form is verified working on both drivers.
    let sep = if admin_dsn.contains('?') { '&' } else { '?' };
    format!("{admin_dsn}{sep}options=-c%20role%3D{role}")
}

struct Handle {
    rt: tokio::runtime::Runtime,
    gateway: RuntimeDbPool,
    worker: PrivateWorkerDbPool,
    admin: Client,
    /// Throwaway `control.users` row this fixture owns, FK target for every
    /// `ops.email_outbox.user_id` this test file inserts.
    user_id: Uuid,
}

impl Drop for Handle {
    fn drop(&mut self) {
        // Best-effort: removes this run's throwaway user and everything that FK-references
        // it, so a passing run leaves the shared dev DB as it found it (repo CLAUDE.md hard
        // rule ④ — this file never touches a schema/table of its own, only rows it created).
        let _ = self.admin.batch_execute(&format!(
            "DELETE FROM ops.email_delivery_events \
               WHERE outbox_id IN (SELECT outbox_id FROM ops.email_outbox WHERE user_id = '{0}'); \
             DELETE FROM ops.email_outbox WHERE user_id = '{0}'; \
             DELETE FROM control.users WHERE user_id = '{0}';",
            self.user_id
        ));
    }
}

struct OutboxFixture;

impl DbIntegrationFixture for OutboxFixture {
    type Handle = Handle;

    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        let dsn =
            std::env::var("HUMAUX_TEST_PG_DSN").map_err(|_| DbFixtureSkipReason::NoDatabaseUrl)?;
        // dep: PostgreSQL(any) — opens the role-scoped connection for `isolate`
        let mut admin = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;

        let migrated: bool = admin
            .query_one("SELECT to_regclass('ops.email_outbox') IS NOT NULL", &[])
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?
            .get(0);
        if !migrated {
            return Err(DbFixtureSkipReason::IsolationSetupFailed(
                "ops.email_outbox does not exist — run `cargo xtask migrate` \
                 (migrations/0038_email_deliverability.sql) against HUMAUX_TEST_PG_DSN first"
                    .to_string(),
            ));
        }

        let user_id = Uuid::new_v4();
        admin
            .execute(
                "INSERT INTO control.users (user_id) VALUES ($1)",
                &[&user_id],
            )
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        let (gateway, worker) = rt
            .block_on(async {
                // dep: PostgreSQL(role_gateway) — opens the role-scoped connection for `isolate`
                let gw = RuntimeDbPool::connect(&dsn_as_role(&dsn, "role_gateway")).await?;
                // dep: PostgreSQL(role_private_worker) — opens the role-scoped connection for `isolate`
                let wk =
                    PrivateWorkerDbPool::connect(&dsn_as_role(&dsn, "role_private_worker")).await?;
                Ok::<_, humaux_adapters::postgres::PoolInitError>((gw, wk))
            })
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;

        Ok(Handle {
            rt,
            gateway,
            worker,
            admin,
            user_id,
        })
    }
}

fn unique_email(tag: &str) -> String {
    format!("email-outbox-test-{tag}-{}@example.invalid", Uuid::new_v4())
}

fn req(handle: &Handle, to: &str, stream: EmailStream) -> outbox::EnqueueRequest {
    outbox::EnqueueRequest {
        user_id: handle.user_id,
        to_email: to.to_string(),
        from_email: "no-reply@humaux.example".to_string(),
        stream,
        template_id: "EMAIL_VERIFICATION".to_string(),
        subject: "Verify your email".to_string(),
        payload: serde_json::json!({}),
        priority: EmailPriority::Auth,
        idempotency_key: None,
    }
}

/// §74.6 "验证码 HTTP handler 不直接阻塞 SMTP" / "入队即返回": `enqueue` does one DB round
/// trip and returns `Queued` with a real row — well under any plausible SMTP round-trip
/// latency, and structurally provable too: `enqueue`'s signature takes no `EmailProvider` at
/// all, so there is nothing in this call that *could* reach the network.
#[test]
fn enqueue_returns_immediately_and_writes_queued_row() {
    let _guard = SERIAL_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    run_db_fixture::<OutboxFixture, _>(
        "enqueue_returns_immediately_and_writes_queued_row",
        |mut handle| {
            let to = unique_email("enqueue");
            let started = std::time::Instant::now();
            let outcome = handle
                .rt
                .block_on(outbox::enqueue(
                    &handle.gateway,
                    &req(&handle, &to, EmailStream::Transactional),
                    &RecipientAllowlist::allow_all(),
                ))
                .expect("enqueue must not error for a non-suppressed address");
            let elapsed = started.elapsed();

            assert_eq!(outcome, outbox::EnqueueOutcome::Queued);
            // Generous upper bound — this is not a network call, one local DB round trip should
            // never approach the seconds an SMTP handshake can take.
            assert!(
                elapsed < std::time::Duration::from_secs(2),
                "enqueue took {elapsed:?} — too slow for a DB-only call, suggests it blocked on something else"
            );

            let state: String = handle
                .admin
                .query_one(
                    "SELECT state FROM ops.email_outbox WHERE user_id = $1 AND to_email = $2",
                    &[&handle.user_id, &to],
                )
                .expect("queued row must exist")
                .get(0);
            assert_eq!(state, "QUEUED");
        },
    );
}

/// §74.6 Suppression: "对已 suppression 邮箱需返回统一安全语义, 不泄露账户存在状态" —
/// suppressed and non-suppressed enqueue calls return the *same outcome shape*
/// (`EnqueueOutcome`), the caller is the one that must not branch its HTTP response on it;
/// this test's own obligation is narrower and concrete: the suppressed call must not write a
/// row at all ("不入队").
#[test]
fn suppressed_address_is_not_enqueued() {
    let _guard = SERIAL_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    run_db_fixture::<OutboxFixture, _>("suppressed_address_is_not_enqueued", |mut handle| {
        let to = unique_email("suppressed");
        handle
            .admin
            .execute(
                "INSERT INTO ops.email_suppressions (email, reason, scope) VALUES ($1, 'HARD_BOUNCE', 'ALL')",
                &[&to],
            )
            .expect("seed suppression row");

        let outcome = handle
            .rt
            .block_on(outbox::enqueue(
                &handle.gateway,
                &req(&handle, &to, EmailStream::Transactional),
                &RecipientAllowlist::allow_all(),
            ))
            .expect("enqueue against a suppressed address must not itself error");
        assert_eq!(outcome, outbox::EnqueueOutcome::Suppressed);

        let count: i64 = handle
            .admin
            .query_one(
                "SELECT count(*) FROM ops.email_outbox WHERE to_email = $1",
                &[&to],
            )
            .expect("count query")
            .get(0);
        assert_eq!(
            count, 0,
            "a suppressed address must not produce an ops.email_outbox row"
        );

        handle
            .admin
            .execute(
                "DELETE FROM ops.email_suppressions WHERE email = $1",
                &[&to],
            )
            .expect("cleanup suppression row");
    });
}

/// A marketing-scoped suppression must not block the transactional stream (§74.6 frozen:
/// "不能让营销投诉率打坏验证码/找回密码通道") — the negative case for the same mechanism the
/// previous test proves the positive case for.
#[test]
fn marketing_suppression_does_not_block_transactional_stream() {
    let _guard = SERIAL_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    run_db_fixture::<OutboxFixture, _>(
        "marketing_suppression_does_not_block_transactional_stream",
        |mut handle| {
            let to = unique_email("marketing-only");
            handle
                .admin
                .execute(
                    "INSERT INTO ops.email_suppressions (email, reason, scope) \
                     VALUES ($1, 'UNSUBSCRIBE', 'MARKETING')",
                    &[&to],
                )
                .expect("seed marketing-scoped suppression row");

            let outcome = handle
                .rt
                .block_on(outbox::enqueue(
                    &handle.gateway,
                    &req(&handle, &to, EmailStream::Transactional),
                    &RecipientAllowlist::allow_all(),
                ))
                .expect("enqueue must not error");
            assert_eq!(
                outcome,
                outbox::EnqueueOutcome::Queued,
                "a MARKETING-scoped suppression must not block a TRANSACTIONAL send"
            );

            handle
                .admin
                .execute(
                    "DELETE FROM ops.email_outbox WHERE user_id = $1 AND to_email = $2",
                    &[&handle.user_id, &to],
                )
                .expect("cleanup outbox row");
            handle
                .admin
                .execute(
                    "DELETE FROM ops.email_suppressions WHERE email = $1",
                    &[&to],
                )
                .expect("cleanup suppression row");
        },
    );
}

/// Task brief: "provider 失败转 FAILED+事件记录". Enqueues a real row, then runs the worker
/// against a [`RecordingEmailProvider`] scripted to fail — asserts both the outbox row's
/// terminal state and the recorded delivery event.
#[test]
fn provider_failure_marks_row_failed_and_records_event() {
    let _guard = SERIAL_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    run_db_fixture::<OutboxFixture, _>(
        "provider_failure_marks_row_failed_and_records_event",
        |mut handle| {
            let to = unique_email("provider-fail");
            handle
                .rt
                .block_on(outbox::enqueue(
                    &handle.gateway,
                    &req(&handle, &to, EmailStream::Transactional),
                    &RecipientAllowlist::allow_all(),
                ))
                .expect("seed a QUEUED row to claim");

            let outbox_id: Uuid = handle
                .admin
                .query_one(
                    "SELECT outbox_id FROM ops.email_outbox WHERE to_email = $1",
                    &[&to],
                )
                .expect("seeded row must exist")
                .get(0);

            let provider = RecordingEmailProvider::new();
            provider.push_outcome(ScriptedOutcome::Err(
                EmailErrorKind::Rejected,
                "550 mailbox unavailable".to_string(),
            ));

            let claimed = handle
                .rt
                .block_on(outbox::run_once(
                    &handle.worker,
                    &provider,
                    &SendPolicy::default(),
                    10,
                    Some(handle.user_id),
                ))
                .expect("run_once must not itself error on a provider failure");
            assert_eq!(
                claimed, 1,
                "worker must claim exactly the one row this test seeded, scoped by user_id"
            );

            let (state, provider_col): (String, Option<String>) = handle
                .admin
                .query_one(
                    "SELECT state, provider FROM ops.email_outbox WHERE outbox_id = $1",
                    &[&outbox_id],
                )
                .map(|row| (row.get(0), row.get(1)))
                .expect("row must still exist");
            assert_eq!(state, "FAILED");
            assert_eq!(
                provider_col.as_deref(),
                Some("recording-test-double"),
                "outbox.provider must be filled in with the dispatching adapter's identity"
            );

            let event_count: i64 = handle
            .admin
            .query_one(
                "SELECT count(*) FROM ops.email_delivery_events \
                 WHERE outbox_id = $1 AND event_type = 'FAILED' AND provider = 'recording-test-double'",
                &[&outbox_id],
            )
            .expect("count query")
            .get(0);
            assert_eq!(
                event_count, 1,
                "exactly one FAILED delivery event must be recorded, with provider set"
            );
        },
    );
}

/// Success-path counterpart: a provider that returns `Ok` drives the row to `SENT` with a
/// matching `SENT` delivery event carrying the provider's message id.
#[test]
fn provider_success_marks_row_sent_and_records_event() {
    let _guard = SERIAL_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    run_db_fixture::<OutboxFixture, _>(
        "provider_success_marks_row_sent_and_records_event",
        |mut handle| {
            let to = unique_email("provider-ok");
            handle
                .rt
                .block_on(outbox::enqueue(
                    &handle.gateway,
                    &req(&handle, &to, EmailStream::Transactional),
                    &RecipientAllowlist::allow_all(),
                ))
                .expect("seed a QUEUED row to claim");

            let outbox_id: Uuid = handle
                .admin
                .query_one(
                    "SELECT outbox_id FROM ops.email_outbox WHERE to_email = $1",
                    &[&to],
                )
                .expect("seeded row must exist")
                .get(0);

            let provider = RecordingEmailProvider::new();
            let claimed = handle
                .rt
                .block_on(outbox::run_once(
                    &handle.worker,
                    &provider,
                    &SendPolicy::default(),
                    10,
                    Some(handle.user_id),
                ))
                .expect("run_once must succeed");
            assert_eq!(
                claimed, 1,
                "worker must claim exactly the one row this test seeded, scoped by user_id"
            );

            let (state, provider_message_id, provider_col): (String, Option<String>, Option<String>) = handle
                .admin
                .query_one(
                    "SELECT state, provider_message_id, provider FROM ops.email_outbox WHERE outbox_id = $1",
                    &[&outbox_id],
                )
                .map(|row| (row.get(0), row.get(1), row.get(2)))
                .expect("row must still exist");
            assert_eq!(state, "SENT");
            assert!(provider_message_id.is_some());
            assert_eq!(
                provider_col.as_deref(),
                Some("recording-test-double"),
                "outbox.provider must be filled in with the dispatching adapter's identity"
            );

            let event_count: i64 = handle
            .admin
            .query_one(
                "SELECT count(*) FROM ops.email_delivery_events WHERE outbox_id = $1 AND event_type = 'SENT'",
                &[&outbox_id],
            )
            .expect("count query")
            .get(0);
            assert_eq!(event_count, 1);
        },
    );
}

fn state_of(handle: &mut Handle, to: &str) -> String {
    handle
        .admin
        .query_one(
            "SELECT state FROM ops.email_outbox WHERE user_id = $1 AND to_email = $2",
            &[&handle.user_id, &to],
        )
        .expect("outbox row must exist")
        .get(0)
}

fn drain(
    handle: &Handle,
    provider: &RecordingEmailProvider,
    policy: &SendPolicy,
    limit: i64,
) -> usize {
    handle
        .rt
        .block_on(outbox::run_once(
            &handle.worker,
            provider,
            policy,
            limit,
            Some(handle.user_id),
        ))
        .expect("run_once must not error")
}

fn smtp_settings() -> SmtpConfig {
    SmtpConfig {
        host: "smtp.invalid".to_string(),
        port: 465,
        username: "u".to_string(),
        password: "p".to_string(),
        implicit_tls: true,
    }
}

/// G-M02-15 (M02 D10): a profile that names no mode gets the non-sending sink, even when SMTP
/// settings are present; SMTP needs the explicit name, and a bad name never falls back to sending.
#[test]
fn default_mode_is_sink_and_smtp_needs_explicit_choice() {
    let dir = std::env::temp_dir().join(format!("humaux-sink-{}", Uuid::new_v4()));

    let default_mode = EmailMode::resolve(None, dir.clone(), Some(smtp_settings()))
        .expect("an absent mode resolves");
    assert!(
        matches!(&default_mode, EmailMode::Sink(d) if d == &dir),
        "no explicit mode must select the sink, got {default_mode:?}"
    );
    assert_eq!(
        default_mode.into_provider().expect("sink builds").name(),
        "sink"
    );

    let explicit_sink = EmailMode::resolve(Some("sink"), dir.clone(), None).expect("sink resolves");
    assert!(matches!(explicit_sink, EmailMode::Sink(_)));

    let smtp = EmailMode::resolve(Some("smtp"), dir.clone(), Some(smtp_settings()))
        .expect("smtp with settings resolves");
    assert!(matches!(smtp, EmailMode::Smtp(_)));

    assert!(
        EmailMode::resolve(Some("smtp"), dir.clone(), None).is_err(),
        "smtp without settings must be refused, not downgraded"
    );
    assert!(
        EmailMode::resolve(Some("SMTP "), dir, Some(smtp_settings())).is_err(),
        "an unknown mode name must be refused"
    );
}

/// G-M02-15: the sink writes the message to a file named after its Message-ID and nothing else.
#[test]
fn sink_writes_one_eml_file_per_message_id() {
    let dir = std::env::temp_dir().join(format!("humaux-sink-{}", Uuid::new_v4()));
    let sink = SinkEmailProvider::new(dir.clone());
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let mail = |body: &str| OutboundEmail {
        to: "owner@example.invalid".to_string(),
        from: "no-reply@humaux.example".to_string(),
        subject: "Hello".to_string(),
        body_text: body.to_string(),
        body_html: None,
        stream: EmailStream::Transactional,
        message_id: "<abc@humaux.example>".to_string(),
    };

    let id = rt.block_on(sink.send(mail("first"))).expect("sink send");
    assert_eq!(id.0, "<abc@humaux.example>");
    rt.block_on(sink.send(mail("second"))).expect("sink resend");

    let files: Vec<String> = std::fs::read_dir(&dir)
        .expect("sink dir exists")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(files, vec!["abc_humaux.example.eml".to_string()]);
    let text = std::fs::read_to_string(sink.path_for("<abc@humaux.example>")).expect("eml");
    assert!(text.contains("Message-ID: <abc@humaux.example>\r\n"));
    assert!(text.contains("To: owner@example.invalid\r\n"));
    assert!(
        text.ends_with("second"),
        "a replay overwrites the same file"
    );

    let mut injected = mail("x");
    injected.subject = "a\r\nBcc: victim@example.invalid".to_string();
    assert!(rt.block_on(sink.send(injected)).is_err());

    std::fs::remove_dir_all(&dir).expect("cleanup sink dir");
}

/// Allowlist parsing: unset allows all, a blank value permits nobody, entries match
/// case-insensitively.
#[test]
fn allowlist_parse_semantics() {
    assert!(RecipientAllowlist::parse(None).permits("anyone@example.invalid"));
    assert!(!RecipientAllowlist::parse(Some("")).permits("anyone@example.invalid"));
    let list = RecipientAllowlist::parse(Some(" Owner@Example.invalid , second@example.invalid "));
    assert!(list.permits("owner@example.invalid"));
    assert!(list.permits("SECOND@example.invalid"));
    assert!(!list.permits("third@example.invalid"));
}

/// G-M02-15: with an allowlist set, any other recipient is stored SUPPRESSED at enqueue and is
/// never handed to the provider; a row queued before the list was tightened is stopped at send time.
#[test]
fn non_allowlisted_recipient_is_suppressed_and_never_sent() {
    let _guard = SERIAL_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    run_db_fixture::<OutboxFixture, _>(
        "non_allowlisted_recipient_is_suppressed_and_never_sent",
        |mut handle| {
            let owner = unique_email("owner");
            let stranger = unique_email("stranger");
            let late = unique_email("late");
            let allowlist = RecipientAllowlist::only([owner.as_str()]);

            let enqueue = |h: &Handle, to: &str, al: &RecipientAllowlist| {
                h.rt.block_on(outbox::enqueue(
                    &h.gateway,
                    &req(h, to, EmailStream::Transactional),
                    al,
                ))
                .expect("enqueue")
            };
            assert_eq!(
                enqueue(&handle, &owner, &allowlist),
                outbox::EnqueueOutcome::Queued
            );
            assert_eq!(
                enqueue(&handle, &stranger, &allowlist),
                outbox::EnqueueOutcome::Suppressed
            );
            assert_eq!(state_of(&mut handle, &stranger), "SUPPRESSED");
            // Queued while no list was configured; the worker's own policy must still stop it.
            assert_eq!(
                enqueue(&handle, &late, &RecipientAllowlist::allow_all()),
                outbox::EnqueueOutcome::Queued
            );

            let provider = RecordingEmailProvider::new();
            let policy = SendPolicy {
                allowlist,
                max_sends_per_minute: None,
            };
            assert_eq!(drain(&handle, &provider, &policy, 10), 2);

            let sent: Vec<String> = provider.sent().into_iter().map(|m| m.to).collect();
            assert_eq!(
                sent,
                vec![owner.clone()],
                "only the allowlisted recipient is sent"
            );
            assert_eq!(state_of(&mut handle, &owner), "SENT");
            assert_eq!(state_of(&mut handle, &late), "SUPPRESSED");
            let suppressed_events: i64 = handle
                .admin
                .query_one(
                    "SELECT count(*) FROM ops.email_delivery_events e \
                     JOIN ops.email_outbox o USING (outbox_id) \
                     WHERE o.user_id = $1 AND e.event_type = 'SUPPRESSED'",
                    &[&handle.user_id],
                )
                .expect("count query")
                .get(0);
            assert_eq!(
                suppressed_events, 1,
                "the send-time refusal records one SUPPRESSED event"
            );
        },
    );
}

/// M02 D10: one row per idempotency key; the replay reports Duplicate and inserts nothing.
#[test]
fn idempotency_key_replay_inserts_once() {
    let _guard = SERIAL_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    run_db_fixture::<OutboxFixture, _>("idempotency_key_replay_inserts_once", |mut handle| {
        let to = unique_email("idem");
        let key = format!("test-key-{}", Uuid::new_v4());
        let mut request = req(&handle, &to, EmailStream::Transactional);
        request.idempotency_key = Some(key.clone());

        let enqueue = |h: &Handle| {
            h.rt.block_on(outbox::enqueue(
                &h.gateway,
                &request,
                &RecipientAllowlist::allow_all(),
            ))
            .expect("enqueue")
        };
        assert_eq!(enqueue(&handle), outbox::EnqueueOutcome::Queued);
        assert_eq!(enqueue(&handle), outbox::EnqueueOutcome::Duplicate);

        let rows: i64 = handle
            .admin
            .query_one(
                "SELECT count(*) FROM ops.email_outbox WHERE idempotency_key = $1",
                &[&key],
            )
            .expect("count query")
            .get(0);
        assert_eq!(rows, 1);
    });
}

/// G-M22-11 shape (the door half): a post-DATA drop is SUBMISSION_UNKNOWN, recorded once, and
/// the next drain never sends it again.
#[test]
fn submission_unknown_is_never_resent() {
    let _guard = SERIAL_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    run_db_fixture::<OutboxFixture, _>("submission_unknown_is_never_resent", |mut handle| {
        let to = unique_email("after-data");
        handle
            .rt
            .block_on(outbox::enqueue(
                &handle.gateway,
                &req(&handle, &to, EmailStream::Transactional),
                &RecipientAllowlist::allow_all(),
            ))
            .expect("seed a QUEUED row");

        let provider = RecordingEmailProvider::new();
        provider.push_outcome(ScriptedOutcome::Err(
            EmailErrorKind::SubmissionUnknown,
            "connection reset after DATA".to_string(),
        ));
        let policy = SendPolicy::default();
        assert_eq!(drain(&handle, &provider, &policy, 10), 1);
        assert_eq!(state_of(&mut handle, &to), "SUBMISSION_UNKNOWN");

        let (attempt, event_count): (i32, i64) = handle
            .admin
            .query_one(
                "SELECT o.attempt, (SELECT count(*) FROM ops.email_delivery_events e \
                   WHERE e.outbox_id = o.outbox_id AND e.event_type = 'SUBMISSION_UNKNOWN') \
                 FROM ops.email_outbox o WHERE o.user_id = $1 AND o.to_email = $2",
                &[&handle.user_id, &to],
            )
            .map(|r| (r.get(0), r.get(1)))
            .expect("row");
        assert_eq!((attempt, event_count), (1, 1));

        assert_eq!(drain(&handle, &provider, &policy, 10), 0);
        assert_eq!(
            provider.sent().len(),
            1,
            "an unknown outcome is never resent"
        );
        assert_eq!(state_of(&mut handle, &to), "SUBMISSION_UNKNOWN");
    });
}

/// M22 D11 (the door half): the drain takes AUTH before DIGEST regardless of arrival order.
#[test]
fn drain_takes_highest_priority_first() {
    let _guard = SERIAL_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    run_db_fixture::<OutboxFixture, _>("drain_takes_highest_priority_first", |handle| {
        let digest = unique_email("digest");
        let login = unique_email("login");
        for (to, priority) in [
            (&digest, EmailPriority::Digest),
            (&login, EmailPriority::Auth),
        ] {
            let mut request = req(&handle, to, EmailStream::Transactional);
            request.priority = priority;
            handle
                .rt
                .block_on(outbox::enqueue(
                    &handle.gateway,
                    &request,
                    &RecipientAllowlist::allow_all(),
                ))
                .expect("enqueue");
        }

        let provider = RecordingEmailProvider::new();
        assert_eq!(drain(&handle, &provider, &SendPolicy::default(), 1), 1);
        let sent: Vec<String> = provider.sent().into_iter().map(|m| m.to).collect();
        assert_eq!(
            sent,
            vec![login],
            "the login code goes first although queued second"
        );
    });
}

/// M22 D11: the per-minute cap bounds sends begun in the window; the rest stay QUEUED.
#[test]
fn send_cap_bounds_one_minute_window() {
    let _guard = SERIAL_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    run_db_fixture::<OutboxFixture, _>("send_cap_bounds_one_minute_window", |mut handle| {
        let addrs: Vec<String> = (0..3).map(|i| unique_email(&format!("cap{i}"))).collect();
        for to in &addrs {
            handle
                .rt
                .block_on(outbox::enqueue(
                    &handle.gateway,
                    &req(&handle, to, EmailStream::Transactional),
                    &RecipientAllowlist::allow_all(),
                ))
                .expect("enqueue");
        }
        // The cap is queue-wide, so size it relative to what other rows already used this minute.
        let recent: i64 = handle
            .admin
            .query_one(
                "SELECT count(*) FROM ops.email_outbox WHERE sent_at > now() - interval '1 minute'",
                &[],
            )
            .expect("count query")
            .get(0);
        let policy = SendPolicy {
            allowlist: RecipientAllowlist::allow_all(),
            max_sends_per_minute: Some(u32::try_from(recent + 2).expect("small cap")),
        };

        let provider = RecordingEmailProvider::new();
        assert_eq!(drain(&handle, &provider, &policy, 10), 2);
        assert_eq!(drain(&handle, &provider, &policy, 10), 0);
        assert_eq!(provider.sent().len(), 2);
        let queued = addrs
            .iter()
            .filter(|to| state_of(&mut handle, to) == "QUEUED")
            .count();
        assert_eq!(queued, 1, "the send that did not fit stays QUEUED");
    });
}

/// M02 D10: Message-ID is `<outbox_id@sender-domain>`, so a resend can be recognised.
#[test]
fn message_id_is_deterministic_per_outbox_row() {
    let _guard = SERIAL_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    run_db_fixture::<OutboxFixture, _>(
        "message_id_is_deterministic_per_outbox_row",
        |mut handle| {
            let to = unique_email("msgid");
            handle
                .rt
                .block_on(outbox::enqueue(
                    &handle.gateway,
                    &req(&handle, &to, EmailStream::Transactional),
                    &RecipientAllowlist::allow_all(),
                ))
                .expect("enqueue");
            let outbox_id: Uuid = handle
                .admin
                .query_one(
                    "SELECT outbox_id FROM ops.email_outbox WHERE user_id = $1 AND to_email = $2",
                    &[&handle.user_id, &to],
                )
                .expect("row")
                .get(0);

            let provider = RecordingEmailProvider::new();
            assert_eq!(drain(&handle, &provider, &SendPolicy::default(), 10), 1);
            let sent = provider.sent();
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0].message_id, format!("<{outbox_id}@humaux.example>"));
        },
    );
}

//! `adapters::remember` — T3.2 `remember` (§34 / §34.1 / §60 transaction B).
//! Depends-on: crates=[humaux-domain, humaux-projection, serde_json, sqlx]; services=[PostgreSQL(role_gateway)
//!   r=[control.private_reasoning_domains] w=[private.events, private.evidence_task_runs, private.ingest_tickets]];
//!   env=[]; modules=[adapters::affect_repo, adapters::coord_repo, adapters::evidence_repo, adapters::note_repo, adapters::postgres, adapters::retrieve,
//!   adapters::stream_repo, adapters::subject_repo, domain::affect, domain::error, domain::evidence, domain::ids,
//!   domain::subject, projection::stream]
//! Called-by: [adapters::affect_repo, adapters::consolidate_repo, adapters::distill_repo, adapters::memory_governance_repo, adapters::note_repo, adapters::operation_receipt, adapters::projection_worker, gateway::guard, gateway::remember, tests]
//! Invariants: [role_gateway's single Evidence write path, one transaction in §60 order; ingest tickets are only
//!   UPDATEd (no INSERT grant); the stream ticket and its outbox row come only from stream_repo::issue_ticket_in_txn
//!   (M09 D1), after the Evidence and note writes; an exhausted batch or non-future token expiry is a RememberError
//!   and nothing commits; private.evidence_task_runs is written only here, from a VerifiedTaskRun consumed by value]
//! Spec: Baseline §34.2; §60.1; §60; §34.1; §30.2
//!
//! [`remember`] is `role_gateway`'s single write path for Evidence acceptance. It runs against
//! [`RuntimeDbPool`] — never [`crate::batch::begin_batch`]'s [`crate::postgres::BatchIssuerDbPool`]
//! (§34.2 point 1: `RememberService`/this module holds no `BatchIssuerPort`). `role_gateway` has
//! no `INSERT` on `private.ingest_tickets` (`migrations/0011_roles_and_grants.sql`, §60.1's
//! authorization table) — every SQL statement below against that table is an `UPDATE`, never an
//! `INSERT`; that omission is not a style choice, it is the one property `crates/adapters/tests/
//! outbox_batch_remember.rs`'s G23-1c fault injection exists to prove is load-bearing.
//!
//! Steps, in one transaction, verbatim to §60's pseudocode:
//! `stream_repo::next_commit_seq` -> `create_evidence_object` -> `insert_event_subtype` -> `redeem_ticket`
//! (skipped when `cmd.batch_id` is `None`, §34.1 "不带 batch_id 的调用方行为一字不变") ->
//! `stream_repo::issue_ticket_in_txn` (stream_log row + outbox row, handed the sequence value taken first) ->
//! sign `consistency_token`.

use sqlx::Row;
use sqlx::types::Uuid;
use sqlx::types::time::OffsetDateTime;

use humaux_domain::affect::MoodHalfLife;
use humaux_domain::error::ErrorCode;
use humaux_domain::evidence::{EvidenceOriginClass, EvidencePayloadSha256};
use humaux_domain::ids::TenantId;
use humaux_domain::subject::SubjectDeclaration;
use humaux_projection::stream::StreamKey;

use crate::affect_repo::{self, AffectInput, AffectParent};
use crate::coord_repo::VerifiedTaskRun;
use crate::evidence_repo::{self, NewEvidence, OccurredAt};
use crate::note_repo::{self, NoteIntake, NoteLineage};
use crate::postgres::RuntimeDbPool;
use crate::retrieve::{self, TokenClaims};
use crate::stream_repo;

/// DB-layer failure plus the one domain-shaped terminal case this module can produce
/// (§34.1 `BATCH_EXHAUSTED`). Adapter-local, not `humaux_domain::error::ErrorCode` itself —
/// same "adapter boundary, not Domain" reasoning as `email::OutboxError` / `jobs::JobsError`;
/// the MCP/REST mapping to `ErrorCode::Conflict` (§52 "CONFLICT") with a `BATCH_EXHAUSTED`
/// reason string is `crates/protocol/src/error_map.rs`'s job, out of this task's scope.
#[derive(Debug)]
pub enum RememberError {
    Db(sqlx::Error),
    /// The caller-supplied consistency-token expiry is not after a validation clock reading.
    /// `remember` returns this only with no committed writes; a late check rolls its transaction
    /// back after a lock wait consumed the deadline.
    ConsistencyTokenExpiryNotFuture,
    /// `cmd.batch_id` named a batch with zero remaining `state = 'ISSUED'` tickets (already
    /// fully redeemed, or every ticket expired). §34.1: "拒绝，错误码 BATCH_EXHAUSTED，不得
    /// 自动补票" — this variant carries no ticket, the transaction is rolled back (nothing this
    /// call would have written — Evidence, event, stream_log row, outbox row — is committed).
    BatchExhausted,
    /// §6.1.3 rules 1/2 (ADR-0028): the command's `subjects` declaration did not resolve under
    /// the tenant's RLS (unknown, merged-away or another tenant's id/key ⇒ `INVALID_INPUT`), or
    /// the resolve itself failed. Raised BEFORE the first write, so nothing is committed.
    Subject(ErrorCode),
    /// §8.5.1 (ADR-0030 D-C): an affect in `cmd.affects` was refused — its `target_subject`
    /// did not resolve (`INVALID_INPUT`, raised BEFORE the first write like [`Self::Subject`]),
    /// or a MOOD arrived with no half-life policy (`DEPENDENCY_UNAVAILABLE`).
    Affect(ErrorCode),
    /// §11.2.1 ingress (ADR-0032 D-A): the command's tenant has no reasoning domain this
    /// Evidence could be processed under — the process-configured domain is another tenant's
    /// and the on-behalf-of user owns no ACTIVE domain here. The tenant is not provisioned for
    /// writes (`DEPENDENCY_UNAVAILABLE`); raised BEFORE the first write, nothing is committed.
    ReasoningDomainUnresolved,
    /// ADR-0059 D-G: no consistency-token key set is installed in this process; the transaction
    /// is rolled back, nothing is committed (`DEPENDENCY_UNAVAILABLE`).
    TokenKeysUnset,
    /// ADR-0067 D-C: a `memory.note_put` intake was refused before the first write — the requested authority exceeds the
    /// server-fixed origin's ceiling (`FORBIDDEN`; the gateway renders the business error). Nothing is committed.
    Note(ErrorCode),
    /// A `data_class` / `visibility_class` string outside its closed CHECK set reached the typed Evidence door
    /// ([`crate::evidence_repo::NewEvidence`]): a producer bug, not an infrastructure fault — every in-repo producer
    /// emits closed-set literals. Refused before the INSERT, nothing is written; every mapper renders it
    /// `INTERNAL` (a retry cannot change a deterministic fault).
    EvidenceClassOutsideSet {
        /// The `private.evidence_objects` column the value was meant for.
        column: &'static str,
        /// The offending string, verbatim.
        value: String,
    },
}

impl From<sqlx::Error> for RememberError {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

impl std::fmt::Display for RememberError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Db(e) => write!(f, "remember DB error: {e}"),
            Self::ConsistencyTokenExpiryNotFuture => {
                write!(f, "consistency_token expiry must be after issuance time")
            }
            Self::BatchExhausted => write!(f, "BATCH_EXHAUSTED (§34.1)"),
            Self::TokenKeysUnset => write!(f, "consistency_token key set is not installed"),
            Self::Subject(code) => write!(f, "subject declaration rejected: {code}"),
            Self::Affect(code) => write!(f, "affect declaration rejected: {code}"),
            Self::Note(code) => write!(f, "note intake rejected: {code}"),
            Self::EvidenceClassOutsideSet { column, value } => {
                write!(f, "evidence {column} {value:?} is outside its closed set")
            }
            Self::ReasoningDomainUnresolved => {
                write!(f, "no reasoning domain for this tenant (§11.2.1)")
            }
        }
    }
}

impl std::error::Error for RememberError {}

/// `remember()` input — already-resolved/validated fields for `private.evidence_objects` +
/// `private.events`, one call = one `evidence_kind = 'EVENT'` row pair (the only subtype this
/// task's `remember` MCP contract produces, §34; `'ARTIFACT'` rows are a different write path,
/// out of scope). Mapping raw MCP `remember(content, kind, source, ...)` input into this shape
/// (client-facing `kind` string -> one of the 9 `event_kind` CHECK values, `source.type` ->
/// [`EvidenceOriginClass`], etc.) is the MCP handler / `application::remember`'s job, not this
/// module's — §60's own pseudocode also starts from an opaque `cmd`, not raw JSON.
#[derive(Debug, Clone)]
pub struct RememberCommand {
    pub tenant_id: Uuid,
    /// Authenticated actor from the trusted gateway request context. This is deliberately
    /// distinct from `visibility_user_id`: workspace-shared Evidence has no visibility user,
    /// but RLS still needs the acting member in `humaux.user_id`.
    pub authorization_user_id: Option<Uuid>,
    /// `projection.stream_log` / `stream_checkpoints` locator (§15.1's other five PK columns,
    /// beyond `tenant_id`) — which pipeline this Evidence's stream_seq is issued against.
    pub scope_kind: String,
    pub scope_id: Uuid,
    pub domain: String,
    pub projection_kind: String,
    pub projection_version: String,
    /// Explicit policy/configuration input for §15.5's token `expiry or policy` field.
    /// It is validated against the one issuance clock captured by [`remember`] before any DB
    /// write. This is an API break: callers must provide their own configured/policy expiry;
    /// the adapter intentionally has no business TTL default.
    pub consistency_token_expires_at: OffsetDateTime,
    /// `Some` = batch write (redeem one ticket, §34.1 row 1); `None` = single sync write, ticket
    /// untouched (§34.1 row 3, `expected_source = "none"`).
    pub batch_id: Option<Uuid>,
    /// §48.0① sole-constructor anchor — accepted as the already-hashed
    /// [`EvidencePayloadSha256`] (never a raw `[u8; 32]`) so this command struct cannot be
    /// built with a digest that skipped `evidence::payload_sha256`'s "no trim/NFC/NFKC/
    /// transcode" contract; the type has no `pub` field and no second constructor, so the only
    /// way a caller has one to put here is to have called that function.
    pub payload_sha256: EvidencePayloadSha256,
    pub data_class: String,
    pub origin_class: EvidenceOriginClass,
    pub origin_principal_id: Option<Uuid>,
    pub origin_connector_id: Option<Uuid>,
    pub visibility_class: String,
    pub visibility_user_id: Option<Uuid>,
    pub visibility_workspace_id: Option<Uuid>,
    pub reasoning_domain_id: Uuid,
    pub occurred_at: Option<OffsetDateTime>,
    pub event_kind: String,
    pub event_payload: serde_json::Value,
    /// §6.1.3 rules 1/2 (ADR-0028): the explicit `subject_ids` / `subject_keys` this Evidence is
    /// about. Resolved under the tenant's RLS before the first write and recorded on
    /// `private.evidence_subjects` in the same transaction; an unknown id/key is
    /// [`RememberError::Subject`]`(INVALID_INPUT)` and nothing is written.
    pub subjects: SubjectDeclaration,
    /// §8.5.1 (ADR-0030 D-C): the affects declared at `remember.put`. Their `target_subject`
    /// ids/keys are resolved with `subjects` BEFORE the first write; the rows land on
    /// `private.evidence_affects` in this same transaction (0157) and reach every memory born
    /// from this Evidence through the `memory_evidence` PRIMARY trigger. Empty = none.
    pub affects: Vec<AffectInput>,
    /// The frozen MOOD half-life policy stamped onto MOOD rows; required only when `affects`
    /// carries a MOOD ([`RememberError::Affect`]`(DEPENDENCY_UNAVAILABLE)` otherwise).
    pub mood_half_life: Option<MoodHalfLife>,
}

/// `remember()`'s accepted result (§34 / §15.5, verbatim field set).
#[derive(Debug, Clone)]
pub struct RememberAccepted {
    pub evidence_id: Uuid,
    /// §34: "通过 processing_handle / memory / context 查询处理结果" — opaque to the caller,
    /// currently just the evidence id's string form (one Evidence : one handle, §34's own
    /// "一个 Evidence 后续可产生多条 memory_id" is a *query-time* fan-out, not something this
    /// handle itself encodes).
    pub processing_handle: String,
    /// §15.5 opaque read-your-writes token, emitted only after the Evidence transaction commits.
    /// Its one encoder is [`crate::retrieve::issue_consistency_token`]; it is not an
    /// authentication token, and `recall` validates tenant/workspace against the authenticated
    /// request context separately.
    pub consistency_token: String,
    pub ticket_ordinal: Option<i32>,
    pub batch_remaining: Option<i64>,
    pub status: &'static str,
}

/// Installs both RLS GUCs for this transaction. The user setting is always overwritten so a
/// pooled connection never inherits a prior request; a headless write uses the UUID sentinel
/// required by the current direct UUID cast in the user-visibility policy.
async fn set_authorization_local(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    user_id: Option<Uuid>,
) -> Result<(), RememberError> {
    sqlx::query(
        "SELECT set_config('humaux.tenant_id', $1, true), \
                set_config('humaux.user_id', $2, true)",
    )
    .bind(tenant_id.to_string())
    .bind(user_id.unwrap_or_else(Uuid::nil).to_string())
    .execute(&mut **txn)
    .await?;
    Ok(())
}

/// §11.2.1 ingress (ADR-0032 D-A): which `control.private_reasoning_domains` row this Evidence
/// is processed under, chosen inside the write transaction from the command's OWN tenant (the
/// tenant-isolation policy on that table is the fence; `set_authorization_local` has already
/// pinned it). Precedence, one indexed read: first `cmd.reasoning_domain_id` — the
/// process-configured domain (`HUMAUX_GATEWAY_REMEMBER_REASONING_DOMAIN_ID`) — when it is one
/// of THIS tenant's ACTIVE domains (the deployment's own tenant keeps its boot-time domain
/// byte-for-byte; the private worker distills exactly that domain); otherwise the ACTIVE domain
/// owned by the on-behalf-of user (§11.2.1 "用户直接输入 -> reasoning_domain = 该用户"); neither
/// ⇒ [`RememberError::ReasoningDomainUnresolved`] — "无法确定 processing principal": the tenant
/// is not provisioned for writes, nothing is written.
/// The single-column FK of 0004 never refused a cross-tenant domain (RI bypasses RLS); 0159's
/// composite FK now does, so a bypass of this resolve is a `23503`, not a silent cross-tenant
/// pointer.
// ponytail: earliest user-owned ACTIVE domain when a user owns several; the §11.2.1
// reasoning_domain_grants binding replaces rule 2 once grants are issued anywhere.
async fn resolve_reasoning_domain(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    cmd: &RememberCommand,
) -> Result<Uuid, RememberError> {
    sqlx::query_scalar(
        "SELECT reasoning_domain_id FROM control.private_reasoning_domains \
         WHERE tenant_id = $1 AND status = 'ACTIVE' \
           AND (reasoning_domain_id = $2 OR owner_user_id = $3) \
         ORDER BY reasoning_domain_id = $2 DESC, created_at, reasoning_domain_id \
         LIMIT 1",
    )
    .bind(cmd.tenant_id)
    .bind(cmd.reasoning_domain_id)
    .bind(cmd.authorization_user_id)
    .fetch_optional(&mut **txn)
    .await?
    .ok_or(RememberError::ReasoningDomainUnresolved)
}

/// A `data_class` / `visibility_class` string outside the CHECK sets: the typed door cannot express it, so it is refused
/// before the INSERT as [`RememberError::EvidenceClassOutsideSet`], and nothing is written.
fn unknown_evidence_literal(column: &'static str, value: &str) -> RememberError {
    RememberError::EvidenceClassOutsideSet {
        column,
        value: value.to_owned(),
    }
}

/// `create_evidence_object` — maps `cmd` onto M07's Evidence door
/// ([`evidence_repo::insert_evidence_in_txn`], the workspace's single `INSERT INTO
/// private.evidence_objects`); `evidence_kind = 'EVENT'` is fixed there (see
/// [`RememberCommand`]'s doc). `evidence_id` / `created_at` stay the table's own defaults.
pub(crate) async fn create_evidence_object(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    cmd: &RememberCommand,
) -> Result<Uuid, RememberError> {
    let data_class = evidence_repo::data_class_from_db_str(&cmd.data_class)
        .ok_or_else(|| unknown_evidence_literal("data_class", &cmd.data_class))?;
    let visibility_class = evidence_repo::visibility_class_from_db_str(&cmd.visibility_class)
        .ok_or_else(|| unknown_evidence_literal("visibility_class", &cmd.visibility_class))?;
    Ok(evidence_repo::insert_evidence_in_txn(
        txn,
        &NewEvidence {
            tenant_id: cmd.tenant_id,
            payload_sha256: &cmd.payload_sha256,
            data_class,
            origin_class: cmd.origin_class,
            origin_principal_id: cmd.origin_principal_id,
            origin_connector_id: cmd.origin_connector_id,
            visibility_class,
            visibility_user_id: cmd.visibility_user_id,
            visibility_workspace_id: cmd.visibility_workspace_id,
            reasoning_domain_id: cmd.reasoning_domain_id,
            occurred_at: OccurredAt::At(cmd.occurred_at),
        },
    )
    .await?)
}

/// The token's optional workspace is a stream-routing binding, not Evidence visibility. A
/// USER_PRIVATE Evidence in a workspace stream therefore carries the workspace in its token
/// even though its stored `visibility_workspace_id` is necessarily NULL.
fn token_workspace_id(key: &StreamKey) -> Option<Uuid> {
    (key.scope_kind == "workspace").then_some(key.scope_id)
}

/// `insert_event_subtype` — `private.events` shares its primary key with the
/// `evidence_objects` row it subtypes (`events.event_id REFERENCES evidence_objects.evidence_id`,
/// 1:1, no separate id minted here).
pub(crate) async fn insert_event_subtype(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    evidence_id: Uuid,
    cmd: &RememberCommand,
) -> Result<(), RememberError> {
    sqlx::query("INSERT INTO private.events (event_id, event_kind, payload) VALUES ($1, $2, $3)")
        .bind(evidence_id)
        .bind(&cmd.event_kind)
        .bind(&cmd.event_payload)
        .execute(&mut **txn)
        .await?;
    Ok(())
}

/// One redeemed ticket's observable result (§34 `ticket_ordinal` / `batch_remaining`).
struct RedeemedTicket {
    ordinal: i32,
    remaining: i64,
}

/// `redeem_ticket` — §60's merged `maybe_issue_ingest_ticket`+`redeem_ticket_if_any` replacement,
/// "纯 UPDATE" (§60 "这个事务里没有任何一条 SQL 能增加票数"). Claims the minimum-`ordinal`
/// still-`ISSUED` ticket in `batch_id` (`FOR UPDATE SKIP LOCKED` so two concurrent `remember`
/// calls against the same batch never redeem the same ticket twice, mirroring
/// `jobs::claim`'s SKIP LOCKED reasoning) and flips it to `REDEEMED`. Zero rows updated —
/// no `ISSUED` ticket left, exhausted or the batch never existed — is [`RememberError::BatchExhausted`]
/// (§34.1), never a silent no-op and never a fallback `INSERT` of a fresh ticket ("绝不补票").
async fn redeem_ticket(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    batch_id: Uuid,
    event_id: Uuid,
) -> Result<RedeemedTicket, RememberError> {
    let updated = sqlx::query(
        "UPDATE private.ingest_tickets \
            SET redeemed_event_id = $2, state = 'REDEEMED' \
          WHERE ticket_id = ( \
                  SELECT ticket_id FROM private.ingest_tickets \
                   WHERE batch_id = $1 AND state = 'ISSUED' \
                   ORDER BY ordinal ASC \
                   FOR UPDATE SKIP LOCKED \
                   LIMIT 1 \
                ) \
          RETURNING ordinal",
    )
    .bind(batch_id)
    .bind(event_id)
    .fetch_optional(&mut **txn)
    .await?;

    let Some(row) = updated else {
        return Err(RememberError::BatchExhausted);
    };
    let ordinal: i32 = row.try_get("ordinal")?;

    let remaining: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM private.ingest_tickets WHERE batch_id = $1 AND state = 'ISSUED'",
    )
    .bind(batch_id)
    .fetch_one(&mut **txn)
    .await?;

    Ok(RedeemedTicket { ordinal, remaining })
}

/// §14/§15.1: `role_consolidation_worker`'s own private-Evidence-shaped outbox event for a
/// published `private.memory_rollups` row (§78.2: pinned here, not reused from
/// `EVIDENCE_ACCEPTED`, so a reader can tell "a rollup published" from "an Evidence was
/// remembered" without inspecting the row's other columns).
pub(crate) const MEMORY_PUBLISHED: &str = "MEMORY_PUBLISHED";

/// §14/§15.1: reserved sibling of [`MEMORY_PUBLISHED`] for a future consolidation undo/
/// retraction op — not emitted by this crate today, named now so the two literals stay next to
/// each other (§78.2 "no second literal elsewhere").
// ponytail: unused until an undo/retraction write path exists; add its call site then.
#[allow(dead_code)]
pub(crate) const MEMORY_LIFECYCLE: &str = "MEMORY_LIFECYCLE";

/// The uncommitted outcome of [`remember_in_txn`]. The receipt/orchestrator caller receives
/// only facts emitted by the successful SQL writes, then decides when to commit its larger
/// transaction. It must call [`Self::into_accepted`] only after that transaction commits.
#[derive(Debug, Clone)]
pub struct RememberPending {
    accepted: RememberAccepted,
    stream_key: StreamKey,
    commit_seq: i64,
    stream_seq: i64,
    memory_id: Option<Uuid>,
}

impl RememberPending {
    /// ADR-0067: the Memory the same transaction wrote for an identity note; `None` for `remember.put`.
    #[must_use]
    pub const fn memory_id(&self) -> Option<Uuid> {
        self.memory_id
    }

    #[must_use]
    pub fn accepted(&self) -> &RememberAccepted {
        &self.accepted
    }

    #[must_use]
    pub fn into_accepted(self) -> RememberAccepted {
        self.accepted
    }

    #[must_use]
    pub fn stream_key(&self) -> &StreamKey {
        &self.stream_key
    }

    #[must_use]
    pub const fn commit_seq(&self) -> i64 {
        self.commit_seq
    }

    #[must_use]
    pub const fn stream_seq(&self) -> i64 {
        self.stream_seq
    }
}

/// §60 transaction B without a commit. This is the atomic gateway-write seam: the caller may
/// append receipt, quota, and audit rows in the same transaction, then commit exactly once.
/// Errors leave rollback to the owning transaction; no SQL here commits independently.
pub async fn remember_in_txn(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    cmd: RememberCommand,
) -> Result<RememberPending, RememberError> {
    remember_in_txn_with(txn, cmd, None).await
}

/// Design v0.2 §15 T04c: the one writer of `private.evidence_task_runs` (xtask G-T04c-3; 0251 grants
/// INSERT to `role_gateway` only). `verified` is taken by value: it is the proof that
/// [`crate::coord_repo::verify_task_run`] passed in this same transaction, which still holds the
/// task row FOR SHARE, so the row records a lease that was live at this write (§30.2) and one
/// verification backs one row. `evidence_id` is the Evidence this transaction just wrote; the
/// tenant-leg FKs and the FORCE RLS policy refuse a run or an Evidence outside `tenant_id`.
pub async fn insert_evidence_task_run_in_txn(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: TenantId,
    verified: VerifiedTaskRun,
    evidence_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO private.evidence_task_runs (tenant_id, evidence_id, task_run_id, fencing_token) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(tenant_id.0)
    .bind(evidence_id)
    .bind(verified.task_run_id().0)
    .bind(verified.fencing_token().0)
    .execute(&mut **txn)
    .await
    .map(|_| ())
}

/// [`remember_in_txn`] with an optional ADR-0067 identity note. With `Some((note, lineage))` the same transaction also writes
/// the identity contract, the one authorised Memory and (D-J) the note-head move (`note_repo::materialize_in_txn`) between
/// the Evidence rows and the stream ticket; the 0235 triggers then see the contract when the `EVIDENCE_ACCEPTED` outbox row is inserted (no distill
/// job; the row is born `DONE`, so the projection claim does not wait on it, 0176). `None` is `remember.put`, byte for byte.
pub async fn remember_in_txn_with(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mut cmd: RememberCommand,
    note: Option<(&NoteIntake, NoteLineage)>,
) -> Result<RememberPending, RememberError> {
    // This check is deliberately inside the reusable path, before its first write. The public
    // wrapper's fast check only avoids opening a transaction for an already-expired command.
    if cmd.consistency_token_expires_at <= OffsetDateTime::now_utc() {
        return Err(RememberError::ConsistencyTokenExpiryNotFuture);
    }

    let key = StreamKey::new(
        TenantId(cmd.tenant_id),
        cmd.scope_kind.clone(),
        cmd.scope_id,
        cmd.domain.clone(),
        cmd.projection_kind.clone(),
        cmd.projection_version.clone(),
    );

    // ADR-0067 D-C: the authority decision is pure and precedes every write.
    let note_class = note
        .map(|(note, _)| note_repo::authorize(note))
        .transpose()?;

    set_authorization_local(txn, cmd.tenant_id, cmd.authorization_user_id).await?;

    // §11.2.1 (ADR-0032 D-A): the reasoning domain is the caller tenant's, resolved per request
    // under that tenant's RLS BEFORE the first write — never the process's boot constant
    // stamped onto another tenant's Evidence (0159's composite FK is the DB-side invariant).
    cmd.reasoning_domain_id = resolve_reasoning_domain(txn, &cmd).await?;

    // §6.1.3 rules 1/2 (ADR-0028): resolve the declaration BEFORE the first write so an unknown
    // id/key rejects with nothing committed — no Evidence, no ticket, no outbox row.
    let subjects =
        crate::subject_repo::resolve_declaration_in_txn(txn, cmd.tenant_id, &cmd.subjects)
            .await
            .map_err(RememberError::Subject)?;
    // §8.5.1 (ADR-0030 D-C): the affects' target subjects resolve under the same rule, also
    // before the first write — an unknown target refuses the whole put with nothing accepted.
    let affect_targets = affect_repo::resolve_targets_in_txn(txn, cmd.tenant_id, &cmd.affects)
        .await
        .map_err(RememberError::Affect)?;

    let commit_seq = stream_repo::next_commit_seq(txn).await?;
    let evidence_id = create_evidence_object(txn, &cmd).await?;
    insert_event_subtype(txn, evidence_id, &cmd).await?;
    // The declaration rides on the Evidence in this same transaction (the memory is born later
    // in the Distill hop and inherits it through link_memory_subjects rule 3a).
    crate::subject_repo::declare_evidence_in_txn(txn, cmd.tenant_id, evidence_id, &subjects)
        .await?;
    // The affect declaration rides on the Evidence the same way (0157 evidence_affects, the
    // sole affect issuer); the newborn memory's copy is the memory_evidence PRIMARY trigger's.
    affect_repo::insert_in_txn(
        txn,
        cmd.tenant_id,
        AffectParent::Evidence,
        evidence_id,
        &cmd.affects,
        &affect_targets,
        cmd.mood_half_life,
    )
    .await
    .map_err(RememberError::Affect)?;

    // §34.1: batch_id present -> redeem (BATCH_EXHAUSTED rolls the whole transaction back,
    // never partially — see this function's doc); absent -> ticket untouched, both output
    // fields stay None (expected_source = "none").
    let ticket = match cmd.batch_id {
        Some(batch_id) => Some(redeem_ticket(txn, batch_id, evidence_id).await?),
        None => None,
    };

    // ADR-0067 D-A/D-B: the contract row precedes the outbox row, so the 0235 enqueue trigger sees it.
    let memory_id = match (note, note_class) {
        (Some((note, lineage)), Some(class)) => {
            Some(note_repo::materialize_in_txn(txn, &cmd, evidence_id, note, lineage, class).await?)
        }
        _ => None,
    };

    let stream_seq = stream_repo::issue_ticket_in_txn(
        txn,
        &key,
        evidence_id,
        "EVIDENCE_ACCEPTED",
        Some(commit_seq),
    )
    .await?
    .stream_seq;

    // Sign at the actual issuance point, after every potentially blocking write. If a lock
    // wait consumed the deadline, returning here drops `txn` and rolls every write back.
    let issued_at = OffsetDateTime::now_utc();
    if cmd.consistency_token_expires_at <= issued_at {
        return Err(RememberError::ConsistencyTokenExpiryNotFuture);
    }
    let consistency_token = retrieve::issue_consistency_token(&TokenClaims {
        tenant_id: key.tenant_id.0,
        // This is routing identity from the trusted stream key, independent of Evidence's
        // row-level visibility. `recall` compares it with its authenticated request context.
        workspace_id: token_workspace_id(&key),
        scope_kind: key.scope_kind.clone(),
        scope_id: key.scope_id,
        domain: key.domain.clone(),
        projection_kind: key.projection_kind.clone(),
        projection_version: key.projection_version.clone(),
        stream_seq,
        commit_seq,
        issued_at,
        expires_at: cmd.consistency_token_expires_at,
    })
    .map_err(|_| RememberError::TokenKeysUnset)?;

    Ok(RememberPending {
        accepted: RememberAccepted {
            evidence_id,
            processing_handle: evidence_id.to_string(),
            consistency_token,
            ticket_ordinal: ticket.as_ref().map(|t| t.ordinal),
            batch_remaining: ticket.as_ref().map(|t| t.remaining),
            status: "accepted",
        },
        stream_key: key,
        commit_seq,
        stream_seq,
        memory_id,
    })
}

/// Public one-shot wrapper. It preserves the original accepted response and owns the commit;
/// callers that need an atomic receipt/quota/audit bundle use [`remember_in_txn`] instead.
pub async fn remember(
    pool: &RuntimeDbPool,
    cmd: RememberCommand,
) -> Result<RememberAccepted, RememberError> {
    if cmd.consistency_token_expires_at <= OffsetDateTime::now_utc() {
        return Err(RememberError::ConsistencyTokenExpiryNotFuture);
    }
    // dep: PostgreSQL(role_gateway) — transaction entry for `remember`
    let mut txn = pool.pool().begin().await?;
    let pending = remember_in_txn(&mut txn, cmd).await?;
    txn.commit().await?;
    Ok(pending.into_accepted())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The refusal is a typed, non-retryable invariant breach carrying the column and the offending string, never a
    /// `Db` error (which the callers' `db_error` mappers would read as a retryable dependency fault).
    #[test]
    fn class_outside_the_closed_set_is_its_own_error_variant() {
        match unknown_evidence_literal("data_class", "private") {
            RememberError::EvidenceClassOutsideSet { column, value } => {
                assert_eq!(column, "data_class");
                assert_eq!(value, "private");
            }
            other => panic!("expected EvidenceClassOutsideSet, got {other:?}"),
        }
        assert_eq!(
            unknown_evidence_literal("visibility_class", "x").to_string(),
            "evidence visibility_class \"x\" is outside its closed set"
        );
    }
}

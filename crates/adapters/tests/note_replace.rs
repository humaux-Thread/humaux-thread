//! `adapters::tests::note_replace` — ADR-0067 D-J card 40c-1 acceptance for `memory.note_put` replacement (G19, G20,
//!   G21, G26, G27, G28 and the note identity of the create path), against a real PostgreSQL and real `role_gateway` logins.
//! Depends-on: crates=[hex, humaux-adapters, humaux-domain, humaux-projection, humaux-testkit, postgres, serde_json, sqlx,
//!   tokio]; services=[PostgreSQL(role_gateway) r=[control.confirm_tokens, control.operation_receipts,
//!   control.usage_reservations, ops.jobs, ops.memory_lifecycle_events, ops.outbox,
//!   private.identity_note_materializations, private.note_heads, projection.stream_log] w=[private.evidence_objects,
//!   private.memory_evidence, private.memory_records]]; env=[];
//!   modules=[adapters::attribution_repo, adapters::confirm_token_repo, adapters::forget_repo, adapters::memory_governance_repo, adapters::note_repo,
//!   adapters::operation_receipt, adapters::postgres, adapters::remember, adapters::tests::support::governance_ops,
//!   adapters::tests::support::operation_receipt_fixture, domain::audit, domain::authority, domain::confirm,
//!   domain::error, domain::evidence, domain::identity, domain::ids, domain::note, domain::subject, humaux-testkit,
//!   projection::stream]
//! Called-by: [cargo-test]
//! Invariants: [every write under test is a real role_gateway login through the production adapter entry points, the
//!   confirm token minted by `confirm_token_repo::mint_with_audit` as the gateway's first leg does; the owner connection
//!   only seeds, holds a barrier lock, forces the EXCLUDE witness and reads back this fixture's tenant; every gate
//!   asserts stored rows or real outcomes, never two literals]
//! Spec: ADR-0067; ADR-0018; ADR-0054
//!
//! The editor is a governance principal (`governance_ops::Governor`): a real credential, because consuming a confirm
//! token rechecks the write scope against `control.api_keys` (ADR-0054 D-B).

// Both fixtures (`operation_receipt_fixture`, `governance_ops`) carry their own `#[path] mod token_keys`; this is the one
// test that loads both, and `token_keys::install` is idempotent per process, so the second copy is inert.
#![allow(clippy::duplicate_mod)]

use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant, SystemTime};

use humaux_adapters::{
    confirm_token_repo::{self, ConfirmationClaim},
    forget_repo,
    memory_governance_repo::ArchiveResult,
    note_repo::NoteIntake,
    operation_receipt::{
        self, AtomicRememberRequest, AtomicRememberResult, NOTE_OPERATION, NoteReplaceOutcome,
        NoteReplaceRequest,
    },
    postgres::RuntimeDbPool,
    remember::RememberCommand,
};
use humaux_domain::{
    audit::{AuditEvent, AuditEventId, AuditMetadata, McpAuditAction},
    authority::AuthorityClass,
    confirm::{DestructiveOp, RISK_TAG_CONFIRMATION_MINTED},
    error::ErrorCode,
    evidence::{EvidenceOriginClass, payload_sha256},
    identity::AuthorizationScope,
    ids::{TenantId, WorkspaceId},
    note::{DEFAULT_AUTHORITY, NoteBody, NoteKind, note_title, replace_intent_sha256},
};
use humaux_projection::stream::StreamKey;
use humaux_testkit::run_db_fixture;
use postgres::error::SqlState;
use sqlx::types::{Uuid, time::OffsetDateTime};

#[allow(dead_code)]
#[path = "support/operation_receipt_fixture.rs"]
mod operation_receipt_fixture;

#[allow(dead_code)]
#[path = "support/governance_ops.rs"]
mod governance_ops;

use governance_ops::Governor;
use operation_receipt_fixture::{DOMAIN, Fixture, Handle, PROJECTION_KIND, PROJECTION_VERSION};

const TOKEN_TTL: Duration = Duration::from_secs(600);

/// The replacing principal, narrowed to the fixture workspace as the gateway's write route does.
struct Editor {
    auth: AuthorizationScope,
    user_id: Uuid,
    principal_id: Uuid,
}

fn editor(handle: &mut Handle) -> Editor {
    let governor = Governor::seed(&mut handle.admin, handle.tenant_id);
    governor.join(&mut handle.admin, handle.workspace_id);
    Editor {
        auth: governor.scope(handle.workspace_id),
        user_id: governor.user_id,
        principal_id: governor.api_key_id,
    }
}

fn audit(handle: &Handle, editor: &Editor, request_id: Uuid, minted: bool) -> AuditEvent {
    AuditEvent {
        event_id: AuditEventId::new(),
        ts: SystemTime::now(),
        tenant_id: TenantId(handle.tenant_id),
        actor_type: "SERVICE_CREDENTIAL".into(),
        actor_id: editor.principal_id.to_string(),
        action: McpAuditAction::McpRequestFinished.as_str().into(),
        resource_type: "MCP_OPERATION".into(),
        resource_id: NOTE_OPERATION.into(),
        result: "OK".into(),
        request_id: request_id.to_string(),
        trace_id: format!("note-replace-{request_id}"),
        client_ip: "127.0.0.1".into(),
        user_agent_hash: "note-replace-test".into(),
        risk_tags: if minted {
            vec![RISK_TAG_CONFIRMATION_MINTED.to_owned()]
        } else {
            Vec::new()
        },
        before_fingerprint: None,
        after_fingerprint: None,
        metadata: AuditMetadata::new(),
    }
}

/// The MANUAL_NOTE command the gateway edge builds for one body (copied from `note_put.rs`; test files do not import each
/// other), as the editor.
fn command(handle: &Handle, editor: &Editor, body: &str) -> RememberCommand {
    let raw = serde_json::to_vec(&serde_json::Value::String(body.to_owned())).expect("string");
    RememberCommand {
        tenant_id: handle.tenant_id,
        authorization_user_id: Some(editor.user_id),
        scope_kind: "workspace".into(),
        scope_id: handle.workspace_id,
        domain: DOMAIN.into(),
        projection_kind: PROJECTION_KIND.into(),
        projection_version: PROJECTION_VERSION.into(),
        consistency_token_expires_at: OffsetDateTime::now_utc() + Duration::from_secs(45),
        batch_id: None,
        payload_sha256: payload_sha256(&raw),
        data_class: "INTERNAL".into(),
        origin_class: EvidenceOriginClass::AuthenticatedAgent,
        origin_principal_id: Some(editor.principal_id),
        origin_connector_id: None,
        visibility_class: "WORKSPACE_SHARED".into(),
        visibility_user_id: None,
        visibility_workspace_id: Some(handle.workspace_id),
        reasoning_domain_id: handle.reasoning_domain_id,
        occurred_at: Some(OffsetDateTime::now_utc()),
        event_kind: "MANUAL_NOTE".into(),
        event_payload: serde_json::Value::String(body.to_owned()),
        subjects: humaux_domain::subject::SubjectDeclaration::default(),
        affects: Vec::new(),
        mood_half_life: None,
    }
}

fn atomic_request(
    handle: &Handle,
    editor: &Editor,
    key: &str,
    fingerprint: String,
    body: &str,
) -> AtomicRememberRequest {
    let request_id = Uuid::new_v4();
    AtomicRememberRequest {
        request_id,
        idempotency_key: key.into(),
        request_fingerprint: fingerprint,
        workspace_id: Some(WorkspaceId(handle.workspace_id)),
        reservation_ttl: Duration::from_secs(30),
        replay_ttl: Duration::from_secs(600),
        command: command(handle, editor, body),
        finished_audit: audit(handle, editor, request_id, false),
    }
}

/// A fresh note through the 40a create path (`note_put_atomically`).
fn create(handle: &Handle, editor: &Editor, body: &str, kind: NoteKind) -> AtomicRememberResult {
    let verbatim = NoteBody::new(body).expect("valid body");
    let note = NoteIntake {
        kind,
        title: note_title(None, &verbatim).expect("derived title"),
        body: verbatim,
        requested: DEFAULT_AUTHORITY,
    };
    let key = format!("create-{}", Uuid::new_v4());
    handle
        .rt
        .block_on(operation_receipt::note_put_atomically(
            &handle.runtime,
            &editor.auth,
            atomic_request(handle, editor, &key, "c".repeat(64), body),
            note,
            &humaux_adapters::attribution_repo::AttributionLadder,
        ))
        .expect("note create commits")
}

/// One replacement intent: every field `H` binds.
#[derive(Clone)]
struct Intent {
    key: String,
    note_id: Uuid,
    supersedes: Uuid,
    body: String,
    title: Option<String>,
    kind: NoteKind,
    requested: AuthorityClass,
}

impl Intent {
    fn new(note_id: Uuid, supersedes: Uuid, body: &str, kind: NoteKind) -> Self {
        Self {
            key: format!("replace-{}", Uuid::new_v4()),
            note_id,
            supersedes,
            body: body.to_owned(),
            title: None,
            kind,
            requested: DEFAULT_AUTHORITY,
        }
    }

    fn note(&self) -> NoteIntake {
        let body = NoteBody::new(&self.body).expect("valid body");
        NoteIntake {
            kind: self.kind,
            title: note_title(self.title.as_deref(), &body).expect("title"),
            body,
            requested: self.requested,
        }
    }

    /// `H` exactly as the gateway computes it for this request.
    fn digest(&self) -> [u8; 32] {
        let note = self.note();
        replace_intent_sha256(
            self.note_id,
            self.supersedes,
            note.kind,
            &note.title,
            &note.body,
            note.requested,
            &self.key,
        )
    }
}

/// The gateway's first leg: a `MemoryNoteReplace` token on `supersedes`, bound to `H` of `intent`.
fn mint(handle: &Handle, editor: &Editor, intent: &Intent, ttl: Duration) -> ConfirmationClaim {
    let nonce_sha256: [u8; 32] = [*Uuid::new_v4().as_bytes(), *Uuid::new_v4().as_bytes()]
        .concat()
        .try_into()
        .expect("32 bytes");
    handle
        .rt
        .block_on(confirm_token_repo::mint_with_audit(
            &handle.runtime,
            &editor.auth,
            DestructiveOp::MemoryNoteReplace,
            intent.supersedes,
            None,
            ttl,
            nonce_sha256,
            Some(intent.digest()),
            &audit(handle, editor, Uuid::new_v4(), true),
        ))
        .expect("mint the replacement token");
    ConfirmationClaim {
        op: DestructiveOp::MemoryNoteReplace,
        target_id: intent.supersedes,
        successor_id: None,
        nonce_sha256,
        request_sha256: Some(intent.digest()),
    }
}

/// `token` presented with the request `intent`: the claim the gateway builds from that request (its own target and `H`).
fn presented(token: &ConfirmationClaim, intent: &Intent) -> ConfirmationClaim {
    ConfirmationClaim {
        op: DestructiveOp::MemoryNoteReplace,
        target_id: intent.supersedes,
        successor_id: None,
        nonce_sha256: token.nonce_sha256,
        request_sha256: Some(intent.digest()),
    }
}

fn replace_parts(
    handle: &Handle,
    editor: &Editor,
    intent: &Intent,
    claim: Option<ConfirmationClaim>,
) -> (AtomicRememberRequest, NoteIntake, NoteReplaceRequest) {
    (
        atomic_request(
            handle,
            editor,
            &intent.key,
            hex::encode(intent.digest()),
            &intent.body,
        ),
        intent.note(),
        NoteReplaceRequest {
            note_id: intent.note_id,
            supersedes: intent.supersedes,
            claim,
        },
    )
}

/// One replacement leg: the challenge with `claim = None`, the confirmed commit otherwise.
fn replace(
    handle: &Handle,
    editor: &Editor,
    intent: &Intent,
    claim: Option<ConfirmationClaim>,
) -> Result<NoteReplaceOutcome, ErrorCode> {
    let (request, note, replace) = replace_parts(handle, editor, intent, claim);
    handle
        .rt
        .block_on(operation_receipt::note_replace_atomically(
            &handle.runtime,
            &editor.auth,
            request,
            note,
            replace,
            &humaux_adapters::attribution_repo::AttributionLadder,
        ))
}

/// The receipt advisory-lock text `operation_receipt::lock_and_find_receipt` derives for `intent`: every member of
/// `(tenant, principal, scope_kind, scope_id, operation, idempotency_key)` comes from the request `replace` builds,
/// and only the `operation-receipt:` format is repeated here (the derivation is not a public API).
fn receipt_lock_key(handle: &Handle, editor: &Editor, intent: &Intent) -> String {
    let (request, _note, _replace) = replace_parts(handle, editor, intent, None);
    format!(
        "operation-receipt:{}:{}:{}:{}:{}:{}",
        editor.auth.tenant_id().0,
        editor.auth.principal().0,
        request.command.scope_kind,
        request.command.scope_id,
        NOTE_OPERATION,
        request.idempotency_key,
    )
}

/// Waits until the receipt lock `intent` names is free on the server, then releases it. A refusal drops its
/// transaction, but sqlx rolls that back asynchronously; a blocking `pg_advisory_lock` queues behind the still-open
/// backend, so on return the prior `pg_try_advisory_xact_lock` is gone and the next call cannot meet it as CONFLICT on
/// whichever pooled connection it gets.
fn await_receipt_lock_release(handle: &mut Handle, editor: &Editor, intent: &Intent) {
    let key = receipt_lock_key(handle, editor, intent);
    handle
        .admin
        .query_one("SELECT pg_advisory_lock(hashtextextended($1,0))", &[&key])
        .expect("queue for the prior receipt transaction");
    handle
        .admin
        .query_one("SELECT pg_advisory_unlock(hashtextextended($1,0))", &[&key])
        .expect("release the receipt lock");
}

fn stored(outcome: Result<NoteReplaceOutcome, ErrorCode>) -> AtomicRememberResult {
    match outcome {
        Ok(NoteReplaceOutcome::Stored(result)) => result,
        other => panic!("expected a stored replacement, got {other:?}"),
    }
}

/// One replacement on its own real role_gateway pool and thread, started together with its sibling.
fn spawn_replace(
    dsn: String,
    auth: AuthorizationScope,
    parts: (AtomicRememberRequest, NoteIntake, NoteReplaceRequest),
    start: Arc<Barrier>,
) -> std::thread::JoinHandle<Result<NoteReplaceOutcome, ErrorCode>> {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("actor runtime");
        let pool = rt
            // dep: PostgreSQL(role_gateway) — the actor's own real gateway pool
            .block_on(RuntimeDbPool::connect(&dsn))
            .map_err(|error| error.to_string())
            .expect("actor gateway login");
        start.wait();
        let (request, note, replace) = parts;
        rt.block_on(operation_receipt::note_replace_atomically(
            &pool,
            &auth,
            request,
            note,
            replace,
            &humaux_adapters::attribution_repo::AttributionLadder,
        ))
    })
}

/// Every row family a replacement may add, for this tenant.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct Residue {
    evidence: i64,
    memories: i64,
    primary_links: i64,
    contracts: i64,
    receipts: i64,
    consumed_bmo: i64,
    consumed_tokens: i64,
    llm_jobs: i64,
    lifecycle_events: i64,
}

fn residue(handle: &mut Handle) -> Residue {
    let row = handle
        .admin
        .query_one(
            "SELECT \
               (SELECT count(*) FROM private.evidence_objects WHERE tenant_id=$1), \
               (SELECT count(*) FROM private.memory_records WHERE tenant_id=$1), \
               (SELECT count(*) FROM private.memory_evidence me JOIN private.memory_records m \
                  ON m.memory_id=me.memory_id WHERE m.tenant_id=$1 AND me.role='PRIMARY'), \
               (SELECT count(*) FROM private.identity_note_materializations WHERE tenant_id=$1), \
               (SELECT count(*) FROM control.operation_receipts WHERE tenant_id=$1), \
               (SELECT count(*) FROM control.usage_reservations WHERE tenant_id=$1 AND status='CONSUMED'), \
               (SELECT count(*) FROM control.confirm_tokens WHERE tenant_id=$1 AND consumed_at IS NOT NULL), \
               (SELECT count(*) FROM ops.jobs WHERE tenant_id=$1 \
                  AND job_type IN ('DERIVED_DISTILL','DERIVED_CONSOLIDATE')), \
               (SELECT count(*) FROM ops.memory_lifecycle_events WHERE tenant_id=$1)",
            &[&handle.tenant_id],
        )
        .expect("owner reads this tenant's rows");
    Residue {
        evidence: row.get(0),
        memories: row.get(1),
        primary_links: row.get(2),
        contracts: row.get(3),
        receipts: row.get(4),
        consumed_bmo: row.get(5),
        consumed_tokens: row.get(6),
        llm_jobs: row.get(7),
        lifecycle_events: row.get(8),
    }
}

/// A stored version: (status, superseded_by, note_id, note_kind).
fn version(
    handle: &mut Handle,
    memory_id: Uuid,
) -> (String, Option<Uuid>, Option<Uuid>, Option<String>) {
    let row = handle
        .admin
        .query_one(
            "SELECT status, superseded_by, note_id, note_kind FROM private.memory_records \
             WHERE tenant_id=$1 AND memory_id=$2",
            &[&handle.tenant_id, &memory_id],
        )
        .expect("version row");
    (row.get(0), row.get(1), row.get(2), row.get(3))
}

/// (op, reason_code, replacement_memory_id, idempotency_key, carries a stream seq) of one lifecycle event row.
type LifecycleRecord = (String, Option<String>, Option<Uuid>, String, bool);

/// ADR-0020: the [`LifecycleRecord`] of the event a version's `lifecycle_head_event_id` names, if any.
fn supersede_record(handle: &mut Handle, memory_id: Uuid) -> Option<LifecycleRecord> {
    handle
        .admin
        .query_opt(
            "SELECT e.op, e.reason_code, e.replacement_memory_id, e.idempotency_key, \
                    e.stream_seq IS NOT NULL AND e.commit_seq IS NOT NULL \
               FROM private.memory_records m \
               JOIN ops.memory_lifecycle_events e \
                 ON e.event_id = m.lifecycle_head_event_id AND e.memory_id = m.memory_id \
              WHERE m.tenant_id=$1 AND m.memory_id=$2",
            &[&handle.tenant_id, &memory_id],
        )
        .expect("lifecycle head read")
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4)))
}

fn head(handle: &mut Handle, note_id: Uuid) -> Option<Uuid> {
    handle
        .admin
        .query_opt(
            "SELECT head_memory_id FROM private.note_heads WHERE tenant_id=$1 AND note_id=$2",
            &[&handle.tenant_id, &note_id],
        )
        .expect("head row read")
        .map(|row| row.get(0))
}

fn versions(handle: &mut Handle, note_id: Uuid) -> i64 {
    handle
        .admin
        .query_one(
            "SELECT count(*) FROM private.memory_records WHERE tenant_id=$1 AND note_id=$2",
            &[&handle.tenant_id, &note_id],
        )
        .expect("version count")
        .get(0)
}

fn token_consumed(handle: &mut Handle, claim: &ConfirmationClaim) -> bool {
    handle
        .admin
        .query_one(
            "SELECT consumed_at IS NOT NULL FROM control.confirm_tokens WHERE nonce_sha256=$1",
            &[&claim.nonce_sha256.to_vec()],
        )
        .expect("token row")
        .get(0)
}

/// An ordinary (non-note) WORKSPACE_SHARED Memory with its PRIMARY Evidence, seeded by the owner — the control operand
/// for the governance gates.
fn plain_memory(handle: &mut Handle) -> Uuid {
    let tenant_id = handle.tenant_id;
    let workspace_id = handle.workspace_id;
    let reasoning_domain_id = handle.reasoning_domain_id;
    let mut txn = handle.admin.transaction().expect("begin plain memory seed");
    let evidence_id: Uuid = txn
        .query_one(
            "INSERT INTO private.evidence_objects \
               (tenant_id, evidence_kind, payload_sha256, data_class, origin_class, visibility_class, \
                visibility_workspace_id, reasoning_domain_id) \
             VALUES ($1, 'EVENT', $2, 'INTERNAL', 'DirectUserInput', 'WORKSPACE_SHARED', $3, $4) \
             RETURNING evidence_id",
            &[&tenant_id, &vec![5_u8; 32], &workspace_id, &reasoning_domain_id],
        )
        .expect("owner seeds plain evidence")
        .get(0);
    let memory_id: Uuid = txn
        .query_one(
            "INSERT INTO private.memory_records \
               (tenant_id, memory_type, content, visibility_class, visibility_workspace_id, authority_class, \
                confidence, status, asserted_at) \
             VALUES ($1, 'FACT', $2, 'WORKSPACE_SHARED', $3, 'PrivateKnowledge', 1.0, 'active', clock_timestamp()) \
             RETURNING memory_id",
            &[
                &tenant_id,
                &serde_json::json!({"title": "plain", "key_claim": "an ordinary memory"}),
                &workspace_id,
            ],
        )
        .expect("owner seeds plain memory")
        .get(0);
    txn.execute(
        "INSERT INTO private.memory_evidence (memory_id, evidence_id, role, grounding_mode) \
         VALUES ($1, $2, 'PRIMARY', 'SNAPSHOT')",
        &[&memory_id, &evidence_id],
    )
    .expect("owner links plain memory");
    txn.commit().expect("commit plain memory seed");
    memory_id
}

fn memory_of(result: &AtomicRememberResult) -> Uuid {
    result.memory_id.expect("a stored note names its memory")
}

// ---------------------------------------------------------------------------------------------------------------------
// Note identity: the create path (and 0236's backfill shape) — note_id = memory_id, head = itself.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn a_created_note_is_its_own_note_id_and_head() {
    run_db_fixture::<Fixture, _>("note_identity", |mut handle| {
        let editor = editor(&mut handle);
        let first = memory_of(&create(&handle, &editor, "a fresh note", NoteKind::Note));
        let (status, superseded_by, note_id, note_kind) = version(&mut handle, first);
        assert_eq!(
            (status.as_str(), superseded_by, note_kind.as_deref()),
            ("active", None, Some("note"))
        );
        assert_eq!(
            note_id,
            Some(first),
            "a fresh note's note_id is its first version's memory_id"
        );
        assert_eq!(
            head(&mut handle, first),
            Some(first),
            "the note's head row is born pointing at it"
        );
        // A non-note Memory carries no note_id (the 0236 CHECK pairs it with note_kind).
        let plain = plain_memory(&mut handle);
        assert_eq!(version(&mut handle, plain).2, None);
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// G28: one success = exactly one of each, zero LLM jobs; the old row is superseded, the head moves; refusals and replays
// add nothing.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)] // one causal chain: replace, its side-effect deltas, then the refused and replayed legs
fn g28_one_replacement_adds_exactly_one_version_and_moves_the_head() {
    run_db_fixture::<Fixture, _>("g28_replace_counts", |mut handle| {
        let editor = editor(&mut handle);
        let first = memory_of(&create(&handle, &editor, "decide: v1", NoteKind::Decision));
        let intent = Intent::new(first, first, "learned: v2", NoteKind::Lesson);
        let before = residue(&mut handle);

        // The challenge leg writes nothing and bills nothing.
        assert!(matches!(
            replace(&handle, &editor, &intent, None),
            Ok(NoteReplaceOutcome::Confirmable)
        ));
        assert_eq!(residue(&mut handle), before, "a challenge writes nothing");

        let token = mint(&handle, &editor, &intent, TOKEN_TTL);
        let done = stored(replace(
            &handle,
            &editor,
            &intent,
            Some(presented(&token, &intent)),
        ));
        assert!(!done.replayed);
        let second = memory_of(&done);
        let after = residue(&mut handle);
        assert_eq!(
            Residue {
                evidence: after.evidence - before.evidence,
                memories: after.memories - before.memories,
                primary_links: after.primary_links - before.primary_links,
                contracts: after.contracts - before.contracts,
                receipts: after.receipts - before.receipts,
                consumed_bmo: after.consumed_bmo - before.consumed_bmo,
                consumed_tokens: after.consumed_tokens - before.consumed_tokens,
                llm_jobs: after.llm_jobs,
                lifecycle_events: after.lifecycle_events - before.lifecycle_events,
            },
            Residue {
                evidence: 1,
                memories: 1,
                primary_links: 1,
                contracts: 1,
                receipts: 1,
                consumed_bmo: 1,
                consumed_tokens: 1,
                llm_jobs: 0,
                lifecycle_events: 1,
            },
            "one replacement = one Evidence / Memory / PRIMARY link / contract / receipt / BMO / token / lifecycle \
             event, no LLM job"
        );
        assert_eq!(
            supersede_record(&mut handle, first),
            Some((
                "SUPERSEDE".to_owned(),
                Some("EXPLICIT_SUPERSEDE".to_owned()),
                Some(second),
                hex::encode(token.nonce_sha256),
                true,
            )),
            "the old version's lifecycle head is the SUPERSEDE event memory.supersede writes, naming the new version"
        );
        assert_eq!(
            version(&mut handle, first),
            (
                "superseded".to_owned(),
                Some(second),
                Some(first),
                Some("decision".to_owned())
            ),
            "the old version is superseded by the new one and keeps its own kind"
        );
        assert_eq!(
            version(&mut handle, second),
            (
                "active".to_owned(),
                None,
                Some(first),
                Some("lesson".to_owned())
            ),
            "the new version joins the note and may carry another kind"
        );
        assert_eq!(head(&mut handle, first), Some(second), "the head moved");

        // A replay adds nothing and answers the original ids.
        let replay = stored(replace(
            &handle,
            &editor,
            &intent,
            Some(presented(&token, &intent)),
        ));
        assert!(replay.replayed);
        assert_eq!(replay.memory_id, done.memory_id);
        assert_eq!(replay.accepted.evidence_id, done.accepted.evidence_id);
        assert_eq!(residue(&mut handle), after, "a replay writes nothing");

        // A stale refusal adds nothing either.
        let stale = Intent::new(first, first, "too late", NoteKind::Lesson);
        assert!(matches!(
            replace(&handle, &editor, &stale, None),
            Ok(NoteReplaceOutcome::StaleVersion)
        ));
        let stale_token = mint(&handle, &editor, &stale, TOKEN_TTL);
        assert!(matches!(
            replace(
                &handle,
                &editor,
                &stale,
                Some(presented(&stale_token, &stale))
            ),
            Ok(NoteReplaceOutcome::StaleVersion)
        ));
        assert_eq!(residue(&mut handle), after, "a refusal writes nothing");
        assert!(!token_consumed(&mut handle, &stale_token));
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// G19: the same key + intent concurrently is one version; the same key with another intent is CONFLICT.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn g19_the_same_key_concurrently_is_one_version_and_another_intent_conflicts() {
    run_db_fixture::<Fixture, _>("g19_same_key", |mut handle| {
        let editor = editor(&mut handle);
        let first = memory_of(&create(&handle, &editor, "g19 v1", NoteKind::State));
        let intent = Intent::new(first, first, "g19 v2", NoteKind::State);
        let token = mint(&handle, &editor, &intent, TOKEN_TTL);
        let start = Arc::new(Barrier::new(2));
        let actors: Vec<_> = (0..2)
            .map(|n| {
                spawn_replace(
                    handle.gateway_application_dsn(&format!("g19-{n}-{}", Uuid::new_v4().simple())),
                    editor.auth.clone(),
                    replace_parts(&handle, &editor, &intent, Some(presented(&token, &intent))),
                    Arc::clone(&start),
                )
            })
            .collect();
        let outcomes: Vec<_> = actors
            .into_iter()
            .map(|actor| actor.join().expect("actor joined"))
            .collect();
        let winners: Vec<&AtomicRememberResult> = outcomes
            .iter()
            .filter_map(|outcome| match outcome {
                Ok(NoteReplaceOutcome::Stored(result)) if !result.replayed => Some(result),
                _ => None,
            })
            .collect();
        assert_eq!(winners.len(), 1, "exactly one new version: {outcomes:?}");
        let winner = memory_of(winners[0]);
        for outcome in &outcomes {
            match outcome {
                Ok(NoteReplaceOutcome::Stored(result)) => {
                    assert_eq!(
                        result.memory_id,
                        Some(winner),
                        "a replay names the same version"
                    );
                }
                // The receipt's advisory lock refuses a same-key call while the other is in flight (§34.0.1).
                Err(ErrorCode::Conflict) => {}
                other => panic!("unexpected same-key outcome {other:?}"),
            }
        }
        // Retried after both settle, the key answers its stored result.
        let retry = stored(replace(
            &handle,
            &editor,
            &intent,
            Some(presented(&token, &intent)),
        ));
        assert!(retry.replayed);
        assert_eq!(retry.memory_id, Some(winner));
        assert_eq!(versions(&mut handle, first), 2, "two versions, never three");

        // The same key with another body is another intent: CONFLICT, nothing written.
        let before = residue(&mut handle);
        let mut edited = intent.clone();
        edited.body = "g19 v2, edited".into();
        assert!(matches!(
            replace(&handle, &editor, &edited, Some(presented(&token, &edited))),
            Err(ErrorCode::Conflict)
        ));
        assert_eq!(residue(&mut handle), before);
        assert_eq!(versions(&mut handle, first), 2);
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// G20: two editors on one old version — exactly one wins, the other is STALE_NOTE_VERSION; the EXCLUDE holds one active
// version per note even when the CAS is bypassed.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)] // one barrier race plus the EXCLUDE witness on the same note
fn g20_two_editors_one_wins_and_the_exclude_keeps_one_active_version() {
    run_db_fixture::<Fixture, _>("g20_two_editors", |mut handle| {
        let editor = editor(&mut handle);
        let first = memory_of(&create(&handle, &editor, "g20 v1", NoteKind::Problem));
        let intents = [
            Intent::new(first, first, "g20 editor A", NoteKind::Problem),
            Intent::new(first, first, "g20 editor B", NoteKind::Fix),
        ];
        let tokens: Vec<ConfirmationClaim> = intents
            .iter()
            .map(|intent| mint(&handle, &editor, intent, TOKEN_TTL))
            .collect();
        let names: Vec<String> = (0..2)
            .map(|n| format!("g20-{n}-{}", Uuid::new_v4().simple()))
            .collect();

        // The owner holds the note's head row: both editors pass their receipt check and park on FOR UPDATE.
        let mut owner = handle.owner_client().expect("owner barrier");
        let mut holder = owner.transaction().expect("barrier transaction");
        holder
            .execute(
                "SELECT 1 FROM private.note_heads WHERE tenant_id=$1 AND note_id=$2 FOR UPDATE",
                &[&handle.tenant_id, &first],
            )
            .expect("hold the head row");
        let start = Arc::new(Barrier::new(2));
        let actors: Vec<_> = intents
            .iter()
            .zip(&tokens)
            .zip(&names)
            .map(|((intent, token), name)| {
                spawn_replace(
                    handle.gateway_application_dsn(name),
                    editor.auth.clone(),
                    replace_parts(&handle, &editor, intent, Some(presented(token, intent))),
                    Arc::clone(&start),
                )
            })
            .collect();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let waiting: i64 = handle
                .admin
                .query_one(
                    "SELECT count(*) FROM pg_stat_activity WHERE application_name = ANY($1) \
                       AND wait_event_type='Lock'",
                    &[&names],
                )
                .expect("inspect editors")
                .get(0);
            if waiting == 2 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "both editors must reach the head lock"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        holder.rollback().expect("release the head row");
        drop(owner);
        let outcomes: Vec<_> = actors
            .into_iter()
            .map(|actor| actor.join().expect("editor joined"))
            .collect();
        let winner: Vec<(usize, Uuid)> = outcomes
            .iter()
            .enumerate()
            .filter_map(|(n, outcome)| match outcome {
                Ok(NoteReplaceOutcome::Stored(result)) if !result.replayed => {
                    Some((n, memory_of(result)))
                }
                _ => None,
            })
            .collect();
        assert_eq!(winner.len(), 1, "exactly one editor wins: {outcomes:?}");
        let (won, winner) = winner[0];
        let lost = 1 - won;
        assert!(
            matches!(outcomes[lost], Ok(NoteReplaceOutcome::StaleVersion)),
            "the other editor is STALE_NOTE_VERSION: {:?}",
            outcomes[lost]
        );
        assert!(
            !token_consumed(&mut handle, &tokens[lost]),
            "the loser's token is not spent"
        );
        assert_eq!(head(&mut handle, first), Some(winner));
        assert_eq!(versions(&mut handle, first), 2);

        // EXCLUDE witness: reviving the superseded version beside the head is refused at COMMIT, whoever writes it.
        let mut owner = handle.owner_client().expect("owner writer");
        let mut forced = owner.transaction().expect("owner transaction");
        let revived = forced
            .execute(
                "UPDATE private.memory_records \
                    SET status='active', superseded_by=NULL, superseded_at=NULL \
                  WHERE tenant_id=$1 AND memory_id=$2",
                &[&handle.tenant_id, &first],
            )
            .expect("the deferred EXCLUDE lets the statement through");
        assert_eq!(revived, 1);
        let error = forced
            .commit()
            .expect_err("two active versions of one note never commit");
        assert_eq!(
            error.code(),
            Some(&SqlState::EXCLUSION_VIOLATION),
            "refused by memory_records_one_active_note_version: {error:?}"
        );
        assert_eq!(version(&mut handle, first).0, "superseded");
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// G21: no replacement executes without a valid confirmation bound to exactly this intent.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)] // one note, every way to present a wrong token, then the valid one and its retries
fn g21_no_replacement_without_a_confirmation_of_exactly_this_intent() {
    run_db_fixture::<Fixture, _>("g21_confirmation", |mut handle| {
        let editor = editor(&mut handle);
        let first = memory_of(&create(&handle, &editor, "g21 note A", NoteKind::Decision));
        let other = memory_of(&create(&handle, &editor, "g21 note B", NoteKind::Decision));
        let intent = Intent::new(first, first, "g21 note A, v2", NoteKind::Decision);
        let before = residue(&mut handle);

        // No token: a challenge, nothing written.
        assert!(matches!(
            replace(&handle, &editor, &intent, None),
            Ok(NoteReplaceOutcome::Confirmable)
        ));
        let token = mint(&handle, &editor, &intent, TOKEN_TTL);

        // The token presented with a changed body, title, kind or authority, for another note, or under another key.
        let mut changed = Vec::new();
        let mut body = intent.clone();
        body.body = "g21 note A, v2 (edited)".into();
        changed.push(("body", body));
        let mut title = intent.clone();
        title.title = Some("another title".into());
        changed.push(("title", title));
        let mut kind = intent.clone();
        kind.kind = NoteKind::Rejected;
        changed.push(("kind", kind));
        let mut authority = intent.clone();
        authority.requested = AuthorityClass::PublicKnowledge;
        changed.push(("authority", authority));
        changed.push((
            "another note",
            Intent {
                note_id: other,
                supersedes: other,
                ..intent.clone()
            },
        ));
        let mut key = intent.clone();
        key.key = format!("replace-{}", Uuid::new_v4());
        changed.push(("another key", key));
        for (label, changed) in &changed {
            assert!(
                matches!(
                    replace(&handle, &editor, changed, Some(presented(&token, changed))),
                    Err(ErrorCode::Conflict)
                ),
                "{label}: the token does not confirm this request"
            );
        }
        // The token's own digest presented with a changed request is refused before the database.
        assert!(matches!(
            replace(&handle, &editor, &changed[0].1, Some(token.clone())),
            Err(ErrorCode::Conflict)
        ));
        // An expired token is refused.
        let late = Intent::new(first, first, "g21 late", NoteKind::Decision);
        let expired = mint(&handle, &editor, &late, Duration::from_secs(1));
        std::thread::sleep(Duration::from_millis(1500));
        assert!(matches!(
            replace(&handle, &editor, &late, Some(presented(&expired, &late))),
            Err(ErrorCode::Conflict)
        ));
        assert_eq!(
            residue(&mut handle),
            before,
            "no refused leg wrote anything"
        );
        assert!(!token_consumed(&mut handle, &token));
        assert_eq!(head(&mut handle, first), Some(first));

        // The valid token commits once; retries of the committed key answer the receipt, with or without the token.
        let done = stored(replace(
            &handle,
            &editor,
            &intent,
            Some(presented(&token, &intent)),
        ));
        assert!(!done.replayed);
        let after = residue(&mut handle);
        for retry in [Some(presented(&token, &intent)), None] {
            let replay = stored(replace(&handle, &editor, &intent, retry));
            assert!(replay.replayed);
            assert_eq!(replay.memory_id, done.memory_id);
        }
        assert_eq!(
            residue(&mut handle),
            after,
            "a retry neither consumes, writes nor bills"
        );

        // A note token cannot be spent by another consumer: memory.correct's consume binds request_sha256 NULL.
        let plain = plain_memory(&mut handle);
        let nonce: [u8; 32] = [*Uuid::new_v4().as_bytes(), *Uuid::new_v4().as_bytes()]
            .concat()
            .try_into()
            .expect("32 bytes");
        let mut correct_audit = audit(&handle, &editor, Uuid::new_v4(), true);
        correct_audit.resource_id = DestructiveOp::MemoryCorrect.operation_key().into();
        handle
            .rt
            .block_on(confirm_token_repo::mint_with_audit(
                &handle.runtime,
                &editor.auth,
                DestructiveOp::MemoryCorrect,
                plain,
                None,
                TOKEN_TTL,
                nonce,
                Some(intent.digest()),
                &correct_audit,
            ))
            .expect("mint an intent-bound correct token");
        let request_id = Uuid::new_v4();
        let mut finished = audit(&handle, &editor, request_id, false);
        finished.resource_id = DestructiveOp::MemoryCorrect.operation_key().into();
        let content = serde_json::Value::String("corrected".into());
        let refused =
            handle
                .rt
                .block_on(humaux_adapters::memory_governance_repo::correct_atomically(
                    &handle.runtime,
                    &editor.auth,
                    humaux_adapters::memory_governance_repo::CorrectRequest {
                        request_id,
                        request_fingerprint: "f".repeat(64),
                        reservation_ttl: Duration::from_secs(30),
                        target: humaux_domain::authority::MemoryId(plain),
                        payload_sha256: payload_sha256(
                            &serde_json::to_vec(&content).expect("json bytes"),
                        ),
                        content,
                        stream: governance_ops::stream(handle.tenant_id, handle.workspace_id),
                        claim: ConfirmationClaim {
                            op: DestructiveOp::MemoryCorrect,
                            target_id: plain,
                            successor_id: None,
                            nonce_sha256: nonce,
                            request_sha256: None,
                        },
                        finished_audit: finished,
                        undo_window: Duration::from_secs(86_400),
                        consistency_token_ttl: Duration::from_secs(600),
                        subjects: humaux_domain::subject::SubjectDeclaration::default(),
                        affects: Vec::new(),
                        mood_half_life: None,
                    },
                    &humaux_adapters::attribution_repo::AttributionLadder,
                ));
        assert!(
            matches!(refused, Err(ErrorCode::Conflict)),
            "an intent-bound token never matches a NULL-bound consume: {:?}",
            refused.map(|done| done.new_memory_id)
        );
        let still_unspent: bool = handle
            .admin
            .query_one(
                "SELECT consumed_at IS NULL FROM control.confirm_tokens WHERE nonce_sha256=$1",
                &[&nonce.to_vec()],
            )
            .expect("token row")
            .get(0);
        assert!(still_unspent);
        // Control: the same consumer spends a NULL-bound token on the same memory.
        governance_ops::correct(
            &handle.rt,
            &handle.runtime,
            &editor.auth,
            &governance_ops::stream(handle.tenant_id, handle.workspace_id),
            plain,
            "corrected",
        )
        .expect("a NULL-bound correct token is spent by memory.correct");
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// G26: memory.correct / supersede / restore on a note are CONFLICT; archive stays per version and never moves the head.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn g26_generic_governance_refuses_a_note_and_archive_never_moves_the_head() {
    run_db_fixture::<Fixture, _>("g26_governance", |mut handle| {
        let editor = editor(&mut handle);
        let note = memory_of(&create(&handle, &editor, "g26 note", NoteKind::Preference));
        let other = memory_of(&create(&handle, &editor, "g26 other", NoteKind::Preference));
        let plain = plain_memory(&mut handle);
        let stream = governance_ops::stream(handle.tenant_id, handle.workspace_id);
        let before = residue(&mut handle);
        {
            let (rt, pool, auth) = (&handle.rt, &handle.runtime, &editor.auth);
            assert!(matches!(
                governance_ops::correct(rt, pool, auth, &stream, note, "rewritten"),
                Err(ErrorCode::Conflict)
            ));
            for (target, successor) in [(note, other), (plain, note), (note, plain)] {
                assert!(
                    matches!(
                        governance_ops::supersede(rt, pool, auth, &stream, target, successor),
                        Err(ErrorCode::Conflict)
                    ),
                    "supersede {target} with {successor}: a note operand is refused"
                );
            }
            assert!(matches!(
                governance_ops::restore(rt, pool, auth, &stream, note),
                Err(ErrorCode::Conflict)
            ));
        }
        let after = residue(&mut handle);
        assert_eq!(
            (after.consumed_tokens, after.consumed_bmo, after.memories),
            (before.consumed_tokens, before.consumed_bmo, before.memories),
            "a refused governance op spends no token, no BMO and writes no version"
        );
        assert_eq!(version(&mut handle, note).0, "active");
        assert_eq!(head(&mut handle, note), Some(note));

        // Archive is per version and leaves the head alone; an archived head cannot be replaced.
        let archived = governance_ops::archive(
            &handle.rt,
            &handle.runtime,
            &editor.auth,
            &stream,
            note,
            DestructiveOp::MemoryArchive,
        );
        assert!(
            matches!(archived, Ok(ArchiveResult::Done(_))),
            "{archived:?}"
        );
        assert_eq!(head(&mut handle, note), Some(note));
        let intent = Intent::new(note, note, "g26 v2", NoteKind::Preference);
        assert!(matches!(
            replace(&handle, &editor, &intent, None),
            Err(ErrorCode::Conflict)
        ));
        let unarchived = governance_ops::archive(
            &handle.rt,
            &handle.runtime,
            &editor.auth,
            &stream,
            note,
            DestructiveOp::MemoryUnarchive,
        );
        assert!(
            matches!(unarchived, Ok(ArchiveResult::Done(_))),
            "{unarchived:?}"
        );
        assert_eq!(head(&mut handle, note), Some(note));
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// G27: a tombstoned head cannot be replaced.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn g27_a_tombstoned_head_cannot_be_replaced() {
    run_db_fixture::<Fixture, _>("g27_tombstoned_head", |mut handle| {
        let editor = editor(&mut handle);
        let created = create(&handle, &editor, "g27 forget me", NoteKind::Research);
        let first = memory_of(&created);
        let intent = Intent::new(first, first, "g27 v2", NoteKind::Research);
        assert!(
            matches!(
                replace(&handle, &editor, &intent, None),
                Ok(NoteReplaceOutcome::Confirmable)
            ),
            "control: replaceable before the tombstone"
        );
        let token = mint(&handle, &editor, &intent, TOKEN_TTL);
        let stream_seq: i64 = handle
            .admin
            .query_one(
                "SELECT sl.stream_seq FROM ops.outbox ob \
                 JOIN projection.stream_log sl \
                   ON sl.tenant_id = ob.tenant_id AND sl.commit_seq = ob.commit_seq \
                 WHERE ob.tenant_id = $1 AND ob.evidence_id = $2",
                &[&handle.tenant_id, &created.accepted.evidence_id],
            )
            .expect("the note's stream entry")
            .get(0);
        let key = StreamKey::new(
            TenantId(handle.tenant_id),
            "workspace",
            handle.workspace_id,
            DOMAIN,
            PROJECTION_KIND,
            PROJECTION_VERSION,
        );
        let tombstoned = handle
            .rt
            .block_on(forget_repo::tombstone(
                &handle.maintenance,
                &key,
                u64::try_from(stream_seq).expect("nonnegative seq"),
            ))
            .expect("role_maintenance tombstone");
        assert!(tombstoned, "this call performed the transition");
        let before = residue(&mut handle);
        assert!(matches!(
            replace(&handle, &editor, &intent, None),
            Err(ErrorCode::NotFound)
        ));
        // #273 F1: the refused transaction's rollback is asynchronous, so the confirmed leg could reach another pooled
        // connection while its receipt key is still held and answer CONFLICT instead of the tombstoned head's NOT_FOUND.
        await_receipt_lock_release(&mut handle, &editor, &intent);
        assert!(matches!(
            replace(&handle, &editor, &intent, Some(presented(&token, &intent))),
            Err(ErrorCode::NotFound)
        ));
        assert_eq!(residue(&mut handle), before);
        assert!(!token_consumed(&mut handle, &token));
        assert_eq!(head(&mut handle, first), Some(first));
    });
}

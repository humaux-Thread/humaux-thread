//! `adapters::tests::note_text_once` — M07 D1 (ADR-0085), view half of G-M07-3: `private.memory_text_v` resolves an identity
//!   note's body from its Evidence payload and any other Memory's body from `content.key_claim`, and the Rust accessor
//!   returns exactly that, against a real PostgreSQL and an actual `role_gateway` role.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, serde_json, sqlx];
//!   services=[PostgreSQL(owner) w=[private.events, private.identity_note_materializations, private.memory_records], PostgreSQL(role_gateway)];
//!   env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::attribution_repo, adapters::memory_repo, adapters::operation_receipt,
//!   adapters::note_repo, adapters::remember, adapters::tests::support::operation_receipt_fixture, domain::audit,
//!   domain::evidence, domain::ids, domain::note, domain::subject, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [notes enter through the real `memory.note_put` transaction; the text is read back only through
//!   `memory_repo::memory_texts_in_txn` under `SET LOCAL ROLE role_gateway` with the member's RLS context, in a transaction
//!   that is rolled back; the owner connection only reshapes this fixture's rows (the stripped identity note M07-3 will
//!   write, the legacy twin) under `session_replication_role = replica`]
//! Spec: Baseline §8.2; §8.5; ADR-0067; ADR-0085
//!
//! | test | gate | injected fault that turns it red |
//! |---|---|---|
//! | `g_m07_3_the_view_resolves_identity_and_legacy_text_alike` | G-M07-3 (view half) | the view returns the title as the body of a non-identity Memory; the identity branch falls back to `key_claim` / drops the `jsonb_typeof` guard |
//!
//! called-by: `cargo test -p humaux-adapters --test note_text_once`.

use std::time::{Duration, SystemTime};

use humaux_adapters::{
    memory_repo::{self, MemoryText},
    note_repo::NoteIntake,
    operation_receipt::{self, AtomicRememberRequest, AtomicRememberResult, NOTE_OPERATION},
    remember::RememberCommand,
};
use humaux_domain::{
    audit::{AuditEvent, AuditEventId, AuditMetadata, McpAuditAction},
    evidence::{EvidenceOriginClass, payload_sha256},
    ids::{TenantId, WorkspaceId},
    note::{DEFAULT_AUTHORITY, NoteBody, NoteKind, note_title},
};
use humaux_testkit::run_db_fixture;
use sqlx::types::{Uuid, time::OffsetDateTime};
use sqlx::{Connection, PgConnection};

#[allow(dead_code)]
#[path = "support/operation_receipt_fixture.rs"]
mod operation_receipt_fixture;

use operation_receipt_fixture::{DOMAIN, Fixture, Handle, PROJECTION_KIND, PROJECTION_VERSION};

/// Longer than the 80-scalar derived-title cut, with a newline, quotes, a backslash, a non-BMP scalar, and leading and
/// trailing blanks: every byte must survive the JSON string round trip through `events.payload`, and title and body differ.
const IDENTITY_BODY: &str = "  First line with \"quotes\", a back\\slash and a \u{1F4A1} emoji, padded well past the eighty-scalar derived-title cut so title and body differ.\n\tSecond line, indented, trailing blanks   \n";
/// A third note, whose Evidence payload the test turns into a JSON object.
const GUARDED_BODY: &str =
    "Guarded note: the writer stored this text as key_claim and as the payload string.";
/// The legacy twin's body as the note put wrote it.
const LEGACY_PUT_BODY: &str =
    "Legacy twin, as the writer stored it: the body is also the key_claim.";
/// What the legacy twin's `key_claim` is rewritten to, so a view that read its Evidence payload instead is caught.
const LEGACY_KEY_CLAIM: &str = "Legacy twin key_claim that is not the Evidence payload.";

fn finished_audit(handle: &Handle, request_id: Uuid) -> AuditEvent {
    let mut metadata = AuditMetadata::new();
    metadata
        .insert("role", "member")
        .expect("allowlisted audit metadata");
    AuditEvent {
        event_id: AuditEventId::new(),
        ts: SystemTime::now(),
        tenant_id: TenantId(handle.tenant_id),
        actor_type: "user".into(),
        actor_id: handle.principal_id.to_string(),
        action: McpAuditAction::McpRequestFinished.as_str().into(),
        resource_type: "mcp".into(),
        resource_id: NOTE_OPERATION.into(),
        result: "OK".into(),
        request_id: request_id.to_string(),
        trace_id: format!("note-text-once-{request_id}"),
        client_ip: "127.0.0.1".into(),
        user_agent_hash: "note-text-once-test".into(),
        risk_tags: vec!["fixture".into()],
        before_fingerprint: None,
        after_fingerprint: None,
        metadata,
    }
}

/// What the gateway edge builds for one note (copied from `note_reads.rs`; test files do not import each other).
fn note_request(
    handle: &Handle,
    body: &str,
    kind: NoteKind,
) -> (AtomicRememberRequest, NoteIntake) {
    let raw = serde_json::to_vec(&serde_json::Value::String(body.to_owned())).expect("string");
    let request_id = Uuid::new_v4();
    let command = RememberCommand {
        tenant_id: handle.tenant_id,
        authorization_user_id: Some(handle.user_id),
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
        origin_principal_id: Some(handle.principal_id),
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
    };
    let verbatim = NoteBody::new(body).expect("test body is valid");
    let title = note_title(None, &verbatim).expect("derived title");
    (
        AtomicRememberRequest {
            request_id,
            idempotency_key: format!("note-text-once-{request_id}"),
            request_fingerprint: "c".repeat(64),
            workspace_id: Some(WorkspaceId(handle.workspace_id)),
            reservation_ttl: Duration::from_secs(30),
            replay_ttl: Duration::from_secs(60),
            command,
            finished_audit: finished_audit(handle, request_id),
        },
        NoteIntake {
            kind,
            title,
            body: verbatim,
            requested: DEFAULT_AUTHORITY,
        },
    )
}

/// Stores one note through the real `memory.note_put` transaction and returns its Memory.
fn put(handle: &Handle, body: &str, kind: NoteKind) -> Uuid {
    let (request, note) = note_request(handle, body, kind);
    let result: AtomicRememberResult = handle
        .rt
        .block_on(operation_receipt::note_put_atomically(
            &handle.runtime,
            &handle.auth,
            request,
            note,
            &humaux_adapters::attribution_repo::AttributionLadder,
        ))
        .expect("note commits");
    result.memory_id.expect("a stored note names its memory")
}

/// The title `memory.note_put` stores for `body` when the caller gives none.
fn derived_title(body: &str) -> String {
    note_title(None, &NoteBody::new(body).expect("test body is valid")).expect("derived title")
}

/// `memory_texts_in_txn` as the member under `role_gateway`, in a transaction that is rolled back.
fn texts(handle: &Handle, ids: &[Uuid]) -> Vec<MemoryText> {
    let dsn = std::env::var("HUMAUX_TEST_PG_DSN").expect("the fixture ran, so the DSN is set");
    handle.rt.block_on(async {
        // dep: PostgreSQL(owner) — test opens a direct PG connection for setup/verification
        let mut conn = PgConnection::connect(&dsn).await.expect("owner connection");
        // dep: PostgreSQL(any) — pool/txn query execution
        let mut txn = conn.begin().await.expect("begin");
        sqlx::query(
            "SELECT set_config('humaux.tenant_id', $1, true), set_config('humaux.user_id', $2, true)",
        )
        .bind(handle.tenant_id.to_string())
        .bind(handle.user_id.to_string())
        .execute(&mut *txn)
        .await
        .expect("the member's RLS context");
        // dep: PostgreSQL(role_gateway) — test switches PG role to exercise RLS
        sqlx::query("SET LOCAL ROLE role_gateway")
            .execute(&mut *txn)
            .await
            .expect("role_gateway");
        let rows = memory_repo::memory_texts_in_txn(&mut txn, handle.tenant_id, ids)
            .await
            .expect("the accessor reads the view");
        txn.rollback().await.expect("rollback");
        rows
    })
}

fn row(rows: &[MemoryText], id: Uuid) -> MemoryText {
    rows.iter()
        .find(|r| r.memory_id == id)
        .cloned()
        .expect("the memory has a row in the view")
}

/// G-M07-3, view half. Two notes written by the real writer, then reshaped: the identity note into the stripped shape card
/// M07-3 will write (no `key_claim`), the other into the legacy shape (no identity contract, a `key_claim` that differs from
/// its Evidence payload). The view must give each its own text, byte for byte, with its own `title`.
#[test]
fn g_m07_3_the_view_resolves_identity_and_legacy_text_alike() {
    run_db_fixture::<Fixture, _>(
        "g_m07_3_the_view_resolves_identity_and_legacy_text_alike",
        |mut handle| {
            handle.seed_current_entitlement_and_window(8);
            let identity = put(&handle, IDENTITY_BODY, NoteKind::Note);
            let legacy = put(&handle, LEGACY_PUT_BODY, NoteKind::Decision);
            let (identity_title, legacy_title) =
                (derived_title(IDENTITY_BODY), derived_title(LEGACY_PUT_BODY));
            assert_ne!(
                identity_title, IDENTITY_BODY,
                "the fixture body must differ from its derived title"
            );

            // As the writer leaves them today: `key_claim` and the payload agree, and the view gives the body.
            let rows = texts(&handle, &[identity, legacy]);
            assert_eq!(rows.len(), 2);
            assert_eq!(row(&rows, identity).body.as_deref(), Some(IDENTITY_BODY));
            assert_eq!(
                row(&rows, identity).title.as_deref(),
                Some(identity_title.as_str())
            );
            assert_eq!(row(&rows, legacy).body.as_deref(), Some(LEGACY_PUT_BODY));
            assert_eq!(
                row(&rows, legacy).title.as_deref(),
                Some(legacy_title.as_str())
            );

            // No fallback on the identity branch: a payload that is not a JSON string reads NULL although `key_claim` holds
            // the text. This also gates the view's `jsonb_typeof` guard.
            let guarded = put(&handle, GUARDED_BODY, NoteKind::Note);
            let guarded_s = guarded.to_string();
            let tenant_s = handle.tenant_id;
            handle
                .admin
                .batch_execute(&format!(
                    "SET session_replication_role = replica; \
                     UPDATE private.events SET payload = '{{\"not\": \"a string\"}}'::jsonb \
                      WHERE event_id = (SELECT evidence_id FROM private.identity_note_materializations \
                                         WHERE tenant_id = '{tenant_s}' AND output_memory_id = '{guarded_s}'); \
                     SET session_replication_role = DEFAULT;"
                ))
                .expect("make the guarded note's Evidence payload a JSON object");
            let kept: bool = handle
                .admin
                .query_one(
                    "SELECT content ? 'key_claim' FROM private.memory_records WHERE memory_id = $1",
                    &[&guarded],
                )
                .expect("owner reads the guarded note")
                .get(0);
            assert!(kept, "the fixture must leave key_claim in place");
            let rows = texts(&handle, &[guarded]);
            assert_eq!(
                row(&rows, guarded).body,
                None,
                "a non-string payload must read NULL, not key_claim and not the JSON text"
            );

            // The identity note without its `key_claim`: the body can only come from the Evidence payload.
            let (tenant, identity_s, legacy_s) =
                (handle.tenant_id, identity.to_string(), legacy.to_string());
            handle
                .admin
                .batch_execute(&format!(
                    "SET session_replication_role = replica; \
                     UPDATE private.memory_records SET content = content - 'key_claim' \
                      WHERE tenant_id = '{tenant}' AND memory_id = '{identity_s}'; \
                     SET session_replication_role = DEFAULT;"
                ))
                .expect("strip the identity note's key_claim");
            let stripped: bool = handle
                .admin
                .query_one(
                    "SELECT NOT (content ? 'key_claim') FROM private.memory_records WHERE memory_id = $1",
                    &[&identity],
                )
                .expect("owner reads the identity note")
                .get(0);
            assert!(stripped, "the fixture must have removed key_claim");
            let rows = texts(&handle, &[identity]);
            assert_eq!(row(&rows, identity).body.as_deref(), Some(IDENTITY_BODY));
            assert_eq!(
                row(&rows, identity).title.as_deref(),
                Some(identity_title.as_str())
            );

            // The legacy twin: no identity contract, and a `key_claim` that is not its Evidence payload.
            handle
                .admin
                .batch_execute(&format!(
                    "SET session_replication_role = replica; \
                     DELETE FROM private.identity_note_materializations \
                      WHERE tenant_id = '{tenant}' AND output_memory_id = '{legacy_s}'; \
                     UPDATE private.memory_records \
                        SET content = jsonb_set(content, '{{key_claim}}', to_jsonb('{LEGACY_KEY_CLAIM}'::text)) \
                      WHERE tenant_id = '{tenant}' AND memory_id = '{legacy_s}'; \
                     SET session_replication_role = DEFAULT;"
                ))
                .expect("reshape the legacy twin");
            let rows = texts(&handle, &[identity, legacy]);
            assert_eq!(row(&rows, legacy).body.as_deref(), Some(LEGACY_KEY_CLAIM));
            assert_eq!(
                row(&rows, legacy).title.as_deref(),
                Some(legacy_title.as_str())
            );
            assert_eq!(row(&rows, identity).body.as_deref(), Some(IDENTITY_BODY));

            // Absent and empty inputs: no row for an unknown id, and no query for an empty slice.
            assert!(texts(&handle, &[Uuid::new_v4()]).is_empty());
            assert!(texts(&handle, &[]).is_empty());
        },
    );
}

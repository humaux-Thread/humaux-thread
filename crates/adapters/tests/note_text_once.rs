//! `adapters::tests::note_text_once` — M07 D1 (ADR-0085), G-M07-3: `private.memory_text_v` resolves an identity
//!   note's body from its Evidence payload and any other Memory's body from `content.key_claim`, the Rust accessor
//!   returns exactly that, and the body materializers behind memory.get, memory.enumerate and recall/context read the
//!   same text through the view, against a real PostgreSQL and an actual `role_gateway` role.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-projection, humaux-testkit, serde_json, sqlx];
//!   services=[PostgreSQL(owner) w=[private.events, private.identity_note_materializations, private.memory_records],
//!   PostgreSQL(role_gateway)];
//!   env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::attribution_repo, adapters::memory_repo, adapters::operation_receipt,
//!   adapters::note_repo, adapters::read_gate, adapters::read_materialize, adapters::remember,
//!   adapters::tests::support::operation_receipt_fixture, domain::audit, domain::authority, domain::evidence,
//!   domain::ids, domain::note, domain::subject, humaux-testkit, projection::serving, projection::stream]
//! Called-by: [cargo-test]
//! Invariants: [notes enter through the real `memory.note_put` transaction; the text is read back only through
//!   `memory_repo::memory_texts_in_txn` and the production body materializers, under `SET LOCAL ROLE role_gateway`
//!   with the member's RLS context, in a transaction that is rolled back; the owner connection only reshapes this
//!   fixture's rows (the stripped identity note M07-3 will write, the legacy twin) under
//!   `session_replication_role = replica`]
//! Spec: Baseline §8.2; §8.5; ADR-0067; ADR-0085
//!
//! | test | gate | injected fault that turns it red |
//! |---|---|---|
//! | `g_m07_3_the_view_resolves_identity_and_legacy_text_alike` | G-M07-3 (view half) | the view returns the title as the body of a non-identity Memory; the identity branch falls back to `key_claim` / drops the `jsonb_typeof` guard |
//! | `g_m07_3_the_body_readers_resolve_text_through_the_view` | G-M07-3 (reader half) | a body reader takes `content ->> 'key_claim'` instead of the view's `body` |
//!
//! called-by: `cargo test -p humaux-adapters --test note_text_once`.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use humaux_adapters::{
    memory_repo::{self, MemoryText},
    note_repo::NoteIntake,
    operation_receipt::{self, AtomicRememberRequest, AtomicRememberResult, NOTE_OPERATION},
    read_gate::{
        MaterializedMemory, MaterializedMemoryPage, MemoryEnumerationParams, NoteEnumerationFilter,
        materialize_memory_enumeration_filtered, materialize_memory_get,
    },
    read_materialize::{MaterializedBodies, MaterializedItem, materialize_final_bodies},
    remember::RememberCommand,
};
use humaux_domain::{
    audit::{AuditEvent, AuditEventId, AuditMetadata, McpAuditAction},
    authority::MemoryId,
    evidence::{EvidenceOriginClass, payload_sha256},
    ids::{Scope, TenantId, UserId, WorkspaceId},
    note::{DEFAULT_AUTHORITY, NoteBody, NoteKind, REPRESENTATION, note_title},
};
use humaux_projection::{serving::StreamFamily, stream::StreamKey};
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
/// A note that keeps the shape the writer stores today, as the parity control for the two reshaped twins.
const NORMAL_BODY: &str = "An ordinary note, whose key_claim and Evidence payload agree.";
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

/// The manifest's page-cursor MAC key (ADR-0062 D-K); a test constant, never a configured secret.
const MAC_KEY: &[u8] = b"card m08-2 memory text parity mac key";

fn scope(handle: &Handle) -> Scope {
    Scope {
        tenant_id: TenantId(handle.tenant_id),
        user_id: Some(UserId(handle.user_id)),
        workspace_id: Some(WorkspaceId(handle.workspace_id)),
        repository_id: None,
        task_id: None,
        run_id: None,
        agent_id: None,
    }
}

/// The note write path's own stream (`workspace`, knowledge, ingest, v1).
fn family(handle: &Handle) -> StreamFamily {
    StreamFamily::new(
        TenantId(handle.tenant_id),
        "workspace",
        handle.workspace_id,
        DOMAIN,
        PROJECTION_KIND,
    )
}

fn key(handle: &Handle) -> StreamKey {
    family(handle).with_version(PROJECTION_VERSION)
}

/// The `memory.get` body reader, as the gateway calls it.
fn get_body(handle: &Handle, memory_id: Uuid) -> MaterializedMemory {
    handle
        .rt
        .block_on(materialize_memory_get(
            &handle.runtime,
            &handle.auth,
            &scope(handle),
            &family(handle),
            &key(handle),
            MemoryId(memory_id),
        ))
        .expect("memory.get materializes")
}

/// The `memory.enumerate` body reader, one unfiltered page.
fn enumerate_bodies(handle: &Handle, page_size: u16) -> MaterializedMemoryPage {
    handle
        .rt
        .block_on(materialize_memory_enumeration_filtered(
            &handle.runtime,
            &handle.auth,
            &scope(handle),
            &family(handle),
            &key(handle),
            MemoryEnumerationParams {
                cursor: None,
                page_size,
                ttl: Duration::from_secs(60),
                manifest_cap: 1000,
                mac_key: MAC_KEY,
                subject_id: None,
            },
            &NoteEnumerationFilter::default(),
        ))
        .expect("memory.enumerate materializes")
}

/// The recall/context/continuity body reader (`materialize_final_bodies`, `Lifecycle::CURRENT`).
fn recall_bodies(handle: &Handle, ids: &[Uuid]) -> MaterializedBodies {
    handle
        .rt
        .block_on(materialize_final_bodies(
            &handle.runtime,
            &handle.auth,
            &family(handle),
            &key(handle),
            ids,
            &[],
        ))
        .expect("final bodies")
}

/// `memory_id → content` for the Memory items `items` holds, asserting every item is a Memory.
fn memory_contents(items: &[MaterializedItem]) -> BTreeMap<Uuid, serde_json::Value> {
    let mut contents = BTreeMap::new();
    for item in items {
        match item {
            MaterializedItem::Memory { memory_id, content } => {
                assert!(
                    contents.insert(*memory_id, content.clone()).is_none(),
                    "one Memory item per id"
                );
            }
            other => panic!("a body read returns Memory items only, got {other:?}"),
        }
    }
    contents
}

/// The exact item set of a body read, sorted.
fn ids_of(contents: &BTreeMap<Uuid, serde_json::Value>) -> Vec<Uuid> {
    contents.keys().copied().collect()
}

/// One note's `content` as the view resolves it: its derived `title`, its canonical `body` in `key_claim`, and the
/// writer's `representation`. Pinned whole, so a reader that leaves a base-column text key behind is caught.
fn expected_content(title: &str, body: &str) -> serde_json::Value {
    serde_json::json!({
        "title": title,
        "key_claim": body,
        "representation": REPRESENTATION,
    })
}

/// G-M07-3, view half. Two notes written by the real writer, then reshaped: the identity note into the stripped shape card
/// M07-3 will write (no `key_claim`), the other into the legacy shape (no identity contract, a `key_claim` that differs from
/// its Evidence payload). The view must give each its own text, byte for byte, with its own `title`.
#[test]
#[allow(clippy::too_many_lines)] // one causal chain: three notes, each reshaped and re-read through the same view
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

/// G-M07-3, reader half (M08-2). The body readers behind `memory.get`, `memory.enumerate` and recall/context
/// (`materialize_final_bodies`; context.assemble and continuity call the same function) must return the view's text,
/// not the base columns: the stripped identity note keeps its body although its `key_claim` is gone, and the legacy
/// twin keeps the rewritten `key_claim` rather than its Evidence payload. The unreshaped note is the control.
#[test]
#[allow(clippy::too_many_lines)] // one causal chain: three notes, each reshaped and re-read through three readers
fn g_m07_3_the_body_readers_resolve_text_through_the_view() {
    run_db_fixture::<Fixture, _>(
        "g_m07_3_the_body_readers_resolve_text_through_the_view",
        |mut handle| {
            handle.seed_current_entitlement_and_window(8);
            let normal = put(&handle, NORMAL_BODY, NoteKind::Note);
            let stripped = put(&handle, IDENTITY_BODY, NoteKind::Note);
            let legacy = put(&handle, LEGACY_PUT_BODY, NoteKind::Decision);
            let (normal_title, identity_title, legacy_title) = (
                derived_title(NORMAL_BODY),
                derived_title(IDENTITY_BODY),
                derived_title(LEGACY_PUT_BODY),
            );
            let (tenant, stripped_s, legacy_s) =
                (handle.tenant_id, stripped.to_string(), legacy.to_string());

            // The stripped identity note: the shape M07-3 writes, where only the Evidence payload holds the body.
            handle
                .admin
                .batch_execute(&format!(
                    "SET session_replication_role = replica; \
                     UPDATE private.memory_records SET content = content - 'key_claim' \
                      WHERE tenant_id = '{tenant}' AND memory_id = '{stripped_s}'; \
                     SET session_replication_role = DEFAULT;"
                ))
                .expect("strip the identity note's key_claim");
            // The legacy twin: no identity contract, and a key_claim that is not its Evidence payload.
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

            // The fixture differs from the base column for the stripped note, which is what makes the reader half
            // load-bearing: the base `content ->> 'key_claim'` is absent while the view's body is the payload text.
            let stripped_base: Option<String> = handle
                .admin
                .query_one(
                    "SELECT content ->> 'key_claim' FROM private.memory_records \
                      WHERE tenant_id = $1 AND memory_id = $2",
                    &[&tenant, &stripped],
                )
                .expect("owner reads the stripped note")
                .get(0);
            assert_eq!(stripped_base, None);
            let view = texts(&handle, &[stripped]);
            assert_eq!(row(&view, stripped).body.as_deref(), Some(IDENTITY_BODY));

            let expected = BTreeMap::from([
                (normal, expected_content(&normal_title, NORMAL_BODY)),
                (stripped, expected_content(&identity_title, IDENTITY_BODY)),
                (legacy, expected_content(&legacy_title, LEGACY_KEY_CLAIM)),
            ]);
            let mut expected_ids = vec![normal, stripped, legacy];
            expected_ids.sort_unstable();

            // memory.get: one item, the exact body.
            let get = get_body(&handle, stripped);
            assert_eq!(get.bodies.items.len(), 1);
            let contents = memory_contents(&get.bodies.items);
            assert_eq!(ids_of(&contents), vec![stripped]);
            assert_eq!(contents[&stripped], expected[&stripped]);

            // memory.enumerate: the exact three-item page, each with its own text.
            let page = enumerate_bodies(&handle, 10);
            assert_eq!(page.memory.bodies.items.len(), 3);
            let contents = memory_contents(&page.memory.bodies.items);
            assert_eq!(ids_of(&contents), expected_ids);
            assert_eq!(contents, expected);

            // recall / context / continuity: the same three bodies through the shared final-body reader.
            let bodies = recall_bodies(&handle, &[normal, stripped, legacy]);
            assert_eq!(bodies.items.len(), 3);
            let contents = memory_contents(&bodies.items);
            assert_eq!(ids_of(&contents), expected_ids);
            assert_eq!(contents, expected);
        },
    );
}

//! `adapters::tests::note_history` — ADR-0067 D-J2 card 40c-2 acceptance for the note history axes (G29-G33, L-6) and
//!   the 40c-1 privacy follow-up (P2-2), against a real PostgreSQL and real `role_gateway` logins.
//! Depends-on: crates=[hex, humaux-adapters, humaux-domain, humaux-projection, humaux-testkit, serde_json, sqlx];
//!   services=[PostgreSQL(role_gateway) r=[ops.outbox, ops.selection_snapshots, private.evidence_objects,
//!   private.memory_evidence, private.note_heads, projection.stream_log] w=[private.memory_records]]; env=[];
//!   modules=[adapters::attribution_repo, adapters::confirm_token_repo, adapters::forget_repo, adapters::note_repo,
//!   adapters::operation_receipt, adapters::read_gate, adapters::read_materialize, adapters::remember, adapters::tests::support::governance_ops,
//!   adapters::tests::support::operation_receipt_fixture, domain::audit, domain::authority, domain::confirm,
//!   domain::error, domain::evidence, domain::identity, domain::ids, domain::note, domain::selection, domain::subject,
//!   humaux-testkit, projection::serving, projection::stream]
//! Called-by: [cargo-test]
//! Invariants: [every read under test is a real role_gateway login through the production adapter entry points; every
//!   version is written by the real 40a create or 40c-1 replacement transaction; the owner connection only archives,
//!   sets a lifecycle status, and reads back this fixture's tenant; every gate asserts stored rows or real responses
//!   against an independent owner read, never two literals]
//! Spec: Baseline §20.4; §22.1; ADR-0067 D-J2; ADR-0054
//!
//! The editor is a governance principal (`governance_ops::Governor`), as in `note_replace.rs`: consuming a replacement
//! token rechecks the write scope against `control.api_keys` (ADR-0054 D-B). Reads run as the fixture's own principal.

// Both fixtures (`operation_receipt_fixture`, `governance_ops`) carry their own `#[path] mod token_keys`; this test loads
// both, and `token_keys::install` is idempotent per process, so the second copy is inert.
#![allow(clippy::duplicate_mod)]

use std::time::{Duration, SystemTime};

use humaux_adapters::{
    confirm_token_repo::{self, ConfirmationClaim},
    forget_repo,
    note_repo::NoteIntake,
    operation_receipt::{
        self, AtomicRememberRequest, AtomicRememberResult, NOTE_OPERATION, NoteReplaceOutcome,
        NoteReplaceRequest,
    },
    read_gate::{
        MaterializedMemory, MaterializedMemoryPage, MemoryEnumerationParams, MemoryGetTarget,
        NoteEnumerationFilter, materialize_memory_enumeration_filtered,
        materialize_memory_get_target,
    },
    read_materialize::{Lifecycle, MaterializedItem, materialize_final_bodies},
    remember::RememberCommand,
};
use humaux_domain::{
    audit::{AuditEvent, AuditEventId, AuditMetadata, McpAuditAction},
    authority::{AuthorityClass, MemoryId},
    confirm::{DestructiveOp, RISK_TAG_CONFIRMATION_MINTED},
    error::ErrorCode,
    evidence::{EvidenceOriginClass, payload_sha256},
    identity::AuthorizationScope,
    ids::{Scope, TenantId, UserId, WorkspaceId},
    note::{DEFAULT_AUTHORITY, NoteBody, NoteKind, note_title, replace_intent_sha256},
    selection::{AUTHORIZED_MEMORY_ENUMERATION_V1, query_fingerprint},
};
use humaux_projection::{serving::StreamFamily, stream::StreamKey};
use humaux_testkit::run_db_fixture;
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
const MAC_KEY: &[u8] = b"card 40c-2 note history test mac key";

/// Every `statuses` value the D-J2 selector admits, and every archive mode.
const STATUSES: [&[&str]; 3] = [&["active"], &["superseded"], &["active", "superseded"]];
const ARCHIVES: [&str; 3] = ["exclude", "only", "include"];

// ---------------------------------------------------------------------------------------------------------------------
// Writers (copied from `note_replace.rs`; test files do not import each other).
// ---------------------------------------------------------------------------------------------------------------------

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
        trace_id: format!("note-history-{request_id}"),
        client_ip: "127.0.0.1".into(),
        user_agent_hash: "note-history-test".into(),
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

/// The MANUAL_NOTE command the gateway edge builds for one body, as the editor (WORKSPACE_SHARED, INTERNAL).
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

fn note_intake(body: &str, kind: NoteKind) -> NoteIntake {
    let verbatim = NoteBody::new(body).expect("valid body");
    NoteIntake {
        kind,
        title: note_title(None, &verbatim).expect("derived title"),
        body: verbatim,
        requested: DEFAULT_AUTHORITY,
    }
}

fn put(
    handle: &Handle,
    editor: &Editor,
    request: AtomicRememberRequest,
    note: NoteIntake,
) -> AtomicRememberResult {
    handle
        .rt
        .block_on(operation_receipt::note_put_atomically(
            &handle.runtime,
            &editor.auth,
            request,
            note,
            &humaux_adapters::attribution_repo::AttributionLadder,
        ))
        .expect("note create commits")
}

/// A fresh WORKSPACE_SHARED note through the 40a create path.
fn create(handle: &Handle, editor: &Editor, body: &str) -> AtomicRememberResult {
    let key = format!("create-{}", Uuid::new_v4());
    put(
        handle,
        editor,
        atomic_request(handle, editor, &key, "c".repeat(64), body),
        note_intake(body, NoteKind::Decision),
    )
}

/// One replacement intent: every field `H` binds.
struct Intent {
    key: String,
    note_id: Uuid,
    supersedes: Uuid,
    body: String,
    requested: AuthorityClass,
}

impl Intent {
    fn new(note_id: Uuid, supersedes: Uuid, body: &str) -> Self {
        Self {
            key: format!("replace-{}", Uuid::new_v4()),
            note_id,
            supersedes,
            body: body.to_owned(),
            requested: DEFAULT_AUTHORITY,
        }
    }

    fn note(&self) -> NoteIntake {
        let mut note = note_intake(&self.body, NoteKind::Decision);
        note.requested = self.requested;
        note
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

/// The gateway's first leg: a `MemoryNoteReplace` token on `supersedes`, bound to `H` of `intent`; returned as the
/// claim the gateway builds from the confirmed request.
fn mint(handle: &Handle, editor: &Editor, intent: &Intent) -> ConfirmationClaim {
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
            TOKEN_TTL,
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

fn replace_leg(
    handle: &Handle,
    editor: &Editor,
    intent: &Intent,
    claim: Option<ConfirmationClaim>,
) -> Result<NoteReplaceOutcome, ErrorCode> {
    handle
        .rt
        .block_on(operation_receipt::note_replace_atomically(
            &handle.runtime,
            &editor.auth,
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
            &humaux_adapters::attribution_repo::AttributionLadder,
        ))
}

/// One confirmed replacement of `supersedes` (the note's head) through the 40c-1 challenge + commit legs.
fn replace(
    handle: &Handle,
    editor: &Editor,
    note_id: Uuid,
    supersedes: Uuid,
    body: &str,
) -> AtomicRememberResult {
    let intent = Intent::new(note_id, supersedes, body);
    assert!(
        matches!(
            replace_leg(handle, editor, &intent, None),
            Ok(NoteReplaceOutcome::Confirmable)
        ),
        "the challenge leg precedes every replacement"
    );
    let claim = mint(handle, editor, &intent);
    match replace_leg(handle, editor, &intent, Some(claim)) {
        Ok(NoteReplaceOutcome::Stored(result)) => result,
        other => panic!("expected a stored replacement, got {other:?}"),
    }
}

fn memory_of(result: &AtomicRememberResult) -> Uuid {
    result.memory_id.expect("a stored note names its memory")
}

// ---------------------------------------------------------------------------------------------------------------------
// Readers (the production entry points, as the fixture principal) and owner-side witnesses.
// ---------------------------------------------------------------------------------------------------------------------

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

fn lifecycle(statuses: &[&str], archive: &str) -> Lifecycle {
    Lifecycle::for_enumerate(Some(statuses), Some(archive)).expect("a valid D-J2 selection")
}

fn selection(statuses: &[&str], archive: &str, note_id: Option<Uuid>) -> NoteEnumerationFilter {
    NoteEnumerationFilter {
        note_id,
        lifecycle: lifecycle(statuses, archive),
        ..NoteEnumerationFilter::default()
    }
}

fn enumerate(
    handle: &Handle,
    cursor: Option<&str>,
    page_size: u16,
    notes: &NoteEnumerationFilter,
) -> Result<MaterializedMemoryPage, ErrorCode> {
    handle.rt.block_on(materialize_memory_enumeration_filtered(
        &handle.runtime,
        &handle.auth,
        &scope(handle),
        &family(handle),
        &key(handle),
        MemoryEnumerationParams {
            cursor,
            page_size,
            ttl: Duration::from_secs(60),
            manifest_cap: 1000,
            mac_key: MAC_KEY,
            subject_id: None,
        },
        notes,
    ))
}

fn sorted(mut ids: Vec<Uuid>) -> Vec<Uuid> {
    ids.sort_unstable();
    ids
}

fn body_ids(items: &[MaterializedItem]) -> Vec<Uuid> {
    sorted(
        items
            .iter()
            .filter_map(|item| match item {
                MaterializedItem::Memory { memory_id, .. } => Some(*memory_id),
                _ => None,
            })
            .collect(),
    )
}

fn page_ids(page: &MaterializedMemoryPage) -> Vec<Uuid> {
    body_ids(&page.memory.bodies.items)
}

/// The §22.1 `total` frozen with this page's manifest; `None` when the census failed (never read as 0).
fn census_total(page: &MaterializedMemoryPage) -> Option<u64> {
    page.census
        .as_ref()
        .and_then(|census| census.census.enumeration())
        .map(|enumeration| enumeration.total())
}

fn get(
    handle: &Handle,
    target: MemoryGetTarget,
    include_history: bool,
) -> Result<MaterializedMemory, ErrorCode> {
    handle.rt.block_on(materialize_memory_get_target(
        &handle.runtime,
        &handle.auth,
        &scope(handle),
        &family(handle),
        &key(handle),
        target,
        include_history,
    ))
}

/// The recall/context final-body gate (`materialize_final_bodies`, which takes no lifecycle) over `ids`.
fn final_bodies(handle: &Handle, ids: &[Uuid]) -> Vec<Uuid> {
    let bodies = handle
        .rt
        .block_on(materialize_final_bodies(
            &handle.runtime,
            &handle.auth,
            &family(handle),
            &key(handle),
            ids,
            &[],
        ))
        .expect("final bodies");
    body_ids(&bodies.items)
}

/// One stored version as the owner reads it, bypassing every read gate.
struct Version {
    memory_id: Uuid,
    status: String,
    archived: bool,
    note_id: Option<Uuid>,
}

fn versions(handle: &mut Handle) -> Vec<Version> {
    handle
        .admin
        .query(
            "SELECT memory_id, status, archived_at IS NOT NULL, note_id FROM private.memory_records \
             WHERE tenant_id = $1",
            &[&handle.tenant_id],
        )
        .expect("owner reads this tenant's versions")
        .iter()
        .map(|row| Version {
            memory_id: row.get(0),
            status: row.get(1),
            archived: row.get(2),
            note_id: row.get(3),
        })
        .collect()
}

/// The ids a selection must yield, computed from the owner's rows (minus the ids the hard gates remove).
fn expected(
    rows: &[Version],
    statuses: &[&str],
    archive: &str,
    note_id: Option<Uuid>,
    gated_out: &[Uuid],
) -> Vec<Uuid> {
    sorted(
        rows.iter()
            .filter(|row| statuses.contains(&row.status.as_str()))
            .filter(|row| match archive {
                "exclude" => !row.archived,
                "only" => row.archived,
                _ => true,
            })
            .filter(|row| note_id.is_none_or(|note| row.note_id == Some(note)))
            .filter(|row| !gated_out.contains(&row.memory_id))
            .map(|row| row.memory_id)
            .collect(),
    )
}

fn archive(handle: &mut Handle, memory_id: Uuid) {
    let updated = handle
        .admin
        .execute(
            "UPDATE private.memory_records SET archived_at = clock_timestamp() \
             WHERE tenant_id = $1 AND memory_id = $2 AND archived_at IS NULL",
            &[&handle.tenant_id, &memory_id],
        )
        .expect("owner archives a version");
    assert_eq!(updated, 1);
}

/// Tombstones the first stream entry of `evidence_id` through `forget_repo::tombstone` (role_maintenance).
fn tombstone(handle: &mut Handle, evidence_id: Uuid) {
    let stream_seq: i64 = handle
        .admin
        .query_one(
            "SELECT sl.stream_seq FROM ops.outbox ob \
             JOIN projection.stream_log sl \
               ON sl.tenant_id = ob.tenant_id AND sl.commit_seq = ob.commit_seq \
             WHERE ob.tenant_id = $1 AND ob.evidence_id = $2 \
             ORDER BY sl.stream_seq LIMIT 1",
            &[&handle.tenant_id, &evidence_id],
        )
        .expect("the version's stream entry")
        .get(0);
    let tombstoned = handle
        .rt
        .block_on(forget_repo::tombstone(
            &handle.maintenance,
            &key(handle),
            u64::try_from(stream_seq).expect("nonnegative seq"),
        ))
        .expect("role_maintenance tombstone");
    assert!(tombstoned, "this call performed the transition");
}

fn head(handle: &mut Handle, note_id: Uuid) -> Option<Uuid> {
    handle
        .admin
        .query_opt(
            "SELECT head_memory_id FROM private.note_heads WHERE tenant_id = $1 AND note_id = $2",
            &[&handle.tenant_id, &note_id],
        )
        .expect("head row read")
        .map(|row| row.get(0))
}

/// The seeded history: note A (a1 superseded → a2 active), note B (active, archived), note C (c1 superseded and
/// archived → c2 active). Returns `[a1, a2, b, c1, c2]`.
fn seed_history(handle: &mut Handle, editor: &Editor) -> [Uuid; 5] {
    let a1 = memory_of(&create(handle, editor, "d-j2 note A, v1"));
    let a2 = memory_of(&replace(handle, editor, a1, a1, "d-j2 note A, v2"));
    let b = memory_of(&create(handle, editor, "d-j2 note B"));
    archive(handle, b);
    let c1 = memory_of(&create(handle, editor, "d-j2 note C, v1"));
    let c2 = memory_of(&replace(handle, editor, c1, c1, "d-j2 note C, v2"));
    archive(handle, c1);
    [a1, a2, b, c1, c2]
}

/// One selection on both §22.1 faces: the page (manifest + final gate) equals `want` and the census counted exactly it.
fn assert_face(
    handle: &Handle,
    notes: &NoteEnumerationFilter,
    want: &[Uuid],
    label: &str,
) -> MaterializedMemoryPage {
    let page =
        enumerate(handle, None, 100, notes).unwrap_or_else(|e| panic!("{label}: enumerate {e:?}"));
    assert_eq!(page_ids(&page), want, "{label}: manifest page");
    assert_eq!(
        census_total(&page),
        Some(want.len() as u64),
        "{label}: the census counted the page's own set in its snapshot"
    );
    assert!(
        page.next_cursor.is_none(),
        "{label}: one page holds the set"
    );
    page
}

// ---------------------------------------------------------------------------------------------------------------------
// G29: every selection, on both faces, equals the owner-computed set; the default is 40b's; note_id narrows to a note.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn g29_every_selection_on_both_faces_is_the_owner_computed_set() {
    run_db_fixture::<Fixture, _>("g29_history_selections", |mut handle| {
        let editor = editor(&mut handle);
        let [a1, a2, b, c1, c2] = seed_history(&mut handle, &editor);
        let rows = versions(&mut handle);
        assert_eq!(rows.len(), 5, "the seeded history is the whole tenant");

        let mut seen = Vec::new();
        for statuses in STATUSES {
            for archive in ARCHIVES {
                let label = format!("{statuses:?} x {archive}");
                let want = expected(&rows, statuses, archive, None, &[]);
                assert!(
                    !want.is_empty(),
                    "{label}: the seed populates every selection"
                );
                let page = assert_face(&handle, &selection(statuses, archive, None), &want, &label);
                for id in &want {
                    let row = rows
                        .iter()
                        .find(|row| row.memory_id == *id)
                        .expect("owner row");
                    assert_eq!(
                        page.memory.statuses.get(id).copied(),
                        Some(row.status.as_str()),
                        "{label}: the item's status is its stored status"
                    );
                    assert_eq!(
                        page.memory.archived_ids.contains(id),
                        row.archived,
                        "{label}: the item's archived flag is its stored one"
                    );
                }
                seen.extend(want);
            }
        }
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(
            seen,
            sorted(vec![a1, a2, b, c1, c2]),
            "every seeded version is reachable by some selection"
        );

        // The default selection is 40b's: no D-J2 field set is the same set as an explicit ["active"] / "exclude".
        let current = expected(&rows, &["active"], "exclude", None, &[]);
        assert_eq!(current, sorted(vec![a2, c2]));
        assert_face(
            &handle,
            &NoteEnumerationFilter::default(),
            &current,
            "default",
        );
        assert_face(
            &handle,
            &selection(&["active"], "exclude", None),
            &current,
            "explicit default",
        );

        // note_id narrows to one note's versions, under any selection.
        for (note, versions_of_note) in [(a1, vec![a1, a2]), (c1, vec![c1, c2]), (b, vec![b])] {
            let want = expected(&rows, &["active", "superseded"], "include", Some(note), &[]);
            assert_eq!(
                want,
                sorted(versions_of_note),
                "the owner's version list of {note}"
            );
            assert_face(
                &handle,
                &selection(&["active", "superseded"], "include", Some(note)),
                &want,
                "version list",
            );
        }
        assert_face(
            &handle,
            &selection(&["active"], "exclude", Some(a1)),
            &expected(&rows, &["active"], "exclude", Some(a1), &[]),
            "note_id under CURRENT",
        );
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// G30: the recall/context final gate takes no selection and never returns a superseded or archived version.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn g30_the_recall_and_context_gate_returns_current_versions_only() {
    run_db_fixture::<Fixture, _>("g30_recall_current_only", |mut handle| {
        let editor = editor(&mut handle);
        let seeded = seed_history(&mut handle, &editor);
        let rows = versions(&mut handle);
        let current = expected(&rows, &["active"], "exclude", None, &[]);
        assert_eq!(final_bodies(&handle, &seeded), current);
        for id in seeded.iter().filter(|id| !current.contains(id)) {
            assert_eq!(
                final_bodies(&handle, &[*id]),
                Vec::<Uuid>::new(),
                "{id}: superseded or archived never reaches recall/context"
            );
        }
        // Control: the same ids are readable through the history selector, so the gate (not absence) removed them.
        assert_face(
            &handle,
            &selection(&["active", "superseded"], "include", None),
            &sorted(seeded.to_vec()),
            "history control",
        );
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// G31: a cursor binds statuses, archive and note_id; an equivalent reordered statuses list pages on; the default keeps
// its pre-40c-2 fingerprint byte for byte.
// ---------------------------------------------------------------------------------------------------------------------

fn stored_fingerprint(handle: &mut Handle, snapshot_id: Uuid) -> String {
    handle
        .admin
        .query_one(
            "SELECT query_fingerprint FROM ops.selection_snapshots WHERE selection_snapshot_id = $1",
            &[&snapshot_id],
        )
        .expect("the manifest row")
        .get(0)
}

fn first_cursor(handle: &Handle, notes: &NoteEnumerationFilter, label: &str) -> String {
    enumerate(handle, None, 1, notes)
        .unwrap_or_else(|e| panic!("{label}: first page {e:?}"))
        .next_cursor
        .unwrap_or_else(|| panic!("{label}: two or more matches, page size one"))
}

#[test]
#[allow(clippy::too_many_lines)] // one fixture, five cursor legs over the same seeded history
fn g31_a_cursor_is_bound_to_the_history_selection() {
    run_db_fixture::<Fixture, _>("g31_history_cursor", |mut handle| {
        let editor = editor(&mut handle);
        let n1 = memory_of(&create(&handle, &editor, "g31 note N, v1"));
        let n2 = memory_of(&replace(&handle, &editor, n1, n1, "g31 note N, v2"));
        let n3 = memory_of(&replace(&handle, &editor, n1, n2, "g31 note N, v3"));
        let p = memory_of(&create(&handle, &editor, "g31 archived P"));
        let q = memory_of(&create(&handle, &editor, "g31 archived Q"));
        archive(&mut handle, p);
        archive(&mut handle, q);
        let r = memory_of(&create(&handle, &editor, "g31 current R"));
        let rows = versions(&mut handle);
        let refused =
            |handle: &Handle, cursor: &str, notes: &NoteEnumerationFilter, label: &str| {
                assert!(
                    matches!(
                        enumerate(handle, Some(cursor), 1, notes),
                        Err(ErrorCode::NotFound)
                    ),
                    "{label}: a cursor minted under another selection is refused"
                );
            };

        // (a) The default keeps its pre-40c-2 fingerprint, independently recomputed; an explicit default is the same.
        let default_page =
            enumerate(&handle, None, 1, &NoteEnumerationFilter::default()).expect("default");
        let pre_40c2 = query_fingerprint(
            &format!(
                "{AUTHORIZED_MEMORY_ENUMERATION_V1}:{}:{}:{}:",
                handle.auth.principal().0,
                handle.user_id,
                handle.workspace_id
            ),
            handle.tenant_id,
        );
        assert_eq!(
            stored_fingerprint(&mut handle, default_page.snapshot_id),
            pre_40c2
        );
        let explicit = selection(&["active"], "exclude", None);
        let explicit_page = enumerate(&handle, None, 1, &explicit).expect("explicit default");
        assert_eq!(
            stored_fingerprint(&mut handle, explicit_page.snapshot_id),
            pre_40c2
        );
        let cursor = default_page.next_cursor.clone().expect("n3 and r");
        let second =
            enumerate(&handle, Some(&cursor), 1, &explicit).expect("the explicit default pages on");
        assert_eq!(
            sorted(
                page_ids(&default_page)
                    .into_iter()
                    .chain(page_ids(&second))
                    .collect()
            ),
            sorted(vec![n3, r])
        );

        // (b) statuses: two superseded versions minted under ["superseded"] never page under both statuses.
        let superseded = selection(&["superseded"], "include", None);
        let cursor = first_cursor(&handle, &superseded, "superseded");
        refused(
            &handle,
            &cursor,
            &selection(&["active", "superseded"], "include", None),
            "statuses",
        );

        // (c) archive: two archived versions minted under "only" never page under "include".
        let only = selection(&["active"], "only", None);
        let cursor = first_cursor(&handle, &only, "archive only");
        refused(
            &handle,
            &cursor,
            &selection(&["active"], "include", None),
            "archive",
        );

        // (d) note_id: N's versions never page without the note axis.
        let note = selection(&["active", "superseded"], "include", Some(n1));
        let cursor = first_cursor(&handle, &note, "note");
        refused(
            &handle,
            &cursor,
            &selection(&["active", "superseded"], "include", None),
            "note_id",
        );

        // (e) An equivalent reordered statuses list is the same selection: it pages the whole set.
        let both = selection(&["active", "superseded"], "include", None);
        let reordered = selection(&["superseded", "active"], "include", None);
        let mut page = enumerate(&handle, None, 2, &both).expect("first page");
        let mut ids = page_ids(&page);
        while let Some(cursor) = page.next_cursor.clone() {
            page = enumerate(&handle, Some(&cursor), 2, &reordered).expect("reordered pages on");
            ids.extend(page_ids(&page));
        }
        assert_eq!(
            sorted(ids),
            expected(&rows, &["active", "superseded"], "include", None, &[]),
            "the reordered selection pages exactly the minted set"
        );
        assert_eq!(rows.len(), 6, "n1, n2, n3, p, q, r");
        assert!(
            [n1, n2, n3, p, q, r]
                .iter()
                .all(|id| rows.iter().any(|row| row.memory_id == *id))
        );
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// G32: memory.get by note_id reads the head; a memory_id never falls back to the note; a closed head is NOT_FOUND.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn g32_get_by_note_id_reads_the_head_and_never_falls_back() {
    run_db_fixture::<Fixture, _>("g32_get_namespaces", |mut handle| {
        let editor = editor(&mut handle);
        let v1 = memory_of(&create(&handle, &editor, "g32 v1"));
        let v2 = memory_of(&replace(&handle, &editor, v1, v1, "g32 v2"));
        let third = replace(&handle, &editor, v1, v2, "g32 v3");
        let v3 = memory_of(&third);
        assert_eq!(
            head(&mut handle, v1),
            Some(v3),
            "precondition: the stored head"
        );

        let read = get(&handle, MemoryGetTarget::Note(v1), false).expect("get by note_id");
        assert_eq!(
            body_ids(&read.bodies.items),
            vec![v3],
            "the note's head, after two replacements"
        );
        assert_eq!(
            read.note_ids.get(&v3),
            Some(&v1),
            "the head carries the same note_id"
        );
        let with_history =
            get(&handle, MemoryGetTarget::Note(v1), true).expect("history on the head");
        let history = with_history.history.expect("history is read");
        assert_eq!(
            (history.memory_id, history.status),
            (v3, "active"),
            "include_history targets the head"
        );

        // v1's memory_id equals the note_id: as a memory_id it names the superseded first version, never the head.
        for old in [v1, v2] {
            assert!(
                matches!(
                    get(&handle, MemoryGetTarget::Memory(MemoryId(old)), false),
                    Err(ErrorCode::NotFound)
                ),
                "{old}: a superseded memory_id is NOT_FOUND by default"
            );
        }
        assert!(matches!(
            get(&handle, MemoryGetTarget::Note(Uuid::new_v4()), false),
            Err(ErrorCode::NotFound)
        ));
        assert!(
            matches!(
                get(&handle, MemoryGetTarget::Note(v3), false),
                Err(ErrorCode::NotFound)
            ),
            "a version id is not a note id"
        );

        tombstone(&mut handle, third.accepted.evidence_id);
        assert_eq!(
            head(&mut handle, v1),
            Some(v3),
            "the head row still names v3"
        );
        assert!(
            matches!(
                get(&handle, MemoryGetTarget::Note(v1), false),
                Err(ErrorCode::NotFound)
            ),
            "a tombstoned head closes the note"
        );
        assert!(
            matches!(
                get(&handle, MemoryGetTarget::Note(v1), true),
                Err(ErrorCode::NotFound)
            ),
            "with history too, and never an older version"
        );
        // Control: the older version is still readable by its own id with history, so NOT_FOUND above is no fallback.
        let older =
            get(&handle, MemoryGetTarget::Memory(MemoryId(v2)), true).expect("v2 with history");
        assert_eq!(body_ids(&older.bodies.items), vec![v2]);
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// G33: a tombstoned version appears in no selection.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn g33_a_tombstone_overrides_every_selection() {
    run_db_fixture::<Fixture, _>("g33_tombstone_every_selection", |mut handle| {
        let editor = editor(&mut handle);
        seed_history(&mut handle, &editor);
        // x1 superseded + archived, x2 active; y active + archived; z1 superseded (z2 stays live).
        let x1_written = create(&handle, &editor, "g33 X v1");
        let x1 = memory_of(&x1_written);
        let x2_written = replace(&handle, &editor, x1, x1, "g33 X v2");
        let x2 = memory_of(&x2_written);
        archive(&mut handle, x1);
        let y_written = create(&handle, &editor, "g33 Y");
        let y = memory_of(&y_written);
        archive(&mut handle, y);
        let z1_written = create(&handle, &editor, "g33 Z v1");
        let z1 = memory_of(&z1_written);
        let z2 = memory_of(&replace(&handle, &editor, z1, z1, "g33 Z v2"));
        for written in [&x1_written, &x2_written, &y_written, &z1_written] {
            tombstone(&mut handle, written.accepted.evidence_id);
        }
        let gone = [x1, x2, y, z1];
        let rows = versions(&mut handle);
        assert!(
            rows.iter()
                .any(|row| row.memory_id == z2 && row.status == "active"),
            "control: z1's live successor stays in the tenant"
        );

        let mut selected_somewhere = Vec::new();
        for statuses in STATUSES {
            for archive in ARCHIVES {
                let label = format!("{statuses:?} x {archive}");
                // Non-vacuity: the owner's rows put the tombstoned versions inside these selections.
                selected_somewhere.extend(
                    expected(&rows, statuses, archive, None, &[])
                        .into_iter()
                        .filter(|id| gone.contains(id)),
                );
                let want = expected(&rows, statuses, archive, None, &gone);
                let page = assert_face(&handle, &selection(statuses, archive, None), &want, &label);
                assert!(
                    gone.iter().all(|id| !page_ids(&page).contains(id)),
                    "{label}: no tombstoned version"
                );
            }
        }
        selected_somewhere.sort_unstable();
        selected_somewhere.dedup();
        assert_eq!(
            selected_somewhere,
            sorted(gone.to_vec()),
            "every tombstoned version is in some selection"
        );
        for id in gone {
            assert!(
                matches!(
                    get(&handle, MemoryGetTarget::Memory(MemoryId(id)), true),
                    Err(ErrorCode::NotFound)
                ),
                "{id}: history does not reach a tombstoned version"
            );
        }
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// L-6: revoked / expired are not selectable, and never readable through any selection.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn l6_the_selector_refuses_revoked_and_expired() {
    for (statuses, archive) in [
        (vec!["revoked"], None),
        (vec!["expired"], None),
        (vec!["active", "revoked"], None),
        (vec!["superseded", "expired"], None),
        (vec!["active", "active"], None),
        (vec![], None),
        (vec!["active", "superseded", "active"], None),
        (vec!["Active"], None),
        (vec!["active"], Some("all")),
        (vec!["active"], Some("")),
    ] {
        assert_eq!(
            Lifecycle::for_enumerate(Some(statuses.as_slice()), archive),
            Err(ErrorCode::InvalidInput),
            "{statuses:?} / {archive:?}"
        );
    }
    // Control: the admitted shapes construct, and the defaults are CURRENT.
    assert_eq!(Lifecycle::for_enumerate(None, None), Ok(Lifecycle::CURRENT));
    assert_eq!(
        Lifecycle::for_enumerate(Some(&["superseded", "active"][..]), Some("include")),
        Lifecycle::for_enumerate(Some(&["active", "superseded"][..]), Some("include")),
    );
}

/// The owner moves one active version to a terminal hide state (`revoked` / `expired`), which no writer under test sets.
fn set_terminal(handle: &mut Handle, memory_id: Uuid, status: &str) {
    let updated = handle
        .admin
        .execute(
            "UPDATE private.memory_records SET status = $2 \
             WHERE memory_id = $1 AND tenant_id = $3 AND status = 'active'",
            &[&memory_id, &status, &handle.tenant_id],
        )
        .expect("owner sets the terminal status");
    assert_eq!(updated, 1);
}

#[test]
fn l6_revoked_and_expired_versions_leave_every_selection() {
    run_db_fixture::<Fixture, _>("l6_terminal_hide_states", |mut handle| {
        let editor = editor(&mut handle);
        seed_history(&mut handle, &editor);
        let mut hidden = Vec::new();
        for status in ["revoked", "expired"] {
            let id = memory_of(&create(&handle, &editor, &format!("l6 {status}")));
            set_terminal(&mut handle, id, status);
            hidden.push(id);
        }
        let rows = versions(&mut handle);
        for statuses in STATUSES {
            for archive in ARCHIVES {
                let want = expected(&rows, statuses, archive, None, &[]);
                let page = assert_face(&handle, &selection(statuses, archive, None), &want, "l6");
                assert!(hidden.iter().all(|id| !page_ids(&page).contains(id)));
            }
        }
    });
}

/// L-6 on `memory.get`, on its own: a revoked / expired version is `NOT_FOUND` by `memory_id` and by `note_id`, with and
/// without history — the final gate's answer. The get path's second lifecycle layer answers `Internal`, never a body,
/// so a gate that admits the row turns this red on the `NOT_FOUND` assertion.
#[test]
fn l6_revoked_and_expired_versions_are_not_gettable() {
    run_db_fixture::<Fixture, _>("l6_terminal_get", |mut handle| {
        let editor = editor(&mut handle);
        let targets = |id: Uuid| {
            [
                (MemoryGetTarget::Memory(MemoryId(id)), false),
                (MemoryGetTarget::Memory(MemoryId(id)), true),
                (MemoryGetTarget::Note(id), false),
                (MemoryGetTarget::Note(id), true),
            ]
        };
        for status in ["revoked", "expired"] {
            let id = memory_of(&create(&handle, &editor, &format!("l6 get {status}")));
            // Control: every leg reads the version while it is active, so NOT_FOUND below is the status alone.
            for (target, include_history) in targets(id) {
                let read = get(&handle, target, include_history)
                    .unwrap_or_else(|e| panic!("{status} {target:?} {include_history}: {e:?}"));
                assert_eq!(body_ids(&read.bodies.items), vec![id]);
            }
            set_terminal(&mut handle, id, status);
            for (target, include_history) in targets(id) {
                let read = get(&handle, target, include_history);
                assert!(
                    matches!(read, Err(ErrorCode::NotFound)),
                    "{status} {target:?} history={include_history}: {:?}",
                    read.map(|read| body_ids(&read.bodies.items))
                );
            }
        }
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// P2-2 (40c-1 review): a replacement inherits the head's visibility and data class, whatever the command carries.
// ---------------------------------------------------------------------------------------------------------------------

/// (visibility_class, visibility_user_id, visibility_workspace_id, PRIMARY Evidence data_class) of one version.
fn privacy(handle: &mut Handle, memory_id: Uuid) -> (String, Option<Uuid>, Option<Uuid>, String) {
    let row = handle
        .admin
        .query_one(
            "SELECT m.visibility_class, m.visibility_user_id, m.visibility_workspace_id, e.data_class \
             FROM private.memory_records m \
             JOIN private.memory_evidence me ON me.memory_id = m.memory_id AND me.role = 'PRIMARY' \
             JOIN private.evidence_objects e ON e.tenant_id = m.tenant_id AND e.evidence_id = me.evidence_id \
             WHERE m.tenant_id = $1 AND m.memory_id = $2",
            &[&handle.tenant_id, &memory_id],
        )
        .expect("the version's privacy");
    (row.get(0), row.get(1), row.get(2), row.get(3))
}

#[test]
fn p2_2_a_replacement_inherits_the_heads_visibility_and_data_class() {
    run_db_fixture::<Fixture, _>("p2_2_replacement_privacy", |mut handle| {
        let editor = editor(&mut handle);
        let body = "p2-2 private head";
        let mut request = atomic_request(
            &handle,
            &editor,
            &format!("create-{}", Uuid::new_v4()),
            "c".repeat(64),
            body,
        );
        request.command.visibility_class = "USER_PRIVATE".into();
        request.command.visibility_user_id = Some(editor.user_id);
        request.command.visibility_workspace_id = None;
        request.command.data_class = "PRIVATE".into();
        let first = memory_of(&put(
            &handle,
            &editor,
            request,
            note_intake(body, NoteKind::Decision),
        ));
        let head_privacy = privacy(&mut handle, first);
        assert_eq!(
            head_privacy,
            (
                "USER_PRIVATE".to_owned(),
                Some(editor.user_id),
                None,
                "PRIVATE".to_owned()
            ),
            "precondition: a non-default head"
        );

        // The replacement's command is the default WORKSPACE_SHARED / INTERNAL one (`command`).
        let replacement = command(&handle, &editor, "p2-2 v2");
        assert_ne!(
            (
                replacement.visibility_class.as_str(),
                replacement.data_class.as_str()
            ),
            (head_privacy.0.as_str(), head_privacy.3.as_str()),
            "precondition: the command differs from the head"
        );
        let second = memory_of(&replace(&handle, &editor, first, first, "p2-2 v2"));
        assert_eq!(
            privacy(&mut handle, second),
            head_privacy,
            "the stored new version carries the head's visibility and data class"
        );
    });
}

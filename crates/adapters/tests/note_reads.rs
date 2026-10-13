//! `adapters::tests::note_reads` — ADR-0067 card 40b acceptance for the verbatim note lane's reads (G11-G15, provenance,
//!   the unchanged default), against a real PostgreSQL and an actual `role_gateway` login.
//! Depends-on: crates=[hex, humaux-adapters, humaux-domain, humaux-projection, humaux-testkit, serde_json, sha2, sqlx,
//!   tokio]; services=[PostgreSQL(role_gateway) r=[ops.outbox, private.identity_note_materializations,
//!   projection.stream_log] w=[private.memory_records, private.memory_subjects, private.subjects]]; env=[];
//!   modules=[adapters::context_repo, adapters::forget_repo, adapters::note_repo, adapters::operation_receipt,
//!   adapters::postgres, adapters::read_materialize, adapters::remember,
//!   adapters::tests::support::operation_receipt_fixture, domain::audit, domain::authority, domain::error,
//!   domain::evidence, domain::identity, domain::ids, domain::note, domain::subject, humaux-testkit, projection::serving,
//!   projection::stream]
//! Called-by: [cargo-test]
//! Invariants: [every read under test is a real role_gateway login through the production adapter entry points; the
//!   owner connection only seeds, rewinds occurred_at, supersedes and reads back this fixture's tenant; every gate
//!   asserts stored rows or real responses, never two literals]
//! Spec: Baseline §20.4; §22.1; ADR-0067
//!
//! Notes are written through `operation_receipt::note_put_atomically` (the 40a write path), so every row read here is a
//! row a real `memory.note_put` would have left.

use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

use humaux_adapters::{
    context_repo::{
        MaterializedMemoryPage, MemoryEnumerationParams, NoteEnumerationFilter,
        arm_census_mint_barrier, materialize_memory_enumeration_filtered, materialize_memory_get,
        materialize_memory_get_versioned,
    },
    forget_repo,
    note_repo::NoteIntake,
    operation_receipt::{self, AtomicRememberRequest, AtomicRememberResult, NOTE_OPERATION},
    postgres::RuntimeDbPool,
    read_materialize::{MaterializedItem, materialize_final_bodies},
    remember::RememberCommand,
};
use humaux_domain::{
    audit::{AuditEvent, AuditEventId, AuditMetadata, McpAuditAction},
    authority::MemoryId,
    error::ErrorCode,
    evidence::{EvidenceOriginClass, payload_sha256},
    identity::AuthorizationScope,
    ids::{Scope, TenantId, UserId, WorkspaceId},
    note::{DEFAULT_AUTHORITY, NoteBody, NoteKind, note_title},
};
use humaux_projection::{serving::StreamFamily, stream::StreamKey};
use humaux_testkit::run_db_fixture;
use sha2::{Digest, Sha256};
use sqlx::types::{Uuid, time::OffsetDateTime};

#[allow(dead_code)]
#[path = "support/operation_receipt_fixture.rs"]
mod operation_receipt_fixture;

use operation_receipt_fixture::{DOMAIN, Fixture, Handle, PROJECTION_KIND, PROJECTION_VERSION};

const MAC_KEY: &[u8] = b"card 40b note reads test mac key";
/// 2020-01-01T00:00:00Z — a past `occurred_at` far from any row's `created_at`.
const DAY0: i64 = 1_577_836_800;
const DAY: i64 = 86_400;

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
        trace_id: format!("note-reads-{request_id}"),
        client_ip: "127.0.0.1".into(),
        user_agent_hash: "note-reads-test".into(),
        risk_tags: vec!["fixture".into()],
        before_fingerprint: None,
        after_fingerprint: None,
        metadata,
    }
}

/// What the gateway edge builds for one note (copied from `note_put.rs`; test files do not import each other).
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
            idempotency_key: format!("note-reads-{request_id}"),
            request_fingerprint: "b".repeat(64),
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

/// Stores one note through the real 40a transaction and returns its result.
fn put(handle: &Handle, body: &str, kind: NoteKind) -> AtomicRememberResult {
    let (request, note) = note_request(handle, body, kind);
    handle
        .rt
        .block_on(operation_receipt::note_put_atomically(
            &handle.runtime,
            &handle.auth,
            request,
            note,
        ))
        .expect("note commits")
}

fn memory_of(result: &AtomicRememberResult) -> Uuid {
    result.memory_id.expect("a stored note names its memory")
}

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

/// The note write path's own stream (`workspace`, knowledge, ingest, v1) — the family the reads are served from.
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

fn kinds(kinds: &[NoteKind]) -> NoteEnumerationFilter {
    NoteEnumerationFilter {
        note_kinds: Some(kinds.to_vec()),
        ..NoteEnumerationFilter::default()
    }
}

fn at(unix: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(unix).expect("valid instant")
}

#[allow(clippy::too_many_arguments)] // the production entry point's inputs, passed through to an actor thread
async fn enumerate_on(
    pool: &RuntimeDbPool,
    auth: &AuthorizationScope,
    scope: &Scope,
    family: &StreamFamily,
    key: &StreamKey,
    cursor: Option<&str>,
    page_size: u16,
    notes: &NoteEnumerationFilter,
) -> Result<MaterializedMemoryPage, ErrorCode> {
    materialize_memory_enumeration_filtered(
        pool,
        auth,
        scope,
        family,
        key,
        MemoryEnumerationParams {
            cursor,
            page_size,
            ttl: Duration::from_secs(60),
            manifest_cap: 1000,
            mac_key: MAC_KEY,
            subject_id: None,
        },
        notes,
    )
    .await
}

fn enumerate(
    handle: &Handle,
    cursor: Option<&str>,
    page_size: u16,
    notes: &NoteEnumerationFilter,
) -> Result<MaterializedMemoryPage, ErrorCode> {
    handle.rt.block_on(enumerate_on(
        &handle.runtime,
        &handle.auth,
        &scope(handle),
        &family(handle),
        &key(handle),
        cursor,
        page_size,
        notes,
    ))
}

fn enumerate_about(
    handle: &Handle,
    subject_id: Uuid,
    notes: &NoteEnumerationFilter,
) -> MaterializedMemoryPage {
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
                page_size: 100,
                ttl: Duration::from_secs(60),
                manifest_cap: 1000,
                mac_key: MAC_KEY,
                subject_id: Some(subject_id),
            },
            notes,
        ))
        .expect("subject-scoped enumerate")
}

fn page_ids(page: &MaterializedMemoryPage) -> Vec<Uuid> {
    let mut ids: Vec<Uuid> = page
        .memory
        .bodies
        .items
        .iter()
        .filter_map(|item| match item {
            MaterializedItem::Memory { memory_id, .. } => Some(*memory_id),
            _ => None,
        })
        .collect();
    ids.sort_unstable();
    ids
}

fn sorted(mut ids: Vec<Uuid>) -> Vec<Uuid> {
    ids.sort_unstable();
    ids
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
    memory_id: Uuid,
    include_history: bool,
) -> Result<humaux_adapters::context_repo::MaterializedMemory, ErrorCode> {
    handle.rt.block_on(materialize_memory_get_versioned(
        &handle.runtime,
        &handle.auth,
        &scope(handle),
        &family(handle),
        &key(handle),
        MemoryId(memory_id),
        include_history,
    ))
}

/// The recall/context final-body gate (`include_archived=false`, current versions only) over `ids`.
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
    sorted(
        bodies
            .items
            .iter()
            .filter_map(|item| match item {
                MaterializedItem::Memory { memory_id, .. } => Some(*memory_id),
                _ => None,
            })
            .collect(),
    )
}

/// Moves a note's `occurred_at` (only) with the owner connection; `created_at` keeps the write time.
fn set_occurred_at(handle: &mut Handle, memory_id: Uuid, unix: i64) {
    let updated = handle
        .admin
        .execute(
            "UPDATE private.memory_records SET occurred_at = to_timestamp($2::double precision) \
             WHERE memory_id = $1 AND tenant_id = $3",
            &[&memory_id, &(unix as f64), &handle.tenant_id],
        )
        .expect("owner rewinds occurred_at");
    assert_eq!(updated, 1);
}

fn seed_subject(handle: &mut Handle, name: &str) -> Uuid {
    handle
        .admin
        .query_one(
            "INSERT INTO private.subjects (tenant_id, kind, display_name) \
             VALUES ($1, 'PERSON', $2) RETURNING subject_id",
            &[&handle.tenant_id, &name],
        )
        .expect("owner seeds subject")
        .get(0)
}

fn link_subject(handle: &mut Handle, memory_id: Uuid, subject_id: Uuid) {
    handle
        .admin
        .execute(
            "INSERT INTO private.memory_subjects \
               (tenant_id, memory_id, subject_id, relation, source_kind, confidence_bp) \
             VALUES ($1, $2, $3, 'ABOUT', 'DECLARED', 10000)",
            &[&handle.tenant_id, &memory_id, &subject_id],
        )
        .expect("owner links memory to subject");
}

/// Disarms the process-global census barrier on every exit, so a panicking test cannot park the next one.
struct BarrierArmed;

impl Drop for BarrierArmed {
    fn drop(&mut self) {
        arm_census_mint_barrier(0);
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// G11: with a note_kinds filter, the page and its census total come from one snapshot; joins do not inflate the count.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)] // one causal chain: park the mint, commit a matching note, release, read both sides
fn g11_a_note_kind_page_and_its_total_share_one_snapshot_under_a_concurrent_write() {
    run_db_fixture::<Fixture, _>("g11_one_snapshot", |mut handle| {
        handle.seed_current_entitlement_and_window(16);
        let first = memory_of(&put(&handle, "g11 decision one", NoteKind::Decision));
        let second = memory_of(&put(&handle, "g11 decision two", NoteKind::Decision));
        let other = memory_of(&put(&handle, "g11 a lesson", NoteKind::Lesson));
        let decisions = kinds(&[NoteKind::Decision]);

        let advisory_key = i64::from_be_bytes(
            handle.tenant_id.as_bytes()[..8]
                .try_into()
                .expect("eight bytes"),
        ) | 1;
        let mut holder = handle.owner_client().expect("owner lock holder");
        holder
            .execute("SELECT pg_advisory_lock($1)", &[&advisory_key])
            .expect("hold the census barrier");
        arm_census_mint_barrier(advisory_key);
        let disarm = BarrierArmed;

        let application_name = format!("note-reads-g11-{}", Uuid::new_v4().simple());
        let actor_dsn = handle.gateway_application_dsn(&application_name);
        let (actor_auth, actor_scope, actor_family, actor_key) = (
            handle.auth.clone(),
            scope(&handle),
            family(&handle),
            key(&handle),
        );
        let filter = decisions.clone();
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let actor = std::thread::spawn(move || {
            let outcome = (|| -> Result<_, String> {
                let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
                // dep: PostgreSQL(role_gateway) — the actor's own real gateway pool
                let pool = rt
                    .block_on(RuntimeDbPool::connect(&actor_dsn))
                    .map_err(|e| e.to_string())?;
                Ok(rt.block_on(enumerate_on(
                    &pool,
                    &actor_auth,
                    &actor_scope,
                    &actor_family,
                    &actor_key,
                    None,
                    100,
                    &filter,
                )))
            })();
            let _ = done_tx.send(outcome);
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let waiting: bool = handle
                .admin
                .query_one(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name=$1 \
                       AND wait_event_type='Lock')",
                    &[&application_name],
                )
                .expect("inspect actor")
                .get(0);
            if waiting {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the enumerate mint never reached the census barrier"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        // The mint holds its id list; a matching note commits inside its window.
        let late = memory_of(&put(
            &handle,
            "g11 decision committed mid-mint",
            NoteKind::Decision,
        ));
        holder
            .execute("SELECT pg_advisory_unlock($1)", &[&advisory_key])
            .expect("release the census barrier");
        let page = done_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("actor finishes after the barrier")
            .expect("actor ran")
            .expect("parked enumerate succeeds");
        actor.join().expect("actor joined");
        drop(disarm);

        assert_eq!(
            page_ids(&page),
            sorted(vec![first, second]),
            "the page is the mint snapshot's decisions: not the lesson, not the late note"
        );
        assert_eq!(
            census_total(&page),
            Some(2),
            "the census counted in the page's snapshot (a younger one would count 3 and fail the cross-check)"
        );
        // Witness that the late note does match the filter: a fresh mint sees and counts it.
        let fresh = enumerate(&handle, None, 100, &decisions).expect("fresh enumerate");
        assert_eq!(page_ids(&fresh), sorted(vec![first, second, late]));
        assert_eq!(census_total(&fresh), Some(3));
        assert!(!page_ids(&fresh).contains(&other));
    });
}

#[test]
fn g11_subject_links_do_not_inflate_a_note_kind_total() {
    run_db_fixture::<Fixture, _>("g11_no_join_inflation", |mut handle| {
        handle.seed_current_entitlement_and_window(8);
        let linked = memory_of(&put(&handle, "g11 linked research", NoteKind::Research));
        let plain = memory_of(&put(&handle, "g11 plain note", NoteKind::Note));
        let alice = seed_subject(&mut handle, "g11 alice");
        let bob = seed_subject(&mut handle, "g11 bob");
        link_subject(&mut handle, linked, alice);
        link_subject(&mut handle, linked, bob);
        // `research` and `note` share memory_type NOTE: the axis is note_kind, not the type.
        let research = kinds(&[NoteKind::Research]);
        let page = enumerate(&handle, None, 100, &research).expect("research enumerate");
        assert_eq!(page_ids(&page), vec![linked]);
        assert_eq!(
            census_total(&page),
            Some(1),
            "two subject links, one memory"
        );
        assert_eq!(
            page.memory.note_kinds.get(&linked),
            Some(&NoteKind::Research),
            "the item carries its stored kind"
        );
        let about_alice = enumerate_about(&handle, alice, &research);
        assert_eq!(page_ids(&about_alice), vec![linked]);
        assert_eq!(census_total(&about_alice), Some(1));
        let both = kinds(&[NoteKind::Research, NoteKind::Note]);
        let page = enumerate(&handle, None, 100, &both).expect("two-kind enumerate");
        assert_eq!(page_ids(&page), sorted(vec![linked, plain]));
        assert_eq!(census_total(&page), Some(2));
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// G12: a cursor is bound to its filter set; a tampered cursor is refused.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn g12_a_cursor_never_pages_another_filter_and_a_flipped_cursor_is_refused() {
    run_db_fixture::<Fixture, _>("g12_cursor_binding", |mut handle| {
        handle.seed_current_entitlement_and_window(8);
        let a = memory_of(&put(&handle, "g12 decision a", NoteKind::Decision));
        let b = memory_of(&put(&handle, "g12 decision b", NoteKind::Decision));
        memory_of(&put(&handle, "g12 lesson", NoteKind::Lesson));
        set_occurred_at(&mut handle, a, DAY0);
        set_occurred_at(&mut handle, b, DAY0 + 1);
        let window = NoteEnumerationFilter {
            note_kinds: Some(vec![NoteKind::Decision]),
            occurred_since: Some(at(DAY0)),
            occurred_until: Some(at(DAY0 + DAY)),
        };
        let first = enumerate(&handle, None, 1, &window).expect("first page");
        let cursor = first
            .next_cursor
            .clone()
            .expect("two matches, page size one");

        // Control: the same filter set pages on.
        let second = enumerate(&handle, Some(&cursor), 1, &window).expect("same filter pages");
        assert_eq!(
            sorted(
                page_ids(&first)
                    .into_iter()
                    .chain(page_ids(&second))
                    .collect()
            ),
            sorted(vec![a, b])
        );

        let other_kind = NoteEnumerationFilter {
            note_kinds: Some(vec![NoteKind::Lesson]),
            ..window.clone()
        };
        let other_since = NoteEnumerationFilter {
            occurred_since: Some(at(DAY0 - DAY)),
            ..window.clone()
        };
        let unfiltered = NoteEnumerationFilter::default();
        for (label, filter) in [
            ("lesson", &other_kind),
            ("since", &other_since),
            ("no filter", &unfiltered),
        ] {
            assert!(
                matches!(
                    enumerate(&handle, Some(&cursor), 1, filter),
                    Err(ErrorCode::NotFound)
                ),
                "{label}: a cursor minted under another filter set is refused"
            );
        }

        // Flip one hex digit of the MAC inside the opaque encoding, so the cursor still decodes and only the MAC
        // can refuse it.
        let mut plain = hex::decode(&cursor).expect("the cursor is hex");
        let last = plain.last_mut().expect("non-empty cursor");
        *last = if *last == b'0' { b'1' } else { b'0' };
        let flipped = hex::encode(plain);
        assert!(
            matches!(
                enumerate(&handle, Some(&flipped), 1, &window),
                Err(ErrorCode::InvalidInput)
            ),
            "a byte-flipped cursor fails its MAC"
        );
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// G13: since/until filter occurred_at (not created_at), half-open.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn g13_the_window_is_half_open_over_occurred_at_not_created_at() {
    run_db_fixture::<Fixture, _>("g13_occurred_at_window", |mut handle| {
        handle.seed_current_entitlement_and_window(8);
        let old = memory_of(&put(&handle, "g13 happened long ago", NoteKind::State));
        let boundary = memory_of(&put(&handle, "g13 happened at the bound", NoteKind::State));
        let recent = memory_of(&put(&handle, "g13 happened now", NoteKind::State));
        set_occurred_at(&mut handle, old, DAY0);
        set_occurred_at(&mut handle, boundary, DAY0 + DAY);
        let window = |since: i64, until: i64| NoteEnumerationFilter {
            note_kinds: None,
            occurred_since: Some(at(since)),
            occurred_until: Some(at(until)),
        };

        let page = enumerate(&handle, None, 100, &window(DAY0, DAY0 + DAY)).expect("window");
        assert_eq!(
            page_ids(&page),
            vec![old],
            "[since, until): the row at `until` is outside"
        );
        assert_eq!(census_total(&page), Some(1));

        let page = enumerate(&handle, None, 100, &window(DAY0, DAY0 + DAY + 1)).expect("window");
        assert_eq!(
            page_ids(&page),
            sorted(vec![old, boundary]),
            "since is inclusive"
        );
        assert_eq!(census_total(&page), Some(2));

        // All three were created now: a created_at window would hold all three, an occurred_at window only `recent`.
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let page = enumerate(&handle, None, 100, &window(now - 3_600, now + 3_600)).expect("now");
        assert_eq!(page_ids(&page), vec![recent]);
        assert_eq!(census_total(&page), Some(1));

        for (since, until) in [(DAY0, DAY0), (DAY0 + DAY, DAY0)] {
            assert!(
                matches!(
                    enumerate(&handle, None, 100, &window(since, until)),
                    Err(ErrorCode::InvalidInput)
                ),
                "since >= until is refused"
            );
        }
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// G14: superseded — NotFound by default, the exact version with include_history, absent from recall.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn g14_a_superseded_note_is_readable_only_with_history_and_never_by_recall() {
    run_db_fixture::<Fixture, _>("g14_superseded", |mut handle| {
        handle.seed_current_entitlement_and_window(8);
        let old = memory_of(&put(&handle, "g14 first version", NoteKind::Decision));
        let new = memory_of(&put(&handle, "g14 second version", NoteKind::Decision));
        let updated = handle
            .admin
            .execute(
                "UPDATE private.memory_records \
                    SET status = 'superseded', superseded_by = $2, superseded_at = clock_timestamp() \
                  WHERE memory_id = $1 AND tenant_id = $3 AND status = 'active'",
                &[&old, &new, &handle.tenant_id],
            )
            .expect("owner supersedes the first version");
        assert_eq!(updated, 1);

        assert!(
            matches!(get(&handle, old, false), Err(ErrorCode::NotFound)),
            "default get: a superseded id stays NOT_FOUND"
        );
        let read = get(&handle, old, true).expect("include_history reads the version itself");
        let ids: Vec<Uuid> = read
            .bodies
            .items
            .iter()
            .filter_map(|item| match item {
                MaterializedItem::Memory { memory_id, .. } => Some(*memory_id),
                _ => None,
            })
            .collect();
        assert_eq!(
            ids,
            vec![old],
            "the exact version asked for, not its successor"
        );
        let history = read.history.expect("history is read");
        assert_eq!(history.memory_id, old);
        assert_eq!(history.status, "superseded");
        assert_eq!(history.superseded_by, Some(new));
        assert_eq!(read.note_kinds.get(&old), Some(&NoteKind::Decision));

        let current = get(&handle, new, true).expect("the successor with history");
        let current = current.history.expect("history is read");
        assert_eq!((current.status, current.superseded_by), ("active", None));

        assert_eq!(
            final_bodies(&handle, &[old, new]),
            vec![new],
            "the recall/context final gate keeps current versions only"
        );
        let page = enumerate(&handle, None, 100, &kinds(&[NoteKind::Decision])).expect("enumerate");
        assert_eq!(page_ids(&page), vec![new]);
        assert_eq!(census_total(&page), Some(1));
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// G15: after the note's evidence stream entry is TOMBSTONED, nothing returns its body or digest.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn g15_a_tombstoned_note_is_gone_from_history_provenance_and_enumerate() {
    run_db_fixture::<Fixture, _>("g15_tombstoned", |mut handle| {
        handle.seed_current_entitlement_and_window(8);
        let body = format!("g15 forget me {}", Uuid::new_v4());
        let forgotten = put(&handle, &body, NoteKind::Problem);
        let gone = memory_of(&forgotten);
        let kept = memory_of(&put(&handle, "g15 keep me", NoteKind::Problem));
        let digest = hex::encode(Sha256::digest(body.as_bytes()).as_slice());
        assert!(
            get(&handle, gone, true).is_ok(),
            "control: readable before the tombstone"
        );

        let stream_seq: i64 = handle
            .admin
            .query_one(
                "SELECT sl.stream_seq FROM ops.outbox ob \
                 JOIN projection.stream_log sl \
                   ON sl.tenant_id = ob.tenant_id AND sl.commit_seq = ob.commit_seq \
                 WHERE ob.tenant_id = $1 AND ob.evidence_id = $2",
                &[&handle.tenant_id, &forgotten.accepted.evidence_id],
            )
            .expect("the note's stream entry")
            .get(0);
        let tombstoned = handle
            .rt
            .block_on(forget_repo::tombstone(
                &handle.maintenance,
                &key(&handle),
                u64::try_from(stream_seq).expect("nonnegative seq"),
            ))
            .expect("role_maintenance tombstone");
        assert!(tombstoned, "this call performed the transition");

        assert!(matches!(get(&handle, gone, true), Err(ErrorCode::NotFound)));
        assert!(matches!(
            get(&handle, gone, false),
            Err(ErrorCode::NotFound)
        ));
        assert_eq!(final_bodies(&handle, &[gone, kept]), vec![kept]);
        let page = enumerate(&handle, None, 100, &kinds(&[NoteKind::Problem])).expect("enumerate");
        assert_eq!(page_ids(&page), vec![kept]);
        assert_eq!(census_total(&page), Some(1), "the census excludes it too");
        let rendered = format!("{:?}", page.memory.bodies);
        assert!(
            !rendered.contains(&body) && !rendered.contains(&digest),
            "no response carries the forgotten body or its digest"
        );
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// D-H provenance and the unchanged default.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn provenance_of_a_note_is_its_contract_its_evidence_and_an_independent_digest() {
    run_db_fixture::<Fixture, _>("note_provenance", |mut handle| {
        handle.seed_current_entitlement_and_window(8);
        let body = "  Provenance body \u{1F680}\r\nwith \"quotes\" and a \\ backslash  ";
        let result = put(&handle, body, NoteKind::Fix);
        let memory_id = memory_of(&result);
        let read = get(&handle, memory_id, true).expect("get with history");
        let history = read.history.expect("history is read");
        let provenance = history.provenance;

        let row = handle
            .admin
            .query_one(
                "SELECT c.strategy, m.authority_class, \
                        floor(extract(epoch FROM m.asserted_at))::bigint \
                 FROM private.identity_note_materializations c \
                 JOIN private.memory_records m \
                   ON m.tenant_id = c.tenant_id AND m.memory_id = c.output_memory_id \
                 WHERE c.output_memory_id = $1 AND c.tenant_id = $2",
                &[&memory_id, &handle.tenant_id],
            )
            .expect("the note's contract");
        let (strategy, authority, asserted_unix): (String, String, i64) =
            (row.get(0), row.get(1), row.get(2));
        assert_eq!(provenance.derivation_strategy, strategy);
        assert_eq!(provenance.derivation_strategy, "identity_note_v1");
        assert_eq!(
            provenance.body_sha256.as_deref(),
            Some(Sha256::digest(body.as_bytes()).as_slice()),
            "the digest equals an independent SHA-256 of the sent body"
        );
        assert_eq!(provenance.origin.as_deref(), Some("AuthenticatedAgent"));
        assert_eq!(provenance.event_kind.as_deref(), Some("MANUAL_NOTE"));
        assert_eq!(
            provenance.primary_evidence_id,
            Some(result.accepted.evidence_id)
        );
        assert_eq!(provenance.authority_class, authority);
        assert_eq!(provenance.asserted_at.unix_timestamp(), asserted_unix);
        assert_eq!((history.status, history.superseded_by), ("active", None));
    });
}

#[test]
fn without_include_history_get_reads_no_history() {
    run_db_fixture::<Fixture, _>("note_default_get", |mut handle| {
        handle.seed_current_entitlement_and_window(4);
        let memory_id = memory_of(&put(&handle, "default get", NoteKind::Preference));
        let read = handle
            .rt
            .block_on(materialize_memory_get(
                &handle.runtime,
                &handle.auth,
                &scope(&handle),
                &family(&handle),
                &key(&handle),
                MemoryId(memory_id),
            ))
            .expect("default get");
        assert!(
            read.history.is_none(),
            "no status / provenance without include_history"
        );
        assert_eq!(read.note_kinds.get(&memory_id), Some(&NoteKind::Preference));
        assert!(
            get(&handle, memory_id, false)
                .expect("versioned default")
                .history
                .is_none()
        );
    });
}

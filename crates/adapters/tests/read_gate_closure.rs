//! `adapters::tests::read_gate_closure` — G-M08-1: the all-backing-evidence closure holds on every read op. A memory
//!   with two backing Evidence rows, one of them unreadable to the caller, is absent from get, enumerate, grep, the
//!   recall materializer, context and continuity, and no count or snippet of it leaks.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-projection, humaux-testkit, serde_json,
//!   sqlx]; services=[PostgreSQL(any) w=[private.evidence_objects, private.memory_evidence, private.memory_records, projection.stream_checkpoints]];
//!   env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::context_repo, adapters::grep_repo, adapters::read_gate,
//!   adapters::read_materialize, adapters::tests::support::continuity_0137_fixture,
//!   adapters::tests::support::operation_receipt_fixture, domain::authority, domain::context, domain::error,
//!   domain::ids, humaux-testkit, projection::serving, projection::stream]
//! Called-by: [cargo-test]
//! Invariants: [every op is the production entry point its gateway route calls, as a real role_gateway login; the
//!   owner connection only seeds and flips Evidence visibility; the same memory is asserted absent while one backing
//!   Evidence is unreadable and present once that Evidence becomes readable, so a pass cannot come from an op that
//!   returns nothing; the continuity row is a separate world because that op reads continuity facets, and the two
//!   fixtures never overlap in time (LOCK)]
//! Spec: Baseline §6.1.1; §8.6; §6.1.3; §57.1
//!
//! Fault this gate catches (module design M08 section 8, G-M08-1): the closure's `LEFT JOIN private.evidence_objects` in
//! `read_gate::readable_memory_ids` replaced by an `INNER JOIN` makes a hidden Evidence row vanish from the join, the
//! memory then looks fully backed by its one visible row, and it reappears in every op here.

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::Duration;

use humaux_adapters::{
    context_repo::assemble_materialized,
    grep_repo::{GrepQuery, grep},
    read_gate::{MemoryEnumerationParams, materialize_memory_enumeration, materialize_memory_get},
    read_materialize::{Lifecycle, MaterializedItem, materialize_final_bodies},
};
use humaux_domain::{
    authority::MemoryId,
    context::ContextBudget,
    error::ErrorCode,
    ids::{Scope, TenantId, UserId, WorkspaceId},
};
use humaux_projection::{serving::StreamFamily, stream::StreamKey};
use humaux_testkit::{ExternalDep, run_db_fixture, skip_or_fail};
use serde_json::{Value, json};
use sqlx::types::Uuid;

#[allow(dead_code)]
#[path = "support/operation_receipt_fixture.rs"]
mod operation_receipt_fixture;

#[allow(dead_code)]
#[path = "support/continuity_0137_fixture.rs"]
mod continuity_0137_fixture;

use operation_receipt_fixture::{DOMAIN, Fixture, Handle, PROJECTION_KIND, PROJECTION_VERSION};

const MAC_KEY: &[u8] = b"M08-3 read gate closure test mac key";
/// Present in the `key_claim` line of both memories, so one grep pattern matches each of them once.
const TOKEN: &str = "m08closuretoken";
const CTRL_MARK: &str = "ctrl-snippet-5d1f";
/// Appears only in the memory whose second Evidence is unreadable; it must never reach any op's output.
const HIDDEN_MARK: &str = "gated-snippet-9c4e";

/// The two worlds share cluster-global owner-side triggers and teardown; run them one after the other even under
/// plain `cargo test` threads (nextest already isolates by process).
static LOCK: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What one op returned for the two seeded memories.
#[derive(Default)]
struct Seen {
    /// Memories the op admitted.
    ids: BTreeSet<Uuid>,
    /// Every count the op reported about its result, by name.
    counts: Vec<(&'static str, u64)>,
    /// Everything the op returned that could carry a body, id or snippet.
    text: String,
    /// `memory.get` only: the code of each id it refused.
    refused: Vec<(Uuid, ErrorCode)>,
}

impl Seen {
    fn absorb(&mut self, items: &[MaterializedItem]) {
        for item in items {
            if let MaterializedItem::Memory { memory_id, .. } = item {
                self.ids.insert(*memory_id);
            }
        }
        self.text.push_str(&format!("{items:?}"));
    }

    fn count(&mut self, name: &'static str, value: i64) {
        self.counts.push((
            name,
            u64::try_from(value).expect("a count is never negative"),
        ));
    }
}

struct World {
    /// Two readable backing Evidence rows.
    ctrl: Uuid,
    /// Two backing Evidence rows, the second unreadable to the caller until flipped.
    gated: Uuid,
    gated_second_evidence: Uuid,
    scope: Scope,
    family: StreamFamily,
    key: StreamKey,
}

type Op = fn(&World, &Handle) -> Seen;

const OPS: [(&str, Op); 5] = [
    ("memory.get", op_get),
    ("memory.enumerate", op_enumerate),
    ("memory.grep", op_grep),
    ("recall materialize", op_recall_materialize),
    ("context.assemble", op_context),
];

fn op_get(world: &World, handle: &Handle) -> Seen {
    let mut seen = Seen::default();
    for id in [world.ctrl, world.gated] {
        match handle.rt.block_on(materialize_memory_get(
            &handle.runtime,
            &handle.auth,
            &world.scope,
            &world.family,
            &world.key,
            MemoryId(id),
        )) {
            Ok(memory) => seen.absorb(&memory.bodies.items),
            Err(code) => seen.refused.push((id, code)),
        }
    }
    seen
}

fn op_enumerate(world: &World, handle: &Handle) -> Seen {
    let page = handle
        .rt
        .block_on(materialize_memory_enumeration(
            &handle.runtime,
            &handle.auth,
            &world.scope,
            &world.family,
            &world.key,
            MemoryEnumerationParams {
                cursor: None,
                page_size: 100,
                ttl: Duration::from_secs(60),
                manifest_cap: 1000,
                mac_key: MAC_KEY,
                subject_id: None,
            },
        ))
        .expect("enumerate succeeds for the caller's own workspace");
    let mut seen = Seen::default();
    seen.absorb(&page.memory.bodies.items);
    // §22.1: the census total, when this route could establish one, counts the readable universe only.
    if let Some(total) = page
        .census
        .as_ref()
        .and_then(|census| census.census.enumeration())
        .map(|enumeration| enumeration.total())
    {
        seen.counts.push(("census total", total));
    }
    seen
}

fn op_grep(_world: &World, handle: &Handle) -> Seen {
    let query = GrepQuery::new(TOKEN, Lifecycle::CURRENT, 100, None, None).expect("grep query");
    let page = handle
        .rt
        .block_on(grep(
            &handle.runtime,
            &handle.auth,
            WorkspaceId(handle.workspace_id),
            &query,
        ))
        .expect("grep succeeds for the caller's own workspace");
    let mut seen = Seen::default();
    for hit in &page.items {
        seen.ids.insert(hit.memory_id);
        seen.text.push_str(&format!("{hit:?}"));
    }
    seen.count("matching lines", page.total_matching_lines);
    seen.count("matching memories", page.total_memories);
    seen
}

fn op_recall_materialize(world: &World, handle: &Handle) -> Seen {
    let bodies = handle
        .rt
        .block_on(materialize_final_bodies(
            &handle.runtime,
            &handle.auth,
            &world.family,
            &world.key,
            &[world.ctrl, world.gated],
            &[],
        ))
        .expect("final bodies");
    let mut seen = Seen::default();
    seen.absorb(&bodies.items);
    seen
}

fn op_context(world: &World, handle: &Handle) -> Seen {
    let context = handle
        .rt
        .block_on(assemble_materialized(
            &handle.runtime,
            &handle.auth,
            &world.scope,
            ContextBudget::new(2_048, 1_024).expect("budget"),
            &world.family,
            &world.key,
        ))
        .expect("context assembles for the caller's own workspace");
    let mut seen = Seen::default();
    seen.absorb(&context.bodies.items);
    for item in context
        .handoff
        .mandatory
        .iter()
        .chain(&context.handoff.pinned)
    {
        seen.ids
            .insert(Uuid::parse_str(&item.memory_id).expect("handoff memory id"));
    }
    seen.counts.push((
        "mandatory expected",
        context.handoff.counts.mandatory_expected,
    ));
    seen.counts.push((
        "mandatory returned",
        context.handoff.counts.mandatory_returned,
    ));
    seen.counts.push((
        "mandatory missing",
        context.handoff.counts.mandatory_missing,
    ));
    seen.text
        .push_str(&serde_json::to_string(&context.handoff).expect("handoff serializes"));
    seen
}

fn set_content(handle: &mut Handle, memory_id: Uuid, content: &Value) {
    handle
        .admin
        .execute(
            "UPDATE private.memory_records SET content = $2 WHERE memory_id = $1",
            &[&memory_id, content],
        )
        .expect("owner sets the fixture memory text");
}

/// Adds a second backing Evidence row to `memory_id`. `hidden` = `USER_PRIVATE` to a peer user, which RLS hides from the
/// caller (the closure's LEFT JOIN then sees NULL); otherwise `TENANT_SHARED`.
fn link_second_evidence(handle: &mut Handle, memory_id: Uuid, hidden: bool) -> Uuid {
    let peer = hidden.then(|| handle.seed_peer_user());
    let class = if hidden {
        "USER_PRIVATE"
    } else {
        "TENANT_SHARED"
    };
    let mut payload = vec![0_u8; 32];
    payload[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    let mut txn = handle
        .admin
        .transaction()
        .expect("begin second evidence seed");
    let evidence_id: Uuid = txn
        .query_one(
            &format!(
                "INSERT INTO private.evidence_objects \
                   (tenant_id, evidence_kind, payload_sha256, data_class, origin_class, \
                    visibility_class, visibility_user_id, reasoning_domain_id) \
                 VALUES ($1, 'EVENT', $2, 'INTERNAL', 'DirectUserInput', '{class}', $3, $4) \
                 RETURNING evidence_id"
            ),
            &[
                &handle.tenant_id,
                &payload,
                &peer,
                &handle.reasoning_domain_id,
            ],
        )
        .expect("owner seeds the second Evidence")
        .get(0);
    txn.execute(
        "INSERT INTO private.memory_evidence (memory_id, evidence_id, role, grounding_mode) \
         VALUES ($1, $2, 'SUPPORTING', 'SNAPSHOT')",
        &[&memory_id, &evidence_id],
    )
    .expect("owner links the second Evidence");
    txn.commit().expect("commit second evidence seed");
    evidence_id
}

fn seed(handle: &mut Handle) -> World {
    handle
        .admin
        .execute(
            "INSERT INTO projection.stream_checkpoints \
               (tenant_id, scope_kind, scope_id, domain, projection_kind, projection_version, serving) \
             VALUES ($1, 'workspace', $2, $3, $4, $5, false)",
            &[
                &handle.tenant_id,
                &handle.workspace_id,
                &DOMAIN,
                &PROJECTION_KIND,
                &PROJECTION_VERSION,
            ],
        )
        .expect("owner seeds the family checkpoint");
    let ctrl = handle.seed_workspace_visible_context_record();
    set_content(
        handle,
        ctrl.memory_id,
        &json!({"title": format!("title {CTRL_MARK}"), "key_claim": format!("{TOKEN} control {CTRL_MARK}")}),
    );
    link_second_evidence(handle, ctrl.memory_id, false);
    let gated = handle.seed_workspace_visible_context_record();
    set_content(
        handle,
        gated.memory_id,
        &json!({"title": format!("title {HIDDEN_MARK}"), "key_claim": format!("{TOKEN} gated {HIDDEN_MARK}")}),
    );
    let gated_second_evidence = link_second_evidence(handle, gated.memory_id, true);
    let family = StreamFamily::new(
        TenantId(handle.tenant_id),
        "workspace",
        handle.workspace_id,
        DOMAIN,
        PROJECTION_KIND,
    );
    World {
        ctrl: ctrl.memory_id,
        gated: gated.memory_id,
        gated_second_evidence,
        scope: Scope {
            tenant_id: TenantId(handle.tenant_id),
            user_id: Some(UserId(handle.user_id)),
            workspace_id: Some(WorkspaceId(handle.workspace_id)),
            repository_id: None,
            task_id: None,
            run_id: None,
            agent_id: None,
        },
        key: family.with_version(PROJECTION_VERSION),
        family,
    }
}

/// `visible` = how many of the two memories the caller may read in this phase (1 while the second Evidence is hidden).
fn check(world: &World, handle: &Handle, visible: u64) {
    let expected: BTreeSet<Uuid> = if visible == 2 {
        BTreeSet::from([world.ctrl, world.gated])
    } else {
        BTreeSet::from([world.ctrl])
    };
    for (name, op) in OPS {
        let seen = op(world, handle);
        assert_eq!(
            seen.ids, expected,
            "{name}: admitted memories with {visible} readable"
        );
        for (count, value) in &seen.counts {
            let want = if *count == "mandatory missing" {
                0
            } else {
                visible
            };
            assert_eq!(*value, want, "{name}: {count} with {visible} readable");
        }
        if visible == 1 {
            assert!(
                !seen.text.contains(HIDDEN_MARK),
                "{name}: the unreadable memory's text leaked"
            );
            assert!(
                !seen.text.contains(&world.gated.to_string()),
                "{name}: the unreadable memory's id leaked"
            );
            assert!(
                !seen.text.contains(&world.gated_second_evidence.to_string()),
                "{name}: the unreadable Evidence id leaked"
            );
        }
        if name == "memory.get" {
            let refused: Vec<(Uuid, bool)> = seen
                .refused
                .iter()
                .map(|(id, code)| (*id, matches!(code, ErrorCode::NotFound)))
                .collect();
            let want: Vec<(Uuid, bool)> = if visible == 1 {
                vec![(world.gated, true)]
            } else {
                Vec::new()
            };
            assert_eq!(
                refused, want,
                "memory.get refuses with NOT_FOUND, never another code"
            );
        } else if name == "memory.grep" || name == "context.assemble" {
            assert!(!seen.counts.is_empty(), "{name}: reported no counts");
        }
    }
}

#[test]
fn unreadable_backing_evidence_removes_the_memory_from_every_read_op() {
    let _lock = serial();
    run_db_fixture::<Fixture, _>(
        "unreadable_backing_evidence_removes_the_memory_from_every_read_op",
        |mut handle| {
            let world = seed(&mut handle);
            // One of the gated memory's two Evidence rows is hidden from the caller by RLS: the closure fails closed.
            check(&world, &handle, 1);
            // The same memory, its second Evidence made readable: every op now returns it, so the absence above was the
            // closure and not an op that returns nothing.
            handle
                .admin
                .execute(
                    "UPDATE private.evidence_objects \
                     SET visibility_class = 'TENANT_SHARED', visibility_user_id = NULL \
                     WHERE evidence_id = $1",
                    &[&world.gated_second_evidence],
                )
                .expect("owner makes the second Evidence readable");
            check(&world, &handle, 2);
        },
    );
}

fn goal(value: &Value) -> &Value {
    value["facets"]
        .as_array()
        .expect("facets")
        .iter()
        .find(|facet| facet["kind"] == "GOAL")
        .expect("GOAL facet")
}

#[test]
fn unreadable_backing_evidence_makes_the_continuity_source_stale_not_current() {
    let _lock = serial();
    const NAME: &str = "unreadable_backing_evidence_makes_the_continuity_source_stale_not_current";
    let Some(dsn) = continuity_0137_fixture::required_dsn() else {
        skip_or_fail(
            NAME,
            "not_applicable: HUMAUX_TEST_PG_DSN (isolated PostgreSQL for the continuity fixture, §57.1)",
            ExternalDep::Postgres,
        );
        return;
    };
    let fixture = continuity_0137_fixture::Fixture::new(dsn, NAME);
    let control = fixture.read().expect("control read");
    assert_eq!(goal(&control)["status"], "CURRENT", "control: {control}");

    let hidden = fixture.add_second_backing_evidence(true);
    let value = fixture
        .read()
        .expect("a hidden second source is a stale facet, not a failed read");
    let facet = goal(&value);
    assert_eq!(facet["status"], "STALE", "{value}");
    assert_eq!(
        facet["diagnostic_code"], "SOURCE_REVALIDATION_FAILED",
        "{value}"
    );
    assert!(
        facet.get("current").is_none(),
        "non-current payload leaked: {value}"
    );
    let wire = value.to_string();
    assert!(
        !wire.contains("authoritative memory") && !wire.contains(&hidden.to_string()),
        "continuity leaked the unreadable source: {wire}"
    );

    fixture.make_evidence_readable(hidden);
    let restored = fixture.read().expect("read with both sources readable");
    assert_eq!(goal(&restored)["status"], "CURRENT", "{restored}");
}

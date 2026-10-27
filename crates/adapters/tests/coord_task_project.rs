//! `adapters::tests::coord_task_project` — M18-3a gate G-M18-6, dynamic half (ADR-0102 D-A, D-C, D-D): the one door
//!   `coord_task_repo::set_task_project_in_txn` writes `coord.tasks.project_id` and, in the same transaction, closes the
//!   old Project CONTAINS Task revision and opens the new one at one DB-clock instant; no other caller can write a
//!   CONTAINS revision.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, sqlx, tokio];
//!   services=[PostgreSQL(owner) r=[coord.tasks, coord.workspace_unfiled_projects, private.memory_projects,
//!   private.project_task_relations] w=[private.continuity_projects, private.evidence_objects,
//!   private.evidence_task_runs, private.memory_evidence, private.memory_records, private.project_task_relations],
//!   PostgreSQL(role_gateway)];
//!   env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::attribution_repo, adapters::coord_repo, adapters::coord_task_repo,
//!   adapters::memory_repo, adapters::relation_repo, adapters::tests::support::operation_receipt_fixture,
//!   domain::continuity, domain::error, domain::identity, domain::ids, domain::relation, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [every move runs the real door in its own role_gateway transaction (tenant and user GUCs installed the
//!   way the gateway installs them); the owner connection only seeds projects and Evidence, reads the mapping and
//!   removes the append-only relation rows a committed test leaves; a rolled-back owner transaction carries the A3
//!   ladder run so the Evidence, carrier and memory rows it needs never outlive it; every refusal case has a passing
//!   positive control in the same test]
//! Spec: Baseline §6.1.4; §30; §52; §79.2; §80.1; ADR-0078 D-C; ADR-0102 D-A; ADR-0102 D-C; ADR-0102 D-D
//!
//! Runs on the real `coord.tasks.project_id` and `private.project_task_relations` (migrations 0249, 0252, 0255, 0289).
//! "The mapping" below is the pair of facts ADR-0102 D-A keeps in step: a non-Unfiled task has exactly one open CONTAINS
//! revision (its relation's highest revision, valid upper-unbounded) whose `src_id` is its `project_id`, and an Unfiled
//! task has none (N09 R3: Unfiled attributes nothing).
//!
//! | test | gate | injected fault that turns it red |
//! |---|---|---|
//! | `g_m18_6_a_move_closes_the_old_edge_and_opens_the_new_one_at_one_instant` | G-M18-6 (a) | the door skips the open (r2) or the close |
//! | `g_m18_6_b_a3_reads_the_old_project_before_the_move_and_the_new_one_from_it` | G-M18-6 (b) | the door skips the close (r1) |
//! | `g_m18_6_c_moving_back_reopens_the_same_relation` | G-M18-6 (c) | the open always mints a new relation id |
//! | `g_m18_6_d_append_revision_refuses_contains` | G-M18-6 (d) | `append_revision` stops refusing CONTAINS (r3) |
//! | `g_m18_6_e_an_invisible_target_is_not_found_and_writes_nothing` | G-M18-6 (e) | the visibility check moves after a write |
//! | `g_m18_6_f_concurrent_moves_never_leave_two_open_edges` | G-M18-6 (f) | the task row is read without `FOR UPDATE` |
//!
//! Skip contract (`humaux_testkit`, §79.2): no DSN / unreachable / migrations not applied each print a visible SKIP and
//! return (a required-DB run turns a skip red).

use std::collections::BTreeSet;
use std::ops::Bound::{Included, Unbounded};
use std::time::Duration;

use humaux_adapters::attribution_repo::AttributionLadder;
use humaux_adapters::coord_repo::{self, ClaimedTaskRun};
use humaux_adapters::coord_task_repo::set_task_project_in_txn;
use humaux_adapters::memory_repo::MemoryAttribution;
use humaux_adapters::relation_repo::append_revision;
use humaux_domain::continuity::ProjectId;
use humaux_domain::error::ErrorCode;
use humaux_domain::identity::PrincipalId;
use humaux_domain::ids::TaskId;
use humaux_domain::relation::{
    DecidedBy, RelationEdge, RelationId, RelationKind, Timestamp, Validity,
};
use humaux_testkit::run_db_fixture;
use sqlx::types::Uuid;
use sqlx::{Connection, PgConnection};

#[allow(dead_code)]
#[path = "support/operation_receipt_fixture.rs"]
mod operation_receipt_fixture;

use operation_receipt_fixture::{Fixture, Handle};

const TTL: Duration = Duration::from_secs(300);

/// 2026-01-01T00:00:00Z in µs: the window of the `append_revision` control case.
const T0: i64 = 1_767_225_600_000_000;

/// One CONTAINS revision as `(relation_id, revision, segments)`, a segment being `(start, end)` in µs with `None` for
/// an open end.
type Edge = (Uuid, i64, Vec<(i64, Option<i64>)>);

/// Every task of the tenant with its column, whether that project is an Unfiled one, how many CONTAINS edges are open
/// for it and how many of those name the column's project.
const MAPPING_SQL: &str = "\
WITH live AS ( \
  SELECT cur.dst_id AS task_id, cur.src_id \
    FROM (SELECT DISTINCT ON (r.relation_id) r.src_id, r.dst_id, r.relation_kind, r.valid \
            FROM private.project_task_relations r WHERE r.tenant_id = $1 \
           ORDER BY r.relation_id, r.revision DESC) cur \
   WHERE cur.relation_kind = 'CONTAINS' AND upper_inf(cur.valid)) \
SELECT t.task_id, t.project_id, \
       EXISTS (SELECT 1 FROM coord.workspace_unfiled_projects u \
                WHERE u.tenant_id = t.tenant_id AND u.project_id = t.project_id), \
       (SELECT count(*) FROM live o WHERE o.task_id = t.task_id), \
       (SELECT count(*) FROM live o WHERE o.task_id = t.task_id AND o.src_id = t.project_id) \
  FROM coord.tasks t WHERE t.tenant_id = $1";

/// The owner DSN the fixture ran against.
fn dsn() -> String {
    std::env::var("HUMAUX_TEST_PG_DSN").expect("the fixture ran, so the DSN is set")
}

/// An Evidence of the fixture tenant: the authorization Evidence every revision of the door cites (0253).
fn authorization_evidence(handle: &mut Handle) -> Uuid {
    handle
        .admin
        .query_one(
            "INSERT INTO private.evidence_objects (tenant_id, evidence_kind, payload_sha256, data_class, \
               origin_class, visibility_class, visibility_workspace_id, reasoning_domain_id) \
             VALUES ($1, 'EVENT', sha256('coord_task_project authorization'::bytea), 'INTERNAL', \
               'DirectUserInput', 'WORKSPACE_SHARED', $2, $3) RETURNING evidence_id",
            &[
                &handle.tenant_id,
                &handle.workspace_id,
                &handle.reasoning_domain_id,
            ],
        )
        .expect("owner seeds the authorization Evidence")
        .get(0)
}

/// An ACTIVE project of `workspace` (owner INSERT; the door only needs the row, not its facet slots).
fn project(handle: &mut Handle, workspace: Uuid) -> Uuid {
    handle
        .admin
        .query_one(
            "INSERT INTO private.continuity_projects (project_id, tenant_id, workspace_id, title) \
             VALUES (uuidv7(), $1, $2, 'coord_task_project') RETURNING project_id",
            &[&handle.tenant_id, &workspace],
        )
        .expect("owner seeds a project")
        .get(0)
}

/// Two projects of the fixture workspace and the authorization Evidence.
fn world(handle: &mut Handle) -> (Uuid, Uuid, Uuid) {
    let workspace = handle.workspace_id;
    let authz = authorization_evidence(handle);
    (
        project(handle, workspace),
        project(handle, workspace),
        authz,
    )
}

/// The Unfiled project of the fixture workspace, which the first `submit` registers.
fn unfiled(handle: &mut Handle) -> Uuid {
    handle
        .admin
        .query_one(
            "SELECT project_id FROM coord.workspace_unfiled_projects WHERE tenant_id = $1 AND workspace_id = $2",
            &[&handle.tenant_id, &handle.workspace_id],
        )
        .expect("the submit registered the workspace's Unfiled project")
        .get(0)
}

/// A fresh task of the fixture principal; it is born in the workspace's Unfiled project.
fn submit(handle: &Handle) -> TaskId {
    handle
        .rt
        .block_on(coord_repo::submit(
            &handle.runtime,
            &handle.auth,
            "coord_task_project",
            "M18-3a gate",
        ))
        .expect("submit")
}

/// A claimed run of `task` by the fixture principal.
fn claim(handle: &Handle, task: TaskId) -> ClaimedTaskRun {
    handle
        .rt
        .block_on(coord_repo::claim(&handle.runtime, &handle.auth, task, TTL))
        .expect("claim")
}

/// `coord.tasks.project_id` of `task`, read as the owner.
fn column(handle: &mut Handle, task: TaskId) -> Uuid {
    handle
        .admin
        .query_one(
            "SELECT project_id FROM coord.tasks WHERE tenant_id = $1 AND task_id = $2",
            &[&handle.tenant_id, &task.0],
        )
        .expect("owner reads the task")
        .get(0)
}

/// Every revision of `project CONTAINS task`, oldest first.
fn edges(handle: &mut Handle, project: Uuid, task: TaskId) -> Vec<Edge> {
    handle
        .admin
        .query(
            "SELECT r.relation_id, r.revision, \
                    array(SELECT (extract(epoch FROM lower(x)) * 1000000)::bigint \
                            FROM unnest(r.valid) x ORDER BY lower(x)), \
                    array(SELECT (extract(epoch FROM upper(x)) * 1000000)::bigint \
                            FROM unnest(r.valid) x ORDER BY lower(x)) \
               FROM private.project_task_relations r \
              WHERE r.tenant_id = $1 AND r.src_id = $2 AND r.dst_id = $3 AND r.relation_kind = 'CONTAINS' \
              ORDER BY r.revision",
            &[&handle.tenant_id, &project, &task.0],
        )
        .expect("owner reads the CONTAINS revisions")
        .iter()
        .map(|row| {
            let starts: Vec<i64> = row.get(2);
            let ends: Vec<Option<i64>> = row.get(3);
            (row.get(0), row.get(1), starts.into_iter().zip(ends).collect())
        })
        .collect()
}

/// How many revisions of any relation name `task`, read as the owner.
fn relation_rows(handle: &mut Handle, task: TaskId) -> i64 {
    handle
        .admin
        .query_one(
            "SELECT count(*) FROM private.project_task_relations WHERE tenant_id = $1 AND dst_id = $2",
            &[&handle.tenant_id, &task.0],
        )
        .expect("owner counts the revisions")
        .get(0)
}

/// The tasks of the tenant that break the mapping (see the module doc); empty when it holds everywhere.
fn violations(handle: &mut Handle) -> Vec<String> {
    handle
        .admin
        .query(MAPPING_SQL, &[&handle.tenant_id])
        .expect("owner reads the mapping")
        .iter()
        .filter_map(|row| {
            let (task, project): (Uuid, Uuid) = (row.get(0), row.get(1));
            let (is_unfiled, open, matching): (bool, i64, i64) =
                (row.get(2), row.get(3), row.get(4));
            let holds = if is_unfiled {
                open == 0
            } else {
                open == 1 && matching == 1
            };
            (!holds).then(|| {
                format!(
                    "task {task} in {project}: unfiled={is_unfiled} open={open} matching={matching}"
                )
            })
        })
        .collect()
}

/// Removes the append-only relation rows a committed test leaves (replica mode lets the owner past their triggers);
/// the fixture's own teardown knows nothing about them.
fn purge_relations(handle: &mut Handle) {
    let tenant = handle.tenant_id;
    handle
        .admin
        .batch_execute(&format!(
            "SET session_replication_role = replica; \
             DELETE FROM private.project_task_relations WHERE tenant_id = '{tenant}'; \
             SET session_replication_role = DEFAULT;"
        ))
        .expect("owner purges the relation rows");
}

/// One owner connection switched to `role_gateway` with the request GUCs the gateway installs, in a new transaction.
async fn gateway_txn<'c>(
    conn: &'c mut PgConnection,
    handle: &Handle,
) -> sqlx::Transaction<'c, sqlx::Postgres> {
    // dep: PostgreSQL(any) — pool/txn query execution
    let mut txn = conn.begin().await.expect("begin");
    // dep: PostgreSQL(role_gateway) — test switches PG role to exercise RLS
    sqlx::query("SET LOCAL ROLE role_gateway")
        .execute(&mut *txn)
        .await
        .expect("gateway role");
    sqlx::query(
        "SELECT set_config('humaux.tenant_id', $1, true), set_config('humaux.user_id', $2, true)",
    )
    .bind(handle.tenant_id.to_string())
    .bind(handle.user_id.to_string())
    .execute(&mut *txn)
    .await
    .expect("request GUCs");
    txn
}

/// `principal:<fixture user>`: an ACTIVE member of the fixture tenant (0253).
fn decider(handle: &Handle) -> DecidedBy {
    DecidedBy::Principal(PrincipalId(handle.user_id))
}

/// The door in its own `role_gateway` transaction. The transaction is committed whatever the door answered, so a
/// refusal that had written anything would show in the tables the caller reads next.
async fn move_in(
    handle: &Handle,
    authz: Uuid,
    task: TaskId,
    project: Uuid,
) -> Result<(), ErrorCode> {
    // dep: PostgreSQL(owner) — test opens a direct PG connection for setup/verification
    let mut conn = PgConnection::connect(&dsn())
        .await
        .expect("owner connection");
    let mut txn = gateway_txn(&mut conn, handle).await;
    let moved = set_task_project_in_txn(
        &mut txn,
        &handle.auth,
        task,
        ProjectId(project),
        &decider(handle),
        &[],
        authz,
    )
    .await;
    txn.commit().await.expect("commit");
    moved
}

/// [`move_in`] to completion.
fn move_task(handle: &Handle, authz: Uuid, task: TaskId, project: Uuid) -> Result<(), ErrorCode> {
    handle.rt.block_on(move_in(handle, authz, task, project))
}

/// The projects A3 attributes a memory to, when its attribution Evidence occurred at `occurred_at` (µs) on `run`: one
/// rolled-back owner transaction seeds that Evidence, its task-run carrier and a memory, runs the real
/// [`AttributionLadder`], and reads the `memory_projects` rows it wrote.
fn attribute(handle: &Handle, run: &ClaimedTaskRun, occurred_at: i64) -> Vec<Uuid> {
    handle.rt.block_on(async {
        // dep: PostgreSQL(owner) — test opens a direct PG connection for setup/verification
        let mut conn = PgConnection::connect(&dsn())
            .await
            .expect("owner connection");
        // dep: PostgreSQL(any) — pool/txn query execution
        let mut txn = conn.begin().await.expect("begin");
        sqlx::query("SELECT set_config('humaux.tenant_id', $1, true)")
            .bind(handle.tenant_id.to_string())
            .execute(&mut *txn)
            .await
            .expect("session tenant");
        let evidence: Uuid = sqlx::query_scalar(
            "INSERT INTO private.evidence_objects (tenant_id, evidence_kind, payload_sha256, data_class, \
               origin_class, visibility_class, visibility_workspace_id, reasoning_domain_id, occurred_at) \
             VALUES ($1, 'EVENT', sha256(convert_to($2, 'UTF8')), 'INTERNAL', 'DirectUserInput', \
               'WORKSPACE_SHARED', $3, $4, \
               to_timestamp($5::bigint / 1000000) + ($5::bigint % 1000000) * interval '1 microsecond') \
             RETURNING evidence_id",
        )
        .bind(handle.tenant_id)
        .bind(format!("coord_task_project {occurred_at}"))
        .bind(handle.workspace_id)
        .bind(handle.reasoning_domain_id)
        .bind(occurred_at)
        .fetch_one(&mut *txn)
        .await
        .expect("owner seeds the attribution Evidence");
        sqlx::query(
            "INSERT INTO private.evidence_task_runs (tenant_id, evidence_id, task_run_id, fencing_token) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(handle.tenant_id)
        .bind(evidence)
        .bind(run.task_run_id.0)
        .bind(run.fencing_token.0)
        .execute(&mut *txn)
        .await
        .expect("owner seeds the task-run carrier");
        let memory: Uuid = sqlx::query_scalar(
            "INSERT INTO private.memory_records (tenant_id, memory_type, content, visibility_class, \
               visibility_workspace_id, authority_class, confidence, status, asserted_at) \
             VALUES ($1, 'NOTE', jsonb_build_object('fixture', 'coord_task_project'), 'WORKSPACE_SHARED', $2, \
               'ProjectConstraint', 0.9, 'active', clock_timestamp()) RETURNING memory_id",
        )
        .bind(handle.tenant_id)
        .bind(handle.workspace_id)
        .fetch_one(&mut *txn)
        .await
        .expect("owner seeds the memory");
        sqlx::query(
            "INSERT INTO private.memory_evidence (memory_id, evidence_id, role, grounding_mode) \
             VALUES ($1, $2, 'PRIMARY', 'SNAPSHOT')",
        )
        .bind(memory)
        .bind(evidence)
        .execute(&mut *txn)
        .await
        .expect("owner links the memory to its Evidence");
        AttributionLadder
            .link_memory_projects(&mut txn, handle.tenant_id, memory, evidence)
            .await
            .expect("the ladder runs");
        let projects: Vec<Uuid> = sqlx::query_scalar(
            "SELECT project_id FROM private.memory_projects WHERE tenant_id = $1 AND memory_id = $2 \
             ORDER BY project_id",
        )
        .bind(handle.tenant_id)
        .bind(memory)
        .fetch_all(&mut *txn)
        .await
        .expect("owner reads memory_projects");
        txn.rollback().await.expect("rollback");
        projects
    })
}

/// G-M18-6 (a): a move writes the column and, at one instant `t`, ends the old project's edge and opens the new one's;
/// the mapping holds after every step, and a move into Unfiled closes without opening.
#[test]
fn g_m18_6_a_move_closes_the_old_edge_and_opens_the_new_one_at_one_instant() {
    run_db_fixture::<Fixture, _>(
        "g_m18_6_a_move_closes_the_old_edge_and_opens_the_new_one_at_one_instant",
        |mut handle| {
            let (p1, p2, authz) = world(&mut handle);
            let task = submit(&handle);
            let home = unfiled(&mut handle);
            assert_eq!(column(&mut handle, task), home, "a submit lands in Unfiled");
            assert!(
                edges(&mut handle, home, task).is_empty(),
                "Unfiled carries no CONTAINS"
            );

            assert_eq!(move_task(&handle, authz, task, p1), Ok(()), "Unfiled -> P1");
            assert_eq!(move_task(&handle, authz, task, p2), Ok(()), "P1 -> P2");
            let on_p1 = edges(&mut handle, p1, task);
            let on_p2 = edges(&mut handle, p2, task);
            let column_now = column(&mut handle, task);
            let broken = violations(&mut handle);
            assert_eq!(column_now, p2, "the column follows the move");
            assert_eq!(broken, Vec::<String>::new(), "the mapping holds");
            assert_eq!(
                on_p1.iter().map(|e| e.1).collect::<Vec<_>>(),
                [1, 2],
                "P1: opened, then closed"
            );
            let t0 = on_p1[0].2[0].0;
            let t1 = on_p2[0].2[0].0;
            assert!(t0 < t1, "the second move is later on the DB clock");
            assert_eq!(on_p1[0].2, [(t0, None)], "P1 revision 1 is open from t0");
            assert_eq!(
                on_p1[1].2,
                [(t0, Some(t1))],
                "P1's latest valid ends exactly where P2's begins"
            );
            assert_eq!(on_p1[0].0, on_p1[1].0, "one relation id for the edge");
            assert_eq!(
                on_p2.iter().map(|e| (e.1, e.2.clone())).collect::<Vec<_>>(),
                [(1, vec![(t1, None)])],
                "P2 is open from t1"
            );

            assert_eq!(
                move_task(&handle, authz, task, home),
                Ok(()),
                "P2 -> Unfiled"
            );
            let closed = edges(&mut handle, p2, task);
            let home_edges = edges(&mut handle, home, task);
            let column_home = column(&mut handle, task);
            let broken = violations(&mut handle);
            assert_eq!(column_home, home);
            assert!(home_edges.is_empty(), "Unfiled still carries none");
            assert_eq!(closed.len(), 2, "P2: opened, then closed");
            assert!(
                closed[1].2.iter().all(|(_, end)| end.is_some()),
                "P2 has no open segment left"
            );
            assert_eq!(broken, Vec::<String>::new(), "the mapping holds in Unfiled");
            purge_relations(&mut handle);
        },
    );
}

/// G-M18-6 (b): A3 through the real ladder reads the old project for an Evidence that occurred before the move and
/// the new one from the move on, with no gap or overlap at `t` itself.
#[test]
fn g_m18_6_b_a3_reads_the_old_project_before_the_move_and_the_new_one_from_it() {
    run_db_fixture::<Fixture, _>(
        "g_m18_6_b_a3_reads_the_old_project_before_the_move_and_the_new_one_from_it",
        |mut handle| {
            let (p1, p2, authz) = world(&mut handle);
            let task = submit(&handle);
            let run = claim(&handle, task);
            assert_eq!(move_task(&handle, authz, task, p1), Ok(()), "Unfiled -> P1");
            assert_eq!(move_task(&handle, authz, task, p2), Ok(()), "P1 -> P2");
            let t = edges(&mut handle, p2, task)[0].2[0].0;
            let before = attribute(&handle, &run, t - 1);
            let at = attribute(&handle, &run, t);
            let after = attribute(&handle, &run, t + 1_000_000);
            purge_relations(&mut handle);
            assert_eq!(before, [p1], "occurred_at before t: P1 only");
            assert_eq!(at, [p2], "occurred_at at t: P2 only");
            assert_eq!(after, [p2], "occurred_at after t: P2 only");
        },
    );
}

/// G-M18-6 (c): moving back to a project reuses that project's relation (revision 3, two segments), so the unique
/// revision-1 index never fires.
#[test]
fn g_m18_6_c_moving_back_reopens_the_same_relation() {
    run_db_fixture::<Fixture, _>(
        "g_m18_6_c_moving_back_reopens_the_same_relation",
        |mut handle| {
            let (p1, p2, authz) = world(&mut handle);
            let task = submit(&handle);
            for (step, target) in [("P1", p1), ("P2", p2), ("P1 again", p1)] {
                assert_eq!(move_task(&handle, authz, task, target), Ok(()), "-> {step}");
            }
            let on_p1 = edges(&mut handle, p1, task);
            let on_p2 = edges(&mut handle, p2, task);
            let broken = violations(&mut handle);
            let column_now = column(&mut handle, task);
            purge_relations(&mut handle);
            assert_eq!(column_now, p1);
            assert_eq!(broken, Vec::<String>::new(), "the mapping holds");
            assert_eq!(
                on_p1.iter().map(|e| e.1).collect::<Vec<_>>(),
                [1, 2, 3],
                "P1: opened, closed, reopened"
            );
            assert_eq!(
                on_p1.iter().map(|e| e.0).collect::<BTreeSet<_>>().len(),
                1,
                "one relation id for P1 CONTAINS the task"
            );
            let (t0, t1) = (on_p1[0].2[0].0, on_p2[0].2[0].0);
            let t2 = on_p2[1].2[0].1.expect("P2 was closed by the move back");
            assert_eq!(
                on_p1[2].2,
                [(t0, Some(t1)), (t2, None)],
                "revision 3 keeps the first stay and opens a second at the move back"
            );
        },
    );
}

/// G-M18-6 (d): `relation_repo::append_revision` refuses a CONTAINS edge before any SQL, so the door is the only way
/// in; the same call for `REFERENCES` is the positive control.
#[test]
fn g_m18_6_d_append_revision_refuses_contains() {
    run_db_fixture::<Fixture, _>(
        "g_m18_6_d_append_revision_refuses_contains",
        |mut handle| {
            let (p1, _, authz) = world(&mut handle);
            let task = submit(&handle);
            let contains = RelationEdge {
                src_id: p1,
                kind: RelationKind::Contains,
                dst_id: task.0,
            };
            let references = RelationEdge {
                kind: RelationKind::References,
                ..contains
            };
            let (refused_relation, control_relation) = (RelationId::new(), RelationId::new());
            let valid = Validity::new(&[(Included(Timestamp::Micros(T0)), Unbounded)])
                .expect("open window");
            let decided = decider(&handle);
            let (refused, rows_after_refusal, control) = handle.rt.block_on(async {
                // dep: PostgreSQL(owner) — test opens a direct PG connection for setup/verification
                let mut conn = PgConnection::connect(&dsn())
                    .await
                    .expect("owner connection");
                let mut txn = gateway_txn(&mut conn, &handle).await;
                let refused = append_revision(
                    &mut txn,
                    &contains,
                    refused_relation,
                    0,
                    &valid,
                    &decided,
                    None,
                    &[],
                    authz,
                )
                .await;
                let rows: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM private.project_task_relations WHERE relation_id = $1",
                )
                .bind(refused_relation.0)
                .fetch_one(&mut *txn)
                .await
                .expect("the refused relation's rows");
                let control = append_revision(
                    &mut txn,
                    &references,
                    control_relation,
                    0,
                    &valid,
                    &decided,
                    None,
                    &[],
                    authz,
                )
                .await;
                txn.rollback().await.expect("rollback");
                (refused, rows, control)
            });
            assert_eq!(refused, Err(ErrorCode::InvalidInput), "CONTAINS is refused");
            assert_eq!(rows_after_refusal, 0, "and writes no row");
            assert_eq!(control, Ok(1), "REFERENCES stays free");
        },
    );
}

/// G-M18-6 (e): a target the scope cannot see (unknown, or in a workspace outside the scope) and an absent task are
/// `NOT_FOUND`, and the committed transaction left the column and the relations untouched; a visible target moves.
#[test]
fn g_m18_6_e_an_invisible_target_is_not_found_and_writes_nothing() {
    run_db_fixture::<Fixture, _>(
        "g_m18_6_e_an_invisible_target_is_not_found_and_writes_nothing",
        |mut handle| {
            let (visible, _, authz) = world(&mut handle);
            let task = submit(&handle);
            let home = unfiled(&mut handle);
            let other_workspace = handle.seed_workspace();
            let elsewhere = project(&mut handle, other_workspace);
            for (label, target) in [
                ("unknown project", Uuid::now_v7()),
                ("project of a workspace outside the scope", elsewhere),
            ] {
                assert_eq!(
                    move_task(&handle, authz, task, target),
                    Err(ErrorCode::NotFound),
                    "{label}"
                );
                assert_eq!(column(&mut handle, task), home, "{label}: column untouched");
                assert_eq!(
                    relation_rows(&mut handle, task),
                    0,
                    "{label}: no relation row"
                );
            }
            assert_eq!(
                move_task(&handle, authz, TaskId(Uuid::now_v7()), visible),
                Err(ErrorCode::NotFound),
                "absent task"
            );
            assert_eq!(move_task(&handle, authz, task, visible), Ok(()), "control");
            let column_now = column(&mut handle, task);
            purge_relations(&mut handle);
            assert_eq!(column_now, visible);
        },
    );
}

/// G-M18-6 (f): two moves of one task, racing for its row, take turns; whichever lands last, the task has exactly one
/// open edge and it is the column's project.
#[test]
fn g_m18_6_f_concurrent_moves_never_leave_two_open_edges() {
    run_db_fixture::<Fixture, _>(
        "g_m18_6_f_concurrent_moves_never_leave_two_open_edges",
        |mut handle| {
            let (p1, p2, authz) = world(&mut handle);
            for round in 0..8 {
                let task = submit(&handle);
                let (to_p1, to_p2) = handle.rt.block_on(async {
                    tokio::join!(
                        move_in(&handle, authz, task, p1),
                        move_in(&handle, authz, task, p2)
                    )
                });
                assert_eq!((to_p1, to_p2), (Ok(()), Ok(())), "round {round}");
            }
            let broken = violations(&mut handle);
            purge_relations(&mut handle);
            assert_eq!(broken, Vec::<String>::new(), "the mapping holds");
        },
    );
}

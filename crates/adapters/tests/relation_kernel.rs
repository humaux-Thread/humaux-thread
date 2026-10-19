//! `adapters::tests::relation_kernel` — M29 T05 gates G-M29-1 (whitelist part), G-M29-2, G-M29-3, G-M29-4 for the
//!   §6.1.4 relation kernel (migration 0249, ADR-0078 D-C), plus the adapter round trip and the 0252 guard / edge
//!   index (issue #92 items 4 and 5, M29 T06a).
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, postgres, sqlx, tokio, uuid];
//!   services=[PostgreSQL(owner) r=[private.project_subject_relations, private.project_task_relations,
//!   private.subject_relations] w=[control.tenants, control.workspaces, coord.tasks, private.continuity_projects,
//!   private.subjects] x=[private.relation_triple_allowed, private.relation_valid_shape], PostgreSQL(role_gateway)];
//!   env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::relation_repo, domain::error, domain::identity, domain::relation,
//!   domain::subject, humaux-testkit, testkit::fixture_purge]
//! Called-by: [cargo-test]
//! Invariants: [every gate compares the Rust closed set / rule with the live migration objects, never a copy; each
//!   gate has one injected fault that turns it red (ADR-0078 gate table, §80.1)]
//! Spec: Baseline §6.1.4; §78.2; §79.2; §80.1; ADR-0078 D-C
//!
//! Runs against the real `private` objects of migration 0249 (the gates are about those objects, not a scratch
//! copy). Each test seeds its own fixture tenant (`e2e-fixture …`: one workspace, project, task and one subject per
//! `SubjectKind`) and purges it through `humaux_testkit::fixture_purge` on drop. Only G-M29-3 commits relation rows;
//! every other test writes inside a rolled-back transaction.
//!
//! | test | gate | injected fault that turns it red |
//! |---|---|---|
//! | `g_m29_1_relation_kind_checks_match_domain` | G-M29-1 | a kind in one table's `relation_kind` CHECK only |
//! | `g_m29_1_whitelist_matches_db` | G-M29-1 | a triple in `private.relation_triple_allowed` only |
//! | `g_m29_2_valid_shape_rust_and_db_agree` | G-M29-2 | drop `NOT upper_inc(r)` from `private.relation_valid_shape` |
//! | `g_m29_3_concurrent_cas_exactly_one_wins` | G-M29-3 | widen the PK past `revision` |
//! | `g_m29_4_no_role_updates_or_deletes_revisions` | G-M29-4 | `GRANT UPDATE` to a runtime role |
//! | `null_tenant_append_is_forbidden` | #92 item 4 (M29 T06a) | drop 0252's NULL-tenant line from the guard |
//! | `a_second_relation_id_for_one_edge_conflicts` | #92 item 5 (M29 T06a) | a predicate no revision matches on the edge index |
//!
//! Skip contract (`humaux_testkit`, §79.2): no DSN / unreachable / migration 0249 not applied each print a visible
//! SKIP and return (a required-DB run turns a skip red).

use std::collections::BTreeSet;
use std::ops::Bound::{Excluded, Included, Unbounded};
use std::time::{Duration, Instant};

use humaux_adapters::relation_repo::{RelationRevision, append_revision, current_revision};
use humaux_domain::error::ErrorCode;
use humaux_domain::identity::PrincipalId;
use humaux_domain::relation::{
    DecidedBy, EndpointKind, ModelRef, RawRange, RelationEdge, RelationId, RelationKind,
    RelationPair, RuleRef, Timestamp, Validity, WHITELIST,
};
use humaux_domain::subject::SubjectKind;
use humaux_testkit::fixture_purge::purge_tenant_fixture_sql;
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::error::SqlState;
use postgres::{Client, NoTls};
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

/// 2026-01-01T00:00:00Z in µs; the cases below are offsets from it.
const T0: i64 = 1_767_225_600_000_000;
const DAY: i64 = 86_400_000_000;

/// §6.2.0's non-owner roles: the five runtime roles plus batch_issuer, maintenance and admin.
const NON_OWNER_ROLES: [&str; 8] = [
    "role_gateway",
    "role_private_worker",
    "role_consolidation_worker",
    "role_public_worker",
    "role_retrieval_worker",
    "role_batch_issuer",
    "role_maintenance",
    "role_admin",
];

struct Fx {
    client: Client,
    dsn: String,
    tenant: Uuid,
    project: Uuid,
    task: Uuid,
    subjects: Vec<(SubjectKind, Uuid)>,
}

impl Fx {
    fn subject(&self, kind: SubjectKind) -> Uuid {
        self.subjects.iter().find(|(k, _)| *k == kind).unwrap().1
    }

    fn table(pair: RelationPair) -> &'static str {
        match pair {
            RelationPair::ProjectTask => "private.project_task_relations",
            RelationPair::ProjectSubject => "private.project_subject_relations",
            RelationPair::SubjectSubject => "private.subject_relations",
        }
    }

    /// One whitelisted edge per pair.
    fn edge(&self, pair: RelationPair) -> RelationEdge {
        let (src_id, kind, dst_id) = match pair {
            RelationPair::ProjectTask => (self.project, RelationKind::Contains, self.task),
            RelationPair::ProjectSubject => (
                self.project,
                RelationKind::Targets,
                self.subject(SubjectKind::Website),
            ),
            RelationPair::SubjectSubject => (
                self.subject(SubjectKind::Website),
                RelationKind::OwnedBy,
                self.subject(SubjectKind::Brand),
            ),
        };
        RelationEdge {
            src_id,
            kind,
            dst_id,
        }
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let purged = purge_tenant_fixture_sql(&self.tenant.to_string())
            .and_then(|sql| self.client.batch_execute(&sql).map_err(|e| e.to_string()));
        if let Err(e) = purged {
            eprintln!("relation_kernel cleanup ({}): {e}", self.tenant);
        }
    }
}

impl DbIntegrationFixture for Fx {
    type Handle = Fx;

    fn isolate() -> Result<Fx, DbFixtureSkipReason> {
        let dsn =
            std::env::var("HUMAUX_TEST_PG_DSN").map_err(|_| DbFixtureSkipReason::NoDatabaseUrl)?;
        // dep: PostgreSQL(owner) — test opens a direct PG connection for setup/verification
        let mut client = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        let ready: bool = client
            .query_one(
                "SELECT to_regclass('private.subject_relations') IS NOT NULL",
                &[],
            )
            .map(|r| r.get(0))
            .unwrap_or(false);
        if !ready {
            return Err(DbFixtureSkipReason::IsolationSetupFailed(
                "missing object: private.subject_relations (migration 0249_relation_kernel not applied)"
                    .to_string(),
            ));
        }
        let setup = |e: postgres::Error| DbFixtureSkipReason::IsolationSetupFailed(e.to_string());
        let tenant: Uuid = client
            .query_one(
                "INSERT INTO control.tenants (name) VALUES ('e2e-fixture m29-t05 relation kernel') \
                 RETURNING tenant_id",
                &[],
            )
            .map_err(setup)?
            .get(0);
        let row = client
            .query_one(
                "WITH w AS (INSERT INTO control.workspaces (tenant_id, name) VALUES ($1, 'w') \
                            RETURNING workspace_id), \
                      p AS (INSERT INTO private.continuity_projects (project_id, tenant_id, workspace_id, title) \
                            SELECT uuidv7(), $1, workspace_id, 'p' FROM w RETURNING project_id), \
                      t AS (INSERT INTO coord.tasks (tenant_id, title) VALUES ($1, 't') RETURNING task_id) \
                 SELECT p.project_id, t.task_id FROM p, t",
                &[&tenant],
            )
            .map_err(setup)?;
        let mut subjects = Vec::new();
        for kind in SubjectKind::ALL {
            let id: Uuid = client
                .query_one(
                    "INSERT INTO private.subjects (tenant_id, kind, display_name) VALUES ($1, $2, $2) \
                     RETURNING subject_id",
                    &[&tenant, &kind.as_str()],
                )
                .map_err(setup)?
                .get(0);
            subjects.push((kind, id));
        }
        Ok(Fx {
            client,
            dsn,
            tenant,
            project: row.get(0),
            task: row.get(1),
            subjects,
        })
    }
}

fn sqlstate(e: &postgres::Error) -> Option<&str> {
    e.code().map(SqlState::code)
}

fn constraint(e: &postgres::Error) -> Option<&str> {
    e.as_db_error().and_then(|d| d.constraint())
}

/// A transaction-local `role_gateway` session on `tenant`: the runtime role and RLS context the kernel runs under.
async fn gateway_txn(
    conn: &mut PgConnection,
    tenant: Uuid,
) -> sqlx::Transaction<'_, sqlx::Postgres> {
    // dep: PostgreSQL(any) — pool/txn query execution
    let mut txn = conn.begin().await.unwrap();
    // dep: PostgreSQL(role_gateway) — test switches PG role to exercise RLS
    sqlx::query("SET LOCAL ROLE role_gateway")
        .execute(&mut *txn)
        .await
        .unwrap();
    sqlx::query("SELECT set_config('humaux.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *txn)
        .await
        .unwrap();
    txn
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn principal() -> DecidedBy {
    DecidedBy::Principal(PrincipalId(Uuid::now_v7()))
}

fn window(start: i64, end: i64) -> Validity {
    Validity::new(&[(
        Included(Timestamp::Micros(start)),
        Excluded(Timestamp::Micros(end)),
    )])
    .unwrap()
}

/// G-M29-1 (§78.2): each table's `relation_kind` CHECK carries exactly the kinds `WHITELIST` gives its pair.
#[test]
fn g_m29_1_relation_kind_checks_match_domain() {
    run_db_fixture::<Fx, _>("g_m29_1_relation_kind_checks_match_domain", |mut fx| {
        for pair in RelationPair::ALL {
            let table = Fx::table(pair);
            let name = table.trim_start_matches("private.");
            let def: String = fx
                .client
                .query_one(
                    "SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c \
                     WHERE c.conrelid = to_regclass($1) AND c.contype = 'c' AND c.conname = $2",
                    &[&table, &format!("{name}_relation_kind_check")],
                )
                .unwrap_or_else(|e| panic!("{table}: no relation_kind CHECK: {e}"))
                .get(0);
            let db: BTreeSet<&str> = def.split('\'').skip(1).step_by(2).collect();
            let rust: BTreeSet<&str> = pair.relation_kinds().iter().map(|k| k.as_str()).collect();
            assert_eq!(
                db, rust,
                "{table} relation_kind CHECK != WHITELIST kinds: {def}"
            );
        }
    });
}

/// G-M29-1 (§78.2): `private.relation_triple_allowed` admits exactly the `WHITELIST` triples over every endpoint
/// kind × relation kind, with the provisional / foreign spellings in the domain so a DB-only triple naming them
/// is caught too.
#[test]
fn g_m29_1_whitelist_matches_db() {
    run_db_fixture::<Fx, _>("g_m29_1_whitelist_matches_db", |mut fx| {
        let mut endpoints: Vec<String> = EndpointKind::all()
            .into_iter()
            .map(|k| k.as_str().to_string())
            .collect();
        endpoints.extend(["CHANNEL_ACCOUNT", "PRODUCT_LINE", "REPOSITORY"].map(String::from));
        let mut kinds: Vec<String> = RelationKind::ALL
            .iter()
            .map(|k| k.as_str().to_string())
            .collect();
        kinds.extend(["DEPENDS_ON", "REORGANIZED_INTO", "ATTRIBUTED_TO"].map(String::from));
        let db: BTreeSet<(String, String, String)> = fx
            .client
            .query(
                "SELECT s, k, d FROM unnest($1::text[]) s, unnest($2::text[]) k, unnest($1::text[]) d \
                 WHERE private.relation_triple_allowed(s, k, d)",
                &[&endpoints, &kinds],
            )
            .unwrap()
            .iter()
            .map(|r| (r.get(0), r.get(1), r.get(2)))
            .collect();
        let rust: BTreeSet<(String, String, String)> = WHITELIST
            .iter()
            .map(|(s, k, d)| {
                (
                    s.as_str().to_string(),
                    k.as_str().to_string(),
                    d.as_str().to_string(),
                )
            })
            .collect();
        assert_eq!(
            db, rust,
            "DB whitelist != humaux_domain::relation::WHITELIST"
        );
    });
}

fn sql_ts(t: Timestamp) -> String {
    match t {
        Timestamp::NegInfinity => "'-infinity'::timestamptz".to_string(),
        Timestamp::Infinity => "'infinity'::timestamptz".to_string(),
        Timestamp::Micros(m) => {
            format!("(to_timestamp({m} / 1000000) + ({m} % 1000000) * interval '1 microsecond')")
        }
    }
}

/// The PostgreSQL value of one case, built from the same `Bound`s the Rust side validates.
fn sql_multirange(ranges: &[RawRange]) -> String {
    if ranges.is_empty() {
        return "'{}'::tstzmultirange".to_string();
    }
    let range = |(lo, hi): &RawRange| {
        let (l, lf) = match lo {
            Included(t) => (sql_ts(*t), '['),
            Excluded(t) => (sql_ts(*t), '('),
            Unbounded => ("NULL".to_string(), '('),
        };
        let (u, uf) = match hi {
            Included(t) => (sql_ts(*t), ']'),
            Excluded(t) => (sql_ts(*t), ')'),
            Unbounded => ("NULL".to_string(), ')'),
        };
        format!("tstzrange({l}, {u}, '{lf}{uf}')")
    };
    format!(
        "tstzmultirange({})",
        ranges.iter().map(range).collect::<Vec<_>>().join(", ")
    )
}

/// G-M29-2 (§6.1.4 ④): one case table, judged by the Rust `Validity`, by `private.relation_valid_shape`, and by
/// an INSERT into each of the three tables (the CHECK, `<table>_valid_shape`).
#[test]
#[allow(clippy::too_many_lines)] // one case table judged three ways
fn g_m29_2_valid_shape_rust_and_db_agree() {
    run_db_fixture::<Fx, _>("g_m29_2_valid_shape_rust_and_db_agree", |mut fx| {
        use Timestamp::{Infinity, Micros, NegInfinity};
        let (t1, t2, t3, t4) = (T0, T0 + DAY, T0 + 2 * DAY, T0 + 3 * DAY);
        let cases: Vec<(&str, Vec<RawRange>, bool)> = vec![
            ("retracted '{}'", vec![], true),
            (
                "[t1,t2)",
                vec![(Included(Micros(t1)), Excluded(Micros(t2)))],
                true,
            ),
            (
                "[t1,) upper omitted",
                vec![(Included(Micros(t1)), Unbounded)],
                true,
            ),
            (
                "[t1,t2) [t3,t4)",
                vec![
                    (Included(Micros(t1)), Excluded(Micros(t2))),
                    (Included(Micros(t3)), Excluded(Micros(t4))),
                ],
                true,
            ),
            (
                "[t1,t2] upper inclusive",
                vec![(Included(Micros(t1)), Included(Micros(t2)))],
                false,
            ),
            (
                "(t1,t2) lower exclusive",
                vec![(Excluded(Micros(t1)), Excluded(Micros(t2)))],
                false,
            ),
            (
                "(,t2) unbounded lower",
                vec![(Unbounded, Excluded(Micros(t2)))],
                false,
            ),
            (
                "[-infinity,t2)",
                vec![(Included(NegInfinity), Excluded(Micros(t2)))],
                false,
            ),
            (
                "[t1,infinity)",
                vec![(Included(Micros(t1)), Excluded(Infinity))],
                false,
            ),
            (
                "[t1,t2) [t3,t4] one bad segment",
                vec![
                    (Included(Micros(t1)), Excluded(Micros(t2))),
                    (Included(Micros(t3)), Included(Micros(t4))),
                ],
                false,
            ),
        ];
        let edges: Vec<(RelationPair, RelationEdge)> = RelationPair::ALL
            .into_iter()
            .map(|p| (p, fx.edge(p)))
            .collect();
        let tenant = fx.tenant;
        let mut txn = fx.client.transaction().unwrap();
        for (name, ranges, admitted) in &cases {
            let rust = Validity::new(ranges).is_ok();
            assert_eq!(rust, *admitted, "Rust Validity on {name}");
            let value = sql_multirange(ranges);
            let db: bool = txn
                .query_one(
                    &format!("SELECT private.relation_valid_shape({value})"),
                    &[],
                )
                .unwrap()
                .get(0);
            assert_eq!(db, *admitted, "relation_valid_shape on {name}");
            for (pair, edge) in &edges {
                let table = Fx::table(*pair);
                let mut sp = txn.transaction().unwrap();
                let result = sp.execute(
                    &format!(
                        "INSERT INTO {table} (tenant_id, relation_id, revision, src_id, dst_id, relation_kind, \
                         valid, decided_by, factual_evidence_ids, authorization_evidence_id) \
                         VALUES ($1, uuidv7(), 1, $2, $3, $4, {value}, 'rule:g_m29_2@1', '{{}}', gen_random_uuid())"
                    ),
                    &[&tenant, &edge.src_id, &edge.dst_id, &edge.kind.as_str()],
                );
                match (result, admitted) {
                    (Ok(_), true) => {}
                    (Err(e), false) => {
                        assert_eq!(sqlstate(&e), Some("23514"), "{table} on {name}: {e}");
                        let expected =
                            format!("{}_valid_shape", table.trim_start_matches("private."));
                        assert_eq!(
                            constraint(&e),
                            Some(expected.as_str()),
                            "{table} on {name}: {e}"
                        );
                    }
                    (result, _) => {
                        panic!("{table} on {name}: expected admitted={admitted}, got {result:?}")
                    }
                }
                sp.rollback().unwrap();
            }
        }
        txn.rollback().unwrap();
    });
}

/// G-M29-3 (§6.1.4 ③): two connections append with the same `expected_revision`; exactly one wins and the other
/// gets `CONFLICT`. The first writer holds its uncommitted revision until the second is observed blocked on it
/// (`pg_blocking_pids`), so the race is real, not sequential.
#[test]
#[allow(clippy::too_many_lines)] // one ordered two-connection race
fn g_m29_3_concurrent_cas_exactly_one_wins() {
    run_db_fixture::<Fx, _>("g_m29_3_concurrent_cas_exactly_one_wins", |fx| {
        let rt = runtime();
        let (dsn, tenant, edge) = (
            fx.dsn.clone(),
            fx.tenant,
            fx.edge(RelationPair::ProjectTask),
        );
        let relation = RelationId::new();
        let auth = Uuid::now_v7();
        rt.block_on(async move {
            // dep: PostgreSQL(any) — open a role-scoped PG connection/pool for this test
            let mut admin = PgConnection::connect(&dsn).await.unwrap();
            let mut first = PgConnection::connect(&dsn).await.unwrap();
            let mut seed = gateway_txn(&mut first, tenant).await;
            let v = window(T0, T0 + DAY);
            let created =
                append_revision(&mut seed, &edge, relation, 0, &v, &principal(), None, &[], auth).await;
            assert_eq!(created, Ok(1));
            seed.commit().await.unwrap();

            let mut a = gateway_txn(&mut first, tenant).await;
            let won_a = append_revision(
                &mut a,
                &edge,
                relation,
                1,
                &Validity::retracted(),
                &principal(),
                None,
                &[],
                auth,
            )
            .await;
            assert_eq!(won_a, Ok(2), "first writer");

            // dep: PostgreSQL(any) — open a role-scoped PG connection/pool for this test
            let mut conn = PgConnection::connect(&dsn).await.unwrap();
            let pid_b: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut conn)
                .await
                .unwrap();
            let second = tokio::spawn(async move {
                let mut b = gateway_txn(&mut conn, tenant).await;
                let result = append_revision(
                    &mut b,
                    &edge,
                    relation,
                    1,
                    &window(T0, T0 + 2 * DAY),
                    &principal(),
                    None,
                    &[],
                    auth,
                )
                .await;
                if result.is_ok() {
                    b.commit().await.unwrap();
                } else {
                    b.rollback().await.unwrap();
                }
                result
            });
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut blocked = false;
            while !second.is_finished() && Instant::now() < deadline {
                blocked = sqlx::query_scalar("SELECT cardinality(pg_blocking_pids($1)) > 0")
                    .bind(pid_b)
                    .fetch_one(&mut admin)
                    .await
                    .unwrap();
                if blocked {
                    break;
                }
                tokio::task::yield_now().await;
            }
            a.commit().await.unwrap();
            let result_b = second.await.unwrap();
            let rows: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM private.project_task_relations WHERE relation_id = $1 AND revision = 2",
            )
            .bind(relation.0)
            .fetch_one(&mut admin)
            .await
            .unwrap();
            assert_eq!(
                (result_b, rows),
                (Err(ErrorCode::Conflict), 1),
                "exactly one writer of expected_revision 1 may win (second writer blocked on the first: {blocked})"
            );
            assert!(blocked, "the second writer never waited on the first");
        });
    });
}

/// G-M29-4 (§6.1.4 ①): UPDATE and DELETE fail for every non-owner role on the privilege check (42501), and the
/// owner's own UPDATE / DELETE hit the append-only trigger (23514), on all three tables.
#[test]
fn g_m29_4_no_role_updates_or_deletes_revisions() {
    run_db_fixture::<Fx, _>("g_m29_4_no_role_updates_or_deletes_revisions", |mut fx| {
        let tenant = fx.tenant;
        let edges: Vec<(RelationPair, RelationEdge)> = RelationPair::ALL
            .into_iter()
            .map(|p| (p, fx.edge(p)))
            .collect();
        let mut txn = fx.client.transaction().unwrap();
        for (pair, edge) in &edges {
            let table = Fx::table(*pair);
            txn.execute(
                &format!(
                    "INSERT INTO {table} (tenant_id, relation_id, revision, src_id, dst_id, relation_kind, valid, \
                     decided_by, factual_evidence_ids, authorization_evidence_id) \
                     VALUES ($1, uuidv7(), 1, $2, $3, $4, '{{}}', 'rule:g_m29_4@1', '{{}}', gen_random_uuid())"
                ),
                &[&tenant, &edge.src_id, &edge.dst_id, &edge.kind.as_str()],
            )
            .unwrap();
            let statements = [
                format!("UPDATE {table} SET decided_by = decided_by WHERE tenant_id = '{tenant}'"),
                format!("DELETE FROM {table} WHERE tenant_id = '{tenant}'"),
            ];
            for statement in &statements {
                for (role, expected) in NON_OWNER_ROLES
                    .iter()
                    .map(|r| (*r, "42501"))
                    .chain([("role_migration_owner", "23514")])
                {
                    let mut sp = txn.transaction().unwrap();
                    // dep: PostgreSQL(any) — test switches PG role to exercise RLS
                    sp.batch_execute(&format!(
                        "SET LOCAL ROLE {role}; SELECT set_config('humaux.tenant_id', '{tenant}', true)"
                    ))
                    .unwrap();
                    match sp.execute(statement.as_str(), &[]) {
                        Err(e) => {
                            assert_eq!(sqlstate(&e), Some(expected), "{role}: {statement}: {e}")
                        }
                        Ok(n) => panic!("{role}: {statement} succeeded on {n} row(s)"),
                    }
                    sp.rollback().unwrap();
                }
            }
        }
        txn.rollback().unwrap();
    });
}

/// The adapter end to end under `role_gateway` + RLS: create, read back, retract, the two CAS refusals, an edge
/// change, non-whitelisted triples and an unknown endpoint, each mapped to its §52 code.
#[test]
#[allow(clippy::too_many_lines)] // one transaction, every adapter outcome
fn relation_kernel_round_trip_through_the_adapter() {
    run_db_fixture::<Fx, _>("relation_kernel_round_trip_through_the_adapter", |fx| {
        let rt = runtime();
        let edge = fx.edge(RelationPair::ProjectTask);
        let person = fx.subject(SubjectKind::Person);
        let (website, brand) = (
            fx.subject(SubjectKind::Website),
            fx.subject(SubjectKind::Brand),
        );
        let (dsn, tenant, project) = (fx.dsn.clone(), fx.tenant, fx.project);
        rt.block_on(async move {
            // dep: PostgreSQL(any) — open a role-scoped PG connection/pool for this test
            let mut conn = PgConnection::connect(&dsn).await.unwrap();
            let mut txn = gateway_txn(&mut conn, tenant).await;
            let relation = RelationId::new();
            let decided = principal();
            let model = ModelRef::new("vendor/model", "2026-10").unwrap();
            let evidence = vec![Uuid::now_v7(), Uuid::now_v7()];
            let auth = Uuid::now_v7();
            let valid = Validity::new(&[
                (Included(Timestamp::Micros(T0 + 2 * DAY)), Unbounded),
                (
                    Included(Timestamp::Micros(T0)),
                    Excluded(Timestamp::Micros(T0 + DAY + 1)),
                ),
            ])
            .unwrap();
            let written = append_revision(
                &mut txn,
                &edge,
                relation,
                0,
                &valid,
                &decided,
                Some(&model),
                &evidence,
                auth,
            )
            .await;
            assert_eq!(written, Ok(1));
            let read = current_revision(&mut txn, RelationPair::ProjectTask, relation).await;
            assert_eq!(
                read,
                Ok(Some(RelationRevision {
                    relation_id: relation,
                    revision: 1,
                    edge,
                    valid,
                    decided_by: decided,
                    proposed_by: Some(model),
                    factual_evidence_ids: evidence,
                    authorization_evidence_id: auth,
                }))
            );

            let rule = DecidedBy::Rule(RuleRef::new("correction", 1).unwrap());
            let retracted = Validity::retracted();
            assert_eq!(
                append_revision(
                    &mut txn,
                    &edge,
                    relation,
                    1,
                    &retracted,
                    &rule,
                    None,
                    &[],
                    auth
                )
                .await,
                Ok(2)
            );
            let current = current_revision(&mut txn, RelationPair::ProjectTask, relation)
                .await
                .unwrap()
                .unwrap();
            assert_eq!((current.revision, current.valid.is_retracted()), (2, true));

            let other_project_kind = RelationEdge {
                kind: RelationKind::References,
                ..edge
            };
            let refused: [(&str, RelationEdge, RelationId, i64, ErrorCode); 7] = [
                (
                    "stale expected_revision",
                    edge,
                    relation,
                    0,
                    ErrorCode::Conflict,
                ),
                (
                    "expected_revision ahead",
                    edge,
                    relation,
                    5,
                    ErrorCode::Conflict,
                ),
                (
                    "edge change",
                    other_project_kind,
                    relation,
                    2,
                    ErrorCode::InvalidInput,
                ),
                (
                    "PROJECT TARGETS PERSON",
                    RelationEdge {
                        src_id: project,
                        kind: RelationKind::Targets,
                        dst_id: person,
                    },
                    RelationId::new(),
                    0,
                    ErrorCode::InvalidInput,
                ),
                (
                    "BRAND OWNED_BY WEBSITE",
                    RelationEdge {
                        src_id: brand,
                        kind: RelationKind::OwnedBy,
                        dst_id: website,
                    },
                    RelationId::new(),
                    0,
                    ErrorCode::InvalidInput,
                ),
                (
                    "unknown subject",
                    RelationEdge {
                        src_id: website,
                        kind: RelationKind::OwnedBy,
                        dst_id: Uuid::now_v7(),
                    },
                    RelationId::new(),
                    0,
                    ErrorCode::InvalidInput,
                ),
                (
                    "unknown task",
                    RelationEdge {
                        dst_id: Uuid::now_v7(),
                        ..edge
                    },
                    RelationId::new(),
                    0,
                    ErrorCode::InvalidInput,
                ),
            ];
            for (name, edge, relation, expected, code) in refused {
                // dep: PostgreSQL(any) — pool/txn query execution
                let mut sp = txn.begin().await.unwrap();
                let result = append_revision(
                    &mut sp,
                    &edge,
                    relation,
                    expected,
                    &retracted,
                    &rule,
                    None,
                    &[],
                    auth,
                )
                .await;
                assert_eq!(result, Err(code), "{name}");
                sp.rollback().await.unwrap();
            }
            let allowed = RelationEdge {
                src_id: website,
                kind: RelationKind::OwnedBy,
                dst_id: brand,
            };
            assert_eq!(
                append_revision(
                    &mut txn,
                    &allowed,
                    RelationId::new(),
                    0,
                    &retracted,
                    &rule,
                    None,
                    &[],
                    auth
                )
                .await,
                Ok(1),
                "WEBSITE OWNED_BY BRAND"
            );
            txn.rollback().await.unwrap();
        });
    });
}

/// #92 item 4 (0252): without a tenant context the guard refuses an append FORBIDDEN (42501) before its predecessor
/// lookup, which would otherwise find nothing and answer CONFLICT.
#[test]
fn null_tenant_append_is_forbidden() {
    run_db_fixture::<Fx, _>("null_tenant_append_is_forbidden", |fx| {
        let rt = runtime();
        let (dsn, edge) = (fx.dsn.clone(), fx.edge(RelationPair::ProjectTask));
        rt.block_on(async move {
            // dep: PostgreSQL(any) — open a role-scoped PG connection/pool for this test
            let mut conn = PgConnection::connect(&dsn).await.unwrap();
            // dep: PostgreSQL(any) — pool/txn query execution
            let mut txn = conn.begin().await.unwrap();
            // dep: PostgreSQL(role_gateway) — test switches PG role to exercise RLS
            sqlx::query("SET LOCAL ROLE role_gateway")
                .execute(&mut *txn)
                .await
                .unwrap();
            let appended = append_revision(
                &mut txn,
                &edge,
                RelationId::new(),
                1,
                &window(T0, T0 + DAY),
                &principal(),
                None,
                &[],
                Uuid::now_v7(),
            )
            .await;
            assert_eq!(appended, Err(ErrorCode::Forbidden));
        });
    });
}

/// #92 item 5 (0252): one (src, dst, kind) edge has one relation; a second `relation_id` for it is CONFLICT at its
/// first revision.
#[test]
fn a_second_relation_id_for_one_edge_conflicts() {
    run_db_fixture::<Fx, _>("a_second_relation_id_for_one_edge_conflicts", |fx| {
        let rt = runtime();
        let (dsn, tenant, edge) = (
            fx.dsn.clone(),
            fx.tenant,
            fx.edge(RelationPair::ProjectTask),
        );
        rt.block_on(async move {
            // dep: PostgreSQL(any) — open a role-scoped PG connection/pool for this test
            let mut conn = PgConnection::connect(&dsn).await.unwrap();
            let mut txn = gateway_txn(&mut conn, tenant).await;
            let v = window(T0, T0 + DAY);
            let auth = Uuid::now_v7();
            let first = append_revision(
                &mut txn,
                &edge,
                RelationId::new(),
                0,
                &v,
                &principal(),
                None,
                &[],
                auth,
            )
            .await;
            assert_eq!(first, Ok(1));
            let second = append_revision(
                &mut txn,
                &edge,
                RelationId::new(),
                0,
                &v,
                &principal(),
                None,
                &[],
                auth,
            )
            .await;
            assert_eq!(second, Err(ErrorCode::Conflict));
        });
    });
}

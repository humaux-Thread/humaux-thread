//! `adapters::tests::relation_kernel` — M29 T05 gates G-M29-1 (whitelist part), G-M29-2, G-M29-3, G-M29-4 for the
//!   §6.1.4 relation kernel (migration 0249, ADR-0078 D-C), plus the adapter round trip, the 0252 guard / edge
//!   index (issue #92 items 4 and 5, M29 T06a) and the 0253 provenance gates G-T06d-1..4 (issue #92 items 1-3,
//!   M29 T06d).
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, postgres, sqlx, tokio, uuid];
//!   services=[PostgreSQL(owner) r=[private.project_subject_relations, private.project_task_relations,
//!   private.subject_relations] w=[control.api_keys, control.memberships, control.private_reasoning_domains,
//!   control.tenants, control.users, control.workspaces, coord.tasks, private.continuity_projects, private.events,
//!   private.evidence_objects, private.subjects] x=[private.relation_principal_is_member,
//!   private.relation_triple_allowed, private.relation_valid_shape], PostgreSQL(role_gateway),
//!   PostgreSQL(role_migration_owner)];
//!   env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::relation_repo, domain::error, domain::identity, domain::relation,
//!   domain::subject, humaux-testkit, testkit::fixture_purge]
//! Called-by: [cargo-test]
//! Invariants: [every gate compares the Rust closed set / rule with the live migration objects, never a copy; each
//!   gate has one injected fault that turns it red (ADR-0078 gate table, §80.1)]
//! Spec: Baseline §6.1.4; §78.2; §79.2; §80.1; ADR-0078 D-C
//!
//! Runs against the real `private` objects of migration 0249 (the gates are about those objects, not a scratch
//! copy). Each test seeds its own fixture tenant (`e2e-fixture …`: one workspace, two projects, two tasks, one
//! subject per `SubjectKind`, three TENANT_SHARED Evidence and one ACTIVE member user) plus a decoy tenant with one
//! Evidence, and purges both through `humaux_testkit::fixture_purge` on drop. Only G-M29-3 commits relation rows;
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
//! | `a_second_relation_id_for_one_edge_conflicts` | #92 item 5 (M29 T06a) | a predicate no revision matches on one table's edge index |
//! | `g_t06d_1_authorization_evidence_is_tenant_evidence` | G-T06d-1 | drop 0253's FK line |
//! | `g_t06d_2_factual_evidence_is_distinct_visible_evidence` | G-T06d-2 | drop the guard's factual check |
//! | `g_t06d_3_principal_decider_is_a_live_member` | G-T06d-3 | drop the guard's membership check, one predicate leg, or the cast guard |
//! | `g_t06d_4_authorization_evidence_is_not_factual` | G-T06d-4 | drop 0253's CHECK line |
//! | `out_of_range_timestamp_is_invalid_input` | #92 item 2 (M29 T06d) | drop `Validity::new`'s lower bound |
//! | `relation_kernel_round_trip_through_the_adapter` | #92 item 3 (M29 T06d) | the guard compares `relation_kind` only |
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
    DecidedBy, EndpointKind, ModelRef, PG_TIMESTAMPTZ_MIN_MICROS, RawRange, RelationEdge,
    RelationId, RelationKind, RelationPair, RuleRef, Timestamp, Validity, WHITELIST,
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
    /// A second project and task: valid endpoints for the src / dst edge-change cases (#92 item 3).
    project2: Uuid,
    task2: Uuid,
    subjects: Vec<(SubjectKind, Uuid)>,
    /// Three TENANT_SHARED Evidence of `tenant`, visible to `role_gateway` under the tenant GUC alone.
    evidence: Vec<Uuid>,
    /// A user with an ACTIVE membership in `tenant`: the `principal:` decider of every valid write.
    member: Uuid,
    /// The decoy tenant and its one Evidence.
    other: Uuid,
    other_evidence: Uuid,
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

    /// One whitelisted edge per pair. The Project-Task edge is `REFERENCES`: ADR-0102 D-C reserves `CONTAINS` to
    /// `coord_task_repo::set_task_project_in_txn`, so the adapter refuses it for any other caller.
    fn edge(&self, pair: RelationPair) -> RelationEdge {
        let (src_id, kind, dst_id) = match pair {
            RelationPair::ProjectTask => (self.project, RelationKind::References, self.task),
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
        for tenant in [self.tenant, self.other] {
            let purged = purge_tenant_fixture_sql(&tenant.to_string())
                .and_then(|sql| self.client.batch_execute(&sql).map_err(|e| e.to_string()));
            if let Err(e) = purged {
                eprintln!("relation_kernel cleanup ({tenant}): {e}");
            }
        }
    }
}

/// `n` TENANT_SHARED EVENT Evidence of `tenant` (with their `private.events` rows), sorted.
fn seed_evidence(client: &mut Client, tenant: Uuid, n: i32) -> Result<Vec<Uuid>, postgres::Error> {
    Ok(client
        .query(
            "WITH d AS (INSERT INTO control.private_reasoning_domains (tenant_id, name) \
                        VALUES ($1, 'relation_kernel') RETURNING reasoning_domain_id), \
                  e AS (INSERT INTO private.evidence_objects (tenant_id, evidence_kind, payload_sha256, data_class, \
                          origin_class, visibility_class, reasoning_domain_id) \
                        SELECT $1, 'EVENT', sha256(convert_to($1::text || g, 'UTF8')), 'INTERNAL', \
                          'DirectUserInput', 'TENANT_SHARED', d.reasoning_domain_id \
                          FROM d, generate_series(1, $2) g RETURNING evidence_id), \
                  v AS (INSERT INTO private.events (event_id, event_kind, payload) \
                        SELECT evidence_id, 'USER_MESSAGE', '{}'::jsonb FROM e) \
             SELECT evidence_id FROM e ORDER BY evidence_id",
            &[&tenant, &n],
        )?
        .iter()
        .map(|r| r.get(0))
        .collect())
}

/// A new `user_state` user with a `state` membership in `tenant`.
fn seed_member(
    client: &mut Client,
    tenant: Uuid,
    user_state: &str,
    state: &str,
) -> Result<Uuid, postgres::Error> {
    Ok(client
        .query_one(
            "WITH u AS (INSERT INTO control.users (state) VALUES ($3) RETURNING user_id), \
                  m AS (INSERT INTO control.memberships (tenant_id, user_id, role, state) \
                        SELECT $1, user_id, 'MEMBER', $2 FROM u) \
             SELECT user_id FROM u",
            &[&tenant, &state, &user_state],
        )?
        .get(0))
}

/// A v1 key of `tenant`: a PAT bound to `user` (the gateway `PrincipalId` is its `api_key_id`), or a machine key
/// when `user` is `None` (0111: no user, no user epoch); `revoked` sets `revoked_at` and nothing else.
fn seed_key(client: &mut Client, tenant: Uuid, user: Option<Uuid>, revoked: bool) -> Uuid {
    client
        .query_one(
            "INSERT INTO control.api_keys (tenant_id, prefix, key_hash, status, authorization_version, user_id, \
               tenant_security_epoch, user_security_epoch, revoked_at) \
             VALUES ($1, md5(gen_random_uuid()::text), sha256('relation_kernel'::bytea), 'ACTIVE', 1, $2::uuid, 0, \
               CASE WHEN $2::uuid IS NOT NULL THEN 0 END, CASE WHEN $3 THEN now() END) \
             RETURNING api_key_id",
            &[&tenant, &user, &revoked],
        )
        .unwrap()
        .get(0)
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
                "INSERT INTO control.tenants (name, state) VALUES ('e2e-fixture m29-t05 relation kernel', 'ACTIVE') \
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
                      t AS (INSERT INTO coord.tasks (tenant_id, title, project_id) \
                            SELECT $1, 't', project_id FROM p RETURNING task_id) \
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
        let (project, task): (Uuid, Uuid) = (row.get(0), row.get(1));
        let second = client
            .query_one(
                "WITH p AS (INSERT INTO private.continuity_projects (project_id, tenant_id, workspace_id, title) \
                            SELECT uuidv7(), tenant_id, workspace_id, 'p2' FROM private.continuity_projects \
                             WHERE project_id = $1 RETURNING project_id), \
                      t AS (INSERT INTO coord.tasks (tenant_id, title, project_id) \
                            SELECT $2, 't2', project_id FROM p RETURNING task_id) \
                 SELECT p.project_id, t.task_id FROM p, t",
                &[&project, &tenant],
            )
            .map_err(setup)?;
        let evidence = seed_evidence(&mut client, tenant, 3).map_err(setup)?;
        let member = seed_member(&mut client, tenant, "ACTIVE", "ACTIVE").map_err(setup)?;
        let other: Uuid = client
            .query_one(
                "INSERT INTO control.tenants (name, state) VALUES ('e2e-fixture m29-t06d decoy tenant', 'ACTIVE') \
                 RETURNING tenant_id",
                &[],
            )
            .map_err(setup)?
            .get(0);
        let other_evidence = seed_evidence(&mut client, other, 1).map_err(setup)?[0];
        Ok(Fx {
            client,
            dsn,
            tenant,
            project,
            task,
            project2: second.get(0),
            task2: second.get(1),
            subjects,
            evidence,
            member,
            other,
            other_evidence,
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

/// `principal:<user>`; valid only for a user with an ACTIVE membership in the row's tenant (0253).
fn principal(user: Uuid) -> DecidedBy {
    DecidedBy::Principal(PrincipalId(user))
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
        let (tenant, auth) = (fx.tenant, fx.evidence[0]);
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
                         VALUES ($1, uuidv7(), 1, $2, $3, $4, {value}, 'rule:g_m29_2@1', '{{}}', $5)"
                    ),
                    &[&tenant, &edge.src_id, &edge.dst_id, &edge.kind.as_str(), &auth],
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
        let (auth, member) = (fx.evidence[0], fx.member);
        rt.block_on(async move {
            // dep: PostgreSQL(any) — open a role-scoped PG connection/pool for this test
            let mut admin = PgConnection::connect(&dsn).await.unwrap();
            let mut first = PgConnection::connect(&dsn).await.unwrap();
            let mut seed = gateway_txn(&mut first, tenant).await;
            let v = window(T0, T0 + DAY);
            let created =
                append_revision(&mut seed, &edge, relation, 0, &v, &principal(member), None, &[], auth)
                    .await;
            assert_eq!(created, Ok(1));
            seed.commit().await.unwrap();

            let mut a = gateway_txn(&mut first, tenant).await;
            let won_a = append_revision(
                &mut a,
                &edge,
                relation,
                1,
                &Validity::retracted(),
                &principal(member),
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
                    &principal(member),
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

/// G-M29-4 (§6.1.4 ①): no non-owner role holds UPDATE (on any column) or DELETE on any of the three tables, asked
/// the way the 0249 / 0252 postchecks ask (issue #92 item 1: a role without USAGE on `private` fails an UPDATE with
/// the schema's 42501, which would hide a table grant), and the owner's own UPDATE / DELETE hit the append-only
/// trigger (23514).
#[test]
fn g_m29_4_no_role_updates_or_deletes_revisions() {
    run_db_fixture::<Fx, _>("g_m29_4_no_role_updates_or_deletes_revisions", |mut fx| {
        let (tenant, auth) = (fx.tenant, fx.evidence[0]);
        let edges: Vec<(RelationPair, RelationEdge)> = RelationPair::ALL
            .into_iter()
            .map(|p| (p, fx.edge(p)))
            .collect();
        let mut txn = fx.client.transaction().unwrap();
        for (pair, edge) in &edges {
            let table = Fx::table(*pair);
            for role in NON_OWNER_ROLES {
                let row = txn
                    .query_one(
                        "SELECT has_any_column_privilege($1::text, $2::text, 'UPDATE'), \
                                has_table_privilege($1::text, $2::text, 'DELETE')",
                        &[&role, &table],
                    )
                    .unwrap();
                let held: (bool, bool) = (row.get(0), row.get(1));
                assert_eq!(
                    held,
                    (false, false),
                    "{role} on {table}: (UPDATE, DELETE) held"
                );
            }
            txn.execute(
                &format!(
                    "INSERT INTO {table} (tenant_id, relation_id, revision, src_id, dst_id, relation_kind, valid, \
                     decided_by, factual_evidence_ids, authorization_evidence_id) \
                     VALUES ($1, uuidv7(), 1, $2, $3, $4, '{{}}', 'rule:g_m29_4@1', '{{}}', $5)"
                ),
                &[&tenant, &edge.src_id, &edge.dst_id, &edge.kind.as_str(), &auth],
            )
            .unwrap();
            for statement in [
                format!("UPDATE {table} SET decided_by = decided_by WHERE tenant_id = '{tenant}'"),
                format!("DELETE FROM {table} WHERE tenant_id = '{tenant}'"),
            ] {
                let mut sp = txn.transaction().unwrap();
                // dep: PostgreSQL(role_migration_owner) — the owner's UPDATE / DELETE must reach the trigger
                sp.batch_execute(&format!(
                    "SET LOCAL ROLE role_migration_owner; SELECT set_config('humaux.tenant_id', '{tenant}', true)"
                ))
                .unwrap();
                match sp.execute(statement.as_str(), &[]) {
                    Err(e) => assert_eq!(sqlstate(&e), Some("23514"), "owner: {statement}: {e}"),
                    Ok(n) => panic!("owner: {statement} succeeded on {n} row(s)"),
                }
                sp.rollback().unwrap();
            }
        }
        txn.rollback().unwrap();
    });
}

/// The adapter end to end under `role_gateway` + RLS: create, read back, retract, the two CAS refusals, an edge
/// change (kind, src or dst: issue #92 item 3, each to a valid endpoint so only edge immutability refuses it),
/// non-whitelisted triples and an unknown endpoint, each mapped to its §52 code.
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
        let (project2, task2, member) = (fx.project2, fx.task2, fx.member);
        let (auth, evidence) = (fx.evidence[0], vec![fx.evidence[1], fx.evidence[2]]);
        rt.block_on(async move {
            // dep: PostgreSQL(any) — open a role-scoped PG connection/pool for this test
            let mut conn = PgConnection::connect(&dsn).await.unwrap();
            let mut txn = gateway_txn(&mut conn, tenant).await;
            let relation = RelationId::new();
            let decided = principal(member);
            let model = ModelRef::new("vendor/model", "2026-10").unwrap();
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

            // ADR-0102 D-C: the repository refuses CONTAINS before any SQL, so the Project-Task pair no longer offers two
            // kinds for one (src, dst) and the guard's kind leg is exercised on a pair that does: PROJECT TARGETS BRAND,
            // then the same pair as SERVES.
            let targets = RelationEdge {
                src_id: project,
                kind: RelationKind::Targets,
                dst_id: brand,
            };
            let kind_relation = RelationId::new();
            let open = Validity::new(&[(Included(Timestamp::Micros(T0)), Unbounded)]).unwrap();
            assert_eq!(
                append_revision(
                    &mut txn,
                    &targets,
                    kind_relation,
                    0,
                    &open,
                    &rule,
                    None,
                    &[],
                    auth
                )
                .await,
                Ok(1)
            );
            let refused: [(&str, RelationEdge, RelationId, i64, ErrorCode); 9] = [
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
                    "kind change",
                    RelationEdge {
                        kind: RelationKind::Serves,
                        ..targets
                    },
                    kind_relation,
                    1,
                    ErrorCode::InvalidInput,
                ),
                (
                    "src change",
                    RelationEdge {
                        src_id: project2,
                        ..edge
                    },
                    relation,
                    2,
                    ErrorCode::InvalidInput,
                ),
                (
                    "dst change",
                    RelationEdge {
                        dst_id: task2,
                        ..edge
                    },
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
        let (auth, member) = (fx.evidence[0], fx.member);
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
                &principal(member),
                None,
                &[],
                auth,
            )
            .await;
            assert_eq!(appended, Err(ErrorCode::Forbidden));
        });
    });
}

/// #92 item 5 (0252): on each of the three tables, one (src, dst, kind) edge has one relation; a second `relation_id`
/// for it is CONFLICT at its first revision.
#[test]
fn a_second_relation_id_for_one_edge_conflicts() {
    run_db_fixture::<Fx, _>("a_second_relation_id_for_one_edge_conflicts", |fx| {
        let rt = runtime();
        let (dsn, tenant) = (fx.dsn.clone(), fx.tenant);
        let edges = RelationPair::ALL.map(|pair| (pair, fx.edge(pair)));
        let (auth, member) = (fx.evidence[0], fx.member);
        rt.block_on(async move {
            // dep: PostgreSQL(any) — open a role-scoped PG connection/pool for this test
            let mut conn = PgConnection::connect(&dsn).await.unwrap();
            let v = window(T0, T0 + DAY);
            for (pair, edge) in edges {
                let mut txn = gateway_txn(&mut conn, tenant).await;
                for expected in [Ok(1), Err(ErrorCode::Conflict)] {
                    let appended = append_revision(
                        &mut txn,
                        &edge,
                        RelationId::new(),
                        0,
                        &v,
                        &principal(member),
                        None,
                        &[],
                        auth,
                    )
                    .await;
                    assert_eq!(appended, expected, "{pair:?}");
                }
            }
        });
    });
}

/// One append creating a fresh relation for `edge`, in a savepoint of `txn` that is rolled back: the adapter's result
/// and, after a successful append, how many rows of that relation the writer saw before the rollback. A failed
/// append is not counted (the aborted savepoint cannot be queried); its 0 restates PostgreSQL's statement atomicity
/// and is not an observation.
async fn try_create(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    edge: &RelationEdge,
    decided: &DecidedBy,
    factual: &[Uuid],
    auth: Uuid,
) -> (Result<i64, ErrorCode>, i64) {
    let relation = RelationId::new();
    // dep: PostgreSQL(any) — pool/txn query execution
    let mut sp = txn.begin().await.unwrap();
    let valid = window(T0, T0 + DAY);
    let result = append_revision(
        &mut sp, edge, relation, 0, &valid, decided, None, factual, auth,
    )
    .await;
    let seen: i64 = if result.is_ok() {
        sqlx::query_scalar(&format!(
            "SELECT count(*) FROM {} WHERE relation_id = $1",
            Fx::table(edge.kind.pair())
        ))
        .bind(relation.0)
        .fetch_one(&mut *sp)
        .await
        .unwrap()
    } else {
        0
    };
    sp.rollback().await.unwrap();
    (result, seen)
}

/// G-T06d-1 (0253 ①): on each table, an `authorization_evidence_id` that is no Evidence, or another tenant's
/// Evidence, is INVALID_INPUT; this tenant's Evidence is accepted.
#[test]
fn g_t06d_1_authorization_evidence_is_tenant_evidence() {
    run_db_fixture::<Fx, _>("g_t06d_1_authorization_evidence_is_tenant_evidence", |fx| {
        let rt = runtime();
        let (dsn, tenant, member) = (fx.dsn.clone(), fx.tenant, fx.member);
        let edges = RelationPair::ALL.map(|pair| (pair, fx.edge(pair)));
        let (own, foreign) = (fx.evidence[0], fx.other_evidence);
        rt.block_on(async move {
            // dep: PostgreSQL(any) — open a role-scoped PG connection/pool for this test
            let mut conn = PgConnection::connect(&dsn).await.unwrap();
            for (pair, edge) in edges {
                let mut txn = gateway_txn(&mut conn, tenant).await;
                for (name, auth, expected) in [
                    (
                        "no Evidence",
                        Uuid::now_v7(),
                        (Err(ErrorCode::InvalidInput), 0),
                    ),
                    (
                        "other tenant's Evidence",
                        foreign,
                        (Err(ErrorCode::InvalidInput), 0),
                    ),
                    ("this tenant's Evidence", own, (Ok(1), 1)),
                ] {
                    let got = try_create(&mut txn, &edge, &principal(member), &[], auth).await;
                    assert_eq!(got, expected, "{pair:?}: {name}");
                }
                txn.rollback().await.unwrap();
            }
        });
    });
}

/// G-T06d-2 (0253 ②): on each table, a factual id that is no Evidence, another tenant's Evidence, this tenant's
/// Evidence the writer cannot see (USER_PRIVATE, and the session carries no user) or a repeated id is INVALID_INPUT;
/// distinct Evidence of this tenant is accepted.
#[test]
fn g_t06d_2_factual_evidence_is_distinct_visible_evidence() {
    run_db_fixture::<Fx, _>(
        "g_t06d_2_factual_evidence_is_distinct_visible_evidence",
        |mut fx| {
            let hidden: Uuid = fx
                .client
                .query_one(
                    "WITH e AS (INSERT INTO private.evidence_objects (tenant_id, evidence_kind, payload_sha256, \
                                  data_class, origin_class, visibility_class, visibility_user_id, reasoning_domain_id) \
                                SELECT tenant_id, 'EVENT', sha256('relation_kernel hidden'::bytea), 'INTERNAL', \
                                  'DirectUserInput', 'USER_PRIVATE', $2, reasoning_domain_id \
                                  FROM private.evidence_objects WHERE evidence_id = $1 RETURNING evidence_id), \
                          v AS (INSERT INTO private.events (event_id, event_kind, payload) \
                                SELECT evidence_id, 'USER_MESSAGE', '{}'::jsonb FROM e) \
                     SELECT evidence_id FROM e",
                    &[&fx.evidence[0], &fx.member],
                )
                .unwrap()
                .get(0);
            let rt = runtime();
            let (dsn, tenant, member) = (fx.dsn.clone(), fx.tenant, fx.member);
            let edges = RelationPair::ALL.map(|pair| (pair, fx.edge(pair)));
            let (auth, e1, e2, foreign) = (
                fx.evidence[0],
                fx.evidence[1],
                fx.evidence[2],
                fx.other_evidence,
            );
            rt.block_on(async move {
                // dep: PostgreSQL(any) — open a role-scoped PG connection/pool for this test
                let mut conn = PgConnection::connect(&dsn).await.unwrap();
                for (pair, edge) in edges {
                    let mut txn = gateway_txn(&mut conn, tenant).await;
                    for (name, factual, expected) in [
                        (
                            "no Evidence",
                            vec![e1, Uuid::now_v7()],
                            (Err(ErrorCode::InvalidInput), 0),
                        ),
                        (
                            "other tenant's Evidence",
                            vec![e1, foreign],
                            (Err(ErrorCode::InvalidInput), 0),
                        ),
                        (
                            "this tenant's Evidence the writer cannot see",
                            vec![e1, hidden],
                            (Err(ErrorCode::InvalidInput), 0),
                        ),
                        (
                            "repeated Evidence",
                            vec![e1, e1],
                            (Err(ErrorCode::InvalidInput), 0),
                        ),
                        ("distinct Evidence of this tenant", vec![e1, e2], (Ok(1), 1)),
                    ] {
                        let got =
                            try_create(&mut txn, &edge, &principal(member), &factual, auth).await;
                        assert_eq!(got, expected, "{pair:?}: {name}");
                    }
                    txn.rollback().await.unwrap();
                }
            });
        },
    );
}

/// G-T06d-3 (0253 ③, design v0.2 §15.5): on each table, a `principal:` decider is accepted only when it resolves to
/// a live member of this tenant (ACTIVE membership, ACTIVE user, ACTIVE tenant): the member user itself and a live
/// key of this tenant bound to it pass. Refused as INVALID_INPUT: a user ACTIVE only in another tenant; an INVITED,
/// SUSPENDED or REMOVED member; a SUSPENDED user whose membership is ACTIVE, and a live key bound to that user; a
/// live key bound to a user who is no member here; a machine key (no user); a revoked key; another tenant's key bound
/// to the member; the member once the tenant is SUSPENDED; and a malformed `principal:` value (not 22P02 /
/// INTERNAL). The predicate also answers false for another tenant than the session's.
#[test]
#[allow(clippy::too_many_lines)] // one decoy per predicate leg, judged on three tables
fn g_t06d_3_principal_decider_is_a_live_member() {
    run_db_fixture::<Fx, _>("g_t06d_3_principal_decider_is_a_live_member", |mut fx| {
        let (tenant, other, member) = (fx.tenant, fx.other, fx.member);
        let c = &mut fx.client;
        let elsewhere = seed_member(c, other, "ACTIVE", "ACTIVE").unwrap();
        let invited = seed_member(c, tenant, "ACTIVE", "INVITED").unwrap();
        let suspended = seed_member(c, tenant, "ACTIVE", "SUSPENDED").unwrap();
        let removed = seed_member(c, tenant, "ACTIVE", "REMOVED").unwrap();
        let suspended_user = seed_member(c, tenant, "SUSPENDED", "ACTIVE").unwrap();
        let suspended_user_key = seed_key(c, tenant, Some(suspended_user), false);
        let non_member_key = seed_key(c, tenant, Some(elsewhere), false);
        let machine_key = seed_key(c, tenant, None, false);
        let revoked_key = seed_key(c, tenant, Some(member), true);
        let foreign_key = seed_key(c, other, Some(member), false);
        let live_key = seed_key(c, tenant, Some(member), false);
        let refused = (Err(ErrorCode::InvalidInput), 0);
        let rt = runtime();
        let (dsn, auth) = (fx.dsn.clone(), fx.evidence[0]);
        let edges = RelationPair::ALL.map(|pair| (pair, fx.edge(pair)));
        rt.block_on(async move {
            // dep: PostgreSQL(any) — open a role-scoped PG connection/pool for this test
            let mut conn = PgConnection::connect(&dsn).await.unwrap();
            for (pair, edge) in edges {
                let mut txn = gateway_txn(&mut conn, tenant).await;
                for (name, principal_id, expected) in [
                    ("user ACTIVE only in another tenant", elsewhere, refused),
                    ("INVITED member", invited, refused),
                    ("SUSPENDED member", suspended, refused),
                    ("REMOVED member", removed, refused),
                    ("SUSPENDED user, ACTIVE membership", suspended_user, refused),
                    ("live key of a SUSPENDED user", suspended_user_key, refused),
                    ("live key of a user who is no member here", non_member_key, refused),
                    ("machine key (no user)", machine_key, refused),
                    ("revoked key", revoked_key, refused),
                    ("another tenant's key", foreign_key, refused),
                    ("ACTIVE member", member, (Ok(1), 1)),
                    ("live key of an ACTIVE member", live_key, (Ok(1), 1)),
                ] {
                    let got = try_create(&mut txn, &edge, &principal(principal_id), &[], auth).await;
                    assert_eq!(got, expected, "{pair:?}: {name}");
                }
                // dep: PostgreSQL(any) — pool/txn query execution
                let mut sp = txn.begin().await.unwrap();
                let malformed = sqlx::query(&format!(
                    "INSERT INTO {} (tenant_id, relation_id, revision, src_id, dst_id, relation_kind, valid, \
                     decided_by, factual_evidence_ids, authorization_evidence_id) \
                     VALUES ($1, uuidv7(), 1, $2, $3, $4, '{{}}', 'principal:not-a-uuid', '{{}}', $5)",
                    Fx::table(pair)
                ))
                .bind(tenant)
                .bind(edge.src_id)
                .bind(edge.dst_id)
                .bind(edge.kind.as_str())
                .bind(auth)
                .execute(&mut *sp)
                .await
                .map_err(|e| e.as_database_error().and_then(|d| d.code()).map(|c| c.to_string()));
                assert_eq!(
                    malformed.map(|_| ()),
                    Err(Some("23503".to_string())),
                    "{pair:?}: malformed principal"
                );
                sp.rollback().await.unwrap();
                txn.rollback().await.unwrap();
            }
            let mut txn = gateway_txn(&mut conn, tenant).await;
            let answers: (bool, bool) = sqlx::query_as(
                "SELECT private.relation_principal_is_member($1, $2), \
                        private.relation_principal_is_member($3, $4)",
            )
            .bind(other)
            .bind(elsewhere)
            .bind(tenant)
            .bind(member)
            .fetch_one(&mut *txn)
            .await
            .unwrap();
            assert_eq!(
                answers,
                (false, true),
                "(another tenant than the session's, the session tenant)"
            );
            txn.rollback().await.unwrap();
            // Last, because it changes the fixture tenant: the same ACTIVE member once the tenant is SUSPENDED.
            let set_state = "UPDATE control.tenants SET state = $2 WHERE tenant_id = $1";
            sqlx::query(set_state)
                .bind(tenant)
                .bind("SUSPENDED")
                .execute(&mut conn)
                .await
                .unwrap();
            for (pair, edge) in edges {
                let mut txn = gateway_txn(&mut conn, tenant).await;
                let got = try_create(&mut txn, &edge, &principal(member), &[], auth).await;
                assert_eq!(got, refused, "{pair:?}: ACTIVE member of a SUSPENDED tenant");
                txn.rollback().await.unwrap();
            }
            sqlx::query(set_state)
                .bind(tenant)
                .bind("ACTIVE")
                .execute(&mut conn)
                .await
                .unwrap();
        });
    });
}

/// G-T06d-4 (0253 ④): on each table, the authorisation Evidence repeated among the factual Evidence is
/// INVALID_INPUT, although every id is a valid Evidence of this tenant.
#[test]
fn g_t06d_4_authorization_evidence_is_not_factual() {
    run_db_fixture::<Fx, _>("g_t06d_4_authorization_evidence_is_not_factual", |fx| {
        let rt = runtime();
        let (dsn, tenant, member) = (fx.dsn.clone(), fx.tenant, fx.member);
        let edges = RelationPair::ALL.map(|pair| (pair, fx.edge(pair)));
        let (auth, e1) = (fx.evidence[0], fx.evidence[1]);
        rt.block_on(async move {
            // dep: PostgreSQL(any) — open a role-scoped PG connection/pool for this test
            let mut conn = PgConnection::connect(&dsn).await.unwrap();
            for (pair, edge) in edges {
                let mut txn = gateway_txn(&mut conn, tenant).await;
                for (name, factual, expected) in [
                    (
                        "authorisation only",
                        vec![auth],
                        (Err(ErrorCode::InvalidInput), 0),
                    ),
                    (
                        "authorisation among others",
                        vec![e1, auth],
                        (Err(ErrorCode::InvalidInput), 0),
                    ),
                    ("disjoint", vec![e1], (Ok(1), 1)),
                ] {
                    let got = try_create(&mut txn, &edge, &principal(member), &factual, auth).await;
                    assert_eq!(got, expected, "{pair:?}: {name}");
                }
                txn.rollback().await.unwrap();
            }
        });
    });
}

/// #92 item 2: a segment start before PostgreSQL's earliest `timestamptz` is INVALID_INPUT in `Validity::new`, never
/// a 22008 that the adapter would answer INTERNAL; the earliest instant itself round-trips through the adapter, so
/// the bound is not stricter than PostgreSQL.
#[test]
fn out_of_range_timestamp_is_invalid_input() {
    run_db_fixture::<Fx, _>("out_of_range_timestamp_is_invalid_input", |fx| {
        let from = |t| Validity::new(&[(Included(Timestamp::Micros(t)), Unbounded)]);
        assert_eq!(from(i64::MIN), Err(ErrorCode::InvalidInput), "i64::MIN");
        assert_eq!(
            from(PG_TIMESTAMPTZ_MIN_MICROS - 1),
            Err(ErrorCode::InvalidInput),
            "1 µs before PostgreSQL's earliest timestamptz"
        );
        assert_eq!(
            Validity::new(&[
                (Included(Timestamp::Micros(T0)), Unbounded),
                (
                    Included(Timestamp::Micros(PG_TIMESTAMPTZ_MIN_MICROS - 1)),
                    Unbounded
                ),
            ]),
            Err(ErrorCode::InvalidInput),
            "a second segment 1 µs before PostgreSQL's earliest timestamptz"
        );
        let earliest = from(PG_TIMESTAMPTZ_MIN_MICROS).unwrap();
        let rt = runtime();
        let (dsn, tenant, member) = (fx.dsn.clone(), fx.tenant, fx.member);
        let (edge, auth) = (fx.edge(RelationPair::ProjectTask), fx.evidence[0]);
        rt.block_on(async move {
            // dep: PostgreSQL(any) — open a role-scoped PG connection/pool for this test
            let mut conn = PgConnection::connect(&dsn).await.unwrap();
            let mut txn = gateway_txn(&mut conn, tenant).await;
            let relation = RelationId::new();
            let written = append_revision(
                &mut txn,
                &edge,
                relation,
                0,
                &earliest,
                &principal(member),
                None,
                &[],
                auth,
            )
            .await;
            assert_eq!(written, Ok(1));
            let read = current_revision(&mut txn, RelationPair::ProjectTask, relation)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(read.valid, earliest);
            txn.rollback().await.unwrap();
        });
    });
}

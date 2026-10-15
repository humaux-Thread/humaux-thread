//! `adapters::tests::auth_scope_rls` — T1.5 integration test — §6.1/§62 RLS defense in depth: a request transaction
//!   sets `SET LOCAL humaux.tenant_id`/`humaux.user_id`, and PostgreSQL Row Level Security enforces tenant isolation
//!   independently of the application-layer `can_read` predicate (`humaux_domain::identity::can_read`, unit-tested in
//!   that crate).
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-projection, humaux-testkit, postgres, serde_json, uuid];
//!   services=[PostgreSQL(any) w=[control.workspace_memberships, private.evidence_objects, private.memory_evidence,
//!   private.memory_records, projection.stream_checkpoints], PostgreSQL(role_gateway)]; env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::credential_repo,
//!   adapters::postgres, adapters::read_gate, adapters::read_materialize,
//!   adapters::tests::support::operation_receipt_fixture, domain::authority, domain::error, domain::identity,
//!   domain::ids, humaux-testkit, projection::serving]
//! Called-by: [cargo-test]
//! Invariants: [builds and drops its own scratch schema and role (the real private schema is never touched); no DSN,
//!   unreachable DB or failed fixture DDL is a visible SKIP (DbFixtureSkipReason, §79.2); the M08 G-M08-4 tests below
//!   read the real `private` tables of a fixture tenant as a real role_gateway login and leave nothing behind]
//! Spec: Baseline §62; §6.1; §6.2.3; §79.2; M08 G-M08-4
//!
//! Self-contained fixture: builds its own scratch schema, table, non-superuser test role,
//! and the exact §62 policy shape, instead of depending on canonical DDL from the sibling
//! T1.1 task (which may not have landed yet in a parallel wave) — this test proves the RLS
//! *mechanism* frozen by §6.1/§62, not T1.1's specific table layout. Everything it creates
//! lives under `test_auth_scope_rls`/`test_auth_scope_rls_role`, dropped up front and again
//! on teardown — the dev DB's real `private` schema is never touched (repo `CLAUDE.md` hard
//! rule ④).
//!
//! Three-state skip contract (`humaux_testkit::DbFixtureSkipReason`, §79.2): no
//! `HUMAUX_TEST_PG_DSN` set, DSN set but unreachable, or fixture DDL failed (e.g. the
//! connecting role lacks `CREATEROLE`/`CREATE SCHEMA`) — each prints a visible `SKIP` with
//! its reason and the test returns, it never silently passes.
//!
//! The RLS check requires a *non-superuser* session: PostgreSQL superusers and
//! `BYPASSRLS` roles bypass row security unconditionally, `FORCE ROW LEVEL SECURITY`
//! included, so a raw superuser connection could not prove anything here. The fixture
//! connects with whatever role `HUMAUX_TEST_PG_DSN` names (dev default: `postgres`,
//! superuser) to create objects, then every assertion runs after `SET LOCAL ROLE` into a
//! freshly created non-superuser/non-`BYPASSRLS` role — `SET LOCAL ROLE` changes
//! `current_user` for RLS purposes without a second login.

use humaux_domain::ids::TenantId;
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

const SCHEMA: &str = "test_auth_scope_rls";
const ROLE: &str = "test_auth_scope_rls_role";

struct RlsHandle {
    client: Client,
}

impl Drop for RlsHandle {
    fn drop(&mut self) {
        // Best-effort teardown so a passing run leaves the dev DB clean; a failed run's
        // leftovers are removed by the next run's `DROP ... IF EXISTS` in `isolate()`
        // regardless, so an error here is not itself a test failure.
        let _ = self.client.batch_execute(&format!(
            "DROP SCHEMA IF EXISTS {SCHEMA} CASCADE; DROP ROLE IF EXISTS {ROLE};"
        ));
    }
}

struct RlsFixture;

impl DbIntegrationFixture for RlsFixture {
    type Handle = RlsHandle;

    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        let dsn =
            std::env::var("HUMAUX_TEST_PG_DSN").map_err(|_| DbFixtureSkipReason::NoDatabaseUrl)?;
        // dep: PostgreSQL(any) — opens the role-scoped connection for `isolate`
        let mut client = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;

        // §62 policy shape verbatim: ENABLE + FORCE ROW LEVEL SECURITY, USING/WITH CHECK
        // both keyed on `current_setting('humaux.tenant_id', true)::uuid`. `NOLOGIN` is
        // sufficient for the test role — assertions reach it via `SET LOCAL ROLE`, never a
        // second network login.
        client
            .batch_execute(&format!(
                "DROP SCHEMA IF EXISTS {SCHEMA} CASCADE;
                 DROP ROLE IF EXISTS {ROLE};
                 CREATE ROLE {ROLE} NOLOGIN NOBYPASSRLS;
                 CREATE SCHEMA {SCHEMA};
                 CREATE TABLE {SCHEMA}.rows (
                     id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                     tenant_id uuid NOT NULL,
                     body text NOT NULL
                 );
                 ALTER TABLE {SCHEMA}.rows ENABLE ROW LEVEL SECURITY;
                 ALTER TABLE {SCHEMA}.rows FORCE ROW LEVEL SECURITY;
                 CREATE POLICY tenant_isolation ON {SCHEMA}.rows
                 USING (tenant_id = nullif(current_setting('humaux.tenant_id', true), '')::uuid)
                 WITH CHECK (tenant_id = nullif(current_setting('humaux.tenant_id', true), '')::uuid);
                 GRANT USAGE ON SCHEMA {SCHEMA} TO {ROLE};
                 GRANT SELECT, INSERT ON {SCHEMA}.rows TO {ROLE};"
            ))
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;

        Ok(RlsHandle { client })
    }
}

#[test]
fn rls_tenant_context_via_set_local() {
    run_db_fixture::<RlsFixture, _>("rls_tenant_context_via_set_local", |mut handle| {
        // `.0`: `postgres::ToSql`/text interpolation need the inner `uuid::Uuid` — this
        // test's own concern, not something `TenantId` itself should grow (`ids.rs` is
        // outside this task's assigned files, see identity.rs module doc).
        let tenant_a = TenantId::new().0;
        let tenant_b = TenantId::new().0;

        // Seed one row for tenant A, as the non-superuser role, under its own tenant
        // context — proves "正确 tenant 可读写自己的行" also covers the write side.
        {
            let mut txn = handle.client.transaction().expect("begin seed transaction");
            // dep: PostgreSQL(any) — role switch before the scoped statements for `rls_tenant_context_via_set_local`
            txn.batch_execute(&format!(
                "SET LOCAL ROLE {ROLE};
                 SET LOCAL humaux.tenant_id = '{tenant_a}';
                 SET LOCAL humaux.user_id = '{tenant_a}';"
            ))
            .expect("set local tenant/user context for seed insert");
            let inserted = txn
                .execute(
                    &format!("INSERT INTO {SCHEMA}.rows (tenant_id, body) VALUES ($1, 'a-row')"),
                    &[&tenant_a],
                )
                .expect("insert own-tenant row must succeed under matching SET LOCAL context");
            assert_eq!(inserted, 1, "exactly one row inserted for tenant A");
            txn.commit().expect("commit seed transaction");
        }

        // Cross-tenant SELECT: SET LOCAL to tenant B, must see 0 of tenant A's rows.
        {
            let mut txn = handle
                .client
                .transaction()
                .expect("begin cross-tenant transaction");
            // dep: PostgreSQL(any) — role switch before the scoped statements for `rls_tenant_context_via_set_local`
            txn.batch_execute(&format!(
                "SET LOCAL ROLE {ROLE};
                 SET LOCAL humaux.tenant_id = '{tenant_b}';"
            ))
            .expect("set local tenant context for cross-tenant read");
            let row = txn
                .query_one(&format!("SELECT count(*) FROM {SCHEMA}.rows"), &[])
                .expect("count query");
            let count: i64 = row.get(0);
            assert_eq!(
                count, 0,
                "§6.1.1: tenant B's session must see 0 rows of tenant A's data"
            );
            txn.rollback().expect("rollback read-only transaction");
        }

        // No SET LOCAL at all — deliberately run *after* two transactions that already used
        // `SET LOCAL humaux.tenant_id` on this same pooled connection. PostgreSQL's
        // placeholder GUCs (an undeclared `namespace.name` like `humaux.tenant_id`, §6.1)
        // reset to `''` — not NULL — once a session-local `SET LOCAL` has ever targeted them
        // and the transaction ends; only a session that *never* touched the GUC sees NULL
        // from `current_setting(..., true)`. A real gateway reuses pooled connections across
        // requests (§6.2.3), so "forgot to SET LOCAL" on request N+1 hits the `''` case, not
        // the pristine-session NULL case — verified by running this scenario third, not
        // first. Plain `current_setting(...)::uuid` (§62's literal example) would then throw
        // `invalid input syntax for type uuid: ""` instead of failing closed to 0 rows: this
        // fixture's policy guards with `nullif(current_setting(...), '')::uuid` so both the
        // pristine-NULL and post-reset-`''` cases collapse to the same NULL comparison, which
        // is NULL (not true) for every row — excluded, 0 rows either way. The canonical §62
        // policy T1.1/T1.3 install on `private.*` must carry the same guard, or the
        // "forgot to SET LOCAL" failure mode is a 500 on a warm connection, not the 0-row
        // fail-closed read this task requires.
        {
            let mut txn = handle
                .client
                .transaction()
                .expect("begin no-context transaction");
            // dep: PostgreSQL(any) — role switch before the scoped statements for `rls_tenant_context_via_set_local`
            txn.batch_execute(&format!("SET LOCAL ROLE {ROLE};"))
                .expect("set local role only, no tenant context");
            let row = txn
                .query_one(&format!("SELECT count(*) FROM {SCHEMA}.rows"), &[])
                .expect("count query");
            let count: i64 = row.get(0);
            assert_eq!(
                count, 0,
                "§6.1: a transaction that never set humaux.tenant_id must read 0 rows, not everything"
            );
            txn.rollback().expect("rollback read-only transaction");
        }

        // Correct tenant reads its own row back.
        {
            let mut txn = handle
                .client
                .transaction()
                .expect("begin own-tenant read transaction");
            // dep: PostgreSQL(any) — role switch before the scoped statements for `rls_tenant_context_via_set_local`
            txn.batch_execute(&format!(
                "SET LOCAL ROLE {ROLE};
                 SET LOCAL humaux.tenant_id = '{tenant_a}';"
            ))
            .expect("set local tenant context for own-tenant read");
            let row = txn
                .query_one(
                    &format!("SELECT count(*), max(body) FROM {SCHEMA}.rows"),
                    &[],
                )
                .expect("count query");
            let count: i64 = row.get(0);
            let body: Option<String> = row.get(1);
            assert_eq!(count, 1, "tenant A must read exactly its own seeded row");
            assert_eq!(body.as_deref(), Some("a-row"));
            txn.rollback().expect("rollback read-only transaction");
        }
    });
}

// ADR-0035 (card 13, §6.1.1): WORKSPACE_SHARED(W) is readable iff the reader holds an ACTIVE
// WorkspaceMembership(T, W, U) — NOT merely an ACTIVE tenant membership. This test proves the
// re-pointed policy (migration 0163) against the canonical FORCE-RLS `private.memory_records` and
// the real `role_gateway` login, and the Rust derivation `credential_repo::load_live_workspace_ids`
// against `control.workspace_memberships` (migration 0162). The fixture's fresh tenant is created
// AFTER the 0162 backfill, so its workspace memberships are seeded explicitly here.
// The shared fixture exposes many helpers; this test uses only a few. Other tests exercise the
// rest, so the unused-here methods are not dead code across the crate.
#[allow(dead_code)]
#[path = "support/operation_receipt_fixture.rs"]
mod operation_receipt_fixture;

use humaux_adapters::credential_repo;
use operation_receipt_fixture::Fixture;
use uuid::Uuid;

fn seed_workspace_membership(admin: &mut Client, tenant: Uuid, workspace: Uuid, user: Uuid) {
    // Superuser bypasses FORCE RLS; role/state are the closed CHECK sets (OWNER|MEMBER,
    // ACTIVE|SUSPENDED|REMOVED). No 0160-style folding trigger on this table, so spell 'MEMBER'.
    admin
        .execute(
            "INSERT INTO control.workspace_memberships(tenant_id,workspace_id,user_id,role,state) \
             VALUES($1,$2,$3,'MEMBER','ACTIVE')",
            &[&tenant, &workspace, &user],
        )
        .expect("owner seeds workspace membership");
}

/// A WORKSPACE_SHARED memory filed under `workspace`, grounded on one PRIMARY evidence (mirrors
/// the fixture's own scoped-context seed, but at a caller-chosen workspace).
fn seed_workspace_shared_memory(
    admin: &mut Client,
    tenant: Uuid,
    workspace: Uuid,
    reasoning_domain: Uuid,
) -> Uuid {
    let mut txn = admin.transaction().expect("begin ws-shared memory seed");
    let evidence_id: Uuid = txn
        .query_one(
            r#"INSERT INTO private.evidence_objects
               (tenant_id,evidence_kind,payload_sha256,data_class,origin_class,visibility_class,visibility_workspace_id,reasoning_domain_id)
             VALUES($1,'EVENT',$2,'INTERNAL','DirectUserInput','WORKSPACE_SHARED',$3,$4)
             RETURNING evidence_id"#,
            &[&tenant, &vec![5_u8; 32], &workspace, &reasoning_domain],
        )
        .expect("owner seeds ws evidence")
        .get(0);
    let confidence: f32 = 0.9;
    let memory_id: Uuid = txn
        .query_one(
            r#"INSERT INTO private.memory_records
               (tenant_id,memory_type,content,visibility_class,visibility_workspace_id,authority_class,confidence,status,asserted_at)
             VALUES($1,'NOTE',$2,'WORKSPACE_SHARED',$3,'ProjectConstraint',$4,'active',clock_timestamp())
             RETURNING memory_id"#,
            &[
                &tenant,
                &serde_json::json!({"fixture": "ws-shared membership rls"}),
                &workspace,
                &confidence,
            ],
        )
        .expect("owner seeds ws-shared memory")
        .get(0);
    txn.execute(
        r#"INSERT INTO private.memory_evidence(memory_id,evidence_id,role,grounding_mode)
         VALUES($1,$2,'PRIMARY','SNAPSHOT')"#,
        &[&memory_id, &evidence_id],
    )
    .expect("owner links ws-shared memory to evidence");
    txn.commit().expect("commit ws-shared memory seed");
    memory_id
}

fn sorted(mut ids: Vec<Uuid>) -> Vec<Uuid> {
    ids.sort_unstable();
    ids
}

/// Reads `memory_id`'s visibility for one on-behalf-of user, through the real `role_gateway`
/// login (non-superuser, non-BYPASSRLS) with `SET LOCAL humaux.tenant_id/user_id` — exactly the
/// gateway request shape. Returns how many rows RLS admits (0 or 1).
fn gateway_sees(gw: &mut Client, tenant: Uuid, user: Uuid, memory_id: Uuid) -> i64 {
    let mut txn = gw.transaction().expect("begin gateway read");
    txn.batch_execute(&format!(
        "SET LOCAL humaux.tenant_id = '{tenant}'; SET LOCAL humaux.user_id = '{user}';"
    ))
    .expect("set gateway request context");
    let count: i64 = txn
        .query_one(
            "SELECT count(*) FROM private.memory_records WHERE memory_id = $1",
            &[&memory_id],
        )
        .expect("gateway visibility count")
        .get(0);
    txn.rollback().expect("rollback gateway read");
    count
}

#[test]
#[allow(clippy::too_many_lines)] // one causally ordered acceptance story: RLS + Rust derivation
fn workspace_shared_needs_workspace_membership_not_tenant_membership() {
    run_db_fixture::<Fixture, _>(
        "workspace_shared_needs_workspace_membership_not_tenant_membership",
        |mut handle| {
            let tenant = handle.tenant_id;
            let alice = handle.user_id; // ACTIVE tenant member (fixture owner user)
            let w1 = handle.workspace_id;
            let w2 = handle.seed_workspace();
            let w3 = handle.seed_workspace();
            let bob = handle.seed_peer_user(); // ACTIVE tenant member, different user
            let reasoning_domain = handle.reasoning_domain_id;

            // Alice {W1, W2}; Bob {W2, W3}. Both are ACTIVE tenant members. Alice's W1 membership
            // is seeded by the fixture (its owner user on its own workspace); `seed_peer_user` gives
            // Bob a W1 membership by default, which this acceptance removes so Bob is exactly
            // {W2, W3} — a member of neither the fixture's W1 nor, importantly, no wider set.
            handle
                .admin
                .execute(
                    "DELETE FROM control.workspace_memberships WHERE tenant_id=$1 AND workspace_id=$2 AND user_id=$3",
                    &[&tenant, &w1, &bob],
                )
                .expect("drop Bob's default-workspace membership");
            seed_workspace_membership(&mut handle.admin, tenant, w2, alice);
            seed_workspace_membership(&mut handle.admin, tenant, w2, bob);
            seed_workspace_membership(&mut handle.admin, tenant, w3, bob);

            let memory_w3 =
                seed_workspace_shared_memory(&mut handle.admin, tenant, w3, reasoning_domain);

            // Live PG RLS: Alice (a tenant member, but NOT a W3 workspace member) must see 0 rows.
            // Under 0153's tenant-membership arm this returned 1 — the §6.1.1 bug this card fixes;
            // dropping the workspace-membership EXISTS collapses right back to that (tenant-wide).
            let mut gw = handle.gateway_client().expect("actual role_gateway login");
            assert_eq!(
                gateway_sees(&mut gw, tenant, alice, memory_w3),
                0,
                "Alice holds no ACTIVE WorkspaceMembership(T, W3): WORKSPACE_SHARED(W3) is invisible"
            );
            assert_eq!(
                gateway_sees(&mut gw, tenant, bob, memory_w3),
                1,
                "Bob holds ACTIVE WorkspaceMembership(T, W3): WORKSPACE_SHARED(W3) is visible"
            );

            // The Rust derivation reads the same live set per (tenant, user).
            let alice_ws = handle
                .rt
                .block_on(credential_repo::load_live_workspace_ids(
                    &handle.runtime,
                    tenant,
                    alice,
                ))
                .expect("load Alice live workspaces");
            assert_eq!(sorted(alice_ws), sorted(vec![w1, w2]));
            let bob_ws = handle
                .rt
                .block_on(credential_repo::load_live_workspace_ids(
                    &handle.runtime,
                    tenant,
                    bob,
                ))
                .expect("load Bob live workspaces");
            assert_eq!(sorted(bob_ws), sorted(vec![w2, w3]));
        },
    );
}

// ---------------------------------------------------------------------------------------------------------------------
// G-M08-4 (module design M08 D7): the tenant GUC is transaction-local, so a pooled connection that served one tenant
// carries nothing into the next request. Two witnesses against the real `private` tables and the real role_gateway
// login: a raw reused connection with the GUC setup removed (the mutant) reads zero rows, and the production read path
// over a one-connection pool answers each tenant from its own context, never from a cached allow.
// ---------------------------------------------------------------------------------------------------------------------

use humaux_adapters::{
    postgres::{PoolSettings, RuntimeDbPool},
    read_gate::materialize_memory_get,
    read_materialize::MaterializedItem,
};
use humaux_domain::{
    authority::MemoryId,
    error::ErrorCode,
    identity::{AuthorizationScope, BoundedSet, PrincipalId},
    ids::{Scope, UserId, WorkspaceId},
};
use humaux_projection::serving::StreamFamily;
use operation_receipt_fixture::{DOMAIN, PROJECTION_KIND, PROJECTION_VERSION};

/// What one count statement did under a given GUC setup.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Probe {
    /// The statement ran and RLS admitted this many rows.
    Rows(i64),
    /// RLS evaluation raised this SQLSTATE; no row was returned.
    Error(String),
}

/// SQLSTATE `invalid_text_representation`: `current_setting('humaux.tenant_id', true)::uuid` over the `''` a
/// placeholder GUC keeps once a `SET LOCAL` transaction on this backend has ended (see the first test's comment).
const INVALID_TEXT_REPRESENTATION: &str = "22P02";

/// Runs `sql` (one `$1` uuid) in its own transaction on `gw`, with `context` = the production request shape
/// (`SET LOCAL` tenant and user) or `None` = the mutant: the same statement with the GUC setup removed. Returns the
/// outcome and the serving backend pid. One transaction per statement: an RLS error aborts its transaction.
fn probe(gw: &mut Client, context: Option<(Uuid, Uuid)>, sql: &str, id: Uuid) -> (Probe, i32) {
    let mut txn = gw.transaction().expect("begin gateway read");
    if let Some((tenant, user)) = context {
        txn.batch_execute(&format!(
            "SET LOCAL humaux.tenant_id = '{tenant}'; SET LOCAL humaux.user_id = '{user}';"
        ))
        .expect("set gateway request context");
    }
    let pid: i32 = txn
        .query_one("SELECT pg_backend_pid()", &[])
        .expect("backend pid")
        .get(0);
    let outcome = match txn.query_one(sql, &[&id]) {
        Ok(row) => Probe::Rows(row.get(0)),
        Err(error) => Probe::Error(
            error
                .code()
                .map_or_else(|| "no-sqlstate".to_owned(), |code| code.code().to_owned()),
        ),
    };
    let _ = txn.rollback();
    (outcome, pid)
}

/// The memory, its Evidence row and their link, each as `(count statement, id it binds)`.
fn private_probes(memory: Uuid, evidence: Uuid) -> [(&'static str, Uuid); 3] {
    [
        (
            "SELECT count(*) FROM private.memory_records WHERE memory_id = $1",
            memory,
        ),
        (
            "SELECT count(*) FROM private.evidence_objects WHERE evidence_id = $1",
            evidence,
        ),
        (
            "SELECT count(*) FROM private.memory_evidence WHERE memory_id = $1",
            memory,
        ),
    ]
}

fn probe_all(
    gw: &mut Client,
    context: Option<(Uuid, Uuid)>,
    probes: &[(&'static str, Uuid); 3],
) -> (Vec<Probe>, i32) {
    let mut pid = 0;
    let outcomes = probes
        .iter()
        .map(|(sql, id)| {
            let (outcome, backend) = probe(gw, context, sql, *id);
            pid = backend;
            outcome
        })
        .collect();
    (outcomes, pid)
}

#[test]
fn guc_setup_removed_on_a_reused_gateway_connection_returns_no_rows() {
    run_db_fixture::<Fixture, _>(
        "guc_setup_removed_on_a_reused_gateway_connection_returns_no_rows",
        |mut handle| {
            let record = handle.seed_workspace_visible_context_record();
            let probes = private_probes(record.memory_id, record.evidence_id);
            let (tenant, user) = (handle.tenant_id, handle.user_id);
            let foreign = (Uuid::new_v4(), Uuid::new_v4());
            let mut gw = handle.gateway_client().expect("actual role_gateway login");

            let (own, pid) = probe_all(&mut gw, Some((tenant, user)), &probes);
            assert_eq!(
                own,
                vec![Probe::Rows(1); 3],
                "positive control: the owner tenant reads its own rows"
            );

            // The mutant: the next request on the very same backend skips the GUC setup. SET LOCAL ended with the
            // previous transaction, so RLS has no tenant: it must admit nothing (§6.1 fail closed, never "the last
            // tenant"). A placeholder GUC that a SET LOCAL has targeted reads back as '', so the policy's plain
            // `::uuid` cast may refuse the statement (22P02) instead of filtering to zero rows: both return no row.
            let (mutant, mutant_pid) = probe_all(&mut gw, None, &probes);
            assert_eq!(mutant_pid, pid, "the mutant ran on the reused connection");
            eprintln!("M08-3 G-M08-4 observed mutant outcomes on a reused connection: {mutant:?}");
            for (outcome, (sql, _)) in mutant.iter().zip(&probes) {
                assert!(
                    matches!(outcome, Probe::Rows(0))
                        || *outcome == Probe::Error(INVALID_TEXT_REPRESENTATION.to_owned()),
                    "no GUC setup must return no row ({sql}): {outcome:?}"
                );
            }
            let guc: String = {
                let mut txn = gw.transaction().expect("begin GUC probe");
                let value = txn
                    .query_one(
                        "SELECT coalesce(current_setting('humaux.tenant_id', true), '')",
                        &[],
                    )
                    .expect("read the tenant GUC")
                    .get(0);
                txn.rollback().expect("rollback GUC probe");
                value
            };
            assert_eq!(guc, "", "no tenant GUC survives the previous transaction");

            // Another tenant on the same backend sees none of the first tenant's rows.
            let (cross, cross_pid) = probe_all(&mut gw, Some(foreign), &probes);
            assert_eq!(cross_pid, pid);
            assert_eq!(
                cross,
                vec![Probe::Rows(0); 3],
                "a foreign tenant context reads zero rows"
            );

            // Nothing was cached on the way: the owner reads again, then the mutant is empty again.
            let (again, _) = probe_all(&mut gw, Some((tenant, user)), &probes);
            assert_eq!(again, vec![Probe::Rows(1); 3]);
            let (mutant_again, _) = probe_all(&mut gw, None, &probes);
            assert_eq!(
                mutant_again, mutant,
                "the mutant outcome is stable, not state-dependent"
            );

            // A backend that never ran a SET LOCAL has no placeholder at all: the same mutant is exactly zero rows.
            let mut pristine = handle.gateway_client().expect("a fresh role_gateway login");
            let (fresh, _) = probe_all(&mut pristine, None, &probes);
            assert_eq!(
                fresh,
                vec![Probe::Rows(0); 3],
                "a connection that never carried a tenant GUC reads zero rows"
            );
        },
    );
}

// ponytail: hand-rolled pgwire framing, simple-query text only; a column spanning frames, a second backend,
// an extended-protocol reply or a non-text column breaks it. Upgrade: a real pgwire crate if a second test needs a tap.
/// A byte-for-byte TCP tap between a one-connection `RuntimeDbPool` and PostgreSQL that can ask that same backend
/// a question while the pool is idle. `RuntimeDbPool` hands no connection out of the crate, so this is the only way
/// to read a session GUC on the backend the product's reads actually ran on.
struct BackendTap {
    port: u16,
    backends: Arc<AtomicUsize>,
    server: Arc<Mutex<Option<TcpStream>>>,
    asking: Arc<Mutex<Option<mpsc::Sender<String>>>>,
}

impl BackendTap {
    /// Listens on loopback and relays to `upstream` (`host:port`) over plaintext.
    fn start(upstream: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback tap");
        let tap = Self {
            port: listener.local_addr().expect("tap address").port(),
            backends: Arc::new(AtomicUsize::new(0)),
            server: Arc::new(Mutex::new(None)),
            asking: Arc::new(Mutex::new(None)),
        };
        let (backends, slot, asking, upstream) = (
            Arc::clone(&tap.backends),
            Arc::clone(&tap.server),
            Arc::clone(&tap.asking),
            upstream.to_owned(),
        );
        thread::spawn(move || {
            for client in listener.incoming().flatten() {
                // dep: PostgreSQL(role_gateway) — the tap relays the pool's connection to the gateway login
                let Ok(server) = TcpStream::connect(&upstream) else {
                    continue;
                };
                backends.fetch_add(1, Ordering::SeqCst);
                *slot.lock().unwrap() = Some(server.try_clone().expect("clone server half"));
                let (mut from_client, mut to_server) = (
                    client.try_clone().expect("clone client half"),
                    server.try_clone().unwrap(),
                );
                thread::spawn(move || {
                    let _ = std::io::copy(&mut from_client, &mut to_server);
                });
                let (mut from_server, mut to_client, asking) =
                    (server, client, Arc::clone(&asking));
                thread::spawn(move || {
                    Self::relay_backend(&mut from_server, &mut to_client, &asking)
                });
            }
        });
        tap
    }

    /// Server to client. While a question is open the backend's bytes are parsed (first column of the first
    /// `DataRow`, answered at `ReadyForQuery`) and withheld from the pool; otherwise they are forwarded untouched.
    fn relay_backend(
        from_server: &mut TcpStream,
        to_client: &mut TcpStream,
        asking: &Mutex<Option<mpsc::Sender<String>>>,
    ) {
        let (mut chunk, mut parsed, mut answer) =
            ([0_u8; 8192], Vec::new(), String::from("NO ROW"));
        while let Ok(read) = from_server.read(&mut chunk) {
            if read == 0 {
                return;
            }
            let mut slot = asking.lock().unwrap();
            if slot.is_none() {
                drop(slot);
                if to_client.write_all(&chunk[..read]).is_err() {
                    return;
                }
                continue;
            }
            parsed.extend_from_slice(&chunk[..read]);
            while parsed.len() >= 5 {
                let length = u32::from_be_bytes(parsed[1..5].try_into().unwrap()) as usize;
                if parsed.len() < 1 + length {
                    break;
                }
                let frame: Vec<u8> = parsed.drain(..1 + length).collect();
                match frame[0] {
                    b'D' => {
                        let column = i32::from_be_bytes(frame[7..11].try_into().unwrap());
                        answer = usize::try_from(column).map_or_else(
                            |_| "NULL".to_owned(),
                            |n| String::from_utf8_lossy(&frame[11..11 + n]).into_owned(),
                        );
                    }
                    b'E' => answer = "ERROR".to_owned(),
                    b'Z' => {
                        let _ = slot.take().expect("open question").send(answer.clone());
                        answer = String::from("NO ROW");
                    }
                    _ => {}
                }
            }
        }
    }

    /// The tenant and user GUCs as the pooled backend itself sees them, joined with `|`.
    fn context_gucs(&self) -> String {
        let (reply, answer) = mpsc::channel();
        *self.asking.lock().unwrap() = Some(reply);
        let text = "SELECT coalesce(current_setting('humaux.tenant_id', true), '') || '|' || \
                    coalesce(current_setting('humaux.user_id', true), '')\0";
        let mut query = vec![b'Q'];
        query.extend_from_slice(&u32::try_from(4 + text.len()).unwrap().to_be_bytes());
        query.extend_from_slice(text.as_bytes());
        self.server
            .lock()
            .unwrap()
            .as_mut()
            .expect("the pool opened a backend")
            .write_all(&query)
            .expect("ask the pooled backend");
        answer
            .recv_timeout(Duration::from_secs(5))
            .expect("the pooled backend answered")
    }
}

#[test]
#[allow(clippy::too_many_lines)] // one seeded tenant pair, three reads on one pooled backend
fn one_connection_pool_never_carries_one_tenants_context_into_the_next_read() {
    run_db_fixture::<Fixture, _>(
        "one_connection_pool_never_carries_one_tenants_context_into_the_next_read",
        |mut handle| {
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
            let memory = handle.seed_workspace_visible_context_record().memory_id;
            let application_name = format!("m08_guc_{}", handle.tenant_id.simple());
            // The pool dials the tap, which relays to the validated gateway login (credential never logged).
            let gateway_dsn = handle.gateway_dsn_for_process().to_owned();
            let (credential, rest) = gateway_dsn.rsplit_once('@').expect("gateway DSN authority");
            let (upstream, database) = rest.split_once('/').expect("gateway DSN database");
            let tap = BackendTap::start(upstream);
            let tapped = format!(
                "{credential}@127.0.0.1:{}/{database}?sslmode=disable",
                tap.port
            );
            // dep: PostgreSQL(role_gateway) — a one-connection production pool: every read below reuses one backend
            let pool = handle
                .rt
                .block_on(RuntimeDbPool::connect_with(
                    &tapped,
                    &PoolSettings {
                        max_connections: 1,
                        min_connections: 0,
                        acquire_timeout: std::time::Duration::from_secs(10),
                        idle_timeout: std::time::Duration::from_secs(60),
                        max_lifetime: std::time::Duration::from_secs(600),
                        statement_timeout: std::time::Duration::from_secs(30),
                        idle_in_transaction_timeout: std::time::Duration::from_secs(30),
                        application_name: application_name.clone(),
                    },
                ))
                .expect("one-connection role_gateway pool");

            let tenant_b = Uuid::new_v4();
            let (user_b, workspace_b) = (Uuid::new_v4(), Uuid::new_v4());
            let auth_b = AuthorizationScope::new(
                TenantId(tenant_b),
                PrincipalId(user_b),
                Some(UserId(user_b)),
                BoundedSet::new([WorkspaceId(workspace_b)]).expect("workspace set"),
            );
            let scope = |tenant: Uuid, user: Uuid, workspace: Uuid| Scope {
                tenant_id: TenantId(tenant),
                user_id: Some(UserId(user)),
                workspace_id: Some(WorkspaceId(workspace)),
                repository_id: None,
                task_id: None,
                run_id: None,
                agent_id: None,
            };
            let family = |tenant: Uuid, workspace: Uuid| {
                StreamFamily::new(
                    TenantId(tenant),
                    "workspace",
                    workspace,
                    DOMAIN,
                    PROJECTION_KIND,
                )
            };
            let get = |auth: &AuthorizationScope, scope: &Scope, family: &StreamFamily| {
                handle.rt.block_on(materialize_memory_get(
                    &pool,
                    auth,
                    scope,
                    family,
                    &family.with_version(PROJECTION_VERSION),
                    MemoryId(memory),
                ))
            };
            let (scope_a, family_a) = (
                scope(handle.tenant_id, handle.user_id, handle.workspace_id),
                family(handle.tenant_id, handle.workspace_id),
            );
            let (scope_b, family_b) = (
                scope(tenant_b, user_b, workspace_b),
                family(tenant_b, workspace_b),
            );
            let first =
                get(&handle.auth, &scope_a, &family_a).expect("owner tenant reads its memory");
            assert!(first.bodies.items.iter().any(
                |item| matches!(item, MaterializedItem::Memory { memory_id, .. } if *memory_id == memory)
            ));
            // The other tenant, on the same backend, is answered from its own context: not found, no cached allow.
            assert!(
                matches!(get(&auth_b, &scope_b, &family_b), Err(ErrorCode::NotFound)),
                "a foreign tenant must not read the memory the previous request on this connection could"
            );
            let last = get(&handle.auth, &scope_a, &family_a)
                .expect("owner tenant still reads its memory");
            assert!(last.bodies.items.iter().any(
                |item| matches!(item, MaterializedItem::Memory { memory_id, .. } if *memory_id == memory)
            ));

            let sessions: i64 = handle
                .admin
                .query_one(
                    "SELECT count(*) FROM pg_stat_activity WHERE application_name = $1",
                    &[&application_name],
                )
                .expect("count pool sessions")
                .get(0);
            assert_eq!(sessions, 1, "all three reads reused one backend");
            assert_eq!(
                tap.backends.load(Ordering::SeqCst),
                1,
                "through one connection"
            );
            // After the product's reads, on that very backend, no tenant or user context outlives its transaction:
            // `SET LOCAL` / `set_config(.., true)` leave the placeholder (''), a session-level `SET` leaves the tenant.
            assert_eq!(
                tap.context_gucs(),
                "|",
                "the pooled backend carries no request context between requests"
            );
        },
    );
}

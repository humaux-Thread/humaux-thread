//! `adapters::tests::memory_in_project` — M29-g1 (ADR-0110 D-F, migration 0282): `private.memory_in_project(tenant,
//!   memory, project)` is true only for a live (existing, unrevoked) link in the caller's tenant, and only `role_gateway`
//!   may execute it.
//! Depends-on: crates=[humaux-testkit, postgres, uuid]; services=[PostgreSQL(owner) w=[control.private_reasoning_domains,
//!   control.tenants, control.workspaces, private.continuity_projects, private.evidence_objects,
//!   private.memory_project_revocations, private.memory_projects, private.memory_records],
//!   PostgreSQL(role_gateway) x=[private.memory_in_project], PostgreSQL(role_maintenance),
//!   PostgreSQL(role_private_worker)]; env=[HUMAUX_TEST_PG_DSN]; modules=[humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [every row, tenant and role switch lives in one transaction that is rolled back, so no row survives and
//!   nothing needs a purge; a positive control precedes each false answer so it is attributable to its one cause]
//! Spec: Baseline §6.1.4; §79.2; §80.1; ADR-0078 D-D; ADR-0110 D-F
//!
//! | test | case | injected fault that turns it red |
//! |---|---|---|
//! | `g_m29_7_in_project_answers_live_links_only` | (a) live -> true | the predicate answers false for a live link |
//! | | (b) revoked -> false | the predicate reads the base table instead of the live view |
//! | | (c) no row (unresolved) -> false | the predicate answers true for a memory with no row |
//! | | (d) another project -> false | the project leg dropped |
//! | | (e) another tenant -> false | the view stops being `security_invoker`, or the tenant leg and RLS both dropped |
//! | `g_m29_7_execute_is_role_gateway_only` | (f) other roles get 42501 | the EXECUTE grant goes to PUBLIC |
//!
//! Skip contract (§79.2): no DSN / unreachable => visible SKIP.

use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::error::SqlState;
use postgres::{Client, NoTls, Transaction};
use uuid::Uuid;

struct Handle {
    client: Client,
}

struct Fixture;

impl DbIntegrationFixture for Fixture {
    type Handle = Handle;

    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        let dsn =
            std::env::var("HUMAUX_TEST_PG_DSN").map_err(|_| DbFixtureSkipReason::NoDatabaseUrl)?;
        // dep: PostgreSQL(owner) — superuser connection; every statement runs in a transaction that is rolled back
        let client = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        Ok(Handle { client })
    }
}

/// The predicate under test.
const CALL: &str = "SELECT private.memory_in_project($1, $2, $3)";

// dep: PostgreSQL(role_gateway) — test switches PG role to exercise the view's RLS and the EXECUTE grant
const AS_GATEWAY: &str = "SET LOCAL ROLE role_gateway";

// dep: PostgreSQL(role_private_worker) — test switches PG role to prove it holds no EXECUTE
const AS_PRIVATE_WORKER: &str = "SET LOCAL ROLE role_private_worker";

// dep: PostgreSQL(role_maintenance) — test switches PG role to prove it holds no EXECUTE
const AS_MAINTENANCE: &str = "SET LOCAL ROLE role_maintenance";

/// Every runtime role and PUBLIC that holds EXECUTE on the predicate, by catalog. §6.2.2: `role_gateway` alone.
const EXECUTE_HOLDERS: &str = "SELECT t.role FROM unnest(ARRAY['public', 'role_admin', 'role_batch_issuer', \
    'role_consolidation_worker', 'role_gateway', 'role_maintenance', 'role_private_worker', 'role_public_worker', \
    'role_retrieval_worker']) AS t(role) \
    WHERE has_function_privilege(t.role, 'private.memory_in_project(uuid,uuid,uuid)', 'EXECUTE')";

/// One seeded tenant: its decision Evidence and two projects. The tenant, its workspace and its reasoning domain are
/// rows of the same rolled-back transaction.
struct Tenant {
    id: Uuid,
    evidence: Uuid,
    p1: Uuid,
    p2: Uuid,
}

fn project(txn: &mut Transaction<'_>, tenant: Uuid, workspace: Uuid) -> Uuid {
    txn.query_one(
        "INSERT INTO private.continuity_projects (project_id, tenant_id, workspace_id, title) \
         VALUES (uuidv7(), $1, $2, 'memory in project') RETURNING project_id",
        &[&tenant, &workspace],
    )
    .expect("project")
    .get(0)
}

fn seed_tenant(txn: &mut Transaction<'_>) -> Tenant {
    let (id, workspace, domain) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    txn.execute(
        "INSERT INTO control.tenants (tenant_id, name) VALUES ($1, $2)",
        &[&id, &format!("memory-in-project-{id}")],
    )
    .expect("tenant");
    txn.execute(
        "INSERT INTO control.workspaces (workspace_id, tenant_id, name) VALUES ($1, $2, 'memory in project')",
        &[&workspace, &id],
    )
    .expect("workspace");
    txn.execute(
        "INSERT INTO control.private_reasoning_domains (reasoning_domain_id, tenant_id, name) VALUES ($1, $2, 'default')",
        &[&domain, &id],
    )
    .expect("reasoning domain");
    let evidence = txn
        .query_one(
            "INSERT INTO private.evidence_objects \
               (tenant_id, evidence_kind, payload_sha256, data_class, origin_class, visibility_class, reasoning_domain_id) \
             VALUES ($1, 'EVENT', sha256(convert_to(gen_random_uuid()::text, 'UTF8')), 'INTERNAL', 'DirectUserInput', \
               'TENANT_SHARED', $2) RETURNING evidence_id",
            &[&id, &domain],
        )
        .expect("decision evidence")
        .get(0);
    let p1 = project(txn, id, workspace);
    let p2 = project(txn, id, workspace);
    Tenant {
        id,
        evidence,
        p1,
        p2,
    }
}

/// A tenant-shared Memory (the owner passes RLS; the gateway sees it under its own tenant GUC).
fn memory(txn: &mut Transaction<'_>, tenant: Uuid) -> Uuid {
    txn.query_one(
        "INSERT INTO private.memory_records \
           (tenant_id, memory_type, content, visibility_class, authority_class, confidence, status, asserted_at) \
         VALUES ($1, 'NOTE', '{}'::jsonb, 'TENANT_SHARED', 'PrivateKnowledge', 0.5, 'active', clock_timestamp()) \
         RETURNING memory_id",
        &[&tenant],
    )
    .expect("memory")
    .get(0)
}

/// One `memory_projects` row, as the ladder writes a declared link (the CHECKs want no inheritance or task ground).
fn link(txn: &mut Transaction<'_>, tenant: &Tenant, memory: Uuid, project: Uuid) {
    txn.execute(
        "INSERT INTO private.memory_projects \
           (tenant_id, memory_id, project_id, relation, source_kind, rule_id_ver, decision_evidence_id) \
         VALUES ($1, $2, $3, 'ATTRIBUTED_TO', 'DECLARED', 'declared@1', $4)",
        &[&tenant.id, &memory, &project, &tenant.evidence],
    )
    .expect("live link");
}

/// A revocation row. Its definer trigger refuses a tenant other than the session's (0255 ⑤), so the caller sets it.
fn revoke(txn: &mut Transaction<'_>, tenant: &Tenant, memory: Uuid, project: Uuid) {
    txn.execute(
        "INSERT INTO private.memory_project_revocations (tenant_id, memory_id, project_id, revoked_by, reason) \
         VALUES ($1, $2, $3, 'rule:fixture@1', 'memory_in_project case (b)')",
        &[&tenant.id, &memory, &project],
    )
    .expect("revocation");
}

fn session_tenant(txn: &mut Transaction<'_>, tenant: Uuid) {
    txn.execute(
        "SELECT set_config('humaux.tenant_id', $1, true)",
        &[&tenant.to_string()],
    )
    .expect("session tenant");
}

fn asks(txn: &mut Transaction<'_>, tenant: Uuid, memory: Uuid, project: Uuid) -> bool {
    txn.query_one(CALL, &[&tenant, &memory, &project])
        .expect("the predicate answers")
        .get(0)
}

/// Cases (a)-(e), as `role_gateway` under the session tenant GUC of the first tenant.
#[test]
fn g_m29_7_in_project_answers_live_links_only() {
    run_db_fixture::<Fixture, _>(
        "g_m29_7_in_project_answers_live_links_only",
        |mut handle| {
            let mut txn = handle.client.transaction().expect("begin");
            let (own, other) = (seed_tenant(&mut txn), seed_tenant(&mut txn));
            let (live, revoked, unresolved) = (
                memory(&mut txn, own.id),
                memory(&mut txn, own.id),
                memory(&mut txn, own.id),
            );
            let foreign = memory(&mut txn, other.id);
            link(&mut txn, &own, live, own.p1);
            link(&mut txn, &own, revoked, own.p1);
            link(&mut txn, &other, foreign, other.p1);
            session_tenant(&mut txn, own.id);
            txn.batch_execute(AS_GATEWAY).expect("gateway role");

            assert!(
                asks(&mut txn, own.id, live, own.p1),
                "(a) a live link answers true"
            );
            assert!(
                asks(&mut txn, own.id, revoked, own.p1),
                "(b) control: the link to be revoked is live first"
            );
            txn.batch_execute("RESET ROLE").expect("owner");
            revoke(&mut txn, &own, revoked, own.p1);
            txn.batch_execute(AS_GATEWAY).expect("gateway role");
            assert!(
                !asks(&mut txn, own.id, revoked, own.p1),
                "(b) the same link after its revocation row answers false"
            );
            assert!(
                !asks(&mut txn, own.id, unresolved, own.p1),
                "(c) a memory with no row answers false"
            );
            assert!(
                !asks(&mut txn, own.id, Uuid::new_v4(), own.p1),
                "(c) an unknown memory id answers false"
            );
            assert!(
                !asks(&mut txn, own.id, live, own.p2),
                "(d) a live link to P1 asked about P2 answers false"
            );
            assert!(
                !asks(&mut txn, other.id, foreign, other.p1),
                "(e) another tenant's live link, under this session's tenant GUC, answers false"
            );
            assert!(
                !asks(&mut txn, own.id, foreign, other.p1),
                "(e) another tenant's memory asked under this tenant's id answers false"
            );
            session_tenant(&mut txn, other.id);
            assert!(
                asks(&mut txn, other.id, foreign, other.p1),
                "(e) control: the same link is live under its own tenant GUC"
            );
            txn.rollback().expect("rollback");
        },
    );
}

/// Case (f): by catalog only `role_gateway` holds EXECUTE (PUBLIC included), and the two roles that must not call it
/// are refused with 42501.
#[test]
fn g_m29_7_execute_is_role_gateway_only() {
    run_db_fixture::<Fixture, _>("g_m29_7_execute_is_role_gateway_only", |mut handle| {
        let holders: Vec<String> = handle
            .client
            .query(EXECUTE_HOLDERS, &[])
            .expect("privilege matrix")
            .iter()
            .map(|row| row.get(0))
            .collect();
        assert_eq!(
            holders,
            ["role_gateway"],
            "(f) EXECUTE holders among PUBLIC and the runtime roles"
        );
        for switch in [AS_PRIVATE_WORKER, AS_MAINTENANCE] {
            let mut txn = handle.client.transaction().expect("begin");
            txn.batch_execute(switch).expect("switch role");
            let refused = txn
                .query_one(CALL, &[&Uuid::new_v4(), &Uuid::new_v4(), &Uuid::new_v4()])
                .expect_err("EXECUTE is refused");
            txn.rollback().expect("rollback");
            assert_eq!(
                refused.code(),
                Some(&SqlState::INSUFFICIENT_PRIVILEGE),
                "(f) {switch}: {refused}"
            );
        }
    });
}

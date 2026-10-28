//! `adapters::tests::exact_census_project` — M13-7 / G-M13-8: the EXACT census narrowed to a project counts and returns
//!   only the memories with a live link to it, on both faces of one snapshot, and a revoked or absent link is outside
//!   the project universe.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-projection, humaux-retrieval, humaux-testkit, postgres,
//!   serde_json, tokio, uuid]; services=[PostgreSQL(owner) r=[control.retrieval_predicates]
//!   w=[control.memberships, control.private_reasoning_domains, control.tenants, control.users,
//!   control.workspace_memberships, control.workspaces, private.continuity_projects, private.events,
//!   private.evidence_objects, private.memory_evidence, private.memory_project_revocations, private.memory_projects,
//!   private.memory_records], PostgreSQL(role_gateway)]; env=[HUMAUX_TEST_PG_DSN];
//!   modules=[adapters::exact_census, adapters::postgres, adapters::tests::support::throwaway_db, domain::continuity,
//!   domain::identity, domain::ids, humaux-testkit, projection::stream, retrieval::predicate_registry]
//! Called-by: [cargo-test]
//! Invariants: [runs in its own throwaway database because the attribution rows are immutable and cannot be cleaned
//!   up in a shared one; the census runs as role_gateway, the one EXECUTE holder of the predicate, over the registry
//!   predicate rejected_decisions_v1; every control precedes the case it makes attributable (the link is live before
//!   its revocation, the foreign project is live under its own tenant); no DSN or unreachable DB is a visible SKIP]
//! Spec: Baseline §22.1; §79.2; §80.1; ADR-0078 D-D; ADR-0110 D-F
//!
//! | case | assertion | injected fault that turns it red |
//! |---|---|---|
//! | (a) | P1 with two live links counts 2 and returns both | the project conjunct dropped from the count or the items |
//! | (b) | after B's revocation P1 counts 1, returns `[A]`, total equals the item count | the census reads `memory_projects` instead of the live view |
//! | (b) | the same readout is an enumerated census | the items statement drops the project conjunct (items past total) |
//! | (c) | no project is the unchanged census: A, B, C, equal to `exact_enumerate` | the `None` path changes its text or binds |
//! | (d) | a project with no link counts 0: C (no link) is never guessed into it | an unresolved memory falls back into a project |
//! | (e) | another tenant's project counts 0 under this tenant's session | the tenant leg or the RLS dropped from the predicate |
//!
//! Skip contract (§79.2): no DSN / unreachable => visible SKIP.

use humaux_adapters::exact_census::{exact_enumerate, exact_enumerate_in_project};
use humaux_adapters::postgres::RuntimeDbPool;
use humaux_domain::continuity::ProjectId;
use humaux_domain::identity::{AuthorizationScope, BoundedSet, PrincipalId};
use humaux_domain::ids::{TenantId, UserId, WorkspaceId};
use humaux_projection::stream::StreamKey;
use humaux_retrieval::predicate_registry::{PredicateEntry, PredicateRow, load_registry};
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls, Transaction};
use uuid::Uuid;

#[path = "support/throwaway_db.rs"]
#[allow(dead_code)]
mod throwaway_db;
use throwaway_db::ThrowawayDb;

struct Handle {
    rt: tokio::runtime::Runtime,
    pool: RuntimeDbPool,
    admin: Client,
    entry: PredicateEntry,
    /// Dropped last: it drops the whole database.
    _db: ThrowawayDb,
}

struct CensusFixture;

impl DbIntegrationFixture for CensusFixture {
    type Handle = Handle;

    fn isolate() -> Result<Handle, DbFixtureSkipReason> {
        let db = throwaway_db::create("m13_census_project")?;
        let dsn = db.dsn();
        // dep: PostgreSQL(owner) — seeds the fixture and reads the registry row
        let mut admin = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        let entry = registry_entry(&mut admin);
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        let sep = if dsn.contains('?') { '&' } else { '?' };
        let pool = rt
            // dep: PostgreSQL(role_gateway) — the role the production census runs as
            .block_on(RuntimeDbPool::connect(&format!(
                "{dsn}{sep}options=-c%20role%3Drole_gateway"
            )))
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        Ok(Handle {
            rt,
            pool,
            admin,
            entry,
            _db: db,
        })
    }
}

/// The seeded registry row, through the same §50 loader production takes (a `PredicateEntry` has no public literal).
fn registry_entry(admin: &mut Client) -> PredicateEntry {
    let row = admin
        .query_one(
            "SELECT predicate_id, sql_predicate, required_columns, enumerable_scope, surface_patterns, owner_module \
             FROM control.retrieval_predicates WHERE predicate_id = 'rejected_decisions_v1'",
            &[],
        )
        .expect("the seeded registry row");
    let raw = PredicateRow {
        predicate_id: row.get(0),
        sql_predicate: row.get(1),
        required_columns: row.get(2),
        enumerable_scope: row.get(3),
        surface_patterns: row.get(4),
        owner_module: row.get(5),
    };
    load_registry(vec![raw]).expect("the seeded row passes the loader")[0].clone()
}

/// One seeded tenant: a user who is an ACTIVE member of its one workspace, the decision Evidence the links cite, and
/// two projects.
struct World {
    tenant: Uuid,
    user: Uuid,
    workspace: Uuid,
    domain: Uuid,
    decision: Uuid,
    p1: Uuid,
    p2: Uuid,
}

/// An EVENT Evidence row with its event, visible to the whole tenant.
fn insert_evidence(txn: &mut Transaction<'_>, tenant: Uuid, domain: Uuid) -> Uuid {
    let id: Uuid = txn
        .query_one(
            "INSERT INTO private.evidence_objects \
               (tenant_id, evidence_kind, payload_sha256, data_class, origin_class, visibility_class, \
                reasoning_domain_id) \
             VALUES ($1, 'EVENT', sha256(convert_to(gen_random_uuid()::text, 'UTF8')), 'INTERNAL', \
                'DirectUserInput', 'TENANT_SHARED', $2) RETURNING evidence_id",
            &[&tenant, &domain],
        )
        .expect("evidence")
        .get(0);
    txn.execute(
        "INSERT INTO private.events (event_id, event_kind, payload) VALUES ($1, 'USER_MESSAGE', '{}'::jsonb)",
        &[&id],
    )
    .expect("event");
    id
}

fn project(admin: &mut Client, tenant: Uuid, workspace: Uuid) -> Uuid {
    admin
        .query_one(
            "INSERT INTO private.continuity_projects (project_id, tenant_id, workspace_id, title) \
             VALUES (uuidv7(), $1, $2, 'exact census project') RETURNING project_id",
            &[&tenant, &workspace],
        )
        .expect("project")
        .get(0)
}

fn seed_world(admin: &mut Client, label: &str) -> World {
    let tenant: Uuid = admin
        .query_one(
            "INSERT INTO control.tenants (name) VALUES ($1) RETURNING tenant_id",
            &[&format!("exact_census_project {label}")],
        )
        .expect("tenant")
        .get(0);
    let domain: Uuid = admin
        .query_one(
            "INSERT INTO control.private_reasoning_domains (tenant_id, name) \
             VALUES ($1, 'exact_census_project') RETURNING reasoning_domain_id",
            &[&tenant],
        )
        .expect("reasoning domain")
        .get(0);
    let user: Uuid = admin
        .query_one(
            "INSERT INTO control.users (state) VALUES ('ACTIVE') RETURNING user_id",
            &[],
        )
        .expect("user")
        .get(0);
    admin
        .execute(
            "INSERT INTO control.memberships (tenant_id, user_id, role, state) \
             VALUES ($1, $2, 'MEMBER', 'ACTIVE')",
            &[&tenant, &user],
        )
        .expect("membership");
    let workspace: Uuid = admin
        .query_one(
            "INSERT INTO control.workspaces (tenant_id, name) VALUES ($1, 'exact_census_project') \
             RETURNING workspace_id",
            &[&tenant],
        )
        .expect("workspace")
        .get(0);
    admin
        .execute(
            "INSERT INTO control.workspace_memberships (tenant_id, workspace_id, user_id, role, state) \
             VALUES ($1, $2, $3, 'MEMBER', 'ACTIVE')",
            &[&tenant, &workspace, &user],
        )
        .expect("workspace membership");
    let mut txn = admin.transaction().expect("begin decision evidence");
    let decision = insert_evidence(&mut txn, tenant, domain);
    txn.commit().expect("commit decision evidence");
    World {
        tenant,
        user,
        workspace,
        domain,
        decision,
        p1: project(admin, tenant, workspace),
        p2: project(admin, tenant, workspace),
    }
}

/// A workspace-shared REJECTION memory with its backing Evidence (the registry predicate's universe), committed with
/// its link so the deferred orphan check (§8.6) holds.
fn rejection(admin: &mut Client, w: &World) -> Uuid {
    let mut txn = admin.transaction().expect("begin memory");
    let evidence = insert_evidence(&mut txn, w.tenant, w.domain);
    let memory: Uuid = txn
        .query_one(
            "INSERT INTO private.memory_records \
               (tenant_id, memory_type, content, visibility_class, visibility_workspace_id, authority_class, \
                confidence, status, asserted_at) \
             VALUES ($1, 'REJECTION', $2, 'WORKSPACE_SHARED', $3, 'ProjectDecision', 0.9, 'active', now()) \
             RETURNING memory_id",
            &[
                &w.tenant,
                &serde_json::json!({"fixture": "exact_census_project"}),
                &w.workspace,
            ],
        )
        .expect("memory")
        .get(0);
    txn.execute(
        "INSERT INTO private.memory_evidence (memory_id, evidence_id, role, grounding_mode) \
         VALUES ($1, $2, 'PRIMARY', 'SNAPSHOT')",
        &[&memory, &evidence],
    )
    .expect("evidence link");
    txn.commit().expect("commit memory");
    memory
}

/// One `memory_projects` row, as the ladder writes a declared link.
fn link(admin: &mut Client, w: &World, memory: Uuid, project: Uuid) {
    admin
        .execute(
            "INSERT INTO private.memory_projects \
               (tenant_id, memory_id, project_id, relation, source_kind, rule_id_ver, decision_evidence_id) \
             VALUES ($1, $2, $3, 'ATTRIBUTED_TO', 'DECLARED', 'declared@1', $4)",
            &[&w.tenant, &memory, &project, &w.decision],
        )
        .expect("live link");
}

/// A revocation row. Its definer trigger refuses a tenant other than the session's (0255 ⑤), so the transaction sets it.
fn revoke(admin: &mut Client, w: &World, memory: Uuid, project: Uuid) {
    let mut txn = admin.transaction().expect("begin revocation");
    txn.execute(
        "SELECT set_config('humaux.tenant_id', $1, true)",
        &[&w.tenant.to_string()],
    )
    .expect("session tenant");
    txn.execute(
        "INSERT INTO private.memory_project_revocations (tenant_id, memory_id, project_id, revoked_by, reason) \
         VALUES ($1, $2, $3, 'rule:fixture@1', 'exact census project case (b)')",
        &[&w.tenant, &memory, &project],
    )
    .expect("revocation");
    txn.commit().expect("commit revocation");
}

fn authorization(w: &World) -> AuthorizationScope {
    AuthorizationScope::new(
        TenantId(w.tenant),
        PrincipalId(w.user),
        Some(UserId(w.user)),
        BoundedSet::new([WorkspaceId(w.workspace)]).expect("one authorized workspace"),
    )
}

fn stream_key(w: &World) -> StreamKey {
    StreamKey::new(
        TenantId(w.tenant),
        "workspace",
        w.workspace,
        "private_memory",
        "retrieval_cards",
        "v1",
    )
}

/// `(total, returned ids)` of one census as `w`'s user. The readout must be the enumerated one: a census the
/// constructor refused (items past the counted universe) is a failed census, which this fails on.
fn census(h: &Handle, w: &World, project: Option<Uuid>) -> (u64, Vec<Uuid>) {
    let outcome =
        h.rt.block_on(exact_enumerate_in_project(
            &h.pool,
            &h.entry,
            &authorization(w),
            WorkspaceId(w.workspace),
            &stream_key(w),
            project.map(ProjectId),
        ))
        .expect("the census transaction opens");
    let enumeration = outcome
        .census
        .enumeration()
        .expect("an enumerated census: a failed one means the items left the counted universe");
    assert_eq!(
        enumeration.returned(),
        outcome.returned_ids.len() as u64,
        "returned is the item count"
    );
    assert_eq!(enumeration.excluded_secret(), 0, "no secret-linked fixture");
    (enumeration.total(), outcome.returned_ids)
}

fn sorted(mut ids: Vec<Uuid>) -> Vec<Uuid> {
    ids.sort();
    ids
}

/// G-M13-8, cases (a)-(e). A and B link to P1 (B's link is later revoked); C has no link at all.
#[test]
fn g_m13_8_census_counts_live_project_links_on_both_faces() {
    run_db_fixture::<CensusFixture, _>(
        "g_m13_8_census_counts_live_project_links_on_both_faces",
        |mut h| {
            let w = seed_world(&mut h.admin, "own");
            let (a, b, c) = (
                rejection(&mut h.admin, &w),
                rejection(&mut h.admin, &w),
                rejection(&mut h.admin, &w),
            );
            link(&mut h.admin, &w, a, w.p1);
            link(&mut h.admin, &w, b, w.p1);

            assert_eq!(
                census(&h, &w, Some(w.p1)),
                (2, sorted(vec![a, b])),
                "(a) control: both links are live"
            );
            revoke(&mut h.admin, &w, b, w.p1);
            let (total, items) = census(&h, &w, Some(w.p1));
            assert_eq!(
                total, 1,
                "(b) the revoked link is outside the counted universe"
            );
            assert_eq!(items, vec![a], "(b) A is the one member, never B or C");
            assert_eq!(
                total as usize,
                items.len(),
                "(b) total equals the items on the EXACT path"
            );

            let (total, items) = census(&h, &w, None);
            assert_eq!(
                (total, items),
                (3, sorted(vec![a, b, c])),
                "(c) no project axis"
            );
            let plain = h.rt.block_on(exact_enumerate(
                &h.pool,
                &h.entry,
                &authorization(&w),
                WorkspaceId(w.workspace),
                &stream_key(&w),
            ));
            let none = h.rt.block_on(exact_enumerate_in_project(
                &h.pool,
                &h.entry,
                &authorization(&w),
                WorkspaceId(w.workspace),
                &stream_key(&w),
                None,
            ));
            assert_eq!(
                plain, none,
                "(c) None is the existing census, field for field"
            );

            assert_eq!(
                census(&h, &w, Some(w.p2)),
                (0, vec![]),
                "(d) P2 has no link: neither A (P1's) nor C (unresolved) is guessed into it"
            );

            let foreign = seed_world(&mut h.admin, "foreign");
            let m = rejection(&mut h.admin, &foreign);
            link(&mut h.admin, &foreign, m, foreign.p1);
            assert_eq!(
                census(&h, &foreign, Some(foreign.p1)),
                (1, vec![m]),
                "(e) control: the foreign link is live under its own tenant"
            );
            assert_eq!(
                census(&h, &w, Some(foreign.p1)),
                (0, vec![]),
                "(e) a project of another tenant is invisible to this tenant's session"
            );
        },
    );
}

//! `adapters::tests::support::project_tree_fixture` — M18 fixture setup stays owner-only; every tree operation runs as role_gateway.
//! Depends-on: crates=[postgres, uuid]; services=[PostgreSQL(owner) w=[control.tenants, control.workspaces, private.continuity_projects], PostgreSQL(role_gateway) x=[private.project_move]]; env=[HUMAUX_TEST_PG_DSN]; modules=[]
//! Called-by: [adapters::tests::coord_rls, adapters::tests::project_tree]
//! Invariants: [§79.2 shared-database fixtures roll back; missing input fails]
//! Spec: Baseline §6.1.1; §79.2; ADR-0101

use postgres::{Client, NoTls};
use uuid::Uuid;

/// §79.2: an owner connection used only for fixture setup and witnesses.
pub fn connect(dsn: &str) -> Client {
    // dep: PostgreSQL(owner) — fixture setup and lock witnesses, never a runtime assertion.
    Client::connect(dsn, NoTls).expect("M18: database connection")
}

/// §79.2: absent CI input is a failure.
pub fn dsn() -> String {
    std::env::var("HUMAUX_TEST_PG_DSN").expect("fail: missing HUMAUX_TEST_PG_DSN")
}

/// §79.2: closing the connection rolls back uncommitted fixture writes.
pub struct Fixture {
    /// Owner setup transaction; runtime calls require `gateway` first.
    pub client: Client,
    /// Isolated tenant.
    pub tenant: Uuid,
    /// The common tree workspace.
    pub workspace: Uuid,
    /// Three initially independent roots.
    pub projects: [Uuid; 3],
    /// Authenticated principal GUC.
    pub principal: Uuid,
}

impl Fixture {
    /// §79.2: fixtures are uncommitted unless a concurrency test explicitly commits them.
    pub fn new(dsn: &str) -> Self {
        let mut client = connect(dsn);
        client.batch_execute("BEGIN").unwrap();
        let tenant = Uuid::now_v7();
        let workspace = Uuid::now_v7();
        let projects = std::array::from_fn(|_| Uuid::now_v7());
        let principal = Uuid::now_v7();
        client.execute("INSERT INTO control.tenants(tenant_id,name,state) VALUES ($1,'e2e-fixture m18 tree','ACTIVE')", &[&tenant]).unwrap();
        client
            .execute(
                "INSERT INTO control.workspaces(tenant_id,workspace_id,name) VALUES ($1,$2,'tree')",
                &[&tenant, &workspace],
            )
            .unwrap();
        for project in projects {
            client.execute("INSERT INTO private.continuity_projects(tenant_id,workspace_id,project_id,title) VALUES ($1,$2,$3,'tree')", &[&tenant,&workspace,&project]).unwrap();
        }
        Self {
            client,
            tenant,
            workspace,
            projects,
            principal,
        }
    }

    /// §6.1.1: request authority is installed before dropping owner privileges.
    pub fn gateway(&mut self) {
        context(&mut self.client, self.tenant, self.principal);
    }
}

/// ADR-0101 D-B: request GUCs, depth and role are transaction-local.
pub fn context(client: &mut Client, tenant: Uuid, principal: Uuid) {
    client.query_one("SELECT set_config('humaux.tenant_id',$1,true),set_config('humaux.principal_id',$2,true),set_config('humaux.project_max_depth','3',true)", &[&tenant.to_string(),&principal.to_string()]).unwrap();
    client
        .execute("SELECT set_config('humaux.user_id','',true)", &[])
        .unwrap();
    // dep: PostgreSQL(role_gateway) — every tree door is called with the runtime role, never the owner.
    client.batch_execute("SET LOCAL ROLE role_gateway").unwrap();
}

/// ADR-0101 D-B: calls the exact runtime move door, without translating its SQLSTATE.
pub fn move_project(
    client: &mut Client,
    tenant: Uuid,
    principal: Uuid,
    workspace: Uuid,
    project: Uuid,
    parent: Option<Uuid>,
) -> Result<i64, postgres::Error> {
    client
        .query_one(
            "SELECT private.project_move($1,$2,$3,1,$4,$5,NULL)",
            &[&tenant, &project, &parent, &vec![workspace], &principal],
        )
        .map(|row| row.get(0))
}

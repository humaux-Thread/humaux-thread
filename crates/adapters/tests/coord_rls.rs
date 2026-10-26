//! `adapters::tests::coord_rls` — G-M18-1 tree isolation: the composite parent FK and the owner doors' per-row visibility are independent barriers.
//! Depends-on: crates=[postgres, uuid]; services=[PostgreSQL(owner) w=[control.tenants, control.workspaces, private.continuity_projects], PostgreSQL(role_gateway) x=[private.project_subtree, private.project_ancestors]]; env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::tests::support::project_tree_fixture]
//! Called-by: [cargo-test]
//! Invariants: [§6.1.1 exact visible sets; fixture DDL rolls back; missing input fails]
//! Spec: Baseline §6.1.1; §79.2; §80.1; ADR-0101 D-A

use postgres::error::SqlState;
use project_tree_fixture::{Fixture, dsn, move_project};
use std::collections::BTreeSet;
use uuid::Uuid;
#[path = "support/project_tree_fixture.rs"]
mod project_tree_fixture;

#[test]
fn g_m18_1_foreign_parent_fk() {
    let mut fx = Fixture::new(&dsn());
    let foreign = Uuid::now_v7();
    let workspace = Uuid::now_v7();
    let parent = Uuid::now_v7();
    fx.client.execute("INSERT INTO control.tenants(tenant_id,name,state) VALUES ($1,'e2e-fixture foreign tree','ACTIVE')", &[&foreign]).unwrap();
    fx.client
        .execute(
            "INSERT INTO control.workspaces(tenant_id,workspace_id,name) VALUES ($1,$2,'foreign')",
            &[&foreign, &workspace],
        )
        .unwrap();
    fx.client.execute("INSERT INTO private.continuity_projects(tenant_id,workspace_id,project_id,title) VALUES ($1,$2,$3,'foreign')", &[&foreign,&workspace,&parent]).unwrap();
    // §6.1.1: temporary UPDATE permission isolates the FK gate from the separate closed-table ACL gate.
    fx.client.batch_execute("GRANT UPDATE(parent_id) ON private.continuity_projects TO role_gateway; GRANT SELECT(project_id) ON private.continuity_projects TO role_gateway; SAVEPOINT foreign_parent").unwrap();
    fx.gateway();
    let error = fx
        .client
        .execute(
            "UPDATE private.continuity_projects SET parent_id=$1 WHERE project_id=$2",
            &[&parent, &fx.projects[0]],
        )
        .expect_err("G-M18-1: FK must refuse foreign parent");
    assert_eq!(error.code(), Some(&SqlState::FOREIGN_KEY_VIOLATION));
    assert_eq!(
        error.as_db_error().unwrap().constraint(),
        Some("continuity_projects_tree_parent_fkey")
    );
    fx.client
        .batch_execute("ROLLBACK TO foreign_parent; RESET ROLE")
        .unwrap();
    fx.client
        .query_one(
            "SELECT set_config('humaux.tenant_id',$1,true)",
            &[&foreign.to_string()],
        )
        .unwrap();
    // dep: PostgreSQL(role_gateway) — a foreign-tenant session reads T1's project through the runtime doors.
    fx.client
        .batch_execute("SET LOCAL ROLE role_gateway")
        .unwrap();
    for door in [
        "SELECT * FROM private.project_subtree($1,$2,$3)",
        "SELECT * FROM private.project_ancestors($1,$2,$3)",
    ] {
        let rows = fx
            .client
            .query(door, &[&foreign, &fx.projects[0], &vec![workspace]])
            .unwrap();
        assert_eq!(rows.len(), 0, "G-M18-1: foreign start is invisible");
    }
}

#[test]
#[ignore = "lane(a:disposable) drops the tree parent FK to seed a corrupted topology (ALTER TABLE takes ACCESS EXCLUSIVE on the shared registry)"]
fn g_m18_1_per_row_visibility() {
    let mut fx = Fixture::new(&dsn());
    let [root, child, archived] = fx.projects;
    fx.client
        .execute(
            "UPDATE private.continuity_projects SET parent_id=$1 WHERE project_id=ANY($2)",
            &[&root, &vec![child, archived]],
        )
        .unwrap();
    fx.client
        .execute(
            "UPDATE private.continuity_projects SET lifecycle_state='ARCHIVED' WHERE project_id=$1",
            &[&archived],
        )
        .unwrap();
    seed_excluded_member(&mut fx, root);
    fx.gateway();
    let rows = fx
        .client
        .query(
            "SELECT project_id FROM private.project_subtree($1,$2,$3)",
            &[&fx.tenant, &root, &vec![fx.workspace]],
        )
        .unwrap();
    assert_eq!(
        rows.len(),
        2,
        "G-M18-1: per-row declared visibility excludes archived descendant"
    );
    assert_eq!(
        rows.into_iter()
            .map(|r| r.get::<_, Uuid>(0))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([root, child])
    );
    for project in [root, child, archived] {
        let rows = fx
            .client
            .query(
                "SELECT * FROM private.project_subtree($1,$2,'{}'::uuid[])",
                &[&fx.tenant, &project],
            )
            .unwrap();
        assert_eq!(
            rows.len(),
            0,
            "G-M18-1: excluded workspace returns no subtree rows"
        );
    }
    assert_eq!(
        move_project(
            &mut fx.client,
            fx.tenant,
            fx.principal,
            fx.workspace,
            child,
            None
        )
        .unwrap(),
        2
    );
}

fn seed_excluded_member(fx: &mut Fixture, root: Uuid) {
    let hidden_workspace = Uuid::now_v7();
    let hidden = Uuid::now_v7();
    // §6.1.1: a rolled-back corrupted topology tests the read barrier independently of the FK barrier.
    fx.client.batch_execute("ALTER TABLE private.continuity_projects DROP CONSTRAINT continuity_projects_tree_parent_fkey").unwrap();
    fx.client
        .execute(
            "INSERT INTO control.workspaces(tenant_id,workspace_id,name) VALUES ($1,$2,'excluded')",
            &[&fx.tenant, &hidden_workspace],
        )
        .unwrap();
    fx.client.execute("INSERT INTO private.continuity_projects(tenant_id,workspace_id,project_id,parent_id,title) VALUES ($1,$2,$3,$4,'excluded member')", &[&fx.tenant,&hidden_workspace,&hidden,&root]).unwrap();
}

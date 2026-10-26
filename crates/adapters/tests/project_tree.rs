//! M18 project move gates on the exact 0281 doors and Rust adapter.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, postgres, serde_json, sqlx, tokio, toml, uuid]; services=[PostgreSQL(owner) r=[pg_stat_activity, pg_constraint, private.continuity_projects, control.audit_events] w=[private.continuity_projects], PostgreSQL(role_gateway) x=[private.project_move, private.project_ancestors, private.project_subtree, private.read_project_rollup]]; env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::coord_tree_repo, domain::continuity, domain::identity, domain::ids, domain::project_tree]
//! Called-by: [cargo-test]
//! Invariants: [§80.1 exact counts/sets; lock witnesses fix concurrency ordering; missing inputs fail]
//! Spec: Baseline §30; §46.1; §78.2; §79.2; §80.1; ADR-0101

use postgres::error::SqlState;
use project_tree_fixture::{Fixture, connect, context, dsn, move_project};
use std::{
    collections::BTreeSet,
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

#[path = "support/project_tree_fixture.rs"]
mod project_tree_fixture;
#[path = "support/throwaway_db.rs"]
mod throwaway_db;

#[test]
fn g_m18_5_depth_boundary() {
    let mut fx = Fixture::new(&dsn());
    let [a, b, c] = fx.projects;
    fx.client
        .execute(
            "UPDATE private.continuity_projects SET parent_id=$1 WHERE project_id=$2",
            &[&a, &b],
        )
        .unwrap();
    fx.gateway();
    assert_eq!(
        move_project(
            &mut fx.client,
            fx.tenant,
            fx.principal,
            fx.workspace,
            c,
            Some(b)
        )
        .unwrap(),
        2,
        "G-M18-5: exactly at configured depth commits"
    );
    fx.client.batch_execute("SAVEPOINT depth_refusal").unwrap();
    // ADR-0101 D-B: moving a height-three subtree under another root exceeds the same limit.
    fx.client.batch_execute("RESET ROLE").unwrap();
    let root = Uuid::now_v7();
    fx.client.execute("INSERT INTO private.continuity_projects(tenant_id,workspace_id,project_id,title) VALUES ($1,$2,$3,'extra')", &[&fx.tenant,&fx.workspace,&root]).unwrap();
    fx.gateway();
    let error = move_project(
        &mut fx.client,
        fx.tenant,
        fx.principal,
        fx.workspace,
        a,
        Some(root),
    )
    .expect_err("G-M18-5: over-depth move must be refused");
    assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
    assert_eq!(
        error.as_db_error().unwrap().message(),
        "project depth exceeds coord.project_max_depth"
    );
    fx.client
        .batch_execute("ROLLBACK TO depth_refusal; RESET ROLE")
        .unwrap();
    let rows = fx.client.query("SELECT project_id,parent_id,version FROM private.continuity_projects WHERE tenant_id=$1 ORDER BY project_id", &[&fx.tenant]).unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(
        rows.into_iter()
            .map(|r| (
                r.get::<_, Uuid>(0),
                r.get::<_, Option<Uuid>>(1),
                r.get::<_, i64>(2)
            ))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([(a, None, 1), (b, Some(a), 1), (c, Some(b), 2)])
    );
}

fn wait_for_two_blocked(client: &mut postgres::Client, pids: &[i32]) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let count:i64=client.query_one("SELECT count(*) FROM pg_stat_activity WHERE pid=ANY($1) AND wait_event_type='Lock'", &[&pids]).unwrap().get(0);
        if count == 2 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "G-M18-4: both runtime calls must reach a witnessed lock wait (got {count})"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn concurrent_move(
    dsn: &str,
    start: &Barrier,
    send: &std::sync::mpsc::Sender<i32>,
    ids: [Uuid; 5],
) -> Result<i64, (String, String)> {
    let [tenant, principal, workspace, project, parent] = ids;
    let mut client = connect(&dsn);
    client
        .batch_execute("BEGIN; SET LOCAL statement_timeout='25s'")
        .unwrap();
    context(&mut client, tenant, principal, workspace);
    let pid: i32 = client
        .query_one("SELECT pg_backend_pid()", &[])
        .unwrap()
        .get(0);
    send.send(pid).unwrap();
    start.wait();
    let result = move_project(
        &mut client,
        tenant,
        principal,
        workspace,
        project,
        Some(parent),
    );
    if result.is_ok() {
        client.batch_execute("COMMIT").unwrap();
    }
    result.map_err(|error| {
        (
            error.code().unwrap().code().to_owned(),
            error.as_db_error().unwrap().message().to_owned(),
        )
    })
}

#[test]
fn g_m18_4_concurrent_cycle() {
    let db = throwaway_db::create("m18_cycle").expect("fail: isolated M18 database");
    let dsn = db.dsn();
    let mut fx = Fixture::new(&dsn);
    fx.client.batch_execute("COMMIT; BEGIN").unwrap();
    fx.client
        .query(
            "SELECT project_id FROM private.continuity_projects WHERE tenant_id=$1 FOR UPDATE",
            &[&fx.tenant],
        )
        .unwrap();
    let start = Arc::new(Barrier::new(3));
    let (send, receive) = std::sync::mpsc::channel();
    let [a, b, _] = fx.projects;
    let mut workers = Vec::new();
    for (project, parent) in [(a, b), (b, a)] {
        let (dsn, start, send) = (dsn.clone(), Arc::clone(&start), send.clone());
        let (tenant, principal, workspace) = (fx.tenant, fx.principal, fx.workspace);
        workers.push(thread::spawn(move || {
            concurrent_move(
                &dsn,
                &start,
                &send,
                [tenant, principal, workspace, project, parent],
            )
        }));
    }
    let pids = (0..2)
        .map(|_| receive.recv_timeout(Duration::from_secs(15)).unwrap())
        .collect::<Vec<_>>();
    start.wait();
    // §80.1: with the guard one waits there; without it both reach UPDATE using stale topology reads.
    wait_for_two_blocked(&mut connect(&dsn), &pids);
    fx.client.batch_execute("COMMIT").unwrap();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    let parents = fx
        .client
        .query(
            "SELECT project_id,parent_id FROM private.continuity_projects WHERE tenant_id=$1",
            &[&fx.tenant],
        )
        .unwrap();
    let edges = parents
        .into_iter()
        .filter_map(|r| {
            r.get::<_, Option<Uuid>>(1)
                .map(|p| (r.get::<_, Uuid>(0), p))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        results.iter().filter(|r| matches!(r, Ok(2))).count(),
        1,
        "G-M18-4: exactly one concurrent move commits; results={results:?}, edges={edges:?}"
    );
    assert_eq!(
        results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .cloned()
            .collect::<Vec<_>>(),
        vec![(
            "23514".to_owned(),
            "project move would create a cycle".to_owned()
        )]
    );
    assert_eq!(edges.len(), 1, "G-M18-4: no two-edge cycle");
    assert!(edges == BTreeSet::from([(a, b)]) || edges == BTreeSet::from([(b, a)]));
    let events:i64=fx.client.query_one("SELECT count(*) FROM control.audit_events WHERE tenant_id=$1 AND action='PROJECT_MOVE'", &[&fx.tenant]).unwrap().get(0);
    assert_eq!(events, 1);
}

#[test]
fn tree_closed_sets_match_both_checks() {
    use humaux_domain::project_tree::{ProjectFacetKind, ProjectKind};
    let mut fx = Fixture::new(&dsn());
    for (name, expected) in [
        (
            "continuity_projects_kind_closed",
            ProjectKind::ALL
                .map(|v| v.as_db_str())
                .into_iter()
                .collect::<BTreeSet<_>>(),
        ),
        (
            "project_facets_kind_closed",
            ProjectFacetKind::ALL
                .map(|v| v.as_db_str())
                .into_iter()
                .collect::<BTreeSet<_>>(),
        ),
    ] {
        let rows = fx
            .client
            .query(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname=$1",
                &[&name],
            )
            .unwrap();
        assert_eq!(rows.len(), 1);
        let definition: String = rows[0].get(0);
        let actual = definition
            .split('\'')
            .enumerate()
            .filter(|(i, _)| i % 2 == 1)
            .map(|(_, v)| v)
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected, "§78.2 exact closed set: {name}");
    }
}

#[test]
fn tree_adapter_reads_moves_and_cas() {
    use humaux_adapters::coord_tree_repo::{ancestors_in_txn, move_in_txn, subtree_in_txn};
    use humaux_domain::{
        continuity::ProjectId,
        error::ErrorCode,
        identity::{AuthorizationScope, BoundedSet, PrincipalId},
        ids::{TenantId, WorkspaceId},
    };
    use sqlx::Connection;
    let db = throwaway_db::create("m18_adapter").expect("fail: adapter database");
    let mut fx = Fixture::new(&db.dsn());
    fx.client.batch_execute("COMMIT").unwrap();
    tokio::runtime::Runtime::new().unwrap().block_on(async {
    let mut connection = sqlx::PgConnection::connect(&db.dsn()).await.unwrap();
    let mut tx = connection.begin().await.unwrap();
    sqlx::query("SELECT set_config('humaux.tenant_id',$1,true),set_config('humaux.principal_id',$2,true),set_config('humaux.user_id','',true)").bind(fx.tenant.to_string()).bind(fx.principal.to_string()).execute(&mut *tx).await.unwrap();
    sqlx::query("SET LOCAL ROLE role_gateway")
        .execute(&mut *tx)
        .await
        .unwrap();
    let scope = AuthorizationScope::new(
        TenantId(fx.tenant),
        PrincipalId(fx.principal),
        None,
        BoundedSet::new([WorkspaceId(fx.workspace)]).unwrap(),
    );
    let [a, b, _] = fx.projects;
    assert_eq!(
        move_in_txn(&mut tx, &scope, ProjectId(b), Some(ProjectId(a)), 1).await,
        Ok(2)
    );
    let tree = subtree_in_txn(&mut tx, &scope, ProjectId(a)).await.unwrap();
    assert_eq!(tree.len(), 2);
    assert_eq!(
        tree.into_iter()
            .map(|p| (p.project_id.0, p.parent_id.map(|id| id.0), p.version))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([(a, None, 1), (b, Some(a), 2)])
    );
    let ancestors = ancestors_in_txn(&mut tx, &scope, ProjectId(b))
        .await
        .unwrap();
    assert_eq!(ancestors.len(), 2);
    assert_eq!(
        ancestors
            .into_iter()
            .map(|p| p.project_id.0)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([a, b])
    );
    assert_eq!(
        move_in_txn(&mut tx, &scope, ProjectId(b), None, 1).await,
        Err(ErrorCode::Conflict)
    );
    tx.rollback().await.unwrap();
    });
}

fn historical_postcheck() -> String {
    let manifest: toml::Value = toml::from_str(include_str!(
        "../../../migrations/0271_project_channels.manifest.toml"
    ))
    .unwrap();
    manifest["postcheck"].as_str().unwrap().to_owned()
}

#[test]
fn channel_backfill_and_head_robust_manifest() {
    let mut fx = Fixture::new(&dsn());
    // §46.1: reconstruct 0271's relevant post-state in a rolled-back transaction, with exact historical SQL.
    fx.client.batch_execute("DROP FUNCTION private.project_ancestors(uuid,uuid,uuid[]); DROP FUNCTION private.project_subtree(uuid,uuid,uuid[]); DROP FUNCTION private.project_move(uuid,uuid,uuid,bigint,uuid[],uuid,uuid); DROP FUNCTION private.set_project_channel(uuid,uuid,uuid[],text); DROP FUNCTION private.read_project_rollup(uuid,uuid,text,uuid[]); DROP TABLE private.project_facets; ALTER TABLE private.continuity_projects DROP COLUMN parent_id, DROP COLUMN kind, DROP COLUMN version;").unwrap();
    fx.client
        .batch_execute(include_str!(
            "../../../migrations/0271_project_channels.sql"
        ))
        .unwrap();
    fx.gateway();
    let project = fx.projects[0];
    let before: bool = fx
        .client
        .query_one(
            "SELECT private.set_project_channel($1,$2,$3,'preserved_channel')",
            &[&fx.tenant, &project, &vec![fx.workspace]],
        )
        .unwrap()
        .get(0);
    assert!(before);
    fx.client.batch_execute("RESET ROLE").unwrap();
    let query = historical_postcheck();
    let before: bool = fx.client.query_one(&query, &[]).unwrap().get(0);
    assert!(
        before,
        "ADR-0082 D-D: all original assertions true at 0271 post-state"
    );
    fx.client
        .batch_execute(include_str!("../../../migrations/0281_project_tree.sql"))
        .unwrap();
    fx.client
        .query(&format!("EXPLAIN {query}"), &[])
        .expect("ADR-0082 D-D: historical check plans at head after DROP");
    let after: bool = fx.client.query_one(&query, &[]).unwrap().get(0);
    assert!(
        !after,
        "head no longer has the historical table; assertions are not weakened"
    );
    let manifest: toml::Value = toml::from_str(include_str!(
        "../../../migrations/0281_project_tree.manifest.toml"
    ))
    .unwrap();
    let post: bool = fx
        .client
        .query_one(manifest["postcheck"].as_str().unwrap(), &[])
        .unwrap()
        .get(0);
    assert!(post, "0281 post-state objects and privileges");
    let copied = fx
        .client
        .query(
            "SELECT project_id,kind,value FROM private.project_facets WHERE tenant_id=$1",
            &[&fx.tenant],
        )
        .unwrap();
    assert_eq!(copied.len(), 1);
    assert_eq!(
        (
            copied[0].get::<_, Uuid>(0),
            copied[0].get::<_, String>(1),
            copied[0].get::<_, String>(2)
        ),
        (
            project,
            "CHANNEL".to_owned(),
            "preserved_channel".to_owned()
        )
    );
    fx.gateway();
    let rollup: serde_json::Value = fx
        .client
        .query_one(
            "SELECT private.read_project_rollup($1,$2,'PROJECT',$3)",
            &[&fx.tenant, &project, &vec![fx.workspace]],
        )
        .unwrap()
        .get(0);
    assert_eq!(rollup["visible_count"], 1);
    assert_eq!(rollup["children"].as_array().unwrap().len(), 1);
    assert_eq!(rollup["children"][0]["project_id"], project.to_string());
    assert_eq!(rollup["children"][0]["channel_key"], "preserved_channel");
}

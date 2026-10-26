//! `adapters::tests::project_rollup` — G-M14-5 on the real 0271 doors.
//! Depends-on: crates=[humaux-adapters, humaux-domain, sqlx, tokio, uuid]; services=[PostgreSQL(owner) r=[] w=[control.tenants, control.workspaces, control.private_reasoning_domains, private.continuity_projects, private.subjects, private.evidence_objects, private.events, private.project_subject_relations, private.subject_relations, private.continuity_facet_versions, private.continuity_facet_slots], PostgreSQL(role_gateway)]; env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::project_rollup, domain::continuity, domain::error, domain::identity, domain::ids, domain::subject]
//! Called-by: [cargo-test]
//! Invariants: [§80.1 both faults hit exact count/set assertions; fixtures and grants roll back in one transaction; missing CI inputs fail]
//! Spec: Baseline §6.1.4; §25.3.1; §79.2; §80.1; ADR-0095 D-C

use std::collections::BTreeSet;

use humaux_adapters::project_rollup::{RollupTarget, read_in_txn, set_channel_in_txn};
use humaux_domain::{
    continuity::{ContinuityFacetKind, ProjectId},
    error::ErrorCode,
    identity::{AuthorizationScope, BoundedSet, PrincipalId},
    ids::{TenantId, WorkspaceId},
    subject::SubjectId,
};
use sqlx::{Connection, PgConnection, Postgres, Transaction};
use uuid::Uuid;

struct Fixture<'a> {
    tx: Transaction<'a, Postgres>,
    scope: AuthorizationScope,
    visible: [Uuid; 2],
    hidden: Uuid,
    brand: Uuid,
    business: Uuid,
    version: Uuid,
}

async fn evidence(tx: &mut Transaction<'_, Postgres>, tenant: Uuid) -> Uuid {
    sqlx::query_scalar(
        "WITH d AS (INSERT INTO control.private_reasoning_domains (tenant_id,name) \
         VALUES ($1,'rollup') RETURNING reasoning_domain_id), \
         e AS (INSERT INTO private.evidence_objects (tenant_id,evidence_kind,payload_sha256, \
           data_class,origin_class,visibility_class,reasoning_domain_id) \
           SELECT $1,'EVENT',sha256(convert_to($1::text,'UTF8')),'INTERNAL', \
             'DirectUserInput','TENANT_SHARED',reasoning_domain_id FROM d RETURNING evidence_id), \
         v AS (INSERT INTO private.events (event_id,event_kind,payload) \
           SELECT evidence_id,'USER_MESSAGE','{}'::jsonb FROM e) SELECT evidence_id FROM e",
    )
    .bind(tenant)
    .fetch_one(&mut **tx)
    .await
    .unwrap()
}

async fn subject(tx: &mut Transaction<'_, Postgres>, tenant: Uuid, kind: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO private.subjects (tenant_id,kind,display_name) \
        VALUES ($1,$2,$2) RETURNING subject_id",
    )
    .bind(tenant)
    .bind(kind)
    .fetch_one(&mut **tx)
    .await
    .unwrap()
}

async fn project(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    workspace: Uuid,
    title: &str,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO private.continuity_projects \
        (project_id,tenant_id,workspace_id,title) VALUES (uuidv7(),$1,$2,$3) RETURNING project_id",
    )
    .bind(tenant)
    .bind(workspace)
    .bind(title)
    .fetch_one(&mut **tx)
    .await
    .unwrap()
}

async fn serve(tx: &mut Transaction<'_, Postgres>, ids: [Uuid; 4]) {
    let [tenant, project, brand, evidence] = ids;
    sqlx::query(
        "INSERT INTO private.project_subject_relations \
        (tenant_id,relation_id,revision,src_id,dst_id,relation_kind,valid,decided_by, \
         factual_evidence_ids,authorization_evidence_id) \
        VALUES ($1,uuidv7(),1,$2,$3,'SERVES','{[2020-01-01,)}','rule:fixture@1','{}',$4)",
    )
    .bind(tenant)
    .bind(project)
    .bind(brand)
    .bind(evidence)
    .execute(&mut **tx)
    .await
    .unwrap();
}

async fn pin(tx: &mut Transaction<'_, Postgres>, ids: [Uuid; 3]) -> Uuid {
    let [tenant, workspace, project] = ids;
    let version = sqlx::query_scalar("INSERT INTO private.continuity_facet_versions \
        (tenant_id,workspace_id,project_id,facet_kind,facet_version,body,body_sha256,authored_by_principal_id) \
        VALUES ($1,$2,$3,'GOAL',1,'{}',sha256(convert_to('{}','UTF8')),uuidv7()) RETURNING facet_version_id")
        .bind(tenant).bind(workspace).bind(project).fetch_one(&mut **tx).await.unwrap();
    sqlx::query(
        "INSERT INTO private.continuity_facet_slots \
        (tenant_id,workspace_id,project_id,facet_kind,slot_version,current_version_id,slot_state) \
        VALUES ($1,$2,$3,'GOAL',1,$4,'CURRENT')",
    )
    .bind(tenant)
    .bind(workspace)
    .bind(project)
    .bind(version)
    .execute(&mut **tx)
    .await
    .unwrap();
    version
}

async fn owner_connection() -> PgConnection {
    let dsn = std::env::var("HUMAUX_TEST_PG_DSN").expect("fail: missing HUMAUX_TEST_PG_DSN");
    // dep: PostgreSQL(owner) — §79.2 fixture access never creates a raw shared pool.
    PgConnection::connect(&dsn).await.unwrap()
}

async fn fixture(connection: &mut PgConnection) -> Fixture<'_> {
    // dep: PostgreSQL(owner) — §79.2 fixture writes remain in one rolled-back transaction.
    let mut tx = connection.begin().await.unwrap();
    let tenant = sqlx::query_scalar(
        "INSERT INTO control.tenants (name,state) \
        VALUES ('e2e-fixture m14-4 rollup','ACTIVE') RETURNING tenant_id",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    sqlx::query("SELECT set_config('humaux.tenant_id',$1,true)")
        .bind(Uuid::to_string(&tenant))
        .execute(&mut *tx)
        .await
        .unwrap();
    let mut workspaces = Vec::new();
    for name in ["visible-a", "visible-b", "hidden"] {
        workspaces.push(
            sqlx::query_scalar(
                "INSERT INTO control.workspaces (tenant_id,name) \
            VALUES ($1,$2) RETURNING workspace_id",
            )
            .bind(tenant)
            .bind(name)
            .fetch_one(&mut *tx)
            .await
            .unwrap(),
        );
    }
    let brand = subject(&mut tx, tenant, "BRAND").await;
    let business = subject(&mut tx, tenant, "BUSINESS").await;
    let evidence = evidence(&mut tx, tenant).await;
    let a = project(&mut tx, tenant, workspaces[0], "visible-a").await;
    let b = project(&mut tx, tenant, workspaces[1], "visible-b").await;
    let hidden = project(&mut tx, tenant, workspaces[2], "hidden-secret-title").await;
    for id in [a, b, hidden] {
        serve(&mut tx, [tenant, id, brand, evidence]).await;
    }
    sqlx::query(
        "INSERT INTO private.subject_relations \
        (tenant_id,relation_id,revision,src_id,dst_id,relation_kind,valid,decided_by, \
         factual_evidence_ids,authorization_evidence_id) \
        VALUES ($1,uuidv7(),1,$2,$3,'OWNED_BY','{[2020-01-01,)}','rule:fixture@1','{}',$4)",
    )
    .bind(tenant)
    .bind(brand)
    .bind(business)
    .bind(evidence)
    .execute(&mut *tx)
    .await
    .unwrap();
    let version = pin(&mut tx, [tenant, workspaces[0], a]).await;
    let scope = AuthorizationScope::new(
        TenantId(tenant),
        PrincipalId(Uuid::now_v7()),
        None,
        BoundedSet::new(workspaces[..2].iter().copied().map(WorkspaceId)).unwrap(),
    );
    // dep: PostgreSQL(role_gateway) — §25.3.1 exercises the runtime doors without owner privileges.
    sqlx::query("SET LOCAL ROLE role_gateway")
        .execute(&mut *tx)
        .await
        .unwrap();
    Fixture {
        tx,
        scope,
        visible: [a, b],
        hidden,
        brand,
        business,
        version,
    }
}

#[tokio::test]
async fn g_m14_5_rollup_no_leak() {
    let mut connection = owner_connection().await;
    let mut fx = fixture(&mut connection).await;
    for target in [
        RollupTarget::Brand(SubjectId(fx.brand)),
        RollupTarget::Business(SubjectId(fx.business)),
    ] {
        let rollup = read_in_txn(&mut fx.tx, &fx.scope, target).await.unwrap();
        assert_eq!(rollup.visible_count, 2, "G-M14-5: count after visibility");
        assert_eq!(rollup.children.len(), 2, "G-M14-5: no hidden child");
        assert_eq!(
            rollup
                .children
                .iter()
                .map(|c| c.project_id.0)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(fx.visible),
            "G-M14-5: exact authorized id set"
        );
        assert_eq!(
            rollup
                .children
                .iter()
                .map(|c| c.title.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["visible-a", "visible-b"]),
            "G-M14-5: exact visible title set"
        );
        let a = rollup
            .children
            .iter()
            .find(|c| c.project_id.0 == fx.visible[0])
            .unwrap();
        assert_eq!(a.source_facet_count, 15);
        assert_eq!(a.facets.len(), 1);
        assert_eq!(a.facets[0].kind, ContinuityFacetKind::Goal);
        assert_eq!(a.facets[0].version_id, fx.version);
        assert_eq!(a.facets[0].version, 1);
        let b = rollup
            .children
            .iter()
            .find(|c| c.project_id.0 == fx.visible[1])
            .unwrap();
        assert_eq!(b.facets.len(), 0);
    }
    fx.tx.rollback().await.unwrap();
    println!("G-M14-5: pass");
}

#[tokio::test]
async fn project_scope_and_channel_door_are_exact() {
    let mut connection = owner_connection().await;
    let mut fx = fixture(&mut connection).await;
    set_channel_in_txn(
        &mut fx.tx,
        &fx.scope,
        ProjectId(fx.visible[0]),
        "alibaba_intl",
    )
    .await
    .unwrap();
    let rollup = read_in_txn(
        &mut fx.tx,
        &fx.scope,
        RollupTarget::Project(ProjectId(fx.visible[0])),
    )
    .await
    .unwrap();
    assert_eq!(rollup.visible_count, 1);
    assert_eq!(rollup.children.len(), 1);
    assert_eq!(rollup.children[0].project_id.0, fx.visible[0]);
    assert_eq!(
        rollup.children[0].channel_key.as_deref(),
        Some("alibaba_intl")
    );
    for id in [fx.hidden, Uuid::now_v7()] {
        assert_eq!(
            read_in_txn(&mut fx.tx, &fx.scope, RollupTarget::Project(ProjectId(id)))
                .await
                .unwrap_err(),
            ErrorCode::NotFound
        );
        assert_eq!(
            set_channel_in_txn(&mut fx.tx, &fx.scope, ProjectId(id), "1688")
                .await
                .unwrap_err(),
            ErrorCode::NotFound
        );
    }
    fx.tx.rollback().await.unwrap();
}

#[tokio::test]
async fn zero_visible_children_disclose_zero() {
    let mut connection = owner_connection().await;
    let mut fx = fixture(&mut connection).await;
    let empty = AuthorizationScope::new(
        fx.scope.tenant_id(),
        fx.scope.principal(),
        None,
        BoundedSet::new([]).unwrap(),
    );
    let result = read_in_txn(&mut fx.tx, &empty, RollupTarget::Brand(SubjectId(fx.brand)))
        .await
        .unwrap();
    assert_eq!(result.visible_count, 0);
    assert_eq!(result.children.len(), 0);
    fx.tx.rollback().await.unwrap();
}

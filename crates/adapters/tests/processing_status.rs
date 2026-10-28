//! G-M13-9: row absence, wording, exact detail and account admission.
//! Depends-on: crates=[humaux-adapters, humaux-application, humaux-domain, humaux-projection, humaux-testkit,
//!   postgres, serde_json, tokio, uuid]; services=[PostgreSQL(owner) w=[control.tenants,
//!   projection.stream_checkpoints, projection.stream_log], PostgreSQL(role_retrieval_worker)];
//!   env=[HUMAUX_TEST_PG_DSN, CI]; modules=[adapters::processing_status, adapters::postgres,
//!   adapters::tests::support::throwaway_db, application::processing_status, domain::identity, projection::stream]
//! Called-by: [cargo-test]
//! Invariants: [isolated real DB; missing DSN fails in CI; exact output sets]
//! Spec: §15.3; §23.1④; §79.2; §79.3; §80.1; ADR-0110 D-E

use humaux_adapters::{
    postgres::RetrievalWorkerDbPool,
    processing_status::{processing_status, processing_status_detailed},
};
use humaux_application::processing_status::{DetailedGate, ProcessingStatusQuery};
use humaux_domain::{
    error::ErrorCode,
    identity::{AuthorizationScope, BoundedSet, PrincipalId},
    ids::{TenantId, WorkspaceId},
};
use humaux_projection::stream::StreamKey;
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use serde_json::{json, to_value};
use std::time::{Duration, Instant};
use uuid::Uuid;
#[path = "support/throwaway_db.rs"]
#[allow(dead_code)]
mod throwaway_db;
struct Fixture;
impl DbIntegrationFixture for Fixture {
    type Handle = throwaway_db::ThrowawayDb;
    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        assert!(
            !(std::env::var_os("CI").is_some() && std::env::var_os("HUMAUX_TEST_PG_DSN").is_none()),
            "missing HUMAUX_TEST_PG_DSN"
        );
        throwaway_db::create("m13_status")
    }
}

fn seed(admin: &mut Client, tenant: Uuid, workspace: Uuid) {
    // §79.2: both families have distinct frontiers and DB-clock timestamps.
    admin
        .execute(
            "INSERT INTO control.tenants(tenant_id,name) VALUES ($1,'processing status fixture')",
            &[&tenant],
        )
        .unwrap();
    admin.execute("INSERT INTO projection.stream_checkpoints
        (tenant_id,scope_kind,scope_id,domain,projection_kind,projection_version,issued_highwater,projection_highwater,serving,updated_at)
        SELECT $1,'workspace',$2,domain,'memory','v1',n,1,true,ts::timestamptz FROM
        (VALUES ('reasoning',4,'2026-01-01T00:00:00Z'),('code',2,'2026-01-02T00:00:00Z')) v(domain,n,ts)", &[&tenant,&workspace]).unwrap();
    admin.execute("INSERT INTO projection.stream_log
        (tenant_id,scope_kind,scope_id,domain,projection_kind,projection_version,stream_seq,commit_seq,state,settled_at)
        SELECT $1,'workspace',$2,domain,'memory','v1',seq,seq,state,
        CASE WHEN state IN ('DONE','FAILED') THEN now() END FROM
        (VALUES ('reasoning',1,'DONE'),('reasoning',2,'FAILED'),('reasoning',3,'WAITING_KEY'),
        ('reasoning',4,'RETRY_WAIT'),('code',1,'DONE'),('code',2,'ISSUED')) v(domain,seq,state)", &[&tenant,&workspace]).unwrap();
}

#[test]
fn processing_status_g_m13_9() {
    run_db_fixture::<Fixture, _>("processing_status_g_m13_9", |db| {
        let dsn = db.dsn();
        // dep: PostgreSQL(owner) — isolated fixture seeding and permission controls
        let mut admin = Client::connect(&dsn, NoTls).unwrap();
        let (tenant, other, workspace, empty, denied) = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        seed(&mut admin, tenant, workspace);
        seed(&mut admin, other, empty);
        let auth = AuthorizationScope::new(
            TenantId(tenant),
            PrincipalId::new(),
            None,
            BoundedSet::new(vec![WorkspaceId(workspace), WorkspaceId(empty)]).unwrap(),
        );
        let query = ProcessingStatusQuery {
            authorization: &auth,
        };
        let key = |t, w, d| StreamKey::new(TenantId(t), "workspace", w, d, "memory", "v1");
        let keys = [
            key(tenant, workspace, "reasoning"),
            key(tenant, workspace, "code"),
            key(tenant, empty, "reasoning"),
        ];
        let rt = tokio::runtime::Runtime::new().unwrap();
        let sep = if dsn.contains('?') { '&' } else { '?' };
        // dep: PostgreSQL(role_retrieval_worker) — both production reader paths
        let pool = rt
            .block_on(RetrievalWorkerDbPool::connect(&format!(
                "{dsn}{sep}options=-c%20role%3Drole_retrieval_worker"
            )))
            .unwrap();
        rt.block_on(async {
            let mut gate = DetailedGate::new(Duration::from_secs(60)).unwrap();
            let now = Instant::now();
            let detail = processing_status_detailed(&pool, &query, &keys, &mut gate, now)
                .await
                .unwrap();
            let detail = to_value(detail).unwrap();
            assert_eq!(
                detail[0]["detailed"],
                json!({"expected":6,"done":2,"pending":3,"failed":1,"waiting_key":1,"retry_wait":1})
            );
            assert_eq!(detail[1]["detailed"], json!(null));
            assert_eq!(
                processing_status_detailed(
                    &pool,
                    &query,
                    &keys,
                    &mut gate,
                    now + Duration::from_secs(59)
                )
                .await
                .unwrap_err(),
                ErrorCode::RateLimited
            );
            assert_eq!(gate.admit(TenantId(other), now), Ok(()));
            assert_eq!(
                gate.admit(TenantId(tenant), now + Duration::from_secs(60)),
                Ok(())
            );
            assert_eq!(
                gate.admit(TenantId(tenant), now),
                Err(ErrorCode::RateLimited)
            );
        });
        // §79.2: summary must survive removal of every closure/stream-log permission.
        admin.batch_execute("REVOKE SELECT ON projection.stream_log FROM role_retrieval_worker, role_gateway;
            REVOKE EXECUTE ON FUNCTION projection.stream_point_ledger(uuid,text,uuid,text,text,text,text,uuid[]) FROM role_retrieval_worker").unwrap();
        rt.block_on(async {
            // dep: PostgreSQL(role_gateway) — caller-owned summary transaction (§6.2.3)
            let gateway = sqlx::Pool::<sqlx::Postgres>::connect(&format!("{dsn}{sep}options=-c%20role%3Drole_gateway")).await.unwrap();
            let mut txn = gateway.begin().await.unwrap();
            let rows = processing_status(&mut txn, &query, &keys).await.unwrap();
            assert_eq!(rows.len(), 2);
            let rows = to_value(rows).unwrap();
            assert_eq!(rows[1], json!({"workspace_id":empty,"projection":null,"reason":"no_checkpoint","behind_label":"not_yet_confirmed_processed"}), "row-less workspace must remain absent");
            assert_eq!(rows[0]["behind_label"], json!("not_yet_confirmed_processed"), "behind wording");
            assert_eq!(rows[0], json!({"workspace_id":workspace,"projection":{"mode":"frontier","issued":6,"settled_prefix":2,"behind":4,"serving":true,"observed_at":"2026-01-01T00:00:00Z"},"reason":null,"behind_label":"not_yet_confirmed_processed"}));
            for invalid in [key(other, empty, "reasoning"), key(tenant, denied, "reasoning"), keys[0].clone()] {
                let bad = [keys[0].clone(), invalid];
                assert_eq!(processing_status(&mut txn, &query, &bad).await.unwrap_err(), ErrorCode::DependencyUnavailable);
            }
            txn.rollback().await.unwrap();
        });
    });
}

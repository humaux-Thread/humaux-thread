//! §37 / ADR-0092 D-C: forgotten Evidence never reaches a provider or retries.
//! Depends-on: crates=[humaux-adapters, humaux-testkit, postgres, serde_json]; services=[PostgreSQL(owner) w=[ops.outbox, private.events, projection.stream_checkpoints, projection.stream_log]]; env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::postgres, private-worker::distill, private-worker::distill_lane]
//! Called-by: [cargo-test]
//! Invariants: [real dispatcher; exact provider count and durable job status]
//! Spec: Baseline §37; ADR-0092 D-C

#[path = "../tests/support/dispatch_fence.rs"]
mod dispatch_fence;
#[allow(dead_code)]
#[path = "../../../crates/adapters/tests/support/operation_receipt_fixture.rs"]
mod fixture;

#[test]
fn forgotten_evidence_finishes_without_provider_call() {
    use crate::{distill, distill_lane as lane};
    humaux_testkit::run_db_fixture::<fixture::Fixture, _>(
        "forgotten_evidence_finishes_without_provider_call",
        |mut h| {
            let dsn = std::env::var("HUMAUX_TEST_PG_DSN").expect("required PG");
            let mut fence = dispatch_fence::open(&mut h.admin, &dsn).unwrap();
            lane::seed_admission_lane(
                &mut h.admin,
                h.tenant_id,
                h.user_id,
                h.reasoning_domain_id,
                "stale-fixture",
            );
            let evidence = h.seed_workspace_visible_context_record().evidence_id;
            h.admin.execute("INSERT INTO private.events(event_id,event_kind,payload) VALUES($1,'USER_MESSAGE',$2)", &[&evidence,&serde_json::json!({"text":"forgotten fixture"})]).unwrap();
            let commit: i64 = h
                .admin
                .query_one("SELECT nextval('ops.commit_seq_seq')", &[])
                .unwrap()
                .get(0);
            h.admin.execute("INSERT INTO projection.stream_checkpoints(tenant_id,scope_kind,scope_id,domain,projection_kind,projection_version) VALUES($1,'workspace',$2,'private_memory','PRIVATE_MEMORY','v1')", &[&h.tenant_id,&h.workspace_id]).unwrap();
            h.admin.execute("INSERT INTO projection.stream_log(tenant_id,scope_kind,scope_id,domain,projection_kind,projection_version,stream_seq,commit_seq,state) VALUES($1,'workspace',$2,'private_memory','PRIVATE_MEMORY','v1',1,$3,'TOMBSTONED')", &[&h.tenant_id,&h.workspace_id,&commit]).unwrap();
            h.admin.execute("INSERT INTO ops.outbox(tenant_id,commit_seq,stream_seq,event_type,evidence_id) VALUES($1,$2,1,'EVIDENCE_ACCEPTED',$3)", &[&h.tenant_id,&commit,&evidence]).unwrap();
            let provider = lane::FakeProvider::new(vec![]);
            let pool =
                h.rt.block_on(humaux_adapters::postgres::PrivateWorkerDbPool::connect(
                    &lane::dsn_as_role(&dsn, "role_private_worker"),
                ))
                .unwrap();
            let report =
                h.rt.block_on(distill::dispatch_pass(
                    &pool,
                    &lane::routes(&provider),
                    lane::contribution_config(),
                    &lane::dispatch_config("stale-worker", 30.0),
                ))
                .unwrap();
            assert_eq!(provider.calls(), 0);
            assert_eq!(
                (report.claimed, report.completed, report.deferred),
                (1, 1, 0)
            );
            let states: Vec<String> = h
                .admin
                .query(
                    "SELECT status FROM ops.jobs WHERE tenant_id=$1 AND job_type='DERIVED_DISTILL'",
                    &[&h.tenant_id],
                )
                .unwrap()
                .iter()
                .map(|r| r.get(0))
                .collect();
            assert_eq!(states, vec!["DONE"], "stale job must finish, never RETRY");
            fence.batch_execute("ROLLBACK").unwrap();
        },
    );
}

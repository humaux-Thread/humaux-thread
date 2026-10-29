//! `adapters::tests::forget_race` — G-M19-4 commit-time deletion overlay checks.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-projection, humaux-testkit, serde_json, sqlx]; services=[PostgreSQL(owner) r=[ops.commit_seq_seq, private.memory_records] w=[ops.outbox, private.context_bindings, private.events, private.memory_evidence, private.memory_consolidation_inputs, private.memory_consolidation_runs, private.memory_rollup_sources, private.memory_rollups, private.processing_runs, projection.private_memory_points, projection.stream_checkpoints, projection.stream_log], PostgreSQL(role_private_worker), PostgreSQL(role_consolidation_worker), PostgreSQL(role_retrieval_worker), PostgreSQL(role_maintenance)]; env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::attribution_repo, adapters::consolidate_repo, adapters::distill_repo, adapters::postgres, adapters::private_projection_registry, adapters::tests::support::operation_receipt_fixture, domain::authority, domain::ids, domain::memory, humaux-testkit, projection::serving, testkit::disposable]
//! Called-by: [cargo-test]
//! Invariants: [load/select precedes deletion; commit checks run as runtime roles; any ticket and any source role can invalidate a derivation; exact durable output sets]
//! Spec: Baseline §37; §11.7; ADR-0092 D-C; ADR-0079 D-J; G-M19-4

use humaux_adapters::{
    attribution_repo::AttributionLadder,
    consolidate_repo as consolidate, distill_repo as distill,
    postgres::{ConsolidationDbPool, PrivateWorkerDbPool, RetrievalWorkerDbPool},
    private_projection_registry::{
        self as registry, PrivateMemoryPointRegistration, PrivateProjectionRegistryError,
        RegistrationOutcome,
    },
};
use humaux_domain::{
    authority::{AuthorityClass, MemoryId},
    ids::TenantId,
    memory::MemoryType,
};
use humaux_projection::serving::StreamFamily;
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use sqlx::types::Uuid;
use std::collections::BTreeSet;

#[allow(dead_code)]
#[path = "support/operation_receipt_fixture.rs"]
mod operation_receipt_fixture;
use operation_receipt_fixture::{DOMAIN, Handle, PROJECTION_KIND, PROJECTION_VERSION};

struct Fixture;
struct World {
    h: Handle,
    source: Uuid,
    memory: Uuid,
    control: Uuid,
}
impl DbIntegrationFixture for Fixture {
    type Handle = World;
    fn isolate() -> Result<World, DbFixtureSkipReason> {
        let mut h = operation_receipt_fixture::Fixture::isolate()?;
        humaux_testkit::disposable::require_disposable(&mut h.admin).expect("disposable PG");
        let control = h.seed_workspace_visible_context_record();
        let record = h.seed_workspace_visible_context_record();
        h.admin.execute("INSERT INTO private.events(event_id,event_kind,payload) VALUES($1,'USER_MESSAGE','{}')", &[&record.evidence_id]).unwrap();
        // §37 common dependency: the PRIMARY stays live; a SUPPORTING source is forgotten.
        h.admin
            .execute(
                "UPDATE private.memory_evidence SET role='SUPPORTING' WHERE memory_id=$1",
                &[&record.memory_id],
            )
            .unwrap();
        h.admin.execute("INSERT INTO private.memory_evidence(memory_id,evidence_id,role,grounding_mode) VALUES($1,$2,'PRIMARY','SNAPSHOT')", &[&record.memory_id,&control.evidence_id]).unwrap();
        h.admin
            .execute(
                "DELETE FROM private.context_bindings WHERE tenant_id=$1",
                &[&h.tenant_id],
            )
            .unwrap();
        h.admin.execute("INSERT INTO projection.stream_checkpoints(tenant_id,scope_kind,scope_id,domain,projection_kind,projection_version) VALUES($1,'workspace',$2,$3,$4,$5)", &[&h.tenant_id,&h.workspace_id,&DOMAIN,&PROJECTION_KIND,&PROJECTION_VERSION]).unwrap();
        for (seq, event) in [(1_i64, "EVIDENCE_ACCEPTED"), (2, "MEMORY_LIFECYCLE")] {
            let commit: i64 = h
                .admin
                .query_one("SELECT nextval('ops.commit_seq_seq')", &[])
                .unwrap()
                .get(0);
            h.admin.execute("INSERT INTO projection.stream_log(tenant_id,scope_kind,scope_id,domain,projection_kind,projection_version,stream_seq,commit_seq,state,settled_at) VALUES($1,'workspace',$2,$3,$4,$5,$6,$7,'DONE',now())", &[&h.tenant_id,&h.workspace_id,&DOMAIN,&PROJECTION_KIND,&PROJECTION_VERSION,&seq,&commit]).unwrap();
            h.admin.execute("INSERT INTO ops.outbox(tenant_id,commit_seq,stream_seq,event_type,evidence_id,status) VALUES($1,$2,$3,$4,$5,'DONE')", &[&h.tenant_id,&commit,&seq,&event,&record.evidence_id]).unwrap();
        }
        Ok(World {
            h,
            source: record.evidence_id,
            memory: record.memory_id,
            control: control.memory_id,
        })
    }
}
impl Drop for World {
    fn drop(&mut self) {
        for sql in [
            "DELETE FROM projection.private_memory_points WHERE tenant_id=$1",
            "DELETE FROM private.processing_runs WHERE tenant_id=$1",
            "DELETE FROM private.memory_rollup_sources WHERE rollup_id IN (SELECT rollup_id FROM private.memory_rollups WHERE tenant_id=$1)",
            "DELETE FROM private.memory_rollups WHERE tenant_id=$1",
            "DELETE FROM private.memory_consolidation_inputs WHERE run_id IN (SELECT run_id FROM private.memory_consolidation_runs WHERE tenant_id=$1)",
            "DELETE FROM private.memory_consolidation_runs WHERE tenant_id=$1",
        ] {
            self.h
                .admin
                .execute(sql, &[&self.h.tenant_id])
                .expect("cleanup own fixture rows");
        }
    }
}
impl World {
    fn forget(&mut self) {
        let mut txn = self.h.admin.transaction().unwrap();
        txn.query_one(
            "SELECT set_config('humaux.tenant_id',$1,true)",
            &[&self.h.tenant_id.to_string()],
        )
        .unwrap();
        // dep: PostgreSQL(role_maintenance) — §37 tombstone runtime role
        txn.batch_execute("SET LOCAL ROLE role_maintenance")
            .unwrap();
        assert_eq!(txn.execute("UPDATE projection.stream_log SET state='TOMBSTONED' WHERE tenant_id=$1 AND stream_seq=2", &[&self.h.tenant_id]).unwrap(), 1);
        txn.commit().unwrap();
    }
    fn ids(&mut self, table: &str, column: &str) -> BTreeSet<Uuid> {
        self.h
            .admin
            .query(
                &format!("SELECT {column} FROM {table} WHERE tenant_id=$1"),
                &[&self.h.tenant_id],
            )
            .unwrap()
            .into_iter()
            .map(|r| r.get(0))
            .collect()
    }
}
fn role_dsn(role: &str) -> String {
    let dsn = std::env::var("HUMAUX_TEST_PG_DSN").expect("required PG input");
    let sep = if dsn.contains('?') { '&' } else { '?' };
    format!("{dsn}{sep}options=-c%20role%3D{role}")
}
fn seed_run(w: &mut World) -> Uuid {
    w.h.admin.query_one(
        "INSERT INTO private.processing_runs(tenant_id,evidence_id,processor_kind,processor_version,model_provider,model_id,model_revision,prompt_version,prompt_hash,parser_version,evidence_payload_sha256,source_hash,context_snapshot_seq) VALUES($1,$2,'distill','fixture','fixture','fixture','fixture','fixture','fixture','fixture',ARRAY[$3::bytea],$3,0) RETURNING processing_run_id",
        &[&w.h.tenant_id,&w.source,&vec![3_u8;32]],
    ).unwrap().get(0)
}
fn distill_publish(w: &mut World, forgotten: bool) {
    let run = seed_run(w);
    let pool =
        w.h.rt
            // dep: PostgreSQL(role_private_worker) — §37 commit role
            .block_on(PrivateWorkerDbPool::connect(&role_dsn(
                "role_private_worker",
            )))
            .unwrap();
    let mut read =
        w.h.rt
            .block_on(distill::begin_read_context(&pool, w.h.tenant_id))
            .unwrap();
    let evidence =
        w.h.rt
            .block_on(distill::load_evidence(
                &mut read,
                w.h.tenant_id,
                w.h.reasoning_domain_id,
                w.h.user_id,
                w.source,
            ))
            .unwrap()
            .expect("source loaded before forget");
    w.h.rt.block_on(read.commit()).unwrap();
    let mut txn =
        w.h.rt
            .block_on(distill::begin_write_context(
                &pool,
                w.h.tenant_id,
                w.h.user_id,
            ))
            .unwrap();
    let content = serde_json::json!({"key_claim":"late output"});
    let id =
        w.h.rt
            .block_on(distill::insert_memory(
                &mut txn,
                w.h.tenant_id,
                &evidence,
                &distill::NewMemory {
                    content: &content,
                    memory_type: MemoryType::Fact,
                    class: AuthorityClass::PrivateKnowledge,
                    confidence: 1.0,
                    note_kind: None,
                    note_id: None,
                    attribution: distill::AttributionSource::Primary,
                    producer: distill::MemoryProducer::Distill,
                },
                &AttributionLadder,
            ))
            .unwrap();
    if forgotten {
        w.forget();
    }
    let result = w.h.rt.block_on(distill::finish_processing_run(
        &mut txn, run, &[1; 32], 1, None,
    ));
    match result {
        Ok(n) => {
            assert_eq!(n, 1);
            w.h.rt
                .block_on(distill::commit_distill_write(txn, n, 1))
                .unwrap();
        }
        Err(sqlx::Error::Protocol(message)) => {
            assert_eq!(message, "STALE_INPUT");
            w.h.rt.block_on(txn.rollback()).unwrap();
        }
        Err(error) => panic!("unexpected failure: {error}"),
    }
    let expected = if forgotten {
        BTreeSet::from([w.memory, w.control])
    } else {
        BTreeSet::from([w.memory, w.control, id])
    };
    assert_eq!(
        w.ids("private.memory_records", "memory_id"),
        expected,
        "G-M19-4: a forgotten source must publish zero Memories"
    );
    let completed: i64 = w.h.admin.query_one("SELECT count(*) FROM private.processing_runs WHERE processing_run_id=$1 AND completed_at IS NOT NULL", &[&run]).unwrap().get(0);
    assert_eq!(completed, i64::from(!forgotten));
}
#[test]
fn g_m19_4_distill_live_source_commits() {
    run_db_fixture::<Fixture, _>("g_m19_4_distill_live_source_commits", |mut w| {
        distill_publish(&mut w, false)
    });
}
#[test]
fn g_m19_4_distill_forgotten_source_rolls_back() {
    run_db_fixture::<Fixture, _>("g_m19_4_distill_forgotten_source_rolls_back", |mut w| {
        distill_publish(&mut w, true)
    });
}
#[test]
fn g_m19_4_consolidation_rollup_rechecks_supporting_source() {
    run_db_fixture::<Fixture, _>(
        "g_m19_4_consolidation_rollup_rechecks_supporting_source",
        |mut w| {
            let pool =
                w.h.rt
                    // dep: PostgreSQL(role_consolidation_worker) — §37 commit role
                    .block_on(ConsolidationDbPool::connect(&role_dsn(
                        "role_consolidation_worker",
                    )))
                    .unwrap();
            let run =
                w.h.rt
                    .block_on(consolidate::create_run(
                        &pool,
                        w.h.tenant_id,
                        w.h.reasoning_domain_id,
                        Some(w.h.workspace_id),
                    ))
                    .unwrap();
            let inputs =
                w.h.rt
                    .block_on(consolidate::select_and_materialize_inputs(
                        &pool,
                        run,
                        w.h.tenant_id,
                        w.h.reasoning_domain_id,
                        Some(w.h.workspace_id),
                        10,
                    ))
                    .unwrap();
            assert_eq!(inputs.len(), 2);
            assert_eq!(
                inputs
                    .iter()
                    .map(|i| i.memory_id.into_inner().0)
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from([w.memory, w.control])
            );
            let sources: Vec<_> = inputs
                .iter()
                .map(|i| (i.memory_id, i.evidence_id))
                .collect();
            w.forget();
            let outcome =
                w.h.rt
                    .block_on(consolidate::publish_rollup(
                        &pool,
                        run,
                        w.h.tenant_id,
                        Some(w.h.workspace_id),
                        serde_json::json!({"rollup":"late"}),
                        AuthorityClass::PrivateKnowledge,
                        None,
                        &sources,
                        None,
                    ))
                    .unwrap();
            assert_eq!(outcome, consolidate::PublishOutcome::StaleInput);
            assert_eq!(
                w.ids("private.memory_rollups", "rollup_id"),
                BTreeSet::new()
            );
            let status: String =
                w.h.admin
                    .query_one(
                        "SELECT status FROM private.memory_consolidation_runs WHERE run_id=$1",
                        &[&run],
                    )
                    .unwrap()
                    .get(0);
            assert_eq!(status, "STALE_INPUT");
        },
    );
}
fn registration(w: &mut World, memory: Uuid) -> PrivateMemoryPointRegistration {
    let row = w.h.admin.query_one("SELECT (extract(epoch FROM updated_at)*1000000)::bigint,sha256(convert_to(content::text,'UTF8')) FROM private.memory_records WHERE memory_id=$1", &[&memory]).unwrap();
    PrivateMemoryPointRegistration::deterministic(
        StreamFamily::new(
            TenantId(w.h.tenant_id),
            "workspace",
            w.h.workspace_id,
            DOMAIN,
            "dense",
        ),
        "private-v1".into(),
        "fixture-embed".into(),
        MemoryId(memory),
        sqlx::types::time::OffsetDateTime::from_unix_timestamp_nanos(
            i128::from(row.get::<_, i64>(0)) * 1000,
        )
        .unwrap(),
        row.get(1),
    )
}
#[test]
fn g_m19_4_projection_publish_rechecks_supporting_source() {
    run_db_fixture::<Fixture, _>(
        "g_m19_4_projection_publish_rechecks_supporting_source",
        |mut w| {
            let memory = w.memory;
            let control_id = w.control;
            let late = registration(&mut w, memory);
            let control = registration(&mut w, control_id);
            let pool =
                w.h.rt
                    // dep: PostgreSQL(role_retrieval_worker) — §37 commit role
                    .block_on(RetrievalWorkerDbPool::connect(&role_dsn(
                        "role_retrieval_worker",
                    )))
                    .unwrap();
            w.forget();
            assert!(matches!(
                w.h.rt.block_on(registry::register_private_memory_point(
                    &pool, &w.h.auth, &late
                )),
                Err(PrivateProjectionRegistryError::SourceNotLive)
            ));
            assert_eq!(
                w.h.rt
                    .block_on(registry::register_private_memory_point(
                        &pool, &w.h.auth, &control
                    ))
                    .unwrap(),
                RegistrationOutcome::Inserted
            );
            assert_eq!(
                w.ids("projection.private_memory_points", "memory_id"),
                BTreeSet::from([w.control])
            );
        },
    );
}

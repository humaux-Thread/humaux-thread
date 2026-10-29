//! `adapters::tests::forget_race` — G-M19-4 commit-time deletion overlay checks.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-projection, humaux-testkit, postgres, serde_json, sqlx]; services=[PostgreSQL(owner) r=[ops.commit_seq_seq, private.memory_records] w=[control.confirm_tokens, control.deletion_requests, control.deletion_targets, ops.memory_lifecycle_events, ops.outbox, private.context_bindings, private.events, private.memory_evidence, private.memory_consolidation_inputs, private.memory_consolidation_runs, private.memory_rollup_sources, private.memory_rollups, private.processing_runs, projection.private_memory_points, projection.stream_checkpoints, projection.stream_log] x=[control.deletion_request_accept, control.deletion_request_freeze], PostgreSQL(role_gateway), PostgreSQL(role_private_worker), PostgreSQL(role_consolidation_worker), PostgreSQL(role_retrieval_worker), PostgreSQL(role_maintenance)]; env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::attribution_repo, adapters::consolidate_repo, adapters::distill_repo, adapters::postgres, adapters::private_projection_registry, adapters::tests::support::operation_receipt_fixture, domain::authority, domain::ids, domain::memory, humaux-testkit, projection::serving, testkit::disposable]
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
    concurrent: bool,
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
            concurrent: false,
        })
    }
}
impl Drop for World {
    fn drop(&mut self) {
        for sql in [
            "DELETE FROM control.deletion_targets WHERE tenant_id=$1",
            "DELETE FROM control.deletion_requests WHERE tenant_id=$1",
            "DELETE FROM control.confirm_tokens WHERE tenant_id=$1",
            "DELETE FROM ops.memory_lifecycle_events WHERE tenant_id=$1",
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
        if self.concurrent {
            return;
        }
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

fn race_registration(w: &mut World, reverse: bool) {
    let memory = w.memory;
    let input = registration(w, memory);
    // dep: PostgreSQL(role_retrieval_worker) — §37 actual registration API
    let pool =
        w.h.rt
            .block_on(RetrievalWorkerDbPool::connect(&role_dsn(
                "role_retrieval_worker",
            )))
            .unwrap();
    let result = w.h.rt.block_on(registry::register_private_memory_point(
        &pool, &w.h.auth, &input,
    ));
    if reverse {
        assert!(matches!(
            result,
            Err(PrivateProjectionRegistryError::SourceNotLive)
        ));
    } else {
        assert_eq!(result.unwrap(), RegistrationOutcome::Inserted);
    }
    assert_eq!(
        w.ids("projection.private_memory_points", "memory_id"),
        if reverse {
            BTreeSet::new()
        } else {
            BTreeSet::from([memory])
        }
    );
}

fn race_publish(w: &mut World, site: &str, reverse: bool) {
    if site == "distill" {
        return distill_publish(w, reverse);
    }
    if site == "registration" {
        return race_registration(w, reverse);
    }
    // dep: PostgreSQL(role_consolidation_worker) — §37 actual consolidation API
    let pool =
        w.h.rt
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
    let outcome =
        w.h.rt
            .block_on(consolidate::publish_rollup(
                &pool,
                run,
                w.h.tenant_id,
                Some(w.h.workspace_id),
                serde_json::json!({"rollup":"race"}),
                AuthorityClass::PrivateKnowledge,
                None,
                &sources,
                None,
            ))
            .unwrap();
    let expected = if reverse {
        assert_eq!(outcome, consolidate::PublishOutcome::StaleInput);
        BTreeSet::new()
    } else {
        let consolidate::PublishOutcome::Published { rollup_id } = outcome else {
            panic!("publish refused");
        };
        BTreeSet::from([rollup_id])
    };
    assert_eq!(w.ids("private.memory_rollups", "rollup_id"), expected);
    let status: String =
        w.h.admin
            .query_one(
                "SELECT status FROM private.memory_consolidation_runs WHERE run_id=$1",
                &[&run],
            )
            .unwrap()
            .get(0);
    assert_eq!(status, if reverse { "STALE_INPUT" } else { "SUCCEEDED" });
}

fn wait_blocked(client: &mut postgres::Client, blocker: i32) -> i32 {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        let rows = client
            .query(
                "SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))",
                &[&blocker],
            )
            .unwrap();
        if rows.len() == 1 {
            return rows[0].get(0);
        }
        assert!(
            std::time::Instant::now() < deadline,
            "G-M19-4: publisher/accept must wait on the fence"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn race_accept(w: &mut World) -> (postgres::Client, Uuid, Vec<u8>) {
    use operation_receipt_fixture::SyntheticCredentialScopes;
    let credential = w.h.seed_synthetic_service_credential(
        SyntheticCredentialScopes::RememberWrite,
        &Uuid::new_v4().to_string(),
        "race-only",
        &[7; 32],
    );
    // dep: PostgreSQL(role_gateway) — §37 deletion accept door
    let mut client = postgres::Client::connect(&role_dsn("role_gateway"), postgres::NoTls).unwrap();
    client
        .query_one(
            "SELECT set_config('humaux.tenant_id',$1,false),set_config('humaux.user_id',$2,false)",
            &[&w.h.tenant_id.to_string(), &w.h.user_id.to_string()],
        )
        .unwrap();
    let request: Uuid = client
        .query_one(
            "SELECT control.deletion_request_freeze($1,'EVIDENCE_CLOSURE',$2)",
            &[&w.h.tenant_id, &vec![w.source]],
        )
        .unwrap()
        .get(0);
    let intent: Vec<u8> = w.h.admin.query_one("SELECT sha256(convert_to('humaux.deletion.confirm.v1' || chr(10) || scope_kind,'UTF8') || '\\x00'::bytea || manifest_hash) FROM control.deletion_requests WHERE deletion_request_id=$1", &[&request]).unwrap().get(0);
    w.h.admin.execute("INSERT INTO control.confirm_tokens(tenant_id,user_id,operation,target_id,nonce_sha256,expires_at,workspace_id,request_sha256) VALUES($1,$2,'memory.forget',$3,$4,now()+interval '1 hour',$5,$4)", &[&w.h.tenant_id,&w.h.user_id,&request,&intent,&w.h.workspace_id]).unwrap();
    client
        .batch_execute("BEGIN; SET LOCAL statement_timeout='20s'")
        .unwrap();
    (client, credential.api_key_id, intent)
}

fn race(name: &'static str, site: &str) {
    for reverse in [false, true] {
        run_db_fixture::<Fixture, _>(name, |mut w| race_order(&mut w, site, reverse));
    }
}
fn race_order(w: &mut World, site: &str, reverse: bool) {
    w.concurrent = true;
    let (mut deletion, principal, intent) = race_accept(w);
    let request: Uuid =
        w.h.admin
            .query_one(
                "SELECT deletion_request_id FROM control.deletion_requests WHERE tenant_id=$1",
                &[&w.h.tenant_id],
            )
            .unwrap()
            .get(0);
    let workspace = w.h.workspace_id;
    let accept = move |c: &mut postgres::Client| {
        c.query_one(
            "SELECT control.deletion_request_accept($1,$2,'memory.forget',$2,$3,$4)",
            &[&request, &intent, &workspace, &principal],
        )
        .unwrap();
    };
    // dep: PostgreSQL(owner) — §37 lock-wait witness
    let mut observer = postgres::Client::connect(
        &std::env::var("HUMAUX_TEST_PG_DSN").unwrap(),
        postgres::NoTls,
    )
    .unwrap();
    let pid: i32 = observer
        .query_one("SELECT pg_backend_pid()", &[])
        .unwrap()
        .get(0);
    let deletion_pid: i32 = deletion
        .query_one("SELECT pg_backend_pid()", &[])
        .unwrap()
        .get(0);
    let key = i64::from(pid);
    let table = match site {
        "distill" => "private.processing_runs",
        "registration" => "projection.private_memory_points",
        _ => "private.memory_rollups",
    };
    let function = format!("{}.race_barrier_{pid}", "public");
    // §37: test-only output barrier; production serialization remains exclusively the stream row lock.
    w.h.admin.batch_execute(&format!("CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id = '{}'::uuid THEN PERFORM pg_advisory_xact_lock({key}); END IF; RETURN NEW; END $$; CREATE TRIGGER race_barrier_{pid} BEFORE INSERT OR UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION {function}()", w.h.tenant_id)).unwrap();
    if reverse {
        accept(&mut deletion);
    } else {
        observer
            .query_one("SELECT pg_advisory_lock($1)", &[&key])
            .unwrap();
    }
    std::thread::scope(|scope| {
        let coordinator = scope.spawn(|| {
            if reverse {
                wait_blocked(&mut observer, deletion_pid);
                deletion.batch_execute("COMMIT").unwrap();
            } else {
                let publisher_pid = wait_blocked(&mut observer, pid);
                let d = std::thread::spawn(move || {
                    accept(&mut deletion);
                    deletion.batch_execute("COMMIT").unwrap();
                });
                assert_eq!(wait_blocked(&mut observer, publisher_pid), deletion_pid);
                observer
                    .query_one("SELECT pg_advisory_unlock($1)", &[&key])
                    .unwrap();
                d.join().unwrap();
            }
        });
        race_publish(w, site, reverse);
        coordinator.join().unwrap();
    });
    w.h.admin
        .batch_execute(&format!(
            "DROP TRIGGER race_barrier_{pid} ON {table}; DROP FUNCTION {function}()"
        ))
        .unwrap();
    let tombstones: Vec<i64> = w.h.admin.query("SELECT stream_seq FROM projection.stream_log WHERE tenant_id=$1 AND state='TOMBSTONED' ORDER BY stream_seq", &[&w.h.tenant_id]).unwrap().iter().map(|r| r.get(0)).collect();
    assert_eq!(tombstones, vec![1, 2]);
}
#[test]
fn registration_fence() {
    race("registration_fence", "registration");
}
#[test]
fn consolidation_fence() {
    race("consolidation_fence", "consolidation");
}
#[test]
fn distill_fence() {
    race("distill_fence", "distill");
}

//! `adapters::tests::billing_slot_handover` — maintenance doors and transactional slot handover.
//! Depends-on: crates=[humaux-adapters, humaux-application, humaux-domain, humaux-testkit, postgres, serde_json, sqlx, time, tokio, uuid]; services=[PostgreSQL(owner) r=[control.subscriptions, control.subscription_events, control.entitlement_grants, control.entitlement_snapshots] w=[control.tenants, control.plans, control.plan_versions, control.subscriptions, control.entitlement_grants, control.billing_inbox, control.billing_payments], PostgreSQL(role_maintenance) x=[control.billing_slot_observe, control.billing_handover_subscription]]; env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::billing_processor_repo, adapters::entitlement_repo, adapters::postgres, adapters::tests::support::throwaway_db, application::billing, domain::billing, domain::error, domain::ids, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [isolated migrated database; owner readback; no provider calls]
//! Spec: Baseline §71.3; §76; §79.2
use humaux_adapters::{
    billing_processor_repo as repo, entitlement_repo, postgres::MaintenanceDbPool,
};
use humaux_application::billing::{
    ExternalCustomerRef, ExternalSubscriptionRef, ProviderSubscription, VerifiedBillingEvent,
};
use humaux_domain::{
    billing::{BillingProviderId, ObservedStatus, SubscriptionState},
    error::ErrorCode,
    ids::TenantId,
};
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
#[path = "support/throwaway_db.rs"]
#[allow(dead_code)]
mod throwaway_db;

struct Fixture;
struct Handle {
    db: throwaway_db::ThrowawayDb,
    owner: Client,
    pool: MaintenanceDbPool,
    rt: tokio::runtime::Runtime,
}
impl DbIntegrationFixture for Fixture {
    type Handle = Handle;
    fn isolate() -> Result<Handle, DbFixtureSkipReason> {
        let db = throwaway_db::create("m04_slot")?;
        let dsn = db.dsn();
        let setup = |e: String| DbFixtureSkipReason::IsolationSetupFailed(e);
        // dep: PostgreSQL(owner) — isolated fixture seed and readback.
        let owner = Client::connect(&dsn, NoTls).map_err(|e| setup(e.to_string()))?;
        let rt = tokio::runtime::Runtime::new().map_err(|e| setup(e.to_string()))?;
        let sep = if dsn.contains('?') { '&' } else { '?' };
        // dep: PostgreSQL(role_maintenance) — exercise the production door role.
        let pool = rt
            .block_on(MaintenanceDbPool::connect(&format!(
                "{dsn}{sep}options=-c%20role%3Drole_maintenance"
            )))
            .map_err(|e| setup(e.to_string()))?;
        Ok(Handle {
            db,
            owner,
            pool,
            rt,
        })
    }
}
fn seed(h: &mut Handle, state: &str) -> (TenantId, Uuid, Uuid, Uuid) {
    let tenant = Uuid::new_v4();
    let plan = Uuid::new_v4();
    let paid = Uuid::new_v4();
    let free = Uuid::new_v4();
    let old = Uuid::new_v4();
    h.owner
        .execute(
            "INSERT INTO control.tenants(tenant_id,name,state) VALUES ($1,'slot fixture','ACTIVE')",
            &[&tenant],
        )
        .unwrap();
    h.owner
        .execute(
            "INSERT INTO control.plans(plan_id,plan_key) VALUES ($1,$2)",
            &[&plan, &format!("slot_{}", tenant.simple())],
        )
        .unwrap();
    for (id, version, template) in [
        (paid, 1_i32, serde_json::json!({"feature.byok":true})),
        (free, 2, serde_json::json!({"feature.byok":false})),
    ] {
        h.owner.execute("INSERT INTO control.plan_versions(plan_version_id,plan_id,version,price_cents,billing_interval,entitlement_template,lease_block) VALUES ($1,$2,$3,0,'month',$4,1)", &[&id,&plan,&version,&template]).unwrap();
    }
    h.owner.execute("INSERT INTO control.subscriptions(subscription_id,tenant_id,provider,provider_subscription_ref,plan_version_id,state,current_period_start,current_period_end) VALUES ($1,$2,'creem','old',$3,$4,now()-interval '1 day',now()+interval '1 day')", &[&old,&tenant,&paid,&state]).unwrap();
    h.owner.execute("INSERT INTO control.entitlement_grants(tenant_id,source,source_ref_id,feature,value,valid_from,valid_until,priority) VALUES ($1,'PLAN',$2,'feature.byok','true',now()-interval '1 hour',now()+interval '1 day',0)", &[&tenant,&old]).unwrap();
    (TenantId(tenant), old, paid, free)
}
fn event() -> VerifiedBillingEvent {
    VerifiedBillingEvent {
        provider: BillingProviderId::Creem,
        event_id: "slot-event".into(),
        event_type: "subscription.active".into(),
        object_id: Some("new".into()),
    }
}
fn subscription() -> ProviderSubscription {
    let now = OffsetDateTime::now_utc();
    ProviderSubscription {
        reference: ExternalSubscriptionRef("new".into()),
        customer: ExternalCustomerRef("customer".into()),
        product: "paid".into(),
        status: ObservedStatus::Active,
        current_period_start: now - Duration::days(1),
        current_period_end: now + Duration::days(1),
    }
}
#[test]
fn atomic_handover_replay_and_rollback() {
    run_db_fixture::<Fixture, _>("atomic_handover_replay_and_rollback", |mut h| {
        let (tenant, old, paid, free) = seed(&mut h, "PAST_DUE");
        let new = subscription();
        let event = event();
        h.rt.block_on(async {
            let mut tx = repo::begin_processor(&h.pool).await.unwrap();
            assert_eq!(
                repo::acquire_billing_scope_in_txn(&mut tx, tenant, &event).await,
                Err(ErrorCode::Forbidden)
            );
            repo::scope_tenant(&mut tx, tenant).await.unwrap();
            repo::acquire_billing_scope_in_txn(&mut tx, tenant, &event)
                .await
                .unwrap();
            let observation = repo::prepare_slot_in_txn(
                &mut tx,
                tenant,
                &event,
                &new.reference,
                [new.current_period_start, new.current_period_end],
            )
            .await
            .unwrap();
            assert!(!observation.replay && !observation.reversed_b);
            assert_eq!(observation.old.unwrap().id, old);
            let error = repo::handover_subscription_in_txn(
                &mut tx,
                tenant,
                &event,
                old,
                SubscriptionState::PastDue,
                &new,
                Uuid::new_v4(),
                free,
            )
            .await;
            assert_eq!(error, Err(ErrorCode::InvalidInput));
            tx.rollback().await.unwrap();
        });
        let state: String = h
            .owner
            .query_one(
                "SELECT state FROM control.subscriptions WHERE subscription_id=$1",
                &[&old],
            )
            .unwrap()
            .get(0);
        assert_eq!(state, "PAST_DUE", "failed B must roll back A");
        let counts = h.owner.query_one("SELECT (SELECT count(*) FROM control.subscription_events),(SELECT count(*) FROM control.entitlement_grants WHERE revoked_at IS NOT NULL)", &[]).unwrap();
        assert_eq!((counts.get::<_, i64>(0), counts.get::<_, i64>(1)), (0, 0));
        // Force the projector's scope guard to fail after a successful handover, then roll back.
        h.rt.block_on(async {
            let mut tx = repo::begin_processor(&h.pool).await.unwrap();
            repo::scope_tenant(&mut tx, tenant).await.unwrap();
            assert_eq!(
                repo::handover_subscription_in_txn(
                    &mut tx,
                    tenant,
                    &event,
                    old,
                    SubscriptionState::PastDue,
                    &new,
                    paid,
                    free
                )
                .await,
                Ok(true)
            );
            sqlx::query("SELECT set_config('humaux.tenant_id',$1,true)")
                .bind(Uuid::new_v4().to_string())
                .execute(&mut *tx)
                .await
                .unwrap();
            assert_eq!(
                entitlement_repo::recompute_in_txn(&mut tx, tenant).await,
                Err(ErrorCode::Forbidden)
            );
            tx.rollback().await.unwrap();
        });
        let unchanged = h.owner.query_one("SELECT (SELECT state FROM control.subscriptions WHERE subscription_id=$1), (SELECT count(*) FROM control.subscription_events), (SELECT count(*) FROM control.entitlement_grants WHERE revoked_at IS NOT NULL), (SELECT count(*) FROM control.entitlement_snapshots)", &[&old]).unwrap();
        assert_eq!(
            (
                unchanged.get::<_, String>(0),
                unchanged.get::<_, i64>(1),
                unchanged.get::<_, i64>(2),
                unchanged.get::<_, i64>(3)
            ),
            ("PAST_DUE".into(), 0, 0, 0),
            "projector failure rolls back every effect"
        );
        h.rt.block_on(async {
            let mut tx = repo::begin_processor(&h.pool).await.unwrap();
            repo::scope_tenant(&mut tx, tenant).await.unwrap();
            assert_eq!(
                repo::handover_subscription_in_txn(
                    &mut tx,
                    tenant,
                    &event,
                    old,
                    SubscriptionState::PastDue,
                    &new,
                    paid,
                    free
                )
                .await,
                Ok(true)
            );
            assert_eq!(
                repo::handover_subscription_in_txn(
                    &mut tx,
                    tenant,
                    &event,
                    old,
                    SubscriptionState::PastDue,
                    &new,
                    paid,
                    free
                )
                .await,
                Ok(false)
            );
            entitlement_repo::recompute_in_txn(&mut tx, tenant)
                .await
                .unwrap();
            tx.commit().await.unwrap();
        });
        let snapshot: serde_json::Value = h
            .owner
            .query_one(
                "SELECT effective FROM control.entitlement_snapshots WHERE tenant_id=$1",
                &[&tenant.0],
            )
            .unwrap()
            .get(0);
        assert_eq!(snapshot, serde_json::json!({"feature.byok":true}));
        let counts = h.owner.query_one("SELECT (SELECT count(*) FROM control.subscriptions WHERE state='ACTIVE'),(SELECT count(*) FROM control.subscriptions WHERE state='CANCELED'),(SELECT count(*) FROM control.subscription_events WHERE source_event_id='slot-event'),(SELECT count(*) FROM control.subscription_events WHERE source_event_id IS NULL)", &[]).unwrap();
        assert_eq!(
            (
                counts.get::<_, i64>(0),
                counts.get::<_, i64>(1),
                counts.get::<_, i64>(2),
                counts.get::<_, i64>(3)
            ),
            (1, 1, 1, 1)
        );
        let _ = &h.db;
    });
}
#[test]
fn active_slot_is_not_retired() {
    run_db_fixture::<Fixture, _>("active_slot_is_not_retired", |mut h| {
        let (tenant, old, paid, free) = seed(&mut h, "ACTIVE");
        let new = subscription();
        h.rt.block_on(async {
            let mut tx = repo::begin_processor(&h.pool).await.unwrap();
            repo::scope_tenant(&mut tx, tenant).await.unwrap();
            assert_eq!(
                repo::apply_subscription_in_txn(
                    &mut tx,
                    tenant,
                    &event(),
                    &new,
                    paid,
                    free,
                    SubscriptionState::Active
                )
                .await,
                Err(ErrorCode::Conflict),
                "actual partial unique index maps to Conflict"
            );
            tx.rollback().await.unwrap();
            let mut tx = repo::begin_processor(&h.pool).await.unwrap();
            repo::scope_tenant(&mut tx, tenant).await.unwrap();
            assert_eq!(
                repo::handover_subscription_in_txn(
                    &mut tx,
                    tenant,
                    &event(),
                    old,
                    SubscriptionState::Active,
                    &new,
                    paid,
                    free
                )
                .await,
                Err(ErrorCode::Conflict)
            );
            tx.rollback().await.unwrap();
        });
        let state: String = h
            .owner
            .query_one(
                "SELECT state FROM control.subscriptions WHERE subscription_id=$1",
                &[&old],
            )
            .unwrap()
            .get(0);
        assert_eq!(state, "ACTIVE");
    });
}

#[test]
fn acl_scope_and_lasting_reversal() {
    run_db_fixture::<Fixture, _>("acl_scope_and_lasting_reversal", |mut h| {
        let (tenant, old, paid, free) = seed(&mut h, "PAST_DUE");
        let new = subscription();
        let sigs = [
            "control.billing_slot_observe(uuid,text,text,text,timestamptz,timestamptz)",
            "control.billing_handover_subscription(uuid,text,text,uuid,text,text,uuid,uuid,timestamptz,timestamptz,timestamptz)",
        ];
        for sig in sigs {
            let row = h.owner.query_one("SELECT pg_get_userbyid(p.proowner), p.prosecdef, 'search_path=pg_catalog'=ANY(p.proconfig), has_function_privilege('role_maintenance',p.oid,'EXECUTE'), has_function_privilege('role_gateway',p.oid,'EXECUTE'), EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') FROM pg_proc p WHERE p.oid=to_regprocedure($1)", &[&sig]).unwrap();
            assert_eq!(row.get::<_, String>(0), "role_migration_owner");
            assert!(row.get::<_, bool>(1) && row.get::<_, bool>(2) && row.get::<_, bool>(3));
            assert!(!row.get::<_, bool>(4) && !row.get::<_, bool>(5));
        }
        assert!(!h
            .owner
            .query_one(
                "SELECT has_table_privilege('role_maintenance','control.subscriptions','SELECT')",
                &[]
            )
            .unwrap()
            .get::<_, bool>(0));
        for scoped in [None, Some(Uuid::new_v4()), Some(Uuid::nil())] {
            for handover in [false, true] {
                h.rt.block_on(async {
                    let mut tx = repo::begin_processor(&h.pool).await.unwrap();
                    if let Some(scope) = scoped {
                        sqlx::query("SELECT set_config('humaux.tenant_id',$1,true)")
                            .bind(scope.to_string())
                            .execute(&mut *tx)
                            .await
                            .unwrap();
                    }
                    let result = if handover {
                        repo::handover_subscription_in_txn(
                            &mut tx,
                            tenant,
                            &event(),
                            old,
                            SubscriptionState::PastDue,
                            &new,
                            paid,
                            free,
                        )
                        .await
                        .map(|_| ())
                    } else {
                        repo::prepare_slot_in_txn(
                            &mut tx,
                            tenant,
                            &event(),
                            &new.reference,
                            [new.current_period_start, new.current_period_end],
                        )
                        .await
                        .map(|_| ())
                    };
                    assert_eq!(
                        result,
                        Err(ErrorCode::Forbidden),
                        "scope {scoped:?}, handover={handover}"
                    );
                    tx.rollback().await.unwrap();
                });
            }
        }
        let start = new.current_period_start.unix_timestamp();
        let end = new.current_period_end.unix_timestamp();
        // Use exact whole-second boundaries on both ledger and observation.
        let start_dt = OffsetDateTime::from_unix_timestamp(start).unwrap();
        let end_dt = OffsetDateTime::from_unix_timestamp(end).unwrap();
        h.owner.execute("INSERT INTO control.billing_inbox(provider,event_id,event_type,object_id,payload) VALUES ('creem','refund-event','refund.created','refund-1','{\"object\":{\"subscription\":{\"id\":\"new\"}}}')", &[]).unwrap();
        h.owner.execute("INSERT INTO control.billing_payments(tenant_id,provider,provider_txn_ref,kind,amount_cents,currency,period_start,period_end,occurred_at) VALUES ($1,'creem','refund-1','REFUND',1,'USD',to_timestamp($2::bigint),to_timestamp($3::bigint),now())", &[&tenant.0,&start,&end]).unwrap();
        h.rt.block_on(async {
            let mut tx = repo::begin_processor(&h.pool).await.unwrap();
            let result = repo::prepare_slot_in_txn(
                &mut tx,
                tenant,
                &event(),
                &new.reference,
                [start_dt, end_dt],
            )
            .await;
            assert!(matches!(result, Err(ErrorCode::Forbidden)));
            repo::scope_tenant(&mut tx, tenant).await.unwrap();
            let observation = repo::prepare_slot_in_txn(
                &mut tx,
                tenant,
                &event(),
                &new.reference,
                [start_dt, end_dt],
            )
            .await
            .unwrap();
            assert!(
                observation.reversed_b,
                "ledger reversal must be visible before handover"
            );
            let mut adjusted = new.clone();
            adjusted.current_period_start = start_dt;
            adjusted.current_period_end = end_dt;
            assert_eq!(
                repo::handover_subscription_in_txn(
                    &mut tx,
                    tenant,
                    &event(),
                    old,
                    SubscriptionState::PastDue,
                    &adjusted,
                    paid,
                    free
                )
                .await,
                Err(ErrorCode::Conflict)
            );
            tx.rollback().await.unwrap();
        });
        // Same ledger fixture must force the legacy apply door to CANCELED as well.
        h.rt.block_on(async {
            let mut tx = repo::begin_processor(&h.pool).await.unwrap();
            repo::scope_tenant(&mut tx, tenant).await.unwrap();
            let mut adjusted = new.clone();
            adjusted.current_period_start = start_dt;
            adjusted.current_period_end = end_dt;
            assert_eq!(
                repo::apply_subscription_in_txn(
                    &mut tx,
                    tenant,
                    &event(),
                    &adjusted,
                    paid,
                    free,
                    SubscriptionState::Active
                )
                .await,
                Ok(true)
            );
            tx.commit().await.unwrap();
        });
        let b_state: String = h.owner.query_one("SELECT state FROM control.subscriptions WHERE tenant_id=$1 AND provider_subscription_ref='new'", &[&tenant.0]).unwrap().get(0);
        assert_eq!(
            b_state, "CANCELED",
            "observe and apply must agree on reversal"
        );
        let state: String = h
            .owner
            .query_one(
                "SELECT state FROM control.subscriptions WHERE subscription_id=$1",
                &[&old],
            )
            .unwrap()
            .get(0);
        assert_eq!(state, "PAST_DUE");
    });
}

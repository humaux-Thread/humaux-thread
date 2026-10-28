//! `adapters::tests::billing_doors` — 0300 processor doors against real PostgreSQL (G-M04-24, G-M04-21).
//! Depends-on: crates=[humaux-adapters, humaux-application, humaux-domain, humaux-testkit, postgres, serde_json, sqlx, time, tokio, uuid];
//!   services=[PostgreSQL(owner) r=[control.entitlement_grants, control.subscriptions, control.subscription_events, control.entitlement_snapshots]
//!   w=[control.tenants, control.plans, control.plan_versions, control.billing_inbox, control.entitlement_grants] x=[control.billing_inbox_settle],
//!   PostgreSQL(role_maintenance) x=[control.billing_apply_subscription]]; env=[];
//!   modules=[adapters::billing_processor_repo, adapters::entitlement_repo, adapters::postgres, adapters::tests::support::throwaway_db,
//!   application::billing, domain::billing, domain::error, domain::ids, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [isolated migrated database; writes through maintenance doors; owner readback asserts full objects/counts]
//! Spec: Baseline §71.3; §76; §78.2; §79.2

use humaux_adapters::{
    billing_processor_repo as repo, entitlement_repo, postgres::MaintenanceDbPool,
};
use humaux_application::billing::{
    ExternalCustomerRef, ExternalSubscriptionRef, ProviderSubscription, VerifiedBillingEvent,
};
use humaux_domain::{
    billing::{BillingProviderId, InboxStatus, ObservedStatus, SubscriptionState as S},
    error::ErrorCode,
    ids::TenantId,
};
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[path = "support/throwaway_db.rs"]
#[allow(dead_code)]
mod throwaway_db;

struct Fixture;
struct Handle {
    rt: tokio::runtime::Runtime,
    pool: MaintenanceDbPool,
    admin: Client,
    _db: throwaway_db::ThrowawayDb,
}
impl DbIntegrationFixture for Fixture {
    type Handle = Handle;
    fn isolate() -> Result<Handle, DbFixtureSkipReason> {
        let setup = |e: String| DbFixtureSkipReason::IsolationSetupFailed(e);
        let db = throwaway_db::create("m04_doors")?;
        let dsn = db.dsn();
        // dep: PostgreSQL(owner) — isolated fixture seeding and independent readback
        let admin = Client::connect(&dsn, NoTls).map_err(|e| setup(e.to_string()))?;
        let rt = tokio::runtime::Runtime::new().map_err(|e| setup(e.to_string()))?;
        let sep = if dsn.contains('?') { '&' } else { '?' };
        // dep: PostgreSQL(role_maintenance) — production door identity (lead ruling 2026-10-29)
        let pool = rt
            .block_on(MaintenanceDbPool::connect(&format!(
                "{dsn}{sep}options=-c%20role%3Drole_maintenance"
            )))
            .map_err(|e| setup(e.to_string()))?;
        Ok(Handle {
            rt,
            pool,
            admin,
            _db: db,
        })
    }
}
fn seed(h: &mut Handle) -> (TenantId, Uuid, Uuid) {
    let tenant = h.admin.query_one("INSERT INTO control.tenants(name,state) VALUES ('door fixture','ACTIVE') RETURNING tenant_id", &[]).unwrap().get(0);
    let plan: Uuid = h
        .admin
        .query_one(
            "INSERT INTO control.plans(plan_key) VALUES ('door_fixture') RETURNING plan_id",
            &[],
        )
        .unwrap()
        .get(0);
    let mut versions = Vec::new();
    for (version, template) in [
        (
            1_i32,
            json!({"feature.byok": true, "feature.cloud_intelligence": true}),
        ),
        (2, json!({"feature.byok": false})),
    ] {
        versions.push(h.admin.query_one("INSERT INTO control.plan_versions(plan_id,version,price_cents,billing_interval,entitlement_template,lease_block) VALUES ($1,$2,0,'month',$3,1) RETURNING plan_version_id", &[&plan,&version,&template]).unwrap().get::<_,Uuid>(0));
    }
    assert_eq!(versions.len(), 2);
    (TenantId(tenant), versions[0], versions[1])
}
fn event(id: &str) -> VerifiedBillingEvent {
    VerifiedBillingEvent {
        provider: BillingProviderId::Creem,
        event_id: id.into(),
        event_type: "subscription.active".into(),
        object_id: Some("sub_fixture".into()),
    }
}
fn subscription() -> ProviderSubscription {
    let now = OffsetDateTime::now_utc();
    ProviderSubscription {
        reference: ExternalSubscriptionRef("sub_fixture".into()),
        customer: ExternalCustomerRef("cust_fixture".into()),
        product: "prod_fixture".into(),
        status: ObservedStatus::Active,
        current_period_start: now - Duration::days(1),
        current_period_end: now + Duration::days(30),
    }
}
fn apply(
    h: &Handle,
    tenant: TenantId,
    plans: (Uuid, Uuid),
    id: &str,
    state: S,
) -> Result<bool, ErrorCode> {
    h.rt.block_on(async {
        let mut txn = repo::begin_processor(&h.pool).await?;
        sqlx::query("SELECT set_config('humaux.tenant_id',$1,true)")
            .bind(tenant.0.to_string())
            .execute(&mut *txn)
            .await
            .unwrap();
        let applied = repo::apply_subscription_in_txn(
            &mut txn,
            tenant,
            &event(id),
            &subscription(),
            plans.0,
            plans.1,
            state,
        )
        .await?;
        entitlement_repo::recompute_in_txn(&mut txn, tenant).await?;
        txn.commit().await.unwrap();
        Ok(applied)
    })
}
/// G-M04-24: replay changes zero facts, grants or snapshot timestamps; counts are exact (§71.3).
#[test]
fn apply_is_idempotent() {
    run_db_fixture::<Fixture, _>("apply_is_idempotent", |mut h| {
        let (tenant, paid, free) = seed(&mut h);
        assert_eq!(
            apply(&h, tenant, (paid, free), "evt_once", S::Active),
            Ok(true)
        );
        let before: Value = h
            .admin
            .query_one("SELECT jsonb_build_object('subscription',to_jsonb(s),'snapshot',(SELECT to_jsonb(e) FROM control.entitlement_snapshots e)) FROM control.subscriptions s", &[])
            .unwrap()
            .get(0);
        assert_eq!(
            apply(&h, tenant, (paid, free), "evt_once", S::PastDue),
            Ok(false)
        );
        let counts = h.admin.query_one("SELECT (SELECT count(*) FROM control.subscriptions), (SELECT count(*) FROM control.subscription_events), (SELECT count(*) FROM control.entitlement_grants)", &[]).unwrap();
        assert_eq!(
            (
                counts.get::<_, i64>(0),
                counts.get::<_, i64>(1),
                counts.get::<_, i64>(2)
            ),
            (1, 1, 2)
        );
        let after: Value = h
            .admin
            .query_one("SELECT jsonb_build_object('subscription',to_jsonb(s),'snapshot',(SELECT to_jsonb(e) FROM control.entitlement_snapshots e)) FROM control.subscriptions s", &[])
            .unwrap()
            .get(0);
        assert_eq!(before, after);
    });
}
/// G-M04-21: PAST_DUE then recompute equals the entire Free template, immediately; active restores paid scope.
#[test]
fn past_due_recomputes_free() {
    run_db_fixture::<Fixture, _>("past_due_recomputes_free", |mut h| {
        let (tenant, paid, free) = seed(&mut h);
        h.admin.execute("INSERT INTO control.entitlement_grants(tenant_id,source,source_ref_id,feature,value,valid_from,valid_until,priority) VALUES ($1,'PLAN',$2,'feature.byok','true','2000-01-01T00:00:00Z','2001-01-01T00:00:00Z',0)", &[&tenant.0, &paid]).unwrap();
        let states = [
            S::Active,
            S::PastDue,
            S::Active,
            S::CancelAtPeriodEnd,
            S::Canceled,
        ];
        assert_eq!(states.len(), 5);
        for (n, state) in states.into_iter().enumerate() {
            assert_eq!(
                apply(&h, tenant, (paid, free), &format!("evt_{n}"), state),
                Ok(true)
            );
            let effective: Value = h
                .admin
                .query_one(
                    "SELECT effective FROM control.entitlement_snapshots WHERE tenant_id=$1",
                    &[&tenant.0],
                )
                .unwrap()
                .get(0);
            assert_eq!(
                effective,
                if matches!(state, S::Active | S::CancelAtPeriodEnd) {
                    json!({"feature.byok": true, "feature.cloud_intelligence": true})
                } else {
                    json!({"feature.byok": false})
                }
            );
            if state == S::PastDue {
                let unrevoked: i64 = h.admin.query_one("SELECT count(*) FROM control.entitlement_grants WHERE tenant_id=$1 AND source='PLAN' AND source_ref_id=$2 AND revoked_at IS NULL", &[&tenant.0, &paid]).unwrap().get(0);
                assert_eq!(unrevoked, 0);
            }
        }
        let count: i64 = h
            .admin
            .query_one("SELECT count(*) FROM control.subscription_events", &[])
            .unwrap()
            .get(0);
        assert_eq!(count, 5);
        let expired_until: i64 = h.admin.query_one("SELECT extract(epoch FROM valid_until)::bigint FROM control.entitlement_grants WHERE tenant_id=$1 AND valid_from = '2000-01-01T00:00:00Z'::timestamptz", &[&tenant.0]).unwrap().get(0);
        assert_eq!(expired_until, 978_307_200);
    });
}
/// §71.3: caller transactions retain claim locks; settlement refuses every terminal-to-terminal transition.
#[test]
fn claim_and_settle() {
    run_db_fixture::<Fixture, _>("claim_and_settle", |mut h| {
        h.admin.batch_execute("INSERT INTO control.billing_inbox(provider,event_id,event_type,payload,received_at) VALUES ('creem','first','subscription.active','{}',now()-interval '1 second'),('creem','second','subscription.active','{}',now())").unwrap();
        for (status, error) in [("FAILED", None), ("PROCESSED", Some("INVALID_INPUT"))] {
            let refusal = h
                .admin
                .query_one(
                    "SELECT control.billing_inbox_settle('creem','first',$1,$2)",
                    &[&status, &error],
                )
                .unwrap_err();
            assert_eq!(
                refusal.code().map(postgres::error::SqlState::code),
                Some("22023")
            );
        }
        h.rt.block_on(async {
            let mut first = repo::begin_processor(&h.pool).await.unwrap();
            let mut second = repo::begin_processor(&h.pool).await.unwrap();
            let rows = repo::inbox_claim(&mut first, 1).await.unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].0.event_id, "first");
            let other = repo::inbox_claim(&mut second, 2).await.unwrap();
            assert_eq!(other.len(), 1);
            assert_eq!(other[0].0.event_id, "second");
            assert_eq!(
                repo::inbox_settle(&mut first, &rows[0].0, InboxStatus::Processed, None).await,
                Ok(true)
            );
            first.commit().await.unwrap();
            assert_eq!(
                repo::inbox_settle(
                    &mut second,
                    &other[0].0,
                    InboxStatus::Failed,
                    Some(ErrorCode::InvalidInput)
                )
                .await,
                Ok(true)
            );
            second.commit().await.unwrap();
            let mut txn = repo::begin_processor(&h.pool).await.unwrap();
            assert_eq!(repo::inbox_claim(&mut txn, 2).await.unwrap().len(), 0);
            assert_eq!(
                repo::inbox_settle(
                    &mut txn,
                    &rows[0].0,
                    InboxStatus::Failed,
                    Some(ErrorCode::InvalidInput)
                )
                .await,
                Err(ErrorCode::InvalidInput)
            );
        });
    });
}
/// §6.2.2 / 0267: the apply door rejects a tenant argument different from its caller GUC.
#[test]
fn apply_refuses_mismatched_tenant_guc() {
    run_db_fixture::<Fixture, _>("apply_refuses_mismatched_tenant_guc", |mut h| {
        let (tenant, paid, free) = seed(&mut h);
        h.rt.block_on(async {
            let mut txn = repo::begin_processor(&h.pool).await.unwrap();
            sqlx::query("SELECT set_config('humaux.tenant_id',$1,true)")
                .bind(Uuid::new_v4().to_string()).execute(&mut *txn).await.unwrap();
            let refusal = sqlx::query("SELECT control.billing_apply_subscription($1,'creem','evt_scope','sub_fixture',$2,$3,'ACTIVE',now(),now()+interval '1 day',now())")
                .bind(tenant.0).bind(paid).bind(free).fetch_one(&mut *txn).await.unwrap_err();
            assert_eq!(refusal.as_database_error().and_then(|e| e.code()).as_deref(), Some("42501"));
            txn.rollback().await.unwrap();
        });
    });
}

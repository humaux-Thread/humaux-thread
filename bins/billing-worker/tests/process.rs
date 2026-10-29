//! `billing-worker::tests::process` — real PG + fake Creem processor gates (§71.3).
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-infra-egress, humaux-testkit, postgres, serde_json, tokio, uuid];
//!   services=[HTTP(loopback), PostgreSQL(owner) r=[control.subscriptions, control.subscription_events, control.entitlement_grants, control.entitlement_snapshots, control.billing_inbox] w=[control.tenants, control.plans, control.plan_versions, control.billing_inbox], PostgreSQL(role_maintenance)]; env=[];
//!   modules=[adapters::postgres, adapters::tests::support::throwaway_db, billing-worker::creem, billing-worker::process, billing-worker::fake_creem, billing-worker::mode, domain::egress, domain::error, domain::ids, infra-egress::http, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [real maintenance identity; complete snapshot and effect counts; no mock PostgreSQL]
//! Spec: Baseline §71.3; §76; §79.2
#[path = "../src/fake_creem.rs"]
mod fake_creem;
#[path = "../../../crates/adapters/tests/support/throwaway_db.rs"]
mod throwaway_db;
use humaux_adapters::postgres::MaintenanceDbPool;
use humaux_billing_worker::{
    creem::CreemClient,
    mode::BillingMode,
    process::{ProcessorConfig, process_one},
};
use humaux_domain::{egress::ProcessorId, error::ErrorCode, ids::TenantId};
use humaux_infra_egress::http::HttpEgressConfig;
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;
struct Fixture;
struct Handle {
    admin: Client,
    rt: tokio::runtime::Runtime,
    pool: MaintenanceDbPool,
    tenant: Uuid,
    config: ProcessorConfig,
    _db: throwaway_db::ThrowawayDb,
}
impl DbIntegrationFixture for Fixture {
    type Handle = Handle;
    fn isolate() -> Result<Handle, DbFixtureSkipReason> {
        let setup = |e: String| DbFixtureSkipReason::IsolationSetupFailed(e);
        let db = throwaway_db::create("m04_process")?;
        let dsn = db.dsn();
        // dep: PostgreSQL(owner) — isolated seeding and independent readback (§79.2).
        let mut admin = Client::connect(&dsn, NoTls).map_err(|e| setup(e.to_string()))?;
        let rt = tokio::runtime::Runtime::new().map_err(|e| setup(e.to_string()))?;
        let sep = if dsn.contains('?') { '&' } else { '?' };
        // dep: PostgreSQL(role_maintenance) — real scoped processor identity (§79.2).
        let pool = rt
            .block_on(MaintenanceDbPool::connect(&format!(
                "{dsn}{sep}options=-c%20role%3Drole_maintenance"
            )))
            .map_err(|e| setup(e.to_string()))?;
        let tenant = admin.query_one("INSERT INTO control.tenants(name,state) VALUES ('process fixture','ACTIVE') RETURNING tenant_id", &[]).unwrap().get(0);
        let plan: Uuid = admin
            .query_one(
                "INSERT INTO control.plans(plan_key) VALUES ('process_fixture') RETURNING plan_id",
                &[],
            )
            .unwrap()
            .get(0);
        let mut versions = Vec::new();
        for (n, template) in [(1_i32, paid()), (2, free())] {
            versions.push(admin.query_one("INSERT INTO control.plan_versions(plan_id,version,price_cents,billing_interval,entitlement_template,lease_block) VALUES ($1,$2,0,'month',$3,1) RETURNING plan_version_id", &[&plan,&n,&template]).unwrap().get::<_,Uuid>(0));
        }
        assert_eq!(versions.len(), 2);
        let config = ProcessorConfig {
            plans: [("prod_fixture".into(), versions[0])].into(),
            free_plan_version: versions[1],
        };
        Ok(Handle {
            admin,
            rt,
            pool,
            tenant,
            config,
            _db: db,
        })
    }
}
fn paid() -> Value {
    json!({"feature.byok":true,"feature.cloud_intelligence":true})
}
fn free() -> Value {
    json!({"feature.byok":false})
}
fn deliver(h: &mut Handle, id: &str, arrival: &str, tenant: Uuid) {
    let payload = json!({"id":id,"eventType":format!("subscription.{arrival}"),"created_at":1000,"object":{"id":"sub_fixture","status":arrival,"product":"prod_fixture","metadata":{"tenant_id":tenant},"current_period_start_date":"2020-01-01T00:00:00Z","current_period_end_date":"2099-01-01T00:00:00Z","last_transaction":{"id":"txn_fixture"}}});
    // dep: PostgreSQL(owner) — authenticated ingress; sparse payment IDs must process before M04-11b money normalization (§71.3).
    let stored = h.admin.execute("INSERT INTO control.billing_inbox(provider,event_id,event_type,object_id,payload) VALUES ('creem',$1,$2,'sub_fixture',$3) ON CONFLICT DO NOTHING", &[&id,&payload["eventType"].as_str().unwrap(),&payload]).unwrap();
    assert_eq!(stored, 1);
}
fn process(h: &Handle, current: &str) -> bool {
    process_with(h, current, "prod_fixture", false).unwrap()
}
fn process_with(
    h: &Handle,
    current: &str,
    product: &str,
    fail_once: bool,
) -> Result<bool, ErrorCode> {
    h.rt.block_on(async {
        let subscription = json!({"id":"sub_fixture","customer":"cust_fixture","product":{"id":product},"status":current,"current_period_start_date":"2020-01-01T00:00:00Z","current_period_end_date":"2099-01-01T00:00:00Z"});
        // dep: HTTP(loopback) — merged Creem-shaped server; no external call (§79.4).
        let (base, server) = if fail_once {
            fake_creem::start_with_failure(subscription, json!({}), true).await
        } else {
            fake_creem::start(subscription, json!({})).await
        };
        let secret = Box::leak(Uuid::new_v4().to_string().into_boxed_str());
        let provider = CreemClient::new(&base, &BillingMode::parse(Some("fake"), None).unwrap(), TenantId(h.tenant), ProcessorId(Uuid::new_v4()), HttpEgressConfig::default(), Arc::new(fake_creem::FixtureCredential(fake_creem::TEST_KEY)), Arc::new(fake_creem::FixtureCredential(secret))).unwrap();
        // §71.3: the signature contract remains the merged ingress boundary, not JSON reserialization.
        assert_eq!(fake_creem::sign(b"{}", secret.as_bytes()).len(), 64);
        let result = process_one(&h.pool, &provider, &h.config).await;
        server.abort();
        result
    })
}
/// §71.3: an unordered body cannot replace the fetched product's pinned plan.
#[test]
fn fetched_product_wins_over_body() {
    run_db_fixture::<Fixture, _>("fetched_product_wins_over_body", |mut h| {
        let tenant = h.tenant;
        h.config
            .plans
            .insert("prod_fetched".into(), h.config.free_plan_version);
        deliver(&mut h, "stale_product", "active", tenant);
        assert_eq!(process_with(&h, "active", "prod_fetched", false), Ok(true));
        let rows = h
            .admin
            .query("SELECT plan_version_id FROM control.subscriptions", &[])
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get::<_, Uuid>(0), h.config.plans["prod_fetched"]);
        assert_eq!(snapshot(&mut h), free());
    });
}
/// §71.3: a provider outage cannot consume an acknowledged webhook; invalid answers are terminal.
#[test]
fn transient_fetch_retries_received() {
    run_db_fixture::<Fixture, _>("transient_fetch_retries_received", |mut h| {
        let tenant = h.tenant;
        deliver(&mut h, "retry_fetch", "active", tenant);
        let before = effects(&mut h);
        let result = process_with(&h, "active", "prod_fixture", true);
        let row = h
            .admin
            .query_one(
                "SELECT status,error_class FROM control.billing_inbox WHERE event_id='retry_fetch'",
                &[],
            )
            .unwrap();
        assert_eq!(
            (row.get::<_, String>(0), row.get::<_, Option<String>>(1)),
            ("RECEIVED".into(), None)
        );
        assert_eq!(result, Err(ErrorCode::DependencyUnavailable));
        assert_eq!(effects(&mut h), before);
        assert!(process(&h, "active"));
        assert_eq!(snapshot(&mut h), paid());
        deliver(&mut h, "invalid_fetch", "active", tenant);
        assert!(process(&h, "invalid-status"));
        let actual: Value = h.admin.query_one("SELECT jsonb_agg(jsonb_build_array(event_id,status,error_class) ORDER BY event_id) FROM control.billing_inbox", &[]).unwrap().get(0);
        assert_eq!(
            actual,
            json!([
                ["invalid_fetch", "FAILED", "INVALID_INPUT"],
                ["retry_fetch", "PROCESSED", null]
            ])
        );
        let count: i64 = h
            .admin
            .query_one("SELECT count(*) FROM control.subscription_events", &[])
            .unwrap()
            .get(0);
        assert_eq!(count, 1);
    });
}
fn snapshot(h: &mut Handle) -> Value {
    h.admin
        .query_one(
            "SELECT effective FROM control.entitlement_snapshots WHERE tenant_id=$1",
            &[&h.tenant],
        )
        .unwrap()
        .get(0)
}
fn effects(h: &mut Handle) -> Value {
    h.admin.query_one("SELECT jsonb_build_object('subscriptions',(SELECT jsonb_agg(to_jsonb(s)) FROM control.subscriptions s),'events',(SELECT jsonb_agg(to_jsonb(e)) FROM control.subscription_events e),'grants',(SELECT jsonb_agg(to_jsonb(g)) FROM control.entitlement_grants g),'snapshots',(SELECT jsonb_agg(to_jsonb(p)) FROM control.entitlement_snapshots p))", &[]).unwrap().get(0)
}
/// G-M04-10: replays have zero effects and reversed delivery order still follows the current fetch.
#[test]
fn replay_and_reordered_delivery() {
    run_db_fixture::<Fixture, _>("replay_and_reordered_delivery", |mut h| {
        let tenant = h.tenant;
        deliver(&mut h, "cancel_first", "canceled", tenant);
        assert!(process(&h, "active"));
        assert_eq!(snapshot(&mut h), paid());
        let before = effects(&mut h);
        // §71.3: persisted replay after processor restart, independently of the inbox PK.
        h.admin.execute("UPDATE control.billing_inbox SET status='RECEIVED',processed_at=NULL WHERE event_id='cancel_first'", &[]).unwrap();
        assert!(process(&h, "past_due"));
        assert_eq!(effects(&mut h), before);
        deliver(&mut h, "paid_later", "paid", tenant);
        assert!(process(&h, "canceled"));
        assert_eq!(snapshot(&mut h), free());
        let row = h.admin.query_one("SELECT state,(SELECT count(*) FROM control.subscriptions),(SELECT count(*) FROM control.subscription_events),(SELECT count(*) FROM control.billing_inbox WHERE status='PROCESSED') FROM control.subscriptions", &[]).unwrap();
        assert_eq!(
            (
                row.get::<_, String>(0),
                row.get::<_, i64>(1),
                row.get::<_, i64>(2),
                row.get::<_, i64>(3)
            ),
            ("CANCELED".into(), 1, 2, 2)
        );
        assert!(!process(&h, "active"));
    });
}
/// G-M04-21: paid-only key disappears immediately on failure; recovery and scheduled cancel retain paid scope.
#[test]
fn past_due_projects_entire_free_template() {
    run_db_fixture::<Fixture, _>("past_due_projects_entire_free_template", |mut h| {
        let tenant = h.tenant;
        for (n, status) in [
            "active",
            "past_due",
            "active",
            "scheduled_cancel",
            "unpaid",
            "expired",
        ]
        .into_iter()
        .enumerate()
        {
            deliver(&mut h, &format!("evt_{n}"), "active", tenant);
            assert!(process(&h, status));
            assert_eq!(
                snapshot(&mut h),
                if matches!(status, "active" | "scheduled_cancel") {
                    paid()
                } else {
                    free()
                }
            );
        }
        let before = effects(&mut h);
        deliver(&mut h, "unknown_tenant", "active", Uuid::new_v4());
        assert!(process(&h, "active"));
        assert_eq!(effects(&mut h), before);
        let rows = h
            .admin
            .query(
                "SELECT event_id,status,error_class FROM control.billing_inbox ORDER BY event_id",
                &[],
            )
            .unwrap();
        let actual: Vec<(String, String, Option<String>)> = rows
            .iter()
            .map(|r| (r.get(0), r.get(1), r.get(2)))
            .collect();
        let mut expected: Vec<_> = (0..6)
            .map(|n| (format!("evt_{n}"), "PROCESSED".into(), None))
            .collect();
        expected.push((
            "unknown_tenant".into(),
            "FAILED".into(),
            Some("NOT_FOUND".into()),
        ));
        assert_eq!(actual, expected);
        let count: i64 = h
            .admin
            .query_one("SELECT count(*) FROM control.subscription_events", &[])
            .unwrap()
            .get(0);
        assert_eq!(count, 6);
    });
}

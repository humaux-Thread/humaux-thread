//! `billing-worker::tests::process` — real PG + fake Creem processor gates (§71.3).
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-infra-egress, humaux-testkit, postgres, serde_json, tokio, uuid];
//!   services=[HTTP(loopback), PostgreSQL(owner) r=[control.subscriptions, control.subscription_events, control.entitlement_grants, control.entitlement_snapshots, control.billing_inbox, control.billing_payments] w=[control.tenants, control.plans, control.plan_versions, control.billing_inbox, control.entitlement_grants], PostgreSQL(role_maintenance)]; env=[];
//!   modules=[adapters::postgres, adapters::entitlement_repo, adapters::tests::support::throwaway_db, billing-worker::creem, billing-worker::process, billing-worker::fake_creem, billing-worker::mode, domain::egress, domain::error, domain::ids, infra-egress::http, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [real maintenance identity; complete snapshot and effect counts; no mock PostgreSQL]
//! Spec: Baseline §71.3; §76; §79.2
#[path = "../src/fake_creem.rs"]
mod fake_creem;
#[path = "../../../crates/adapters/tests/support/throwaway_db.rs"]
mod throwaway_db;
use humaux_adapters::{entitlement_repo, postgres::MaintenanceDbPool};
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
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::sync::Notify;
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
    let payload = json!({"id":id,"eventType":format!("subscription.{arrival}"),"created_at":1000,"object":{"id":"sub_fixture","status":arrival,"product":"prod_fixture","metadata":{"tenant_id":tenant},"current_period_start_date":"2020-01-01T00:00:00Z","current_period_end_date":"2099-01-01T00:00:00Z","last_transaction":{"id":"txn_fixture","amount":500,"amount_paid":500,"currency":"USD","period_start":1577836800000_i64,"period_end":4070908800000_i64}}});
    // dep: PostgreSQL(owner) — authenticated ingress with provider payment facts (§71.3).
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
    process_fetched(
        h,
        fetched_subscription(current, product),
        fail_once.then_some(503),
    )
}
fn process_fetched(
    h: &Handle,
    subscription: Value,
    failure_status: Option<u16>,
) -> Result<bool, ErrorCode> {
    h.rt.block_on(async {
        // dep: HTTP(loopback) — merged Creem-shaped server; no external call (§79.4).
        let (base, server) =
            fake_creem::start_with_failure(subscription, json!({}), failure_status).await;
        let secret = Box::leak(Uuid::new_v4().to_string().into_boxed_str());
        let provider = CreemClient::new(
            &base,
            &BillingMode::parse(Some("fake"), None).unwrap(),
            TenantId(h.tenant),
            ProcessorId(Uuid::new_v4()),
            HttpEgressConfig::default(),
            Arc::new(fake_creem::FixtureCredential(fake_creem::TEST_KEY)),
            Arc::new(fake_creem::FixtureCredential(secret)),
        )
        .unwrap();
        // §71.3: the signature contract remains the merged ingress boundary, not JSON reserialization.
        assert_eq!(fake_creem::sign(b"{}", secret.as_bytes()).len(), 64);
        let result = process_one(&h.pool, &provider, &h.config).await;
        server.abort();
        result
    })
}
fn fetched_subscription(current: &str, product: &str) -> Value {
    json!({"id":"sub_fixture","customer":"cust_fixture","product":{"id":product},"status":current,"current_period_start_date":"2020-01-01T00:00:00Z","current_period_end_date":"2099-01-01T00:00:00Z"})
}

/// G-M04-25: an older response committed last cannot overwrite a newer authoritative observation (§71.3).
#[test]
fn concurrent_subscription_observations_are_ordered() {
    run_db_fixture::<Fixture, _>(
        "concurrent_subscription_observations_are_ordered",
        |mut h| {
            let tenant = h.tenant;
            deliver(&mut h, "ordering_1", "past_due", tenant);
            deliver(&mut h, "ordering_2", "active", tenant);
            h.rt.block_on(async {
                let order = Arc::new(fake_creem::FetchOrder {
                    newer: fetched_subscription("active", "prod_fixture"),
                    fetches: AtomicUsize::new(0),
                    release_first: Notify::new(),
                });
                // dep: HTTP(loopback) — the first fetch is older, independent of arrival payload (§71.3).
                let (base, server) = fake_creem::start_controlled(
                    fetched_subscription("past_due", "prod_fixture"),
                    json!({}),
                    None,
                    Some(order.clone()),
                )
                .await;
                let provider = CreemClient::new(
                    &base,
                    &BillingMode::parse(Some("fake"), None).unwrap(),
                    TenantId(tenant),
                    ProcessorId(Uuid::new_v4()),
                    HttpEgressConfig::default(),
                    Arc::new(fake_creem::FixtureCredential(fake_creem::TEST_KEY)),
                    Arc::new(fake_creem::FixtureCredential(fake_creem::TEST_KEY)),
                )
                .unwrap();
                let newer_done = AtomicBool::new(false);
                let older = process_one(&h.pool, &provider, &h.config);
                let newer = async {
                    while order.fetches.load(Ordering::SeqCst) == 0 {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    let result = process_one(&h.pool, &provider, &h.config).await;
                    newer_done.store(true, Ordering::SeqCst);
                    result
                };
                let release = release_older(&mut h.admin, &order, &newer_done);
                let results = tokio::time::timeout(Duration::from_secs(20), async {
                    tokio::join!(older, newer, release)
                })
                .await;
                server.abort();
                let (older, newer, ()) = results.expect("G-M04-25: both workers must finish");
                assert_eq!((older, newer), (Ok(true), Ok(true)));
                assert_eq!(order.fetches.load(Ordering::SeqCst), 2);
            });
            let rows = h
                .admin
                .query("SELECT state FROM control.subscriptions", &[])
                .unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(
                rows[0].get::<_, String>(0),
                "ACTIVE",
                "G-M04-25: newer fetch must win"
            );
            assert_eq!(snapshot(&mut h), paid());
            let events: Value = h.admin.query_one("SELECT jsonb_agg(jsonb_build_array(source_event_id,to_state) ORDER BY source_event_id) FROM control.subscription_events", &[]).unwrap().get(0);
            assert_eq!(
                events,
                json!([["ordering_1", "PAST_DUE"], ["ordering_2", "ACTIVE"]])
            );
            let inbox: Value = h.admin.query_one("SELECT jsonb_agg(jsonb_build_array(event_id,status,error_class) ORDER BY event_id) FROM control.billing_inbox", &[]).unwrap().get(0);
            assert_eq!(
                inbox,
                json!([
                    ["ordering_1", "PROCESSED", null],
                    ["ordering_2", "PROCESSED", null]
                ])
            );
        },
    );
}
async fn release_older(
    admin: &mut Client,
    order: &fake_creem::FetchOrder,
    newer_done: &AtomicBool,
) {
    loop {
        // §71.3: a lock waiter permits serial progress; without it, force the newer worker to commit first.
        let waiters: i64 = tokio::task::block_in_place(|| {
            admin.query_one("SELECT count(*) FROM pg_catalog.pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())", &[]).unwrap().get(0)
        });
        if waiters == 1 || newer_done.load(Ordering::SeqCst) {
            order.release_first.notify_one();
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
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

fn money_payload(h: &Handle, id: &str, kind: &str, reference: &str) -> Value {
    let transaction = json!({"id":"txn_charge","transaction":"txn_charge","subscription":"sub_fixture","amount":1000,"amount_due":1210,"amount_paid":1210,"tax_amount":210,"currency":"USD","period_start":1577836800000_i64,"period_end":4070908800000_i64});
    let metadata = json!({"tenant_id":h.tenant});
    let reversal = matches!(kind, "refund.created" | "dispute.created");
    let mut payload = json!({"id":id,"eventType":kind,"created_at":1700000000000_i64,"object":{
        "id":reference,"subscription":{"id":"sub_fixture","metadata":metadata},
        "order":transaction,"last_transaction":transaction,"transaction":transaction,
        "refund_amount":123,"amount":211,"currency":"USD"}});
    if !reversal {
        payload["object"]["metadata"] = metadata;
    }
    payload
}
fn insert_payload(h: &mut Handle, payload: &Value) {
    assert_eq!(h.admin.execute("INSERT INTO control.billing_inbox(provider,event_id,event_type,object_id,payload) VALUES ('creem',$1,$2,$3,$4)", &[&payload["id"].as_str().unwrap(),&payload["eventType"].as_str().unwrap(),&payload["object"]["id"].as_str().unwrap(),payload]).unwrap(), 1);
}
fn payments(h: &mut Handle) -> Value {
    h.admin.query_one("SELECT coalesce(jsonb_agg(jsonb_build_array(provider_txn_ref,kind,amount_cents,currency) ORDER BY kind,provider_txn_ref),'[]'::jsonb) FROM control.billing_payments", &[]).unwrap().get(0)
}
/// G-M04-18: gross tax-inclusive webhook amount_paid is stored (§71.3, lead ruling 2026-10-29).
#[test]
fn money_source_and_charge_replay() {
    run_db_fixture::<Fixture, _>("money_source_and_charge_replay", |mut h| {
        let mut payload = money_payload(
            &h,
            "checkout_paid",
            "checkout.completed",
            "checkout_fixture",
        );
        payload["object"]["order"]
            .as_object_mut()
            .unwrap()
            .remove("period_start");
        payload["object"]["order"]
            .as_object_mut()
            .unwrap()
            .remove("period_end");
        insert_payload(&mut h, &payload);
        assert!(process(&h, "active"));
        assert_eq!(
            payments(&mut h),
            json!([["txn_charge", "CHARGE", 1210, "USD"]]),
            "G-M04-18: gross amount_paid=1210, not pre-tax amount=1000"
        );
        assert_eq!(snapshot(&mut h), paid());
        let before = effects(&mut h);
        h.admin.execute("UPDATE control.billing_inbox SET status='RECEIVED',processed_at=NULL WHERE event_id='checkout_paid'", &[]).unwrap();
        assert!(process(&h, "active"));
        assert_eq!(effects(&mut h), before);
        payload["id"] = json!("stale_checkout");
        payload["object"]["order"]["transaction"] = json!("txn_stale");
        payload["object"]["order"]["period_start"] = json!(1);
        payload["object"]["order"]["period_end"] = json!(2);
        insert_payload(&mut h, &payload);
        assert!(process(&h, "active"));
        let period: Value = h.admin.query_one("SELECT jsonb_build_array(extract(epoch from period_start)::bigint,extract(epoch from period_end)::bigint) FROM control.billing_payments WHERE kind='CHARGE' AND provider_txn_ref='txn_stale'", &[]).unwrap().get(0);
        assert_eq!(period, json!([1577836800_i64, 4070908800_i64]));
        let before = effects(&mut h);
        payload["id"] = json!("no_period");
        insert_payload(&mut h, &payload);
        let mut fetched = fetched_subscription("active", "prod_fixture");
        fetched["current_period_start_date"] = Value::Null;
        assert_eq!(process_fetched(&h, fetched, None), Ok(true));
        let failed: Value = h.admin.query_one("SELECT jsonb_build_array(status,error_class) FROM control.billing_inbox WHERE event_id='no_period'", &[]).unwrap().get(0);
        assert_eq!(failed, json!(["FAILED", "INVALID_INPUT"]));
        assert_eq!(effects(&mut h), before);
        let mut renewal = money_payload(&h, "renewal_paid", "subscription.paid", "sub_fixture");
        renewal["object"]["last_transaction"]["id"] = json!("txn_renewal");
        insert_payload(&mut h, &renewal);
        assert!(process(&h, "active"));
        assert_eq!(
            payments(&mut h),
            json!([
                ["txn_charge", "CHARGE", 1210, "USD"],
                ["txn_renewal", "CHARGE", 1210, "USD"],
                ["txn_stale", "CHARGE", 1210, "USD"]
            ])
        );
        let mut refund = money_payload(&h, "full_refund", "refund.created", "rf_full");
        refund["object"]["refund_amount"] = json!(1210);
        insert_payload(&mut h, &refund);
        assert!(process(&h, "active"));
        assert_eq!(
            payments(&mut h),
            json!([
                ["txn_charge", "CHARGE", 1210, "USD"],
                ["txn_renewal", "CHARGE", 1210, "USD"],
                ["txn_stale", "CHARGE", 1210, "USD"],
                ["rf_full", "REFUND", 1210, "USD"]
            ])
        );
    });
}
/// G-M04-19: each reversal has its own key and amount; partial refund downgrades the entire snapshot (§76).
#[test]
fn partial_refund_and_dispute_downgrade() {
    run_db_fixture::<Fixture, _>("partial_refund_and_dispute_downgrade", |mut h| {
        let tenant = h.tenant;
        deliver(&mut h, "initial", "active", tenant);
        assert!(process(&h, "active"));
        assert_eq!(snapshot(&mut h), paid());
        for (id, kind, reference) in [
            ("refund_1", "refund.created", "rf_1"),
            ("refund_2", "refund.created", "rf_2"),
            ("dispute_1", "dispute.created", "dp_1"),
        ] {
            let mut payload = money_payload(&h, id, kind, reference);
            payload["object"]["checkout"] = json!({"metadata":{"tenant_id":h.tenant}});
            payload["object"]
                .as_object_mut()
                .unwrap()
                .remove("subscription");
            insert_payload(&mut h, &payload);
            assert!(process(&h, "active"));
            assert_eq!(
                snapshot(&mut h),
                free(),
                "G-M04-19: reversal downgrades immediately"
            );
            let before = effects(&mut h);
            h.admin.execute("UPDATE control.billing_inbox SET status='RECEIVED',processed_at=NULL WHERE event_id=$1", &[&id]).unwrap();
            assert!(process(&h, "active"));
            assert_eq!(effects(&mut h), before);
        }
        assert_eq!(
            payments(&mut h),
            json!([
                ["dp_1", "CHARGEBACK", 211, "USD"],
                ["rf_1", "REFUND", 123, "USD"],
                ["rf_2", "REFUND", 123, "USD"]
            ]),
            "G-M04-19: exact partial refunds, no full-charge substitution"
        );
        let rows: Value = h.admin.query_one("SELECT jsonb_agg(jsonb_build_array(event_id,status,error_class) ORDER BY event_id) FROM control.billing_inbox", &[]).unwrap().get(0);
        assert_eq!(
            rows,
            json!([
                ["dispute_1", "PROCESSED", null],
                ["initial", "PROCESSED", null],
                ["refund_1", "PROCESSED", null],
                ["refund_2", "PROCESSED", null]
            ])
        );
    });
}
/// §71.3: malformed money fails terminally without partial grants or payments; historic reversals are ledger-only.
#[test]
fn invalid_money_and_historic_refund() {
    run_db_fixture::<Fixture, _>("invalid_money_and_historic_refund", |mut h| {
        let tenant = h.tenant;
        deliver(&mut h, "initial", "active", tenant);
        assert!(process(&h, "active"));
        let before = effects(&mut h);
        for (id, amount, currency) in [
            ("negative", json!(-1), "USD"),
            ("currency", json!(500), "EUR"),
            ("missing", Value::Null, "USD"),
        ] {
            let mut payload = money_payload(&h, id, "checkout.completed", id);
            payload["object"]["order"]["amount_paid"] = amount;
            payload["object"]["order"]["currency"] = json!(currency);
            insert_payload(&mut h, &payload);
            assert!(process(&h, "active"));
        }
        assert_eq!(effects(&mut h), before);
        assert_eq!(payments(&mut h), json!([]));
        let mut payload = money_payload(&h, "historic", "refund.created", "rf_old");
        payload["object"]["transaction"]["period_end"] = json!(1609459200000_i64);
        insert_payload(&mut h, &payload);
        assert!(process(&h, "active"));
        assert_eq!(effects(&mut h), before);
        assert_eq!(snapshot(&mut h), paid());
        assert_eq!(payments(&mut h), json!([["rf_old", "REFUND", 123, "USD"]]));
        let rows: Value = h.admin.query_one("SELECT jsonb_agg(jsonb_build_array(event_id,status,error_class) ORDER BY event_id) FROM control.billing_inbox", &[]).unwrap().get(0);
        assert_eq!(
            rows,
            json!([
                ["currency", "FAILED", "INVALID_INPUT"],
                ["historic", "PROCESSED", null],
                ["initial", "PROCESSED", null],
                ["missing", "FAILED", "INVALID_INPUT"],
                ["negative", "FAILED", "INVALID_INPUT"]
            ])
        );
    });
}
/// §71.3: conflicting nested tenants and foreign historical reversals have no money/grant effects.
#[test]
fn reversal_tenant_boundaries() {
    run_db_fixture::<Fixture, _>("reversal_tenant_boundaries", |mut h| {
        let tenant = h.tenant;
        deliver(&mut h, "initial", "active", tenant);
        assert!(process(&h, "active"));
        let other: Uuid = h.admin.query_one("INSERT INTO control.tenants(name,state) VALUES ('other fixture','ACTIVE') RETURNING tenant_id", &[]).unwrap().get(0);
        let before = effects(&mut h);
        for kind in ["refund.created", "dispute.created"] {
            for conflict in [true, false] {
                let id = format!("{kind}_{conflict}");
                let mut payload = money_payload(&h, &id, kind, &id);
                payload["object"]["checkout"] = json!({"metadata":{"tenant_id":other}});
                if !conflict {
                    payload["object"]["subscription"]["metadata"]["tenant_id"] = json!(other);
                    payload["object"]["transaction"]["period_start"] = json!(1);
                    payload["object"]["transaction"]["period_end"] = json!(2);
                }
                insert_payload(&mut h, &payload);
                assert!(process(&h, "active"));
                let row: Value = h.admin.query_one("SELECT jsonb_build_array(status,error_class) FROM control.billing_inbox WHERE event_id=$1", &[&id]).unwrap().get(0);
                let expected = if conflict {
                    "TENANT_BOUNDARY"
                } else {
                    "FORBIDDEN"
                };
                assert_eq!(row, json!(["FAILED", expected]));
                assert_eq!(effects(&mut h), before);
                assert_eq!(payments(&mut h), json!([]));
                assert_eq!(snapshot(&mut h), paid());
            }
        }
    });
}
/// G-M04-19 / §71.3: a reversal arriving before checkout must survive and project Free.
#[test]
fn reversal_before_subscription_delivery() {
    for (kind, reference, payment_kind, amount) in [
        ("refund.created", "rf_first", "REFUND", 123),
        ("dispute.created", "dp_first", "CHARGEBACK", 211),
    ] {
        run_db_fixture::<Fixture, _>("reversal_before_subscription_delivery", |mut h| {
            let tenant = h.tenant;
            let plan = h.config.plans["prod_fixture"];
            h.admin.execute("INSERT INTO control.entitlement_grants(tenant_id,source,source_ref_id,feature,value,valid_from,priority) SELECT $1,'PLAN',$2,e.key,e.value,clock_timestamp(),0 FROM jsonb_each($3::jsonb) e", &[&tenant,&plan,&paid()]).unwrap();
            let recompute = entitlement_repo::recompute(&h.pool, TenantId(tenant));
            h.rt.block_on(recompute).unwrap();
            assert_eq!(snapshot(&mut h), paid());
            let count: i64 = h.admin.query_one("SELECT count(*) FROM control.subscriptions WHERE provider_subscription_ref='sub_fixture'", &[]).unwrap().get(0);
            assert_eq!(count, 0);
            let payload = money_payload(&h, "reversal_first", kind, reference);
            insert_payload(&mut h, &payload);
            assert!(process(&h, "active"));
            let inbox: Value = h.admin.query_one("SELECT jsonb_build_array(status,error_class) FROM control.billing_inbox WHERE event_id='reversal_first'", &[]).unwrap().get(0);
            assert_eq!(
                inbox,
                json!(["PROCESSED", null]),
                "G-M04-19: unordered reversal must survive"
            );
            assert_eq!(
                payments(&mut h),
                json!([[reference, payment_kind, amount, "USD"]])
            );
            assert_eq!(snapshot(&mut h), free());
            let events: Value = h.admin.query_one("SELECT jsonb_agg(jsonb_build_array(source_event_id,to_state) ORDER BY source_event_id) FROM control.subscription_events", &[]).unwrap().get(0);
            assert_eq!(events, json!([["reversal_first", "CANCELED"]]));
            for (id, arrival) in [
                ("delayed_paid", "paid"),
                ("resent_paid", "paid"),
                ("updated", "update"),
            ] {
                deliver(&mut h, id, arrival, tenant);
                assert!(process(&h, "active"));
                assert_eq!(
                    snapshot(&mut h),
                    free(),
                    "recorded reversal survives {arrival}"
                );
                let state: String = h.admin.query_one("SELECT state FROM control.subscriptions WHERE provider_subscription_ref='sub_fixture'", &[]).unwrap().get(0);
                assert_eq!(state, "CANCELED");
            }
            assert_eq!(
                payments(&mut h),
                json!([
                    ["txn_fixture", "CHARGE", 500, "USD"],
                    [reference, payment_kind, amount, "USD"]
                ])
            );
        });
    }
}

/// G-M04-26: late cancellation and current-period reversal affect only their own subscription (§71.3).
#[test]
fn late_canceled_preserves_own_subscription_grants() {
    run_db_fixture::<Fixture, _>(
        "late_canceled_preserves_own_subscription_grants",
        |mut h| {
            let tenant = h.tenant;
            deliver(&mut h, "old_cancel", "canceled", tenant);
            assert!(process(&h, "canceled"));
            let mut new = fetched_subscription("active", "prod_fixture");
            new["id"] = json!("sub_new");
            deliver(&mut h, "new_active", "active", tenant);
            h.admin.execute("UPDATE control.billing_inbox SET object_id='sub_new',payload=jsonb_set(payload,'{object,id}',to_jsonb('sub_new'::text)) WHERE event_id='new_active'", &[]).unwrap();
            assert_eq!(process_fetched(&h, new, None), Ok(true));
            assert_eq!(snapshot(&mut h), paid());
            let grants: Value = h.admin.query_one("SELECT jsonb_agg(grant_id ORDER BY grant_id) FROM control.entitlement_grants WHERE source_ref_id=(SELECT subscription_id FROM control.subscriptions WHERE provider_subscription_ref='sub_new') AND revoked_at IS NULL AND valid_until>clock_timestamp()", &[]).unwrap().get(0);
            assert_eq!(grants.as_array().unwrap().len(), 2);
            for reversal in [false, true] {
                if reversal {
                    let payload = money_payload(&h, "old_refund", "refund.created", "rf_old");
                    insert_payload(&mut h, &payload);
                } else {
                    deliver(&mut h, "old_late", "canceled", tenant);
                }
                assert!(process(&h, "canceled"));
                let current: Value = h.admin.query_one("SELECT jsonb_agg(grant_id ORDER BY grant_id) FROM control.entitlement_grants WHERE source_ref_id=(SELECT subscription_id FROM control.subscriptions WHERE provider_subscription_ref='sub_new') AND revoked_at IS NULL AND valid_until>clock_timestamp()", &[]).unwrap().get(0);
                assert_eq!(current, grants, "G-M04-26: sub_B PLAN grants survive sub_A");
                assert_eq!(snapshot(&mut h), paid(), "G-M04-26: snapshot stays paid");
            }
            let states: Value = h.admin.query_one("SELECT jsonb_agg(jsonb_build_array(provider_subscription_ref,state) ORDER BY provider_subscription_ref) FROM control.subscriptions", &[]).unwrap().get(0);
            assert_eq!(
                states,
                json!([["sub_fixture", "CANCELED"], ["sub_new", "ACTIVE"]])
            );
        },
    );
}
/// G-M04-27: rate limits and DB-cancelled advisory waits retain the acknowledged inbox (§71.3).
#[test]
fn transient_rate_limit_and_lock_cancel_stay_received() {
    run_db_fixture::<Fixture, _>(
        "transient_rate_limit_and_lock_cancel_stay_received",
        |mut h| {
            let tenant = h.tenant;
            deliver(&mut h, "transient", "active", tenant);
            let before = effects(&mut h);
            let result = process_fetched(
                &h,
                fetched_subscription("active", "prod_fixture"),
                Some(429),
            );
            assert_received_without_effects(&mut h, result, &before);
            let dsn = h._db.dsn();
            h.pool =
                // dep: PostgreSQL(role_maintenance) — real lock cancellation, not a mocked error (§79.2).
                h.rt.block_on(MaintenanceDbPool::connect(&format!(
                    "{dsn}{}options=-c%20role%3Drole_maintenance%20-c%20lock_timeout%3D50ms",
                    if dsn.contains('?') { '&' } else { '?' }
                )))
                .unwrap();
            h.admin.batch_execute("BEGIN; SELECT pg_advisory_xact_lock(hashtextextended('billing-subscription:creem:sub_fixture',0))").unwrap();
            let result = process_with(&h, "active", "prod_fixture", false);
            h.admin.batch_execute("ROLLBACK").unwrap();
            assert_received_without_effects(&mut h, result, &before);
            assert!(process(&h, "active"));
            assert_eq!(snapshot(&mut h), paid());
        },
    );
}
fn assert_received_without_effects(
    h: &mut Handle,
    result: Result<bool, ErrorCode>,
    before: &Value,
) {
    let row: Value = h.admin.query_one("SELECT jsonb_build_array(status,error_class,(SELECT count(*) FROM control.subscription_events)) FROM control.billing_inbox WHERE event_id='transient'", &[]).unwrap().get(0);
    assert_eq!(
        row,
        json!(["RECEIVED", null, 0]),
        "G-M04-27: transient stays RECEIVED"
    );
    assert_eq!(result, Err(ErrorCode::DependencyUnavailable));
    assert_eq!(&effects(h), before);
}

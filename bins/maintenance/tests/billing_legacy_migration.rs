//! `maintenance::tests::billing_legacy_migration` — real migrator and legacy PLAN guard.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, postgres, serde_json, tokio, uuid]; services=[PostgreSQL(disposable), subprocess(humaux-maintenance)]; env=[HUMAUX_TEST_PG_DSN, HUMAUX_MAINTENANCE_PG_DSN]; modules=[maintenance::tests::support::throwaway]
//! Called-by: [cargo-test]
//! Invariants: [fresh CI database or isolated empty fixture only; no provider calls]
//! Spec: Baseline §71.3; §76; §79.2
#[path = "support/throwaway.rs"]
#[allow(dead_code)]
mod throwaway;

use humaux_adapters::{entitlement_repo, postgres::MaintenanceDbPool};
use humaux_domain::ids::TenantId;
use postgres::{Client, NoTls};
use serde_json::{Value, json};
use uuid::Uuid;

const M05: &str = "0305_billing_own_subscription";
const M06: &str = "0306_billing_legacy_guard";
const C05: &str = "7206490fd4fa6910";
const C06: &str = "85c84adcf2b5831e";

fn ledger(db: &mut Client, id: &str) -> Option<String> {
    db.query_opt(
        "SELECT checksum FROM ops.schema_migrations WHERE migration_id=$1",
        &[&id],
    )
    .unwrap()
    .map(|r| r.get(0))
}
fn migrate(dsn: &str, through: bool) {
    let args: &[&str] = if through {
        &["migrate", "--through", "0305"]
    } else {
        &["migrate"]
    };
    let result = throwaway::run(args, &[("HUMAUX_MIGRATOR_PG_DSN", dsn.to_owned())]);
    let stderr = String::from_utf8_lossy(&result.stderr);
    for line in stderr.lines().filter(|l| {
        l.starts_with("migrate: ")
            && (l.contains("0305") || l.contains("0306") || l.contains("pass ("))
    }) {
        eprintln!("{line}");
    }
    assert!(
        result.status.success(),
        "production migrator failed; inspect CI stderr"
    );
}
fn seed(db: &mut Client) -> (Uuid, Uuid, Vec<Uuid>) {
    let tenant = Uuid::new_v4();
    let plan = Uuid::new_v4();
    let paid_version = Uuid::new_v4();
    let free_version = Uuid::new_v4();
    let paid = json!({"feature.byok":true,"feature.cloud_intelligence":true});
    let free = json!({"feature.byok":false});
    db.execute("INSERT INTO control.tenants(tenant_id,name,state) VALUES ($1,'m04 migration fixture','ACTIVE')", &[&tenant]).unwrap();
    db.execute(
        "INSERT INTO control.plans(plan_id,plan_key) VALUES ($1,$2)",
        &[
            &plan,
            &format!("m04_{}", &tenant.simple().to_string()[..28]),
        ],
    )
    .unwrap();
    for (id, version, template) in [(paid_version, 1_i32, &paid), (free_version, 2_i32, &free)] {
        db.execute("INSERT INTO control.plan_versions(plan_version_id,plan_id,version,price_cents,billing_interval,entitlement_template,lease_block) VALUES ($1,$2,$3,0,'month',$4,1)", &[&id,&plan,&version,template]).unwrap();
    }
    for (reference, state) in [("m04_paid", "ACTIVE"), ("m04_old", "CANCELED")] {
        let reference = format!("{reference}_{tenant}");
        db.execute("INSERT INTO control.subscriptions(tenant_id,provider,provider_subscription_ref,plan_version_id,state,current_period_start,current_period_end) VALUES ($1,'creem',$2,$3,$4,now()-interval '1 day',now()+interval '1 day')", &[&tenant,&reference,&paid_version,&state]).unwrap();
    }
    let rows = db.query("INSERT INTO control.entitlement_grants(tenant_id,source,source_ref_id,feature,value,valid_from,valid_until,priority) SELECT $1,'PLAN',$2,key,value,now()-interval '1 hour',now()+interval '1 day',0 FROM jsonb_each($3) RETURNING grant_id", &[&tenant,&paid_version,&paid]).unwrap();
    (
        tenant,
        free_version,
        rows.iter().map(|r| r.get(0)).collect(),
    )
}
fn recompute(dsn: &str, tenant: Uuid) -> Value {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let role_dsn = format!(
        "{dsn}{}options=-c%20role%3Drole_maintenance",
        if dsn.contains('?') { '&' } else { '?' }
    );
    rt.block_on(async {
        let pool = MaintenanceDbPool::connect(&role_dsn).await.unwrap();
        entitlement_repo::recompute(&pool, TenantId(tenant))
            .await
            .unwrap();
    });
    let mut db = Client::connect(dsn, NoTls).unwrap();
    db.query_one(
        "SELECT effective FROM control.entitlement_snapshots WHERE tenant_id=$1",
        &[&tenant],
    )
    .unwrap()
    .get(0)
}
fn exercise(db: &mut Client, dsn: &str, tenant: Uuid, free: Uuid, mut ids: Vec<Uuid>) {
    let paid = json!({"feature.byok":true,"feature.cloud_intelligence":true});
    assert_eq!(recompute(dsn, tenant), paid);
    let reference = format!("m04_old_{tenant}");
    let mut tx = db.transaction().unwrap();
    tx.query_one(
        "SELECT set_config('humaux.tenant_id',$1,true)",
        &[&tenant.to_string()],
    )
    .unwrap();
    let version: Uuid = tx.query_one("SELECT plan_version_id FROM control.subscriptions WHERE tenant_id=$1 AND provider_subscription_ref=$2", &[&tenant,&reference]).unwrap().get(0);
    tx.query_one("SELECT control.billing_apply_subscription($1,'creem',$2,$3,$4,$5,'CANCELED',now()-interval '1 day',now()+interval '1 day',now())", &[&tenant,&format!("late_{tenant}"),&reference,&version,&free]).unwrap();
    tx.commit().unwrap();
    let mut after: Vec<Uuid> = db.query("SELECT grant_id FROM control.entitlement_grants WHERE tenant_id=$1 AND source='PLAN' AND revoked_at IS NULL", &[&tenant]).unwrap().iter().map(|r| r.get(0)).collect();
    ids.sort();
    after.sort();
    assert_eq!(after, ids, "paid legacy grant identities survive");
    assert_eq!(
        recompute(dsn, tenant),
        paid,
        "complete paid snapshot survives"
    );
}
#[test]
fn fresh_migrator_installed_guard() {
    let dsn = std::env::var("HUMAUX_TEST_PG_DSN").expect("CI disposable postgres DSN");
    let mut db = Client::connect(&dsn, NoTls).unwrap();
    let name: String = db
        .query_one("SELECT current_database()", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        name, "humaux_thread_ci",
        "fresh case is restricted to CI disposable database"
    );
    assert_eq!(ledger(&mut db, M05).as_deref(), Some(C05));
    assert_eq!(ledger(&mut db, M06).as_deref(), Some(C06));
    eprintln!("fresh ledger {M05}={C05} {M06}={C06}");
    let (tenant, free, ids) = seed(&mut db);
    exercise(&mut db, &dsn, tenant, free, ids);
}
#[test]
fn populated_0305_upgrade_uses_migrator() {
    let Some(mut db) = throwaway::empty("populated_0305_upgrade_uses_migrator", "m04_upgrade")
    else {
        return;
    };
    let dsn = throwaway::with_db(&db.owner_dsn, &db.name);
    migrate(&dsn, true);
    assert_eq!(ledger(db.client(), M05).as_deref(), Some(C05));
    assert_eq!(ledger(db.client(), M06), None);
    let (tenant, free, ids) = seed(db.client());
    assert_eq!(
        recompute(&dsn, tenant),
        json!({"feature.byok":true,"feature.cloud_intelligence":true})
    );
    migrate(&dsn, false);
    assert_eq!(ledger(db.client(), M05).as_deref(), Some(C05));
    assert_eq!(ledger(db.client(), M06).as_deref(), Some(C06));
    eprintln!("upgrade ledger {M05}={C05} {M06}={C06}");
    exercise(db.client(), &dsn, tenant, free, ids);
}

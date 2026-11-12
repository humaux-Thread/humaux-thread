//! `maintenance::tests::billing_slot_migration` — production migrator fresh and populated upgrade.
//! Depends-on: crates=[postgres, uuid]; services=[PostgreSQL(owner) r=[ops.schema_migrations, control.subscriptions] w=[control.tenants, control.plans, control.plan_versions, control.subscriptions], subprocess(humaux-maintenance)]; env=[HUMAUX_MIGRATOR_PG_DSN, HUMAUX_TEST_PG_DSN, HUMAUX_MAINTENANCE_PG_DSN]; modules=[maintenance::tests::support::throwaway]
//! Called-by: [cargo-test]
//! Invariants: [isolated disposable database, real migrator, no provider calls]
//! Spec: Baseline §71.3; §76; §79.2
#[path = "support/throwaway.rs"]
#[allow(dead_code)]
mod throwaway;

use uuid::Uuid;

fn migrate(dsn: &str, through: bool) {
    let args: &[&str] = if through {
        &["migrate", "--through", "0306"]
    } else {
        &["migrate"]
    };
    // dep: subprocess(humaux-maintenance) — real production migrator on a disposable database.
    let output = throwaway::run(args, &[("HUMAUX_MIGRATOR_PG_DSN", dsn.to_owned())]);
    assert!(
        output.status.success(),
        "migrator failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn ledger(db: &mut postgres::Client, id: &str) -> bool {
    db.query_one(
        "SELECT EXISTS(SELECT 1 FROM ops.schema_migrations WHERE migration_id=$1)",
        &[&id],
    )
    .unwrap()
    .get(0)
}

#[test]
fn fresh_and_populated_0306_upgrade() {
    for populated in [false, true] {
        let Some(mut db) = throwaway::empty("fresh_and_populated_0306_upgrade", "m04_slot") else {
            return;
        };
        let dsn = throwaway::with_db(&db.owner_dsn, &db.name);
        let tenant = Uuid::new_v4();
        let subscription = Uuid::new_v4();
        if populated {
            migrate(&dsn, true);
            assert!(ledger(db.client(), "0306_billing_legacy_guard"));
            assert!(!ledger(db.client(), "0307_billing_slot_handover"));
            let plan = Uuid::new_v4();
            let version = Uuid::new_v4();
            db.client().execute("INSERT INTO control.tenants(tenant_id,name,state) VALUES ($1,'slot upgrade','ACTIVE')", &[&tenant]).unwrap();
            db.client()
                .execute(
                    "INSERT INTO control.plans(plan_id,plan_key) VALUES ($1,$2)",
                    &[&plan, &format!("slot_{}", tenant.simple())],
                )
                .unwrap();
            db.client().execute("INSERT INTO control.plan_versions(plan_version_id,plan_id,version,price_cents,billing_interval,entitlement_template,lease_block) VALUES ($1,$2,1,0,'month','{}',1)", &[&version,&plan]).unwrap();
            db.client().execute("INSERT INTO control.subscriptions(subscription_id,tenant_id,provider,provider_subscription_ref,plan_version_id,state,current_period_start,current_period_end) VALUES ($1,$2,'creem','old',$3,'PAST_DUE',now()-interval '1 day',now()+interval '1 day')", &[&subscription,&tenant,&version]).unwrap();
        }
        migrate(&dsn, false);
        assert!(ledger(db.client(), "0307_billing_slot_handover"));
        let doors: i64 = db.client().query_one("SELECT count(*) FROM pg_proc WHERE oid IN (to_regprocedure('control.billing_slot_observe(uuid,text,text,text,timestamptz,timestamptz)'),to_regprocedure('control.billing_handover_subscription(uuid,text,text,uuid,text,text,uuid,uuid,timestamptz,timestamptz,timestamptz)'))", &[]).unwrap().get(0);
        assert_eq!(doors, 2);
        if populated {
            let state: String = db.client().query_one("SELECT state FROM control.subscriptions WHERE subscription_id=$1 AND tenant_id=$2", &[&subscription,&tenant]).unwrap().get(0);
            assert_eq!(state, "PAST_DUE", "upgrade retains existing subscription");
        }
    }
}

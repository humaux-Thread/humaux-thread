//! `adapters::tests::billing_repo` — the billing core of migration 0288 against a real PostgreSQL throwaway database:
//!   the webhook inbox stores an event once, the gateway holds INSERT on the inbox and nothing else (G-M04-13), the
//!   applied facts are append-only even for the owner, and a tenant holds one live subscription over a closed set of
//!   states.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, postgres, serde_json, tokio, uuid];
//!   services=[PostgreSQL(owner) r=[control.billing_customers] w=[control.billing_inbox, control.billing_payments,
//!   control.plan_versions, control.plans, control.subscription_events, control.subscriptions, control.tenants],
//!   PostgreSQL(role_gateway)]; env=[];
//!   modules=[adapters::billing_repo, adapters::postgres, adapters::tests::support::throwaway_db, domain::billing,
//!   domain::error, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [every test owns its throwaway database humaux_thread_m04_billing_<pid>_<n>, created and migrated by the
//!   fixture and dropped by its Drop even on panic; the inbox is written as role_gateway through billing_repo and read
//!   back as the database owner, so the assertions judge the stored rows and not the repository's reading of them; the
//!   denial checks run as a plain role_gateway client; no DSN or unreachable DB is a visible §79.2 skip]
//! Spec: Baseline §71.2; §71.3; §76; §78.2; §79.2

use humaux_adapters::billing_repo::{self, InboxInsert};
use humaux_adapters::postgres::RuntimeDbPool;
use humaux_domain::billing::BillingProviderId;
use humaux_domain::error::ErrorCode;
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::error::SqlState;
use postgres::{Client, NoTls};
use serde_json::{Value, json};
use uuid::Uuid;

#[path = "support/throwaway_db.rs"]
#[allow(dead_code)]
mod throwaway_db;
use throwaway_db::ThrowawayDb;

/// The five tables of migration 0288.
const BILLING_TABLES: [&str; 5] = [
    "control.billing_customers",
    "control.subscriptions",
    "control.subscription_events",
    "control.billing_payments",
    "control.billing_inbox",
];

/// The nine principals that must hold nothing on them but the gateway's INSERT on the inbox: the eight login roles,
/// the health reader, and PUBLIC.
const PRINCIPALS: [&str; 10] = [
    "role_gateway",
    "role_private_worker",
    "role_consolidation_worker",
    "role_public_worker",
    "role_retrieval_worker",
    "role_batch_issuer",
    "role_maintenance",
    "role_admin",
    "role_health_reader",
    "public",
];

const VERBS: [&str; 7] = [
    "SELECT",
    "INSERT",
    "UPDATE",
    "REFERENCES",
    "DELETE",
    "TRUNCATE",
    "TRIGGER",
];

const SUBSCRIPTION_SQL: &str = "INSERT INTO control.subscriptions \
    (tenant_id, provider, provider_subscription_ref, plan_version_id, state, current_period_start, current_period_end) \
    VALUES ($1, $2, $3, $4, $5, now(), now() + $6::integer * interval '1 day') RETURNING subscription_id";

const EVENT_SQL: &str = "INSERT INTO control.subscription_events \
    (tenant_id, subscription_id, from_state, to_state, observed_at) VALUES ($1, $2, NULL, 'ACTIVE', now())";

const PAYMENT_SQL: &str = "INSERT INTO control.billing_payments \
    (tenant_id, provider, provider_txn_ref, kind, amount_cents, currency, period_start, period_end, occurred_at) \
    VALUES ($1, 'creem', $2, $3, 500, 'USD', now(), now() + interval '30 days', now())";

fn dsn_as_role(admin_dsn: &str, role: &str) -> String {
    let sep = if admin_dsn.contains('?') { '&' } else { '?' };
    format!("{admin_dsn}{sep}options=-c%20role%3D{role}")
}

/// The SQLSTATE of a refused statement.
fn sqlstate(error: &postgres::Error) -> Option<&str> {
    error.code().map(SqlState::code)
}

/// The server's message of a refused statement (`postgres::Error` displays only "db error").
fn message(error: &postgres::Error) -> &str {
    error.as_db_error().map_or("", |db| db.message())
}

/// The constraint or index a refused statement violated.
fn violated(error: &postgres::Error) -> Option<&str> {
    error.as_db_error().and_then(|db| db.constraint())
}

/// Fields drop in order: the runtime and the pool close before the clients, and all before `_db` drops the database.
struct Handle {
    rt: tokio::runtime::Runtime,
    gateway: RuntimeDbPool,
    gateway_client: Client,
    admin: Client,
    plan_version: Uuid,
    _db: ThrowawayDb,
}

struct BillingFixture;

impl DbIntegrationFixture for BillingFixture {
    type Handle = Handle;

    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        let setup = |e: String| DbFixtureSkipReason::IsolationSetupFailed(e);
        let db = throwaway_db::create("m04_billing")?;
        let dsn = db.dsn();
        // dep: PostgreSQL(owner) — the fixture's owner connection to this test's throwaway database
        let mut admin = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        let rt = tokio::runtime::Runtime::new().map_err(|e| setup(e.to_string()))?;
        // dep: PostgreSQL(role_gateway) — the webhook route's role: inbox_insert runs through its typed pool
        let gateway = rt
            .block_on(RuntimeDbPool::connect(&dsn_as_role(&dsn, "role_gateway")))
            .map_err(|e| setup(e.to_string()))?;
        // dep: PostgreSQL(role_gateway) — a plain client in the same role, to show what the role cannot do
        let gateway_client = Client::connect(&dsn_as_role(&dsn, "role_gateway"), NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        let plan_version = seed_plan_version(&mut admin).map_err(|e| setup(e.to_string()))?;
        Ok(Handle {
            rt,
            gateway,
            gateway_client,
            admin,
            plan_version,
            _db: db,
        })
    }
}

/// One plan version, written as the owner (the subscriptions pin it).
fn seed_plan_version(admin: &mut Client) -> Result<Uuid, postgres::Error> {
    let plan: Uuid = admin
        .query_one(
            "INSERT INTO control.plans (plan_key) VALUES ('billing_fixture') RETURNING plan_id",
            &[],
        )?
        .get(0);
    Ok(admin
        .query_one(
            "INSERT INTO control.plan_versions \
               (plan_id, version, price_cents, billing_interval, entitlement_template, lease_block) \
             VALUES ($1, 1, 0, 'month', '{}'::jsonb, 1) RETURNING plan_version_id",
            &[&plan],
        )?
        .get(0))
}

impl Handle {
    /// One inbox insert as role_gateway through the repository.
    fn insert(
        &self,
        event_id: &str,
        event_type: &str,
        payload: &Value,
    ) -> Result<InboxInsert, ErrorCode> {
        self.rt.block_on(billing_repo::inbox_insert(
            &self.gateway,
            BillingProviderId::Creem,
            event_id,
            event_type,
            Some("2026-01-01"),
            Some("sub_ref"),
            payload,
        ))
    }

    fn tenant(&mut self, name: &str) -> Uuid {
        self.admin
            .query_one(
                "INSERT INTO control.tenants (name, state) VALUES ($1, 'ACTIVE') RETURNING tenant_id",
                &[&name],
            )
            .expect("insert tenant")
            .get(0)
    }

    /// A subscription row as the owner; `days` is the length of the paid period.
    fn subscription(
        &mut self,
        tenant: Uuid,
        provider: &str,
        reference: &str,
        state: &str,
        days: i32,
    ) -> Result<Uuid, postgres::Error> {
        let version = self.plan_version;
        let row = self.admin.query_one(
            SUBSCRIPTION_SQL,
            &[&tenant, &provider, &reference, &version, &state, &days],
        )?;
        Ok(row.get(0))
    }

    fn inbox_rows(&mut self) -> i64 {
        self.admin
            .query_one("SELECT count(*) FROM control.billing_inbox", &[])
            .expect("count inbox rows")
            .get(0)
    }
}

/// C4: the first delivery of an event is stored, a redelivery is `Duplicate` and changes nothing (the first payload is
/// kept), and a different event is a second row. Fault: an insert without ON CONFLICT DO NOTHING ⇒ the redelivery is a
/// unique violation ⇒ red.
#[test]
fn an_inbox_event_is_stored_once_and_a_redelivery_is_a_duplicate() {
    run_db_fixture::<BillingFixture, _>(
        "an_inbox_event_is_stored_once_and_a_redelivery_is_a_duplicate",
        |mut h| {
            let first = json!({ "id": "evt_1", "delivery": 1 });
            assert_eq!(
                h.insert("evt_1", "subscription.paid", &first),
                Ok(InboxInsert::Stored)
            );
            let again = json!({ "id": "evt_1", "delivery": 2 });
            assert_eq!(
                h.insert("evt_1", "subscription.canceled", &again),
                Ok(InboxInsert::Duplicate)
            );
            assert_eq!(h.inbox_rows(), 1, "a redelivery stores nothing");

            let stored = h
                .admin
                .query_one(
                    "SELECT event_type, payload, status, api_version, object_id, processed_at IS NULL \
                       FROM control.billing_inbox WHERE event_id = 'evt_1'",
                    &[],
                )
                .expect("the stored row");
            assert_eq!(stored.get::<_, String>(0), "subscription.paid");
            assert_eq!(stored.get::<_, Value>(1), first, "the first delivery wins");
            assert_eq!(stored.get::<_, String>(2), "RECEIVED");
            assert_eq!(
                stored.get::<_, Option<String>>(3).as_deref(),
                Some("2026-01-01")
            );
            assert_eq!(
                stored.get::<_, Option<String>>(4).as_deref(),
                Some("sub_ref")
            );
            assert!(stored.get::<_, bool>(5), "an event starts unprocessed");

            let other = json!({ "id": "evt_2" });
            assert_eq!(
                h.insert("evt_2", "subscription.paid", &other),
                Ok(InboxInsert::Stored)
            );
            assert_eq!(h.inbox_rows(), 2);
        },
    );
}

/// G-M04-13 (§76): role_gateway can insert into the inbox and read, change or delete nothing there, and holds nothing on
/// the four tenant tables; no other principal holds any privilege on the five tables; the tenant tables are FORCE RLS.
/// Fault: a GRANT SELECT on a billing table to the gateway ⇒ its denial turns into a result ⇒ red.
#[test]
fn the_gateway_holds_insert_on_the_inbox_and_nothing_else() {
    run_db_fixture::<BillingFixture, _>(
        "the_gateway_holds_insert_on_the_inbox_and_nothing_else",
        |mut h| {
            for table in BILLING_TABLES {
                let read = format!("SELECT count(*) FROM {table}");
                let denied = h.gateway_client.query(&read, &[]).expect_err(&read);
                assert_eq!(sqlstate(&denied), Some("42501"), "{read}: {denied:?}");
            }
            for statement in [
                "UPDATE control.billing_inbox SET status = 'PROCESSED'",
                "DELETE FROM control.billing_inbox",
                "INSERT INTO control.subscriptions (provider) VALUES ('creem')",
            ] {
                let denied = h
                    .gateway_client
                    .execute(statement, &[])
                    .expect_err(statement);
                assert_eq!(sqlstate(&denied), Some("42501"), "{statement}: {denied:?}");
            }

            let principals: Vec<&str> = PRINCIPALS.to_vec();
            let tables: Vec<&str> = BILLING_TABLES.to_vec();
            let verbs: Vec<&str> = VERBS.to_vec();
            let held: Vec<String> = h
                .admin
                .query(
                    "SELECT r || ' ' || v || ' ' || t FROM unnest($1::text[]) r CROSS JOIN unnest($2::text[]) t \
                     CROSS JOIN unnest($3::text[]) v WHERE has_table_privilege(r, t, v) ORDER BY 1",
                    &[&principals, &tables, &verbs],
                )
                .expect("table privileges")
                .iter()
                .map(|row| row.get(0))
                .collect();
            assert_eq!(held, ["role_gateway INSERT control.billing_inbox"]);

            let forced: Vec<String> = h
                .admin
                .query(
                    "SELECT t FROM unnest($1::text[]) t JOIN pg_class c ON c.oid = to_regclass(t) \
                      WHERE c.relrowsecurity AND c.relforcerowsecurity ORDER BY t COLLATE \"C\"",
                    &[&tables],
                )
                .expect("row security flags")
                .iter()
                .map(|row| row.get(0))
                .collect();
            assert_eq!(
                forced,
                [
                    "control.billing_customers",
                    "control.billing_payments",
                    "control.subscription_events",
                    "control.subscriptions",
                ],
                "the four tenant tables are RLS + FORCE; the global inbox is not"
            );
        },
    );
}

/// M04 D7: an applied fact and a payment are never rewritten or removed, not even by the database owner (the
/// reject-mutation trigger, not a missing grant), and one provider transaction is one row per kind.
/// Fault: drop any of the four triggers ⇒ the owner's UPDATE, DELETE or TRUNCATE succeeds ⇒ red (TRUNCATE needs the
/// statement-level guard: a row trigger never fires on it, the 0101 defect).
#[test]
fn the_applied_facts_are_append_only_even_for_the_owner() {
    run_db_fixture::<BillingFixture, _>(
        "the_applied_facts_are_append_only_even_for_the_owner",
        |mut h| {
            let tenant = h.tenant("billing append only");
            let subscription = h
                .subscription(tenant, "creem", "sub_a", "ACTIVE", 30)
                .expect("a live subscription");
            h.admin
                .execute(EVENT_SQL, &[&tenant, &subscription])
                .expect("record an applied fact");
            h.admin
                .execute(PAYMENT_SQL, &[&tenant, &"txn_a", &"CHARGE"])
                .expect("record a payment");

            for statement in [
                "UPDATE control.billing_payments SET amount_cents = amount_cents + 1",
                "DELETE FROM control.billing_payments",
                "UPDATE control.subscription_events SET to_state = 'CANCELED'",
                "DELETE FROM control.subscription_events",
                "TRUNCATE control.billing_payments",
                "TRUNCATE control.subscription_events",
            ] {
                let refused = h.admin.execute(statement, &[]).expect_err(statement);
                assert_eq!(
                    refused.code(),
                    Some(&SqlState::INSUFFICIENT_PRIVILEGE),
                    "{statement}: {refused:?}"
                );
                assert!(
                    message(&refused).contains("append-only"),
                    "{statement}: {refused:?}"
                );
            }
            let rows: i64 = h
                .admin
                .query_one(
                    "SELECT (SELECT count(*) FROM control.billing_payments) \
                          + (SELECT count(*) FROM control.subscription_events)",
                    &[],
                )
                .expect("count facts")
                .get(0);
            assert_eq!(rows, 2, "the refused statements removed nothing");

            let twice = h
                .admin
                .execute(PAYMENT_SQL, &[&tenant, &"txn_a", &"CHARGE"])
                .expect_err("one transaction, one row per kind");
            assert_eq!(violated(&twice), Some("billing_payments_txn_unique"));
            h.admin
                .execute(PAYMENT_SQL, &[&tenant, &"txn_a", &"REFUND"])
                .expect("the refund of a charge is its own row");
        },
    );
}

/// M04 D1 / D7: a tenant has at most one subscription that is not CANCELED, a canceled one frees the slot, a provider
/// reference belongs to one row, and the state, provider and period are closed. Fault: drop the partial unique index, or
/// the state CHECK ⇒ the second live row or the unknown state is accepted ⇒ red.
#[test]
fn a_tenant_holds_one_live_subscription_over_a_closed_set_of_states() {
    run_db_fixture::<BillingFixture, _>(
        "a_tenant_holds_one_live_subscription_over_a_closed_set_of_states",
        |mut h| {
            let a = h.tenant("billing tenant a");
            let b = h.tenant("billing tenant b");
            let first = h
                .subscription(a, "creem", "sub_1", "ACTIVE", 30)
                .expect("the first live subscription");

            let second = h
                .subscription(a, "creem", "sub_2", "TRIALING", 30)
                .expect_err("a second live subscription for one tenant");
            assert_eq!(sqlstate(&second), Some("23505"), "{second:?}");
            assert_eq!(violated(&second), Some("subscriptions_one_live_per_tenant"));
            h.subscription(b, "creem", "sub_3", "ACTIVE", 30)
                .expect("another tenant has its own slot");

            h.admin
                .execute(
                    "UPDATE control.subscriptions SET state = 'CANCELED' WHERE subscription_id = $1",
                    &[&first],
                )
                .expect("cancel the first");
            h.subscription(a, "creem", "sub_2", "TRIALING", 30)
                .expect("a canceled subscription frees the slot");
            h.subscription(a, "creem", "sub_4", "CANCELED", 30)
                .expect("canceled rows do not occupy it");

            let reused = h
                .subscription(b, "creem", "sub_1", "CANCELED", 30)
                .expect_err("a provider reference belongs to one row");
            assert_eq!(violated(&reused), Some("subscriptions_provider_ref_unique"));

            let c = h.tenant("billing tenant c");
            for (provider, state, days, constraint) in [
                ("creem", "SUSPENDED", 30, "subscriptions_state_v1_check"),
                ("stripe", "ACTIVE", 30, "subscriptions_provider_v1_check"),
                ("creem", "ACTIVE", 0, "subscriptions_period_check"),
            ] {
                let refused = h
                    .subscription(c, provider, "sub_c", state, days)
                    .expect_err(constraint);
                assert_eq!(sqlstate(&refused), Some("23514"), "{refused:?}");
                assert_eq!(violated(&refused), Some(constraint));
            }
        },
    );
}

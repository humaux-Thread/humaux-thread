//! G-M21-4: the M09 expiry door preserves §15.6's denominator and only expires due ISSUED tickets.
//! Depends-on: crates=[humaux-adapters, humaux-testkit, postgres, sqlx, tokio];
//!   services=[PostgreSQL(owner) w=[control.tenants, control.private_reasoning_domains, private.evidence_objects,
//!   private.events, private.ingest_tickets], PostgreSQL(role_maintenance)]; env=[HUMAUX_TEST_PG_DSN];
//!   modules=[adapters::postgres, adapters::stream_repo, adapters::tests::support::throwaway_db, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [each test owns a migrated throwaway DB; missing CI input fails through run_db_fixture;
//!   six retained ticket identities cover expiry, state, tenant, locking, ordering and the bounded batch]
//! Spec: Baseline §6.2.2; §15.6; §79.2; ADR-0123 D4

use humaux_adapters::{postgres::MaintenanceDbPool, stream_repo::expire_ingest_tickets};
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use sqlx::types::Uuid;

#[path = "support/throwaway_db.rs"]
mod throwaway_db;

struct Handle {
    rt: tokio::runtime::Runtime,
    maintenance: MaintenanceDbPool,
    admin: Client,
    _db: throwaway_db::ThrowawayDb,
}

struct Fixture;

impl DbIntegrationFixture for Fixture {
    type Handle = Handle;

    fn isolate() -> Result<Handle, DbFixtureSkipReason> {
        let db = throwaway_db::create("m21_expiry")?;
        let dsn = db.dsn();
        // dep: PostgreSQL(owner) — this test's isolated setup and readback connection
        let admin = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        let sep = if dsn.contains('?') { '&' } else { '?' };
        let maintenance = rt
            // dep: PostgreSQL(role_maintenance) — the production door's existing §6.2.2 role
            .block_on(MaintenanceDbPool::connect(&format!(
                "{dsn}{sep}options=-c%20role%3Drole_maintenance"
            )))
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        Ok(Handle {
            rt,
            maintenance,
            admin,
            _db: db,
        })
    }
}

fn tenants(admin: &mut Client) -> [Uuid; 2] {
    // dep: PostgreSQL(owner) — synthetic tenants in the test's throwaway DB
    let rows = admin.query(
        "INSERT INTO control.tenants (name) VALUES ('expiry target'), ('expiry bystander') RETURNING tenant_id",
        &[],
    ).expect("seed two tenants");
    assert_eq!(rows.len(), 2);
    [rows[0].get(0), rows[1].get(0)]
}

fn seed(admin: &mut Client, tenant: Uuid, other: Uuid) {
    // dep: PostgreSQL(owner) — §15.6 truth table, with a real event FK for the redeemed ticket
    let n = admin.execute(
        "WITH d AS ( \
             INSERT INTO control.private_reasoning_domains (tenant_id, name) VALUES ($1, 'expiry') \
             RETURNING reasoning_domain_id \
         ), e AS ( \
             INSERT INTO private.evidence_objects (tenant_id, evidence_kind, payload_sha256, \
                 data_class, origin_class, visibility_class, reasoning_domain_id) \
             SELECT $1, 'EVENT', sha256(convert_to('{}', 'UTF8')), 'INTERNAL', 'DirectUserInput', \
                 'TENANT_SHARED', reasoning_domain_id FROM d RETURNING evidence_id \
         ), event AS ( \
             INSERT INTO private.events (event_id, event_kind, payload) \
             SELECT evidence_id, 'USER_MESSAGE', '{}' FROM e RETURNING event_id \
         ) \
         INSERT INTO private.ingest_tickets (tenant_id, scope_kind, scope_id, batch_id, client_batch_id, \
             ordinal, issued_at, expires_at, state, redeemed_event_id) \
         SELECT CASE WHEN v.label = 'f' THEN $2 ELSE $1 END, 'workspace', $3, $3, v.label, 1, \
             now() - interval '1 day', now() + make_interval(secs => v.seconds), v.state, \
             CASE WHEN v.state = 'REDEEMED' THEN event.event_id END \
         FROM (VALUES ('a', -10800, 'ISSUED'), ('b', -7200, 'ISSUED'), ('c', 3600, 'ISSUED'), \
             ('d', -3600, 'REDEEMED'), ('e', -3600, 'EXPIRED'), ('f', -3600, 'ISSUED')) \
             AS v(label, seconds, state) CROSS JOIN event",
        &[&tenant, &other, &Uuid::new_v4()],
    ).expect("seed six tickets");
    assert_eq!(n, 6);
}

fn states(admin: &mut Client) -> Vec<(String, String, bool)> {
    // dep: PostgreSQL(owner) — complete cross-tenant denominator and redemption readback
    admin
        .query(
            "SELECT client_batch_id, state, redeemed_event_id IS NOT NULL \
         FROM private.ingest_tickets ORDER BY client_batch_id",
            &[],
        )
        .expect("read every ticket")
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect()
}

#[test]
fn g_m21_4_expiry_preserves_the_exact_ticket_set() {
    run_db_fixture::<Fixture, _>("g_m21_4_expiry_preserves_the_exact_ticket_set", |mut h| {
        let [tenant, other] = tenants(&mut h.admin);
        seed(&mut h.admin, tenant, other);
        for limit in [0, -1] {
            let err =
                h.rt.block_on(expire_ingest_tickets(&h.maintenance, tenant, limit))
                    .expect_err("nonpositive limits fail closed");
            assert!(
                matches!(err, sqlx::Error::Protocol(ref s) if s == "ingest expiry limit must be positive")
            );
        }
        // dep: PostgreSQL(owner) — a held oldest row must be skipped, not block the bounded batch
        let mut lock = h.admin.transaction().expect("lock transaction");
        assert_eq!(lock.query(
            "SELECT ticket_id FROM private.ingest_tickets WHERE client_batch_id = 'a' FOR UPDATE", &[],
        ).expect("hold oldest ticket").len(), 1);
        assert_eq!(
            h.rt.block_on(expire_ingest_tickets(&h.maintenance, tenant, 1))
                .expect("skip locked"),
            1
        );
        lock.rollback().expect("release oldest ticket");
        assert_eq!(
            states(&mut h.admin),
            [
                ("a", "ISSUED", false),
                ("b", "EXPIRED", false),
                ("c", "ISSUED", false),
                ("d", "REDEEMED", true),
                ("e", "EXPIRED", false),
                ("f", "ISSUED", false),
            ]
            .map(|(id, state, redeemed)| (id.to_owned(), state.to_owned(), redeemed))
        );
        assert_eq!(
            h.rt.block_on(expire_ingest_tickets(&h.maintenance, tenant, 1))
                .expect("oldest expires"),
            1
        );
        assert_eq!(
            h.rt.block_on(expire_ingest_tickets(&h.maintenance, tenant, 50))
                .expect("idempotent"),
            0
        );
        let expected = [
            ("a", "EXPIRED", false),
            ("b", "EXPIRED", false),
            ("c", "ISSUED", false),
            ("d", "REDEEMED", true),
            ("e", "EXPIRED", false),
            ("f", "ISSUED", false),
        ]
        .map(|(id, state, redeemed)| (id.to_owned(), state.to_owned(), redeemed));
        assert_eq!(states(&mut h.admin), expected);
        assert_eq!(
            h.rt.block_on(expire_ingest_tickets(&h.maintenance, other, 1))
                .expect("other tenant"),
            1
        );
        let mut after = expected;
        after[5].1 = "EXPIRED".into();
        assert_eq!(states(&mut h.admin), after);
    });
}

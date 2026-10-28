//! `maintenance::tests::i4_scan` — the report-only authority I4 scan of `humaux-maintenance --serve` against real
//!   throwaway PostgreSQL databases (ADR-0123 D3, §59.1 I4 / G59-4, §65; gate G-M21-2): a compliant database reads 0,
//!   a database whose CHECK is dropped and holding one violating row reads 1 with that row's id, the scan changes
//!   nothing it reads, and the scan door and the findings table belong to the daemon's role alone.
//! Depends-on: crates=[]; services=[PostgreSQL(owner) r=[ops.repair_findings, private.memory_records]
//!   w=[control.tenants, ops.repair_findings, private.memory_records] x=[ops.i4_authority_scan],
//!   PostgreSQL(role_gateway), PostgreSQL(role_maintenance), subprocess(humaux-maintenance)];
//!   env=[CARGO_TARGET_TMPDIR, HUMAUX_MAINTENANCE_SERVE_AUTHORITY_I4_EVERY_SECONDS];
//!   modules=[maintenance::tests::support::throwaway]
//! Called-by: [cargo-test]
//! Invariants: [every DB test owns its throwaway database humaux_thread_m21_i4_<pid>_<n>, dropped by the fixture's Drop
//!   even on panic; every spawned daemon is killed by its own Drop; the scan runs once per daemon (EVERY far above
//!   CYCLE), so a database holds exactly one finding row per spawn; the violating row is read back byte for byte and
//!   by xmin after the scan, and an UPDATE or a DELETE of it would change one of the two]
//! Spec: Baseline §41.2; §42; §59.1; §65; §79.2; ADR-0123 D3

use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::time::Duration;

#[path = "support/throwaway.rs"]
#[allow(dead_code)]
mod throwaway;
use throwaway::{BIN, Db, Serve, free_addr, poll};

/// ADR-0123 D1: the scan's cadence key; set far above CYCLE so the first run is the only run of a test.
const I4_EVERY: &str = "HUMAUX_MAINTENANCE_SERVE_AUTHORITY_I4_EVERY_SECONDS";
/// §65: the repair job's name, the key of `docs/architecture/schedule_register.toml` and the findings row's `job`.
const JOB: &str = "authority superseded_by consistency scan";
/// The gauge's unlabeled sample line prefix (§41.2).
const SAMPLE: &str = "authority_i4_violations ";
/// The one CHECK that keeps a violation un-insertable (0004, §59.1 G59-4).
const G59_4: &str = "memory_records_g59_4_status_superseded_by";

// dep: PostgreSQL(role_gateway) — role switch: a runtime role the scan door must refuse
const AS_GATEWAY: &str = "SET LOCAL ROLE role_gateway";
// dep: PostgreSQL(role_maintenance) — role switch: the daemon's own role, which holds the door and nothing more
const AS_MAINTENANCE: &str = "SET LOCAL ROLE role_maintenance";

fn db(test: &str) -> Option<Db> {
    throwaway::db(test, "m21_i4")
}

/// Every key `--serve` requires, valid for a 1 s cycle, with the I4 scan due once an hour.
fn keys(addr: SocketAddr, dsn: &str) -> Vec<(String, String)> {
    throwaway::serve_keys(
        addr,
        dsn,
        1,
        1000,
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
    )
    .into_iter()
    .map(|(k, v)| {
        if k == I4_EVERY {
            (k, "3600".to_owned())
        } else {
            (k, v)
        }
    })
    .collect()
}

fn spawn(env: &[(String, String)]) -> Serve {
    // dep: subprocess(humaux-maintenance) — the resident `--serve` under test
    let child = Command::new(BIN)
        .arg("--serve")
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn humaux-maintenance --serve");
    Serve(child)
}

/// The daemon's `/metrics` once the gauge has a sample, and that sample's value.
fn gauge(addr: SocketAddr) -> f64 {
    let (code, body) = poll(addr, "/metrics", Duration::from_secs(30), |(c, b)| {
        *c == 200 && b.lines().any(|l| l.starts_with(SAMPLE))
    })
    .expect("/metrics answers");
    assert_eq!(code, 200, "{body}");
    body.lines()
        .find_map(|l| l.strip_prefix(SAMPLE)?.trim().parse().ok())
        .unwrap_or_else(|| panic!("no {SAMPLE}sample: {body}"))
}

/// A fresh tenant, the owner of the memory rows below.
fn tenant(db: &mut Db) -> String {
    db.client()
        .query_one(
            "INSERT INTO control.tenants (name) VALUES ('m21-2-i4') RETURNING tenant_id::text",
            &[],
        )
        .expect("tenant")
        .get(0)
}

/// One memory row with no evidence link and its own id as `superseded_by` when `self_superseded` (a valid FK target;
/// the CHECK must be dropped for `active` + a target). The §8.6 orphan trigger is the only thing the missing link would
/// trip, so a test disables it first.
fn memory(db: &mut Db, tenant: &str, status: &str, self_superseded: bool) -> String {
    db.client()
        .query_one(
            "INSERT INTO private.memory_records (memory_id, tenant_id, memory_type, content, visibility_class, \
               authority_class, confidence, status, asserted_at, superseded_by) \
             SELECT m, $1::text::uuid, 'NOTE', '{}'::jsonb, 'TENANT_SHARED', 'PrivateKnowledge', 0.9, $2, now(), \
               CASE WHEN $3 THEN m END \
               FROM (SELECT uuidv7() AS m) s RETURNING memory_id::text",
            &[&tenant, &status, &self_superseded],
        )
        .expect("memory")
        .get(0)
}

/// The row's whole text and its xmin: any UPDATE changes the first or the second.
fn row_state(db: &mut Db, id: &str) -> (String, String) {
    let row = db
        .client()
        .query_one(
            "SELECT m::text, m.xmin::text FROM private.memory_records m WHERE m.memory_id = $1::text::uuid",
            &[&id],
        )
        .expect("memory row");
    (row.get(0), row.get(1))
}

/// Every finding row as `(job, finding_count, sample ids, cluster-level)`.
fn findings(db: &mut Db) -> Vec<(String, i64, Vec<String>, bool)> {
    db.client()
        .query(
            "SELECT job, finding_count, sample_ids::text[], tenant_id IS NULL FROM ops.repair_findings",
            &[],
        )
        .expect("findings")
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
        .collect()
}

/// The SQLSTATE `statement` fails with after `role_switch` inside a transaction that is rolled back; `None` = it ran.
fn sqlstate(db: &mut Db, role_switch: &str, statement: &str) -> Option<String> {
    let c = db.client();
    c.batch_execute("BEGIN").expect("begin");
    c.batch_execute(role_switch).expect("switch role");
    let outcome = c.batch_execute(statement);
    c.batch_execute("ROLLBACK").expect("rollback");
    outcome
        .err()
        .and_then(|e| e.code().map(|c| c.code().to_owned()))
}

/// G-M21-2 / G59-4 注错 b, second reading: on a compliant database the scan counts 0, the gauge is a real 0 (not
/// absent), and exactly one finding row records it (cluster-level, empty sample). Fault: hard-code the gauge or the
/// count to 1 ⇒ red.
#[test]
fn a_compliant_database_reads_zero_and_records_one_finding() {
    let Some(mut db) = db("a_compliant_database_reads_zero_and_records_one_finding") else {
        return;
    };
    let tenant = tenant(&mut db);
    db.sql("ALTER TABLE private.memory_records DISABLE TRIGGER memory_records_requires_evidence");
    memory(&mut db, &tenant, "active", false);
    let addr = free_addr();
    let _serve = spawn(&keys(addr, &db.maintenance_dsn));
    assert_eq!(gauge(addr), 0.0, "a clean scan is a real 0");
    assert_eq!(
        findings(&mut db),
        vec![(JOB.to_owned(), 0, Vec::new(), true)]
    );
}

/// G-M21-2 / G59-4 注错 b: with the CHECK dropped and one `active` row that has a `superseded_by`, the scan counts 1,
/// samples exactly that id, publishes gauge 1, and leaves the row untouched (report-only, G-M21-3). Fault: hard-code
/// the count to 0 ⇒ red; make the scan repair the row ⇒ the row-state comparison is red.
#[test]
fn a_violating_row_is_counted_sampled_and_left_unchanged() {
    let Some(mut db) = db("a_violating_row_is_counted_sampled_and_left_unchanged") else {
        return;
    };
    let tenant = tenant(&mut db);
    db.sql("ALTER TABLE private.memory_records DISABLE TRIGGER memory_records_requires_evidence");
    memory(&mut db, &tenant, "active", false);
    db.sql(&format!(
        "ALTER TABLE private.memory_records DROP CONSTRAINT {G59_4}"
    ));
    let violating = memory(&mut db, &tenant, "active", true);
    let before = row_state(&mut db, &violating);
    let addr = free_addr();
    let _serve = spawn(&keys(addr, &db.maintenance_dsn));
    assert_eq!(gauge(addr), 1.0);
    assert_eq!(
        findings(&mut db),
        vec![(JOB.to_owned(), 1, vec![violating.clone()], true)]
    );
    assert_eq!(
        row_state(&mut db, &violating),
        before,
        "the scan must not repair what it reports"
    );
}

/// ADR-0123 U3 / §6.2.2: the scan door is the daemon's alone (the PUBLIC default of 0004's function is gone), and
/// `ops.repair_findings` is append-only for the daemon: it can read the scan and the table, never UPDATE or DELETE a
/// finding. Fault: leave EXECUTE on PUBLIC, or grant UPDATE or DELETE ⇒ red.
#[test]
fn the_scan_door_and_the_findings_table_are_the_daemons_alone() {
    let Some(mut db) = db("the_scan_door_and_the_findings_table_are_the_daemons_alone") else {
        return;
    };
    let scan = "SELECT * FROM ops.i4_authority_scan()";
    assert_eq!(
        sqlstate(&mut db, AS_GATEWAY, scan).as_deref(),
        Some("42501")
    );
    assert_eq!(sqlstate(&mut db, AS_MAINTENANCE, scan), None);
    for statement in [
        "UPDATE ops.repair_findings SET job = 'edited'",
        "DELETE FROM ops.repair_findings",
    ] {
        assert_eq!(
            sqlstate(&mut db, AS_MAINTENANCE, statement).as_deref(),
            Some("42501"),
            "{statement}"
        );
    }
}

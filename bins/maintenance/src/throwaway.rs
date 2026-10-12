//! `maintenance::throwaway` — test support: disposable `humaux_thread_c25_<purpose>_<pid>` databases on the
//!   `HUMAUX_TEST_PG_DSN` cluster, serialized by one process-wide cluster-DDL lock.
//! Depends-on: crates=[humaux-testkit, postgres]; services=[PostgreSQL(any), subprocess(ps)]; env=[HUMAUX_TEST_PG_DSN];
//!   modules=[humaux-testkit]
//! Called-by: [maintenance::migrate, maintenance::rls_check, xtask::e2e_seed, xtask::serial_lane]
//! Invariants: [every database is created and dropped `WITH (FORCE)` by one guard that holds `CLUSTER_DDL` for its whole
//!   life; a dead pid's leftover of the same purpose is dropped on the next create; a missing DSN goes through
//!   `skip_or_fail` (red under `HUMAUX_REQUIRE_DB=1`)]
//! Spec: Baseline §79.2; ADR-0050 D-D; ADR-0063; ADR-0066 D-Q
//!
//! Compiled only for this crate's tests and for the `test-support` feature, which only `xtask`'s dev-dependency
//! turns on (ADR-0066 D-Q: the migrate tests moved here from xtask, and xtask's lane and seed tests still need the
//! same guard). The production binary never contains it.

use humaux_testkit::{ExternalDep, skip_or_fail};
use postgres::{Client, NoTls};

/// The superuser DSN of the test cluster (dev: `humaux_thread_dev`'s owner).
const TEST_DSN_ENV: &str = "HUMAUX_TEST_PG_DSN";

/// `HUMAUX_TEST_PG_DSN`, or a `testkit::skip_or_fail` (a red under `HUMAUX_REQUIRE_DB=1`).
pub fn base_dsn(test: &str) -> Option<String> {
    match std::env::var(TEST_DSN_ENV) {
        Ok(dsn) => Some(dsn),
        Err(_) => {
            skip_or_fail(
                test,
                "missing object: HUMAUX_TEST_PG_DSN",
                ExternalDep::Postgres,
            );
            None
        }
    }
}

/// Creates `humaux_thread_c25_<purpose>_<pid>` (dropped `WITH (FORCE)` by the guard) and
/// returns the guard plus a DSN onto it. `None` = skipped through `skip_or_fail`.
pub fn throwaway(test: &str, purpose: &str) -> Option<(DisposableDatabase, String)> {
    let base = base_dsn(test)?;
    // dep: PostgreSQL(any) — superuser from HUMAUX_TEST_PG_DSN — CREATE/DROP DATABASE.
    let mut admin = match Client::connect(&base, NoTls) {
        Ok(client) => client,
        Err(e) => {
            skip_or_fail(
                test,
                &format!("missing object: live Postgres at ${TEST_DSN_ENV}: {e}"),
                ExternalDep::Postgres,
            );
            return None;
        }
    };
    // Taken BEFORE the CREATE so the whole migrate run of this database holds it.
    let cluster_ddl = CLUSTER_DDL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let name = format!("humaux_thread_c25_{purpose}_{}", std::process::id());
    admin
        .batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
        .expect("drop a leftover throwaway of this pid");
    drop_dead_leftovers(&mut admin, purpose);
    admin
        .batch_execute(&format!("CREATE DATABASE {name}"))
        .expect("create throwaway database");
    let dsn = database_dsn(&base, &name);
    Some((
        DisposableDatabase {
            admin_dsn: base,
            name,
            _cluster_ddl: cluster_ddl,
        },
        dsn,
    ))
}

/// A killed test never runs its guard's DROP, so its `humaux_thread_c25_<purpose>_<pid>` stays for good (owner
/// disk constraint, 2026-10-05: `humaux_thread_c25_purge_36283`). On creation, every same-purpose leftover whose
/// pid is no longer a live process is dropped; a live pid is another running test's database and stays.
fn drop_dead_leftovers(admin: &mut Client, purpose: &str) {
    let prefix = format!("humaux_thread_c25_{purpose}_");
    let rows = admin
        .query(
            "SELECT datname::text FROM pg_database WHERE starts_with(datname, $1)",
            &[&prefix],
        )
        .expect("list leftover throwaways");
    for row in rows {
        let leftover: String = row.get(0);
        // `<purpose>_<other>_<pid>` of a longer purpose is not ours: the suffix must be the pid alone.
        let Ok(pid) = leftover[prefix.len()..].parse::<u32>() else {
            continue;
        };
        if pid != std::process::id() && !pid_alive(pid) {
            admin
                .batch_execute(&format!("DROP DATABASE IF EXISTS {leftover} WITH (FORCE)"))
                .expect("drop a dead test's leftover throwaway");
            eprintln!("throwaway: dropped {leftover} (pid {pid} is gone)");
        }
    }
}

/// `ps -p <pid>`; a `ps` that cannot run counts as alive (keeping a database is the safe error).
fn pid_alive(pid: u32) -> bool {
    // dep: subprocess(ps) — is the pid in a leftover throwaway's name still a process?
    std::process::Command::new("ps")
        .args(["-p", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_or(true, |s| s.success())
}

/// `base` with its database path replaced by `database` (query string kept).
pub fn database_dsn(base: &str, database: &str) -> String {
    let (without_query, query) = base
        .split_once('?')
        .map_or((base, None), |(head, tail)| (head, Some(tail)));
    let slash = without_query.rfind('/').expect("database path in test DSN");
    format!(
        "{}{database}{}",
        &without_query[..=slash],
        query.map_or(String::new(), |tail| format!("?{tail}"))
    )
}

/// Throwaway databases are isolated from each other, the cluster's roles are not: 0201's
/// `ALTER ROLE role_migration_owner …` (and every GRANT/REVOKE on a role) writes one shared
/// `pg_authid` tuple, so two tests migrating their throwaway databases on parallel threads
/// race into `XX000 tuple concurrently updated` (card 34b chain, 2026-10-04). One guard for
/// the lifetime of every throwaway database serializes them; the lock is poison-tolerant so a
/// panicking test does not take the others down with it.
static CLUSTER_DDL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Drops its database `WITH (FORCE)` on drop and holds [`CLUSTER_DDL`] until then.
pub struct DisposableDatabase {
    admin_dsn: String,
    name: String,
    _cluster_ddl: std::sync::MutexGuard<'static, ()>,
}

impl Drop for DisposableDatabase {
    fn drop(&mut self) {
        // dep: PostgreSQL(any) — superuser from HUMAUX_TEST_PG_DSN — DROP DATABASE of the disposable database.
        if let Ok(mut admin) = Client::connect(&self.admin_dsn, NoTls) {
            let _ = admin.batch_execute(&format!("DROP DATABASE {} WITH (FORCE)", self.name));
        }
    }
}

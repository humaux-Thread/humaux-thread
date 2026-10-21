//! `maintenance::migrate` — `humaux-maintenance migrate`: applies the migration set in filename order against one
//!   PostgreSQL database (§46), from the set embedded at build time or from `--migrations-dir`.
//! Depends-on: crates=[humaux-testkit, postgres, toml]; services=[PostgreSQL(any) w=[ops.schema_migrations]
//!   x=[private.read_continuity_project_storage_v1], PostgreSQL(role_gateway), subprocess(true)];
//!   env=[CARGO_MANIFEST_DIR, HUMAUX_MIGRATOR_PG_DSN, OUT_DIR]; modules=[maintenance::migration_manifest,
//!   maintenance::rls_check]
//! Called-by: [maintenance::main, maintenance::rls_check, tests, xtask::migrate]
//! Invariants: [each PENDING migration runs in one explicit transaction (ADR-0050 D-D) unless its manifest says
//!   transaction = "none" (only that value, only for a CONCURRENTLY body; ADR-0052 D-G); a second run is idempotent;
//!   an applied file whose checksum changed is drift and stops the run, unless the recorded checksum is on the file's
//!   reviewed `accepted_prior_checksums` (ADR-0082: logged, continues, `ops.schema_migrations` never rewritten);
//!   0011 pending with one of its roles missing is refused unless --dev-placeholder-roles (ADR-0059 D-A); a session of
//!   a runtime role in the TARGET database
//!   (`datname = current_database()`) refuses the run with exit 3 naming each role, unless --allow-live-sessions
//!   (ADR-0066 D-Q, OPS-9)]
//! Spec: Baseline §46; ADR-0050; ADR-0052; ADR-0059; ADR-0066 D-Q; ADR-0082
//!
//! Moved from `xtask::migrate` (ADR-0066 D-Q) so a production node migrates with the release image and no toolchain;
//! `cargo xtask migrate` is now a delegation that passes `--migrations-dir migrations` and the test DSN.
//!
//! Source of the set: without `--migrations-dir` the run applies the files `build.rs` embedded from `migrations/`
//! (every `.sql` and its sibling `.manifest.toml`), so the image carries exactly the set its binary was built with and
//! needs no source tree. Checksums are computed from those bytes at run time, the same FNV-1a as for a directory, so
//! drift detection does not depend on the source. DSN: `--dsn <url>` or `HUMAUX_MIGRATOR_PG_DSN` (the superuser path,
//! ADR-0066 L-13); neither ⇒ exit 2 naming both. Exit codes: 0 pass, 1 fail, 2 usage, 3 refused (live sessions).
//!
//! Each PENDING migration runs in one explicit transaction (ADR-0050 D-D, Baseline 2.9 §46.1):
//! its manifest `precheck` (must return exactly 1 row × 1 `bool` column, value `true`), the
//! unchanged `.sql` bytes via [`postgres::Transaction::batch_execute`], its `postcheck` (same
//! shape rule), and the `ops.schema_migrations` row — then COMMIT. A false / non-boolean /
//! invalid check refuses the migration with the check's name and the server's text, the
//! transaction rolls back (drift 0: no object, no record), and the run stops. One log line per
//! check. A pending migration with no manifest is refused. Already-applied migrations are
//! never re-checked (a precheck is false after apply by construction); their drift is the
//! checksum's job.
//!
//! The one exception (ADR-0052 D-G, card 27): a manifest may say `transaction = "none"` — the only
//! accepted value; anything else refuses the migration. Such a body must contain `CONCURRENTLY`
//! outside `--` comments (so the key is not a way to escape atomicity for ordinary DDL), and runs
//! precheck → body → postcheck → ledger row in autocommit, because `CREATE INDEX CONCURRENTLY` is
//! illegal inside a transaction block. PostgreSQL itself refuses `CONCURRENTLY` in a
//! multi-statement simple-query string (an implicit transaction block), so the one-statement rule
//! is enforced by the server. Not atomic with the ledger: a failed build leaves an INVALID index
//! that the rerun's precheck (`to_regclass(<name>) IS NULL`) refuses by name, and the manifest's
//! `rollback_or_forward_fix` names the `DROP INDEX CONCURRENTLY IF EXISTS` that clears it. The key
//! is read here from the manifest text (`toml`), so `migration_manifest::Manifest` is untouched.
//!
//! One migrator per database (ADR-0050 D-F, audit DM-6): the whole run holds the session-level
//! advisory lock [`MIGRATE_ADVISORY_LOCK`] ("HXMIGRAT"), taken after `SET lock_timeout` and
//! before the bootstrap DDL, so a second `migrate` waits up to [`LOCK_TIMEOUT`] and then
//! refuses with `55P03` and 0 applied. The same `lock_timeout` bounds every migration's DDL,
//! so a migration queued behind a live worker's lock is refused with drift 0 instead of
//! stalling traffic. The live-session refusal (OPS-9) is the explicit form of runbook §1's "stop the workers first":
//! it reads `pg_stat_activity` filtered on `datname = current_database()`, because that view is cluster-wide and the
//! dev chain migrates throwaway databases while its own gateway is connected to another database of the same cluster.

use crate::migration_manifest::{self, AcceptedChecksum, Manifest, RecordedChecksum};
use postgres::error::SqlState;
use postgres::types::Type;
use postgres::{Client, GenericClient, NoTls};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

/// ADR-0066 D-J / L-13: the superuser migrator principal, held only by the `migrate` service's secret file.
const DSN_ENV: &str = "HUMAUX_MIGRATOR_PG_DSN";

/// ADR-0066 D-Q: the explicit override of the OPS-9 live-session refusal.
const ALLOW_LIVE_SESSIONS_FLAG: &str = "--allow-live-sessions";

// The migration set `build.rs` embedded: `(migration_id, sql, manifest)` sorted by filename.
include!(concat!(env!("OUT_DIR"), "/embedded_migrations.rs"));

/// ADR-0050 D-F: the one advisory key every `migrate` run holds, ASCII "HXMIGRAT". A fixed
/// bigint with no meaning, same style as `testkit::DISCLOSURE_LEDGER_ADVISORY_LOCK`; advisory
/// locks are per database, so per-run lane databases never contend with the dev database.
pub const MIGRATE_ADVISORY_LOCK: i64 = 0x4858_4D49_4752_4154;

/// ADR-0050 D-F: how long a second migrator waits for [`MIGRATE_ADVISORY_LOCK`], and how long
/// any migration's DDL may queue behind another session's lock, before refusing (`55P03`).
const LOCK_TIMEOUT: &str = "30s";

/// Bootstrap table this runner owns; not a `migrations/*.sql` file itself because it must
/// exist *before* the first migration can be recorded (chicken-and-egg on migration 0001).
const BOOTSTRAP_SQL: &str = "\
    CREATE SCHEMA IF NOT EXISTS ops; \
    CREATE TABLE IF NOT EXISTS ops.schema_migrations ( \
      migration_id text PRIMARY KEY, \
      checksum     text NOT NULL, \
      applied_at   timestamptz NOT NULL DEFAULT now() \
    ); \
    DO $owner$ BEGIN \
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'role_migration_owner') THEN \
        ALTER TABLE ops.schema_migrations OWNER TO role_migration_owner; \
      END IF; \
    END $owner$;";

/// FNV-1a: dependency-free, deterministic, sufficient for drift detection (this is not a
/// security boundary — sha256 is already the workspace's payload-identity function,
/// §48.0①, and reusing it here would suggest this check carries that same guarantee).
fn fnv1a_hex(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let mut out = String::with_capacity(16);
    let _ = write!(out, "{hash:016x}");
    out
}

fn dsn_from_args(args: &[String]) -> Option<String> {
    flag_value(args, "--dsn")
}

/// The first of `names` present without a separate value (last, empty, followed by another `--flag`, or written
/// `--flag=value`). PR #2 review: a bare
/// value flag read as absent let a default stand in for it (`--migrations-dir` → the embedded set, `--dsn` → the
/// environment DSN, `--spec` → no table-set check); callers refuse it as a usage error (exit 2) before any default.
pub(crate) fn flag_without_value(args: &[String], names: &[&'static str]) -> Option<&'static str> {
    names.iter().copied().find(|name| {
        // Card 39b: `--dsn=URL` is not a form these parsers read — it would also fall to the default.
        let joined = format!("{name}=");
        args.iter().any(|a| a.starts_with(&joined))
            || args.iter().position(|a| a == name).is_some_and(|i| {
                args.get(i + 1)
                    .is_none_or(|v| v.is_empty() || v.starts_with("--"))
            })
    })
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// One `migrations/*.sql` file in filename order, paired with its already-loaded contents and
/// its sibling manifest (`None` when the file has none — refused only if it is pending).
#[derive(Clone)]
struct PendingMigration {
    migration_id: String,
    sql: String,
    manifest: Option<Manifest>,
    /// The manifest's raw `transaction` key (ADR-0052 D-G); `None` = the default one-transaction
    /// apply. Validated by [`apply_locked`] before anything of that migration runs.
    transaction: Option<String>,
    /// The manifest's reviewed `accepted_prior_checksums` (ADR-0082); empty when it has none or there is no manifest.
    accepted_prior_checksums: Vec<AcceptedChecksum>,
}

/// ADR-0052 D-G: the manifest's `transaction` key as written — absent ⇒ `None`, a string ⇒ that
/// string, any other TOML type ⇒ its rendering (so [`apply_locked`] refuses it by value).
fn manifest_transaction(text: &str) -> Option<String> {
    let value: toml::Value = toml::from_str(text).ok()?;
    value.get("transaction").map(|v| match v {
        toml::Value::String(s) => s.clone(),
        other => other.to_string(),
    })
}

/// The body with `--` line comments removed, for the `CONCURRENTLY` rule: a comment that merely
/// mentions the word must not qualify ordinary DDL for a transaction-less apply.
fn body_without_line_comments(sql: &str) -> String {
    sql.lines()
        .map(|line| line.split_once("--").map_or(line, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Enumerates `migrations_dir/*.sql` sorted by filename (the numeric prefix is the ordering
/// key, §46 "按序应用") with each sibling `<stem>.manifest.toml`, then [`parse_sources`]. A missing
/// manifest is carried as `None` and refused by [`apply_all`] only if that file is pending.
fn collect_migrations(migrations_dir: &Path) -> Result<Vec<PendingMigration>, String> {
    let mut paths: Vec<_> = fs::read_dir(migrations_dir)
        .map_err(|e| format!("cannot read {}: {e}", migrations_dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("sql"))
        .collect();
    paths.sort();

    let sources = paths
        .into_iter()
        .map(|path| {
            let migration_id = path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let sql = fs::read_to_string(&path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            let manifest_path = path.with_extension("manifest.toml");
            let manifest = match fs::read_to_string(&manifest_path) {
                Ok(text) => Some(text),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(format!("cannot read {}: {e}", manifest_path.display())),
            };
            Ok((migration_id, sql, manifest))
        })
        .collect::<Result<Vec<_>, String>>()?;
    parse_sources(sources)
}

/// The embedded body of `migration_id` (ADR-0066 D-Q), for a check that scans a migration's text on a node
/// (`rls_check`'s R4 registry); `None` when the set has no such id.
pub(crate) fn embedded_sql(migration_id: &str) -> Option<&'static str> {
    EMBEDDED_MIGRATIONS
        .iter()
        .find(|(id, _, _)| *id == migration_id)
        .map(|(_, sql, _)| *sql)
}

/// The set `build.rs` embedded (already in filename order), through the same [`parse_sources`].
fn collect_embedded() -> Result<Vec<PendingMigration>, String> {
    parse_sources(
        EMBEDDED_MIGRATIONS
            .iter()
            .map(|(id, sql, manifest)| {
                (
                    (*id).to_owned(),
                    (*sql).to_owned(),
                    manifest.map(str::to_owned),
                )
            })
            .collect(),
    )
}

/// Parses each `(migration_id, sql, manifest text)` with the one manifest parser
/// (`migration_manifest::parse_manifest`); an unparsable manifest is an error here.
fn parse_sources(
    sources: Vec<(String, String, Option<String>)>,
) -> Result<Vec<PendingMigration>, String> {
    sources
        .into_iter()
        .map(|(migration_id, sql, text)| {
            let (manifest, transaction, accepted_prior_checksums) = match text {
                Some(text) => {
                    let name = format!("{migration_id}.manifest.toml");
                    (
                        Some(
                            migration_manifest::parse_manifest(&name, &text)
                                .map_err(|e| e.to_string())?,
                        ),
                        manifest_transaction(&text),
                        migration_manifest::accepted_prior_checksums(&name, &text)
                            .map_err(|e| e.to_string())?,
                    )
                }
                None => (None, None, Vec::new()),
            };
            Ok(PendingMigration {
                migration_id,
                sql,
                manifest,
                transaction,
                accepted_prior_checksums,
            })
        })
        .collect()
}

/// The server's own complaint: `Display` alone can collapse to a bare "db error"; the text
/// lives in `DbError` (falls back to `{e:?}` for non-server errors like a dropped connection).
fn db_error_text(e: &postgres::Error) -> String {
    e.as_db_error()
        .map(|db| {
            format!(
                "{} {} — {}",
                db.code().code(),
                db.message(),
                db.detail().unwrap_or("")
            )
        })
        .unwrap_or_else(|| format!("{e:?}"))
}

/// Runs one manifest check inside the migration's transaction. It must return exactly one
/// row with one `bool` column whose value is `true`; anything else is an `Err` naming the
/// migration, the check, and why (server text, `returned false`, `returned <type>`, …).
fn run_check(
    tx: &mut impl GenericClient,
    migration_id: &str,
    field: &str,
    sql: &str,
) -> Result<(), String> {
    let refuse = |why: String| format!("{migration_id}: {field} refused the migration — {why}");
    let rows = tx.query(sql, &[]).map_err(|e| refuse(db_error_text(&e)))?;
    let [row] = rows.as_slice() else {
        return Err(refuse(format!("returned {} rows, expected 1", rows.len())));
    };
    if row.columns().len() != 1 {
        return Err(refuse(format!(
            "returned {} columns, expected 1",
            row.columns().len()
        )));
    }
    let ty = row.columns()[0].type_();
    if *ty != Type::BOOL {
        return Err(refuse(format!("returned {ty}, expected bool")));
    }
    match row.get::<_, Option<bool>>(0) {
        Some(true) => {
            eprintln!("migrate: {field} {migration_id} ok");
            Ok(())
        }
        Some(false) => Err(refuse("returned false".to_string())),
        None => Err(refuse("returned NULL".to_string())),
    }
}

/// The migration whose `CREATE ROLE ... IF NOT EXISTS` blocks carry the repository's dev-only
/// placeholder passwords (ADR-0059 D-A).
const ROLES_MIGRATION: &str = "0011_roles_and_grants";

/// ADR-0059 D-A: the only way to let [`ROLES_MIGRATION`] create a missing role with its
/// repository placeholder password. Meant for a brand-new dev container, never a deployment.
const DEV_PLACEHOLDER_ROLES_FLAG: &str = "--dev-placeholder-roles";

/// The role names `sql` creates, in order (`CREATE ROLE <name> ...`). Names only: nothing after the
/// name is read, so no password literal ever leaves the file through this function.
fn created_role_names(sql: &str) -> Vec<String> {
    sql.split("CREATE ROLE ")
        .skip(1)
        .filter_map(|rest| {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            (!name.is_empty()).then_some(name)
        })
        .collect()
}

/// ADR-0059 D-A, fresh-cluster guard: when [`ROLES_MIGRATION`] is about to run and one of the roles
/// it creates does not exist yet, applying it would create that role LOGIN with a password
/// published in the repository. Refused unless the operator passed [`DEV_PLACEHOLDER_ROLES_FLAG`];
/// production pre-provisions the roles with `humaux-maintenance roles rotate --create-missing`.
fn placeholder_role_guard(
    roles_migration_pending: bool,
    missing_roles: &[String],
    dev_placeholder_roles: bool,
) -> Result<(), String> {
    match missing_roles.first() {
        Some(role) if roles_migration_pending && !dev_placeholder_roles => Err(format!(
            "missing object: role {role} — pre-provision with 'humaux-maintenance roles rotate \
             --create-missing --roles-sql migrations/0011_roles_and_grants.sql' (runbook §2) or pass {DEV_PLACEHOLDER_ROLES_FLAG} (dev clusters \
             only); 0 applied"
        )),
        _ => Ok(()),
    }
}

/// Feeds [`placeholder_role_guard`] from the target cluster: whether [`ROLES_MIGRATION`] is in this
/// run and not yet recorded, and which of its roles are absent from `pg_roles`.
fn check_placeholder_roles(
    client: &mut Client,
    migrations: &[PendingMigration],
    dev_placeholder_roles: bool,
) -> Result<(), String> {
    let Some(roles) = migrations
        .iter()
        .find(|m| m.migration_id == ROLES_MIGRATION)
    else {
        return Ok(());
    };
    let query = |e: postgres::Error| format!("placeholder-role guard: {}", db_error_text(&e));
    // dep: PostgreSQL(any) — ledger and pg_roles reads for the fresh-cluster guard
    // The ledger is bootstrapped later, under the same lock: no table yet = nothing applied.
    let ledger: bool = client
        .query_one(
            "SELECT to_regclass('ops.schema_migrations') IS NOT NULL",
            &[],
        )
        .map_err(query)?
        .get(0);
    let pending = !ledger
        || client
            .query_opt(
                "SELECT 1 FROM ops.schema_migrations WHERE migration_id = $1",
                &[&ROLES_MIGRATION],
            )
            .map_err(query)?
            .is_none();
    let missing: Vec<String> = client
        .query(
            "SELECT n FROM unnest($1::text[]) WITH ORDINALITY AS u(n, i) \
             WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = n) ORDER BY i",
            &[&created_role_names(&roles.sql)],
        )
        .map_err(query)?
        .iter()
        .map(|row| row.get(0))
        .collect();
    placeholder_role_guard(pending, &missing, dev_placeholder_roles)
}

/// Applies every not-yet-recorded migration in order under [`MIGRATE_ADVISORY_LOCK`]; stops
/// at the first failure (a later migration may depend on an earlier one's objects, so
/// partial-then-continue would mask the real error behind a cascade of unrelated ones).
/// `lock_timeout` is a PostgreSQL interval literal ([`LOCK_TIMEOUT`] in production; tests
/// pass `1s`). `dev_placeholder_roles` is [`DEV_PLACEHOLDER_ROLES_FLAG`] (ADR-0059 D-A guard, checked
/// under the lock before anything is applied). Returns `(applied, skipped)` counts.
fn apply_all(
    client: &mut Client,
    migrations: &[PendingMigration],
    lock_timeout: &str,
    dev_placeholder_roles: bool,
) -> Result<(usize, usize), String> {
    client
        .batch_execute(&format!("SET lock_timeout = '{lock_timeout}'"))
        .map_err(|e| format!("cannot set lock_timeout: {}", db_error_text(&e)))?;
    client
        .execute("SELECT pg_advisory_lock($1)", &[&MIGRATE_ADVISORY_LOCK])
        .map_err(|e| {
            if e.code() == Some(&SqlState::LOCK_NOT_AVAILABLE) {
                format!(
                    "another migrate holds HXMIGRAT (advisory lock {MIGRATE_ADVISORY_LOCK:#x}, \
                     55P03 lock_not_available after {lock_timeout}); refused, 0 applied"
                )
            } else {
                format!("cannot take HXMIGRAT advisory lock: {}", db_error_text(&e))
            }
        })?;
    let result = check_placeholder_roles(client, migrations, dev_placeholder_roles)
        .and_then(|()| apply_locked(client, migrations));
    // Explicit release; a dropped connection releases it too. An unlock error cannot change
    // what was applied, so it never masks `result`.
    let _ = client.execute("SELECT pg_advisory_unlock($1)", &[&MIGRATE_ADVISORY_LOCK]);
    result
}

/// ADR-0082: the operator line for an accepted amendment, naming the migration, the checksum its database recorded and
/// the file's current one.
fn amended_notice(migration_id: &str, recorded: &str, current: &str, reason: &str) -> String {
    format!(
        "migrate: amended {migration_id} — recorded checksum {recorded} is on its accepted_prior_checksums \
         ({reason}); file checksum now {current}; ops.schema_migrations left as recorded (ADR-0082)"
    )
}

fn apply_locked(
    client: &mut Client,
    migrations: &[PendingMigration],
) -> Result<(usize, usize), String> {
    client
        .batch_execute(BOOTSTRAP_SQL)
        .map_err(|e| format!("bootstrap ops.schema_migrations: {e}"))?;

    let mut applied = 0usize;
    let mut skipped = 0usize;
    for m in migrations {
        // §46 drift detection: `ops.schema_migrations.checksum` is written on every apply
        // but was never read back — editing an already-applied file silently printed
        // "skip (already applied)" and returned `pass`, on the one axis the column exists
        // to catch. `Option` distinguishes "not yet applied" (no row) from "applied with
        // this checksum" so a changed file fails loudly instead of being skipped quietly.
        let recorded_checksum: Option<String> = client
            .query_opt(
                "SELECT checksum FROM ops.schema_migrations WHERE migration_id = $1",
                &[&m.migration_id],
            )
            .map_err(|e| {
                format!(
                    "{}: cannot check ops.schema_migrations: {e}",
                    m.migration_id
                )
            })?
            .map(|row| row.get(0));

        if let Some(recorded) = recorded_checksum {
            let current = fnv1a_hex(m.sql.as_bytes());
            // ADR-0082: the one drift rule. An amendment is logged and the run goes on; nothing here writes
            // `ops.schema_migrations` (ADR-0060 SEC-2: no command rewrites a recorded checksum).
            match migration_manifest::compare_recorded(
                &current,
                &recorded,
                &m.accepted_prior_checksums,
            ) {
                RecordedChecksum::Same => {}
                RecordedChecksum::Amended { reason } => {
                    eprintln!(
                        "{}",
                        amended_notice(&m.migration_id, &recorded, &current, reason)
                    );
                }
                RecordedChecksum::Drift => {
                    return Err(format!(
                        "{}: drift detected — file's checksum {current} does not match \
                         recorded {recorded} (already applied with different content; §46 \
                         migrations are immutable once applied, add a new migration instead \
                         of editing this one)",
                        m.migration_id
                    ));
                }
            }
            skipped += 1;
            eprintln!("migrate: skip  {} (already applied)", m.migration_id);
            continue;
        }

        let Some(manifest) = &m.manifest else {
            return Err(format!(
                "{0}: refused — no manifest {0}.manifest.toml; migrate cannot execute a \
                 precheck/postcheck it does not have (§46.1, ADR-0050 D-D)",
                m.migration_id
            ));
        };
        let checksum = fnv1a_hex(m.sql.as_bytes());
        match m.transaction.as_deref() {
            None => {}
            Some("none") => {
                apply_outside_transaction(client, m, manifest, &checksum)?;
                applied += 1;
                continue;
            }
            Some(other) => {
                return Err(format!(
                    "{}: refused — manifest transaction = {other:?}; the only accepted value is \
                     \"none\" (ADR-0052 D-G), 0 statements run",
                    m.migration_id
                ));
            }
        }
        // ADR-0050 D-D: precheck, body, postcheck and the ledger row commit together or not
        // at all. Dropping `tx` on any `?` below rolls everything back.
        let mut tx = client
            .transaction()
            .map_err(|e| format!("{}: cannot begin: {}", m.migration_id, db_error_text(&e)))?;
        run_check(&mut tx, &m.migration_id, "precheck", &manifest.precheck)?;
        tx.batch_execute(&m.sql)
            .map_err(|e| format!("{}: {}", m.migration_id, db_error_text(&e)))?;
        run_check(&mut tx, &m.migration_id, "postcheck", &manifest.postcheck)?;
        tx.execute(
            "INSERT INTO ops.schema_migrations (migration_id, checksum) VALUES ($1, $2)",
            &[&m.migration_id, &checksum],
        )
        .map_err(|e| {
            format!(
                "{}: cannot record in ops.schema_migrations: {e}",
                m.migration_id
            )
        })?;
        tx.commit()
            .map_err(|e| format!("{}: commit: {}", m.migration_id, db_error_text(&e)))?;

        applied += 1;
        eprintln!("migrate: apply {}", m.migration_id);
    }

    Ok((applied, skipped))
}

/// ADR-0052 D-G: a `transaction = "none"` migration — precheck, body, postcheck and the ledger row
/// each in autocommit, because `CREATE INDEX CONCURRENTLY` cannot run inside a transaction block.
/// The body must contain `CONCURRENTLY` outside `--` comments or nothing runs. A failure after the
/// body leaves what the body built (an INVALID index for a failed CIC) and no ledger row; the
/// rerun's precheck refuses by name and the manifest names the `DROP INDEX CONCURRENTLY` fix.
fn apply_outside_transaction(
    client: &mut Client,
    m: &PendingMigration,
    manifest: &Manifest,
    checksum: &str,
) -> Result<(), String> {
    if !body_without_line_comments(&m.sql)
        .to_ascii_uppercase()
        .contains("CONCURRENTLY")
    {
        return Err(format!(
            "{}: refused — transaction = \"none\" requires a CONCURRENTLY body (ADR-0052 D-G); \
             0 statements run",
            m.migration_id
        ));
    }
    eprintln!(
        "migrate: mode  {} transaction=none (CONCURRENTLY, outside a transaction block)",
        m.migration_id
    );
    run_check(client, &m.migration_id, "precheck", &manifest.precheck)?;
    client
        .batch_execute(&m.sql)
        .map_err(|e| format!("{}: {}", m.migration_id, db_error_text(&e)))?;
    run_check(client, &m.migration_id, "postcheck", &manifest.postcheck)?;
    client
        .execute(
            "INSERT INTO ops.schema_migrations (migration_id, checksum) VALUES ($1, $2)",
            &[&m.migration_id, &checksum],
        )
        .map_err(|e| {
            format!(
                "{}: cannot record in ops.schema_migrations: {e}",
                m.migration_id
            )
        })?;
    eprintln!("migrate: apply {} (transaction=none)", m.migration_id);
    Ok(())
}

/// The runtime principals whose live session refuses a migrate (ADR-0066 D-Q, OPS-9): every
/// `rls_check::RUNTIME_ROLES` entry plus the resident maintenance daemon's role.
fn live_session_roles() -> Vec<&'static str> {
    crate::rls_check::RUNTIME_ROLES
        .iter()
        .copied()
        .chain(["role_maintenance"])
        .collect()
}

/// ADR-0066 D-Q (OPS-9): `<role>=<n>` for each runtime role with a session in the database this client is connected
/// to (empty = none). `pg_stat_activity` is cluster-wide; the `datname` filter keeps another database's traffic (the
/// dev chain's gateway on `humaux_thread_dev`) from refusing a throwaway's migrate.
fn live_runtime_sessions(client: &mut Client) -> Result<Vec<String>, String> {
    // dep: PostgreSQL(any) — pg_stat_activity of the target database (OPS-9 live-session refusal)
    let rows = client
        .query(
            "SELECT usename::text, count(*) FROM pg_stat_activity \
             WHERE datname = current_database() AND usename = ANY($1) AND pid <> pg_backend_pid() \
             GROUP BY usename ORDER BY usename",
            &[&live_session_roles()],
        )
        .map_err(|e| format!("live-session check: {}", db_error_text(&e)))?;
    Ok(rows
        .iter()
        .map(|row| format!("{}={}", row.get::<_, String>(0), row.get::<_, i64>(1)))
        .collect())
}

/// `humaux-maintenance migrate [--migrations-dir DIR] [--dsn URL] [--through ID] [--dev-placeholder-roles]
/// [--allow-live-sessions]`: 0 pass (every migration recorded, newly applied or already applied), 1 fail (names the
/// migration), 2 usage (no DSN, or a value flag without its value), 3 refused (live runtime sessions in the target database, nothing applied).
pub fn run(args: &[String]) -> i32 {
    if let Some(name) = flag_without_value(args, &["--dsn", "--migrations-dir", "--through"]) {
        eprintln!("migrate: usage — {name} needs a value");
        return 2;
    }
    let dsn = dsn_from_args(args).or_else(|| std::env::var(DSN_ENV).ok().filter(|v| !v.is_empty()));
    let Some(dsn) = dsn else {
        eprintln!("migrate: missing --dsn or environment variable {DSN_ENV}");
        return 2;
    };

    let collected = match flag_value(args, "--migrations-dir") {
        Some(dir) => collect_migrations(Path::new(&dir)),
        None => collect_embedded(),
    };
    let mut migrations = match collected {
        Ok(m) => m,
        Err(e) => {
            eprintln!("migrate: fail ({e})");
            return 1;
        }
    };
    // `--through <id>` stops after the migration whose file stem starts with `<id>` — the only
    // way to build the *pre-N* schema a migration's own hard-stop test has to assert against
    // (`contribution_policy_lifecycle_0132.rs::pre_0132_unresolved_triples_hard_stop` re-runs
    // 0132's SQL and requires 55000). Ordering is the filename's numeric prefix, same as
    // `collect_migrations`; an id that matches nothing is a fail, never a silent full apply.
    if let Some(through) = flag_value(args, "--through") {
        let Some(last) = migrations
            .iter()
            .position(|m| m.migration_id.starts_with(&through))
        else {
            eprintln!("migrate: fail (--through {through} matches no migration file)");
            return 1;
        };
        migrations.truncate(last + 1);
        eprintln!(
            "migrate: --through {through} — applying {} of the migration set",
            migrations.len()
        );
    }
    let migrations = migrations;

    // dep: PostgreSQL(any) — the target database this run migrates.
    let mut client = match Client::connect(&dsn, NoTls) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("migrate: fail (cannot connect: {e})");
            return 1;
        }
    };
    if !args.iter().any(|a| a == ALLOW_LIVE_SESSIONS_FLAG) {
        match live_runtime_sessions(&mut client) {
            Ok(live) if live.is_empty() => {}
            Ok(live) => {
                eprintln!(
                    "migrate: refused (live_runtime_sessions:{}; stop them first or pass \
                     {ALLOW_LIVE_SESSIONS_FLAG}), 0 applied",
                    live.join(",")
                );
                return 3;
            }
            Err(e) => {
                eprintln!("migrate: fail ({e})");
                return 1;
            }
        }
    }

    match apply_all(
        &mut client,
        &migrations,
        LOCK_TIMEOUT,
        args.iter().any(|a| a == DEV_PLACEHOLDER_ROLES_FLAG),
    ) {
        Ok((applied, skipped)) => {
            eprintln!(
                "migrate: pass ({applied} applied, {skipped} already-applied, {} total)",
                migrations.len()
            );
            0
        }
        Err(e) => {
            eprintln!("migrate: fail ({e})");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration_manifest::MigrationClass;
    use crate::throwaway::{base_dsn, database_dsn, throwaway};
    use humaux_testkit::{ExternalDep, skip_or_fail};
    use postgres::{Client, types::Type};
    use std::fs;
    use std::path::PathBuf;
    use std::time::Instant;

    /// PR #2 Codex P1 round 5: a bare `--migrations-dir`, `--dsn` or `--through` is a usage error (exit 2) before
    /// the embedded set or the environment DSN can stand in (no database is reached). Fault: drop the guard ⇒ red.
    #[test]
    fn bare_value_flags_are_usage_errors_before_any_default() {
        let own = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        // Every case discriminates without the guard (it would reach a default and return 1), and every case is
        // judged before the assert, so a red names them all.
        let wrong: Vec<(Vec<String>, i32)> = [
            own(&["--dsn", "postgres://127.0.0.1:1/x", "--migrations-dir"]),
            own(&["--dsn", "--migrations-dir", "/nonexistent/migrations"]),
            own(&["--migrations-dir", "--dsn", "postgres://127.0.0.1:1/x"]),
            own(&["--dsn", "postgres://127.0.0.1:1/x", "--through", ""]),
        ]
        .into_iter()
        .map(|args| {
            let code = run(&args);
            (args, code)
        })
        .filter(|(_, code)| *code != 2)
        .collect();
        assert!(wrong.is_empty(), "not a usage error: {wrong:?}");
    }

    /// A minimal in-memory manifest: only the two checks matter to `apply_all`.
    fn manifest(id: &str, precheck: &str, postcheck: &str) -> Manifest {
        Manifest {
            migration_id: id.to_string(),
            class: MigrationClass::ForwardOnly,
            precheck: precheck.to_string(),
            postcheck: postcheck.to_string(),
            rollback_or_forward_fix: "test fixture".to_string(),
            backup_restore_requirement: "test fixture".to_string(),
        }
    }

    fn migration(id: &str, sql: &str) -> PendingMigration {
        PendingMigration {
            migration_id: id.to_string(),
            sql: sql.to_string(),
            manifest: Some(manifest(id, "select true", "select true")),
            transaction: None,
            accepted_prior_checksums: Vec::new(),
        }
    }

    /// Writes `<stem>.sql` and (when `checks` is given) a full `<stem>.manifest.toml`.
    fn write_migration(dir: &Path, stem: &str, sql: &str, checks: Option<(&str, &str)>) {
        fs::write(dir.join(format!("{stem}.sql")), sql).unwrap();
        if let Some((pre, post)) = checks {
            fs::write(
                dir.join(format!("{stem}.manifest.toml")),
                format!(
                    "migration_id = \"{stem}\"\nclass = \"FORWARD_ONLY\"\n\
                     precheck = \"{pre}\"\npostcheck = \"{post}\"\n\
                     rollback_or_forward_fix = \"test\"\nbackup_restore_requirement = \"test\"\n"
                ),
            )
            .unwrap();
        }
    }

    fn scratch_dir(purpose: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "xtask_migrate_c25_{purpose}_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A same-purpose leftover of a dead pid is dropped when the next throwaway of that purpose is created; one of a
    /// live pid (1) and one of a longer purpose stay. Fault: delete the `drop_dead_leftovers` call ⇒ the dead pid's
    /// database survives ⇒ red.
    #[test]
    fn a_dead_pids_leftover_throwaway_is_dropped_on_the_next_create() {
        let test = "a_dead_pids_leftover_throwaway_is_dropped_on_the_next_create";
        let Some(base) = base_dsn(test) else {
            return;
        };
        // dep: PostgreSQL(any) — superuser from HUMAUX_TEST_PG_DSN — CREATE/DROP DATABASE.
        let mut admin = Client::connect(&base, NoTls).expect("admin connect");
        // dep: subprocess(true) — a pid that is certainly dead once reaped
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        let dead = child.id();
        child.wait().expect("reap true");
        let leftovers = [
            format!("humaux_thread_c25_leftover_{dead}"),
            "humaux_thread_c25_leftover_1".to_owned(),
            format!("humaux_thread_c25_leftover_x_{dead}"),
        ];
        for db in &leftovers {
            // Two statements: a multi-statement batch is one implicit transaction, and neither may run inside one.
            admin
                .batch_execute(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)"))
                .expect("clear a stale probe");
            admin
                .batch_execute(&format!("CREATE DATABASE {db}"))
                .expect("plant a leftover");
        }
        let created = throwaway(test, "leftover");
        let mut present = |db: &str| -> bool {
            admin
                .query_one(
                    "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)",
                    &[&db],
                )
                .expect("pg_database")
                .get(0)
        };
        let seen: Vec<bool> = leftovers.iter().map(|db| present(db)).collect();
        drop(created);
        for db in &leftovers {
            admin
                .batch_execute(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)"))
                .expect("remove the planted leftovers");
        }
        assert_eq!(
            seen,
            [false, true, true],
            "dead pid dropped; live pid and other purpose kept"
        );
    }

    fn scalar_bool(client: &mut Client, sql: &str) -> bool {
        client.query_one(sql, &[]).unwrap().get(0)
    }

    fn assert_exact_manifest_boolean(client: &mut Client, field: &str, expected: bool) {
        let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../migrations/0137_project_continuity_read.manifest.toml");
        let manifest: toml::Value =
            toml::from_str(&fs::read_to_string(manifest_path).expect("read exact 0137 manifest"))
                .expect("parse exact 0137 manifest");
        let query = manifest
            .get(field)
            .and_then(toml::Value::as_str)
            .expect("exact 0137 manifest boolean query");
        let rows = client
            .query(query, &[])
            .expect("execute exact manifest query");
        assert_eq!(rows.len(), 1, "{field} must return exactly one row");
        assert_eq!(rows[0].columns().len(), 1, "{field} must return one column");
        assert_eq!(
            *rows[0].columns()[0].type_(),
            Type::BOOL,
            "{field} must return a boolean"
        );
        assert_eq!(rows[0].get::<_, bool>(0), expected, "exact 0137 {field}");
    }

    /// T27 (ADR-0059 D-A): a fresh cluster never gets a placeholder-password role unless the dev flag
    /// says so; an applied 0011 or a cluster that already has every role passes.
    #[test]
    fn placeholder_role_guard_refuses_fresh_cluster_without_dev_flag() {
        let missing = vec!["role_gateway".to_owned()];
        let err = placeholder_role_guard(true, &missing, false).expect_err("fresh cluster");
        assert!(err.contains("missing object: role role_gateway"), "{err}");
        assert!(err.contains("roles rotate --create-missing"), "{err}");
        assert!(placeholder_role_guard(true, &missing, true).is_ok());
        assert!(placeholder_role_guard(false, &missing, false).is_ok());
        assert!(placeholder_role_guard(true, &[], false).is_ok());
    }

    /// The guard reads the role names from the real 0011 body: all eight, names only.
    #[test]
    fn created_role_names_reads_the_eight_0011_roles() {
        let sql = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../migrations/0011_roles_and_grants.sql"),
        )
        .expect("0011 body");
        let names = created_role_names(&sql);
        assert_eq!(names.len(), 8, "{names:?}");
        assert!(names.iter().all(|n| n.starts_with("role_")), "{names:?}");
        assert!(
            names.contains(&"role_migration_owner".to_owned()),
            "{names:?}"
        );
    }

    /// The DB half of T27: on the real cluster 0011's roles all exist, so a pending 0011 passes
    /// without the flag (existing clusters and lane databases are unaffected).
    #[test]
    fn placeholder_role_guard_passes_on_a_cluster_that_has_the_roles() {
        let Some((_db, dsn)) = throwaway("guard", "placeholder_role_guard") else {
            return;
        };
        // dep: PostgreSQL(any) — the throwaway database of this test
        let mut client = Client::connect(&dsn, NoTls).expect("throwaway connect");
        let migrations =
            collect_migrations(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations"))
                .expect("collect");
        check_placeholder_roles(&mut client, &migrations, false)
            .expect("every 0011 role exists cluster-wide");
    }

    /// T27 wiring (ADR-0059 D-A, fault 12(a)): `apply_all` itself consults the guard — a pending
    /// 0011 that would create a role absent from `pg_roles` is refused before anything runs and the
    /// role is not created. The pure-function test above stays green when the guard call inside
    /// `check_placeholder_roles` (or its call in `apply_all`) is dropped; this one goes red.
    #[test]
    fn migrate_refuses_a_pending_roles_migration_whose_role_is_missing() {
        let Some((_db, dsn)) = throwaway("guard_wiring", "guard_wiring") else {
            return;
        };
        let role = format!("role_c33_absent_{}", std::process::id());
        // dep: PostgreSQL(any) — the throwaway database of this test
        let mut client = Client::connect(&dsn, NoTls).expect("throwaway connect");
        let roles = migration(ROLES_MIGRATION, &format!("CREATE ROLE {role} NOLOGIN;"));
        let result = apply_all(&mut client, &[roles], "1s", false);
        let created = scalar_bool(
            &mut client,
            &format!("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}')"),
        );
        if created {
            let _ = client.batch_execute(&format!("DROP ROLE {role}"));
        }
        let err = result.expect_err("a fresh-cluster 0011 is refused without the dev flag");
        assert!(
            err.contains(&format!("missing object: role {role}")),
            "{err}"
        );
        assert!(!created, "the guard must refuse before 0011 creates {role}");
    }

    #[test]
    fn collect_migrations_sorts_by_filename() {
        let dir =
            std::env::temp_dir().join(format!("xtask_migrate_collect_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        write_migration(
            &dir,
            "0002_b",
            "-- second",
            Some(("select true", "select true")),
        );
        write_migration(
            &dir,
            "0001_a",
            "-- first",
            Some(("select true", "select false")),
        );

        // Manifests are loaded beside their `.sql` (ADR-0050 D-D), never applied as
        // migrations themselves: the applied set is the `.sql` files only.
        let migrations = collect_migrations(&dir).expect("dir reads cleanly");
        let ids: Vec<&str> = migrations.iter().map(|m| m.migration_id.as_str()).collect();
        assert_eq!(ids, vec!["0001_a", "0002_b"]);
        assert_eq!(
            migrations[0]
                .manifest
                .as_ref()
                .map(|m| m.postcheck.as_str()),
            Some("select false"),
            "each migration carries its own sibling manifest"
        );

        // A missing manifest is carried as `None` (refused only if pending); an unparsable
        // one is an error naming the file.
        write_migration(&dir, "0003_c", "-- third", None);
        let migrations = collect_migrations(&dir).expect("missing manifest is not a read error");
        assert!(migrations[2].manifest.is_none());
        fs::write(
            dir.join("0003_c.manifest.toml"),
            "migration_id = \"0003_c\"",
        )
        .unwrap();
        let err = collect_migrations(&dir)
            .err()
            .expect("an incomplete manifest must not load");
        assert!(err.contains("0003_c.manifest.toml"), "{err}");

        let _ = fs::remove_dir_all(&dir);
    }

    /// Idempotency + atomicity, live-DB gated (repo CLAUDE.md 硬规则③: skip with a
    /// printed reason, never a silent pass, when `HUMAUX_TEST_PG_DSN` is unset). Runs
    /// against an isolated schema so a failing assertion never pollutes the dev DB's
    /// main schemas (硬规则④).
    #[test]
    fn apply_all_is_idempotent_and_atomic_on_a_bad_file() {
        const TEST: &str = "apply_all_is_idempotent_and_atomic_on_a_bad_file";
        let Some(dsn) = base_dsn(TEST) else { return };
        // dep: PostgreSQL(any) — HUMAUX_TEST_PG_DSN — apply_all against the disposable database.
        let Ok(mut client) = Client::connect(&dsn, NoTls) else {
            skip_or_fail(
                TEST,
                "missing object: live Postgres at HUMAUX_TEST_PG_DSN",
                ExternalDep::Postgres,
            );
            return;
        };

        // `ops.schema_migrations.migration_id` is a real (global, not schema-scoped)
        // primary key shared with the dev DB's actual migration history — reusing a
        // fixed id like "0001_ok" across test runs would find it "already applied" from
        // a *previous* run of this same test and silently break the first-run
        // assertion below. A run-unique suffix keeps this test's rows from colliding
        // with themselves, with real migrations, or with another agent's concurrent
        // run of this same suite against the same shared dev DB.
        let run_id = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let schema = format!("xtask_migrate_fixture_{run_id}");
        client
            .batch_execute(&format!(
                "DROP SCHEMA IF EXISTS {schema} CASCADE; CREATE SCHEMA {schema};"
            ))
            .expect("fixture schema setup");

        let id_ok1 = format!("test_{run_id}_0001_ok");
        let id_ok2 = format!("test_{run_id}_0002_ok");
        let id_bad = format!("test_{run_id}_0003_bad");
        let migrations = vec![
            migration(&id_ok1, &format!("CREATE TABLE {schema}.t (id int)")),
            migration(&id_ok2, &format!("INSERT INTO {schema}.t VALUES (1)")),
        ];

        let (applied, skipped) =
            apply_all(&mut client, &migrations, LOCK_TIMEOUT, false).expect("clean apply");
        assert_eq!((applied, skipped), (2, 0), "first run applies both");
        let migration_table_owner: String = client
            .query_one(
                "SELECT tableowner FROM pg_tables \
                 WHERE schemaname = 'ops' AND tablename = 'schema_migrations'",
                &[],
            )
            .expect("migration ledger owner query")
            .get(0);
        assert_eq!(
            migration_table_owner, "role_migration_owner",
            "migration bootstrap must converge to the Canonical owner once that role exists"
        );

        let (applied, skipped) =
            apply_all(&mut client, &migrations, LOCK_TIMEOUT, false).expect("idempotent re-apply");
        assert_eq!(
            (applied, skipped),
            (0, 2),
            "second run must apply nothing, skip both"
        );

        // Fault injection: a third migration that fails at RUNTIME (not parse time) must
        // roll back its whole batch-execute call and record nothing for it (simple-query
        // implicit transaction atomicity — the module doc's central claim). A syntax error
        // like a stray `THIS IS NOT SQL;` is rejected by the parser for the entire
        // multi-statement string before any statement executes — `to_regclass(u) IS NULL`
        // would then hold trivially because nothing ran, not because rollback undid it,
        // and this test would still pass against a server that wrapped nothing in a
        // transaction. `1/0` only fails once the engine actually executes it, after the
        // preceding CREATE TABLE has already run — only rollback can explain it vanishing.
        let bad = vec![migration(
            &id_bad,
            &format!("CREATE TABLE {schema}.u (id int); INSERT INTO {schema}.u VALUES (1/0);"),
        )];
        let err = apply_all(&mut client, &bad, LOCK_TIMEOUT, false)
            .expect_err("a runtime-failing statement must fail, not silently pass");
        assert!(
            err.contains(&id_bad),
            "error must name the failing migration: {err}"
        );

        let recorded: bool = client
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM ops.schema_migrations WHERE migration_id = $1)",
                &[&id_bad],
            )
            .unwrap()
            .get(0);
        assert!(
            !recorded,
            "failed migration must not be recorded (atomicity)"
        );

        let table_exists: bool = client
            .query_one(
                &format!("SELECT to_regclass('{schema}.u') IS NOT NULL"),
                &[],
            )
            .unwrap()
            .get(0);
        assert!(
            !table_exists,
            "the CREATE TABLE half of the failed batch must have rolled back too"
        );

        client
            .batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
            .expect("fixture cleanup");
        client
            .execute(
                "DELETE FROM ops.schema_migrations WHERE migration_id = ANY($1)",
                &[&vec![id_ok1, id_ok2, id_bad]],
            )
            .expect("fixture cleanup: unrecord this test's own migration ids");
    }

    #[test]
    fn final_0137_candidate_runtime_failure_has_zero_residue() {
        const TEST: &str = "final_0137_candidate_runtime_failure_has_zero_residue";
        let Some((_database, test_dsn)) = throwaway(TEST, "migrate_0137") else {
            return;
        };
        let run_id = std::process::id();

        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let migrations = collect_migrations(&root.join("migrations")).expect("collect migrations");
        let split = migrations
            .iter()
            .position(|migration| migration.migration_id == "0137_project_continuity_read")
            .expect("exact 0137 migration");
        let before = &migrations[..split];
        let exact = &migrations[split];
        assert_eq!(exact.migration_id, "0137_project_continuity_read");
        // dep: PostgreSQL(any) — disposable database — split apply up to 0137.
        let mut client = Client::connect(&test_dsn, NoTls).expect("connect disposable database");
        let (applied, skipped) =
            apply_all(&mut client, before, LOCK_TIMEOUT, false).expect("apply through 0136");
        assert_eq!(
            (applied, skipped),
            (before.len(), 0),
            "fresh through-0136 apply"
        );
        assert_exact_manifest_boolean(&mut client, "precheck", true);

        let probe = format!("w2_0137_probe_{run_id}");
        let failed_id = format!("w2_0137_failed_{run_id}");
        let failed = PendingMigration {
            migration_id: failed_id.clone(),
            sql: format!(
                "{}\nCREATE TABLE {probe} (id integer);\nSELECT 1/0;",
                exact.sql
            ),
            manifest: exact.manifest.clone(),
            transaction: None,
            accepted_prior_checksums: Vec::new(),
        };
        let error = apply_all(&mut client, &[failed], LOCK_TIMEOUT, false)
            .expect_err("exact 0137 candidate must fail");
        assert!(
            error.contains(&failed_id),
            "failure names exact candidate: {error}"
        );
        let residue = client
            .query_one(
                "SELECT \
                   to_regprocedure('private.read_continuity_project_storage_v1(uuid,uuid,uuid,uuid,uuid,uuid[])') IS NULL, \
                   to_regclass($1) IS NULL, \
                   NOT EXISTS (SELECT 1 FROM ops.schema_migrations WHERE migration_id=$2)",
                &[&probe, &failed_id],
            )
            .expect("candidate residue query");
        assert!(
            residue.get::<_, bool>(0),
            "0137 reader function must roll back"
        );
        assert!(residue.get::<_, bool>(1), "post-body probe must roll back");
        assert!(
            residue.get::<_, bool>(2),
            "failed candidate must not enter ledger"
        );

        let (applied, skipped) = apply_all(
            &mut client,
            std::slice::from_ref(exact),
            LOCK_TIMEOUT,
            false,
        )
        .expect("apply untouched exact 0137");
        assert_eq!((applied, skipped), (1, 0), "untouched 0137 applies once");
        assert_exact_manifest_boolean(&mut client, "postcheck", true);
        // Migrations authored after 0137 must be applied before the replay assertion below.
        // Without this the test silently encodes "0137 is the last migration on disk": every
        // later migration would show up as a fresh apply during the replay and turn the
        // zero-apply assertion red for a reason that has nothing to do with 0137's residue.
        let after = &migrations[split + 1..];
        let (applied, skipped) = apply_all(&mut client, after, LOCK_TIMEOUT, false)
            .expect("apply migrations authored after 0137");
        assert_eq!(
            (applied, skipped),
            (after.len(), 0),
            "post-0137 migrations apply exactly once"
        );
        let (applied, skipped) = apply_all(&mut client, &migrations, LOCK_TIMEOUT, false)
            .expect("replay exact migration set");
        assert_eq!(
            (applied, skipped),
            (0, migrations.len()),
            "replay is zero-apply"
        );
    }

    /// ADR-0050 D-D stop condition: a fresh database built 0001→head with every manifest's
    /// precheck (in its migration's PRE-state) and postcheck executed. This is the only place
    /// the prechecks are proven true where they are meant to hold.
    #[test]
    fn migrate_throwaway_db_applies_0001_to_head_executing_every_manifest_check() {
        const TEST: &str =
            "migrate_throwaway_db_applies_0001_to_head_executing_every_manifest_check";
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let migrations = collect_migrations(&root.join("migrations")).expect("collect migrations");
        assert!(
            migrations.len() >= 143,
            "the repo holds at least the 143 migrations of 2026-09-26, got {}",
            migrations.len()
        );
        let missing: Vec<&str> = migrations
            .iter()
            .filter(|m| m.manifest.is_none())
            .map(|m| m.migration_id.as_str())
            .collect();
        assert!(
            missing.is_empty(),
            "migrations without a manifest: {missing:?}"
        );
        let Some((_db, dsn)) = throwaway(TEST, "migrate_head") else {
            return;
        };
        // dep: PostgreSQL(any) — throwaway c25 database — apply 0001→head executing every manifest check.
        let mut client = Client::connect(&dsn, NoTls).expect("connect throwaway");
        let started = Instant::now();
        let (applied, skipped) = apply_all(&mut client, &migrations, LOCK_TIMEOUT, false)
            .unwrap_or_else(|e| panic!("0001→head with every manifest check: {e}"));
        eprintln!(
            "migrate test: 0001→head applied {applied} migrations, {} checks, in {:.1}s",
            2 * applied,
            started.elapsed().as_secs_f64()
        );
        assert_eq!((applied, skipped), (migrations.len(), 0));
        let recorded: i64 = client
            .query_one("SELECT count(*) FROM ops.schema_migrations", &[])
            .unwrap()
            .get(0);
        assert_eq!(
            recorded as usize,
            migrations.len(),
            "one ledger row per migration"
        );
    }

    /// A false postcheck and an invalid-SQL precheck each refuse their migration, name the
    /// check and carry the reason, and leave drift 0 (no object, no ledger row).
    #[test]
    fn migrate_refuses_false_postcheck_and_invalid_check_sql_with_drift_0() {
        const TEST: &str = "migrate_refuses_false_postcheck_and_invalid_check_sql_with_drift_0";
        let Some((_db, dsn)) = throwaway(TEST, "migrate_refuse") else {
            return;
        };
        // dep: PostgreSQL(any) — throwaway c25 database — refusal on false/invalid scratch checks.
        let mut client = Client::connect(&dsn, NoTls).expect("connect throwaway");
        let cases = [
            (
                "false_post",
                "select true",
                "select false",
                "postcheck",
                "returned false",
            ),
            (
                "invalid_pre",
                "selec true",
                "select true",
                "precheck",
                "syntax error",
            ),
        ];
        for (purpose, pre, post, field, reason) in cases {
            let dir = scratch_dir(purpose);
            let stem = format!("0001_c25_{purpose}");
            let table = format!("c25_scratch_{purpose}");
            write_migration(
                &dir,
                &stem,
                &format!("CREATE TABLE {table} (id int)"),
                Some((pre, post)),
            );
            let migrations = collect_migrations(&dir).expect("scratch dir");
            let err = apply_all(&mut client, &migrations, LOCK_TIMEOUT, false)
                .expect_err("a failing check must refuse the migration");
            assert!(
                err.contains(&stem) && err.contains(field) && err.contains(reason),
                "{purpose}: error must name the migration, the check and the reason: {err}"
            );
            assert!(
                scalar_bool(
                    &mut client,
                    &format!(
                        "SELECT to_regclass('{table}') IS NULL AND NOT EXISTS \
                         (SELECT 1 FROM ops.schema_migrations WHERE migration_id = '{stem}')"
                    )
                ),
                "{purpose}: drift must be 0 — no object, no ledger row"
            );
            let _ = fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn migrate_refuses_non_boolean_check() {
        const TEST: &str = "migrate_refuses_non_boolean_check";
        let Some((_db, dsn)) = throwaway(TEST, "migrate_nonbool") else {
            return;
        };
        // dep: PostgreSQL(any) — throwaway c25 database — refusal on a non-boolean check.
        let mut client = Client::connect(&dsn, NoTls).expect("connect throwaway");
        let mut m = migration("0001_c25_nonbool", "CREATE TABLE c25_nonbool (id int)");
        m.manifest = Some(manifest(&m.migration_id, "select 1", "select true"));
        let err =
            apply_all(&mut client, &[m], LOCK_TIMEOUT, false).expect_err("int is not a verdict");
        assert!(
            err.contains("precheck") && err.contains("expected bool"),
            "{err}"
        );
        assert!(scalar_bool(
            &mut client,
            "SELECT to_regclass('c25_nonbool') IS NULL"
        ));
    }

    #[test]
    fn migrate_refuses_pending_migration_without_manifest() {
        const TEST: &str = "migrate_refuses_pending_migration_without_manifest";
        let dir = scratch_dir("nomanifest");
        write_migration(
            &dir,
            "0001_c25_nomanifest",
            "CREATE TABLE c25_nomanifest (id int)",
            None,
        );
        let migrations = collect_migrations(&dir).expect("scratch dir");
        let Some((_db, dsn)) = throwaway(TEST, "migrate_nomanifest") else {
            return;
        };
        // dep: PostgreSQL(any) — throwaway c25 database — apply_all under the advisory lock.
        let mut client = Client::connect(&dsn, NoTls).expect("connect throwaway");
        let err = apply_all(&mut client, &migrations, LOCK_TIMEOUT, false)
            .expect_err("a pending migration without a manifest is refused");
        assert!(err.contains("no manifest"), "{err}");
        assert!(scalar_bool(
            &mut client,
            "SELECT to_regclass('c25_nomanifest') IS NULL AND NOT EXISTS \
             (SELECT 1 FROM ops.schema_migrations WHERE migration_id = '0001_c25_nomanifest')"
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    /// Writes `<stem>.sql` + a manifest carrying `transaction = <tx>` (ADR-0052 D-G).
    fn write_migration_tx(dir: &Path, stem: &str, sql: &str, tx: &str) {
        fs::write(dir.join(format!("{stem}.sql")), sql).unwrap();
        fs::write(
            dir.join(format!("{stem}.manifest.toml")),
            format!(
                "migration_id = \"{stem}\"\nclass = \"REVERSIBLE\"\ntransaction = {tx}\n\
                 precheck = \"select true\"\npostcheck = \"select true\"\n\
                 rollback_or_forward_fix = \"test\"\nbackup_restore_requirement = \"test\"\n"
            ),
        )
        .unwrap();
    }

    /// ADR-0052 D-G: a `transaction = "none"` file builds its CONCURRENTLY index outside any
    /// transaction block, is recorded once, and is idempotent. Fault injection: the identical body
    /// WITHOUT the key goes through the default transactional path and PostgreSQL refuses it
    /// (25001), drift 0 — which is exactly why the key exists.
    #[test]
    fn migrate_applies_a_transaction_none_concurrent_index_outside_a_transaction() {
        const TEST: &str =
            "migrate_applies_a_transaction_none_concurrent_index_outside_a_transaction";
        let Some((_db, dsn)) = throwaway(TEST, "migrate_txnone") else {
            return;
        };
        // dep: PostgreSQL(any) — throwaway c25 database — transaction = "none" CIC apply.
        let mut client = Client::connect(&dsn, NoTls).expect("connect throwaway");
        let dir = scratch_dir("txnone");
        write_migration(
            &dir,
            "0001_c27_table",
            "CREATE TABLE c27_t (id int, v int)",
            Some(("select true", "select true")),
        );
        let cic = "-- one statement\nCREATE INDEX CONCURRENTLY c27_t_v_idx ON c27_t (v);";
        // the fault first: same body, default (transactional) path
        write_migration(
            &dir,
            "0002_c27_cic",
            cic,
            Some(("select true", "select true")),
        );
        let migrations = collect_migrations(&dir).expect("scratch dir");
        let err = apply_all(&mut client, &migrations, LOCK_TIMEOUT, false)
            .expect_err("CIC inside a transaction block must be refused by the server");
        assert!(
            err.contains("0002_c27_cic") && err.contains("25001"),
            "{err}"
        );
        assert!(scalar_bool(
            &mut client,
            "SELECT to_regclass('c27_t_v_idx') IS NULL AND NOT EXISTS \
             (SELECT 1 FROM ops.schema_migrations WHERE migration_id = '0002_c27_cic')"
        ));
        // the key: the same file now applies outside a transaction
        write_migration_tx(&dir, "0002_c27_cic", cic, "\"none\"");
        let migrations = collect_migrations(&dir).expect("scratch dir");
        assert_eq!(migrations[1].transaction.as_deref(), Some("none"));
        let (applied, skipped) = apply_all(&mut client, &migrations, LOCK_TIMEOUT, false)
            .expect("transaction=none applies");
        assert_eq!((applied, skipped), (1, 1));
        assert!(scalar_bool(
            &mut client,
            "SELECT coalesce((SELECT indisvalid FROM pg_index \
                              WHERE indexrelid = to_regclass('c27_t_v_idx')), false) \
             AND (SELECT count(*) = 1 FROM ops.schema_migrations WHERE migration_id = '0002_c27_cic')"
        ));
        assert_eq!(
            apply_all(&mut client, &migrations, LOCK_TIMEOUT, false).expect("replay"),
            (0, 2),
            "a second run applies nothing"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// ADR-0052 D-G: `transaction = "none"` is not a way to escape atomicity for ordinary DDL — a
    /// body without CONCURRENTLY (outside comments) is refused before any statement runs.
    #[test]
    fn migrate_refuses_transaction_none_without_concurrently_with_drift_0() {
        const TEST: &str = "migrate_refuses_transaction_none_without_concurrently_with_drift_0";
        let Some((_db, dsn)) = throwaway(TEST, "migrate_txnone_plain") else {
            return;
        };
        // dep: PostgreSQL(any) — throwaway c25 database — refusal of a non-CONCURRENTLY transaction = "none" body.
        let mut client = Client::connect(&dsn, NoTls).expect("connect throwaway");
        let dir = scratch_dir("txnone_plain");
        write_migration_tx(
            &dir,
            "0001_c27_plain",
            "-- CONCURRENTLY only in a comment\nCREATE TABLE c27_plain (id int);",
            "\"none\"",
        );
        let migrations = collect_migrations(&dir).expect("scratch dir");
        let err = apply_all(&mut client, &migrations, LOCK_TIMEOUT, false)
            .expect_err("a non-CONCURRENTLY transaction=none body is refused");
        assert!(
            err.contains("0001_c27_plain") && err.contains("requires a CONCURRENTLY body"),
            "{err}"
        );
        assert!(scalar_bool(
            &mut client,
            "SELECT to_regclass('c27_plain') IS NULL AND NOT EXISTS \
             (SELECT 1 FROM ops.schema_migrations WHERE migration_id = '0001_c27_plain')"
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    /// ADR-0052 D-G: the only accepted `transaction` value is "none"; anything else (another
    /// string, a boolean) refuses the migration with drift 0.
    #[test]
    fn migrate_refuses_an_unknown_transaction_value() {
        const TEST: &str = "migrate_refuses_an_unknown_transaction_value";
        let Some((_db, dsn)) = throwaway(TEST, "migrate_txunknown") else {
            return;
        };
        // dep: PostgreSQL(any) — throwaway c25 database — refusal of an unknown transaction value.
        let mut client = Client::connect(&dsn, NoTls).expect("connect throwaway");
        for (purpose, value) in [("auto", "\"auto\""), ("bool", "false")] {
            let dir = scratch_dir(&format!("txunknown_{purpose}"));
            let stem = format!("0001_c27_{purpose}");
            write_migration_tx(
                &dir,
                &stem,
                &format!(
                    "CREATE INDEX CONCURRENTLY c27_{purpose}_idx ON ops.schema_migrations (checksum)"
                ),
                value,
            );
            let migrations = collect_migrations(&dir).expect("scratch dir");
            let err = apply_all(&mut client, &migrations, LOCK_TIMEOUT, false)
                .expect_err("an unknown transaction value is refused");
            assert!(
                err.contains(&stem) && err.contains("the only accepted value"),
                "{purpose}: {err}"
            );
            let index = format!("{}.c27_{purpose}_idx", "ops");
            assert!(scalar_bool(
                &mut client,
                &format!(
                    "SELECT to_regclass('{index}') IS NULL AND NOT EXISTS \
                     (SELECT 1 FROM ops.schema_migrations WHERE migration_id = '{stem}')"
                )
            ));
            let _ = fs::remove_dir_all(&dir);
        }
    }

    /// ADR-0050 D-F: while client A holds HXMIGRAT, client B's migrate refuses with 55P03 and
    /// records nothing; after A releases, B applies. Two concurrent migrators on a slow
    /// migration apply each id exactly once.
    #[test]
    fn migrate_advisory_lock_second_client_waits_or_refuses_with_drift_0() {
        const TEST: &str = "migrate_advisory_lock_second_client_waits_or_refuses_with_drift_0";
        let Some((_db, dsn)) = throwaway(TEST, "migrate_lock") else {
            return;
        };
        // dep: PostgreSQL(any) — throwaway c25 database — client A holds HXMIGRAT.
        let mut a = Client::connect(&dsn, NoTls).expect("client A");
        // dep: PostgreSQL(any) — throwaway c25 database — client B must wait or refuse with drift 0.
        let mut b = Client::connect(&dsn, NoTls).expect("client B");
        a.execute("SELECT pg_advisory_lock($1)", &[&MIGRATE_ADVISORY_LOCK])
            .expect("A takes HXMIGRAT");
        let ms = [migration("0001_c25_lock", "CREATE TABLE c25_lock (id int)")];
        let err = apply_all(&mut b, &ms, "1s", false).expect_err("B must not interleave with A");
        assert!(err.contains("55P03") && err.contains("0 applied"), "{err}");
        assert!(
            scalar_bool(&mut b, "SELECT to_regclass('c25_lock') IS NULL"),
            "B refused before touching anything: drift 0"
        );
        a.execute("SELECT pg_advisory_unlock($1)", &[&MIGRATE_ADVISORY_LOCK])
            .expect("A releases");
        assert_eq!(
            apply_all(&mut b, &ms, "1s", false).expect("B applies after A"),
            (1, 0)
        );

        // Two real migrators racing on a slow migration: the lock serialises them, so one
        // applies and the other finds it recorded.
        let slow = vec![migration(
            "0002_c25_slow",
            "SELECT pg_sleep(2); CREATE TABLE c25_slow (id int)",
        )];
        let racers: Vec<_> = (0..2)
            .map(|_| {
                let dsn = dsn.clone();
                let slow = slow.clone();
                std::thread::spawn(move || {
                    // dep: PostgreSQL(any) — throwaway c25 database — one of the concurrent migrate racers.
                    let mut c = Client::connect(&dsn, NoTls).expect("racer connects");
                    apply_all(&mut c, &slow, LOCK_TIMEOUT, false)
                })
            })
            .collect();
        let mut outcomes: Vec<(usize, usize)> = racers
            .into_iter()
            .map(|r| {
                r.join()
                    .expect("racer thread")
                    .expect("racer applies or skips")
            })
            .collect();
        outcomes.sort_unstable();
        assert_eq!(
            outcomes,
            vec![(0, 1), (1, 0)],
            "exactly one apply of 0002_c25_slow"
        );
        let rows: i64 = b
            .query_one(
                "SELECT count(*) FROM ops.schema_migrations WHERE migration_id = '0002_c25_slow'",
                &[],
            )
            .unwrap()
            .get(0);
        assert_eq!(rows, 1);
    }

    /// A scratch directory holding one trivial migration `<purpose>_probe` that creates table `c39_<purpose>_probe`.
    fn one_migration_dir(purpose: &str) -> PathBuf {
        let dir = scratch_dir(purpose);
        write_migration(
            &dir,
            &format!("0001_{purpose}_probe"),
            &format!("CREATE TABLE c39_{purpose}_probe (id int)"),
            Some(("select true", "select true")),
        );
        dir
    }

    /// A live `role_gateway` session on `dsn`'s database (ADR-0059 D-D real login), or a `skip_or_fail`.
    fn gateway_session(test: &str, dsn: &str) -> Option<Client> {
        let login = match humaux_testkit::role_login_dsn(dsn, "role_gateway", |name| {
            std::env::var(name).ok()
        }) {
            Ok(login) => login,
            Err(missing) => {
                skip_or_fail(
                    test,
                    &format!("missing object: {missing}"),
                    ExternalDep::Postgres,
                );
                return None;
            }
        };
        // dep: PostgreSQL(role_gateway) — an idle runtime session the live-session refusal must see (or ignore)
        Some(Client::connect(&login, NoTls).expect("role_gateway login"))
    }

    /// A second disposable database `humaux_thread_c39_<purpose>_<pid>`, dropped `WITH (FORCE)` on drop. Created
    /// while the caller already holds a `throwaway` guard (and so the cluster-DDL lock, which is not re-entrant).
    struct SecondDatabase {
        admin_dsn: String,
        name: String,
    }

    impl SecondDatabase {
        fn create(admin_dsn: &str, purpose: &str) -> Self {
            let name = format!("humaux_thread_c39_{purpose}_{}", std::process::id());
            // dep: PostgreSQL(any) — superuser from HUMAUX_TEST_PG_DSN — CREATE/DROP DATABASE.
            let mut admin = Client::connect(admin_dsn, NoTls).expect("admin connect");
            admin
                .batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
                .expect("drop a leftover of this pid");
            admin
                .batch_execute(&format!("CREATE DATABASE {name}"))
                .expect("create the second database");
            Self {
                admin_dsn: admin_dsn.to_owned(),
                name,
            }
        }
    }

    impl Drop for SecondDatabase {
        fn drop(&mut self) {
            // dep: PostgreSQL(any) — superuser from HUMAUX_TEST_PG_DSN — DROP DATABASE of the second database.
            let dropped = Client::connect(&self.admin_dsn, NoTls).and_then(|mut admin| {
                admin.batch_execute(&format!(
                    "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                    self.name
                ))
            });
            if let Err(e) = dropped {
                eprintln!("second database {}: drop failed: {e}", self.name);
            }
        }
    }

    fn migrate_args(dsn: &str, dir: &Path) -> Vec<String> {
        vec![
            "--dsn".to_owned(),
            dsn.to_owned(),
            "--migrations-dir".to_owned(),
            dir.display().to_string(),
        ]
    }

    /// ADR-0066 D-Q (OPS-9): a `role_gateway` session in the target database refuses the run with exit 3, the
    /// refusal names the role, and nothing is applied. Fault: skip the `pg_stat_activity` query (return an empty
    /// list) ⇒ exit 0 and the probe table exists ⇒ red.
    #[test]
    fn live_runtime_session_refuses() {
        const TEST: &str = "live_runtime_session_refuses";
        let Some((_db, dsn)) = throwaway(TEST, "c39_live") else {
            return;
        };
        let Some(_gateway) = gateway_session(TEST, &dsn) else {
            return;
        };
        let dir = one_migration_dir("live");
        // dep: PostgreSQL(any) — superuser on the throwaway: the refusal's own query and the drift-0 check
        let mut owner = Client::connect(&dsn, NoTls).expect("owner connect");
        assert_eq!(
            live_runtime_sessions(&mut owner).expect("live-session query"),
            vec!["role_gateway=1".to_owned()],
            "the session is named with its count"
        );
        assert_eq!(
            run(&migrate_args(&dsn, &dir)),
            3,
            "a live runtime session refuses the migrate"
        );
        assert!(
            scalar_bool(&mut owner, "SELECT to_regclass('c39_live_probe') IS NULL"),
            "a refused run applies nothing"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// ADR-0066 D-Q / RF-16: a runtime session in ANOTHER database of the cluster does not refuse this database's
    /// migrate (the dev chain migrates throwaways while its gateway is connected to the dev database). Fault: drop the
    /// `datname = current_database()` filter ⇒ the other database's session refuses ⇒ exit 3 ⇒ red.
    #[test]
    fn live_session_in_another_database_is_ignored() {
        const TEST: &str = "live_session_in_another_database_is_ignored";
        let Some((_db, dsn)) = throwaway(TEST, "c39_target") else {
            return;
        };
        let Some(base) = base_dsn(TEST) else {
            return;
        };
        let other = SecondDatabase::create(&base, "other");
        let Some(_gateway) = gateway_session(TEST, &database_dsn(&base, &other.name)) else {
            return;
        };
        let dir = one_migration_dir("other");
        assert_eq!(
            run(&migrate_args(&dsn, &dir)),
            0,
            "a session in another database is not this database's live traffic"
        );
        // dep: PostgreSQL(any) — superuser on the throwaway: the migration was applied
        let mut owner = Client::connect(&dsn, NoTls).expect("owner connect");
        assert!(scalar_bool(
            &mut owner,
            "SELECT to_regclass('c39_other_probe') IS NOT NULL"
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    /// Writes `<stem>.sql` and a full manifest whose `accepted_prior_checksums` names each of `prior` (ADR-0082).
    fn write_amendable(dir: &Path, stem: &str, sql: &str, prior: &[&str]) {
        fs::write(dir.join(format!("{stem}.sql")), sql).unwrap();
        let list: String = prior
            .iter()
            .map(|c| format!("{{ checksum = \"{c}\", reason = \"test amendment\" }}, "))
            .collect();
        fs::write(
            dir.join(format!("{stem}.manifest.toml")),
            format!(
                "migration_id = \"{stem}\"\nclass = \"FORWARD_ONLY\"\n\
                 precheck = \"select true\"\npostcheck = \"select true\"\n\
                 rollback_or_forward_fix = \"test\"\nbackup_restore_requirement = \"test\"\n\
                 accepted_prior_checksums = [{list}]\n"
            ),
        )
        .unwrap();
    }

    const AMEND_STEM: &str = "0001_adr0082_amend";
    const AMEND_V1: &str = "CREATE TABLE adr0082_t (id int)";
    /// The same statement behind a new comment: an amendment with no schema effect.
    const AMEND_V2: &str = "-- amended: comment only\nCREATE TABLE adr0082_t (id int)";

    /// Applies [`AMEND_V1`] to the client's database and returns the checksum the ledger recorded for it.
    fn apply_amend_v1(client: &mut Client, dir: &Path) -> String {
        write_amendable(dir, AMEND_STEM, AMEND_V1, &[]);
        let migrations = collect_migrations(dir).expect("scratch dir");
        assert_eq!(
            apply_all(client, &migrations, LOCK_TIMEOUT, false).expect("v1 applies"),
            (1, 0)
        );
        let (recorded, _) = amend_ledger_row(client);
        assert_eq!(recorded, fnv1a_hex(AMEND_V1.as_bytes()));
        recorded
    }

    /// The fixture's ledger row as `(checksum, xmin)`: any UPDATE of it, even to the same value, changes `xmin`.
    fn amend_ledger_row(client: &mut Client) -> (String, String) {
        let row = client
            .query_one(
                "SELECT checksum, xmin::text FROM ops.schema_migrations WHERE migration_id = $1",
                &[&AMEND_STEM],
            )
            .expect("the fixture's ledger row");
        (row.get(0), row.get(1))
    }

    /// ADR-0082 gate 1a: a recorded checksum listed in the file's `accepted_prior_checksums` is accepted (nothing
    /// applied, one skipped), on every replay, and the recorded row is never rewritten. Fault: rewrite the row on
    /// acceptance ⇒ the `xmin`/checksum comparison is red.
    #[test]
    fn a_listed_prior_checksum_is_accepted_and_the_recorded_row_is_never_rewritten() {
        const TEST: &str =
            "a_listed_prior_checksum_is_accepted_and_the_recorded_row_is_never_rewritten";
        let Some((_db, dsn)) = throwaway(TEST, "migrate_amend_ok") else {
            return;
        };
        // dep: PostgreSQL(any) — throwaway c25 database — a listed prior checksum is accepted, the ledger row stays.
        let mut client = Client::connect(&dsn, NoTls).expect("connect throwaway");
        let dir = scratch_dir("amend_ok");
        let v1 = apply_amend_v1(&mut client, &dir);
        let before = amend_ledger_row(&mut client);
        write_amendable(&dir, AMEND_STEM, AMEND_V2, &[&v1]);
        let migrations = collect_migrations(&dir).expect("scratch dir");
        assert_ne!(fnv1a_hex(AMEND_V2.as_bytes()), v1, "the bytes changed");
        for run in 1..=2 {
            assert_eq!(
                apply_all(&mut client, &migrations, LOCK_TIMEOUT, false)
                    .expect("a listed prior checksum is accepted"),
                (0, 1),
                "run {run}: nothing applied, the amended migration skipped"
            );
            assert_eq!(
                amend_ledger_row(&mut client),
                before,
                "run {run}: the recorded row is untouched"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// ADR-0082 gate 1b: drift the file does not list is refused with the existing message, whether the list is
    /// empty, names another checksum, or names the old one while the database holds a forged value. Fault: accept any
    /// drift ⇒ the first `expect_err` is red.
    #[test]
    fn an_unlisted_drift_is_refused_with_the_existing_message() {
        const TEST: &str = "an_unlisted_drift_is_refused_with_the_existing_message";
        let Some((_db, dsn)) = throwaway(TEST, "migrate_amend_drift") else {
            return;
        };
        // dep: PostgreSQL(any) — throwaway c25 database — drift the file does not list is refused.
        let mut client = Client::connect(&dsn, NoTls).expect("connect throwaway");
        let dir = scratch_dir("amend_drift");
        let v1 = apply_amend_v1(&mut client, &dir);
        let v2 = fnv1a_hex(AMEND_V2.as_bytes());
        let refused = |client: &mut Client, dir: &Path, what: &str| {
            let migrations = collect_migrations(dir).expect("scratch dir");
            let err = apply_all(client, &migrations, LOCK_TIMEOUT, false)
                .expect_err(&format!("{what}: drift must stop the run"));
            assert!(
                err.contains(&format!("{AMEND_STEM}: drift detected"))
                    && err.contains(&format!("file's checksum {v2} does not match recorded"))
                    && err.contains("add a new migration instead of editing this one"),
                "{what}: {err}"
            );
        };
        write_amendable(&dir, AMEND_STEM, AMEND_V2, &[]);
        refused(&mut client, &dir, "an empty list");
        write_amendable(&dir, AMEND_STEM, AMEND_V2, &["ffffffffffffffff"]);
        refused(&mut client, &dir, "a list naming another checksum");
        // dep: PostgreSQL(any) — superuser on the throwaway: forge the recorded row, which the list cannot excuse
        client
            .execute(
                "UPDATE ops.schema_migrations SET checksum = 'eeeeeeeeeeeeeeee' WHERE migration_id = $1",
                &[&AMEND_STEM],
            )
            .expect("forge the row");
        write_amendable(&dir, AMEND_STEM, AMEND_V2, &[&v1]);
        refused(&mut client, &dir, "a forged row outside the list");
        assert_eq!(
            amend_ledger_row(&mut client).0,
            "eeeeeeeeeeeeeeee",
            "a refusal leaves the row as it found it"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// ADR-0082: the operator line names the migration, both checksums and the reason, on one line.
    #[test]
    fn the_amendment_notice_names_the_migration_both_checksums_and_the_reason() {
        let line = amended_notice("0228_x", "aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", "the why");
        for needle in ["0228_x", "aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", "the why"] {
            assert!(line.contains(needle), "{needle}: {line}");
        }
        assert_eq!(line.lines().count(), 1, "{line}");
    }

    /// ADR-0082: only 0228 and 0229 are amended in this tree, and a listed checksum is an OLDER body's: one equal to
    /// the file's own would mean the list was computed after the edit and names nothing a database holds. A new
    /// amendment adds its id here, which puts it in front of the reviewer (ADR-0082 D-D).
    #[test]
    fn the_amended_migrations_list_checksums_that_are_not_their_own() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
        let set = collect_migrations(&dir).expect("migrations dir");
        let amended: Vec<&str> = set
            .iter()
            .filter(|m| !m.accepted_prior_checksums.is_empty())
            .map(|m| m.migration_id.as_str())
            .collect();
        assert_eq!(
            amended,
            ["0228_partition_events", "0229_partition_audit_events"]
        );
        for m in &set {
            for prior in &m.accepted_prior_checksums {
                assert_ne!(
                    prior.checksum,
                    fnv1a_hex(m.sql.as_bytes()),
                    "{}: the listed checksum is the file's own",
                    m.migration_id
                );
            }
        }
    }

    /// ADR-0066 D-Q: the set `build.rs` embedded is the `migrations/` directory, file for file and byte for byte
    /// (same ids, same order, same checksums, same manifests). Fault: skip the manifests in `build.rs` ⇒ red.
    #[test]
    fn embedded_set_equals_the_migrations_directory() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
        let on_disk = collect_migrations(&dir).expect("migrations dir");
        let embedded = collect_embedded().expect("embedded set");
        let shape = |set: &[PendingMigration]| -> Vec<(String, String, Option<String>)> {
            set.iter()
                .map(|m| {
                    (
                        m.migration_id.clone(),
                        fnv1a_hex(m.sql.as_bytes()),
                        m.manifest.as_ref().map(|x| x.precheck.clone()),
                    )
                })
                .collect()
        };
        assert!(!on_disk.is_empty());
        assert_eq!(shape(&embedded), shape(&on_disk));
    }
}

//! `xtask::load_open` — `cargo xtask load-open`: open-loop (constant-arrival) load against one gateway, the X-BASE measurement of M03.
//! Depends-on: crates=[postgres, serde_json]; services=[PostgreSQL(any)]; env=[]; modules=[xtask::load, xtask::soak]
//! Called-by: [xtask::main]
//! Invariants: [arrivals are scheduled on the clock, never on the previous response, so latency is taken from the
//!   intended start and a slow gateway cannot thin the offered load; an arrival that finds every worker busy and the
//!   queue full is a dropped iteration, never retried; the closed-loop mode exists to show it reports dropped
//!   iterations at overload; every XBASE line carries n, unit, host= and measured_at_unix=; a missing database
//!   object prints XBASE_NOT_APPLICABLE with its name; the database session is READ ONLY and reads pg_stat_database,
//!   pg_stat_statements and the WAL position only; bearers come from the identities file and are never printed]
//! Spec: Baseline §67.2; §72.3; §78.1; ADR-0065
//!
//! Card M03-1 (module design M03, experiment X-BASE). `xtask::load` is closed-loop: a client sends its next call when
//! the previous one returns, so a stalled gateway receives less load exactly when it is slowest (coordinated omission).
//! This harness fixes the arrival rate per user (`--rate-per-user` x users) and measures each call from its intended
//! start. Users x identities: the identities file lists `<user>\t<workspace_uuid>\t<bearer>` rows; a level takes the
//! first N users and cycles each user's identities, so 80 agents of one user share one tenant and one `Forwarded` /64.
//!
//! Per level it prints and records: scheduled / issued / dropped iterations, outcomes, p50/p95/p99 per op class
//! (admitted 2xx only, after warm-up), and the database deltas per answered call: commits (txns/op), WAL bytes,
//! `pg_stat_statements` calls and `total_exec_time` (executor wall time, not CPU: the extension has no CPU column).
//! The deltas cover warm-up too and the denominator is every call that received an answer: a NoAnswer (reset, EOF or
//! socket timeout) is not an answer, so it stays out of the denominator (§57.1). Backends report statistics at most
//! once a second (PG `PGSTAT_MIN_INTERVAL`) and an idle one defers up to 10 s, so `--settle-secs` (validated >= 1) is
//! slept after connecting (one throwaway snapshot first, so level 1 starts from flushed counters) and again before each
//! level's second snapshot; set it to 10 when the gateway pool idles. The first snapshot's own commits land inside
//! the delta and are subtracted for commits, left in for statements. A negative delta or zero answered calls prints NA
//! with an `XBASE_NOT_APPLICABLE` line naming the cause, never a number.
//!
//! The HTTP client, credential and request builder are `xtask::load`'s (visibility-only change, card M03-1).
//! Ops are the two the closed-loop harness uses (`memory.enumerate`, `tools/list`): neither reaches a provider, the
//! outbox or Qdrant, so a run spends no money. `--ops enumerate|tools_list` runs one class alone for per-class
//! txns/op. §78.1: every number is a flag (the 7/10 enumerate share of `mixed` included); the identities and the
//! report are files.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, sync_channel};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use postgres::{Client, NoTls};

use crate::load::{Conn, Key, Op, Outcome, Target, outcome_of, request};
use crate::soak::percentile;

const USAGE: &str = "usage: cargo xtask load-open \
--gateway-url http://HOST:PORT/mcp --identities <tsv> --users <n,n,..> --identities-per-user <n> \
--rate-per-user <calls/s> --warmup-secs <n> --secs <n> --settle-secs <n> --workers <n> --queue <n> \
--io-timeout-secs <n> --enumerate-tenths <0..=10> --mode <open|closed> --ops <mixed|enumerate|tools_list> --pg-dsn-env <VAR> --report <path> \
[--host-class <name>]";

/// Op classes by index; `mixed` sends `enumerate` for `--enumerate-tenths` of every 10 arrivals (7 matches `xtask::load`).
const OPS: [&str; 2] = ["enumerate", "tools_list"];

/// Arrival discipline: `Open` schedules on the clock; `Closed` sends the next call when the last returned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Open,
    Closed,
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Mode::Open => "open",
            Mode::Closed => "closed",
        }
    }
}

/// Parsed flags.
struct Config {
    target: Target,
    users: Vec<usize>,
    per_user: usize,
    rate_per_user: f64,
    warmup: Duration,
    window: Duration,
    settle: Duration,
    enumerate_tenths: u64,
    workers: usize,
    queue: usize,
    mode: Mode,
    only: Option<usize>,
    pg_dsn: String,
    host_class: Option<String>,
    report_path: String,
    ids: Vec<Vec<Key>>,
}

fn flag<T: std::str::FromStr>(args: &[String], name: &str) -> Result<T, String>
where
    T::Err: std::fmt::Display,
{
    let i = args
        .iter()
        .position(|a| a == name)
        .ok_or_else(|| format!("missing required flag {name} (§78.1: no default)"))?;
    let raw = args.get(i + 1).ok_or_else(|| format!("{name}: no value"))?;
    raw.parse::<T>().map_err(|e| format!("{name} {raw}: {e}"))
}

/// `http://HOST:PORT/path` -> (`HOST:PORT`, `/path`).
fn split_url(url: &str) -> Result<(String, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("{url}: only http:// loopback URLs are supported"))?;
    let (host_port, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    Ok((
        host_port.to_string(),
        if path.is_empty() { "/" } else { path }.to_string(),
    ))
}

/// Rows `<user>\t<workspace>\t<bearer>`, grouped by user in order of first appearance.
fn parse_identities(text: &str) -> Result<Vec<Vec<Key>>, String> {
    let mut order: Vec<String> = Vec::new();
    let mut by_user: BTreeMap<String, Vec<Key>> = BTreeMap::new();
    for (n, line) in text
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
    {
        let mut f = line.split('\t');
        match (f.next(), f.next(), f.next(), f.next()) {
            (Some(u), Some(w), Some(b), None)
                if !u.is_empty() && !w.is_empty() && !b.is_empty() =>
            {
                if !by_user.contains_key(u) {
                    order.push(u.to_string());
                }
                by_user.entry(u.to_string()).or_default().push(Key {
                    workspace: w.to_string(),
                    bearer: b.to_string(),
                });
            }
            _ => {
                return Err(format!(
                    "--identities line {}: want <user>\\t<workspace>\\t<bearer>",
                    n + 1
                ));
            }
        }
    }
    Ok(order
        .into_iter()
        .filter_map(|u| by_user.remove(&u))
        .collect())
}

fn parse_config(args: &[String]) -> Result<Config, String> {
    let (host_port, path) = split_url(&flag::<String>(args, "--gateway-url")?)?;
    let users = flag::<String>(args, "--users")?
        .split(',')
        .map(|l| {
            l.trim()
                .parse::<usize>()
                .map_err(|e| format!("--users {l}: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let per_user: usize = flag(args, "--identities-per-user")?;
    let rate_per_user: f64 = flag(args, "--rate-per-user")?;
    let workers: usize = flag(args, "--workers")?;
    let queue: usize = flag(args, "--queue")?;
    if users.contains(&0)
        || per_user == 0
        || workers == 0
        || queue == 0
        || !(rate_per_user.is_finite() && rate_per_user > 0.0)
    {
        return Err("--users, --identities-per-user, --workers, --queue and --rate-per-user must be positive".to_string());
    }
    let settle_secs: u64 = flag(args, "--settle-secs")?;
    let enumerate_tenths: u64 = flag(args, "--enumerate-tenths")?;
    if settle_secs < 1 || enumerate_tenths > 10 {
        return Err(
            "--settle-secs must be >= 1 (PG stats flush) and --enumerate-tenths <= 10".to_string(),
        );
    }
    let id_path: String = flag(args, "--identities")?;
    let ids = parse_identities(
        &std::fs::read_to_string(&id_path).map_err(|e| format!("--identities {id_path}: {e}"))?,
    )?;
    let need = users.iter().copied().max().unwrap_or(0);
    if ids.len() < need || ids.iter().take(need).any(|u| u.len() < per_user) {
        return Err(format!(
            "--identities: need {need} users with {per_user} identities each"
        ));
    }
    let dsn_env: String = flag(args, "--pg-dsn-env")?;
    let mode = match flag::<String>(args, "--mode")?.as_str() {
        "open" => Mode::Open,
        "closed" => Mode::Closed,
        other => return Err(format!("--mode {other}: want open|closed")),
    };
    let only = match flag::<String>(args, "--ops")?.as_str() {
        "mixed" => None,
        name => Some(
            OPS.iter()
                .position(|o| *o == name)
                .ok_or_else(|| format!("--ops {name}: want mixed|enumerate|tools_list"))?,
        ),
    };
    Ok(Config {
        target: Target {
            origin: format!("http://{host_port}"),
            host_port,
            path,
            io_timeout: Duration::from_secs(flag(args, "--io-timeout-secs")?),
        },
        users,
        per_user,
        rate_per_user,
        warmup: Duration::from_secs(flag(args, "--warmup-secs")?),
        window: Duration::from_secs(flag(args, "--secs")?),
        settle: Duration::from_secs(settle_secs),
        enumerate_tenths,
        workers,
        queue,
        mode,
        only,
        pg_dsn: std::env::var(&dsn_env)
            .map_err(|_| format!("--pg-dsn-env: {dsn_env} is not set"))?,
        host_class: args
            .iter()
            .position(|a| a == "--host-class")
            .and_then(|i| args.get(i + 1))
            .cloned(),
        report_path: flag(args, "--report")?,
        ids,
    })
}

// ---------------------------------------------------------------------------------------------
// Arrival driver
// ---------------------------------------------------------------------------------------------

/// One level's arrival plan.
struct Plan<'a> {
    mode: Mode,
    /// Arrivals per second, all users together.
    rate: f64,
    total: u64,
    /// Arrivals before this index are warm-up: counted, never in a latency percentile.
    warm_n: u64,
    workers: usize,
    /// Open loop: arrivals waiting for a free worker; one more is a dropped iteration.
    queue: usize,
    users: usize,
    per_user: usize,
    only: Option<usize>,
    /// `mixed` sends `enumerate` for this many arrivals of every 10.
    enumerate_tenths: u64,
    target: &'a Target,
}

/// One scheduled call: its intended start, op class, user and that user's identity index.
struct Arrival {
    at: Instant,
    op: usize,
    user: usize,
    ident: usize,
    warm: bool,
}

/// One answered call. `intended_ms` runs from the intended start (queue wait included), `service_ms` from the send.
struct Rec {
    op: usize,
    warm: bool,
    intended_ms: f64,
    service_ms: f64,
    answer: Outcome,
}

struct Tally {
    scheduled: u64,
    issued: u64,
    recs: Vec<Rec>,
}

fn arrival(p: &Plan, k: u64, at: Instant) -> Arrival {
    let users = p.users as u64;
    Arrival {
        at,
        op: p
            .only
            .unwrap_or_else(|| usize::from(k % 10 >= p.enumerate_tenths)),
        user: (k % users) as usize,
        ident: ((k / users) % p.per_user as u64) as usize,
        warm: k < p.warm_n,
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// One worker until the queue closes (open) or the schedule is exhausted / past `end` (closed).
fn worker<F>(
    p: &Plan,
    send: &F,
    rx: &Mutex<Receiver<Arrival>>,
    taken: &AtomicU64,
    end: Instant,
    out: &Mutex<Vec<Rec>>,
) where
    F: Fn(&mut Conn, &Arrival) -> Outcome,
{
    let mut conn = Conn::new(&p.target.host_port, p.target.io_timeout);
    let mut mine = Vec::new();
    loop {
        let a = match p.mode {
            Mode::Open => match rx.lock().ok().and_then(|r| r.recv().ok()) {
                Some(a) => a,
                None => break,
            },
            Mode::Closed => {
                if Instant::now() >= end {
                    break;
                }
                let k = taken.fetch_add(1, Ordering::Relaxed);
                if k >= p.total {
                    break;
                }
                arrival(p, k, Instant::now())
            }
        };
        let sent = Instant::now();
        let answer = send(&mut conn, &a);
        let done = Instant::now();
        mine.push(Rec {
            op: a.op,
            warm: a.warm,
            intended_ms: ms(done.saturating_duration_since(a.at)),
            service_ms: ms(done.saturating_duration_since(sent)),
            answer,
        });
    }
    if let Ok(mut all) = out.lock() {
        all.append(&mut mine);
    }
}

/// Run one level. Open: the scheduler thread enqueues arrival `k` at `start + k / rate` and counts a full queue as a
/// drop. Closed: workers take the next index as soon as they are free, so whatever the schedule demanded but the
/// workers could not issue before the level's end is dropped. `issued + dropped == scheduled` in both modes.
fn drive<F>(p: &Plan, send: &F) -> Tally
where
    F: Fn(&mut Conn, &Arrival) -> Outcome + Sync,
{
    let start = Instant::now() + Duration::from_millis(50);
    let end = start + Duration::from_secs_f64(p.total as f64 / p.rate);
    let taken = AtomicU64::new(0);
    let (tx, rx) = sync_channel::<Arrival>(p.queue);
    let rx = Mutex::new(rx);
    let recs = Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for _ in 0..p.workers {
            s.spawn(|| worker(p, send, &rx, &taken, end, &recs));
        }
        if p.mode == Mode::Open {
            for k in 0..p.total {
                let at = start + Duration::from_secs_f64(k as f64 / p.rate);
                std::thread::sleep(at.saturating_duration_since(Instant::now()));
                if tx.try_send(arrival(p, k, at)).is_ok() {
                    taken.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        drop(tx);
    });
    Tally {
        scheduled: p.total,
        issued: taken.load(Ordering::Relaxed).min(p.total),
        recs: recs.into_inner().unwrap_or_default(),
    }
}

// ---------------------------------------------------------------------------------------------
// Database counters and report
// ---------------------------------------------------------------------------------------------

/// Counters at one instant; `stmts` = (`pg_stat_statements` calls, `total_exec_time` ms), or why it did not answer.
// ponytail: `xact_commit` is database-wide, so autovacuum, other sessions and background jobs add to txns/op; upgrade
// to per-role `pg_stat_statements` deltas or a dedicated database for the run.
struct PgSnap {
    commits: i64,
    wal_bytes: f64,
    stmts: Result<(f64, f64), String>,
}

const SNAP_SQL: &str = "select xact_commit, pg_wal_lsn_diff(pg_current_wal_lsn(), '0/0')::float8 \
 from pg_stat_database where datname = current_database()";
const STMT_SQL: &str = "select coalesce(sum(calls), 0)::float8, coalesce(sum(total_exec_time), 0)::float8 from pg_stat_statements";

fn pg_connect(dsn: &str) -> Result<Client, String> {
    // dep: PostgreSQL(any) — read-only counter session.
    let mut c = Client::connect(dsn, NoTls).map_err(|e| format!("connect: {e}"))?;
    c.batch_execute(
        "SET default_transaction_read_only = on; SET application_name = 'xtask-load-open'",
    )
    .map_err(|e| format!("session setup: {e}"))?;
    Ok(c)
}

fn pg_snap(db: &mut Client) -> Result<PgSnap, String> {
    // dep: PostgreSQL(any) — pg_stat_database and the WAL position, read-only.
    let row = db
        .query_one(SNAP_SQL, &[])
        .map_err(|e| format!("pg_stat_database: {e}"))?;
    // dep: PostgreSQL(any) — pg_stat_statements when installed; absent is reported, never guessed.
    let stmts = db
        .query_one(STMT_SQL, &[])
        .map(|r| (r.get::<_, f64>(0), r.get::<_, f64>(1)))
        .map_err(|e| format!("pg_stat_statements: {e}"));
    Ok(PgSnap {
        commits: row.get(0),
        wal_bytes: row.get(1),
        stmts,
    })
}

/// Calls that got an answer. `Outcome::Dropped` is a NoAnswer (reset, EOF, socket timeout), not an answer, so it is
/// excluded from the denominator and from the `answered` field (§57.1: an NA is not a value).
fn answered_count(t: &Tally) -> u64 {
    t.recs
        .iter()
        .filter(|r| r.answer != Outcome::Dropped)
        .count() as u64
}

/// A counter delta per answered call. `None` when no call got an answer (never divide by zero) or the counter moved
/// backwards (stats reset or eviction); both print NA with their cause (§57.1).
fn per_call(delta: f64, answered: u64) -> Option<f64> {
    if answered == 0 || delta < 0.0 {
        return None;
    }
    Some(delta / answered as f64)
}

/// One level's database deltas per answered call, plus the `XBASE_NOT_APPLICABLE` lines its NAs require.
struct PgCost {
    txns: Option<f64>,
    wal: Option<f64>,
    stmts: (Option<f64>, Option<f64>),
    na: Vec<String>,
}

fn pg_cost(a: &PgSnap, b: &PgSnap, answered: u64) -> PgCost {
    let mut na = Vec::new();
    // The first snapshot's own commit (and its statements query, when it succeeded) lands inside the delta.
    let own = 1 + i64::from(a.stmts.is_ok());
    let txns = per_call((b.commits - a.commits - own) as f64, answered);
    let wal = per_call(b.wal_bytes - a.wal_bytes, answered);
    if answered == 0 {
        na.push(
            "XBASE_NOT_APPLICABLE pg_stat_database: answered=0 (no answer to divide by; NoAnswer is not answered, §57.1)"
                .to_string(),
        );
    } else if txns.is_none() || wal.is_none() {
        na.push(format!(
            "XBASE_NOT_APPLICABLE pg_stat_database: negative delta (stats reset or a standby), commits {} -> {}",
            a.commits, b.commits
        ));
    }
    let stmts = match (&a.stmts, &b.stmts) {
        (Ok(x), Ok(y)) => {
            if answered == 0 {
                na.push(
                    "XBASE_NOT_APPLICABLE pg_stat_statements: answered=0 (no answer to divide by, §57.1)"
                        .to_string(),
                );
            }
            let calls = per_call(y.0 - x.0, answered);
            let exec = per_call(y.1 - x.1, answered);
            if answered > 0 && (calls.is_none() || exec.is_none()) {
                na.push(format!(
                    "XBASE_NOT_APPLICABLE pg_stat_statements: negative delta (stats reset or eviction), calls {} -> {}, exec_ms {} -> {}",
                    x.0, y.0, x.1, y.1
                ));
            }
            (calls, exec)
        }
        (Err(e), _) | (_, Err(e)) => {
            na.push(format!("XBASE_NOT_APPLICABLE pg_stat_statements: {e}"));
            (None, None)
        }
    };
    PgCost {
        txns,
        wal,
        stmts,
        na,
    }
}

fn quant(mut v: Vec<f64>) -> (usize, f64, f64, f64) {
    v.sort_by(f64::total_cmp);
    (
        v.len(),
        percentile(&v, 0.50),
        percentile(&v, 0.95),
        percentile(&v, 0.99),
    )
}

fn na(v: Option<f64>) -> String {
    v.map_or_else(|| "NA".to_string(), |x| format!("{x:.2}"))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Print the XBASE lines of one level and return its JSON row.
fn report_level(
    cfg: &Config,
    users: usize,
    t: &Tally,
    pg: Result<(&PgSnap, &PgSnap), String>,
    host: &str,
) -> serde_json::Value {
    let at = unix_now();
    let closed = cfg.mode == Mode::Closed;
    let tag = if closed {
        "mode=closed self-test-only"
    } else {
        "mode=open"
    };
    let count = |f: fn(&Outcome) -> bool| t.recs.iter().filter(|r| f(&r.answer)).count();
    let (ok, refused, failed, none) = (
        count(|o| matches!(o, Outcome::Ok)),
        count(|o| matches!(o, Outcome::Refused { .. })),
        count(|o| matches!(o, Outcome::Failed(_))),
        count(|o| matches!(o, Outcome::Dropped)),
    );
    let dropped = t.scheduled - t.issued;
    let answered = answered_count(t);
    println!(
        "XBASE_LEVEL users={users} {tag} scheduled={} issued={} dropped_iterations={dropped} answered={answered} ok={ok} refused_503={refused} failed={failed} no_answer={none} host={host} measured_at_unix={at}",
        t.scheduled, t.issued
    );
    let mut ops = serde_json::Map::new();
    for (i, name) in OPS.iter().enumerate() {
        let pick = |f: fn(&Rec) -> f64| -> Vec<f64> {
            t.recs
                .iter()
                .filter(|r| r.op == i && !r.warm && r.answer == Outcome::Ok)
                .map(f)
                .collect()
        };
        let (n, p50, p95, p99) = quant(pick(|r| r.intended_ms));
        let (_, _, svc95, _) = quant(pick(|r| r.service_ms));
        if n > 0 {
            println!(
                "XBASE users={users} {tag} op={name} n={n} p50={p50:.1}ms p95={p95:.1}ms p99={p99:.1}ms service_p95={svc95:.1}ms host={host} measured_at_unix={at}"
            );
        }
        ops.insert(
            (*name).to_string(),
            serde_json::json!({"n": n, "p50": p50, "p95": p95, "p99": p99, "service_p95": svc95, "unit": "ms"}),
        );
    }
    let pg_json = match pg {
        Ok((a, b)) => {
            let cost = pg_cost(a, b, answered);
            for line in &cost.na {
                println!("{line}");
            }
            let (sc, sm) = cost.stmts;
            println!(
                "XBASE_PG users={users} {tag} txns_per_op={} wal_bytes_per_op={} pg_stmts_per_op={} pg_exec_ms_per_op={} n={answered} host={host} measured_at_unix={at}",
                na(cost.txns),
                na(cost.wal),
                na(sc),
                na(sm)
            );
            serde_json::json!({"txns_per_op": cost.txns, "wal_bytes_per_op": cost.wal,
                "pg_stmts_per_op": sc, "pg_exec_ms_per_op": sm})
        }
        Err(e) => {
            println!("XBASE_NOT_APPLICABLE pg_stat_database: {e}");
            serde_json::Value::Null
        }
    };
    serde_json::json!({
        "users": users, "mode": cfg.mode.label(), "self_test_only": closed, "scheduled": t.scheduled, "issued": t.issued,
        "dropped_iterations": dropped, "answered": answered, "ok": ok, "refused_503": refused,
        "failed": failed, "no_answer": none, "ops": ops, "pg_per_answered_call": pg_json, "measured_at_unix": at,
    })
}

fn execute(cfg: &Config) -> i32 {
    let cpus = std::thread::available_parallelism().map_or(0, std::num::NonZero::get);
    let host = format!(
        "{}{cpus}cpu",
        cfg.host_class
            .as_ref()
            .map_or_else(String::new, |c| format!("{c}-"))
    );
    let mut db = pg_connect(&cfg.pg_dsn);
    match &mut db {
        Ok(c) => {
            // Throwaway snapshot, then a flush interval: level 1's first snapshot must start from flushed counters.
            if let Err(e) = pg_snap(c) {
                eprintln!("load-open: throwaway snapshot: {e}");
            }
            std::thread::sleep(cfg.settle);
        }
        Err(e) => eprintln!("load-open: no counter session: {e}"),
    }
    let snap = |db: &mut Result<Client, String>| match db {
        Ok(c) => pg_snap(c),
        Err(e) => Err(format!("no counter session: {e}")),
    };
    let mut levels = Vec::new();
    for &users in &cfg.users {
        let rate = users as f64 * cfg.rate_per_user;
        let plan = Plan {
            mode: cfg.mode,
            rate,
            total: (rate * (cfg.warmup + cfg.window).as_secs_f64()).round() as u64,
            warm_n: (rate * cfg.warmup.as_secs_f64()).round() as u64,
            workers: cfg.workers,
            queue: cfg.queue,
            users,
            per_user: cfg.per_user,
            only: cfg.only,
            enumerate_tenths: cfg.enumerate_tenths,
            target: &cfg.target,
        };
        let before = snap(&mut db);
        let tally = drive(&plan, &|conn: &mut Conn, a: &Arrival| {
            // One `Forwarded` /64 per user (`2001:db8:<user>::1`, documentation range): a user's identities share an IP.
            let wire = request(
                &cfg.target,
                &cfg.ids[a.user][a.ident],
                &format!("2001:db8:{:x}::1", a.user + 1),
                if a.op == 0 {
                    Op::Enumerate
                } else {
                    Op::ToolsList
                },
            );
            conn.send(&wire)
                .map_or(Outcome::Dropped, |r| outcome_of(&r))
        });
        std::thread::sleep(cfg.settle);
        let after = snap(&mut db);
        let pg = match (&before, &after) {
            (Ok(a), Ok(b)) => Ok((a, b)),
            (Err(e), _) | (_, Err(e)) => Err(e.clone()),
        };
        levels.push(report_level(cfg, users, &tally, pg, &host));
    }
    let report = serde_json::json!({"host": host, "unit_note": "latency ms from intended start, nearest rank, admitted 2xx after warm-up", "levels": levels});
    match serde_json::to_string_pretty(&report)
        .map_err(|e| e.to_string())
        .and_then(|text| std::fs::write(&cfg.report_path, text).map_err(|e| e.to_string()))
    {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("load-open: cannot write {}: {e}", cfg.report_path);
            1
        }
    }
}

/// `cargo xtask load-open …`
pub fn run(args: &[String]) -> i32 {
    match parse_config(args) {
        Ok(cfg) => execute(&cfg),
        Err(e) => {
            eprintln!("load-open: {e}\n{USAGE}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target {
            host_port: "127.0.0.1:1".to_string(),
            path: "/mcp".to_string(),
            origin: "http://127.0.0.1:1".to_string(),
            io_timeout: Duration::from_secs(1),
        }
    }

    fn plan(
        t: &Target,
        mode: Mode,
        rate: f64,
        total: u64,
        workers: usize,
        queue: usize,
    ) -> Plan<'_> {
        Plan {
            target: t,
            mode,
            rate,
            total,
            warm_n: 0,
            workers,
            queue,
            users: 2,
            per_user: 3,
            only: None,
            enumerate_tenths: 7,
        }
    }

    fn slow(_: &mut Conn, _: &Arrival) -> Outcome {
        std::thread::sleep(Duration::from_millis(25));
        Outcome::Ok
    }

    fn snap(commits: i64, wal_bytes: f64, stmts: Result<(f64, f64), String>) -> PgSnap {
        PgSnap {
            commits,
            wal_bytes,
            stmts,
        }
    }

    /// A one-level config for `report_level`; the target and `ids` are unused by the report shape.
    fn cfg(mode: Mode) -> Config {
        Config {
            target: target(),
            users: vec![2],
            per_user: 3,
            rate_per_user: 1.0,
            warmup: Duration::ZERO,
            window: Duration::ZERO,
            settle: Duration::ZERO,
            enumerate_tenths: 7,
            workers: 1,
            queue: 1,
            mode,
            only: None,
            pg_dsn: String::new(),
            host_class: None,
            report_path: String::new(),
            ids: Vec::new(),
        }
    }

    /// §57.1: a NoAnswer is not an answer. With N records of which K are NoAnswer, the per-response DB cost divides by
    /// N-K, not by N, and `report_level` publishes that denominator.
    #[test]
    fn load_open_denominator_excludes_no_answer() {
        let mut t = Tally {
            scheduled: 10,
            issued: 10,
            recs: Vec::new(),
        };
        for i in 0..10 {
            t.recs.push(Rec {
                op: 0,
                warm: false,
                intended_ms: 1.0,
                service_ms: 1.0,
                answer: if i < 3 { Outcome::Dropped } else { Outcome::Ok },
            });
        }
        let report = report_level(
            &cfg(Mode::Open),
            2,
            &t,
            Err("no counter session".to_string()),
            "test",
        );
        assert_eq!(
            report["answered"].as_u64(),
            Some(7),
            "report_level must publish answers, not issued calls: {report}"
        );
        let a = snap(100, 0.0, Ok((0.0, 0.0)));
        let b = snap(109, 700.0, Ok((14.0, 140.0)));
        let cost = pg_cost(&a, &b, 7);
        assert_eq!(cost.txns, Some(1.0));
        assert_eq!(cost.wal, Some(100.0));
        assert_eq!(cost.stmts, (Some(2.0), Some(20.0)));
        assert!(
            cost.na.is_empty(),
            "a positive delta has no NA: {:?}",
            cost.na
        );
    }

    /// Zero answered calls prints NA with its cause and never divides by zero.
    #[test]
    fn load_open_zero_answered_prints_na_cause() {
        let a = snap(100, 0.0, Ok((0.0, 0.0)));
        let b = snap(109, 700.0, Ok((14.0, 140.0)));
        let cost = pg_cost(&a, &b, 0);
        assert_eq!(cost.txns, None);
        assert_eq!(cost.wal, None);
        assert_eq!(cost.stmts, (None, None));
        assert!(
            cost.na
                .iter()
                .any(|l| l.contains("answered=0") && l.contains("pg_stat_database")),
            "pg_stat_database NA names its cause: {:?}",
            cost.na
        );
        assert!(
            cost.na
                .iter()
                .any(|l| l.contains("answered=0") && l.contains("pg_stat_statements")),
            "pg_stat_statements NA names its cause: {:?}",
            cost.na
        );
    }

    /// A negative `pg_stat_statements` delta prints NA and an `XBASE_NOT_APPLICABLE` line naming the cause, like the
    /// txns and WAL deltas do.
    #[test]
    fn load_open_negative_statement_delta_prints_na_cause() {
        let a = snap(100, 0.0, Ok((100.0, 50.0)));
        let b = snap(104, 40.0, Ok((99.0, 60.0)));
        let cost = pg_cost(&a, &b, 4);
        assert_eq!(cost.stmts.0, None, "calls moved backwards");
        assert_eq!(cost.stmts.1, Some(10.0 / 4.0));
        assert!(
            cost.na
                .iter()
                .any(|l| l.starts_with("XBASE_NOT_APPLICABLE pg_stat_statements: negative delta")),
            "the NA names its cause: {:?}",
            cost.na
        );
    }

    /// The card's self-test: a server that cannot keep up with the schedule makes the closed loop report dropped
    /// iterations, the number an open-loop run turns into queue wait instead.
    #[test]
    fn closed_loop_reports_dropped_iterations_at_overload() {
        let t = drive(&plan(&target(), Mode::Closed, 200.0, 200, 1, 1), &slow);
        // 1 s of schedule at 25 ms per call: > 0 issued rules out a worker that does nothing (vacuous pass),
        // >= 20 leaves 2x slack for a loaded runner, < scheduled is the overload itself.
        assert!(
            t.issued >= 20 && t.issued < t.scheduled,
            "issued {} of {}",
            t.issued,
            t.scheduled
        );
        assert_ne!(t.scheduled - t.issued, 0);
        assert_eq!(t.recs.len() as u64, t.issued);
    }

    /// Open loop at overload with `queue = 1`: arrivals that find no room are dropped at their scheduled time, so the
    /// level takes about `total / rate` however slow the service is. A scheduler that blocks on a full queue
    /// (`send` for `try_send`) would take `total x 25 ms` = 5 s here; the 2.5 s bound leaves a loaded runner 4x slack.
    #[test]
    fn open_loop_overload_drops_without_slipping_the_schedule() {
        let tg = target();
        let began = Instant::now();
        let t = drive(&plan(&tg, Mode::Open, 400.0, 200, 1, 1), &slow);
        let took = began.elapsed();
        let dropped = t.scheduled - t.issued;
        assert!(dropped > 0, "issued {} of {}", t.issued, t.scheduled);
        assert_eq!(t.recs.len() as u64 + dropped, t.scheduled);
        assert!(took < Duration::from_millis(2500), "level took {took:?}");
    }

    /// Open loop measures from the intended start: with one 25 ms worker under a 100/s schedule the backlog shows
    /// in `intended_ms` while `service_ms` stays near 25 ms.
    #[test]
    fn open_loop_latency_includes_queue_wait() {
        let t = drive(&plan(&target(), Mode::Open, 100.0, 50, 1, 64), &slow);
        assert_eq!(t.scheduled - t.issued, 0);
        let worst = |f: fn(&Rec) -> f64| t.recs.iter().map(f).fold(0.0, f64::max);
        assert!(
            worst(|r| r.intended_ms) > 3.0 * worst(|r| r.service_ms),
            "backlog must show in intended latency"
        );
    }

    #[test]
    fn identities_group_by_user_and_reject_bad_rows() {
        let ids = parse_identities("u1\tw1\tb1\nu2\tw2\tb2\n\nu1\tw1\tb3\n").expect("rows");
        assert_eq!(ids.iter().map(Vec::len).collect::<Vec<_>>(), vec![2, 1]);
        assert!(parse_identities("u1\tw1\n").is_err());
    }
}

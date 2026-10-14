//! `gateway::tests::capacity_agents` — EXPERIMENT (branch exp/capacity-agents, never merged): what agent populations
//!   the real gateway binary sustains under the deployed admission / pool / rate values, and how fair it is between
//!   tenants.
//! Depends-on: crates=[humaux-protocol, humaux-testkit, serde_json, tokio, uuid]; services=[PostgreSQL(owner)
//!   w=[control.rate_buckets, private.evidence_objects, private.memory_evidence, private.memory_records,
//!   projection.stream_checkpoints], PostgreSQL(role_gateway) via the subprocess, subprocess(humaux-gateway),
//!   HTTP(gateway), HTTP(gateway ops listener)]; env=[CARGO_BIN_EXE_humaux-gateway, CARGO_MANIFEST_DIR,
//!   HUMAUX_GATEWAY_PG_DSN, HUMAUX_MAINTENANCE_PG_DSN, HUMAUX_TEST_PG_DSN];
//!   modules=[adapters::tests::support::operation_receipt_fixture, protocol::edge]
//! Called-by: [cargo-test, manual only: every test is #[ignore = "experiment"]]
//! Invariants: [PostgreSQL only — no Qdrant, provider or retrieval worker on any path; one fixture tenant per simulated
//!   user, each with its own credential and its own client source IP 127.0.0.(10+i) (Linux loopback /8), so the
//!   pre-auth IP bucket is per user as on real hosts; admission, pool, rate and handler-timeout values are read from
//!   deploy/env/values/gateway.env at run time, never copied]
//! Spec: §67.2; ADR-0065
//!
//! Run (CI, Linux; binding 127.0.0.x ≠ .1 fails on macOS):
//!   cargo test --release -p humaux-gateway --test capacity_agents -- --include-ignored --nocapture --test-threads=1
//!
//! Output, one line per (scenario, tenant group):
//!   CAPHOST  host facts + the effective admission / pool / bucket values;
//!   CAP      the aggregate (the requested prefix, then `ok_per_s` and `rate_limited_429` appended);
//!   CAPT     per tenant (multi-tenant scenarios);
//!   CAPERR   the first non-OK, non-refusal reply per op (diagnosis);
//!   CAPM     the gateway's cumulative `*rejected_total` counters after the phase (admission reason / bucket scope).
//! `rejected_503` = admission refusal (503 + bare `RATE_LIMITED`); `rate_limited_429` = a post-auth or pre-auth token
//! bucket refusal; latency percentiles are over every completed call, refusals included.
//!
//! Runtime estimate with the defaults below: load 4 × 60 s + 4 × 30 s = 6 min, plus per test ≈ 10–40 s of fixture
//! seeding, gateway boot and fixture teardown (it deletes every audit row the run wrote) ⇒ ≈ 8–9 min of test time,
//! before the release build.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read as _, Write as _},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener, TcpStream as StdTcpStream},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use humaux_protocol::edge::compute_api_key_hash;
use humaux_testkit::{DbIntegrationFixture, run_db_fixture};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpSocket, TcpStream},
    task::JoinSet,
};
use uuid::Uuid;

#[allow(dead_code)]
#[path = "../../../crates/adapters/tests/support/operation_receipt_fixture.rs"]
mod operation_receipt_fixture;

use operation_receipt_fixture::{
    Fixture, Handle, SYNTHETIC_CREDENTIAL_PEPPER, SyntheticCredentialScopes,
};

// ---- knobs the main line may shrink to fit the CI step (targeted.yml: 40 min for build + test) ----
/// Mean agent think time; each sleep is uniform in [0.5, 1.5] × this.
const THINK_MS: u64 = 1_000;
const AGENTS_PER_USER: usize = 80;
const PHASE_SECS: u64 = 60;
const NOISY_A_AGENTS: usize = 80;
const NOISY_QUIET_TENANTS: usize = 4;
const NOISY_QUIET_AGENTS: usize = 10;
const CEILING_AGENTS: [usize; 4] = [16, 32, 64, 128];
const CEILING_SECS: u64 = 30;
/// Op mix in per-mille: the requested get 50 / grep 20 / enumerate 15 / tools-list 15, scaled by 0.9, plus 10 %
/// `remember.put` (outbox only — no Qdrant on the write path).
const MIX: [(Op, u64); 5] = [
    (Op::Get, 450),
    (Op::Grep, 180),
    (Op::Enumerate, 135),
    (Op::ToolsList, 135),
    (Op::Remember, 100),
];
// ---- workload shape ----
const MEMORIES_PER_TENANT: i32 = 200;
/// Of the 200, this many are the proven `memory.get` targets (PRIMARY-grounded context records).
const GET_TARGETS: usize = 8;
/// Appears in exactly 2 of the bulk memories (rows 96 and 192).
const RARE_WORD: &str = "zqcaprare";
const ENUMERATE_LIMIT: u32 = 50;
const QUOTA_LIMIT: i64 = 100_000_000;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(30);

const HOST: &str = "mcp.test";
const ORIGIN: &str = "https://mcp.test";
const GATEWAY_ENV_PREFIX: &str = "HUMAUX_GATEWAY_";
/// Keys taken verbatim from the deployed bundle constants (the rest is the mcp_gateway process fixture's).
const DEPLOYED_PREFIXES: [&str; 5] = [
    "HUMAUX_GATEWAY_ADMISSION_",
    "HUMAUX_GATEWAY_PG_",
    "HUMAUX_GATEWAY_RATE_",
    "HUMAUX_GATEWAY_HANDLER_TIMEOUT_SECONDS",
    "HUMAUX_GATEWAY_FINALIZE_TIMEOUT_SECONDS",
];

// ================================ scenarios ================================

#[test]
#[ignore = "experiment"]
fn one_user_80() {
    lab("one_user_80", 1, |lab| {
        let groups = lab.run(&[(0, AGENTS_PER_USER, THINK_MS)], PHASE_SECS);
        report("one_user_80", groups, PHASE_SECS);
        lab.print_rejection_metrics("one_user_80");
    });
}

#[test]
#[ignore = "experiment"]
fn users_5x80() {
    users("users_5x80", 5);
}

#[test]
#[ignore = "experiment"]
fn users_10x80() {
    users("users_10x80", 10);
}

fn users(scenario: &str, tenants: usize) {
    lab(scenario, tenants, |lab| {
        let plan: Vec<_> = (0..tenants)
            .map(|tenant| (tenant, AGENTS_PER_USER, THINK_MS))
            .collect();
        report(scenario, lab.run(&plan, PHASE_SECS), PHASE_SECS);
        lab.print_rejection_metrics(scenario);
    });
}

/// Tenant A floods closed-loop on one credential; B..E behave like ordinary users. Question: does A's flood give
/// B..E 503s or a large p95?
#[test]
#[ignore = "experiment"]
fn noisy_neighbor() {
    lab("noisy_neighbor", 1 + NOISY_QUIET_TENANTS, |lab| {
        let mut plan = vec![(0, NOISY_A_AGENTS, 0)];
        plan.extend((1..=NOISY_QUIET_TENANTS).map(|tenant| (tenant, NOISY_QUIET_AGENTS, THINK_MS)));
        let mut groups = lab.run(&plan, PHASE_SECS);
        let quiet = groups.split_off(1);
        report("noisy_neighbor_A", groups, PHASE_SECS);
        report("noisy_neighbor_BE", quiet, PHASE_SECS);
        lab.print_rejection_metrics("noisy_neighbor");
    });
}

/// One tenant, closed loop, stepping the agent count to find the per-tenant saturation calls/s.
#[test]
#[ignore = "experiment"]
fn tenant_ceiling() {
    lab("tenant_ceiling", 1, |lab| {
        for agents in CEILING_AGENTS {
            report(
                "tenant_ceiling",
                lab.run(&[(0, agents, 0)], CEILING_SECS),
                CEILING_SECS,
            );
            lab.print_rejection_metrics(&format!("tenant_ceiling_{agents}"));
        }
    });
}

// ================================ lab: tenants + gateway ================================

/// One simulated user: its own fixture tenant, credential, workspace and client source IP.
struct Tenant {
    bearer: String,
    workspace: Uuid,
    get_ids: Vec<Uuid>,
    source: Ipv4Addr,
}

struct Lab {
    rt: tokio::runtime::Runtime,
    gateway: Gateway,
    tenants: Vec<Arc<Tenant>>,
}

/// Builds `tenants` fixture tenants (the first from `run_db_fixture`, the rest on the same thread, which the
/// fixture's SERIAL guard allows), seeds them, boots the gateway binary, warms every op up once per tenant, runs
/// `body`, then tears everything down.
fn lab(test_name: &str, tenants: usize, body: impl FnOnce(&Lab)) {
    run_db_fixture::<Fixture, _>(test_name, |primary| {
        let mut handles = vec![primary];
        for _ in 1..tenants {
            handles.push(
                Fixture::isolate()
                    .unwrap_or_else(|reason| panic!("extra tenant fixture: {reason}")),
            );
        }
        let seeded = handles
            .iter_mut()
            .enumerate()
            .map(|(index, handle)| Arc::new(seed_tenant(handle, index)))
            .collect();
        let env = gateway_env(&handles[0]);
        print_host_facts(&mut handles[0], &env);
        let lab = Lab {
            rt: tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("agent runtime"),
            gateway: Gateway::start(&env),
            tenants: seeded,
        };
        lab.warm_up();
        body(&lab);
        let subjects: Vec<String> = lab.tenants.iter().map(|t| t.source.to_string()).collect();
        drop(lab);
        // The pre-auth buckets of our source IPs live under the system tenant, outside every fixture teardown.
        handles[0]
            .admin
            .execute(
                "DELETE FROM control.rate_buckets \
                 WHERE tenant_id='00000000-0000-0000-0000-000000000000' \
                   AND subject_kind='ip' AND subject_id=ANY($1) \
                   AND operation='mcp' AND bucket_key='preauth'",
                &[&subjects],
            )
            .expect("owner deletes the experiment's pre-auth buckets");
        // The primary handle holds the fixture's SERIAL guard: drop it last.
        while let Some(handle) = handles.pop() {
            drop(handle);
        }
    });
}

fn seed_tenant(handle: &mut Handle, index: usize) -> Tenant {
    let prefix = format!("cap{}", Uuid::new_v4().simple());
    let wire = format!("{prefix}.{}", Uuid::new_v4().simple());
    let credential = handle.seed_synthetic_service_credential_and_window(
        SyntheticCredentialScopes::RememberWriteAndContextRead,
        &prefix,
        &wire,
        &compute_api_key_hash(SYNTHETIC_CREDENTIAL_PEPPER, &wire),
        QUOTA_LIMIT,
    );
    let get_ids = (0..GET_TARGETS)
        .map(|_| handle.seed_workspace_visible_context_record().memory_id)
        .collect();
    seed_bulk_memories(
        handle,
        MEMORIES_PER_TENANT - i32::try_from(GET_TARGETS).expect("small"),
    );
    provision_stream_pair(handle);
    Tenant {
        bearer: credential.bearer,
        workspace: handle.workspace_id,
        get_ids,
        source: Ipv4Addr::new(127, 0, 0, 10 + u8::try_from(index).expect("< 245 tenants")),
    }
}

/// mcp_gateway's `seed_bulk_memories` shape: one INTERNAL evidence backs `rows` workspace-shared NOTE memories.
fn seed_bulk_memories(handle: &mut Handle, rows: i32) {
    let mut txn = handle.admin.transaction().expect("bulk seed transaction");
    let evidence: Uuid = txn
        .query_one(
            "INSERT INTO private.evidence_objects \
               (tenant_id,evidence_kind,payload_sha256,data_class,origin_class,visibility_class, \
                visibility_workspace_id,reasoning_domain_id) \
             VALUES($1,'EVENT',$2,'INTERNAL','DirectUserInput','WORKSPACE_SHARED',$3,$4) RETURNING evidence_id",
            &[&handle.tenant_id, &vec![5_u8; 32], &handle.workspace_id, &handle.reasoning_domain_id],
        )
        .expect("bulk evidence")
        .get(0);
    txn.execute(
        &format!(
            "WITH m AS (INSERT INTO private.memory_records \
               (tenant_id,memory_type,content,visibility_class,visibility_workspace_id,authority_class, \
                confidence,status,asserted_at) \
               SELECT $1,'NOTE',jsonb_build_object('key_claim', \
                        CASE WHEN g % 96 = 0 THEN 'capacity row ' || g || ' {RARE_WORD}' \
                             ELSE 'capacity row ' || g || E' with filler text\\nsecond line' END), \
                      'WORKSPACE_SHARED',$2,'ProjectConstraint',0.5,'active',clock_timestamp() \
                 FROM generate_series(1, $3::int) g RETURNING memory_id) \
             INSERT INTO private.memory_evidence(memory_id,evidence_id,role,grounding_mode) \
             SELECT memory_id, $4, 'SUPPORTING', 'SNAPSHOT' FROM m"
        ),
        &[&handle.tenant_id, &handle.workspace_id, &rows, &evidence],
    )
    .expect("bulk memories");
    txn.commit().expect("commit the bulk seed");
}

/// mcp_gateway's `provision_stream_pair_blocking`: the `v1` checkpoint row exists and serves (ADR-0031).
fn provision_stream_pair(handle: &Handle) {
    let mut owner = handle
        .owner_client()
        .expect("owner provisions the stream pair");
    owner
        .execute(
            "INSERT INTO projection.stream_checkpoints \
               (tenant_id,scope_kind,scope_id,domain,projection_kind,projection_version) \
             VALUES($1,'workspace',$2,'knowledge','ingest','v1') ON CONFLICT DO NOTHING",
            &[&handle.tenant_id, &handle.workspace_id],
        )
        .expect("owner seeds the v1 checkpoint row");
    owner
        .execute(
            "UPDATE projection.stream_checkpoints SET serving=true \
             WHERE tenant_id=$1 AND scope_kind='workspace' AND scope_id=$2 \
               AND domain='knowledge' AND projection_kind='ingest' AND projection_version='v1' \
               AND NOT EXISTS (SELECT 1 FROM projection.stream_checkpoints \
                               WHERE tenant_id=$1 AND scope_kind='workspace' AND scope_id=$2 \
                                 AND domain='knowledge' AND projection_kind='ingest' AND serving)",
            &[&handle.tenant_id, &handle.workspace_id],
        )
        .expect("owner promotes v1 to serving");
}

/// mcp_gateway's `GatewayProcessConfig::for_fixture`, then the deployed bundle constants for admission, pool, rate
/// buckets and timeouts overlaid from deploy/env/values/gateway.env.
fn gateway_env(handle: &Handle) -> BTreeMap<String, String> {
    let mut values: BTreeMap<String, String> = [
        ("BIND_ADDR", unused_loopback_address().to_string()),
        ("METRICS_ADDR", unused_loopback_address().to_string()),
        ("ALLOWED_HOSTS", HOST.into()),
        ("ALLOWED_ORIGINS", ORIGIN.into()),
        ("MAX_REQUEST_BODY_BYTES", "65536".into()),
        ("PG_DSN", handle.gateway_dsn_for_process().to_owned()),
        (
            "CREDENTIAL_PEPPER_HEX",
            hex::encode(SYNTHETIC_CREDENTIAL_PEPPER),
        ),
        ("TOKEN_HMAC_KEY", random_hex_32()),
        ("TRUSTED_PROXY_CIDRS", String::new()),
        ("MAX_FORWARDED_HOPS", "1".into()),
        ("GLOBAL_DENYLIST", String::new()),
        ("GLOBAL_EMERGENCY_ALLOWLIST", String::new()),
        ("RESERVATION_TTL_SECONDS", "30".into()),
        ("REPLAY_TTL_SECONDS", "60".into()),
        ("CONFIRM_TOKEN_TTL_SECONDS", "300".into()),
        ("UNDO_WINDOW_SECONDS", "86400".into()),
        ("PROJECTION_LAG_SECONDS", "60".into()),
        ("MOOD_HALF_LIFE_SECONDS", "21600".into()),
        ("REMEMBER_SCOPE_KIND", "workspace".into()),
        ("REMEMBER_DOMAIN", "knowledge".into()),
        ("REMEMBER_PROJECTION_KIND", "ingest".into()),
        ("REMEMBER_PROJECTION_VERSION", "v1".into()),
        (
            "REMEMBER_REASONING_DOMAIN_ID",
            handle.reasoning_domain_id.to_string(),
        ),
        ("REMEMBER_TOKEN_TTL_SECONDS", "60".into()),
        ("REMEMBER_DATA_CLASS", "INTERNAL".into()),
        ("REMEMBER_VISIBILITY_CLASS", "WORKSPACE_SHARED".into()),
        ("REMEMBER_EVENT_KIND", "USER_MESSAGE".into()),
        ("CONTEXT_TOTAL_TOKENS", "2048".into()),
        ("CONTEXT_MANDATORY_TOKENS", "1024".into()),
        ("READINESS_REFRESH_SECONDS", "1".into()),
        ("ENUMERATION_TTL_SECONDS", "900".into()),
        ("ENUMERATION_MANIFEST_CAP", "1000".into()),
    ]
    .into_iter()
    .map(|(key, value)| (format!("{GATEWAY_ENV_PREFIX}{key}"), value))
    .collect();
    let deployed = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/env/values/gateway.env"
    ))
    .expect("read deploy/env/values/gateway.env");
    let mut overlaid = 0;
    for line in deployed.lines().filter(|line| !line.starts_with('#')) {
        if let Some((key, value)) = line.split_once('=')
            && DEPLOYED_PREFIXES
                .iter()
                .any(|prefix| key.starts_with(prefix))
        {
            values.insert(key.to_owned(), value.to_owned());
            overlaid += 1;
        }
    }
    // 5 admission + 7 pool + 12 rate + 2 timeouts today; far fewer means the file moved or was renamed.
    assert!(overlaid >= 20, "only {overlaid} deployed keys overlaid");
    values
}

fn print_host_facts(handle: &mut Handle, env: &BTreeMap<String, String>) {
    let nproc = std::thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get);
    let mem_total = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|info| {
            info.lines()
                .find(|line| line.starts_with("MemTotal:"))
                .map(|line| line.split_whitespace().skip(1).collect::<String>())
        })
        .unwrap_or_else(|| "unknown".into());
    let max_connections: String = handle
        .admin
        .query_one("SHOW max_connections", &[])
        .expect("SHOW max_connections")
        .get(0);
    let effective = env
        .iter()
        .filter(|(key, _)| {
            [
                "ADMISSION_",
                "PG_POOL_",
                "_PER_SECOND",
                "_CAPACITY",
                "HANDLER_TIMEOUT",
            ]
            .iter()
            .any(|part| key.contains(*part))
        })
        .map(|(key, value)| format!("{}={value}", key.trim_start_matches(GATEWAY_ENV_PREFIX)))
        .collect::<Vec<_>>()
        .join(" ");
    println!(
        "CAPHOST nproc={nproc} mem_total={mem_total} pg_max_connections={max_connections} {effective}"
    );
}

struct Gateway {
    child: Child,
    address: SocketAddr,
    metrics: SocketAddr,
}

impl Gateway {
    fn start(env: &BTreeMap<String, String>) -> Self {
        let address = env["HUMAUX_GATEWAY_BIND_ADDR"].parse().expect("bind addr");
        let metrics = env["HUMAUX_GATEWAY_METRICS_ADDR"]
            .parse()
            .expect("metrics addr");
        // dep: subprocess(humaux-gateway) — spawns the humaux-gateway binary under test
        let mut command = Command::new(env!("CARGO_BIN_EXE_humaux-gateway"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with(GATEWAY_ENV_PREFIX) {
                command.env_remove(key);
            }
        }
        let mut child = command
            .envs(env)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn gateway binary");
        let deadline = Instant::now() + Duration::from_secs(10);
        // dep: HTTP(gateway) — readiness poll against the spawned gateway subprocess
        while StdTcpStream::connect_timeout(&address, Duration::from_millis(25)).is_err() {
            if let Some(status) = child.try_wait().expect("inspect gateway binary") {
                panic!("gateway binary exited during startup: {status}");
            }
            assert!(
                Instant::now() < deadline,
                "gateway did not listen within 10 s"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Self {
            child,
            address,
            metrics,
        }
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn unused_loopback_address() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("reserve loopback port");
    listener.local_addr().expect("reserved loopback address")
}

fn random_hex_32() -> String {
    let mut key = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut urandom| urandom.read_exact(&mut key))
        .expect("read 32 bytes from /dev/urandom");
    hex::encode(key)
}

// ================================ agents ================================

#[derive(Clone, Copy)]
enum Op {
    Get,
    Grep,
    Enumerate,
    ToolsList,
    Remember,
}

impl Op {
    const fn name(self) -> &'static str {
        match self {
            Self::Get => "memory.get",
            Self::Grep => "memory.grep",
            Self::Enumerate => "memory.enumerate",
            Self::ToolsList => "tools/list",
            Self::Remember => "remember.put",
        }
    }
}

struct Group {
    tenant: usize,
    agents: usize,
    think_ms: u64,
    stats: Stats,
}

impl Lab {
    /// Runs every `(tenant, agents, think_ms)` group concurrently for `secs`; one `Group` per plan entry.
    fn run(&self, plan: &[(usize, usize, u64)], secs: u64) -> Vec<Group> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        self.rt.block_on(async {
            let mut seed = 0_u64;
            let mut sets = Vec::new();
            for &(tenant, agents, think_ms) in plan {
                let mut set = JoinSet::new();
                for _ in 0..agents {
                    seed += 1;
                    set.spawn(agent(
                        self.gateway.address,
                        Arc::clone(&self.tenants[tenant]),
                        think_ms,
                        deadline,
                        seed,
                    ));
                }
                sets.push(set);
            }
            let mut groups = Vec::new();
            for (&(tenant, agents, think_ms), mut set) in plan.iter().zip(sets) {
                let mut stats = Stats::default();
                while let Some(joined) = set.join_next().await {
                    stats.merge(joined.expect("agent task"));
                }
                groups.push(Group {
                    tenant,
                    agents,
                    think_ms,
                    stats,
                });
            }
            groups
        })
    }

    /// The one correctness check of the harness: every op of the mix answers OK for every tenant before any load,
    /// so a broken op cannot hide as `other_err` noise.
    fn warm_up(&self) {
        self.rt.block_on(async {
            for tenant in &self.tenants {
                let mut client = Client::new(self.gateway.address, tenant.source);
                for (op, _) in MIX {
                    let reply = client
                        .send(&http_request(tenant, op, 0, 0))
                        .await
                        .unwrap_or_else(|error| panic!("{} warm-up transport: {error}", op.name()));
                    assert!(
                        matches!(classify(&reply), Outcome::Ok),
                        "{} warm-up for {}: status={} body={}",
                        op.name(),
                        tenant.source,
                        reply.status,
                        reply.body
                    );
                }
            }
        });
    }

    /// Cumulative over this gateway process: diff consecutive phases of one test by hand.
    fn print_rejection_metrics(&self, scenario: &str) {
        // dep: HTTP(gateway ops listener) — loopback /metrics scrape of the spawned gateway
        let text = StdTcpStream::connect_timeout(&self.gateway.metrics, Duration::from_secs(5))
            .and_then(|mut stream| {
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                stream.write_all(
                    b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                )?;
                let mut text = String::new();
                stream.read_to_string(&mut text)?;
                Ok(text)
            });
        match text {
            Ok(text) => text
                .lines()
                .filter(|line| line.contains("rejected_total") && !line.starts_with('#'))
                .for_each(|line| println!("CAPM scenario={scenario} {line}")),
            Err(error) => println!("CAPM scenario={scenario} unavailable: {error}"),
        }
    }
}

async fn agent(
    address: SocketAddr,
    tenant: Arc<Tenant>,
    think_ms: u64,
    deadline: Instant,
    seed: u64,
) -> Stats {
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let mut client = Client::new(address, tenant.source);
    let mut stats = Stats::default();
    // Spread the first calls over one think period so a think-time population starts in steady state.
    if think_ms > 0 {
        tokio::time::sleep(Duration::from_millis(rng.below(think_ms))).await;
    }
    let mut id = 0_u64;
    while Instant::now() < deadline {
        id += 1;
        let op = pick(&mut rng);
        let request = http_request(&tenant, op, id, rng.next());
        let started = Instant::now();
        let result = tokio::time::timeout(CLIENT_TIMEOUT, client.send(&request)).await;
        let outcome = match result {
            Ok(Ok(reply)) => classify(&reply),
            Ok(Err(error)) => Outcome::Other(format!("transport={error}")),
            Err(_) => {
                client.stream = None;
                Outcome::Other("transport=client timeout".into())
            }
        };
        let elapsed = started.elapsed();
        // A refused agent honours Retry-After (1 s when absent), as a well-behaved MCP client would.
        let pause = match &outcome {
            Outcome::Rejected503(retry) | Outcome::RateLimited(retry) => {
                jitter(&mut rng, retry.unwrap_or(1) * 1_000)
            }
            _ => jitter(&mut rng, think_ms),
        };
        stats.record(op, elapsed, outcome);
        let remaining = deadline.saturating_duration_since(Instant::now());
        if !pause.is_zero() && !remaining.is_zero() {
            tokio::time::sleep(pause.min(remaining)).await;
        }
    }
    stats
}

fn pick(rng: &mut Rng) -> Op {
    let mut roll = rng.below(1_000);
    for (op, weight) in MIX {
        if roll < weight {
            return op;
        }
        roll -= weight;
    }
    Op::ToolsList
}

/// Uniform in [0.5, 1.5] × `base_ms`.
fn jitter(rng: &mut Rng, base_ms: u64) -> Duration {
    if base_ms == 0 {
        return Duration::ZERO;
    }
    Duration::from_millis(base_ms / 2 + rng.below(base_ms + 1))
}

/// xorshift64 — the harness needs spread, not cryptographic randomness, and the crate has no `rand`.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// The full HTTP/1.1 request (keep-alive) for one op, headers as mcp_gateway's `tool_call_headers` /
/// `operation_headers`.
fn http_request(tenant: &Tenant, op: Op, id: u64, roll: u64) -> String {
    let call = |name: &str, arguments: Value| json!({"name": name, "arguments": arguments, "_meta": metadata()});
    let workspace = tenant.workspace;
    let (method, tool, params) = match op {
        Op::ToolsList => ("tools/list", None, json!({"_meta": metadata()})),
        Op::Get => {
            let memory_id = tenant.get_ids
                [usize::try_from(roll % tenant.get_ids.len() as u64).expect("index fits")];
            (
                "tools/call",
                Some("memory"),
                call("memory", json!({"action":"get","memory_id":memory_id})),
            )
        }
        Op::Grep => (
            "tools/call",
            Some("memory"),
            call(
                "memory",
                json!({"action":"grep","pattern":RARE_WORD,"workspace_id":workspace}),
            ),
        ),
        Op::Enumerate => (
            "tools/call",
            Some("memory"),
            call(
                "memory",
                json!({"action":"enumerate","workspace_id":workspace,"limit":ENUMERATE_LIMIT}),
            ),
        ),
        Op::Remember => (
            "tools/call",
            Some("remember"),
            call(
                "remember",
                json!({
                    "operation": "put",
                    "content": format!("capacity probe write {}", Uuid::now_v7()),
                    "idempotency_key": format!("cap-{}", Uuid::now_v7()),
                    "workspace_id": workspace,
                }),
            ),
        ),
    };
    let body = json!({"jsonrpc":"2.0", "id": id, "method": method, "params": params}).to_string();
    let mut request = format!(
        "POST /mcp HTTP/1.1\r\nHost: {HOST}\r\nOrigin: {ORIGIN}\r\n\
         Accept: application/json, text/event-stream\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: {method}\r\n\
         Authorization: {}\r\n",
        body.len(),
        tenant.bearer
    );
    if let Some(tool) = tool {
        request.push_str(&format!("Mcp-Name: {tool}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(&body);
    request
}

fn metadata() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "capacity-agent", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {},
    })
}

// ================================ keep-alive HTTP/1.1 client ================================

struct Reply {
    status: u16,
    retry_after: Option<u64>,
    body: String,
}

/// One connection per agent, reused across calls, bound to the tenant's source IP.
// ponytail: hand-rolled HTTP/1.1 (Content-Length / chunked / close-delimited) because the crate has no HTTP client
// dependency; swap for hyper's client if an op ever answers with SSE framing.
struct Client {
    address: SocketAddr,
    source: Ipv4Addr,
    stream: Option<BufReader<TcpStream>>,
}

impl Client {
    const fn new(address: SocketAddr, source: Ipv4Addr) -> Self {
        Self {
            address,
            source,
            stream: None,
        }
    }

    async fn send(&mut self, request: &str) -> Result<Reply, String> {
        // Resend once, on a fresh connection, only when a reused keep-alive connection turned out stale.
        let mut reused = self.stream.is_some();
        loop {
            if self.stream.is_none() {
                let socket = TcpSocket::new_v4().map_err(|error| format!("socket: {error}"))?;
                socket
                    .bind(SocketAddr::new(IpAddr::V4(self.source), 0))
                    .map_err(|error| format!("bind {}: {error}", self.source))?;
                // dep: HTTP(gateway) — agent connection to the spawned gateway's MCP listener
                let stream = socket
                    .connect(self.address)
                    .await
                    .map_err(|error| format!("connect: {error}"))?;
                stream
                    .set_nodelay(true)
                    .map_err(|error| format!("nodelay: {error}"))?;
                self.stream = Some(BufReader::new(stream));
            }
            let stream = self.stream.as_mut().expect("connected above");
            match roundtrip(stream, request.as_bytes()).await {
                Ok((reply, keep_alive)) => {
                    if !keep_alive {
                        self.stream = None;
                    }
                    return Ok(reply);
                }
                Err(error) => {
                    self.stream = None;
                    if !reused {
                        return Err(error);
                    }
                    reused = false;
                }
            }
        }
    }
}

async fn roundtrip(
    stream: &mut BufReader<TcpStream>,
    request: &[u8],
) -> Result<(Reply, bool), String> {
    stream
        .get_mut()
        .write_all(request)
        .await
        .map_err(|error| format!("write: {error}"))?;
    let mut line = String::new();
    read_line(stream, &mut line).await?;
    let status = line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| format!("status line {line:?}"))?;
    let (mut length, mut chunked, mut keep_alive, mut retry_after) = (None, false, true, None);
    loop {
        read_line(stream, &mut line).await?;
        let header = line.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            let value = value.trim();
            match name.to_ascii_lowercase().as_str() {
                "content-length" => length = value.parse::<usize>().ok(),
                "transfer-encoding" => chunked = value.eq_ignore_ascii_case("chunked"),
                "connection" => keep_alive = !value.eq_ignore_ascii_case("close"),
                "retry-after" => retry_after = value.parse::<u64>().ok(),
                _ => {}
            }
        }
    }
    let mut body = Vec::new();
    if chunked {
        loop {
            read_line(stream, &mut line).await?;
            let size_hex = line.trim().split(';').next().unwrap_or_default();
            let size =
                usize::from_str_radix(size_hex, 16).map_err(|_| format!("chunk size {line:?}"))?;
            // The chunk plus its CRLF; the last chunk (size 0, no trailers) reads just the final CRLF.
            let mut chunk = vec![0; size + 2];
            stream
                .read_exact(&mut chunk)
                .await
                .map_err(|error| format!("chunk: {error}"))?;
            if size == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..size]);
        }
    } else if let Some(length) = length {
        body.resize(length, 0);
        stream
            .read_exact(&mut body)
            .await
            .map_err(|error| format!("body: {error}"))?;
    } else {
        stream
            .read_to_end(&mut body)
            .await
            .map_err(|error| format!("body: {error}"))?;
        keep_alive = false;
    }
    Ok((
        Reply {
            status,
            retry_after,
            body: String::from_utf8_lossy(&body).into_owned(),
        },
        keep_alive,
    ))
}

async fn read_line(stream: &mut BufReader<TcpStream>, line: &mut String) -> Result<(), String> {
    line.clear();
    match stream.read_line(line).await {
        Ok(0) => Err("connection closed".into()),
        Ok(_) => Ok(()),
        Err(error) => Err(format!("read: {error}")),
    }
}

// ================================ outcomes + report ================================

enum Outcome {
    Ok,
    /// Admission refusal: 503 + bare `RATE_LIMITED` (ADR-0065 D-C), with its Retry-After.
    Rejected503(Option<u64>),
    /// Token-bucket refusal (pre-auth IP or post-auth credential/user/tenant/operation, ADR-0065 D-D).
    RateLimited(Option<u64>),
    Other(String),
}

fn classify(reply: &Reply) -> Outcome {
    let rate_limited = reply.body.contains("RATE_LIMITED");
    match reply.status {
        503 if reply.body.trim() == "RATE_LIMITED" => Outcome::Rejected503(reply.retry_after),
        429 => Outcome::RateLimited(reply.retry_after),
        200 => {
            let value: Value = serde_json::from_str(&reply.body).unwrap_or(Value::Null);
            if value.get("result").is_some()
                && value.get("error").is_none()
                && value["result"]["isError"] != true
            {
                Outcome::Ok
            } else if rate_limited {
                Outcome::RateLimited(reply.retry_after)
            } else {
                Outcome::Other(sample(reply))
            }
        }
        _ if rate_limited => Outcome::RateLimited(reply.retry_after),
        _ => Outcome::Other(sample(reply)),
    }
}

fn sample(reply: &Reply) -> String {
    let body: String = reply.body.chars().take(240).collect();
    format!(
        "status={} body={}",
        reply.status,
        body.replace(['\r', '\n'], " ")
    )
}

#[derive(Default)]
struct Stats {
    latency_us: Vec<u64>,
    ok: u64,
    rejected_503: u64,
    rate_limited: u64,
    other: u64,
    /// The first unexpected reply per op.
    samples: BTreeMap<&'static str, String>,
}

impl Stats {
    fn record(&mut self, op: Op, elapsed: Duration, outcome: Outcome) {
        self.latency_us
            .push(u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX));
        match outcome {
            Outcome::Ok => self.ok += 1,
            Outcome::Rejected503(_) => self.rejected_503 += 1,
            Outcome::RateLimited(_) => self.rate_limited += 1,
            Outcome::Other(sample) => {
                self.other += 1;
                self.samples.entry(op.name()).or_insert(sample);
            }
        }
    }

    fn merge(&mut self, other: Self) {
        self.latency_us.extend(other.latency_us);
        self.ok += other.ok;
        self.rejected_503 += other.rejected_503;
        self.rate_limited += other.rate_limited;
        self.other += other.other;
        for (op, sample) in other.samples {
            self.samples.entry(op).or_insert(sample);
        }
    }

    #[allow(clippy::cast_precision_loss)] // counts and microseconds far below 2^52
    fn summary(&mut self, secs: u64) -> String {
        self.latency_us.sort_unstable();
        let pct = |q: f64| {
            if self.latency_us.is_empty() {
                return 0.0;
            }
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let index = ((self.latency_us.len() - 1) as f64 * q).round() as usize;
            self.latency_us[index] as f64 / 1_000.0
        };
        let calls = self.latency_us.len();
        let secs = secs.max(1) as f64;
        format!(
            "calls={calls} per_s={:.1} ok={} rejected_503={} other_err={} p50_ms={:.1} p95_ms={:.1} p99_ms={:.1} \
             ok_per_s={:.1} rate_limited_429={}",
            calls as f64 / secs,
            self.ok,
            self.rejected_503,
            self.other,
            pct(0.50),
            pct(0.95),
            pct(0.99),
            self.ok as f64 / secs,
            self.rate_limited,
        )
    }
}

fn report(scenario: &str, groups: Vec<Group>, secs: u64) {
    let tenants = groups
        .iter()
        .map(|group| group.tenant)
        .collect::<BTreeSet<_>>()
        .len();
    let agents: usize = groups.iter().map(|group| group.agents).sum();
    let think_ms = groups.first().map_or(0, |group| group.think_ms);
    let mut total = Stats::default();
    let mut per_tenant = Vec::new();
    for mut group in groups {
        if tenants > 1 {
            per_tenant.push(format!(
                "CAPT scenario={scenario} tenant={} agents={} {}",
                group.tenant,
                group.agents,
                group.stats.summary(secs)
            ));
        }
        total.merge(group.stats);
    }
    println!(
        "CAP scenario={scenario} tenants={tenants} agents={agents} think_ms={think_ms} secs={secs} {}",
        total.summary(secs)
    );
    for line in per_tenant {
        println!("{line}");
    }
    for (op, sample) in &total.samples {
        println!("CAPERR scenario={scenario} op={op} {sample}");
    }
}

//! `retrieval-worker::tests::same_uid_boot` — ADR-0066 D-K against the BINARY: `--serve-rpc` refuses to boot (exit 2,
//!   the key named) when the expected gateway uid is its own uid, unless HUMAUX_RETRIEVAL_WORKER_ALLOW_SAME_UID is
//!   exactly `1`; with the opt-in it boots, and the boot and every accepted same-uid peer log a WARN.
//! Depends-on: crates=[humaux-infra-cell, humaux-testkit, tokio]; services=[subprocess(humaux-retrieval-worker),
//!   UDS(retrieval-worker)]; env=[CARGO_BIN_EXE_humaux-retrieval-worker, HUMAUX_RETRIEVAL_WORKER_ALLOW_SAME_UID,
//!   HUMAUX_RETRIEVAL_WORKER_CALLER, HUMAUX_RETRIEVAL_WORKER_CELL_ID, HUMAUX_RETRIEVAL_WORKER_DIMENSION,
//!   HUMAUX_RETRIEVAL_WORKER_EGRESS_PROCESSOR_ID, HUMAUX_RETRIEVAL_WORKER_EMBEDDING_MAX_BATCH_ITEMS,
//!   HUMAUX_RETRIEVAL_WORKER_EMBEDDING_MODEL,
//!   HUMAUX_RETRIEVAL_WORKER_EMBEDDING_PROVIDER, HUMAUX_RETRIEVAL_WORKER_EMBEDDING_VERSION,
//!   HUMAUX_RETRIEVAL_WORKER_GATEWAY_UID, HUMAUX_RETRIEVAL_WORKER_GITLEAKS_BIN,
//!   HUMAUX_RETRIEVAL_WORKER_GITLEAKS_SHA256, HUMAUX_RETRIEVAL_WORKER_GITLEAKS_VERSION,
//!   HUMAUX_RETRIEVAL_WORKER_MAX_INPUT_TOKENS, HUMAUX_RETRIEVAL_WORKER_MODEL_REVISION,
//!   HUMAUX_RETRIEVAL_WORKER_PG_DSN, HUMAUX_RETRIEVAL_WORKER_QDRANT_CIDR, HUMAUX_RETRIEVAL_WORKER_QDRANT_HOST,
//!   HUMAUX_RETRIEVAL_WORKER_QDRANT_PORT, HUMAUX_RETRIEVAL_WORKER_QDRANT_TLS, HUMAUX_RETRIEVAL_WORKER_REGION,
//!   HUMAUX_RETRIEVAL_WORKER_RPC_SOCKET_PATH, HUMAUX_RETRIEVAL_WORKER_SERVE_RPC_METRICS_ADDR,
//!   HUMAUX_TEST_GITLEAKS_BIN, HUMAUX_TEST_GITLEAKS_SHA256, HUMAUX_TEST_GITLEAKS_VERSION];
//!   modules=[humaux-testkit, infra-cell::uds, testkit::reaped]
//! Called-by: [cargo-test]
//! Invariants: [the binary runs with a cleared environment and is held as Reaped (killed when the test ends or
//!   unwinds); the refused boots open no connection and bind no socket; the admitted boot connects only as
//!   role_retrieval_worker and is sent one malformed request that no handler accepts (no provider call, no row); a
//!   missing env is a failure under HUMAUX_REQUIRE_DB, a named SKIP otherwise (§79.2)]
//! Spec: §79.2; ADR-0066

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use humaux_infra_cell::uds::{connect_verified, own_uid};
use humaux_testkit::reaped::{Reaped, SpawnReaped};
use humaux_testkit::{ExternalDep, skip_or_fail};

const BIN: &str = env!("CARGO_BIN_EXE_humaux-retrieval-worker");
const UID_KEY: &str = "HUMAUX_RETRIEVAL_WORKER_GATEWAY_UID";
const ALLOW_KEY: &str = "HUMAUX_RETRIEVAL_WORKER_ALLOW_SAME_UID";

/// A 0700 socket directory of this uid (ADR-0066 D-M), removed on drop. Short `/tmp` path: a macOS temp dir plus a
/// name overflows `sockaddr_un`.
struct SockDir(PathBuf);

impl SockDir {
    fn new(tag: &str) -> Self {
        let dir = PathBuf::from(format!("/tmp/hq-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).expect("create the socket dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("chmod the socket dir");
        SockDir(dir)
    }
}

impl Drop for SockDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A loopback address that was bound and released: free for the child's ops listener.
fn free_addr() -> String {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("reserve a loopback port")
        .to_string()
}

/// `--serve-rpc` with exactly `env`; stderr goes to `log` (a file, so a chatty child never blocks on a pipe).
fn spawn(env: &[(&str, String)], log: &Path) -> Reaped {
    let stderr = std::fs::File::create(log).expect("create the stderr log");
    // dep: subprocess(humaux-retrieval-worker) — the binary under test
    Command::new(BIN)
        .arg("--serve-rpc")
        .env_clear()
        .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn_reaped("spawn humaux-retrieval-worker --serve-rpc")
}

fn wait_exit(child: &mut Reaped, limit: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("poll the child") {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

/// ADR-0066 D-K: the expected gateway uid equals this process's own uid ⇒ exit 2 naming the key, before any socket
/// is bound; an allow value other than exactly `1` is refused the same way. Fault: drop the `server_policy` call ⇒
/// the boot runs on to the next missing key and the refusal line is absent ⇒ red.
#[tokio::test]
async fn same_uid_expected_gateway_refuses_boot_without_allow() {
    let own = own_uid().expect("own uid");
    let dir = SockDir::new("rwboot");
    let socket = dir.0.join("rpc.sock");
    for allow in [None, Some("true")] {
        let log = dir.0.join("stderr.log");
        let mut env = vec![
            (
                "HUMAUX_RETRIEVAL_WORKER_SERVE_RPC_METRICS_ADDR",
                free_addr(),
            ),
            (
                "HUMAUX_RETRIEVAL_WORKER_EMBEDDING_MODEL",
                "boot-test-model".to_owned(),
            ),
            ("HUMAUX_RETRIEVAL_WORKER_MODEL_REVISION", "r1".to_owned()),
            ("HUMAUX_RETRIEVAL_WORKER_DIMENSION", "4".to_owned()),
            (UID_KEY, own.to_string()),
            (
                "HUMAUX_RETRIEVAL_WORKER_RPC_SOCKET_PATH",
                socket.display().to_string(),
            ),
        ];
        if let Some(value) = allow {
            env.push((ALLOW_KEY, value.to_owned()));
        }
        let mut child = spawn(&env, &log);
        let status = wait_exit(&mut child, Duration::from_secs(30));
        let stderr = std::fs::read_to_string(&log).unwrap_or_default();
        assert_eq!(
            status.and_then(|s| s.code()),
            Some(2),
            "allow={allow:?}: {stderr}"
        );
        let want = match allow {
            None => format!("{UID_KEY}={own} equals this process's own uid"),
            Some(_) => format!("{ALLOW_KEY} must be unset or exactly 1"),
        };
        assert!(stderr.contains(&want), "allow={allow:?}: {stderr}");
        assert!(
            !socket.exists(),
            "a refused boot bound {}",
            socket.display()
        );
    }
}

/// ADR-0066 D-K: with the dev-only opt-in the same configuration boots, logs the opt-in, and logs the accepted
/// same-uid peer when a client is admitted past the peer-credential layer (a malformed body: 422, no handler work).
/// Fault: drop the accept-time WARN from `admit_peer` ⇒ red.
#[tokio::test]
async fn same_uid_with_allow_boots_and_warns_on_accept() {
    let test = "same_uid_with_allow_boots_and_warns_on_accept";
    let Some(dsn) = std::env::var("HUMAUX_RETRIEVAL_WORKER_PG_DSN")
        .ok()
        .filter(|v| !v.is_empty())
    else {
        skip_or_fail(
            test,
            "missing object: HUMAUX_RETRIEVAL_WORKER_PG_DSN",
            ExternalDep::Postgres,
        );
        return;
    };
    let mut gitleaks = Vec::new();
    for (key, test_key) in [
        (
            "HUMAUX_RETRIEVAL_WORKER_GITLEAKS_BIN",
            "HUMAUX_TEST_GITLEAKS_BIN",
        ),
        (
            "HUMAUX_RETRIEVAL_WORKER_GITLEAKS_VERSION",
            "HUMAUX_TEST_GITLEAKS_VERSION",
        ),
        (
            "HUMAUX_RETRIEVAL_WORKER_GITLEAKS_SHA256",
            "HUMAUX_TEST_GITLEAKS_SHA256",
        ),
    ] {
        let Some(value) = std::env::var(test_key).ok().filter(|v| !v.is_empty()) else {
            skip_or_fail(
                test,
                &format!("missing object: {test_key}"),
                ExternalDep::Postgres,
            );
            return;
        };
        gitleaks.push((key, value));
    }
    let own = own_uid().expect("own uid");
    let dir = SockDir::new("rwallow");
    let socket = dir.0.join("rpc.sock");
    let log = dir.0.join("stderr.log");
    let env = admitted_env(dsn, gitleaks, &socket, own);
    let mut child = spawn(&env, &log);
    let (status, response) = admitted_request(&mut child, &socket, &log, own).await;
    let stderr = std::fs::read_to_string(&log).unwrap_or_default();
    assert_eq!(
        status, "422",
        "admitted past the peer layer; got: {response} / {stderr}"
    );
    for want in [
        format!("WARN humaux-retrieval-worker: {ALLOW_KEY}=1 (dev only)"),
        format!("WARN humaux-retrieval-worker: same-uid peer accepted uid={own}"),
    ] {
        assert!(stderr.contains(&want), "missing `{want}` in: {stderr}");
    }
}

/// Waits for `--serve-rpc` to bind `socket`, dials it verified as `own` and sends one malformed request;
/// returns the HTTP status and the raw response.
async fn admitted_request(
    child: &mut Reaped,
    socket: &Path,
    log: &Path,
    own: u32,
) -> (String, String) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !socket.exists() {
        if let Some(status) = child.try_wait().expect("poll the child") {
            panic!(
                "--serve-rpc exited ({status}) before binding: {}",
                std::fs::read_to_string(log).unwrap_or_default()
            );
        }
        assert!(
            Instant::now() < deadline,
            "--serve-rpc never bound {}",
            socket.display()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    // dep: UDS(retrieval-worker) — the test dials the worker as its gateway would, verified (ADR-0066 D-L)
    let stream = connect_verified(socket.to_str().expect("utf-8 path"), own)
        .await
        .expect("a verified dial of the worker this uid serves");
    let mut stream = stream.into_std().expect("std stream");
    stream.set_nonblocking(false).expect("blocking");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("read timeout");
    stream
        .write_all(
            b"POST /internal/v1/retrieval/query-embedding HTTP/1.1\r\nHost: localhost\r\n\
              Content-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        )
        .expect("write the request");
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    let status = response
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    (status, response)
}

/// The full `--serve-rpc` configuration with the dev-only opt-in: this uid is the expected gateway uid.
fn admitted_env(
    dsn: String,
    gitleaks: Vec<(&'static str, String)>,
    socket: &Path,
    own: u32,
) -> Vec<(&'static str, String)> {
    let mut env: Vec<(&'static str, String)> = vec![
        ("HUMAUX_RETRIEVAL_WORKER_PG_DSN", dsn),
        (
            "HUMAUX_RETRIEVAL_WORKER_EMBEDDING_PROVIDER",
            "dashscope".to_owned(),
        ),
        (
            "HUMAUX_RETRIEVAL_WORKER_EMBEDDING_MODEL",
            "boot-test-model".to_owned(),
        ),
        ("HUMAUX_RETRIEVAL_WORKER_MODEL_REVISION", "r1".to_owned()),
        ("HUMAUX_RETRIEVAL_WORKER_DIMENSION", "4".to_owned()),
        (
            "HUMAUX_RETRIEVAL_WORKER_EMBEDDING_VERSION",
            "boot-test@r1".to_owned(),
        ),
        ("HUMAUX_RETRIEVAL_WORKER_REGION", "cn-beijing".to_owned()),
        (
            "HUMAUX_RETRIEVAL_WORKER_MAX_INPUT_TOKENS",
            "8192".to_owned(),
        ),
        (
            "HUMAUX_RETRIEVAL_WORKER_EMBEDDING_MAX_BATCH_ITEMS",
            "10".to_owned(),
        ),
        (
            "HUMAUX_RETRIEVAL_WORKER_EGRESS_PROCESSOR_ID",
            "0190c39a-0000-7000-8000-000000000039".to_owned(),
        ),
        (
            "HUMAUX_RETRIEVAL_WORKER_CELL_ID",
            "00000000-0000-7000-8000-0000000c3901".to_owned(),
        ),
        (
            "HUMAUX_RETRIEVAL_WORKER_CALLER",
            "humaux-retrieval-worker".to_owned(),
        ),
        (
            "HUMAUX_RETRIEVAL_WORKER_QDRANT_HOST",
            "127.0.0.1".to_owned(),
        ),
        ("HUMAUX_RETRIEVAL_WORKER_QDRANT_PORT", {
            let addr = free_addr();
            addr.rsplit(':').next().unwrap_or_default().to_owned()
        }),
        (
            "HUMAUX_RETRIEVAL_WORKER_QDRANT_CIDR",
            "127.0.0.0/8".to_owned(),
        ),
        ("HUMAUX_RETRIEVAL_WORKER_QDRANT_TLS", "false".to_owned()),
        (
            "HUMAUX_RETRIEVAL_WORKER_SERVE_RPC_METRICS_ADDR",
            free_addr(),
        ),
        (
            "HUMAUX_RETRIEVAL_WORKER_RPC_SOCKET_PATH",
            socket.display().to_string(),
        ),
        (UID_KEY, own.to_string()),
        (ALLOW_KEY, "1".to_owned()),
    ];
    env.extend(gitleaks);
    env
}

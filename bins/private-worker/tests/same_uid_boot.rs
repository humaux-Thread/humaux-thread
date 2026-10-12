//! `private-worker::tests::same_uid_boot` — ADR-0066 D-K against the BINARY: `--serve-rpc` refuses to boot (exit 2,
//!   the key named) when the expected consolidation-worker uid is its own uid, unless
//!   HUMAUX_PRIVATE_WORKER_ALLOW_SAME_UID is exactly `1`; with the opt-in it boots, and the boot and every accepted
//!   same-uid peer log a WARN.
//! Depends-on: crates=[humaux-infra-cell, humaux-testkit, tokio]; services=[subprocess(humaux-private-worker),
//!   UDS(private-worker)]; env=[CARGO_BIN_EXE_humaux-private-worker, HUMAUX_PRIVATE_WORKER_ALLOW_SAME_UID,
//!   HUMAUX_PRIVATE_WORKER_CONSOLIDATION_UID, HUMAUX_PRIVATE_WORKER_CREDENTIALS,
//!   HUMAUX_PRIVATE_WORKER_EGRESS_RECIPIENTS, HUMAUX_PRIVATE_WORKER_HEALTH_RENEW_SECS,
//!   HUMAUX_PRIVATE_WORKER_HTTP_TIMEOUT_SECS, HUMAUX_PRIVATE_WORKER_PERMIT_TTL_SECS, HUMAUX_PRIVATE_WORKER_REGIONS,
//!   HUMAUX_PRIVATE_WORKER_RPC_SOCKET_PATH, HUMAUX_PRIVATE_WORKER_SERVE_RPC_METRICS_ADDR, PRIVATE_WORKER_PG_DSN];
//!   modules=[humaux-testkit, infra-cell::uds, testkit::reaped]
//! Called-by: [cargo-test]
//! Invariants: [the binary runs with a cleared environment and is held as Reaped (killed when the test ends or
//!   unwinds); the refused boots open no connection and bind no socket; the admitted boot connects only as
//!   role_private_worker with an empty credential map and is sent one malformed request that no handler accepts (no
//!   provider call, no row); a missing env is a failure under HUMAUX_REQUIRE_DB, a named SKIP otherwise (§79.2)]
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

const BIN: &str = env!("CARGO_BIN_EXE_humaux-private-worker");
const UID_KEY: &str = "HUMAUX_PRIVATE_WORKER_CONSOLIDATION_UID";
const ALLOW_KEY: &str = "HUMAUX_PRIVATE_WORKER_ALLOW_SAME_UID";

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
    // dep: subprocess(humaux-private-worker) — the binary under test
    Command::new(BIN)
        .arg("--serve-rpc")
        .env_clear()
        .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn_reaped("spawn humaux-private-worker --serve-rpc")
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

/// ADR-0066 D-K: the expected consolidation-worker uid equals this process's own uid ⇒ exit 2 naming the key, before any socket
/// is bound; an allow value other than exactly `1` is refused the same way. Fault: drop the `server_policy` call ⇒
/// the boot runs on to the next missing key and the refusal line is absent ⇒ red.
#[tokio::test]
async fn same_uid_expected_consolidation_refuses_boot_without_allow() {
    let own = own_uid().expect("own uid");
    let dir = SockDir::new("pwboot");
    let socket = dir.0.join("rpc.sock");
    for allow in [None, Some("true")] {
        let log = dir.0.join("stderr.log");
        let mut env = vec![
            ("HUMAUX_PRIVATE_WORKER_SERVE_RPC_METRICS_ADDR", free_addr()),
            (
                "HUMAUX_PRIVATE_WORKER_RPC_SOCKET_PATH",
                socket.display().to_string(),
            ),
            (UID_KEY, own.to_string()),
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
    let Some(dsn) = std::env::var("PRIVATE_WORKER_PG_DSN")
        .ok()
        .filter(|v| !v.is_empty())
    else {
        skip_or_fail(
            test,
            "missing object: PRIVATE_WORKER_PG_DSN",
            ExternalDep::Postgres,
        );
        return;
    };
    let own = own_uid().expect("own uid");
    let dir = SockDir::new("pwallow");
    let socket = dir.0.join("rpc.sock");
    let log = dir.0.join("stderr.log");
    // ADR-0060 D-J: an explicitly empty credential map, recipient list and region list boot (every route parks).
    let env: Vec<(&str, String)> = vec![
        ("PRIVATE_WORKER_PG_DSN", dsn),
        ("HUMAUX_PRIVATE_WORKER_HTTP_TIMEOUT_SECS", "5".to_owned()),
        ("HUMAUX_PRIVATE_WORKER_HEALTH_RENEW_SECS", "1800".to_owned()),
        ("HUMAUX_PRIVATE_WORKER_PERMIT_TTL_SECS", "30".to_owned()),
        ("HUMAUX_PRIVATE_WORKER_CREDENTIALS", String::new()),
        ("HUMAUX_PRIVATE_WORKER_EGRESS_RECIPIENTS", String::new()),
        ("HUMAUX_PRIVATE_WORKER_REGIONS", String::new()),
        ("HUMAUX_PRIVATE_WORKER_SERVE_RPC_METRICS_ADDR", free_addr()),
        (
            "HUMAUX_PRIVATE_WORKER_RPC_SOCKET_PATH",
            socket.display().to_string(),
        ),
        (UID_KEY, own.to_string()),
        (ALLOW_KEY, "1".to_owned()),
    ];
    let mut child = spawn(&env, &log);
    let (status, response) = admitted_request(&mut child, &socket, &log, own).await;
    let stderr = std::fs::read_to_string(&log).unwrap_or_default();
    assert_eq!(
        status, "422",
        "admitted past the peer layer; got: {response} / {stderr}"
    );
    for want in [
        format!("WARN humaux-private-worker: {ALLOW_KEY}=1 (dev only)"),
        format!("WARN humaux-private-worker: same-uid peer accepted uid={own}"),
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
    // dep: UDS(private-worker) — the test dials the worker as the consolidation worker would, verified (ADR-0066 D-L)
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
            b"POST /internal/v1/private/infer HTTP/1.1\r\nHost: localhost\r\n\
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

//! `private-worker::tests::exit_codes` — the process command line of `humaux-private-worker` (ADR-0066 D-D / D-N): no argument and an unknown argument
//!   are usage (exit 2), `--version` follows the burned-in sha, and `--serve-rpc` prints the start line first.
//! Depends-on: crates=[humaux-telemetry, humaux-testkit]; services=[subprocess(humaux-private-worker)];
//!   env=[CARGO_BIN_EXE_humaux-private-worker, CARGO_PKG_VERSION, HUMAUX_BUILD_GIT_SHA, HUMAUX_BUILD_TIME, HUMAUX_PRIVATE_WORKER_CONSOLIDATION_UID, HUMAUX_PRIVATE_WORKER_CREDENTIALS, HUMAUX_PRIVATE_WORKER_EGRESS_RECIPIENTS, HUMAUX_PRIVATE_WORKER_HEALTH_RENEW_SECS, HUMAUX_PRIVATE_WORKER_HTTP_TIMEOUT_SECS, HUMAUX_PRIVATE_WORKER_PERMIT_TTL_SECS, HUMAUX_PRIVATE_WORKER_PG_DSN, HUMAUX_PRIVATE_WORKER_REGIONS, HUMAUX_PRIVATE_WORKER_RPC_SOCKET_PATH, HUMAUX_PRIVATE_WORKER_SERVE_RPC_METRICS_ADDR]; modules=[humaux-telemetry, testkit::reaped]
//! Called-by: [cargo-test]
//! Invariants: [every humaux-private-worker spawn runs with a cleared environment and closed stdin and exits on its own (the one mode that connects dials a loopback listener that drops every connection, under a 60 s deadline, owned by a Reaped); nothing is written outside the process]
//! Spec: ADR-0037; ADR-0066 D-D; ADR-0066 D-N

use std::process::{Command, Output, Stdio};

use humaux_telemetry::{start_line, version_line};
use humaux_testkit::reaped::SpawnReaped as _;

const BIN: &str = env!("CARGO_BIN_EXE_humaux-private-worker");

/// The binary with exactly `args` and `env` (everything else cleared, stdin closed). Every mode exercised here
/// exits on its own within milliseconds: none has the configuration it would need to connect or serve.
fn run(args: &[&str], env: &[(&str, &str)]) -> Output {
    // dep: subprocess(humaux-private-worker) — the binary under test
    Command::new(BIN)
        .args(args)
        .env_clear()
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .output()
        .expect("run humaux-private-worker")
}

/// A loopback "database" that accepts every connection and closes it at once: the role pool's handshake fails
/// immediately (sqlx retries only a refused connect, until its acquire timeout) — a runtime failure, never a
/// configuration one. The accept thread lives as long as the test process.
fn dead_database() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            drop(stream);
        }
    });
    format!("postgres://role:unused@127.0.0.1:{port}/humaux_c39_dead")
}

/// A loopback address nothing listens on, for the mode's own ops listener.
fn free_addr() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    listener.local_addr().expect("addr").to_string()
}

/// `run` for a mode that reaches a connection: the child is owned by a [`Reaped`] (killed if an assertion or the
/// deadline fires first) and must exit within `secs`.
fn run_bounded(args: &[&str], env: &[(&str, &str)], secs: u64) -> (Option<i32>, String) {
    use std::io::Read as _;
    // dep: subprocess(humaux-private-worker) — the binary under test, bounded and reaped (ADR-0063 "Chain stall")
    let mut child = Command::new(BIN)
        .args(args)
        .env_clear()
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn_reaped("spawn the binary under test");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "did not exit within {secs} s"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    (status.code(), stderr)
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// ADR-0066 D-D, checked against the sha this cargo invocation burned in (the same `option_env!` the binary
/// read): with a sha the line on stdout and exit 0, without one exit 2 naming the missing object. Fault: answer
/// exit 0 without a sha ⇒ red in every build that carries none.
#[test]
fn version_mode_matches_the_burned_in_sha() {
    let out = run(&["--version"], &[]);
    let (code, stdout, stderr) = (out.status.code(), text(&out.stdout), text(&out.stderr));
    match version_line(
        "humaux-private-worker",
        env!("CARGO_PKG_VERSION"),
        option_env!("HUMAUX_BUILD_GIT_SHA"),
        option_env!("HUMAUX_BUILD_TIME"),
    ) {
        Ok(line) => assert_eq!(
            (code, stdout.trim_end()),
            (Some(0), line.as_str()),
            "{stderr}"
        ),
        Err(reason) => {
            assert_eq!(code, Some(2), "{stdout}{stderr}");
            assert!(
                stdout.is_empty() && stderr.contains(&reason),
                "{stdout}{stderr}"
            );
        }
    }
}

/// ADR-0066 D-N: an argument the binary does not know is usage, exit 2 — never ignored.
#[test]
fn unknown_arg_exits_2() {
    let out = run(&["--not-a-mode"], &[]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("usage:"),
        "{}",
        text(&out.stderr)
    );
}

/// ADR-0066 D-N: no argument is usage, exit 2 (a supervisor restarting on exit must not loop on a silent 0).
/// Fault: restore the argument-less arm ⇒ red.
#[test]
fn no_args_exits_2_with_usage() {
    let out = run(&[], &[]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("usage:"),
        "{}",
        text(&out.stderr)
    );
}

/// ADR-0066 D-D: the resident mode's FIRST stderr line is the start line, printed before any configuration is
/// read; with an empty environment the mode then refuses with exit 2 (the first missing key). Fault: print it after the
/// configuration ⇒ red.
#[test]
fn resident_start_line_comes_first() {
    let out = run(&["--serve-rpc"], &[]);
    let stderr = text(&out.stderr);
    let expected = start_line(
        "humaux-private-worker",
        "serve-rpc",
        env!("CARGO_PKG_VERSION"),
        option_env!("HUMAUX_BUILD_GIT_SHA"),
    );
    assert_eq!(stderr.lines().next(), Some(expected.as_str()), "{stderr}");
    assert_eq!(out.status.code(), Some(2), "{stderr}");
}

/// ADR-0066 D-N / ADR-0037 addendum (review P1, 2026-10-08): a resident mode whose database is down at boot is a
/// runtime failure — exit 1 (a restart can help), never 2 (usage/configuration), which `restart: on-failure:5`
/// would retry the same way but the runbook reads as "an operator must change something". The whole configuration is valid (empty route lists are legal, ADR-0060 D-C); only the database is unreachable.
/// Fault: map the runtime failure to 2 (the pre-fix code) ⇒ red.
#[test]
fn resident_runtime_failure_exits_1() {
    let dsn = dead_database();
    let ops = free_addr();
    let sock = std::env::temp_dir().join(format!("humaux_c39_exit_{}.sock", std::process::id()));
    let sock = sock.display().to_string();
    let (code, stderr) = run_bounded(
        &["--serve-rpc"],
        &[
            ("HUMAUX_PRIVATE_WORKER_SERVE_RPC_METRICS_ADDR", &ops),
            ("HUMAUX_PRIVATE_WORKER_RPC_SOCKET_PATH", &sock),
            ("HUMAUX_PRIVATE_WORKER_CONSOLIDATION_UID", "4000000000"),
            ("HUMAUX_PRIVATE_WORKER_PG_DSN", &dsn),
            ("HUMAUX_PRIVATE_WORKER_HTTP_TIMEOUT_SECS", "30"),
            ("HUMAUX_PRIVATE_WORKER_HEALTH_RENEW_SECS", "60"),
            ("HUMAUX_PRIVATE_WORKER_CREDENTIALS", ""),
            ("HUMAUX_PRIVATE_WORKER_EGRESS_RECIPIENTS", ""),
            ("HUMAUX_PRIVATE_WORKER_REGIONS", ""),
            ("HUMAUX_PRIVATE_WORKER_PERMIT_TTL_SECS", "60"),
        ],
        60,
    );
    assert!(
        stderr.contains("database role connection failed"),
        "{stderr}"
    );
    assert_eq!(code, Some(1), "{stderr}");
}

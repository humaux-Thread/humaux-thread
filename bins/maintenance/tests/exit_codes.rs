//! `maintenance::tests::exit_codes` — the process command line of `humaux-maintenance` (ADR-0066 D-D / D-N): no argument and an unknown argument
//!   are usage (exit 2), `--version` follows the burned-in sha, `readyz serve|health-serve` map the ops listener's
//!   200 / 503 to 0 / 2, and `--serve` prints the start line first.
//! Depends-on: crates=[humaux-telemetry]; services=[HTTP(loopback), subprocess(humaux-maintenance)];
//!   env=[CARGO_BIN_EXE_humaux-maintenance, CARGO_PKG_VERSION, HUMAUX_BUILD_GIT_SHA, HUMAUX_BUILD_TIME, HUMAUX_MAINTENANCE_HEALTH_SERVE_METRICS_ADDR, HUMAUX_MAINTENANCE_SERVE_METRICS_ADDR]; modules=[humaux-telemetry]
//! Called-by: [cargo-test]
//! Invariants: [every humaux-maintenance spawn runs with a cleared environment and closed stdin and exits on its own (no mode reached here can connect or serve); nothing is written outside the process; the probed listeners are the test's own loopback threads]
//! Spec: ADR-0037; ADR-0066 D-D; ADR-0066 D-N

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output, Stdio};

use humaux_telemetry::{start_line, version_line};

const BIN: &str = env!("CARGO_BIN_EXE_humaux-maintenance");

/// The binary with exactly `args` and `env` (everything else cleared, stdin closed). Every mode exercised here
/// exits on its own within milliseconds: none has the configuration it would need to connect or serve.
fn run(args: &[&str], env: &[(&str, &str)]) -> Output {
    // dep: subprocess(humaux-maintenance) — the binary under test
    Command::new(BIN)
        .args(args)
        .env_clear()
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .output()
        .expect("run humaux-maintenance")
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
        "humaux-maintenance",
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
    let out = run(&["--serve"], &[]);
    let stderr = text(&out.stderr);
    let expected = start_line(
        "humaux-maintenance",
        "serve",
        env!("CARGO_PKG_VERSION"),
        option_env!("HUMAUX_BUILD_GIT_SHA"),
    );
    assert_eq!(stderr.lines().next(), Some(expected.as_str()), "{stderr}");
    assert_eq!(out.status.code(), Some(2), "{stderr}");
}

/// A loopback listener answering one request with `status`; returns its address and the request line it read.
fn answer_once(status: &'static str) -> (String, std::thread::JoinHandle<String>) {
    // dep: HTTP(loopback) — a stand-in for the probed listener
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr").to_string();
    let served = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the probe connects");
        let (mut head, mut chunk) = (Vec::new(), [0u8; 512]);
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => head.extend_from_slice(&chunk[..n]),
            }
        }
        let body = "{\"status\":\"x\"}\n";
        let _ = write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        text(&head).lines().next().unwrap_or("").to_owned()
    });
    (addr, served)
}

/// A loopback address nothing listens on (bound, then released).
fn closed_addr() -> String {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("reserve a loopback port")
        .to_string()
}

/// ADR-0066 D-D: the compose healthcheck of each resident mode — GET /metrics on that mode's own ops address,
/// 200 ⇒ 0, 503 or nothing listening ⇒ 2. Fault: exit 0 on any answer ⇒ the 503 case red.
#[test]
fn readyz_probe_exit_code() {
    for (mode, key) in [
        ("serve", "HUMAUX_MAINTENANCE_SERVE_METRICS_ADDR"),
        (
            "health-serve",
            "HUMAUX_MAINTENANCE_HEALTH_SERVE_METRICS_ADDR",
        ),
    ] {
        let (addr, served) = answer_once("200 OK");
        let out = run(&["readyz", mode], &[(key, &addr)]);
        assert_eq!(out.status.code(), Some(0), "{mode}: {}", text(&out.stderr));
        assert_eq!(served.join().expect("served"), "GET /metrics HTTP/1.0");
        let (addr, served) = answer_once("503 Service Unavailable");
        let out = run(&["readyz", mode], &[(key, &addr)]);
        assert_eq!(out.status.code(), Some(2), "{mode}: {}", text(&out.stderr));
        assert!(
            text(&out.stderr).contains("status 503"),
            "{}",
            text(&out.stderr)
        );
        served.join().expect("served");
        let out = run(&["readyz", mode], &[(key, &closed_addr())]);
        assert_eq!(out.status.code(), Some(2), "{mode}: nothing listening");
    }
}

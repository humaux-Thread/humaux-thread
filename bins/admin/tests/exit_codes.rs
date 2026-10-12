//! `admin::tests::exit_codes` — the process command line of `humaux-admin` (ADR-0066 D-D / D-N): no argument and an unknown argument are
//!   usage (exit 2); `version` and `--version` print the same line, which follows the sha build.rs burned in.
//! Depends-on: crates=[humaux-telemetry]; services=[subprocess(humaux-admin)];
//!   env=[CARGO_BIN_EXE_humaux-admin, CARGO_PKG_VERSION, HUMAUX_BUILD_GIT_SHA, HUMAUX_BUILD_TIME]; modules=[humaux-telemetry]
//! Called-by: [cargo-test]
//! Invariants: [every humaux-admin spawn runs with a cleared environment and closed stdin and exits on its own (no mode reached here can connect or serve); nothing is written outside the process]
//! Spec: ADR-0037; ADR-0066 D-D; ADR-0066 D-N

use std::process::{Command, Output, Stdio};

use humaux_telemetry::version_line;

const BIN: &str = env!("CARGO_BIN_EXE_humaux-admin");

/// The binary with exactly `args` and `env` (everything else cleared, stdin closed). Every mode exercised here
/// exits on its own within milliseconds: none has the configuration it would need to connect or serve.
fn run(args: &[&str], env: &[(&str, &str)]) -> Output {
    // dep: subprocess(humaux-admin) — the binary under test
    Command::new(BIN)
        .args(args)
        .env_clear()
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .output()
        .expect("run humaux-admin")
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
        "humaux-admin",
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

/// `humaux-admin version` (the card's literal command) is the `--version` line.
#[test]
fn version_subcommand_is_the_version_flag() {
    let (sub, flag) = (run(&["version"], &[]), run(&["--version"], &[]));
    assert_eq!(
        (sub.status.code(), text(&sub.stdout), text(&sub.stderr)),
        (flag.status.code(), text(&flag.stdout), text(&flag.stderr))
    );
}

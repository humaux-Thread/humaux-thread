//! `xtask::tests::version` — `xtask --version` (ADR-0066 D-D / D-S): the loadgen image's `--version` line, which
//!   `deploy-check --release` compares with the release manifest's `binary=xtask git_sha=…`.
//! Depends-on: crates=[humaux-telemetry]; services=[subprocess(xtask)]; env=[CARGO_BIN_EXE_xtask, CARGO_PKG_VERSION,
//!   HUMAUX_BUILD_GIT_SHA, HUMAUX_BUILD_TIME]; modules=[humaux-telemetry]
//! Called-by: [cargo-test]
//! Invariants: [the binary runs with a cleared environment and closed stdin and exits on its own]
//! Spec: ADR-0066 D-D; ADR-0066 D-R; ADR-0066 D-S

use std::process::{Command, Stdio};

/// With the sha this cargo invocation burned in (the binary read the same `option_env!`): the shared version line
/// whose first token is `xtask` (build.sh's `loadgen:xtask`), exit 0; without one: exit 2 naming the missing
/// object — never the usage text. Fault (review P1, 2026-10-08): no `--version` arm ⇒ usage, exit 2 ⇒ red.
#[test]
fn version_flag_prints_the_xtask_line() {
    // dep: subprocess(xtask) — the binary under test
    let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("--version")
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .expect("run xtask --version");
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(!stderr.contains("usage:"), "{stderr}");
    match humaux_telemetry::version_line(
        "xtask",
        env!("CARGO_PKG_VERSION"),
        option_env!("HUMAUX_BUILD_GIT_SHA"),
        option_env!("HUMAUX_BUILD_TIME"),
    ) {
        Ok(line) => assert_eq!(
            (out.status.code(), stdout.trim_end()),
            (Some(0), line.as_str())
        ),
        Err(reason) => {
            assert_eq!(out.status.code(), Some(2), "{stdout}{stderr}");
            assert!(stderr.contains(&reason), "{stderr}");
        }
    }
    assert!(
        include_str!("../../deploy/release/build.sh").contains("loadgen:xtask"),
        "the manifest's loadgen binary is this binary's name"
    );
}

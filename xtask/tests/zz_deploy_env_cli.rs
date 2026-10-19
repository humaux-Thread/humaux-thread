//! Throwaway vehicle (not part of the PR): runs the CI step `xtask deploy-env` as a process, because targeted.yml only
//! runs `cargo test`. Prints the exit code and both streams, then asserts exit 0.

use std::process::Command;

#[test]
fn deploy_env_cli() {
    let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("deploy-env")
        .output()
        .expect("run xtask deploy-env");
    println!("EXIT={:?}", out.status.code());
    println!("STDOUT:\n{}", String::from_utf8_lossy(&out.stdout));
    println!("STDERR:\n{}", String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "xtask deploy-env exited {:?}", out.status.code());
}

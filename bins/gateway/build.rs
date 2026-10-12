//! `gateway::build` — Burns the revision this binary was built from into `HUMAUX_BUILD_GIT_SHA`, the input of both
//!   `--version` and the envelope's `provenance.binary_build` (§23.1③), so the gateway names its build without
//!   reading its own executable at runtime (ADR-0066 Review fix 2).
//! Depends-on: crates=[]; services=[subprocess(git)]; env=[HUMAUX_BUILD_GIT_SHA]; modules=[]
//! Called-by: [cargo-build]
//! Invariants: [an explicit `HUMAUX_BUILD_GIT_SHA` (release builds, build.sh) is never shadowed; a build without a
//!   resolvable sha still succeeds and the gateway then refuses to boot rather than report a placeholder (§23.1③)]
//! Spec: Baseline §4.4; §23.1③; ADR-0066 D-D; ADR-0066 Review fix 2
//!
//! Same logic as `bins/admin/build.rs` (one copy per package: a build script cannot be shared without a crate).
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=HUMAUX_BUILD_GIT_SHA");
    println!("cargo:rerun-if-env-changed=HUMAUX_BUILD_TIME");
    if std::env::var("HUMAUX_BUILD_GIT_SHA").is_ok_and(|v| !v.trim().is_empty()) {
        return; // rustc already sees it; do not shadow an explicit release value.
    }
    let Some(sha) = git(&["rev-parse", "HEAD"]) else {
        return;
    };
    // ponytail: HEAD + its branch ref only, so a dev build from a dirty tree carries HEAD's identity and two dirty
    // builds of one HEAD share it; release builds compile one `git archive` commit (ADR-0066 D-A) and pass the sha
    // explicitly, so there commit == build. Add a source-tree digest here if a dev e2e ever needs G23-5 across
    // uncommitted builds.
    if let Some(git_dir) = git(&["rev-parse", "--absolute-git-dir"]) {
        println!("cargo:rerun-if-changed={git_dir}/HEAD");
        if let Some(reference) = git(&["symbolic-ref", "--quiet", "HEAD"]) {
            println!("cargo:rerun-if-changed={git_dir}/{reference}");
        }
    }
    println!("cargo:rustc-env=HUMAUX_BUILD_GIT_SHA={sha}");
}

fn git(args: &[&str]) -> Option<String> {
    // dep: subprocess(git) — runs `git rev-parse` to read the build SHA
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!value.is_empty()).then_some(value)
}

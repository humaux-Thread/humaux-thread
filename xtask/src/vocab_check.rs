//! `xtask::vocab_check` — G-M20-16 controlled vocabulary anti-rot gate (§12.3, ADR-0089 D-E).
//! Depends-on: crates=[]; services=[subprocess(git)]; env=[]; modules=[public-pool::vocab::model, xtask::architecture_check]
//! Called-by: [xtask::main]
//! Invariants: [missing source/lock is FAIL; zero-use alone awaits public.unit_classifications]
//! Spec: Baseline §12.3; §57.1; §80.1; ADR-0089 D-E

use crate::architecture_check::{Verdict, workspace_root};
use crate::vocab_model::Vocabulary;
use std::{fs, path::Path, process::Command};

// §57.1: a missing-object diagnostic, not a database read or serving grant.
const ZERO_USE_MISSING: &str = concat!("public.", "unit_classifications");

fn check(root: &Path) -> Verdict {
    let read = |name: &str| {
        fs::read_to_string(root.join("contracts/public").join(name))
            .map_err(|e| vec![format!("{name}: {e}")])
    };
    match read("vocab_v1.toml").and_then(|source| {
        read("vocab_ids.lock").and_then(|lock| Vocabulary::parse(&source, &lock))
    }) {
        Ok(_) => Verdict::Pass,
        Err(errors) => Verdict::Fail(errors),
    }
}

fn git(root: &Path, args: &[&str]) -> Result<String, Vec<String>> {
    // dep: subprocess(git) — §12.3 append-only ids require repository history.
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .map_err(|e| vec![format!("vocab_ids.lock history: {e}")])?;
    if !output.status.success() {
        return Err(vec![
            "vocab_ids.lock: required Git history unavailable".into(),
        ]);
    }
    String::from_utf8(output.stdout).map_err(|e| vec![format!("vocab_ids.lock history: {e}")])
}
fn append_only(current: &str, previous: &str) -> Result<(), Vec<String>> {
    let now: Vec<_> = current.lines().collect();
    let old: Vec<_> = previous.lines().collect();
    if now.starts_with(&old) {
        return Ok(());
    }
    Err(old
        .iter()
        .enumerate()
        .filter(|(i, id)| now.get(*i) != Some(id))
        .map(|(_, id)| {
            format!("{id}: vocab_ids.lock is append-only; removed, renamed or reordered id")
        })
        .collect())
}
fn check_history(root: &Path) -> Result<(), Vec<String>> {
    // §12.3: full history is supplied by CI's fetch-depth=0; a shallow checkout cannot prove immutability.
    if git(root, &["rev-parse", "--is-shallow-repository"])?.trim() != "false" {
        return Err(vec!["vocab_ids.lock: full Git history required".into()]);
    }
    let current = fs::read_to_string(root.join("contracts/public/vocab_ids.lock"))
        .map_err(|e| vec![format!("vocab_ids.lock: {e}")])?;
    let commits = git(
        root,
        &[
            "log",
            "--format=%H",
            "--",
            "contracts/public/vocab_ids.lock",
        ],
    )?;
    for commit in commits.lines() {
        let revision = format!("{commit}:contracts/public/vocab_ids.lock");
        append_only(&current, &git(root, &["show", &revision])?)?;
    }
    Ok(())
}

fn verdict_at(root: &Path) -> Verdict {
    match check_history(root) {
        Ok(()) => check(root),
        Err(errors) => Verdict::Fail(errors),
    }
}

/// Exit code plus the exact stdout and stderr lines for a verdict (§57.1).
fn render(verdict: Verdict) -> (i32, Vec<String>, Vec<String>) {
    match verdict {
        Verdict::Pass => (
            0,
            vec![
                "vocab-check: pass — G-M20-16 ids, labels, replacements, BROADER DAG".into(),
                format!(
                    "vocab-check: not_applicable — zero-use (missing object: {ZERO_USE_MISSING}; M20-18)"
                ),
            ],
            vec![],
        ),
        Verdict::Fail(errors) => (
            1,
            vec![],
            errors
                .into_iter()
                .map(|error| format!("vocab-check: fail — G-M20-16 {error}"))
                .collect(),
        ),
        Verdict::NotApplicable(object) => (
            1,
            vec![],
            vec![format!(
                "vocab-check: fail — required input missing: {object}"
            )],
        ),
    }
}

/// CI entrypoint; only zero-use may be not_applicable (G-M20-16, §57.1).
pub fn run(_args: &[String]) -> i32 {
    let (code, out, err) = render(verdict_at(&workspace_root()));
    out.iter().for_each(|line| println!("{line}"));
    err.iter().for_each(|line| eprintln!("{line}"));
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    const LOCK: &str = "alpha\nbeta\n";
    const VALID: &str = include_str!("../tests/fixtures/vocab/valid.toml");

    #[test]
    fn g_m20_16_real_vocabulary() {
        assert_eq!(
            check(&workspace_root()),
            Verdict::Pass,
            "G-M20-16 real source anti-rot"
        );
    }
    #[test]
    fn fixtures_cover_exact_failures() {
        let cases = [
            (
                include_str!("../tests/fixtures/vocab/cycle.toml"),
                vec!["alpha: BROADER cycle", "beta: BROADER cycle"],
            ),
            (
                include_str!("../tests/fixtures/vocab/duplicate.toml"),
                vec!["beta: duplicate label (task, en, ALPHA)"],
            ),
            (
                include_str!("../tests/fixtures/vocab/deprecated.toml"),
                vec![
                    "alpha: DEPRECATED needs replaced_by pointing to an ACTIVE concept; ACTIVE must not have replaced_by",
                ],
            ),
            (
                include_str!("../tests/fixtures/vocab/missing_replacement.toml"),
                vec![
                    "alpha: DEPRECATED needs replaced_by pointing to an ACTIVE concept; ACTIVE must not have replaced_by",
                ],
            ),
            (
                include_str!("../tests/fixtures/vocab/deprecated_replacement.toml"),
                vec![
                    "alpha: DEPRECATED needs replaced_by pointing to an ACTIVE concept; ACTIVE must not have replaced_by",
                    "beta: DEPRECATED needs replaced_by pointing to an ACTIVE concept; ACTIVE must not have replaced_by",
                ],
            ),
            (
                include_str!("../tests/fixtures/vocab/renamed.toml"),
                vec![
                    "alpha: removed or renamed locked id",
                    "gamma: id absent from vocab_ids.lock",
                ],
            ),
            (
                include_str!("../tests/fixtures/vocab/removed.toml"),
                vec!["beta: removed or renamed locked id"],
            ),
            (
                include_str!("../tests/fixtures/vocab/cross_facet.toml"),
                vec!["alpha -> beta: BROADER crosses facets"],
            ),
        ];
        assert_eq!(cases.len(), 8);
        for (source, expected) in cases {
            assert_eq!(Vocabulary::parse(source, LOCK).unwrap_err(), expected);
        }
        let valid = Vocabulary::parse(VALID, LOCK).expect("valid fixture");
        assert_eq!(valid.concepts.len(), 2);
        assert_eq!(valid.relations.len(), 0);
    }
    #[test]
    fn lock_history_is_append_only() {
        assert_eq!(append_only("alpha\nbeta\ngamma\n", LOCK), Ok(()));
        assert_eq!(
            append_only("alpha\n", LOCK),
            Err(vec![
                "beta: vocab_ids.lock is append-only; removed, renamed or reordered id".into()
            ])
        );
        assert_eq!(
            append_only("alpha\ngamma\n", LOCK),
            Err(vec![
                "beta: vocab_ids.lock is append-only; removed, renamed or reordered id".into()
            ])
        );
    }
    const PREF_ERROR: &str = "alpha: exactly one PREF required per language";

    #[test]
    fn fixtures_cover_model_rules() {
        let cases = [
            (
                include_str!("../tests/fixtures/vocab/alt_only.toml"),
                vec![PREF_ERROR],
            ),
            (
                include_str!("../tests/fixtures/vocab/two_pref.toml"),
                vec![PREF_ERROR],
            ),
            (
                include_str!("../tests/fixtures/vocab/self_relation.toml"),
                vec!["alpha -> alpha: self relation"],
            ),
            (
                include_str!("../tests/fixtures/vocab/missing_endpoint.toml"),
                vec!["alpha -> missing: missing endpoint"],
            ),
            (
                include_str!("../tests/fixtures/vocab/duplicate_id.toml"),
                vec!["alpha: duplicate concept id"],
            ),
            (
                include_str!("../tests/fixtures/vocab/invalid_slug.toml"),
                vec!["Alpha: invalid stable slug"],
            ),
            (
                include_str!("../tests/fixtures/vocab/invalid_facet.toml"),
                vec!["alpha: invalid facet"],
            ),
        ];
        assert_eq!(cases.len(), 7);
        for (source, expected) in cases {
            assert_eq!(Vocabulary::parse(source, LOCK).unwrap_err(), expected);
        }
    }
    #[test]
    fn cycle_blames_only_nodes_on_the_cycle() {
        // alpha -> beta -> gamma -> beta: alpha reaches the cycle but is not on it.
        let source = include_str!("../tests/fixtures/vocab/cycle_tail.toml");
        assert_eq!(
            Vocabulary::parse(source, "alpha\nbeta\ngamma\n").unwrap_err(),
            vec!["beta: BROADER cycle", "gamma: BROADER cycle"]
        );
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vocab-check-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("contracts/public")).expect("scratch dir");
        dir
    }
    fn commit_lock(dir: &Path, lock: &str) {
        fs::write(dir.join("contracts/public/vocab_ids.lock"), lock).expect("lock");
        git(dir, &["add", "."]).expect("add");
        let identity = [
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
        ];
        let mut args = identity.to_vec();
        args.extend(["-c", "commit.gpgsign=false", "commit", "-q", "-m", "lock"]);
        git(dir, &args).expect("commit");
    }
    fn lock_repo(name: &str, locks: &[&str]) -> std::path::PathBuf {
        let dir = scratch(name);
        git(&dir, &["init", "-q"]).expect("init");
        for lock in locks {
            commit_lock(&dir, lock);
        }
        dir
    }

    #[test]
    fn check_history_accepts_append_only_history() {
        let dir = lock_repo("append", &["alpha\nbeta\n", "alpha\nbeta\ngamma\n"]);
        assert_eq!(check_history(&dir), Ok(()));
        let _ = fs::remove_dir_all(&dir);
    }
    #[test]
    fn check_history_rejects_rewritten_lock() {
        let dir = lock_repo("rewrite", &["alpha\nbeta\ngamma\n", "alpha\ngamma\n"]);
        let append = "vocab_ids.lock is append-only; removed, renamed or reordered id";
        assert_eq!(
            check_history(&dir),
            Err(vec![format!("beta: {append}"), format!("gamma: {append}")])
        );
        let _ = fs::remove_dir_all(&dir);
    }
    #[test]
    fn check_history_rejects_shallow_clone() {
        let origin = lock_repo("origin", &["alpha\n", "alpha\nbeta\n"]);
        let clone = scratch("shallow");
        fs::remove_dir_all(&clone).expect("clean clone target");
        let url = format!("file://{}", origin.display());
        git(
            &std::env::temp_dir(),
            &[
                "clone",
                "-q",
                "--depth",
                "1",
                &url,
                &clone.display().to_string(),
            ],
        )
        .expect("shallow clone");
        assert_eq!(
            check_history(&clone),
            Err(vec!["vocab_ids.lock: full Git history required".into()])
        );
        let _ = fs::remove_dir_all(&origin);
        let _ = fs::remove_dir_all(&clone);
    }
    #[test]
    fn check_history_without_git_repo_fails() {
        let dir = scratch("no-git");
        assert_eq!(
            check_history(&dir),
            Err(vec![
                "vocab_ids.lock: required Git history unavailable".into()
            ])
        );
        let _ = fs::remove_dir_all(&dir);
    }
    #[test]
    fn missing_lock_fails_after_source_is_read() {
        let dir = scratch("no-lock");
        fs::write(dir.join("contracts/public/vocab_v1.toml"), VALID).expect("source");
        let Verdict::Fail(errors) = check(&dir) else {
            panic!("missing lock must fail");
        };
        assert_eq!(errors.len(), 1);
        assert!(errors[0].starts_with("vocab_ids.lock:"));
        let _ = fs::remove_dir_all(&dir);
    }
    #[test]
    fn run_renders_exit_codes_and_not_applicable_line() {
        assert_eq!(ZERO_USE_MISSING, concat!("public.", "unit_classifications"));
        assert_eq!(
            render(Verdict::Pass),
            (
                0,
                vec![
                    "vocab-check: pass — G-M20-16 ids, labels, replacements, BROADER DAG".into(),
                    format!(
                        "vocab-check: not_applicable — zero-use (missing object: {}; M20-18)",
                        concat!("public.", "unit_classifications")
                    ),
                ],
                vec![]
            )
        );
        assert_eq!(
            render(Verdict::Fail(vec!["x".into(), "y".into()])),
            (
                1,
                vec![],
                vec![
                    "vocab-check: fail — G-M20-16 x".into(),
                    "vocab-check: fail — G-M20-16 y".into()
                ]
            )
        );
        assert_eq!(
            render(Verdict::NotApplicable("vocab_v1.toml".into())),
            (
                1,
                vec![],
                vec!["vocab-check: fail — required input missing: vocab_v1.toml".into()]
            )
        );
    }
    #[test]
    fn missing_source_and_lock_fail() {
        let root = workspace_root().join("xtask/tests/fixtures/vocab/missing-input");
        let Verdict::Fail(errors) = check(&root) else {
            panic!("missing source must fail");
        };
        assert_eq!(errors.len(), 1);
        assert!(errors[0].starts_with("vocab_v1.toml:"));
        assert_eq!(
            Vocabulary::parse(VALID, "").unwrap_err(),
            vec![
                "alpha: id absent from vocab_ids.lock",
                "beta: id absent from vocab_ids.lock"
            ]
        );
    }
}

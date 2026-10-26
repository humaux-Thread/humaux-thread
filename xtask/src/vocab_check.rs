//! `xtask::vocab_check` — G-M20-16 controlled vocabulary anti-rot gate (§12.3, ADR-0089 D-E).
//! Depends-on: crates=[]; services=[subprocess(git)]; env=[]; modules=[public-pool::vocab::model, xtask::architecture_check]
//! Called-by: [xtask::main]
//! Invariants: [missing source/lock is FAIL; zero-use alone awaits public.unit_classifications]
//! Spec: Baseline §12.3; §57.1; §80.1; ADR-0089 D-E

use crate::architecture_check::{Verdict, workspace_root};
use crate::vocab_model::Vocabulary;
use std::{fs, path::Path, process::Command};

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

/// CI entrypoint; only zero-use may be not_applicable (G-M20-16, §57.1).
pub fn run(_args: &[String]) -> i32 {
    let root = workspace_root();
    let verdict = match check_history(&root) {
        Ok(()) => check(&root),
        Err(errors) => Verdict::Fail(errors),
    };
    match verdict {
        Verdict::Pass => {
            println!("vocab-check: pass — G-M20-16 ids, labels, replacements, BROADER DAG");
            println!(
                "vocab-check: not_applicable — zero-use (missing object: public.unit_classifications; M20-18)"
            );
            0
        }
        Verdict::Fail(errors) => {
            for error in errors {
                eprintln!("vocab-check: fail — G-M20-16 {error}");
            }
            1
        }
        Verdict::NotApplicable(object) => {
            eprintln!("vocab-check: fail — required input missing: {object}");
            1
        }
    }
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

//! `xtask::schedule_register` — G-M21-1: the schedule register covers every frozen §65 repair job.
//! Depends-on: crates=[toml]; services=[]; env=[CARGO_MANIFEST_DIR, GITHUB_ACTIONS]; modules=[]
//! Called-by: [xtask::main]
//! Invariants: [every §65 job has exactly one register entry keyed by the table's job name; a `task` target is a `Task`
//!   variant named by serve.rs's exhaustive every_key match; `not_applicable` carries owner and reason; an entry outside
//!   §65, a repeated §65 job, or both/neither target is red]
//! Spec: Baseline §65; §57.1; ADR-0123; C-M21-3
//!
//! `cargo xtask schedule-register` — G-M21-1. Baseline §65 freezes the repair-job table: a job exists only if the
//! table lists it, so `docs/architecture/schedule_register.toml` must map every §65 row to a resident `Task` or to
//! `not_applicable(owner, reason)` (module design note M21 D2). The table is parsed from the first fenced block under
//! `# 65.`; the `Task` variant names are read from `bins/maintenance/src/serve.rs` (its `every_key` match is
//! exhaustive, so its arms are exactly the closed `MaintenanceTask` set that serve.rs imports as `Task`).
//!
//! The gate is tri-state (§57.1): `pass`, `fail: <reason>` naming the §65 job, or `not_applicable` naming the missing
//! Baseline file/heading. In CI a missing input is a failure, never a skip.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// The frozen §65 authority (D2: "what exists").
const BASELINE: &str = "docs/architecture/Baseline_2.9.md";
/// The schedule register (C-M21-3).
const REGISTER: &str = "docs/architecture/schedule_register.toml";
/// The resident daemon whose `Task` variant names the register may use.
const SERVE: &str = "bins/maintenance/src/serve.rs";
/// The §65 heading this gate parses; the next `# ` heading ends the section.
const SECTION_65: &str = "# 65.";

/// This gate's three-state verdict (§57.1: every gate is pass/fail/not_applicable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every §65 row is covered and every register entry is well-formed.
    Pass,
    /// One reason per failure; every reason names the §65 job or the offending entry.
    Fail(Vec<String>),
    /// The Baseline file or its §65 heading is absent.
    NotApplicable(String),
}

/// One register entry: the §65 job name as the table spells it, and exactly one target (§65).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The §65 job name, verbatim.
    pub job: String,
    /// What the entry points at.
    pub target: Target,
}

/// A register entry's single target (§65).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// An existing `Task` variant name from `bins/maintenance/src/serve.rs`.
    Task(String),
    /// No resident task; the owning card/module and the note clause that says why.
    NotApplicable {
        /// The owning card or module (`Mxx…`).
        owner: String,
        /// One clause from the module design note.
        reason: String,
    },
}

/// Parses the job column of the first fenced table under the Baseline `# 65.` heading (§65).
///
/// `None` means the heading is absent (not_applicable, §57.1); an empty vector means the heading exists but its
/// table has no rows, which [`check`] reports as a failure rather than a pass.
pub fn parse_section_65(baseline: &str) -> Option<Vec<String>> {
    let mut in_section = false;
    let mut in_fence = false;
    let mut jobs = Vec::new();
    for line in baseline.lines() {
        if !in_section {
            in_section = line.starts_with(SECTION_65);
            continue;
        }
        if in_fence && line.trim() == "```" {
            return Some(jobs);
        }
        if !in_fence {
            if line.starts_with("# ") {
                return Some(jobs);
            }
            in_fence = line.trim() == "```text";
            continue;
        }
        if let Some(job) = first_cell(line)
            && job != "job"
        {
            jobs.push(job.to_string());
        }
    }
    in_section.then_some(jobs)
}

/// The first whitespace-separated cell of a §65 table row (the run of spaces separates the job from its frequency).
fn first_cell(line: &str) -> Option<&str> {
    line.split("  ")
        .map(str::trim)
        .find(|cell| !cell.is_empty())
}

/// Collects the `Task` variant names named by the `every_key` match in `bins/maintenance/src/serve.rs` (§65).
///
/// `every_key` matches `Task` exhaustively, so its arms are exactly the closed `MaintenanceTask` set (ADR-0062
/// D-C) even though the enum lives in `crates/adapters/src/maintenance_repo.rs` and serve.rs imports it as `Task`.
/// Only the `fn every_key` body is scanned, so a `Task::… =>` arm elsewhere in the file cannot widen the set, and
/// an alternation arm (`Task::A | Task::B =>`) contributes every name it lists.
pub fn parse_task_variants(serve_src: &str) -> BTreeSet<String> {
    let mut variants = BTreeSet::new();
    let mut lines = serve_src
        .lines()
        .skip_while(|line| !line.contains("fn every_key("));
    let Some(signature) = lines.next() else {
        return variants;
    };
    let mut depth = braces(signature);
    for line in lines {
        if depth <= 0 {
            break;
        }
        variants.extend(arm_variants(line));
        depth += braces(line);
    }
    variants
}

/// The net `{` minus `}` count of one line, which bounds the `every_key` body.
fn braces(line: &str) -> i32 {
    line.matches('{').count() as i32 - line.matches('}').count() as i32
}

/// The `Task` variant names in one match arm, including both sides of a `|` alternation.
fn arm_variants(line: &str) -> Vec<String> {
    let Some((pattern, _)) = line.split_once("=>") else {
        return Vec::new();
    };
    pattern
        .match_indices("Task::")
        .map(|(at, marker)| ident(&pattern[at + marker.len()..]))
        .filter(|name| !name.is_empty())
        .collect()
}

/// The identifier starting at `src`; empty when `src` does not start with one.
fn ident(src: &str) -> String {
    src.chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

/// Parses the register TOML into one [`Entry`] per top-level job table (§65).
///
/// An entry must carry exactly one of `task` / `not_applicable`; anything else is a parse error the gate reports as
/// a failure naming the entry.
pub fn parse_register(register_toml: &str) -> Result<Vec<Entry>, String> {
    let value: toml::Value =
        toml::from_str(register_toml).map_err(|error| format!("{REGISTER}: {error}"))?;
    let table = value
        .as_table()
        .ok_or_else(|| format!("{REGISTER}: the top level is not a table"))?;
    table
        .iter()
        .map(|(job, value)| entry_from_value(job, value))
        .collect()
}

/// Builds one [`Entry`] and enforces the exactly-one-target rule.
fn entry_from_value(job: &str, value: &toml::Value) -> Result<Entry, String> {
    let table = value
        .as_table()
        .ok_or_else(|| format!("entry `{job}` is not a table"))?;
    let target = match (table.get("task"), table.get("not_applicable")) {
        (Some(_), Some(_)) => {
            return Err(format!(
                "entry `{job}` has both `task` and `not_applicable`"
            ));
        }
        (None, None) => {
            return Err(format!(
                "entry `{job}` has neither `task` nor `not_applicable`"
            ));
        }
        (Some(task), None) => Target::Task(string_field(job, "task", task)?),
        (None, Some(not_applicable)) => not_applicable_target(job, not_applicable)?,
    };
    Ok(Entry {
        job: job.to_string(),
        target,
    })
}

/// Reads a required string field, with an error that names the entry and the field.
fn string_field(job: &str, field: &str, value: &toml::Value) -> Result<String, String> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("entry `{job}`: `{field}` is not a string"))
}

/// Builds the `not_applicable` target from its `owner` and `reason` fields.
fn not_applicable_target(job: &str, value: &toml::Value) -> Result<Target, String> {
    let table = value
        .as_table()
        .ok_or_else(|| format!("entry `{job}`: `not_applicable` is not a table"))?;
    let owner = table
        .get("owner")
        .ok_or_else(|| format!("entry `{job}`: `not_applicable.owner` is missing"))
        .and_then(|field| string_field(job, "not_applicable.owner", field))?;
    let reason = table
        .get("reason")
        .ok_or_else(|| format!("entry `{job}`: `not_applicable.reason` is missing"))
        .and_then(|field| string_field(job, "not_applicable.reason", field))?;
    if owner.trim().is_empty() || reason.trim().is_empty() {
        return Err(format!(
            "entry `{job}`: `not_applicable` needs a non-empty owner and reason"
        ));
    }
    Ok(Target::NotApplicable { owner, reason })
}

/// Compares the §65 rows with the register and the `Task` variant set (§65, §57.1).
pub fn check(section_65: &[String], entries: &[Entry], variants: &BTreeSet<String>) -> Verdict {
    if section_65.is_empty() {
        return Verdict::Fail(vec!["§65 table has no job rows".to_string()]);
    }
    let expected: BTreeSet<&str> = section_65.iter().map(String::as_str).collect();
    let mut failures = Vec::new();
    if expected.len() != section_65.len() {
        failures.push("§65 table repeats a job name".to_string());
    }
    failures.extend(uncovered(section_65, entries));
    for entry in entries {
        if !expected.contains(entry.job.as_str()) {
            failures.push(format!("register entry `{}` is not a §65 job", entry.job));
        }
        if let Target::Task(label) = &entry.target
            && !variants.contains(label)
        {
            failures.push(format!(
                "entry `{}` names task `{label}`, which is not a Task variant in {SERVE}",
                entry.job
            ));
        }
    }
    if failures.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(failures)
    }
}

/// The §65 jobs with no register entry, each reason naming the job.
fn uncovered(section_65: &[String], entries: &[Entry]) -> Vec<String> {
    section_65
        .iter()
        .filter(|job| !entries.iter().any(|entry| entry.job == job.as_str()))
        .map(|job| format!("no register entry for §65 job `{job}`"))
        .collect()
}

/// `cargo xtask schedule-register` entry point (§65, §57.1).
pub fn run(_args: &[String]) -> i32 {
    let root = workspace_root();
    let baseline = match fs::read_to_string(root.join(BASELINE)) {
        Ok(text) => text,
        Err(_) => return report(Verdict::NotApplicable(BASELINE.to_string())),
    };
    let Some(section_65) = parse_section_65(&baseline) else {
        return report(Verdict::NotApplicable(
            "the `# 65.` heading in docs/architecture/Baseline_2.9.md".to_string(),
        ));
    };
    let register = match fs::read_to_string(root.join(REGISTER)) {
        Ok(text) => text,
        Err(_) => return report(Verdict::Fail(vec![format!("cannot read {REGISTER}")])),
    };
    let serve_src = match fs::read_to_string(root.join(SERVE)) {
        Ok(text) => text,
        Err(_) => return report(Verdict::Fail(vec![format!("cannot read {SERVE}")])),
    };
    let entries = match parse_register(&register) {
        Ok(entries) => entries,
        Err(reason) => return report(Verdict::Fail(vec![reason])),
    };
    report(check(
        &section_65,
        &entries,
        &parse_task_variants(&serve_src),
    ))
}

/// Renders a verdict in the §57.1 three-state form: the exit code and the exact line to print (§57.1).
fn render(verdict: &Verdict, in_ci: bool) -> (i32, String) {
    match verdict {
        Verdict::Pass => (0, "pass".to_string()),
        Verdict::Fail(reasons) => (
            1,
            reasons
                .iter()
                .map(|reason| format!("fail: {reason}"))
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        Verdict::NotApplicable(missing) if in_ci => (
            1,
            format!("fail: {missing} is missing and CI cannot report not_applicable (§57.1)"),
        ),
        Verdict::NotApplicable(missing) => (0, format!("not_applicable: {missing}")),
    }
}

/// Prints the rendered verdict — stdout unless it is a failure, which goes to stderr — and returns its exit code.
fn report(verdict: Verdict) -> i32 {
    let in_ci = std::env::var("GITHUB_ACTIONS").is_ok_and(|value| value == "true");
    let (code, line) = render(&verdict, in_ci);
    if code == 0 {
        println!("{line}");
    } else {
        eprintln!("{line}");
    }
    code
}

/// The workspace root this gate reads, from the crate manifest directory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_BASELINE: &str = "# 65. Automated repair jobs\n\n```text\njob                                   频率\nPG <-> Qdrant diff                    每日\norphan relation scan                  每日\n```\n\n# 66. Next\n";
    const FIXTURE_SERVE: &str = "const fn every_key(task: Task) -> &'static str {\n    match task {\n        Task::Lost => \"a\",\n        Task::Partitions => \"b\",\n    }\n}\n";
    const COMPLETE_REGISTER: &str = "[\"PG <-> Qdrant diff\"]\nnot_applicable = { owner = \"M21-5\", reason = \"missing\" }\n\n[\"orphan relation scan\"]\ntask = \"Lost\"\n";
    const ALTERNATION_SERVE: &str = "fn other(task: Task) -> &'static str {\n    match task {\n        Task::Bogus => \"z\",\n    }\n}\n\nconst fn every_key(task: Task) -> &'static str {\n    match task {\n        Task::Lost | Task::Partitions => \"a\",\n    }\n}\n";

    /// The exact §65 jobs the frozen table lists; a spec row added, removed or renamed must turn this test red.
    const SECTION_65_JOBS: [&str; 12] = [
        "PG <-> Qdrant diff",
        "orphan relation scan",
        "authority superseded_by consistency scan",
        "projection watermark audit",
        "public source closure audit",
        "artifact object existence",
        "stale lease/lock reap",
        "waiting_key visibility",
        "retention",
        "backup verification",
        "restore drill scheduling",
        "config drift",
    ];

    fn variants() -> BTreeSet<String> {
        parse_task_variants(FIXTURE_SERVE)
    }

    #[test]
    fn complete_register_passes() {
        let section = parse_section_65(FIXTURE_BASELINE).expect("fixture heading");
        assert_eq!(
            section,
            vec![
                "PG <-> Qdrant diff".to_string(),
                "orphan relation scan".to_string()
            ]
        );
        let entries = parse_register(COMPLETE_REGISTER).expect("fixture register");
        assert_eq!(entries.len(), 2);
        let expected: BTreeSet<String> = ["Lost", "Partitions"]
            .iter()
            .map(|name| name.to_string())
            .collect();
        assert_eq!(variants(), expected);
        assert_eq!(check(&section, &entries, &variants()), Verdict::Pass);
    }

    #[test]
    fn deleted_register_row_fails_naming_the_job() {
        let section = parse_section_65(FIXTURE_BASELINE).expect("fixture heading");
        let entries =
            parse_register("[\"PG <-> Qdrant diff\"]\ntask = \"Lost\"\n").expect("register");
        assert_eq!(
            check(&section, &entries, &variants()),
            Verdict::Fail(vec![
                "no register entry for §65 job `orphan relation scan`".to_string()
            ])
        );
    }

    #[test]
    fn unknown_task_label_fails() {
        let section = parse_section_65(FIXTURE_BASELINE).expect("fixture heading");
        let entries = parse_register(
            "[\"PG <-> Qdrant diff\"]\ntask = \"NoSuchTask\"\n\n[\"orphan relation scan\"]\ntask = \"Lost\"\n",
        )
        .expect("register");
        assert_eq!(
            check(&section, &entries, &variants()),
            Verdict::Fail(vec![format!(
                "entry `PG <-> Qdrant diff` names task `NoSuchTask`, which is not a Task variant in {SERVE}"
            )])
        );
    }

    #[test]
    fn entry_with_both_targets_fails() {
        let error = parse_register(
            "[\"PG <-> Qdrant diff\"]\ntask = \"Lost\"\nnot_applicable = { owner = \"M21-5\", reason = \"missing\" }\n",
        )
        .expect_err("both targets must be rejected");
        assert_eq!(
            error,
            "entry `PG <-> Qdrant diff` has both `task` and `not_applicable`"
        );
    }

    #[test]
    fn entry_with_neither_target_fails() {
        let error =
            parse_register("[\"PG <-> Qdrant diff\"]\n").expect_err("no target must be rejected");
        assert_eq!(
            error,
            "entry `PG <-> Qdrant diff` has neither `task` nor `not_applicable`"
        );
    }

    #[test]
    fn entry_outside_section_65_fails() {
        let section = parse_section_65(FIXTURE_BASELINE).expect("fixture heading");
        let entries = parse_register(
            "[\"PG <-> Qdrant diff\"]\ntask = \"Lost\"\n\n[\"orphan relation scan\"]\ntask = \"Lost\"\n\n[\"not a listed job\"]\ntask = \"Lost\"\n",
        )
        .expect("register");
        assert_eq!(
            check(&section, &entries, &variants()),
            Verdict::Fail(vec![
                "register entry `not a listed job` is not a §65 job".to_string()
            ])
        );
    }

    #[test]
    fn parse_section_65_absent_heading_is_none() {
        assert_eq!(parse_section_65("# 64. x\n"), None);
    }

    #[test]
    fn render_not_applicable_locally_exits_zero() {
        assert_eq!(
            render(&Verdict::NotApplicable("X".to_string()), false),
            (0, "not_applicable: X".to_string())
        );
    }

    #[test]
    fn render_not_applicable_in_ci_exits_one() {
        assert_eq!(
            render(&Verdict::NotApplicable("X".to_string()), true),
            (
                1,
                "fail: X is missing and CI cannot report not_applicable (§57.1)".to_string()
            )
        );
    }

    #[test]
    fn check_empty_section_65_table_fails() {
        assert_eq!(
            check(&[], &[], &variants()),
            Verdict::Fail(vec!["§65 table has no job rows".to_string()])
        );
    }

    #[test]
    fn check_duplicate_section_65_job_fails() {
        let entries = parse_register("[\"a\"]\ntask = \"Lost\"\n").expect("register");
        assert_eq!(
            check(&["a".to_string(), "a".to_string()], &entries, &variants()),
            Verdict::Fail(vec!["§65 table repeats a job name".to_string()])
        );
    }

    #[test]
    fn parse_task_variants_reads_only_every_key_arms() {
        let expected: BTreeSet<String> = ["Lost", "Partitions"]
            .iter()
            .map(|name| name.to_string())
            .collect();
        assert_eq!(parse_task_variants(ALTERNATION_SERVE), expected);
    }

    #[test]
    fn parse_register_rejects_empty_not_applicable_fields() {
        let empty_owner =
            parse_register("[\"a\"]\nnot_applicable = { owner = \" \", reason = \"missing\" }\n")
                .expect_err("blank owner must be rejected");
        assert_eq!(
            empty_owner,
            "entry `a`: `not_applicable` needs a non-empty owner and reason"
        );
        let empty_reason =
            parse_register("[\"a\"]\nnot_applicable = { owner = \"M21-5\", reason = \"\" }\n")
                .expect_err("blank reason must be rejected");
        assert_eq!(
            empty_reason,
            "entry `a`: `not_applicable` needs a non-empty owner and reason"
        );
    }

    #[test]
    fn repository_register_covers_section_65_exactly() {
        let root = workspace_root();
        let baseline = fs::read_to_string(root.join(BASELINE)).expect("Baseline must be readable");
        let register = fs::read_to_string(root.join(REGISTER)).expect("register must be readable");
        let serve_src = fs::read_to_string(root.join(SERVE)).expect("serve.rs must be readable");
        let section = parse_section_65(&baseline).expect("§65 heading must exist");
        assert_eq!(section, SECTION_65_JOBS.map(str::to_string).to_vec());
        let entries = parse_register(&register).expect("register must parse");
        let variants = parse_task_variants(&serve_src);
        assert!(variants.contains("Partitions"));
        assert_eq!(check(&section, &entries, &variants), Verdict::Pass);
        assert_eq!(entries.len(), SECTION_65_JOBS.len());
    }
}

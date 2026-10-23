//! `xtask::tests::experiment_workflow` — `.github/workflows/experiment.yml`'s subcommand guard (M24-16): the dispatch
//!   input reaches the shell as `$SUBCOMMAND`, and a value outside the workflow's choice list exits 2 before cargo.
//! Depends-on: crates=[]; services=[subprocess(bash)]; env=[]; modules=[]
//! Called-by: [cargo-test]
//! Invariants: [the guard body is extracted from the committed workflow, never restated; the case arms equal the
//!   workflow's `options:` list exactly; an unknown, empty, padded or unset value exits 2]
//! Spec: Baseline §46; §80.1; M24-16

use std::process::{Command, Output, Stdio};

/// The committed workflow: `include_str!` holds the test to the exact text that ships.
const WORKFLOW: &str = include_str!("../../.github/workflows/experiment.yml");

const GUARD_BEGIN: &str = "# BEGIN experiment-subcommand-guard";
const GUARD_END: &str = "# END experiment-subcommand-guard";

/// The experiment harnesses that exist in xtask today, in the workflow's order.
const EXPECTED: [&str; 3] = ["load", "load-open", "soak"];

/// Values that are not one of the three: unknown, empty, case-shifted, padded, shell metacharacters, two words, and
/// the input not set at all (§57.1: a missing value is a failure, never a green no-op).
const OUTSIDE: [Option<&str>; 7] = [
    Some("storage-measure"),
    Some(""),
    Some("LOAD"),
    Some("load "),
    Some("load;true"),
    Some("load-open soak"),
    None,
];

fn leading_spaces(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// The step's `run:` body, dedented by the YAML block scalar's indentation. The sentinels make the extraction
/// unambiguous: moving the guard away from them fails here instead of silently testing nothing.
fn guard_script() -> String {
    let lines: Vec<&str> = WORKFLOW.lines().collect();
    let begin = lines
        .iter()
        .position(|line| line.trim_end().ends_with(GUARD_BEGIN))
        .expect("experiment.yml must carry the guard BEGIN sentinel");
    let end = lines
        .iter()
        .position(|line| line.trim_end().ends_with(GUARD_END))
        .expect("experiment.yml must carry the guard END sentinel");
    assert!(begin < end, "the guard's sentinels are out of order");
    let indent = leading_spaces(lines[begin]);
    assert!(indent > 0, "the guard must be a `run: |` block scalar");
    let pad = " ".repeat(indent);
    let body: Vec<&str> = lines[begin + 1..end].to_vec();
    for line in &body {
        if !line.trim().is_empty() {
            assert!(
                line.starts_with(&pad),
                "guard line is not indented as the block scalar's body: {line:?}"
            );
        }
    }
    body.iter()
        .map(|line| line.get(indent..).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// The `subcommand` input's `options:` list, in declaration order.
fn choice_list() -> Vec<String> {
    let lines: Vec<&str> = WORKFLOW.lines().collect();
    let subcommand = lines
        .iter()
        .position(|line| line.trim_end() == "subcommand:")
        .expect("experiment.yml must declare the subcommand input");
    let input_indent = leading_spaces(lines[subcommand]);
    let mut options = None;
    for (index, line) in lines.iter().enumerate().skip(subcommand + 1) {
        if line.trim().is_empty() {
            continue;
        }
        if line.trim_end() == "options:" {
            options = Some(index);
            break;
        }
        if leading_spaces(line) <= input_indent {
            break;
        }
    }
    let start = options.expect("the subcommand input must carry an options: list") + 1;
    let item_indent = leading_spaces(lines[start]);
    let mut list = Vec::new();
    for line in &lines[start..] {
        let Some(item) = line.trim().strip_prefix("- ") else {
            break;
        };
        if leading_spaces(line) != item_indent {
            break;
        }
        list.push(item.to_string());
    }
    list
}

/// Run the extracted guard with `subcommand` set in the environment (`None` leaves it unset).
fn run_guard(script: &str, subcommand: Option<&str>) -> Output {
    let mut command = Command::new("bash");
    // dep: subprocess(bash) — the workflow's own guard text, not a second copy of it
    command
        .arg("-c")
        .arg(script)
        .stdin(Stdio::null())
        .env_remove("SUBCOMMAND");
    if let Some(value) = subcommand {
        command.env("SUBCOMMAND", value);
    }
    command.output().expect("run the experiment guard")
}

/// The workflow's choice list is exactly the three harnesses, and the guard's accepting arm is that same list:
/// the red mutation is an arm that accepts everything (M24-16 gate).
#[test]
fn the_choice_list_and_the_guard_arms_are_the_same_three() {
    assert_eq!(choice_list(), EXPECTED.to_vec());
    let script = guard_script();
    let arm = script
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("load|"))
        .expect("the guard must carry the accepting arm");
    let alternatives: Vec<&str> = arm.trim_end_matches(')').split('|').collect();
    assert_eq!(alternatives, EXPECTED.to_vec());
}

/// Each declared choice is accepted by the guard and echoed back.
#[test]
fn every_choice_passes_the_guard() {
    let script = guard_script();
    for subcommand in EXPECTED {
        let out = run_guard(&script, Some(subcommand));
        assert_eq!(
            out.status.code(),
            Some(0),
            "{subcommand}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout)
                .contains(&format!("subcommand={subcommand} accepted")),
            "{subcommand} is in the choice list but the guard did not accept it"
        );
    }
}

/// Anything outside the list — including an unset input — exits 2 with the accepted set in the message, before any
/// cargo step would run.
#[test]
fn a_value_outside_the_choice_list_exits_2() {
    let script = guard_script();
    for subcommand in OUTSIDE {
        let out = run_guard(&script, subcommand);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{subcommand:?}: expected exit 2, stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("must be one of [load, load-open, soak]"),
            "{subcommand:?}: the refusal must name the accepted set"
        );
    }
}

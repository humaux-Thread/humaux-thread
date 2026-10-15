//! `xtask::known_red` — `cargo xtask known-red`: the ledger of gates that are due but still red, every row owned by a module card and forced out when its item passes.
//! Depends-on: crates=[toml]; services=[]; env=[CARGO_MANIFEST_DIR]; modules=[xtask::benchset_declaration, xtask::dod_check, xtask::phase]
//! Called-by: [xtask::main]
//! Invariants: [a failing item without a ledger row is red; a ledger row whose item no longer fails is red (the row must be deleted); a row without a module-card owner is red; --release turns every row without deferred_past_go_live red and lists every deferred row for owner sign-off; an unknown ledger section or key, and an unparsable --phase value, is rejected, never ignored]
//! Spec: Baseline §57.1; §69; §80.1.1; §46
//!
//! §57.1 rule 2: `not_applicable` is only for an object that is not yet due, and it names the missing object. A
//! due gate that is red is therefore a row in `xtask/known_red.toml` with the module card that fixes it, never an
//! echo line or a waiver. A row is forced out when its item passes (§80.1.1 shape); adding a row is a reviewed
//! diff line that must name its owner, and every run prints `rows: N (deferred: M)` so growth shows in the log.
//!
//! Three sections, one evaluator each: `dod` (G80-33 verdicts per DoD id, reused from `dod_check`),
//! `benchset` (G80-16 verdicts per benchmark set, reused from `benchset_declaration`) and `due_items`
//! (the §57.1 rule 3 list, judged against the `PHASE` file). M01 cards add their sections to [`SECTIONS`]
//! together with an evaluator.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use crate::dod_check::GateStatus;

/// Ledger file, relative to the xtask crate (the same anchor `dod_check` uses for its inputs).
const LEDGER_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/known_red.toml");
/// Name used in messages (what a reader opens).
const LEDGER_FILE: &str = "xtask/known_red.toml";
/// Sections this build evaluates. A section nobody evaluates would never go red, so the parser rejects any
/// other name instead of ignoring it.
const SECTIONS: [&str; 3] = ["dod", "benchset", "due_items"];
/// Keys a ledger row may carry; anything else is a typo that would silently weaken a rule.
const ROW_KEYS: [&str; 4] = ["id", "owner", "reason", "deferred_past_go_live"];

/// §57.1 tri-state outcome of one ledger-tracked item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Pass,
    Fail,
    NotApplicable,
}

/// One item a section evaluates: a DoD id, a benchmark set, a due gate.
#[derive(Debug, Clone)]
struct Item {
    id: String,
    status: Status,
    detail: String,
}

/// One `[[section]]` entry of `known_red.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    id: String,
    owner: String,
    reason: String,
    deferred: Option<String>,
}

/// Rows per section name.
type Ledger = BTreeMap<String, Vec<Row>>;

/// What one section produced: counts for the summary line, the lines §57.1 rule 2 and the go-live report need,
/// and the red reasons. `ledgered_lines` pair each failing row's reason with the verdict it gets today.
#[derive(Debug, Default)]
struct Report {
    pass: usize,
    fail: usize,
    na: usize,
    ledgered: usize,
    na_lines: Vec<String>,
    ledgered_lines: Vec<String>,
    deferred: Vec<String>,
    reds: Vec<String>,
}

// ---------------------------------------------------------------------------
// Ledger file
// ---------------------------------------------------------------------------

fn text<'a>(t: &'a toml::Table, key: &str) -> Option<&'a str> {
    t.get(key).and_then(toml::Value::as_str).map(str::trim)
}

fn parse_row(section: &str, n: usize, v: &toml::Value, errors: &mut Vec<String>) -> Option<Row> {
    let Some(t) = v.as_table() else {
        errors.push(format!("[{section}] row #{n}: not a table"));
        return None;
    };
    for k in t.keys().filter(|k| !ROW_KEYS.contains(&k.as_str())) {
        errors.push(format!(
            "[{section}] row #{n}: unknown key `{k}` (known: {})",
            ROW_KEYS.join(", ")
        ));
    }
    let Some(id) = text(t, "id").filter(|s| !s.is_empty()) else {
        errors.push(format!("[{section}] row #{n}: missing `id`"));
        return None;
    };
    Some(Row {
        id: id.to_string(),
        owner: text(t, "owner").unwrap_or_default().to_string(),
        reason: text(t, "reason").unwrap_or_default().to_string(),
        deferred: text(t, "deferred_past_go_live").map(str::to_string),
    })
}

/// Parses the ledger text. Structural problems come back as red reasons beside whatever rows were readable;
/// an owner or reason that is merely empty is left to [`judge`], which can name the section and id.
fn parse_ledger(raw: &str) -> (Ledger, Vec<String>) {
    let mut ledger = Ledger::new();
    let mut errors = Vec::new();
    let table = match toml::from_str::<toml::Value>(raw) {
        Ok(toml::Value::Table(t)) => t,
        Ok(_) => return (ledger, vec![format!("{LEDGER_FILE}: root is not a table")]),
        Err(e) => return (ledger, vec![format!("{LEDGER_FILE}: not valid TOML: {e}")]),
    };
    for (section, value) in &table {
        if !SECTIONS.contains(&section.as_str()) {
            errors.push(format!(
                "[{section}]: unknown ledger section (known: {})",
                SECTIONS.join(", ")
            ));
            continue;
        }
        let Some(entries) = value.as_array() else {
            errors.push(format!(
                "[{section}]: must be an array of tables, written [[{section}]]"
            ));
            continue;
        };
        let mut rows = Vec::new();
        for (i, entry) in entries.iter().enumerate() {
            rows.extend(parse_row(section, i + 1, entry, &mut errors));
        }
        ledger.insert(section.clone(), rows);
    }
    (ledger, errors)
}

/// `M<nn>` or `M<nn>-<card>`: the module card that owns the fix (module ids of `docs/architecture/module_ownership.toml`).
// ponytail: checks the shape, not that the card exists; review of known_red.toml is the gate, upgrade is
// reading the module ids from docs/architecture/module_ownership.toml.
fn owner_ok(owner: &str) -> bool {
    let Some(rest) = owner.strip_prefix('M') else {
        return false;
    };
    let (module, card) = match rest.split_once('-') {
        Some((m, c)) => (m, Some(c)),
        None => (rest, None),
    };
    module.len() == 2
        && module.bytes().all(|b| b.is_ascii_digit())
        && card.is_none_or(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_alphanumeric()))
}

// ---------------------------------------------------------------------------
// The rules (pure: verdicts + rows in, red reasons out)
// ---------------------------------------------------------------------------

/// Worst verdict wins when one id is reported twice, so a duplicate can never hide a failure.
fn rank(s: Status) -> u8 {
    match s {
        Status::NotApplicable => 0,
        Status::Pass => 1,
        Status::Fail => 2,
    }
}

/// Reasons a row is malformed on its own, independent of what its item does.
fn row_shape_reds(tag: &str, row: &Row, release: bool) -> Vec<String> {
    let mut reds = Vec::new();
    if row.owner.is_empty() {
        reds.push(format!(
            "{tag}: row has no owner (every row names the module card that fixes it)"
        ));
    } else if !owner_ok(&row.owner) {
        reds.push(format!(
            "{tag}: owner `{}` is not a module card (expected M<nn> or M<nn>-<card>, e.g. M11-3)",
            row.owner
        ));
    }
    if row.reason.is_empty() {
        reds.push(format!("{tag}: row has no reason"));
    }
    // ponytail: deferral is self-declared; card 53 (go-live rehearsal) gets owner sign-off on every printed deferred row; upgrade: require an ADR id in the reason
    match &row.deferred {
        Some(d) if d.is_empty() => reds.push(format!(
            "{tag}: deferred_past_go_live is empty (state why, or drop the key)"
        )),
        None if release => reds.push(format!(
            "{tag}: --release and the row has no deferred_past_go_live (fix it before go-live, or defer it with a reason)"
        )),
        _ => {}
    }
    reds
}

/// D4 rules for one section. A row is forced out when its item stops failing (§80.1.1 shape), so a row for an
/// item that passes, or is not yet due without a declared deferral, is red.
fn judge(section: &str, items: &[Item], rows: &[Row], release: bool) -> Report {
    let mut by_id: BTreeMap<&str, &Item> = BTreeMap::new();
    for it in items {
        let keep = by_id
            .get(it.id.as_str())
            .is_none_or(|cur| rank(it.status) > rank(cur.status));
        if keep {
            by_id.insert(it.id.as_str(), it);
        }
    }
    let mut rep = Report {
        ledgered: rows.len(),
        ..Report::default()
    };
    for it in by_id.values() {
        match it.status {
            Status::Pass => rep.pass += 1,
            Status::Fail => rep.fail += 1,
            Status::NotApplicable => {
                rep.na += 1;
                rep.na_lines.push(format!("{}: {}", it.id, it.detail));
            }
        }
    }
    let mut listed = BTreeSet::new();
    for row in rows {
        let tag = format!("[{section}] {}", row.id);
        if !listed.insert(row.id.as_str()) {
            rep.reds.push(format!("{tag}: listed twice"));
            continue;
        }
        rep.reds.extend(row_shape_reds(&tag, row, release));
        if let Some(d) = row.deferred.as_deref().filter(|d| !d.is_empty()) {
            rep.deferred.push(format!(
                "{} (owner {}): deferred: {d}; red because: {}",
                row.id, row.owner, row.reason
            ));
        }
        match by_id.get(row.id.as_str()) {
            None => rep.reds.push(format!(
                "{tag}: matches no item of this section (typo, or the item was removed): delete the row"
            )),
            Some(it) => match it.status {
                Status::Pass => rep.reds.push(format!(
                    "{tag}: now passes: delete its row from {LEDGER_FILE} (§80.1.1)"
                )),
                Status::NotApplicable if row.deferred.is_none() => rep.reds.push(format!(
                    "{tag}: is not_applicable (not yet due): delete the row; only a deferred_past_go_live row may pre-declare an item"
                )),
                Status::NotApplicable => {}
                Status::Fail => rep.ledgered_lines.push(format!(
                    "{} (owner {}): {} | verdict now: {}",
                    row.id, row.owner, row.reason, it.detail
                )),
            },
        }
    }
    for it in by_id.values().filter(|it| it.status == Status::Fail) {
        if !listed.contains(it.id.as_str()) {
            rep.reds.push(format!(
                "[{section}] {}: failing and not in {LEDGER_FILE}: {}",
                it.id, it.detail
            ));
        }
    }
    rep
}

// ---------------------------------------------------------------------------
// Verdict sources
// ---------------------------------------------------------------------------

fn dod_items(phase: u32) -> Result<Vec<Item>, String> {
    Ok(crate::dod_check::verdicts(phase)?
        .into_iter()
        .map(|r| Item {
            id: r.gate,
            status: match r.status {
                GateStatus::Pass => Status::Pass,
                GateStatus::Fail => Status::Fail,
                GateStatus::NotApplicable => Status::NotApplicable,
            },
            detail: r.detail,
        })
        .collect())
}

/// Attributes `benchset_declaration`'s violation texts to sets. Every per-set violation begins `<set_id>: `
/// (that module's format); whatever matches no set concerns the table as a whole (row count, name alignment)
/// and becomes the `benchset-table` item.
fn benchset_items(set_ids: &[String], violations: &[String], na_list: &[String]) -> Vec<Item> {
    let mut items = Vec::new();
    let mut attributed = BTreeSet::new();
    for id in set_ids {
        let prefix = format!("{id}:");
        let own: Vec<&String> = violations
            .iter()
            .filter(|v| v.starts_with(&prefix))
            .collect();
        attributed.extend(own.iter().copied());
        let na_prefix = format!("{id} (");
        let (status, detail) = if let Some(first) = own.first() {
            (Status::Fail, first.to_string())
        } else if let Some(entry) = na_list.iter().find(|e| e.starts_with(&na_prefix)) {
            (
                Status::NotApplicable,
                format!("not yet due: {entry} (missing object: measured declaration)"),
            )
        } else {
            (Status::Pass, "declared".to_string())
        };
        items.push(Item {
            id: id.clone(),
            status,
            detail,
        });
    }
    let table: Vec<&str> = violations
        .iter()
        .filter(|v| !attributed.contains(v))
        .map(String::as_str)
        .collect();
    items.push(Item {
        id: "benchset-table".to_string(),
        status: if table.is_empty() {
            Status::Pass
        } else {
            Status::Fail
        },
        detail: table.join(" | "),
    });
    items
}

fn benchset_section(phase: u32) -> Result<Vec<Item>, String> {
    let eval = crate::benchset_declaration::evaluate_repo(phase)?.ok_or_else(|| {
        "the §69 benchmark declaration table is missing from the spec".to_string()
    })?;
    Ok(benchset_items(
        &eval.set_ids,
        &eval.violations,
        &eval.na_list,
    ))
}

/// A gate §57.1 rule 3 lists as due from a Phase on.
struct DueItem {
    id: &'static str,
    due_phase: u32,
    /// The object that does not exist yet (named in the `not_applicable` line, §57.1 rule 2).
    missing_object: &'static str,
}

// ponytail: no due item has a verifier yet, so a due one is always Fail; the card that delivers a verifier
// adds a verdict column here in the same PR and deletes the row.
const DUE_ITEMS: [DueItem; 4] = [
    DueItem {
        id: "retrieval benchmark",
        due_phase: 6,
        missing_object: "retrieval benchmark corpus / embedding index",
    },
    DueItem {
        id: "mutation tests",
        due_phase: 1,
        missing_object: "mutation harness / testkit fault targets",
    },
    DueItem {
        id: "deploy smoke",
        due_phase: 14,
        missing_object: "live deploy target with /live /ready /status",
    },
    DueItem {
        id: "container scan",
        due_phase: 14,
        missing_object: "container image to scan",
    },
];

fn due_items(phase: u32) -> Vec<Item> {
    DUE_ITEMS
        .iter()
        .map(|d| {
            let (status, detail) = if phase < d.due_phase {
                (
                    Status::NotApplicable,
                    format!(
                        "missing object: {} (delivered Phase {}, §57.1 rule 3)",
                        d.missing_object, d.due_phase
                    ),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "due since Phase {} and no verifier exists (missing object: {})",
                        d.due_phase, d.missing_object
                    ),
                )
            };
            Item {
                id: d.id.to_string(),
                status,
                detail,
            }
        })
        .collect()
}

fn section_items(section: &str, phase: u32) -> Result<Vec<Item>, String> {
    match section {
        "dod" => dod_items(phase),
        "benchset" => benchset_section(phase),
        "due_items" => Ok(due_items(phase)),
        other => Err(format!("no evaluator is wired for section `{other}`")),
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// `Some(release)` when every argument is understood; `--phase` is read by `phase::current_phase`. A `--phase`
/// whose value is missing or not a `u32` is rejected: swallowing the next token (`--phase --release`) would run a
/// non-release check that passes.
fn parse_args(args: &[String]) -> Option<bool> {
    let mut release = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--release" => release = true,
            "--phase" => {
                if it.next().is_none_or(|v| v.parse::<u32>().is_err()) {
                    return None;
                }
            }
            s if s
                .strip_prefix("--phase=")
                .is_some_and(|v| v.parse::<u32>().is_ok()) => {}
            _ => return None,
        }
    }
    Some(release)
}

/// The log lines of one section. Deferred rows are listed only under `--release`, where the go-live rehearsal
/// needs each one for owner sign-off; every run still prints the `rows: N (deferred: M)` totals.
fn report_lines(section: &str, r: &Report, release: bool) -> Vec<String> {
    let mut out = vec![format!(
        "known-red: [{section}] pass {} · fail {} · not_applicable {} · ledgered {}",
        r.pass, r.fail, r.na, r.ledgered
    )];
    out.extend(
        r.na_lines
            .iter()
            .map(|l| format!("known-red: not_applicable [{section}] {l}")),
    );
    out.extend(
        r.ledgered_lines
            .iter()
            .map(|l| format!("known-red: ledgered [{section}] {l}")),
    );
    if release {
        out.extend(
            r.deferred.iter().map(|l| {
                format!("known-red: deferred past go-live, owner sign-off [{section}] {l}")
            }),
        );
    }
    out
}

/// Where a section's items come from: the real evaluators in `run`, a fake in tests.
type ItemSource<'a> = dyn Fn(&str, u32) -> Result<Vec<Item>, String> + 'a;

/// What one invocation decided.
struct Outcome {
    reports: Vec<(&'static str, Report)>,
    rows: usize,
    deferred: usize,
    reds: Vec<String>,
}

/// The whole decision from the ledger text and an item source: `run` passes the real evaluators, tests a fake.
fn check(raw: &str, phase: u32, release: bool, items_for: &ItemSource<'_>) -> Outcome {
    let (ledger, mut reds) = parse_ledger(raw);
    let mut reports = Vec::new();
    for section in SECTIONS {
        match items_for(section, phase) {
            Ok(items) => {
                let rows = ledger.get(section).map_or(&[][..], Vec::as_slice);
                let mut rep = judge(section, &items, rows, release);
                reds.append(&mut rep.reds);
                reports.push((section, rep));
            }
            Err(e) => reds.push(format!("[{section}]: cannot evaluate: {e}")),
        }
    }
    Outcome {
        reports,
        rows: ledger.values().map(Vec::len).sum(),
        deferred: ledger
            .values()
            .flatten()
            .filter(|r| r.deferred.is_some())
            .count(),
        reds,
    }
}

/// `cargo xtask known-red [--release] [--phase N]`: 0 green, 1 red, 2 usage.
pub fn run(args: &[String]) -> i32 {
    let Some(release) = parse_args(args) else {
        eprintln!("usage: cargo xtask known-red [--release] [--phase N]");
        return 2;
    };
    let phase = crate::phase::current_phase(args);
    let raw = match fs::read_to_string(LEDGER_PATH) {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!("known-red: fail: cannot read {LEDGER_PATH}: {e}");
            return 1;
        }
    };
    let mode = if release { " (--release)" } else { "" };
    println!("known-red: phase {phase}{mode}");
    let out = check(&raw, phase, release, &section_items);
    for (section, rep) in &out.reports {
        for line in report_lines(section, rep, release) {
            println!("{line}");
        }
    }
    println!("known-red: rows: {} (deferred: {})", out.rows, out.deferred);
    if out.reds.is_empty() {
        println!("known-red: pass");
        return 0;
    }
    for r in &out.reds {
        eprintln!("known-red: RED {r}");
    }
    eprintln!("known-red: fail: {} red reason(s)", out.reds.len());
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../docs/architecture/Baseline_2.9.md"
    );

    fn item(id: &str, status: Status) -> Item {
        Item {
            id: id.to_string(),
            status,
            detail: format!("detail of {id}"),
        }
    }

    fn row(id: &str, owner: &str) -> Row {
        Row {
            id: id.to_string(),
            owner: owner.to_string(),
            reason: "why it is red".to_string(),
            deferred: None,
        }
    }

    fn deferred(id: &str, owner: &str) -> Row {
        Row {
            deferred: Some("needs production traffic".to_string()),
            ..row(id, owner)
        }
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(ToString::to_string).collect()
    }

    /// Positive control: an unchanged ledger over the same verdicts is green and counts add up.
    #[test]
    fn unchanged_ledger_is_green() {
        let items = [
            item("A", Status::Fail),
            item("B", Status::Pass),
            item("C", Status::NotApplicable),
        ];
        let rep = judge("dod", &items, &[row("A", "M11-3")], false);
        assert!(rep.reds.is_empty(), "{:?}", rep.reds);
        assert_eq!((rep.pass, rep.fail, rep.na, rep.ledgered), (1, 1, 1, 1));
        assert_eq!(rep.na_lines.len(), 1);
        assert!(rep.na_lines[0].contains('C'));
    }

    /// Fault: a failing item that lost its row goes red and the reason names the id and the rule.
    #[test]
    fn unlisted_failure_is_red() {
        let rep = judge("dod", &[item("DOD-006", Status::Fail)], &[], false);
        assert_eq!(rep.reds.len(), 1, "{:?}", rep.reds);
        assert!(
            rep.reds[0].contains("[dod] DOD-006: failing and not in xtask/known_red.toml"),
            "{:?}",
            rep.reds
        );
    }

    /// Fault: the item is fixed but its row stays.
    #[test]
    fn a_row_whose_item_now_passes_is_red() {
        let rep = judge(
            "dod",
            &[item("DOD-006", Status::Pass)],
            &[row("DOD-006", "M13")],
            false,
        );
        assert_eq!(rep.reds.len(), 1, "{:?}", rep.reds);
        assert!(
            rep.reds[0].contains("[dod] DOD-006: now passes"),
            "{:?}",
            rep.reds
        );
    }

    /// A row for an item that is not due is stale too, unless it is a declared go-live deferral.
    #[test]
    fn a_row_for_an_item_not_yet_due_is_red_unless_deferred() {
        let items = [item("DOD-081", Status::NotApplicable)];
        let stale = judge("dod", &items, &[row("DOD-081", "M22")], false);
        assert_eq!(stale.reds.len(), 1, "{:?}", stale.reds);
        assert!(
            stale.reds[0].contains("[dod] DOD-081: is not_applicable (not yet due)"),
            "{:?}",
            stale.reds
        );
        let declared = judge("dod", &items, &[deferred("DOD-081", "M22")], false);
        assert!(declared.reds.is_empty(), "{:?}", declared.reds);
        assert_eq!(declared.deferred.len(), 1);
    }

    /// Fault: no owner, or an owner that is not a module card; each is its own rule.
    #[test]
    fn a_row_without_a_module_card_owner_is_red() {
        let items = [item("A", Status::Fail), item("B", Status::Fail)];
        for owner in ["", "TBD", "M1", "M11-", "11-3"] {
            let rep = judge("dod", &items, &[row("A", owner), row("B", "M11")], false);
            assert_eq!(rep.reds.len(), 1, "owner {owner:?}: {:?}", rep.reds);
            let want = if owner.is_empty() {
                "[dod] A: row has no owner"
            } else {
                "[dod] A: owner `"
            };
            assert!(
                rep.reds[0].contains(want),
                "owner {owner:?}: {:?}",
                rep.reds
            );
            if !owner.is_empty() {
                assert!(
                    rep.reds[0].contains("is not a module card"),
                    "{:?}",
                    rep.reds
                );
            }
        }
    }

    /// Fault: a row with an empty reason, or an empty deferral text.
    #[test]
    fn a_row_without_a_reason_or_with_an_empty_deferral_is_red() {
        let items = [item("A", Status::Fail)];
        let no_reason = Row {
            reason: String::new(),
            ..row("A", "M11")
        };
        let rep = judge("dod", &items, &[no_reason], false);
        assert_eq!(rep.reds.len(), 1, "{:?}", rep.reds);
        assert!(
            rep.reds[0].contains("[dod] A: row has no reason"),
            "{:?}",
            rep.reds
        );
        let empty_deferral = Row {
            deferred: Some(String::new()),
            ..row("A", "M11")
        };
        let rep = judge("dod", &items, &[empty_deferral], false);
        assert_eq!(rep.reds.len(), 1, "{:?}", rep.reds);
        assert!(
            rep.reds[0].contains("[dod] A: deferred_past_go_live is empty"),
            "{:?}",
            rep.reds
        );
    }

    /// Fault: --release with a row that is not deferred; a deferred row stays green.
    #[test]
    fn release_mode_is_red_on_a_non_deferred_row_only() {
        let items = [item("A", Status::Fail), item("B", Status::Fail)];
        let rows = [row("A", "M11"), deferred("B", "M24")];
        assert!(judge("dod", &items, &rows, false).reds.is_empty());
        let rep = judge("dod", &items, &rows, true);
        assert_eq!(rep.reds.len(), 1, "{:?}", rep.reds);
        assert!(
            rep.reds[0].contains("[dod] A: --release and the row has no deferred_past_go_live"),
            "{:?}",
            rep.reds
        );
    }

    /// Fault: a typo'd or removed id, and a duplicated row.
    #[test]
    fn a_row_matching_no_item_or_listed_twice_is_red() {
        let items = [item("A", Status::Fail)];
        let ghost = judge("dod", &items, &[row("A", "M11"), row("Z", "M11")], false);
        assert_eq!(ghost.reds.len(), 1, "{:?}", ghost.reds);
        assert!(
            ghost.reds[0].contains("[dod] Z: matches no item"),
            "{:?}",
            ghost.reds
        );
        let twice = judge("dod", &items, &[row("A", "M11"), row("A", "M11")], false);
        assert_eq!(twice.reds.len(), 1, "{:?}", twice.reds);
        assert!(
            twice.reds[0].contains("[dod] A: listed twice"),
            "{:?}",
            twice.reds
        );
    }

    /// A duplicated item id cannot hide a failure behind a pass.
    #[test]
    fn the_worst_verdict_wins_for_a_duplicated_item() {
        let items = [item("A", Status::Pass), item("A", Status::Fail)];
        let rep = judge("dod", &items, &[], false);
        assert_eq!((rep.pass, rep.fail), (0, 1));
        assert_eq!(rep.reds.len(), 1, "{:?}", rep.reds);
        assert!(
            rep.reds[0].contains("[dod] A: failing and not in"),
            "{:?}",
            rep.reds
        );
    }

    /// A ledgered failing row prints today's verdict next to its reason, so a verifier that errors differently
    /// from "no verifier registered" is visible in the log.
    #[test]
    fn a_failing_row_prints_the_verdict_next_to_its_reason() {
        let rep = judge("dod", &[item("A", Status::Fail)], &[row("A", "M11")], false);
        assert_eq!(rep.ledgered_lines.len(), 1);
        let line = &rep.ledgered_lines[0];
        assert!(
            line.contains("why it is red") && line.contains("verdict now: detail of A"),
            "{line}"
        );
        let lines = report_lines("dod", &rep, false);
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("known-red: ledgered [dod] A")),
            "{lines:?}"
        );
    }

    /// `--release` lists every deferred row (id, owner, reasons) for owner sign-off; a plain run does not.
    #[test]
    fn release_lists_every_deferred_row() {
        let items = [item("A", Status::Fail), item("B", Status::NotApplicable)];
        let rows = [row("A", "M11"), deferred("B", "M24")];
        let rep = judge("dod", &items, &rows, true);
        let lines = report_lines("dod", &rep, true);
        let listed: Vec<&String> = lines
            .iter()
            .filter(|l| l.contains("deferred past go-live, owner sign-off [dod]"))
            .collect();
        assert_eq!(listed.len(), 1, "{lines:?}");
        assert!(
            listed[0].contains("B (owner M24)")
                && listed[0].contains("needs production traffic")
                && listed[0].contains("why it is red"),
            "{}",
            listed[0]
        );
        let plain = report_lines("dod", &rep, false);
        assert!(
            plain.iter().all(|l| !l.contains("owner sign-off")),
            "{plain:?}"
        );
    }

    /// The whole decision, as `run` makes it (ledger text + evaluators in, red reasons out): an unknown section
    /// goes red here, not only in the parser.
    #[test]
    fn an_unknown_section_goes_red_through_check() {
        let none = |_: &str, _: u32| -> Result<Vec<Item>, String> { Ok(Vec::new()) };
        let out = check(
            "[[dods]]\nid = \"x\"\nowner = \"M11\"\nreason = \"r\"\n",
            9,
            false,
            &none,
        );
        assert_eq!(out.reds.len(), 1, "{:?}", out.reds);
        assert!(
            out.reds[0].contains("[dods]: unknown ledger section"),
            "{:?}",
            out.reds
        );
    }

    /// An evaluator that cannot run is red for its section, never skipped.
    #[test]
    fn an_evaluator_error_goes_red_through_check() {
        let broken = |section: &str, _: u32| -> Result<Vec<Item>, String> {
            if section == "benchset" {
                Err("spec unreadable".to_string())
            } else {
                Ok(Vec::new())
            }
        };
        let out = check("", 9, false, &broken);
        assert_eq!(out.reds.len(), 1, "{:?}", out.reds);
        assert!(
            out.reds[0].contains("[benchset]: cannot evaluate: spec unreadable"),
            "{:?}",
            out.reds
        );
        assert_eq!(out.reports.len(), 2);
    }

    /// Unchanged ledger through `check`: green, and the totals the log prints count rows and deferrals.
    #[test]
    fn check_counts_rows_and_deferrals() {
        let items_for = |section: &str, _: u32| -> Result<Vec<Item>, String> {
            Ok(match section {
                "dod" => vec![item("A", Status::Fail), item("B", Status::NotApplicable)],
                _ => Vec::new(),
            })
        };
        let raw = "[[dod]]\nid = \"A\"\nowner = \"M11\"\nreason = \"r\"\n\
                   [[dod]]\nid = \"B\"\nowner = \"M24\"\nreason = \"r\"\ndeferred_past_go_live = \"d\"\n";
        let out = check(raw, 9, false, &items_for);
        assert!(out.reds.is_empty(), "{:?}", out.reds);
        assert_eq!((out.rows, out.deferred), (2, 1));
        let release = check(raw, 9, true, &items_for);
        assert_eq!(release.reds.len(), 1, "{:?}", release.reds);
        assert!(
            release.reds[0].contains("[dod] A: --release"),
            "{:?}",
            release.reds
        );
    }

    #[test]
    fn owner_shapes() {
        for ok in ["M01", "M24", "M24-4", "M11-3b"] {
            assert!(owner_ok(ok), "{ok}");
        }
        for bad in ["", "M", "M1", "M123", "m11", "M11-", "M11-3/M14", "11"] {
            assert!(!owner_ok(bad), "{bad}");
        }
    }

    #[test]
    fn ledger_parser_reads_rows_and_rejects_unknown_sections_and_keys() {
        let ok = "[[dod]]\nid = \"DOD-006\"\nowner = \"M13\"\nreason = \"r\"\n\
                  [[due_items]]\nid = \"x\"\nowner = \"M24\"\nreason = \"r\"\ndeferred_past_go_live = \"d\"\n";
        let (ledger, errors) = parse_ledger(ok);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(ledger["dod"].len(), 1);
        assert_eq!(ledger["dod"][0].id, "DOD-006");
        assert_eq!(ledger["dod"][0].owner, "M13");
        assert_eq!(ledger["dod"][0].deferred, None);
        assert_eq!(ledger["due_items"][0].deferred.as_deref(), Some("d"));

        let (_, unknown_section) = parse_ledger("[[dods]]\nid = \"a\"\n");
        assert_eq!(unknown_section.len(), 1);
        assert!(unknown_section[0].contains("unknown ledger section"));

        let (_, unknown_key) =
            parse_ledger("[[dod]]\nid = \"a\"\nowner = \"M11\"\ndeferred_past_golive = \"x\"\n");
        assert_eq!(unknown_key.len(), 1, "{unknown_key:?}");
        assert!(unknown_key[0].contains("unknown key `deferred_past_golive`"));

        let (rows, missing_id) = parse_ledger("[[dod]]\nowner = \"M11\"\n");
        assert!(missing_id[0].contains("missing `id`"), "{missing_id:?}");
        assert!(rows["dod"].is_empty());

        assert!(parse_ledger("[dod]\nid = \"a\"\n").1[0].contains("array of tables"));
        assert!(parse_ledger("= not toml").1[0].contains("not valid TOML"));
    }

    /// A missing owner survives parsing (empty) so `judge` can name the section and id.
    #[test]
    fn a_missing_owner_parses_as_empty() {
        let (ledger, errors) = parse_ledger("[[dod]]\nid = \"a\"\nreason = \"r\"\n");
        assert!(errors.is_empty());
        assert_eq!(ledger["dod"][0].owner, "");
    }

    /// §57.1 rule 2: before its Phase a due item is not_applicable and names the object; from its Phase on it fails.
    #[test]
    fn due_items_switch_at_their_phase() {
        let find = |items: &[Item], id: &str| {
            items
                .iter()
                .find(|i| i.id == id)
                .map(|i| (i.status, i.detail.clone()))
                .unwrap()
        };
        let at_9 = due_items(9);
        assert_eq!(find(&at_9, "retrieval benchmark").0, Status::Fail);
        assert_eq!(find(&at_9, "mutation tests").0, Status::Fail);
        let (st, detail) = find(&at_9, "deploy smoke");
        assert_eq!(st, Status::NotApplicable);
        assert!(
            detail.contains("missing object: live deploy target"),
            "{detail}"
        );
        assert_eq!(find(&due_items(14), "container scan").0, Status::Fail);
        assert_eq!(
            find(&due_items(5), "retrieval benchmark").0,
            Status::NotApplicable
        );
    }

    /// `DUE_ITEMS` repeats the §57.1 table; this pins the copy. The spec has a parseable Phase table, so each due
    /// item must sit (as a backticked name in the last column) in exactly one row, the row of its due Phase.
    #[test]
    fn due_item_phases_match_the_57_1_table() {
        let spec = fs::read_to_string(SPEC_PATH).expect("the spec is committed");
        let from = spec.find("## 57.1 ").expect("§57.1 heading");
        let section = spec[from..].split("\n# ").next().unwrap_or_default();
        let rows: Vec<(u32, &str)> = section
            .lines()
            .filter_map(|l| {
                let l = l.trim();
                let phase = l
                    .strip_prefix("| ")?
                    .split(" | ")
                    .next()?
                    .trim()
                    .parse()
                    .ok()?;
                let last = l.trim_end_matches('|').rsplit('|').next()?;
                Some((phase, last))
            })
            .collect();
        assert!(
            rows.len() >= 18,
            "found {} Phase rows in §57.1; the table moved or changed shape",
            rows.len()
        );
        for d in &DUE_ITEMS {
            let needle = format!("`{}`", d.id);
            let hits: Vec<u32> = rows
                .iter()
                .filter(|(_, last)| last.contains(&needle))
                .map(|(phase, _)| *phase)
                .collect();
            assert_eq!(
                hits,
                vec![d.due_phase],
                "`{}`: §57.1 lists it in Phase row(s) {hits:?}, DUE_ITEMS says {}",
                d.id,
                d.due_phase
            );
        }
        // The other direction: a new non-G80 name in a Phase >= 1 row must be a ledger candidate or be
        // listed here on purpose. These four are enforced by CI jobs outside the ledger and pass today.
        const NOT_LEDGER_ITEMS: [&str; 4] = [
            "integration",
            "migration",
            "tenant isolation",
            "secret isolation",
        ];
        for (phase, last) in rows.iter().filter(|(phase, _)| *phase >= 1) {
            for name in last
                .split('`')
                .skip(1)
                .step_by(2)
                .filter(|n| !n.starts_with("G80-"))
            {
                assert!(
                    DUE_ITEMS.iter().any(|d| d.id == name) || NOT_LEDGER_ITEMS.contains(&name),
                    "§57.1 Phase {phase} lists `{name}`, which is neither in DUE_ITEMS nor in NOT_LEDGER_ITEMS"
                );
            }
        }
    }

    /// Violations are attributed by their `<set_id>: ` prefix; the rest is the table item.
    #[test]
    fn benchset_violations_are_attributed_per_set() {
        let ids = s(&["a_set", "b_set", "c_set", "d_set"]);
        let violations = s(&[
            "a_set: owning phase 4 expired",
            "a_set_extra: not a_set's violation",
            "b_set: manifest missing",
            "the table should have 10 rows",
        ]);
        let na = s(&["c_set (owner phase=11)"]);
        let items = benchset_items(&ids, &violations, &na);
        let status = |id: &str| items.iter().find(|i| i.id == id).unwrap().status;
        assert_eq!(status("a_set"), Status::Fail);
        assert_eq!(status("b_set"), Status::Fail);
        assert_eq!(status("c_set"), Status::NotApplicable);
        assert_eq!(status("d_set"), Status::Pass);
        let table = items.iter().find(|i| i.id == "benchset-table").unwrap();
        assert_eq!(table.status, Status::Fail);
        assert!(table.detail.contains("a_set_extra") && table.detail.contains("10 rows"));
        let na_item = items.iter().find(|i| i.id == "c_set").unwrap();
        assert!(
            na_item.detail.contains("missing object"),
            "{}",
            na_item.detail
        );
    }

    #[test]
    fn a_clean_benchset_run_has_only_passing_items() {
        let items = benchset_items(&s(&["a_set"]), &[], &[]);
        assert!(items.iter().all(|i| i.status == Status::Pass));
    }

    #[test]
    fn arguments() {
        assert_eq!(parse_args(&[]), Some(false));
        assert_eq!(parse_args(&s(&["--release"])), Some(true));
        assert_eq!(parse_args(&s(&["--phase", "9", "--release"])), Some(true));
        assert_eq!(parse_args(&s(&["--phase=9"])), Some(false));
        assert_eq!(parse_args(&s(&["--relase"])), None);
    }

    /// Fault: `--phase` must not swallow the next flag or accept a non-number (fail-open: `--phase --release`
    /// would run a non-release check and pass).
    #[test]
    fn a_phase_flag_without_a_numeric_value_is_a_usage_error() {
        for bad in [
            s(&["--phase", "--release"]),
            s(&["--phase", "x"]),
            s(&["--phase"]),
            s(&["--phase=x"]),
            s(&["--phase=", "--release"]),
            s(&["--release", "--phase", "-1"]),
        ] {
            assert_eq!(parse_args(&bad), None, "{bad:?}");
        }
    }

    /// The committed ledger is well formed: it parses clean and every row has a module-card owner and a reason.
    #[test]
    fn the_committed_ledger_is_well_formed() {
        let raw = fs::read_to_string(LEDGER_PATH).expect("xtask/known_red.toml is committed");
        let (ledger, errors) = parse_ledger(&raw);
        assert!(errors.is_empty(), "{errors:?}");
        for (section, rows) in &ledger {
            for r in rows {
                assert!(
                    owner_ok(&r.owner),
                    "[{section}] {}: owner {:?}",
                    r.id,
                    r.owner
                );
                assert!(!r.reason.is_empty(), "[{section}] {}: no reason", r.id);
            }
        }
    }
}

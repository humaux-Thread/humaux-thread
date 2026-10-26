//! `contracts::tests::freshness` — G-M13-5, §21.5 / §50 values-file loading and §78.1 literal guard.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[contracts::freshness]
//! Called-by: [cargo-test]
//! Invariants: [missing config inputs fail; exact row set and count; no business durations in signals production]
//! Spec: Baseline §8.5; §21.5; §50; §78.1; §80.1; ADR-0111

use humaux_contracts::freshness::{VALUES, parse_values, values};
use std::collections::BTreeSet;

// §8.5's existing wire set, independently pinned here and against MemoryType::ALL in retrieval's test.
const TYPES: [&str; 12] = [
    "FACT",
    "PREFERENCE",
    "DECISION",
    "REJECTION",
    "STATE",
    "ISSUE",
    "LESSON",
    "CONSTRAINT",
    "PROCEDURE",
    "OUTCOME",
    "REFERENCE",
    "NOTE",
];

#[test]
fn g_m13_5_every_memory_type_has_exactly_one_row() {
    let table = values(&TYPES).expect("G-M13-5 fail: all MemoryType rows must load");
    assert_eq!(table.rows.len(), 12);
    assert_eq!(
        table
            .rows
            .iter()
            .map(|row| row.name.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(TYPES)
    );
    assert_eq!((&*table.policy_id, table.version), ("evidence-per-type", 1));
    println!("G-M13-5 pass: exactly twelve MemoryType rows");
}

#[test]
fn g_m13_5_missing_duplicate_unknown_and_invalid_values_fail_loading() {
    let state = "[[memory_type]]\nname = \"STATE\"\naging_after_days = 7\nstale_after_days = 30\n";
    let missing = parse_values(&VALUES.replace(state, ""), &TYPES).unwrap_err();
    assert_eq!(
        missing.reason,
        "MemoryType rows differ: missing=[\"STATE\"], unknown=[]"
    );
    let duplicate = format!("{VALUES}\n{state}");
    assert_eq!(
        parse_values(&duplicate, &TYPES).unwrap_err().reason,
        "duplicate MemoryType row"
    );
    let unknown = VALUES.replace("\"STATE\"", "\"PLAN\"");
    assert_eq!(
        parse_values(&unknown, &TYPES).unwrap_err().reason,
        "MemoryType rows differ: missing=[\"STATE\"], unknown=[\"PLAN\"]"
    );
    for bad in [
        VALUES.replace("version = 1", "version = 0"),
        VALUES.replace("aging_after_days = 7", "aging_after_days = 31"),
        VALUES.replace("aging_after_days = 7", "aging_after_days = -1"),
        VALUES.replace(
            "aging_after_days = 7",
            "aging_after_days = 18446744073709551615",
        ),
        VALUES.replace("policy_id = \"evidence-per-type\"", "policy_id = \"\""),
    ] {
        assert!(parse_values(&bad, &TYPES).is_err());
    }
}

#[test]
fn g_m13_5_signals_has_no_hardcoded_duration() {
    let source = include_str!("../../retrieval/src/signals.rs");
    let production = source.split("#[cfg(test)]").next().expect("signals source");
    let violations: Vec<_> = production
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            !line.trim_start().starts_with("//")
                && (line.contains("Duration::from_secs(") || line.contains("Duration::from_days("))
        })
        .collect();
    assert_eq!(
        violations,
        vec![],
        "G-M13-5 fail: duration construction in signals: {violations:?}"
    );
    println!("G-M13-5 pass: no duration construction in signals production");
}

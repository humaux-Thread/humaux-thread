//! `protocol::tests::note_kind_contract` — ADR-0067 D-D contract test: every `note_kind` / `note_kinds` enum the MCP
//!   contracts publish is exactly the domain's closed `NoteKind` set, in its order.
//! Depends-on: crates=[humaux-domain, serde_json]; services=[]; env=[CARGO_MANIFEST_DIR]; modules=[domain::note]
//! Called-by: [cargo-test]
//! Invariants: [every `contracts/mcp/*.json` is scanned at test time; the files holding a note-kind site and their site
//!   counts are pinned as one map, so a new file with a note-kind enum, or a renamed key dropping out of one, fails
//!   until the map names it; each site's enum equals `NoteKind::ALL` wire strings in order; the `note_kinds` filter's
//!   `maxItems` equals `NoteKind::ALL.len()` (its items are unique, so it is the number of distinct kinds)]
//! Spec: §78.2; ADR-0067 D-D, D-G; ADR-0124

use std::collections::BTreeMap;
use std::path::PathBuf;

use humaux_domain::note::NoteKind;
use serde_json::Value;

/// Exactly the published contracts that carry a note-kind enum, with how many sites each holds.
const SITES: [(&str, usize); 2] = [
    // The memory.get / memory.enumerate item's `note_kind`.
    ("context.output.schema.json", 1),
    // memory.note_put's `note_kind` input and memory.enumerate's `note_kinds` filter.
    ("memory.schema.json", 2),
];

/// Every `enum` reachable under a `note_kind` or `note_kinds` key (an array filter's enum sits under `items`).
fn note_kind_enums(value: &Value, out: &mut Vec<Vec<String>>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key == "note_kind" || key == "note_kinds" {
                    if key == "note_kinds" {
                        assert_eq!(
                            child["maxItems"].as_u64(),
                            Some(NoteKind::ALL.len() as u64),
                            "`note_kinds` maxItems must be the number of distinct kinds: {child}"
                        );
                    }
                    let site = child.get("items").unwrap_or(child);
                    let values = site["enum"]
                        .as_array()
                        .unwrap_or_else(|| panic!("`{key}` carries no enum: {child}"));
                    out.push(
                        values
                            .iter()
                            .map(|v| v.as_str().expect("enum values are strings").to_owned())
                            .collect(),
                    );
                }
                note_kind_enums(child, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| note_kind_enums(item, out)),
        _ => {}
    }
}

#[test]
fn every_published_note_kind_enum_is_the_domain_set() {
    let domain: Vec<String> = NoteKind::ALL
        .iter()
        .map(|kind| kind.wire().to_owned())
        .collect();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/mcp");
    let mut scanned = 0;
    let mut found = BTreeMap::new();
    for entry in std::fs::read_dir(&dir).expect("contracts/mcp") {
        let path = entry.expect("contracts/mcp entry").path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        scanned += 1;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("utf-8 file name")
            .to_owned();
        let text = std::fs::read_to_string(&path).expect("contract reads");
        let schema: Value = serde_json::from_str(&text).expect("contract parses");
        let mut sites = Vec::new();
        note_kind_enums(&schema, &mut sites);
        for site in &sites {
            assert_eq!(
                site, &domain,
                "{name}: a note-kind enum drifted from NoteKind::ALL"
            );
        }
        if !sites.is_empty() {
            found.insert(name, sites.len());
        }
    }
    assert!(
        scanned > SITES.len(),
        "the scan saw the contract directory ({scanned} files)"
    );
    let pinned: BTreeMap<String, usize> = SITES
        .iter()
        .map(|(name, count)| ((*name).to_owned(), *count))
        .collect();
    assert_eq!(
        found, pinned,
        "the contracts holding note-kind sites, and their counts"
    );
}

//! `protocol::tests::note_kind_contract` — ADR-0067 D-D contract test: every `note_kind` / `note_kinds` enum the MCP
//!   contracts publish is exactly the domain's closed `NoteKind` set, in its order.
//! Depends-on: crates=[humaux-domain, serde_json]; services=[]; env=[]; modules=[domain::note]
//! Called-by: [cargo-test]
//! Invariants: [every schema site that names a note kind is found (the expected count is pinned, so a renamed key
//!   cannot silently drop out of the check); each site's enum equals `NoteKind::ALL` wire strings in order]
//! Spec: §78.2; ADR-0067 D-D, D-G

use humaux_domain::note::NoteKind;
use serde_json::Value;

/// The published contracts that carry a note-kind enum, with how many sites each holds.
const CONTRACTS: [(&str, &str, usize); 2] = [
    // memory.note_put's `note_kind` input and memory.enumerate's `note_kinds` filter.
    (
        "memory.schema.json",
        include_str!("../../../contracts/mcp/memory.schema.json"),
        2,
    ),
    // The memory.get / memory.enumerate item's `note_kind`.
    (
        "context.output.schema.json",
        include_str!("../../../contracts/mcp/context.output.schema.json"),
        1,
    ),
];

/// Every `enum` reachable under a `note_kind` or `note_kinds` key (an array filter's enum sits under `items`).
fn note_kind_enums(value: &Value, out: &mut Vec<Vec<String>>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key == "note_kind" || key == "note_kinds" {
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
    for (name, text, expected_sites) in CONTRACTS {
        let schema: Value = serde_json::from_str(text).expect("contract parses");
        let mut sites = Vec::new();
        note_kind_enums(&schema, &mut sites);
        assert_eq!(
            sites.len(),
            expected_sites,
            "{name}: note-kind sites found {sites:?}"
        );
        for site in sites {
            assert_eq!(
                site, domain,
                "{name}: a note-kind enum drifted from NoteKind::ALL"
            );
        }
    }
}

//! `protocol::tests::remember_source_contract` — G-M06-8 source and evidence-ref wire contracts (§33.1; §34; ADR-0098).
//! Depends-on: crates=[humaux-domain, serde_json]; services=[]; env=[];
//!   modules=[domain::error, domain::source, protocol::mcp, protocol::mcp_catalog]
//! Called-by: [cargo-test]
//! Invariants: [gateway's canonical validator refuses every malformed source field and extra key; no contract lock]
//! Spec: Baseline §33.1; §34; §78.2; §80.1; ADR-0098

use humaux_domain::{error::ErrorCode, source::SOURCE_VERSION_MAX_CHARS};
use humaux_protocol::{
    mcp::ToolName,
    mcp_catalog::{self, CanonicalCatalog},
};
use serde_json::{Value, json};

fn remember(source: Value) -> Value {
    json!({"operation":"put", "content":"relayed text", "idempotency_key":"source-contract", "source":source})
}

fn full_source() -> Value {
    json!({"kind":"EmailMessage", "object_key":"message-key", "version":"v1", "thread_key":"thread-key", "occurred_at":"2026-10-28T12:34:56Z"})
}

#[test]
fn source_fields_and_extra_keys_fail_closed() {
    mcp_catalog::trusted_catalog().expect("trusted catalog loads");
    let catalog = CanonicalCatalog::load().unwrap();
    for source in [
        full_source(),
        json!({"kind":"AgentNote", "object_key":"key"}),
    ] {
        assert_eq!(
            catalog
                .validate(ToolName::Remember, &remember(source))
                .unwrap()
                .operation_key(),
            "remember.put"
        );
    }
    // §33.1: one invalid type per field, plus the additionalProperties negative control.
    let cases = [
        ("kind", json!(1)),
        ("object_key", json!(1)),
        ("version", json!(1)),
        ("thread_key", json!(1)),
        ("occurred_at", json!(1)),
        ("unexpected", json!(1)),
    ];
    assert_eq!(cases.len(), 6);
    let refused = cases
        .into_iter()
        .filter(|(field, value)| {
            let mut source = full_source();
            source[*field] = value.clone();
            matches!(
                catalog.validate(ToolName::Remember, &remember(source)),
                Err(ErrorCode::InvalidInput)
            )
        })
        .count();
    assert_eq!(
        refused, 6,
        "every source field and extra-key case must be refused"
    );
    let mut cases = Vec::new();
    for (field, value) in [
        ("kind", json!("Email")),
        ("object_key", json!("")),
        ("version", json!("v".repeat(65))),
    ] {
        let mut source = full_source();
        source[field] = value;
        cases.push(source);
    }
    cases.push(json!({"object_key":"key"}));
    let refused = cases
        .into_iter()
        .filter(|source| {
            matches!(
                catalog.validate(ToolName::Remember, &remember(source.clone())),
                Err(ErrorCode::InvalidInput)
            )
        })
        .count();
    assert_eq!(refused, 4);
    let (_, branch) = catalog.operations()["remember.put"].input_branch().unwrap();
    assert_eq!(SOURCE_VERSION_MAX_CHARS, 64);
    assert_eq!(
        branch["properties"]["source"]["properties"]["version"]["maxLength"],
        json!(SOURCE_VERSION_MAX_CHARS)
    );
}

#[test]
fn evidence_refs_schema_bounds_are_exact() {
    let catalog = CanonicalCatalog::load().unwrap();
    let mut arguments = json!({"action":"note_put", "content":"note", "note_kind":"note", "idempotency_key":"refs-contract"});
    let refs: Vec<_> = (1..=17)
        .map(|id| format!("00000000-0000-0000-0000-{id:012x}"))
        .collect();
    for count in [0, 1, 16] {
        arguments["evidence_refs"] = json!(&refs[..count]);
        assert_eq!(
            catalog
                .validate(ToolName::Memory, &arguments)
                .unwrap()
                .operation_key(),
            "memory.note_put"
        );
    }
    arguments["evidence_refs"] = json!(refs);
    assert!(matches!(
        catalog.validate(ToolName::Memory, &arguments),
        Err(ErrorCode::InvalidInput)
    ));
    arguments["evidence_refs"] = json!([refs[0], refs[0]]);
    assert!(matches!(
        catalog.validate(ToolName::Memory, &arguments),
        Err(ErrorCode::InvalidInput)
    ));
}

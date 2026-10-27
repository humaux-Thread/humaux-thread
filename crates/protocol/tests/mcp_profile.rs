//! `protocol::tests::mcp_profile` — G-M26-2 / G-M26-3: every registry operation round-trips through its tool's flat profile, and a call for one action can never reach another action's fields (M26 D3, B22).
//! Depends-on: crates=[humaux-domain, jsonschema, serde_json]; services=[]; env=[];
//!   modules=[domain::error, protocol::mcp, protocol::mcp_catalog, protocol::mcp_profile]
//! Called-by: [cargo-test]
//! Invariants: [the minimal example of each registry operation is built from its own schema (required fields plus
//!   types, an unknown schema shape fails the test) and must decode from the flat encoding to the original wire call;
//!   a rejection is asserted by its reason, so a rule silently replaced by the schema check still turns red]
//! Spec: §33; §33.1

use std::collections::BTreeSet;

use humaux_domain::error::ErrorCode;
use humaux_protocol::mcp::ToolName;
use humaux_protocol::mcp_catalog::CanonicalCatalog;
use humaux_protocol::mcp_profile::{flat_profile, validate};
use jsonschema::Validator;
use serde_json::{Map, Value, json};

const UUID: &str = "018f0000-0000-7000-8000-000000000001";
/// Keywords that annotate a schema without constraining it; a schema holding only these accepts any value.
const ANNOTATION_ONLY: [&str; 2] = ["description", "title"];

/// One registry operation with its own input-schema branch, in registry order within its tool.
struct Case {
    tool: ToolName,
    action: String,
    index: usize,
    branch: Value,
}

fn cases() -> Vec<Case> {
    let catalog = CanonicalCatalog::load().expect("registry loads");
    let mut cases: Vec<Case> = catalog
        .operations()
        .values()
        .map(|op| {
            let (index, branch) = op.input_branch().expect("input_schema resolves");
            Case {
                tool: op.tool_name().expect("wire tool"),
                action: op.action.clone(),
                index,
                branch,
            }
        })
        .collect();
    cases.sort_by_key(|case| (case.tool, case.index));
    cases
}

fn compile(schema: &Value) -> Validator {
    jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(schema)
        .expect("schema compiles")
}

fn fixed_value(schema: &Value) -> Option<&Value> {
    schema
        .get("const")
        .or_else(|| match schema.get("enum")?.as_array()?.as_slice() {
            [only] => Some(only),
            _ => None,
        })
}

fn discriminators(branch: &Value) -> BTreeSet<String> {
    branch["properties"]
        .as_object()
        .expect("branch properties")
        .iter()
        .filter(|(_, schema)| fixed_value(schema).is_some())
        .map(|(name, _)| name.clone())
        .collect()
}

fn required(branch: &Value) -> Vec<String> {
    branch
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// Folds the first `oneOf` / `anyOf` alternative into a schema, so the smallest example satisfies it.
fn effective(schema: &Value) -> Value {
    let mut merged = schema.clone();
    for key in ["oneOf", "anyOf"] {
        if let Some(first) = schema.get(key).and_then(|alternatives| alternatives.get(0)) {
            overlay(&mut merged, first);
        }
    }
    merged
}

fn overlay(base: &mut Value, extra: &Value) {
    match (base, extra) {
        (Value::Object(base), Value::Object(extra)) => {
            for (key, value) in extra {
                overlay_key(base, key, value);
            }
        }
        (Value::Array(base), Value::Array(extra)) => {
            let missing: Vec<Value> = extra
                .iter()
                .filter(|item| !base.contains(item))
                .cloned()
                .collect();
            base.extend(missing);
        }
        (base, extra) => *base = extra.clone(),
    }
}

fn overlay_key(base: &mut Map<String, Value>, key: &str, value: &Value) {
    match base.get_mut(key) {
        Some(slot) => overlay(slot, value),
        None => {
            base.insert(key.to_owned(), value.clone());
        }
    }
}

/// The smallest value the schema accepts, from `required` and types only; an unknown shape fails the test.
fn example(schema: &Value) -> Value {
    let schema = effective(schema);
    if let Some(value) = schema.get("const") {
        return value.clone();
    }
    if let Some(first) = schema.get("enum").and_then(|values| values.get(0)) {
        return first.clone();
    }
    match schema.get("type").and_then(Value::as_str) {
        Some("string") => string_example(&schema),
        Some("integer") => schema.get("minimum").cloned().unwrap_or(json!(0)),
        Some("boolean") => json!(false),
        Some("array") => {
            let count = schema.get("minItems").and_then(Value::as_u64).unwrap_or(0);
            Value::Array((0..count).map(|_| example(&schema["items"])).collect())
        }
        Some("object") | None if schema.get("properties").is_some() => object_example(&schema),
        None if only_annotations(&schema) => json!("x"),
        other => panic!("example builder does not know this schema ({other:?}): {schema}"),
    }
}

fn string_example(schema: &Value) -> Value {
    if schema.get("format").and_then(Value::as_str) == Some("uuid") {
        return json!(UUID);
    }
    if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
        return json!("a".repeat(if pattern.ends_with("{64}$") { 64 } else { 1 }));
    }
    let length = schema
        .get("minLength")
        .and_then(Value::as_u64)
        .unwrap_or(1)
        .max(1);
    json!("a".repeat(usize::try_from(length).expect("minLength fits usize")))
}

fn object_example(schema: &Value) -> Value {
    Value::Object(
        required(schema)
            .into_iter()
            .map(|name| {
                let value = example(&schema["properties"][name.as_str()]);
                (name, value)
            })
            .collect(),
    )
}

fn only_annotations(schema: &Value) -> bool {
    schema.as_object().is_some_and(|map| {
        map.keys()
            .all(|key| ANNOTATION_ONLY.contains(&key.as_str()))
    })
}

fn example_call(case: &Case) -> Map<String, Value> {
    match example(&case.branch) {
        Value::Object(call) => call,
        other => panic!("{}: example is not an object: {other}", case.action),
    }
}

/// What a host sends for `call`: only fields the profile lists, plus the root `action`; discriminators are the
/// server's to fill.
fn encode_flat(case: &Case, profile: &Value, call: &Map<String, Value>) -> Map<String, Value> {
    let listed = profile["properties"]
        .as_object()
        .expect("profile properties");
    let fixed = discriminators(&case.branch);
    let mut flat = Map::new();
    flat.insert("action".to_owned(), json!(case.action));
    for (name, value) in call {
        if !fixed.contains(name) && listed.contains_key(name) {
            flat.insert(name.clone(), value.clone());
        }
    }
    flat
}

/// A model that fills every field of the profile: absent ones become null.
fn null_filled(profile: &Value, flat: &Map<String, Value>) -> Value {
    let mut filled = flat.clone();
    for name in profile["properties"]
        .as_object()
        .expect("profile properties")
        .keys()
    {
        filled.entry(name.clone()).or_insert(Value::Null);
    }
    Value::Object(filled)
}

fn rejected(tool: ToolName, args: Value) -> String {
    match validate(tool, &args) {
        Ok(call) => panic!("{} accepted {args}: {call:?}", tool.as_str()),
        Err(error) => {
            assert_eq!(error.code(), ErrorCode::InvalidInput);
            error.reason().to_owned()
        }
    }
}

#[test]
fn g_m26_2_every_operation_round_trips_through_the_flat_profile() {
    for case in cases() {
        let who = format!("{}.{}", case.tool.as_str(), case.action);
        let profile = flat_profile(case.tool).expect("flat profile");
        let call = example_call(&case);
        let wire = Value::Object(call.clone());
        assert!(
            compile(&case.branch).is_valid(&wire),
            "{who}: example {wire} is not valid for its own schema"
        );
        let listed = profile["properties"]
            .as_object()
            .expect("profile properties");
        let fixed = discriminators(&case.branch);
        for name in required(&case.branch)
            .iter()
            .filter(|name| !fixed.contains(*name))
        {
            assert!(
                listed.contains_key(name),
                "{who}: flat profile lacks required field {name}"
            );
        }
        let flat = encode_flat(&case, &profile, &call);
        assert!(
            compile(&profile).is_valid(&Value::Object(flat.clone())),
            "{who}: flat call {flat:?} is not valid for the flat profile"
        );
        for sent in [Value::Object(flat.clone()), null_filled(&profile, &flat)] {
            let decoded = validate(case.tool, &sent)
                .unwrap_or_else(|error| panic!("{who}: {sent} did not decode: {error:?}"));
            assert_eq!(decoded.action, case.action, "{who}");
            assert_eq!(
                decoded.args, wire,
                "{who}: decode(encode(call)) differs from the call"
            );
        }
    }
}

#[test]
fn g_m26_2_profile_shape_and_determinism() {
    let cases = cases();
    let tools: BTreeSet<ToolName> = cases.iter().map(|case| case.tool).collect();
    assert!(!tools.is_empty());
    for tool in tools {
        let name = tool.as_str();
        let profile = flat_profile(tool).expect("flat profile");
        let again = flat_profile(tool).expect("flat profile");
        assert_eq!(
            serde_json::to_vec(&profile).expect("serialises"),
            serde_json::to_vec(&again).expect("serialises"),
            "{name}: two generations differ"
        );
        let root = profile.as_object().expect("profile is an object");
        for keyword in ["oneOf", "anyOf", "allOf", "not"] {
            assert!(!root.contains_key(keyword), "{name}: root {keyword}");
        }
        assert_eq!(root["type"], "object", "{name}");
        assert_eq!(root["additionalProperties"], false, "{name}");
        assert_eq!(root["required"], json!(["action"]), "{name}");
        let registry: Vec<&str> = cases
            .iter()
            .filter(|case| case.tool == tool)
            .map(|case| case.action.as_str())
            .collect();
        assert_eq!(
            profile["properties"]["action"]["enum"],
            json!(registry),
            "{name}"
        );
        compile(&profile);
    }
}

#[test]
fn g_m26_2_looser_field_is_carried_while_the_action_keeps_its_own_constraint() {
    // annotate_affect requires at least one affect; correct and note_put do not (ruling 1').
    let profile = flat_profile(ToolName::Memory).expect("flat profile");
    assert!(profile["properties"]["affects"].get("minItems").is_none());
    let reason = rejected(
        ToolName::Memory,
        json!({ "action": "annotate_affect", "memory_id": UUID, "affects": [] }),
    );
    assert!(
        reason.contains("annotate_affect") && reason.contains("affects"),
        "{reason}"
    );
}

#[test]
fn g_m26_3_read_action_rejects_a_mutation_only_field() {
    let reason = rejected(
        ToolName::Memory,
        json!({ "action": "get", "memory_id": UUID, "confirm_token": "0123456789abcdef" }),
    );
    assert!(
        reason.contains("confirm_token") && reason.contains("get"),
        "{reason}"
    );
    let read = json!({ "action": "get", "memory_id": UUID });
    assert_eq!(
        validate(ToolName::Memory, &read)
            .expect("plain read decodes")
            .args,
        read
    );
}

#[test]
fn g_m26_3_every_operation_rejects_every_foreign_field() {
    for case in cases() {
        let profile = flat_profile(case.tool).expect("flat profile");
        let flat = encode_flat(&case, &profile, &example_call(&case));
        let own = case.branch["properties"]
            .as_object()
            .expect("branch properties");
        let listed = profile["properties"]
            .as_object()
            .expect("profile properties");
        for foreign in listed
            .keys()
            .filter(|name| *name != "action" && !own.contains_key(*name))
        {
            let mut sent = flat.clone();
            sent.insert(foreign.clone(), json!("x"));
            let reason = rejected(case.tool, Value::Object(sent));
            assert!(
                reason.contains(foreign.as_str()) && reason.contains(case.action.as_str()),
                "{}.{}: foreign field {foreign}: {reason}",
                case.tool.as_str(),
                case.action
            );
        }
    }
}

#[test]
fn g_m26_3_null_never_fills_a_required_field() {
    for case in cases() {
        let profile = flat_profile(case.tool).expect("flat profile");
        let flat = encode_flat(&case, &profile, &example_call(&case));
        let fixed = discriminators(&case.branch);
        for name in required(&case.branch)
            .into_iter()
            .filter(|name| !fixed.contains(name))
        {
            let mut sent = flat.clone();
            sent.insert(name.clone(), Value::Null);
            let reason = rejected(case.tool, Value::Object(sent));
            assert!(
                reason.contains("null") && reason.contains(name.as_str()),
                "{}.{}: null for {name}: {reason}",
                case.tool.as_str(),
                case.action
            );
        }
    }
}

#[test]
fn g_m26_3_irrelevant_and_optional_nulls_are_dropped() {
    let sent = json!({
        "action": "get", "memory_id": UUID, "note_id": null, "confirm_token": null, "text": null,
    });
    let call = validate(ToolName::Memory, &sent).expect("nulls carry no data");
    assert_eq!(call.args, json!({ "action": "get", "memory_id": UUID }));
}

#[test]
fn g_m26_3_action_and_discriminator_rules() {
    for (tool, args) in [
        (ToolName::Memory, json!({ "action": "no_such_action" })),
        (ToolName::Memory, json!({})),
        (ToolName::Memory, json!({ "action": 7 })),
        (ToolName::Memory, json!([])),
        // A single-op tool still needs its `action`.
        (ToolName::Recall, json!({ "query": "q" })),
    ] {
        rejected(tool, args);
    }
    let reason = rejected(
        ToolName::Remember,
        json!({ "action": "put", "operation": "begin_batch", "content": "a", "idempotency_key": "k" }),
    );
    assert!(reason.contains("operation"), "{reason}");
    // put and put_batch share the wire discriminator `operation: put`; the registry action picks the schema.
    let wire = json!({ "operation": "put", "content": "a", "batch_id": UUID });
    for sent in [
        json!({ "action": "put_batch", "content": "a", "batch_id": UUID }),
        json!({ "action": "put_batch", "operation": "put", "content": "a", "batch_id": UUID }),
    ] {
        assert_eq!(
            validate(ToolName::Remember, &sent).expect("decodes").args,
            wire
        );
    }
    let search = json!({ "action": "search", "query": "q" });
    assert_eq!(
        validate(ToolName::Recall, &search).expect("decodes").args,
        json!({ "query": "q" })
    );
}

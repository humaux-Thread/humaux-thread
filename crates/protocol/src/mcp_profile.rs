//! `protocol::mcp_profile` — Flat MCP tool profile generated from the registry's per-action input schemas, and the per-action argument gate that serves it (§33.1; M26 D3).
//! Depends-on: crates=[humaux-domain, jsonschema, serde_json]; services=[];
//!   env=[]; modules=[domain::error, protocol::mcp, protocol::mcp_catalog]
//! Called-by: [tests]
//! Invariants: [the flat profile is a pure function of the registry (actions in registry order, fields sorted, never a
//!   root oneOf/anyOf) and fails closed on a field two actions define incompatibly; validate checks only the chosen
//!   action's own schema, null never fills a required field, and every rejection is ErrorCode::InvalidInput naming
//!   tool, action and field but never a value]
//! Spec: §33; §33.1
//!
//! Hosts that reject a root `oneOf` (B22 matrix) get one object: a root `action` enum plus the union of every
//! action's fields. The union is only what the model sees. The server decodes a flat call back to the exact wire
//! shape of the chosen action, so dispatch never sees a union (M26 D3). Listing the profile in `tools/list` and the
//! gateway wiring belong to later cards (M26-3).
//!
//! Field merge across actions (M26 ruling 1'): schemas are compared with annotation keywords removed; equal ones merge
//! and keep the first action's annotations; a schema that is another plus extra constraint keywords makes the profile
//! carry the looser one; anything else is a generator error. `validate` still enforces the chosen action's own,
//! possibly stricter, schema, so a looser profile field never weakens the server.
//!
//! Discriminators (M26 ruling 5): a property whose schema is a `const` or one-value `enum` (memory's per-action
//! `action`, remember's `operation`) is excluded from the union and filled by `validate` after the root `action` is
//! mapped to the registry action. Tools without such a property (recall, context, continuity) get no extra field.

use std::cmp::Ordering;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use humaux_domain::error::ErrorCode;
use jsonschema::Validator;
use serde_json::{Map, Value, json};

use crate::mcp::ToolName;
use crate::mcp_catalog::{CanonicalCatalog, Operation, validator_for};

/// Keywords that annotate but never constrain; ignored when two field schemas are compared (M26 ruling 1').
const ANNOTATIONS: [&str; 6] = [
    "description",
    "title",
    "examples",
    "$comment",
    "default",
    "deprecated",
];
/// Keywords whose object value maps names, not keywords, to schemas: a property called `title` is not an annotation.
const NAME_MAPS: [&str; 5] = [
    "properties",
    "patternProperties",
    "$defs",
    "dependentSchemas",
    "dependentRequired",
];
/// Keywords whose value is instance data, never a schema.
const DATA_KEYWORDS: [&str; 2] = ["const", "enum"];

/// Profile generation or call validation failure. It is always `ErrorCode::InvalidInput` (§52: no third error
/// enum); the reason names the tool, action and field but never an argument value (§33).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileError {
    reason: String,
}

impl ProfileError {
    fn new(reason: String) -> Self {
        Self { reason }
    }

    /// The terminal code every profile failure maps to (§52).
    pub const fn code(&self) -> ErrorCode {
        ErrorCode::InvalidInput
    }

    /// Why the call or the registry was rejected; safe to relay, it carries no argument value.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// A call that passed per-action validation: the chosen registry action and its exact wire arguments (nulls
/// dropped, discriminators filled), so dispatch needs no knowledge of the flat shape (M26 D3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedCall {
    /// Registry action the root `action` field selected.
    pub action: String,
    /// Arguments exactly as the chosen action's own schema accepts them.
    pub args: Value,
}

/// One registry action: its own schema, compiled once, plus the facts `validate` needs.
struct ActionSchema {
    action: String,
    fields: BTreeMap<String, Value>,
    required: BTreeSet<String>,
    discriminators: BTreeMap<String, Value>,
    validator: Validator,
}

/// A tool's actions in registry (oneOf index) order.
struct ToolProfile {
    actions: Vec<ActionSchema>,
}

/// A merged union field: the schema the profile carries and the action that contributed it.
struct Field {
    schema: Value,
    owner: String,
}

// ponytail: compiled once per process; the registry is embedded at build time, so the cache never goes stale.
static PROFILES: OnceLock<Result<BTreeMap<ToolName, ToolProfile>, ProfileError>> = OnceLock::new();

/// Generates the flat profile of `tool`: `{type: object, properties: {action: enum, ..union}, required: [action],
/// additionalProperties: false}`. Deterministic (actions in registry order, fields sorted) and fail-closed when two
/// actions define one field incompatibly (M26 D3, ruling 1').
pub fn flat_profile(tool: ToolName) -> Result<Value, ProfileError> {
    let actions = &tool_profile(tool)?.actions;
    let names: Vec<&str> = actions
        .iter()
        .map(|action| action.action.as_str())
        .collect();
    let mut properties = Map::new();
    properties.insert(
        "action".to_owned(),
        json!({ "type": "string", "enum": names }),
    );
    for (name, field) in merge_fields(tool, actions)? {
        properties.insert(name, field.schema);
    }
    Ok(json!({
        "type": "object",
        "properties": properties,
        "required": ["action"],
        "additionalProperties": false,
    }))
}

/// Decodes a flat call into the chosen action's wire arguments (M26 D3, B22). Rejects a missing or unknown `action`,
/// a discriminator that contradicts it, a non-null field the action does not define, null for a required field and
/// anything the action's own schema refuses. Nulls elsewhere carry no data and are dropped.
pub fn validate(tool: ToolName, args: &Value) -> Result<ValidatedCall, ProfileError> {
    let profile = tool_profile(tool)?;
    let reject = |why: &str| ProfileError::new(format!("{}: {why}", tool.as_str()));
    let object = args
        .as_object()
        .ok_or_else(|| reject("arguments must be a JSON object"))?;
    let name = object
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| reject("`action` is missing or not a string"))?;
    let chosen = profile
        .actions
        .iter()
        .find(|candidate| candidate.action == name)
        .ok_or_else(|| reject("`action` is not a registry action of this tool"))?;
    Ok(ValidatedCall {
        action: chosen.action.clone(),
        args: chosen.admit(tool, object)?,
    })
}

impl ActionSchema {
    fn new(tool: ToolName, action: &str, branch: &Value) -> Result<Self, ProfileError> {
        let fail = |why: &str| ProfileError::new(format!("{}.{action}: {why}", tool.as_str()));
        let properties = branch
            .get("properties")
            .and_then(Value::as_object)
            .ok_or_else(|| fail("branch has no `properties` object"))?;
        let mut fields = BTreeMap::new();
        let mut discriminators = BTreeMap::new();
        for (name, schema) in properties {
            match fixed_value(schema) {
                Some(value) => discriminators.insert(name.clone(), value.clone()),
                None => fields.insert(name.clone(), schema.clone()),
            };
        }
        // The root `action` is the profile's own field: a branch may only reuse the name as its fixed discriminator.
        let action_clash = fields.contains_key("action")
            || discriminators
                .get("action")
                .is_some_and(|value| value.as_str() != Some(action));
        if action_clash {
            return Err(fail(
                "`action` must be a const equal to the registry action",
            ));
        }
        Ok(Self {
            action: action.to_owned(),
            fields,
            required: branch
                .get("required")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
            discriminators,
            validator: validator_for(branch).map_err(|_| fail("schema does not compile"))?,
        })
    }

    /// Builds the wire arguments of this action from a flat object, or names the first offending field.
    fn admit(&self, tool: ToolName, object: &Map<String, Value>) -> Result<Value, ProfileError> {
        let reject =
            |why: String| ProfileError::new(format!("{}.{}: {why}", tool.as_str(), self.action));
        let mut args = Map::new();
        for (name, value) in object {
            if name == "action" {
                continue;
            }
            if let Some(fixed) = self.discriminators.get(name) {
                if value != fixed {
                    return Err(reject(format!("field `{name}` contradicts the action")));
                }
            } else if value.is_null() {
                if self.required.contains(name) {
                    return Err(reject(format!("null for required field `{name}`")));
                }
            } else if self.fields.contains_key(name) {
                args.insert(name.clone(), value.clone());
            } else {
                return Err(reject(format!(
                    "field `{name}` is not accepted by this action"
                )));
            }
        }
        args.extend(
            self.discriminators
                .iter()
                .map(|(name, value)| (name.clone(), value.clone())),
        );
        let candidate = Value::Object(args);
        if let Err(error) = self.validator.validate(&candidate) {
            return Err(reject(format!(
                "arguments violate the action schema at `{}`",
                error.instance_path().as_str()
            )));
        }
        Ok(candidate)
    }
}

impl Field {
    /// Folds another action's schema for the same field name into the carried one (M26 ruling 1').
    fn absorb(
        &mut self,
        tool: ToolName,
        name: &str,
        action: &str,
        incoming: &Value,
    ) -> Result<(), ProfileError> {
        match relate(&self.schema, incoming) {
            Some(Ordering::Less | Ordering::Equal) => {}
            Some(Ordering::Greater) => {
                self.schema = incoming.clone();
                action.clone_into(&mut self.owner);
            }
            None => {
                return Err(ProfileError::new(format!(
                    "{}: field `{name}` has incompatible schemas in actions `{}` and `{action}`",
                    tool.as_str(),
                    self.owner
                )));
            }
        }
        Ok(())
    }
}

/// Union of every action's non-discriminator fields, reconciled per ruling 1'; the first conflict aborts.
fn merge_fields(
    tool: ToolName,
    actions: &[ActionSchema],
) -> Result<BTreeMap<String, Field>, ProfileError> {
    let mut merged: BTreeMap<String, Field> = BTreeMap::new();
    for action in actions {
        for (name, schema) in &action.fields {
            match merged.entry(name.clone()) {
                Entry::Vacant(slot) => {
                    slot.insert(Field {
                        schema: schema.clone(),
                        owner: action.action.clone(),
                    });
                }
                Entry::Occupied(mut slot) => {
                    slot.get_mut().absorb(tool, name, &action.action, schema)?;
                }
            }
        }
    }
    Ok(merged)
}

/// Orders two field schemas by constraint strength once annotations are removed: `Equal` same, `Less` when `a` is
/// `b` minus constraint keywords, `Greater` for the reverse, `None` when incomparable (the caller fails closed).
fn relate(a: &Value, b: &Value) -> Option<Ordering> {
    let (a, b) = (strip_annotations(a), strip_annotations(b));
    if a == b {
        Some(Ordering::Equal)
    } else if drops_keywords(&a, &b) {
        Some(Ordering::Less)
    } else if drops_keywords(&b, &a) {
        Some(Ordering::Greater)
    } else {
        None
    }
}

/// `loose` is `strict` with at least one top-level keyword removed, everything else byte-equal.
fn drops_keywords(loose: &Value, strict: &Value) -> bool {
    match (loose.as_object(), strict.as_object()) {
        (Some(loose), Some(strict)) => {
            loose.len() < strict.len()
                && loose
                    .iter()
                    .all(|(key, value)| strict.get(key) == Some(value))
        }
        _ => false,
    }
}

/// Removes annotation keywords at every schema depth, leaving property names and instance data untouched.
fn strip_annotations(schema: &Value) -> Value {
    match schema {
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(key, _)| !ANNOTATIONS.contains(&key.as_str()))
                .map(|(key, value)| (key.clone(), strip_keyword(key, value)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(strip_annotations).collect()),
        other => other.clone(),
    }
}

fn strip_keyword(key: &str, value: &Value) -> Value {
    match value {
        _ if DATA_KEYWORDS.contains(&key) => value.clone(),
        Value::Object(names) if NAME_MAPS.contains(&key) => Value::Object(
            names
                .iter()
                .map(|(name, schema)| (name.clone(), strip_annotations(schema)))
                .collect(),
        ),
        _ => strip_annotations(value),
    }
}

/// The single value a schema allows (`const` or a one-value `enum`): the mark of a discriminator (M26 ruling 5).
fn fixed_value(schema: &Value) -> Option<&Value> {
    schema
        .get("const")
        .or_else(|| match schema.get("enum")?.as_array()?.as_slice() {
            [only] => Some(only),
            _ => None,
        })
}

fn tool_profile(tool: ToolName) -> Result<&'static ToolProfile, ProfileError> {
    PROFILES
        .get_or_init(build_profiles)
        .as_ref()
        .map_err(ProfileError::clone)?
        .get(&tool)
        .ok_or_else(|| ProfileError::new(format!("{}: no registry action", tool.as_str())))
}

fn build_profiles() -> Result<BTreeMap<ToolName, ToolProfile>, ProfileError> {
    let catalog = CanonicalCatalog::load()
        .map_err(|_| ProfileError::new("registry does not load".to_owned()))?;
    let mut by_tool: BTreeMap<ToolName, Vec<(usize, ActionSchema)>> = BTreeMap::new();
    for op in catalog.operations().values() {
        let tool = op.tool_name().map_err(|_| unresolved(op))?;
        let (index, branch) = op.input_branch().map_err(|_| unresolved(op))?;
        let schema = ActionSchema::new(tool, &op.action, &branch)?;
        by_tool.entry(tool).or_default().push((index, schema));
    }
    Ok(by_tool
        .into_iter()
        .map(|(tool, mut actions)| {
            actions.sort_by_key(|(index, _)| *index);
            let actions = actions.into_iter().map(|(_, action)| action).collect();
            (tool, ToolProfile { actions })
        })
        .collect())
}

fn unresolved(op: &Operation) -> ProfileError {
    ProfileError::new(format!("{}: input schema does not resolve", op.op))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(name: &str, properties: &Value) -> ActionSchema {
        let branch =
            json!({ "properties": properties, "required": [], "additionalProperties": false });
        ActionSchema::new(ToolName::Memory, name, &branch).unwrap()
    }

    #[test]
    fn annotation_only_difference_merges_and_keeps_the_first_annotations() {
        let a = action(
            "a",
            &json!({ "x": { "type": "string", "description": "first" } }),
        );
        let b = action(
            "b",
            &json!({ "x": { "type": "string", "description": "second" } }),
        );
        let merged = merge_fields(ToolName::Memory, &[a, b]).unwrap();
        assert_eq!(merged["x"].schema["description"], "first");
    }

    #[test]
    fn constraint_superset_carries_the_looser_schema_in_either_order() {
        let loose = json!({ "x": { "type": "array" } });
        let strict = json!({ "x": { "type": "array", "minItems": 1 } });
        for (first, second) in [(&loose, &strict), (&strict, &loose)] {
            let actions = [action("a", first), action("b", second)];
            let merged = merge_fields(ToolName::Memory, &actions).unwrap();
            assert_eq!(merged["x"].schema, json!({ "type": "array" }));
        }
    }

    #[test]
    fn incompatible_field_schemas_fail_closed_naming_tool_field_and_both_actions() {
        let a = action("a", &json!({ "x": { "type": "string" } }));
        let b = action("b", &json!({ "x": { "type": "integer" } }));
        let error = merge_fields(ToolName::Memory, &[a, b]).err().unwrap();
        for needle in ["memory", "`x`", "`a`", "`b`"] {
            assert!(error.reason().contains(needle), "{error:?}");
        }
        assert_eq!(error.code(), ErrorCode::InvalidInput);
    }

    #[test]
    fn a_property_named_like_an_annotation_is_still_compared() {
        let nested = |kind: &str| json!({ "x": { "type": "object", "properties": { "title": { "type": kind } } } });
        let a = action("a", &nested("string"));
        let b = action("b", &nested("integer"));
        assert!(merge_fields(ToolName::Memory, &[a, b]).is_err());
    }
}

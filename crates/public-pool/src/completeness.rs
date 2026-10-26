//! Type completeness and F3/A1/A2 receipts; no admission or persistence authority (ADR-0090 D-B/D-C).
//! Depends-on: crates=[humaux-domain, serde_json, uuid]; services=[]; env=[]; modules=[]
//! Called-by: [cargo-test]
//! Invariants: [unchecked is NOT_RUN; result is never model-inferred; causal conditions cannot all be stripped]
//! Spec: Baseline §12.6; §52; §57.1; §78.2; ADR-0090 D-B/D-C

use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

// §78.2: mirror domain::attribution until its private macro becomes a shared export.
macro_rules! closed_set {
    ($(#[$meta:meta])* $name:ident { $($(#[$vmeta:meta])* $variant:ident => $wire:literal,)+ }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name { $($(#[$vmeta])* $variant,)+ }
        impl $name {
            /// Exact SQL CHECK domain (§78.2).
            pub const ALL: &[Self] = &[$(Self::$variant,)+];
            /// Wire literal, also used by migration 0275 (§78.2).
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $wire,)+ }
            }
            /// Unknown wire literals cannot silently become defaults (§78.2).
            pub fn parse(wire: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|v| v.as_str() == wire)
            }
        }
    };
}
closed_set! {
    /// Phase-one unit domain (ADR-0090 D-B).
    UnitType {
        /// Reproduced defect and change.
        Fix => "FIX",
        /// Choice between alternatives.
        Decision => "DECISION",
        /// Sourced claims and limits.
        Research => "RESEARCH",
        /// Application instructions.
        Usage => "USAGE",
        /// Completion checkpoints.
        Checklist => "CHECKLIST",
        /// Failed hypothesis and observations.
        FailureCase => "FAILURE_CASE",
    }
}
closed_set! {
    /// Explicit field knowledge, independent of result (ADR-0089 D-B).
    FieldState {
        /// A value exists.
        Known => "KNOWN",
        /// Value cannot yet be established.
        Unknown => "UNKNOWN",
        /// Field does not apply.
        NotApplicable => "NOT_APPLICABLE",
    }
}
closed_set! {
    /// Field provenance (ADR-0090 D-B).
    Assist {
        /// Deterministic extraction.
        Rule => "RULE",
        /// Model draft; forbidden for result.
        Model => "MODEL",
        /// Contributor supplied.
        Contributor => "CONTRIBUTOR",
    }
}
closed_set! {
    /// Reported outcome, never inferred from tone (ADR-0090 D-B).
    UnitResult {
        /// No outcome established.
        Unknown => "UNKNOWN",
        /// Succeeded.
        Success => "SUCCESS",
        /// Partially succeeded.
        Partial => "PARTIAL",
        /// Failed.
        Failed => "FAILED",
    }
}

/// Receipt version changes whenever the deterministic rules change (ADR-0090 D-B).
pub const RULE_VERSION: &str = "M20-completeness-1";
const COMMON: &[&str] = &[
    "problem_goal",
    "context_constraints",
    "environment",
    "preconditions",
    "approach",
    "result",
    "verification_method",
    "failure_conditions",
    "alternatives",
    "rights",
];

/// Required fields and the subset allowed to remain UNKNOWN (ADR-0090 D-B).
pub fn type_fields(kind: UnitType) -> (&'static [&'static str], &'static [&'static str]) {
    match kind {
        UnitType::Fix => (
            &[
                "repro",
                "expected_vs_actual",
                "root_cause",
                "certainty",
                "change",
                "regression_check",
                "rollback",
                "failure_conditions",
            ],
            &["certainty", "rollback"],
        ),
        UnitType::Decision => (
            &[
                "goal",
                "candidates",
                "constraints",
                "trade_offs",
                "why_not",
                "redecide_triggers",
            ],
            &[],
        ),
        UnitType::Research => (
            &[
                "source",
                "version",
                "locator",
                "fact_or_inference",
                "applicability",
                "limits",
            ],
            &[],
        ),
        UnitType::Usage => (
            &[
                "environment",
                "input",
                "steps",
                "expected_output",
                "verification_state",
                "errors",
                "not_applicable_cases",
            ],
            &["errors"],
        ),
        UnitType::Checklist => (
            &[
                "preconditions",
                "steps",
                "checkpoints",
                "done_criteria",
                "exception_branches",
                "rollback",
            ],
            &["rollback"],
        ),
        UnitType::FailureCase => (
            &[
                "hypothesis",
                "attempt",
                "environment",
                "observation",
                "excluded",
                "unknowns",
            ],
            &[],
        ),
    }
}

/// One draft field; checks remain necessary for unpersisted drafts (ADR-0090 D-B).
#[derive(Debug, Clone)]
pub struct UnitField {
    /// Knowledge state, not an outcome.
    pub state: FieldState,
    /// SQL NULL is represented by None; JSON null is not SQL NULL (§78.2).
    pub value: Option<Value>,
    /// Extraction provenance.
    pub assist: Assist,
}

/// Causal information loss must be explicit (ADR-0090 D-B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CausalConditions {
    /// No causal conditions existed in the source.
    NoneOriginally,
    /// At least one original causal condition remains.
    Preserved,
    /// Every original causal condition was removed for publication.
    Stripped,
}

/// A revision's deterministic inputs; no private identifiers (ADR-0089 D-D).
pub struct UnitDraft {
    /// Phase-one type.
    pub kind: UnitType,
    /// Exactly one field per key, matching the DB primary key.
    pub fields: BTreeMap<String, UnitField>,
    /// Whether publication discarded every causal condition.
    pub conditions: CausalConditions,
}

/// Closed completeness verdict; reason codes are not a third error enum (§52).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every required field satisfies the type rule.
    Complete,
    /// Sorted, deduplicated exact field names or the CONDITIONS_STRIPPED code.
    Incomplete {
        /// The complete set of unsatisfied requirements.
        missing: Vec<String>,
    },
}

/// Versioned deterministic completeness receipt (ADR-0090 D-B).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletenessReceipt {
    /// Rule manifest version used by this evaluation.
    pub rule_version: &'static str,
    /// Closed decision with exact reasons.
    pub verdict: Verdict,
}

fn valid_field(key: &str, field: &UnitField, unknown_ok: bool) -> bool {
    if (field.state == FieldState::Known) != field.value.is_some() {
        return false;
    }
    if key == "result" {
        return field.assist != Assist::Model
            && field
                .value
                .as_ref()
                .and_then(Value::as_str)
                .and_then(UnitResult::parse)
                .is_some();
    }
    field.state == FieldState::Known || (unknown_ok && field.state == FieldState::Unknown)
}

/// Evaluate a draft without inferring missing values (ADR-0090 D-B).
pub fn completeness(draft: &UnitDraft) -> CompletenessReceipt {
    let (required, unknown_ok) = type_fields(draft.kind);
    let mut missing: Vec<String> = COMMON
        .iter()
        .chain(required)
        .copied()
        .filter(|key| {
            !draft
                .fields
                .get(*key)
                .is_some_and(|field| valid_field(key, field, unknown_ok.contains(key)))
        })
        .map(str::to_owned)
        .collect();
    if draft.kind == UnitType::Decision
        && !draft
            .fields
            .get("candidates")
            .and_then(|f| f.value.as_ref())
            .and_then(Value::as_array)
            .is_some_and(|v| v.len() >= 2)
    {
        missing.push("candidates".into());
    }
    if draft.conditions == CausalConditions::Stripped {
        missing.push("CONDITIONS_STRIPPED".into());
    }
    missing.sort();
    missing.dedup();
    CompletenessReceipt {
        rule_version: RULE_VERSION,
        verdict: if missing.is_empty() {
            Verdict::Complete
        } else {
            Verdict::Incomplete { missing }
        },
    }
}

/// Receipt execution state; NOT_RUN cannot become pass (ADR-0090 D-C, §57.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateState {
    /// Checked and satisfied.
    Pass,
    /// Checked and rejected, exact reasons.
    Fail(Vec<String>),
    /// Explicitly unchecked.
    NotRun,
    /// Phase object does not exist; name is mandatory (§57.1).
    NotApplicable(&'static str),
}

/// Versioned F3/A1/A2 rule result; persistence belongs to M20-11 (ADR-0090 D-C).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleReceipt {
    /// Stable front-gate or rule name.
    pub rule: &'static str,
    /// Current deterministic rule version.
    pub rule_version: &'static str,
    /// Execution result.
    pub state: GateState,
}
fn receipt(rule: &'static str, state: GateState) -> RuleReceipt {
    RuleReceipt {
        rule,
        rule_version: RULE_VERSION,
        state,
    }
}
fn field_state(draft: &UnitDraft) -> GateState {
    if let Verdict::Incomplete { missing } = completeness(draft).verdict {
        GateState::Fail(missing)
    } else {
        GateState::Pass
    }
}

/// F3's field and entity legs remain independently visible (§57.1, ADR-0090 D-C).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontGateReceipt {
    /// Type-required field check, always evaluated.
    pub fields: RuleReceipt,
    /// Entity reference check; public.entities is delivered by M20-18.
    pub entities: RuleReceipt,
}

/// F3 today: evaluate fields even though the entity relation has not landed (M20-18).
pub fn f3(draft: &UnitDraft) -> FrontGateReceipt {
    FrontGateReceipt {
        fields: receipt("F3.fields", field_state(draft)),
        entities: receipt("F3.entities", GateState::NotApplicable("public.entities")),
    }
}

/// A1 requires an explicitly checked transferable-value result and type completeness (ADR-0090 D-C).
pub fn a1(draft: &UnitDraft, transferable: Option<bool>) -> RuleReceipt {
    let state = transferable.map_or(GateState::NotRun, |value| {
        if value {
            field_state(draft)
        } else {
            GateState::Fail(vec!["transferable_value".into()])
        }
    });
    receipt("A1", state)
}

/// Per-claim public evidence, not protected lineage (ADR-0090 D-B, ADR-0089 D-D).
pub struct ClaimEvidence {
    /// Public claim identifier.
    pub claim_id: Uuid,
    /// Original evidence source.
    pub source: String,
    /// Source version.
    pub version: String,
    /// Source locator.
    pub locator: String,
}

/// A2 checks fields and evidence for every claim; None means unchecked (ADR-0090 D-C).
pub fn a2(draft: &UnitDraft, claims: &[Uuid], evidence: Option<&[ClaimEvidence]>) -> RuleReceipt {
    let Some(evidence) = evidence else {
        return receipt("A2", GateState::NotRun);
    };
    let complete = !claims.is_empty()
        && claims.iter().all(|id| {
            evidence
                .iter()
                .filter(|e| {
                    e.claim_id == *id
                        && !e.source.trim().is_empty()
                        && !e.version.trim().is_empty()
                        && !e.locator.trim().is_empty()
                })
                .count()
                >= 1
        });
    receipt(
        "A2",
        if complete {
            field_state(draft)
        } else {
            GateState::Fail(vec!["per_claim_evidence".into()])
        },
    )
}

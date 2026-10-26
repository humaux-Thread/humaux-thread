//! G-M20-6 exact type completeness and Rust/DB contracts (ADR-0090 D-B).
//! Depends-on: crates=[humaux-public-pool, postgres, serde_json, uuid]; services=[PostgreSQL(any)
//!   r=[public.units, public.unit_fields, public.unit_conditions] w=[public.units, public.unit_fields, public.syntheses]];
//!   env=[HUMAUX_TEST_PG_DSN]; modules=[public-pool::completeness]
//! Called-by: [cargo-test]
//! Invariants: [DB probes roll back; missing CI inputs fail; independent oracle retains every required field]
//! Spec: Baseline §12.6; §57.1; §78.2; §79.2; ADR-0090 D-B/D-C

use humaux_public_pool::completeness::{
    Assist, CausalConditions, ClaimEvidence, FieldState, GateState, RULE_VERSION, UnitDraft,
    UnitField, UnitResult, UnitType, Verdict, a1, a2, completeness, f3,
};
use postgres::{Client, NoTls, Transaction};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

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
// §79: expected coverage is independent of the implementation's type_fields dispatch.
const CASES: &[(UnitType, &[&str], &[&str])] = &[
    (
        UnitType::Fix,
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
    (
        UnitType::Decision,
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
    (
        UnitType::Research,
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
    (
        UnitType::Usage,
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
    (
        UnitType::Checklist,
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
    (
        UnitType::FailureCase,
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
];
fn draft(case: &(UnitType, &[&str], &[&str])) -> UnitDraft {
    let fields = COMMON
        .iter()
        .chain(case.1)
        .map(|&key| {
            let value = if key == "result" {
                json!("SUCCESS")
            } else if key == "candidates" {
                json!(["a", "b"])
            } else {
                json!("established")
            };
            (
                key.to_owned(),
                UnitField {
                    state: FieldState::Known,
                    value: Some(value),
                    assist: Assist::Rule,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    UnitDraft {
        kind: case.0,
        fields,
        conditions: CausalConditions::Preserved,
    }
}
fn incomplete(unit: &UnitDraft, expected: &[&str]) {
    let receipt = completeness(unit);
    assert_eq!(receipt.rule_version, RULE_VERSION);
    assert_eq!(
        receipt.verdict,
        Verdict::Incomplete {
            missing: expected.iter().map(|s| (*s).to_owned()).collect()
        }
    );
}

#[test]
fn complete_and_drop_each_required_field_all_six_types() {
    assert_eq!(CASES.len(), 6);
    assert_eq!(
        CASES.iter().map(|c| c.0.as_str()).collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "FIX",
            "DECISION",
            "RESEARCH",
            "USAGE",
            "CHECKLIST",
            "FAILURE_CASE"
        ])
    );
    for case in CASES {
        assert_eq!(completeness(&draft(case)).verdict, Verdict::Complete);
        let required = COMMON
            .iter()
            .chain(case.1)
            .copied()
            .collect::<BTreeSet<_>>();
        for key in required {
            let mut unit = draft(case);
            unit.fields.remove(key);
            incomplete(&unit, &[key]);
            if !case.2.contains(&key) {
                for state in [FieldState::Unknown, FieldState::NotApplicable] {
                    unit.fields.insert(
                        key.into(),
                        UnitField {
                            state,
                            value: None,
                            assist: Assist::Rule,
                        },
                    );
                    incomplete(&unit, &[key]);
                }
            }
        }
    }
}
#[test]
fn fix_without_repro_is_incomplete() {
    let mut unit = draft(&CASES[0]);
    unit.fields.remove("repro");
    incomplete(&unit, &["repro"]);
}
#[test]
fn unknown_permitted_fields_and_stripped_conditions() {
    let mut count = 0;
    for case in CASES {
        for key in case.2 {
            let mut unit = draft(case);
            unit.fields.insert(
                (*key).into(),
                UnitField {
                    state: FieldState::Unknown,
                    value: None,
                    assist: Assist::Contributor,
                },
            );
            assert_eq!(completeness(&unit).verdict, Verdict::Complete);
            count += 1;
        }
    }
    assert_eq!(count, 4);
    let mut unit = draft(&CASES[0]);
    unit.conditions = CausalConditions::Stripped;
    incomplete(&unit, &["CONDITIONS_STRIPPED"]);
    unit.conditions = CausalConditions::NoneOriginally;
    assert_eq!(completeness(&unit).verdict, Verdict::Complete);
    unit.fields.remove("rights");
    unit.fields.remove("approach");
    incomplete(&unit, &["approach", "rights"]);
}
#[test]
fn decision_needs_two_candidates() {
    let mut unit = draft(&CASES[1]);
    unit.fields.get_mut("candidates").unwrap().value = Some(json!(["only"]));
    incomplete(&unit, &["candidates"]);
}
#[test]
fn front_and_rules_are_versioned_and_unchecked_is_not_run() {
    let mut unit = draft(&CASES[0]);
    let front = f3(&unit);
    assert_eq!(front.fields.rule, "F3.fields");
    assert_eq!(front.fields.rule_version, RULE_VERSION);
    assert_eq!(front.fields.state, GateState::Pass);
    assert_eq!(
        front.entities.state,
        GateState::NotApplicable("public.entities")
    );
    assert_eq!(a1(&unit, None).state, GateState::NotRun);
    assert_eq!(
        a1(&unit, Some(false)).state,
        GateState::Fail(vec!["transferable_value".into()])
    );
    assert_eq!(a1(&unit, Some(true)).state, GateState::Pass);
    let claim = Uuid::from_u128(1);
    let evidence = [ClaimEvidence {
        claim_id: claim,
        source: "source".into(),
        version: "1".into(),
        locator: "section".into(),
    }];
    assert_eq!(a2(&unit, &[claim], None).state, GateState::NotRun);
    assert_eq!(
        a2(&unit, &[claim], Some(&[])).state,
        GateState::Fail(vec!["per_claim_evidence".into()])
    );
    assert_eq!(a2(&unit, &[claim], Some(&evidence)).state, GateState::Pass);
    assert_eq!(
        a2(&unit, &[claim, Uuid::from_u128(2)], Some(&evidence)).state,
        GateState::Fail(vec!["per_claim_evidence".into()])
    );
    unit.fields.remove("repro");
    assert_eq!(
        f3(&unit).fields.state,
        GateState::Fail(vec!["repro".into()])
    );
    assert_eq!(
        a1(&unit, Some(true)).state,
        GateState::Fail(vec!["repro".into()])
    );
    let receipt = a2(&unit, &[claim], Some(&evidence));
    assert_eq!(receipt.rule, "A2");
    assert_eq!(receipt.rule_version, RULE_VERSION);
    assert_eq!(receipt.state, GateState::Fail(vec!["repro".into()]));
}
fn database() -> Client {
    Client::connect(
        &std::env::var("HUMAUX_TEST_PG_DSN").expect("G-M20-6 requires PostgreSQL"),
        NoTls,
    )
    .expect("G-M20-6 PostgreSQL connection")
}
fn revision(tx: &mut Transaction<'_>) -> Uuid {
    tx.query_one(
        "INSERT INTO public.syntheses(content) VALUES ('{}') RETURNING synthesis_id",
        &[],
    )
    .unwrap()
    .get(0)
}
fn insert_field(
    tx: &mut Transaction<'_>,
    revision: Uuid,
    key: &str,
    state: &str,
    value: Option<Value>,
    assist: &str,
    constraint: Option<&str>,
) {
    tx.batch_execute("SAVEPOINT field_probe").unwrap();
    let result = tx.execute("INSERT INTO public.unit_fields(revision_id,field_key,state,value,assist) VALUES ($1,$2,$3,$4,$5)",
        &[&revision, &key, &state, &value, &assist]);
    if let Some(constraint) = constraint {
        let error = result.expect_err("CHECK must reject the injected value");
        let error = error.as_db_error().expect("database error");
        assert_eq!(error.code().code(), "23514");
        assert_eq!(error.constraint(), Some(constraint));
    } else {
        assert_eq!(result.unwrap(), 1);
    }
    tx.batch_execute("ROLLBACK TO SAVEPOINT field_probe")
        .unwrap();
}
#[test]
fn result_model_is_refused_by_rust_and_db() {
    let mut client = database();
    let mut tx = client.transaction().unwrap();
    let id = revision(&mut tx);
    let mut unit = draft(&CASES[0]);
    unit.fields.get_mut("result").unwrap().assist = Assist::Model;
    incomplete(&unit, &["result"]);
    insert_field(
        &mut tx,
        id,
        "result",
        "KNOWN",
        Some(json!("SUCCESS")),
        "MODEL",
        Some("unit_fields_result_assist_check"),
    );
    tx.rollback().unwrap();
}
fn literals(tx: &mut Transaction<'_>, name: &str) -> BTreeSet<String> {
    let rows = tx.query("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname=$1 AND connamespace='public'::regnamespace", &[&name]).unwrap();
    assert_eq!(rows.len(), 1, "exactly one {name}");
    let definition: String = rows[0].get(0);
    definition
        .split('\'')
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, s)| s.trim_matches('"').to_owned())
        .collect()
}
fn exact_set(actual: BTreeSet<String>, expected: &[&str]) {
    assert_eq!(actual, expected.iter().map(|s| (*s).to_owned()).collect());
}
#[test]
fn every_check_has_an_exact_rust_db_contract() {
    let mut client = database();
    let mut tx = client.transaction().unwrap();
    let domains = [
        (
            "units_type_check",
            UnitType::ALL.iter().map(|x| x.as_str()).collect::<Vec<_>>(),
        ),
        (
            "unit_fields_state_check",
            FieldState::ALL.iter().map(|x| x.as_str()).collect(),
        ),
        (
            "unit_fields_assist_check",
            Assist::ALL.iter().map(|x| x.as_str()).collect(),
        ),
    ];
    for (name, values) in domains {
        exact_set(literals(&mut tx, name), &values);
    }
    let mut result_values: Vec<_> = UnitResult::ALL.iter().map(|x| x.as_str()).collect();
    result_values.extend(["result", "KNOWN"]);
    exact_set(
        literals(&mut tx, "unit_fields_result_check"),
        &result_values,
    );
    exact_set(literals(&mut tx, "unit_fields_value_check"), &["KNOWN"]);
    exact_set(
        literals(&mut tx, "unit_fields_result_assist_check"),
        &["result", "MODEL"],
    );
    let rows = tx.query("SELECT conname FROM pg_constraint WHERE contype='c' AND conrelid IN ('public.units'::regclass,'public.unit_fields'::regclass)", &[]).unwrap();
    exact_set(
        rows.iter().map(|r| r.get::<_, String>(0)).collect(),
        &[
            "units_type_check",
            "unit_fields_state_check",
            "unit_fields_assist_check",
            "unit_fields_value_check",
            "unit_fields_result_check",
            "unit_fields_result_assist_check",
        ],
    );
    tx.rollback().unwrap();
}
#[test]
fn field_value_and_closed_domains_are_enforced() {
    let mut client = database();
    let mut tx = client.transaction().unwrap();
    let id = revision(&mut tx);
    for state in FieldState::ALL {
        for present in [false, true] {
            let value = present.then(|| json!("established"));
            let valid = (*state == FieldState::Known) == present;
            insert_field(
                &mut tx,
                id,
                "repro",
                state.as_str(),
                value.clone(),
                "RULE",
                (!valid).then_some("unit_fields_value_check"),
            );
            let mut unit = draft(&CASES[0]);
            unit.fields.get_mut("repro").unwrap().state = *state;
            unit.fields.get_mut("repro").unwrap().value = value;
            assert_eq!(
                completeness(&unit).verdict == Verdict::Complete,
                valid && *state == FieldState::Known
            );
        }
    }
    for assist in Assist::ALL {
        insert_field(
            &mut tx,
            id,
            "repro",
            "KNOWN",
            Some(json!("repro")),
            assist.as_str(),
            None,
        );
        for result in UnitResult::ALL {
            let value = json!(result.as_str());
            insert_field(
                &mut tx,
                id,
                "result",
                "KNOWN",
                Some(value.clone()),
                assist.as_str(),
                (*assist == Assist::Model).then_some("unit_fields_result_assist_check"),
            );
            let mut unit = draft(&CASES[0]);
            unit.fields.insert(
                "result".into(),
                UnitField {
                    state: FieldState::Known,
                    value: Some(value),
                    assist: *assist,
                },
            );
            assert_eq!(
                completeness(&unit).verdict == Verdict::Complete,
                *assist != Assist::Model
            );
        }
    }
    insert_field(
        &mut tx,
        id,
        "repro",
        "BOGUS",
        None,
        "RULE",
        Some("unit_fields_state_check"),
    );
    insert_field(
        &mut tx,
        id,
        "repro",
        "KNOWN",
        Some(json!("x")),
        "BOGUS",
        Some("unit_fields_assist_check"),
    );
    insert_field(
        &mut tx,
        id,
        "result",
        "KNOWN",
        Some(json!("BOGUS")),
        "RULE",
        Some("unit_fields_result_check"),
    );
    tx.rollback().unwrap();
}
#[test]
fn six_unit_types_roundtrip_and_phase_two_is_rejected() {
    let mut client = database();
    let mut tx = client.transaction().unwrap();
    for kind in UnitType::ALL {
        let wire = kind.as_str();
        let row = tx
            .query_one(
                "INSERT INTO public.units(unit_type) VALUES ($1) RETURNING unit_type",
                &[&wire],
            )
            .unwrap();
        assert_eq!(UnitType::parse(&row.get::<_, String>(0)), Some(*kind));
    }
    for wire in ["DATA", "PLAYBOOK", "BOGUS"] {
        tx.batch_execute("SAVEPOINT type_probe").unwrap();
        let error = tx
            .execute("INSERT INTO public.units(unit_type) VALUES ($1)", &[&wire])
            .unwrap_err();
        assert_eq!(error.code().unwrap().code(), "23514");
        assert_eq!(
            error.as_db_error().unwrap().constraint(),
            Some("units_type_check")
        );
        assert_eq!(UnitType::parse(wire), None);
        tx.batch_execute("ROLLBACK TO SAVEPOINT type_probe")
            .unwrap();
    }
    tx.rollback().unwrap();
}

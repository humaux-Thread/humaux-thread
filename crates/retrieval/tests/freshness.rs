//! `retrieval::tests::freshness` — §21.5 / ADR-0111 pure policy contract and G-M13-6 envelope orthogonality.
//! Depends-on: crates=[humaux-contracts, humaux-domain, serde_json]; services=[]; env=[];
//!   modules=[contracts::freshness, domain::memory, retrieval::completeness, retrieval::envelope, retrieval::request, retrieval::signals]
//! Called-by: [cargo-test]
//! Invariants: [freshness never changes completeness; domain MemoryType set exhaustively loads]
//! Spec: Baseline §21.5; §23.3; §80.1; ADR-0111

use humaux_domain::memory::MemoryType;
use humaux_retrieval::{
    completeness::{CensusResult, ExactEnumeration, FreshnessClass, ledger},
    envelope::*,
    request::{RetrievalIntent, build_request, resolve_registered_retrieval_profile},
    signals::{compute_freshness, default_freshness_policy, summarize_freshness},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime},
};

#[test]
fn embedded_rows_match_the_actual_memory_type_set() {
    let types = MemoryType::ALL.map(MemoryType::wire);
    let table = humaux_contracts::freshness::values(&types).expect("all domain types load");
    assert_eq!(types.len(), 12);
    assert_eq!(table.rows.len(), types.len());
    for memory_type in MemoryType::ALL {
        assert_eq!(
            table
                .rows
                .iter()
                .filter(|row| row.name == memory_type.wire())
                .count(),
            1
        );
        let policy = default_freshness_policy(memory_type);
        assert_eq!((policy.policy_id, policy.version), ("evidence-per-type", 1));
    }
}

#[test]
fn adr_0111_all_type_thresholds_and_boundaries() {
    let cases = [
        (MemoryType::State, Some(7), Some(30)),
        (MemoryType::Issue, Some(7), Some(30)),
        (MemoryType::Preference, Some(180), None),
        (MemoryType::Lesson, Some(90), Some(365)),
        (MemoryType::Procedure, Some(90), Some(365)),
        (MemoryType::Fact, Some(365), None),
        (MemoryType::Reference, Some(365), None),
        (MemoryType::Decision, None, None),
        (MemoryType::Rejection, None, None),
        (MemoryType::Constraint, None, None),
        (MemoryType::Outcome, None, None),
        (MemoryType::Note, None, None),
    ];
    assert_eq!(cases.len(), MemoryType::ALL.len());
    assert_eq!(
        cases
            .iter()
            .map(|(memory_type, _, _)| memory_type.wire())
            .collect::<BTreeSet<_>>(),
        MemoryType::ALL
            .map(MemoryType::wire)
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
    for (memory_type, aging, stale) in cases {
        let policy = default_freshness_policy(memory_type);
        assert_eq!(
            policy.aging_after,
            aging.map(|n| Duration::from_secs(n * 86400))
        );
        assert_eq!(
            policy.stale_after,
            stale.map(|n| Duration::from_secs(n * 86400))
        );
        let long_age = Duration::from_secs(1000 * 86400);
        assert_eq!(
            policy.classify_age(long_age),
            if stale.is_some() {
                FreshnessClass::Stale
            } else if aging.is_some() {
                FreshnessClass::Aging
            } else {
                FreshnessClass::Fresh
            }
        );
        if let Some(boundary) = policy.aging_after {
            assert_eq!(policy.classify_age(boundary), FreshnessClass::Fresh);
            assert_eq!(
                policy.classify_age(boundary + Duration::from_secs(1)),
                FreshnessClass::Aging
            );
        }
        if let Some(boundary) = policy.stale_after {
            assert_eq!(policy.classify_age(boundary), FreshnessClass::Aging);
            assert_eq!(
                policy.classify_age(boundary + Duration::from_secs(1)),
                FreshnessClass::Stale
            );
        }
    }
}

#[test]
fn g_m15_3_alias_decision_does_not_decay_under_a_global_seven_day_rule() {
    let signal = compute_freshness(
        MemoryType::Decision,
        Some(SystemTime::UNIX_EPOCH),
        SystemTime::UNIX_EPOCH + Duration::from_secs(400 * 86400),
        None,
        None,
    );
    assert_eq!(signal.class, FreshnessClass::Fresh);
    assert_eq!(signal.state_age_seconds, Some(400 * 86400));
    assert_eq!(
        (signal.policy_id, signal.policy_version),
        ("evidence-per-type", 1)
    );
}

#[test]
fn compute_freshness_missing_and_future_evidence_are_unknown() {
    for evidence in [None, Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1))] {
        let signal = compute_freshness(
            MemoryType::Decision,
            evidence,
            SystemTime::UNIX_EPOCH,
            None,
            None,
        );
        assert_eq!(signal.class, FreshnessClass::Unknown);
        assert_eq!(signal.state_age_seconds, None);
        assert_eq!(signal.latest_evidence_at, evidence);
        assert_eq!(signal.policy_id, "evidence-per-type");
    }
}

#[test]
fn summarize_freshness_worst_item_and_unknown_ordering() {
    use FreshnessClass::{Aging, Fresh, Stale, Unknown};
    for (items, expected) in [
        (vec![], Unknown),
        (vec![Fresh], Fresh),
        (vec![Fresh, Aging], Aging),
        (vec![Aging, Unknown], Unknown),
        (vec![Unknown, Stale], Stale),
        (vec![Stale, Unknown], Stale),
        (vec![Fresh, Stale], Stale),
    ] {
        assert_eq!(summarize_freshness(items), expected);
    }
}

fn pipeline() -> PipelineBlock {
    PipelineBlock {
        evidence: EvidenceBlock::no_batch(Some(1), CountScope::StreamLedger),
        knowledge: KnowledgeBlock {
            eligible: Some(1),
            processed: Some(1),
            waiting_key: Some(0),
            failed: Some(0),
            count_scope: CountScope::StreamLedger,
        },
        projection: ProjectionBlock {
            expected: 1,
            done: 1,
            deleted: 0,
            skipped: 0,
            visible: Some(1),
            open_gaps: 0,
            pending: 0,
            points_expected: 1,
            points_settled: 1,
            points_in_flight: 0,
            points_unsettled: 0,
            points_retiring: 0,
            completeness_ratio: Some(1.0),
            current: true,
        },
    }
}

fn provenance() -> (humaux_retrieval::request::RetrievalRequest, ProvenanceBlock) {
    let profile = resolve_registered_retrieval_profile(&BTreeMap::new()).expect("profile");
    let request =
        build_request(RetrievalIntent::trusted_memory_enumerate(), &profile).expect("request");
    let provenance = ProvenanceBlock {
        binary_build: "fixture-build".to_owned(),
        projection_version: ProvenanceValue::NotApplicable {},
        embedding_model_id: ProvenanceValue::NotApplicable {},
        rerank_model_id: ProvenanceValue::NotApplicable {},
        card_builder_version: ProvenanceValue::NotApplicable {},
        profile_fingerprint: request.profile_fingerprint_identity().clone(),
        profile: ProfileBlock {
            top_k: request.top_k(),
            cand_k: request.cand_k(),
            cand_k_formula: request.cand_k_formula(),
            lanes: vec![],
        },
    };
    (request, provenance)
}

#[test]
fn g_m13_6_exact_envelope_with_a_stale_item_stays_exact() {
    let item = compute_freshness(
        MemoryType::State,
        Some(SystemTime::UNIX_EPOCH),
        SystemTime::UNIX_EPOCH + Duration::from_secs(31 * 86400),
        None,
        None,
    );
    assert_eq!(item.class, FreshnessClass::Stale);
    let summary = summarize_freshness([item.class]);
    let pipeline = pipeline();
    let (request, provenance) = provenance();
    let census = CensusResult::enumerated(
        ExactEnumeration::new(
            humaux_domain::selection::AUTHORIZED_MEMORY_ENUMERATION_V1,
            1,
            1,
            0,
        )
        .unwrap(),
    );
    let ledger = ledger::close(
        ledger::LedgerReads {
            expected: 1,
            done: 1,
            deleted: 0,
            skipped: 0,
            open_gaps: 0,
            pending: 0,
        },
        ledger::ProjectionReads {
            points_expected: 1,
            points_settled: 1,
            ..Default::default()
        },
    );
    let envelope = envelope_outcome_block(
        &request,
        CompletenessInputs {
            lane_status: &LaneStatus::Ok,
            census: &census,
            ledger: &ledger,
            pipeline: &pipeline,
            provenance: &provenance,
            visible: Some(1),
            context: None,
            mandatory_missing: 0,
            lag_threshold: Duration::from_secs(60),
        },
        |outcome| {
            Ok(Envelope {
                items: vec![item],
                pipeline: pipeline.clone(),
                provenance: provenance.clone(),
                completeness: CompletenessBlock {
                    class: outcome.class,
                    reason: outcome.reason,
                    exact: outcome.exact,
                    known_lower_bound: outcome.known_lower_bound,
                    lanes: BTreeMap::new(),
                    candidate_count: 1,
                    reranked_count: 1,
                    returned: 1,
                    truncated: false,
                    degradations: vec![],
                },
                freshness: FreshnessBlock {
                    class: summary,
                    latest_evidence_at: None,
                    state_age_seconds: Some(31 * 86400),
                },
                grounding: GroundingBlock::tally([]),
                mandatory: MandatoryReport::NotRun,
                pinned: PinnedReport::NotRun,
            })
        },
    )
    .expect("final envelope outcome")
    .finish();
    let json = serde_json::to_value(&envelope).expect("Envelope serialization");
    assert_eq!(json["items"].as_array().unwrap().len(), 1);
    assert_eq!(json["items"][0]["class"], "stale");
    assert_eq!(json["freshness"]["class"], "stale");
    assert_eq!(
        json["completeness"]["class"], "exact",
        "G-M13-6 fail: stale must not downgrade EXACT"
    );
    assert_eq!(json["completeness"]["exact"]["total"], 1);
    assert_eq!(json["completeness"]["exact"]["returned"], 1);
    assert_eq!(json["completeness"]["degradations"], serde_json::json!([]));
    println!("G-M13-6 pass: EXACT envelope with one stale item remains EXACT");
}

//! `public-pool::tests::admission_deid` — G-M20-7 (A3) and the A3 slice of E-M20-1: every surface in zh and en, NOT_RUN, receipt privacy (D6').
//! Depends-on: crates=[serde_json]; services=[]; env=[]; modules=[public-pool::admission::deid, public-pool::completeness]
//! Called-by: [cargo-test]
//! Invariants: [fixtures are synthetic data files; zero must-reject items are admitted; an unsupplied surface or an unrun secret scan is
//!   NOT_RUN, never pass; a receipt reason is detector@surface:offset+len and never matched text]
//! Spec: Baseline §12.6; §57.1; §78.2; §79.2; ADR-0088 D-D; ADR-0090 D-C

use humaux_public_pool::admission::deid::{
    A3_RULE_VERSION, COMBINED_FLOOR, CONTRIBUTOR, Detector, Hit, SecretScan, Surface, SurfaceText,
    Surfaces, a3, scan,
};
use humaux_public_pool::completeness::{
    Assist, CausalConditions, FieldState, GateState, RuleReceipt, UnitDraft, UnitField, UnitType,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const MUST_REJECT: &str = include_str!("fixtures/deid/must_reject.txt");
const GOOD: &str = include_str!("fixtures/deid/good.txt");
const DEID_SOURCE: &str = include_str!("../src/admission/deid.rs");

struct Case {
    id: String,
    surface: String,
    lang: String,
    expect: Vec<String>,
    text: String,
}

fn parse_cases(raw: &str) -> Vec<Case> {
    raw.lines()
        .map(str::trim_end)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let parts: Vec<&str> = l.splitn(5, " :: ").collect();
            assert_eq!(parts.len(), 5, "malformed fixture line: {l}");
            let expect = if parts[3] == "-" {
                Vec::new()
            } else {
                parts[3].split(',').map(str::to_owned).collect()
            };
            Case {
                id: parts[0].to_owned(),
                surface: parts[1].to_owned(),
                lang: parts[2].to_owned(),
                expect,
                text: parts[4].to_owned(),
            }
        })
        .collect()
}

fn empty_draft() -> UnitDraft {
    UnitDraft {
        kind: UnitType::Fix,
        fields: BTreeMap::new(),
        conditions: CausalConditions::NoneOriginally,
    }
}

fn draft_with(entries: &[(&str, Value)]) -> UnitDraft {
    let fields = entries
        .iter()
        .map(|(key, value)| {
            let field = UnitField {
                state: FieldState::Known,
                value: Some(value.clone()),
                assist: Assist::Contributor,
            };
            ((*key).to_owned(), field)
        })
        .collect();
    UnitDraft {
        kind: UnitType::Fix,
        fields,
        conditions: CausalConditions::NoneOriginally,
    }
}

/// Every surface supplied and empty: the extractors ran and found nothing.
fn blank() -> Surfaces {
    let empty = || SurfaceText::Supplied(Vec::new());
    Surfaces {
        body: empty(),
        title: empty(),
        tags: empty(),
        entity_aliases: empty(),
        code_comments: empty(),
        paths: empty(),
        url_queries: empty(),
        quotes: empty(),
        edge_text: empty(),
        numbers: empty(),
        dates: empty(),
        attribution: CONTRIBUTOR.to_owned(),
    }
}

fn slot(s: &mut Surfaces, surface: Surface) -> Option<&mut SurfaceText> {
    Some(match surface {
        Surface::Body => &mut s.body,
        Surface::Title => &mut s.title,
        Surface::Tags => &mut s.tags,
        Surface::EntityAliases => &mut s.entity_aliases,
        Surface::CodeComments => &mut s.code_comments,
        Surface::Paths => &mut s.paths,
        Surface::UrlQueries => &mut s.url_queries,
        Surface::Quotes => &mut s.quotes,
        Surface::EdgeText => &mut s.edge_text,
        Surface::Numbers => &mut s.numbers,
        Surface::Dates => &mut s.dates,
        Surface::Attribution => return None,
    })
}

fn put(s: &mut Surfaces, surface: Surface, text: &str) {
    if surface == Surface::Attribution {
        s.attribution = text.to_owned();
    } else if let Some(SurfaceText::Supplied(items)) = slot(s, surface) {
        items.push(text.to_owned());
    }
}

fn surface_named(name: &str, id: &str) -> Surface {
    Surface::parse(name).unwrap_or_else(|| panic!("{id}: unknown surface {name}"))
}

fn build(case: &Case) -> Surfaces {
    let mut s = blank();
    if case.surface == "multi" {
        for piece in case.text.split(" §§ ") {
            let (name, text) = piece
                .split_once('=')
                .unwrap_or_else(|| panic!("{}: multi piece without '='", case.id));
            put(&mut s, surface_named(name, &case.id), text);
        }
    } else {
        put(&mut s, surface_named(&case.surface, &case.id), &case.text);
    }
    s
}

fn body_only(text: &str) -> Surfaces {
    let mut s = blank();
    put(&mut s, Surface::Body, text);
    s
}

fn clean() -> SecretScan {
    SecretScan::Clean {
        receipt_digest: "scanner-receipt-digest".to_owned(),
    }
}

fn verdict(s: &Surfaces) -> RuleReceipt {
    a3(&empty_draft(), s, clean())
}

fn fired(s: &Surfaces) -> BTreeSet<&'static str> {
    scan(&empty_draft(), s)
        .iter()
        .map(|h| h.detector.as_str())
        .collect()
}

#[test]
fn detector_ids_match_the_doc_table() {
    let table: BTreeSet<&str> = DEID_SOURCE
        .lines()
        .filter_map(|l| l.strip_prefix("//! | `"))
        .filter_map(|rest| rest.split_once('`'))
        .map(|(id, _)| id)
        .collect();
    let code: BTreeSet<&str> = Detector::ALL.iter().map(|d| d.as_str()).collect();
    assert_eq!(
        table, code,
        "the detector table in admission/deid.rs and Detector::ALL must list the same ids"
    );
    assert_eq!(Surface::ALL.len(), 12, "D6' names twelve surfaces");
}

#[test]
fn dictionaries_carry_a_source_and_version_line() {
    let dictionaries = [
        ("names", include_str!("../src/admission/deid_names_en.txt")),
        (
            "surnames",
            include_str!("../src/admission/deid_surnames_zh.txt"),
        ),
        ("places", include_str!("../src/admission/deid_places.txt")),
        ("roles", include_str!("../src/admission/deid_roles.txt")),
    ];
    for (name, raw) in dictionaries {
        assert!(
            raw.lines().any(|l| l.starts_with("# source:")),
            "{name}: no source line"
        );
        assert!(
            raw.lines().any(|l| l.starts_with("# version:")),
            "{name}: no version line"
        );
    }
}

#[test]
fn zero_must_reject_items_are_admitted() {
    let cases = parse_cases(MUST_REJECT);
    assert!(
        cases.len() >= 100,
        "need at least 100 must-reject items, have {}",
        cases.len()
    );
    let admitted: Vec<&str> = cases
        .iter()
        .filter(|c| !matches!(verdict(&build(c)).state, GateState::Fail(_)))
        .map(|c| c.id.as_str())
        .collect();
    println!(
        "MUST_REJECT items={} admitted={}",
        cases.len(),
        admitted.len()
    );
    assert!(
        admitted.is_empty(),
        "must-reject items that were not rejected: {admitted:?}"
    );
}

#[test]
fn expected_detectors_fire_on_every_must_reject_item() {
    let mut missing = Vec::new();
    for case in parse_cases(MUST_REJECT) {
        let seen = fired(&build(&case));
        for want in &case.expect {
            if !seen.contains(want.as_str()) {
                missing.push(format!("{} expects {want}", case.id));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "expected detectors that did not fire: {missing:?}"
    );
}

#[test]
fn must_reject_set_covers_every_surface_in_both_languages_with_two_detectors() {
    let cases = parse_cases(MUST_REJECT);
    for surface in Surface::ALL {
        for lang in ["en", "zh"] {
            let detectors: BTreeSet<&str> = cases
                .iter()
                .filter(|c| c.surface == surface.as_str() && c.lang == lang)
                .flat_map(|c| c.expect.iter().map(String::as_str))
                .collect();
            assert!(
                detectors.len() >= 2,
                "{} x {lang}: only {detectors:?}",
                surface.as_str()
            );
        }
    }
    let combined = cases
        .iter()
        .filter(|c| c.expect.iter().any(|d| d == "combined_identifiability"))
        .count();
    assert!(
        combined >= 12,
        "need at least 12 combined-floor items, have {combined}"
    );
}

#[test]
fn good_items_admit_rate_meets_the_u4_start_value() {
    let cases = parse_cases(GOOD);
    assert!(
        cases.len() >= 60,
        "need at least 60 good items, have {}",
        cases.len()
    );
    let refused: Vec<&str> = cases
        .iter()
        .filter(|c| verdict(&build(c)).state != GateState::Pass)
        .map(|c| c.id.as_str())
        .collect();
    let admitted = cases.len() - refused.len();
    let rate = admitted as f64 * 100.0 / cases.len() as f64;
    println!(
        "GOOD_ADMIT_RATE {admitted}/{} = {rate:.1}% (U4 start value 70%); refused: {refused:?}",
        cases.len()
    );
    assert!(
        rate >= 70.0,
        "good-item admit rate {rate:.1}% is below the 70% start value"
    );
}

#[test]
fn every_unsupplied_surface_is_not_run() {
    assert_eq!(verdict(&blank()).state, GateState::Pass);
    for surface in Surface::ALL
        .iter()
        .copied()
        .filter(|s| *s != Surface::Attribution)
    {
        let mut s = blank();
        *slot(&mut s, surface).expect("every surface but attribution has a slot") =
            SurfaceText::NotSupplied;
        assert_eq!(verdict(&s).state, GateState::NotRun, "{surface:?}");
    }
    let mut hit_elsewhere = blank();
    hit_elsewhere.title = SurfaceText::NotSupplied;
    put(
        &mut hit_elsewhere,
        Surface::Body,
        "mail pat.sampleton@example.com",
    );
    assert!(matches!(verdict(&hit_elsewhere).state, GateState::Fail(_)));
}

#[test]
fn a_draft_supplies_only_its_own_text_and_numbers() {
    let draft = draft_with(&[
        ("approach", json!("use the retry loop")),
        ("limits", json!({"max": 3})),
    ]);
    let s = Surfaces::from_draft(&draft);
    assert_eq!(
        s.body,
        SurfaceText::Supplied(vec!["use the retry loop".to_owned(), "max".to_owned()])
    );
    assert_eq!(s.numbers, SurfaceText::Supplied(vec!["3".to_owned()]));
    for text in [
        &s.title,
        &s.tags,
        &s.entity_aliases,
        &s.code_comments,
        &s.paths,
        &s.url_queries,
        &s.quotes,
        &s.edge_text,
        &s.dates,
    ] {
        assert_eq!(*text, SurfaceText::NotSupplied);
    }
    assert_eq!(s.attribution, CONTRIBUTOR);
    assert_eq!(a3(&draft, &s, clean()).state, GateState::NotRun);
}

#[test]
fn the_drafts_own_text_is_scanned_even_when_the_surfaces_are_clean() {
    let draft = draft_with(&[("approach", json!("mail pat.sampleton@example.com"))]);
    let receipt = a3(&draft, &blank(), clean());
    assert_eq!(
        receipt.state,
        GateState::Fail(vec!["email@body:5+25".to_owned()])
    );
}

#[test]
fn secret_scan_states_map_to_the_receipt() {
    let (draft, surfaces) = (empty_draft(), blank());
    let receipt = a3(&draft, &surfaces, clean());
    assert_eq!(receipt.state, GateState::Pass);
    assert_eq!(
        (receipt.rule, receipt.rule_version),
        ("A3", A3_RULE_VERSION)
    );
    assert_eq!(A3_RULE_VERSION, "M20-deid-1");
    assert_eq!(
        a3(&draft, &surfaces, SecretScan::NotRun).state,
        GateState::NotRun
    );
    let blank_digest = SecretScan::Clean {
        receipt_digest: "  ".to_owned(),
    };
    assert_eq!(a3(&draft, &surfaces, blank_digest).state, GateState::NotRun);
    let hit = SecretScan::Hit {
        rule_id: "scanner-rule-1",
    };
    assert_eq!(
        a3(&draft, &surfaces, hit).state,
        GateState::Fail(vec!["secret_scan:scanner-rule-1".to_owned()])
    );
    let leaky = body_only("mail pat.sampleton@example.com");
    let state = a3(&draft, &leaky, SecretScan::NotRun).state;
    assert!(
        matches!(state, GateState::Fail(_)),
        "a known hit beats an unrun scan"
    );
}

#[test]
fn attribution_is_the_literal_contributor() {
    let mut s = blank();
    s.attribution = "someone".to_owned();
    assert_eq!(
        verdict(&s).state,
        GateState::Fail(vec!["attribution@attribution:0+7".to_owned()])
    );
    s.attribution = CONTRIBUTOR.to_owned();
    assert_eq!(verdict(&s).state, GateState::Pass);
}

#[test]
fn hit_offsets_are_char_offsets_per_surface_item() {
    let mut s = blank();
    put(&mut s, Surface::Body, "联系 a.b@example.com");
    put(&mut s, Surface::Tags, "x");
    put(&mut s, Surface::Tags, "a.b@example.com");
    let hits = scan(&empty_draft(), &s);
    let body = Hit {
        detector: Detector::Email,
        surface: Surface::Body,
        char_offset: 3,
        len: 15,
    };
    let tags = Hit {
        detector: Detector::Email,
        surface: Surface::Tags,
        char_offset: 2,
        len: 15,
    };
    assert!(hits.contains(&body), "{hits:?}");
    assert!(hits.contains(&tags), "{hits:?}");
    assert_eq!(hits, scan(&empty_draft(), &s), "A3 is deterministic");
}

fn well_formed(reason: &str) -> bool {
    let Some((detector, rest)) = reason.split_once('@') else {
        return false;
    };
    let Some((surface, span)) = rest.split_once(':') else {
        return false;
    };
    let Some((offset, len)) = span.split_once('+') else {
        return false;
    };
    Detector::parse(detector).is_some()
        && Surface::parse(surface).is_some()
        && offset.parse::<usize>().is_ok()
        && len.parse::<usize>().is_ok()
}

#[test]
fn receipt_never_carries_matched_text() {
    let needles = [
        "sampleton",
        "Hannah",
        "13800138000",
        "198.18.0.7",
        "dev_box",
        "psampleton",
    ];
    let mut s = blank();
    put(
        &mut s,
        Surface::Body,
        "Hannah Sampleton wrote from pat.sampleton@example.com",
    );
    put(&mut s, Surface::Paths, "/Users/psampleton/work");
    put(&mut s, Surface::Quotes, "call 13800138000 or 198.18.0.7");
    put(&mut s, Surface::Tags, "dev_box+ci@mail.example.org");
    let receipt = verdict(&s);
    let GateState::Fail(reasons) = &receipt.state else {
        panic!("expected Fail, got {:?}", receipt.state);
    };
    assert!(reasons.len() >= 5, "{reasons:?}");
    let rendered = format!("{receipt:?}");
    for needle in needles {
        assert!(
            !rendered.contains(needle),
            "the receipt copied matched text: {needle}"
        );
    }
    for reason in reasons {
        assert!(
            well_formed(reason),
            "reason is not detector@surface:offset+len: {reason}"
        );
    }
}

#[test]
fn combined_floor_counts_distinct_classes_and_skips_release_dates() {
    assert_eq!(COMBINED_FLOOR, 2);
    let one_class = body_only("Filed on March 5, 2023 by the maintainer.");
    assert_eq!(verdict(&one_class).state, GateState::Pass);
    let two_classes = body_only("Filed on March 5, 2023 by a 34-year-old maintainer.");
    let combined = scan(&empty_draft(), &two_classes)
        .iter()
        .filter(|h| h.detector == Detector::CombinedIdentifiability)
        .count();
    assert_eq!(combined, 2);
    let release = body_only("v2.0.0 was released on March 5, 2023 by a 34-year-old maintainer.");
    assert_eq!(verdict(&release).state, GateState::Pass);
    let two_dates = body_only("Filed on March 5, 2023 and again on 6 June 2023.");
    assert_eq!(verdict(&two_dates).state, GateState::Pass);
}

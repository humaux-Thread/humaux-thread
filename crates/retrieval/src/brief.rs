//! `retrieval::brief` — §25.3 pure brief assembly preserves the stable prefix byte domain.
//! Depends-on: crates=[humaux-domain, serde, serde_json, sha2]; services=[];
//!   env=[]; modules=[domain::context]
//! Called-by: []
//! Invariants: [prefix has no clock, score, map, request id or tail; fixed section order]
//! Spec: §25.3; §25.4; §25.5; §57.1; §78.1; §80.1
use humaux_domain::context::BriefBudget;
use serde::Serialize;
use sha2::{Digest, Sha256};
/// §25.3: declaration order is the section priority, highest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[repr(usize)]
pub enum SectionKind {
    /// §25.4: user-pinned rules precede project facets.
    UserPinned,
    /// §25.4: Mandatory rules cannot be evicted.
    Mandatory,
    /// §25.3.1: GOAL carries its facet version.
    Goal,
    /// §25.3.1: CONSTRAINTS carry their facet versions.
    Constraints,
    /// §25.3.1: REJECTIONS carry their facet versions.
    Rejections,
    /// §78.1: active prevention rules have a configured quota.
    Prevention,
    /// §25.3.1: CURRENT_STATE belongs only to the tail.
    CurrentState,
    /// §25.3.1: NEXT_ACTIONS belong only to the tail.
    NextActions,
    /// §57.1: M18 owns active-task delivery.
    ActiveTasks,
    /// §25.3: the last hand-off belongs only to the tail.
    LastHandoff,
    /// §57.1: M13 owns FACET_COMPLETE and freshness.
    Coverage,
    /// §57.1: experience-list delivery belongs to T-KNOW.
    Experience,
    /// §78.1: reuse suggestions have a configured quota.
    Reuse,
}
const SECTIONS: [SectionKind; 13] = [
    SectionKind::UserPinned,
    SectionKind::Mandatory,
    SectionKind::Goal,
    SectionKind::Constraints,
    SectionKind::Rejections,
    SectionKind::Prevention,
    SectionKind::CurrentState,
    SectionKind::NextActions,
    SectionKind::ActiveTasks,
    SectionKind::LastHandoff,
    SectionKind::Coverage,
    SectionKind::Experience,
    SectionKind::Reuse,
];
const PROTOCOL_VERSION: u32 = 1;
const PREFIX_LEN: usize = 6;
const MANDATORY: usize = SectionKind::Mandatory as usize;
/// §25.3.1: caller-supplied text and identity must come from one snapshot.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct BriefItem {
    /// §25.3: ascending text identity is the primary ordering key.
    pub memory_id: String,
    /// §25.3.1: project facet bodies retain their version identity.
    pub facet_version_id: Option<String>,
    /// §25.3: verbatim text is part of the canonical byte domain.
    pub body: String,
    /// §25.5: the caller accounts for the complete rendered item's tokens.
    pub est_tokens: u32,
    /// §25.4: authority labels accompany rules where applicable.
    pub authority: Option<String>,
}
/// §57.1: only an undelivered owner may be not applicable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionAvailability {
    /// §25.3.1: a successful read may return zero rows.
    Available,
    /// §57.1: the owner has not delivered this source yet.
    NotDelivered,
    /// §25.4: a selected source failed; completeness cannot be established.
    Failed,
}
/// §25.3.1: indices follow [`SectionKind`]; availability is required for every source.
#[derive(Debug, Clone)]
pub struct BriefInput {
    /// §25.3: all thirteen sections use the same snapshot and fixed ordering.
    pub sections: [Vec<BriefItem>; 13],
    /// §57.1: row count cannot establish whether a source was read successfully.
    pub availability: [SectionAvailability; 13],
}
/// §57.1: absence remains distinct from an available section trimmed to zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SectionContent {
    /// §25.5: an empty delivered list can result from explicit truncation.
    Items(Vec<BriefItem>),
    /// §57.1: unavailable input must name the missing object.
    NotApplicable {
        /// §57.1: the owner object, rather than a generic unavailable label.
        missing: &'static str,
    },
}
/// §25.3: section names are closed and cannot reorder the prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BriefSection {
    /// §25.3: identity is independent of delivered row count.
    pub kind: SectionKind,
    /// §57.1: missing input is explicit.
    pub content: SectionContent,
}
/// §25.3: only the fixed protocol and six stable sections enter this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BriefPrefix {
    protocol_version: u32,
    sections: Vec<BriefSection>,
}
/// §25.5: omission counts correspond exactly to [`SectionKind`] indices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Brief {
    /// §25.3: this is the complete prefix serialization domain.
    pub prefix: BriefPrefix,
    /// §25.3: seven variable sections follow the prefix in declaration order.
    pub tail: Vec<BriefSection>,
    /// §25.3: SHA256 of the sole canonical serialization entry.
    pub prefix_sha256: [u8; 32],
    /// §25.5: true exactly when at least one input item was omitted.
    pub truncated: bool,
    /// §25.5: all thirteen counts are present even when zero.
    pub omitted: [usize; 13],
}
impl Brief {
    /// §25.3: structs serialize in declaration order, without alternate encoders.
    #[must_use]
    pub fn prefix_canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.prefix).expect("brief prefix is infallibly serializable")
    }
}
/// §25.4–§25.5: unavailable required input or overflow returns no partial brief.
#[derive(Debug, PartialEq, Eq)]
pub struct BriefFailure {
    /// §25.4: every Mandatory identity remains visible without returning rows.
    pub manifest: Vec<String>,
    /// §25.5: the rejected validated budget is preserved.
    pub budget: BriefBudget,
    /// §25.5: widened accounting cannot wrap at the total cap's integer bound.
    pub required: u64,
    /// §25.4: failed sources and unavailable Mandatory input in fixed section order.
    pub failed_sections: Vec<SectionKind>,
}
/// §25.3: section order and ascending ids define priority; remaining fields break ties.
///
/// # Errors
/// §25.4–§25.5: failed sources or Mandatory overflow return no partial output.
pub fn assemble(mut input: BriefInput, budget: BriefBudget) -> Result<Brief, BriefFailure> {
    for rows in &mut input.sections {
        rows.sort();
    }
    let failed_sections = SECTIONS
        .iter()
        .enumerate()
        .filter(|(index, _)| {
            let state = input.availability[*index];
            state == SectionAvailability::Failed
                || (state != SectionAvailability::Available
                    && (*index == MANDATORY || !input.sections[*index].is_empty()))
        })
        .map(|(_, kind)| *kind)
        .collect::<Vec<_>>();
    let (prefix_overhead, tail_overhead) = fixed_overhead(input.availability);
    let required = prefix_overhead + tail_overhead + tokens(&input.sections[MANDATORY]);
    let cap = u64::from(budget.cap_tokens());
    if required > cap || !failed_sections.is_empty() {
        return Err(BriefFailure {
            manifest: input.sections[MANDATORY]
                .iter()
                .map(|row| row.memory_id.clone())
                .collect(),
            budget,
            required,
            failed_sections,
        });
    }
    let available = input
        .availability
        .map(|state| state == SectionAvailability::Available);
    let mut omitted = [0; 13];
    for (index, limit) in [
        (SectionKind::Prevention as usize, budget.prevention_cap()),
        (SectionKind::Reuse as usize, budget.reuse_cap()),
    ] {
        let rows = &mut input.sections[index];
        omitted[index] = rows.len().saturating_sub(limit);
        rows.truncate(limit);
    }
    let prefix_used = fit(
        &mut input.sections,
        0..PREFIX_LEN,
        budget
            .optional_prefix_tokens()
            .saturating_sub(prefix_overhead)
            .min(cap - required),
        &mut omitted,
    );
    fit(
        &mut input.sections,
        PREFIX_LEN..SECTIONS.len(),
        cap - required - prefix_used,
        &mut omitted,
    );
    let mut sections = input
        .sections
        .into_iter()
        .enumerate()
        .map(|(index, rows)| BriefSection {
            kind: SECTIONS[index],
            content: if available[index] {
                SectionContent::Items(rows)
            } else {
                SectionContent::NotApplicable {
                    missing: missing(SECTIONS[index]),
                }
            },
        })
        .collect::<Vec<_>>();
    let tail = sections.split_off(PREFIX_LEN);
    let mut brief = Brief {
        prefix: BriefPrefix {
            protocol_version: PROTOCOL_VERSION,
            sections,
        },
        tail,
        prefix_sha256: [0; 32],
        truncated: omitted.iter().any(|count| *count != 0),
        omitted,
    };
    brief.prefix_sha256 = Sha256::digest(brief.prefix_canonical_bytes()).into();
    Ok(brief)
}
fn fixed_overhead(availability: [SectionAvailability; 13]) -> (u64, u64) {
    // §25.5: one UTF-8 byte per token conservatively bounds fixed JSON framing;
    // item estimates include their own serialization and separators, not this framing.
    let mut sections = SECTIONS
        .into_iter()
        .enumerate()
        .map(|(index, kind)| BriefSection {
            kind,
            content: if availability[index] == SectionAvailability::Available {
                SectionContent::Items(Vec::new())
            } else {
                SectionContent::NotApplicable {
                    missing: missing(kind),
                }
            },
        })
        .collect::<Vec<_>>();
    let tail = sections.split_off(PREFIX_LEN);
    let prefix = BriefPrefix {
        protocol_version: PROTOCOL_VERSION,
        sections,
    };
    (
        serde_json::to_vec(&prefix)
            .expect("serializable prefix")
            .len() as u64,
        serde_json::to_vec(&tail).expect("serializable tail").len() as u64,
    )
}
fn tokens(rows: &[BriefItem]) -> u64 {
    rows.iter().map(|row| u64::from(row.est_tokens)).sum()
}
fn fit(
    rows: &mut [Vec<BriefItem>; 13],
    range: std::ops::Range<usize>,
    cap: u64,
    omitted: &mut [usize; 13],
) -> u64 {
    let mut used: u64 = range
        .clone()
        .filter(|i| *i != MANDATORY)
        .map(|i| tokens(&rows[i]))
        .sum();
    for index in range.rev().filter(|i| *i != MANDATORY) {
        while used > cap {
            let Some(row) = rows[index].pop() else {
                break;
            };
            used -= u64::from(row.est_tokens);
            omitted[index] += 1;
        }
    }
    used
}
fn missing(kind: SectionKind) -> &'static str {
    match kind {
        SectionKind::UserPinned => "user pinned rules",
        SectionKind::Mandatory => "Mandatory rules",
        SectionKind::Goal => "GOAL facet",
        SectionKind::Constraints => "CONSTRAINTS facet",
        SectionKind::Rejections => "REJECTIONS facet",
        SectionKind::Prevention => "memory_trigger_clauses",
        SectionKind::CurrentState => "CURRENT_STATE facet",
        SectionKind::NextActions => "NEXT_ACTIONS facet",
        SectionKind::ActiveTasks => "M18 task/lease read port",
        SectionKind::LastHandoff => "last hand-off",
        SectionKind::Coverage => "M13 FACET_COMPLETE and freshness",
        SectionKind::Experience => "T-KNOW experience list",
        SectionKind::Reuse => "reuse suggestions",
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use humaux_domain::error::ErrorCode;
    fn item(id: &str, est_tokens: u32) -> BriefItem {
        BriefItem {
            memory_id: id.into(),
            facet_version_id: Some("v1".into()),
            body: id.into(),
            est_tokens,
            authority: Some("User".into()),
        }
    }
    fn budget(cap: u32, share: u8, prevention: usize, reuse: usize) -> BriefBudget {
        BriefBudget::new(cap, share, prevention, reuse).expect("valid budget")
    }
    fn empty() -> BriefInput {
        BriefInput {
            sections: std::array::from_fn(|_| vec![]),
            availability: [SectionAvailability::Available; 13],
        }
    }
    fn overhead() -> u32 {
        let (prefix, tail) = fixed_overhead(empty().availability);
        u32::try_from(prefix + tail).unwrap()
    }
    fn populated() -> BriefInput {
        BriefInput {
            sections: std::array::from_fn(|_| vec![item("b", 2), item("a", 2)]),
            availability: [SectionAvailability::Available; 13],
        }
    }
    #[test]
    fn g_m14_3_same_and_permuted_inputs_have_identical_bytes_and_sha() {
        let input = populated();
        let first = assemble(input.clone(), budget(2000, 70, 3, 3)).unwrap();
        let same = assemble(input.clone(), budget(2000, 70, 3, 3)).unwrap();
        let mut permuted = input;
        for rows in &mut permuted.sections {
            rows.reverse();
        }
        let permuted = assemble(permuted, budget(2000, 70, 3, 3)).unwrap();
        for other in [same, permuted] {
            assert_eq!(
                first.prefix_canonical_bytes(),
                other.prefix_canonical_bytes()
            );
            assert_eq!(first.prefix_sha256, other.prefix_sha256);
        }
        let expected = SECTIONS.map(|kind| BriefSection {
            kind,
            content: SectionContent::Items(vec![item("a", 2), item("b", 2)]),
        });
        assert_eq!(first.prefix.sections, expected[..PREFIX_LEN]);
        assert_eq!(first.tail, expected[PREFIX_LEN..]);
    }
    #[test]
    fn g_m14_3_tail_only_change_keeps_prefix_sha() {
        let mut input = populated();
        let first = assemble(input.clone(), budget(2000, 70, 3, 3)).unwrap();
        input.sections[SectionKind::NextActions as usize][0].body = "changed".into();
        let second = assemble(input, budget(2000, 70, 3, 3)).unwrap();
        assert_eq!(
            first.prefix_canonical_bytes(),
            second.prefix_canonical_bytes()
        );
        assert_eq!(first.prefix_sha256, second.prefix_sha256);
        assert_ne!(first.tail, second.tail);
    }
    #[test]
    fn g_m14_3_prefix_matches_exact_serialization() {
        let mut input = empty();
        input.availability = [SectionAvailability::NotDelivered; 13];
        input.availability[MANDATORY] = SectionAvailability::Available;
        let brief = assemble(input, budget(2000, 0, 0, 0)).unwrap();
        let expected = r#"{"protocol_version":1,"sections":[{"kind":"UserPinned","content":{"NotApplicable":{"missing":"user pinned rules"}}},{"kind":"Mandatory","content":{"Items":[]}},{"kind":"Goal","content":{"NotApplicable":{"missing":"GOAL facet"}}},{"kind":"Constraints","content":{"NotApplicable":{"missing":"CONSTRAINTS facet"}}},{"kind":"Rejections","content":{"NotApplicable":{"missing":"REJECTIONS facet"}}},{"kind":"Prevention","content":{"NotApplicable":{"missing":"memory_trigger_clauses"}}}]}"#;
        assert_eq!(brief.prefix_canonical_bytes(), expected.as_bytes());
        assert_eq!(
            brief.prefix_sha256,
            <[u8; 32]>::from(Sha256::digest(expected.as_bytes()))
        );
        assert_eq!(
            brief.tail,
            SECTIONS[PREFIX_LEN..]
                .iter()
                .map(|kind| BriefSection {
                    kind: *kind,
                    content: SectionContent::NotApplicable {
                        missing: missing(*kind)
                    },
                })
                .collect::<Vec<_>>()
        );
        assert_eq!((brief.omitted, brief.truncated), ([0; 13], false));
    }
    #[test]
    fn g_m14_4_omissions_and_mandatory_retention_are_exact() {
        let brief = assemble(populated(), budget(overhead() + 13, 100, 1, 1)).unwrap();
        assert_eq!(
            (brief.omitted, brief.truncated),
            ([0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2], true)
        );
        assert_eq!(
            brief.prefix.sections[MANDATORY].content,
            SectionContent::Items(vec![item("a", 2), item("b", 2)])
        );
        assert_eq!(
            brief.prefix.sections[0].content,
            SectionContent::Items(vec![item("a", 2), item("b", 2)])
        );
        assert_eq!(brief.tail[0].content, SectionContent::Items(vec![]));
        assert_eq!(brief.tail[1].content, SectionContent::Items(vec![]));
    }
    #[test]
    fn g_m14_4_overflow_has_exact_manifest_and_no_partial_output() {
        let limits = budget(overhead() + 3, 0, 0, 0);
        assert_eq!(
            assemble(populated(), limits),
            Err(BriefFailure {
                manifest: vec!["a".into(), "b".into()],
                budget: limits,
                required: u64::from(overhead()) + 4,
                failed_sections: vec![],
            })
        );
        let brief = assemble(populated(), budget(overhead() + 4, 0, 0, 0)).unwrap();
        assert_eq!(
            (brief.omitted, brief.truncated),
            ([2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2], true)
        );
        assert_eq!(
            brief.prefix.sections[MANDATORY].content,
            SectionContent::Items(vec![item("a", 2), item("b", 2)])
        );
    }
    #[test]
    fn g_m14_4_availability_is_not_inferred_from_row_count() {
        let limits = budget(2000, 100, 0, 0);
        let brief = assemble(empty(), limits).unwrap();
        let expected = SECTIONS.map(|kind| BriefSection {
            kind,
            content: SectionContent::Items(vec![]),
        });
        assert_eq!(brief.prefix.sections, expected[..PREFIX_LEN]);
        assert_eq!(brief.tail, expected[PREFIX_LEN..]);
        for state in [
            SectionAvailability::Failed,
            SectionAvailability::NotDelivered,
        ] {
            let mut input = empty();
            input.availability[MANDATORY] = state;
            let (prefix, tail) = fixed_overhead(input.availability);
            assert_eq!(
                assemble(input, limits),
                Err(BriefFailure {
                    manifest: vec![],
                    budget: limits,
                    required: prefix + tail,
                    failed_sections: vec![SectionKind::Mandatory],
                })
            );
        }
        let mut input = empty();
        input.availability = [SectionAvailability::Failed; 13];
        assert_eq!(
            assemble(input, limits).unwrap_err().failed_sections,
            SECTIONS
        );
    }
    #[test]
    fn g_m14_4_fixed_framing_is_charged_at_the_boundary() {
        assert_eq!(fixed_overhead(empty().availability), (299, 314));
        for cap in [0, 612] {
            let limits = budget(cap, 100, 0, 0);
            assert_eq!(
                assemble(empty(), limits),
                Err(BriefFailure {
                    manifest: vec![],
                    budget: limits,
                    required: 613,
                    failed_sections: vec![],
                })
            );
        }
        let brief = assemble(empty(), budget(613, 100, 0, 0)).unwrap();
        assert_eq!(brief.prefix_canonical_bytes().len(), 299);
        assert_eq!(serde_json::to_vec(&brief.tail).unwrap().len(), 314);
        assert_eq!((brief.omitted, brief.truncated), ([0; 13], false));
        let mut input = empty();
        input.sections[0] = vec![item("optional", 1)];
        let brief = assemble(input, budget(613, 100, 0, 0)).unwrap();
        assert_eq!(brief.omitted, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            brief.prefix.sections[0].content,
            SectionContent::Items(vec![])
        );
    }
    #[test]
    fn g_m14_4_mandatory_cannot_be_evicted_to_meet_the_cap() {
        let mut input = empty();
        input.sections[MANDATORY] = vec![item("b", 2), item("a", 2)];
        input.sections[0] = vec![item("optional", 6)];
        let brief = assemble(input, budget(621, 100, 0, 0)).unwrap();
        assert_eq!(
            brief.prefix.sections[MANDATORY].content,
            SectionContent::Items(vec![item("a", 2), item("b", 2)])
        );
        assert_eq!(
            (brief.omitted, brief.truncated),
            ([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], true)
        );
    }
    #[test]
    fn g_m14_4_caps_share_and_validation() {
        assert_eq!(BriefBudget::new(7, 101, 0, 0), Err(ErrorCode::InvalidInput));
        assert_eq!(budget(7, 0, 0, 0).optional_prefix_tokens(), 0);
        assert_eq!(
            budget(u32::MAX, 100, 0, 0).optional_prefix_tokens(),
            u64::from(u32::MAX)
        );
        let brief = assemble(populated(), budget(2000, 100, 1, 1)).unwrap();
        assert_eq!(
            (brief.omitted, brief.truncated),
            ([0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1], true)
        );
    }
}

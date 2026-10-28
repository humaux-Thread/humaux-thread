//! §25.3: pure brief assembly preserves the stable prefix byte domain.
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
/// §25.3.1: indices follow [`SectionKind`]; empty input names the absent object.
#[derive(Debug, Clone, Default)]
pub struct BriefInput {
    /// §25.3: all thirteen sections use the same snapshot and fixed ordering.
    pub sections: [Vec<BriefItem>; 13],
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
/// §25.5: overflow has the full Mandatory manifest and no partial brief.
#[derive(Debug, PartialEq, Eq)]
pub struct BriefOverflow {
    /// §25.4: every Mandatory item remains visible to the caller.
    pub manifest: Vec<BriefItem>,
    /// §25.5: the rejected validated budget is preserved.
    pub budget: BriefBudget,
    /// §25.5: widened accounting cannot wrap at the total cap's integer bound.
    pub required: u64,
}
/// §25.3: lower-priority sections and larger ids are evicted first; duplicate ids
/// use the remaining item fields as deterministic tie-breakers (§25.3.1).
///
/// # Errors
/// §25.5: Mandatory overflow returns only its manifest, never partial output.
pub fn assemble(mut input: BriefInput, budget: BriefBudget) -> Result<Brief, BriefOverflow> {
    for rows in &mut input.sections {
        rows.sort();
    }
    let required = tokens(&input.sections[MANDATORY]);
    let cap = u64::from(budget.cap_tokens());
    if required > cap {
        return Err(BriefOverflow {
            manifest: input.sections[MANDATORY].clone(),
            budget,
            required,
        });
    }
    let available = input.sections.each_ref().map(|rows| !rows.is_empty());
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
        budget.optional_prefix_tokens().min(cap - required),
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
        SectionKind::Prevention => "private.memory_trigger_clauses",
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
    fn populated() -> BriefInput {
        BriefInput {
            sections: std::array::from_fn(|_| vec![item("b", 2), item("a", 2)]),
        }
    }
    #[test]
    fn g_m14_3_same_and_permuted_inputs_have_identical_bytes_and_sha() {
        let input = populated();
        let first = assemble(input.clone(), budget(200, 70, 3, 3)).unwrap();
        let same = assemble(input.clone(), budget(200, 70, 3, 3)).unwrap();
        let mut permuted = input;
        for rows in &mut permuted.sections {
            rows.reverse();
        }
        let permuted = assemble(permuted, budget(200, 70, 3, 3)).unwrap();
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
        let first = assemble(input.clone(), budget(200, 70, 3, 3)).unwrap();
        input.sections[SectionKind::NextActions as usize][0].body = "changed".into();
        let second = assemble(input, budget(200, 70, 3, 3)).unwrap();
        assert_eq!(
            first.prefix_canonical_bytes(),
            second.prefix_canonical_bytes()
        );
        assert_eq!(first.prefix_sha256, second.prefix_sha256);
        assert_ne!(first.tail, second.tail);
    }
    #[test]
    fn g_m14_3_prefix_matches_exact_serialization() {
        let brief = assemble(BriefInput::default(), budget(0, 0, 0, 0)).unwrap();
        let expected = r#"{"protocol_version":1,"sections":[{"kind":"UserPinned","content":{"NotApplicable":{"missing":"user pinned rules"}}},{"kind":"Mandatory","content":{"NotApplicable":{"missing":"Mandatory rules"}}},{"kind":"Goal","content":{"NotApplicable":{"missing":"GOAL facet"}}},{"kind":"Constraints","content":{"NotApplicable":{"missing":"CONSTRAINTS facet"}}},{"kind":"Rejections","content":{"NotApplicable":{"missing":"REJECTIONS facet"}}},{"kind":"Prevention","content":{"NotApplicable":{"missing":"private.memory_trigger_clauses"}}}]}"#;
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
        assert_eq!(brief.omitted, [0; 13]);
        assert_eq!(brief.truncated, false);
    }
    #[test]
    fn g_m14_4_omissions_and_mandatory_retention_are_exact() {
        let brief = assemble(populated(), budget(13, 30, 1, 1)).unwrap();
        assert_eq!(brief.omitted, [1, 0, 2, 2, 2, 2, 0, 1, 2, 2, 2, 2, 2]);
        assert_eq!(brief.truncated, true);
        assert_eq!(
            brief.prefix.sections[MANDATORY].content,
            SectionContent::Items(vec![item("a", 2), item("b", 2)])
        );
        assert_eq!(
            brief.prefix.sections[0].content,
            SectionContent::Items(vec![item("a", 2)])
        );
        assert_eq!(
            brief.tail[0].content,
            SectionContent::Items(vec![item("a", 2), item("b", 2)])
        );
        assert_eq!(
            brief.tail[1].content,
            SectionContent::Items(vec![item("a", 2)])
        );
    }
    #[test]
    fn g_m14_4_overflow_has_exact_manifest_and_no_partial_output() {
        let limits = budget(3, 0, 0, 0);
        assert_eq!(
            assemble(populated(), limits),
            Err(BriefOverflow {
                manifest: vec![item("a", 2), item("b", 2)],
                budget: limits,
                required: 4,
            })
        );
        let brief = assemble(populated(), budget(4, 0, 0, 0)).unwrap();
        assert_eq!(brief.omitted, [2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]);
        assert_eq!(brief.truncated, true);
        assert_eq!(
            brief.prefix.sections[MANDATORY].content,
            SectionContent::Items(vec![item("a", 2), item("b", 2)])
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
        let brief = assemble(populated(), budget(200, 100, 1, 1)).unwrap();
        assert_eq!(brief.omitted, [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(brief.truncated, true);
    }
}

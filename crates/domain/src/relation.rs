//! `domain::relation` — the §6.1.4 relation kernel's closed sets and validated values (ADR-0078 D-C, M29 T05).
//! Depends-on: crates=[uuid]; services=[]; env=[]; modules=[domain::error, domain::identity, domain::subject]
//! Called-by: [adapters::relation_repo, tests]
//! Invariants: [WHITELIST is the only Rust list of allowed (src_kind, relation_kind, dst_kind) triples and every
//!   other relation set derives from it; a Validity always has the shape private.relation_valid_shape admits]
//! Spec: Baseline §6.1.4; §78.2; ADR-0078 D-C
//!
//! One kernel serves every relation pair: the pair is a value ([`RelationPair`]), never a per-pair copy of the
//! revision / CAS / interval logic. The DB mirrors of this module (migration `0249_relation_kernel.sql`):
//!
//! | Rust | DB |
//! |---|---|
//! | [`WHITELIST`] | `private.relation_triple_allowed(src_kind, relation_kind, dst_kind)` |
//! | [`RelationPair::relation_kinds`] | `<pair>_relation_kind_check` on each table |
//! | [`Validity::new`] | `private.relation_valid_shape(tstzmultirange)` in `<pair>_valid_shape` |
//! | [`DecidedBy`] / [`ModelRef`] wire forms | `<pair>_decided_by_format` / `<pair>_proposed_by_format` |

use std::ops::Bound;

use crate::error::ErrorCode;
use crate::identity::PrincipalId;
use crate::subject::SubjectKind;
use uuid::Uuid;

/// The three first-slice relation pairs (ADR-0078 D-C). Project → Project, workflow and repository relations are
/// deferred and are not variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelationPair {
    /// `private.project_task_relations`: Project → Task.
    ProjectTask,
    /// `private.project_subject_relations`: Project → Subject.
    ProjectSubject,
    /// `private.subject_relations`: Subject → Subject.
    SubjectSubject,
}

impl RelationPair {
    /// All variants — the §78.2 contract-test surface.
    pub const ALL: [RelationPair; 3] = [
        RelationPair::ProjectTask,
        RelationPair::ProjectSubject,
        RelationPair::SubjectSubject,
    ];

    /// The pair whose endpoints are `src` → `dst`, if any.
    pub fn of(src: EndpointKind, dst: EndpointKind) -> Option<Self> {
        match (src, dst) {
            (EndpointKind::Project, EndpointKind::Task) => Some(RelationPair::ProjectTask),
            (EndpointKind::Project, EndpointKind::Subject(_)) => Some(RelationPair::ProjectSubject),
            (EndpointKind::Subject(_), EndpointKind::Subject(_)) => {
                Some(RelationPair::SubjectSubject)
            }
            _ => None,
        }
    }

    /// The relation kinds this pair's table admits, derived from [`WHITELIST`] (§78.2: mirrored by the table's
    /// `relation_kind` CHECK). Ordered as in [`RelationKind::ALL`].
    pub fn relation_kinds(self) -> Vec<RelationKind> {
        RelationKind::ALL
            .into_iter()
            .filter(|kind| kind.pair() == self)
            .collect()
    }
}

/// The kind of a relation endpoint: a project (`private.continuity_projects`), a task (`coord.tasks`) or a subject
/// of one [`SubjectKind`] (§6.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointKind {
    /// A `private.continuity_projects` row.
    Project,
    /// A `coord.tasks` row.
    Task,
    /// A `private.subjects` row of this kind.
    Subject(SubjectKind),
}

impl EndpointKind {
    /// Every endpoint kind — the domain of the whitelist reconciliation.
    pub fn all() -> Vec<EndpointKind> {
        let mut all = vec![EndpointKind::Project, EndpointKind::Task];
        all.extend(SubjectKind::ALL.map(EndpointKind::Subject));
        all
    }

    /// The string `private.relation_triple_allowed` takes: `PROJECT`, `TASK`, or the subject's kind wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            EndpointKind::Project => "PROJECT",
            EndpointKind::Task => "TASK",
            EndpointKind::Subject(kind) => kind.as_str(),
        }
    }
}

/// A relation kind (§6.1.4). Frozen closed set; each kind belongs to exactly one [`RelationPair`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelationKind {
    /// Project → Task; the only kind that counts toward a project's workload.
    Contains,
    /// Project → Task; a reference that does not count toward the workload.
    References,
    /// Project → Website / Product / Brand.
    Targets,
    /// Project → Business / Brand.
    Serves,
    /// Website / Product → Brand; Brand → Business.
    OwnedBy,
    /// Product → Product (a product line is a product others are part of, §6.1.4).
    PartOf,
}

impl RelationKind {
    /// All variants — the §78.2 contract-test and exhaustiveness surface.
    pub const ALL: [RelationKind; 6] = [
        RelationKind::Contains,
        RelationKind::References,
        RelationKind::Targets,
        RelationKind::Serves,
        RelationKind::OwnedBy,
        RelationKind::PartOf,
    ];

    /// Wire string frozen on the `relation_kind` columns.
    pub fn as_str(self) -> &'static str {
        match self {
            RelationKind::Contains => "CONTAINS",
            RelationKind::References => "REFERENCES",
            RelationKind::Targets => "TARGETS",
            RelationKind::Serves => "SERVES",
            RelationKind::OwnedBy => "OWNED_BY",
            RelationKind::PartOf => "PART_OF",
        }
    }

    /// Parse a wire string; unknown / lowercase input is `None`.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }

    /// The pair this kind belongs to: the pair of its first [`WHITELIST`] triple. The unit tests pin that every
    /// kind has a triple and that all of a kind's triples share one pair.
    pub fn pair(self) -> RelationPair {
        WHITELIST
            .iter()
            .find(|(_, kind, _)| *kind == self)
            .and_then(|(src, _, dst)| RelationPair::of(*src, *dst))
            .expect("every RelationKind has a WHITELIST triple (unit-tested)")
    }
}

/// §6.1.4 ⑤ / ADR-0078 D-C first-slice whitelist: the only allowed (src_kind, relation_kind, dst_kind) triples.
/// The single source; `private.relation_triple_allowed` mirrors it (§78.2, gate G-M29-1). `CHANNEL_ACCOUNT`
/// triples join only with the kind, after experiment E-C (ADR-0078 D-B).
pub const WHITELIST: &[(EndpointKind, RelationKind, EndpointKind)] = &[
    (
        EndpointKind::Project,
        RelationKind::Contains,
        EndpointKind::Task,
    ),
    (
        EndpointKind::Project,
        RelationKind::References,
        EndpointKind::Task,
    ),
    (
        EndpointKind::Project,
        RelationKind::Targets,
        EndpointKind::Subject(SubjectKind::Website),
    ),
    (
        EndpointKind::Project,
        RelationKind::Targets,
        EndpointKind::Subject(SubjectKind::Product),
    ),
    (
        EndpointKind::Project,
        RelationKind::Targets,
        EndpointKind::Subject(SubjectKind::Brand),
    ),
    (
        EndpointKind::Project,
        RelationKind::Serves,
        EndpointKind::Subject(SubjectKind::Business),
    ),
    (
        EndpointKind::Project,
        RelationKind::Serves,
        EndpointKind::Subject(SubjectKind::Brand),
    ),
    (
        EndpointKind::Subject(SubjectKind::Website),
        RelationKind::OwnedBy,
        EndpointKind::Subject(SubjectKind::Brand),
    ),
    (
        EndpointKind::Subject(SubjectKind::Product),
        RelationKind::OwnedBy,
        EndpointKind::Subject(SubjectKind::Brand),
    ),
    (
        EndpointKind::Subject(SubjectKind::Brand),
        RelationKind::OwnedBy,
        EndpointKind::Subject(SubjectKind::Business),
    ),
    (
        EndpointKind::Subject(SubjectKind::Product),
        RelationKind::PartOf,
        EndpointKind::Subject(SubjectKind::Product),
    ),
];

/// Relation id: one edge across all its revisions (UUIDv7, §49).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RelationId(pub Uuid);

#[allow(clippy::new_without_default)]
impl RelationId {
    /// Mints a new relation id (UUIDv7, §49).
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

/// One edge: `src_id —kind→ dst_id`. Fixed for the life of a relation id (the DB guard rejects a revision that
/// changes it). The pair, and so the table, follows from `kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelationEdge {
    /// Source endpoint id (a project or subject id, per `kind.pair()`).
    pub src_id: Uuid,
    /// Relation kind.
    pub kind: RelationKind,
    /// Destination endpoint id (a task or subject id, per `kind.pair()`).
    pub dst_id: Uuid,
}

/// A `timestamptz` value as PostgreSQL admits it, including its two special values. Input form only: a
/// [`Validity`] never holds the special values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timestamp {
    /// Explicit `-infinity`.
    NegInfinity,
    /// Microseconds since 1970-01-01T00:00:00Z.
    Micros(i64),
    /// Explicit `infinity`.
    Infinity,
}

/// One PostgreSQL range value as its (lower, upper) bounds: the unvalidated input of [`Validity::new`].
pub type RawRange = (Bound<Timestamp>, Bound<Timestamp>);

/// The `valid` multirange of a revision, validated (§6.1.4 ④): every segment is `[start, end)` with a finite
/// start and a finite or omitted end. Empty = retracted (§6.1.4 ②). Segments are sorted and merged, which is the
/// form PostgreSQL stores, so a value read back equals the value written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validity {
    segments: Vec<(i64, Option<i64>)>,
}

impl Validity {
    /// The retraction value `'{}'`.
    pub fn retracted() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    /// Validates PostgreSQL range values (lower bound, upper bound) with the rules of
    /// `private.relation_valid_shape`: a lower bound that is not an included finite instant (unbounded,
    /// exclusive, `±infinity`) or an upper bound that is inclusive or an explicit `±infinity` is `INVALID_INPUT`.
    /// A segment whose end is not after its start is also `INVALID_INPUT` (PostgreSQL rejects a reversed range
    /// and silently drops an empty one; neither carries meaning here).
    pub fn new(ranges: &[RawRange]) -> Result<Self, ErrorCode> {
        let mut segments = Vec::with_capacity(ranges.len());
        for range in ranges {
            let start = match range.0 {
                Bound::Included(Timestamp::Micros(t)) => t,
                _ => return Err(ErrorCode::InvalidInput),
            };
            let end = match range.1 {
                Bound::Excluded(Timestamp::Micros(t)) if t > start => Some(t),
                Bound::Unbounded => None,
                _ => return Err(ErrorCode::InvalidInput),
            };
            segments.push((start, end));
        }
        segments.sort_unstable();
        let mut merged: Vec<(i64, Option<i64>)> = Vec::with_capacity(segments.len());
        for (start, end) in segments {
            match merged.last_mut() {
                Some((_, last_end)) if last_end.is_none_or(|e| start <= e) => {
                    *last_end = match (*last_end, end) {
                        (Some(a), Some(b)) => Some(a.max(b)),
                        _ => None,
                    };
                }
                _ => merged.push((start, end)),
            }
        }
        Ok(Self { segments: merged })
    }

    /// The segments as `[start, end)` microsecond pairs; `None` = no end.
    pub fn segments(&self) -> &[(i64, Option<i64>)] {
        &self.segments
    }

    /// Whether this is the retraction value `'{}'`.
    pub fn is_retracted(&self) -> bool {
        self.segments.is_empty()
    }
}

/// A registered rule and its version (`rule:<id>@<ver>`, N09 R6). `id` is `[a-z0-9_]+`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleRef {
    id: String,
    version: u32,
}

impl RuleRef {
    /// Validates a rule id (`[a-z0-9_]+`); anything else is `INVALID_INPUT`.
    pub fn new(id: &str, version: u32) -> Result<Self, ErrorCode> {
        let ok = !id.is_empty()
            && id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        ok.then(|| Self {
            id: id.to_string(),
            version,
        })
        .ok_or(ErrorCode::InvalidInput)
    }
}

/// Who decided a revision (§6.1.4 ⑦): a registered rule or a principal. Wire form `rule:<id>@<ver>` |
/// `principal:<uuid>`, the `<pair>_decided_by_format` CHECK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecidedBy {
    /// A deterministic rule (N09 R1 ③).
    Rule(RuleRef),
    /// A principal's explicit decision (N09 R1 ①/④).
    Principal(PrincipalId),
}

impl DecidedBy {
    /// The wire string stored in `decided_by`.
    pub fn to_wire(&self) -> String {
        match self {
            DecidedBy::Rule(rule) => format!("rule:{}@{}", rule.id, rule.version),
            DecidedBy::Principal(principal) => format!("principal:{}", principal.0.hyphenated()),
        }
    }

    /// Parses a stored `decided_by`; any other shape is `None`.
    pub fn parse(s: &str) -> Option<Self> {
        if let Some(rest) = s.strip_prefix("rule:") {
            let (id, version) = rest.split_once('@')?;
            if !version.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            return RuleRef::new(id, version.parse().ok()?)
                .ok()
                .map(DecidedBy::Rule);
        }
        let uuid = s.strip_prefix("principal:")?;
        (uuid.len() == 36 && !uuid.bytes().any(|b| b.is_ascii_uppercase()))
            .then(|| Uuid::parse_str(uuid).ok())
            .flatten()
            .map(|u| DecidedBy::Principal(PrincipalId(u)))
    }
}

/// A model and its version that proposed a revision (`model:<id>@<ver>`): provenance only, never authority
/// (§6.1.4 ⑦, N09 R2). `id` is `[A-Za-z0-9._/-]+`, `version` is `[A-Za-z0-9._-]+`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelRef {
    id: String,
    version: String,
}

impl ModelRef {
    /// Validates both parts against the `<pair>_proposed_by_format` CHECK; anything else is `INVALID_INPUT`.
    pub fn new(id: &str, version: &str) -> Result<Self, ErrorCode> {
        let part = |s: &str, slash: bool| {
            !s.is_empty()
                && s.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || b"._-".contains(&b) || (slash && b == b'/')
                })
        };
        (part(id, true) && part(version, false))
            .then(|| Self {
                id: id.to_string(),
                version: version.to_string(),
            })
            .ok_or(ErrorCode::InvalidInput)
    }

    /// The wire string stored in `proposed_by`.
    pub fn to_wire(&self) -> String {
        format!("model:{}@{}", self.id, self.version)
    }

    /// Parses a stored `proposed_by`; any other shape is `None`.
    pub fn parse(s: &str) -> Option<Self> {
        let (id, version) = s.strip_prefix("model:")?.split_once('@')?;
        Self::new(id, version).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn whitelist_partitions_relation_kinds_by_pair() {
        for kind in RelationKind::ALL {
            let pairs: HashSet<_> = WHITELIST
                .iter()
                .filter(|(_, k, _)| *k == kind)
                .map(|(s, _, d)| RelationPair::of(*s, *d))
                .collect();
            assert_eq!(pairs.len(), 1, "{kind:?} must map to exactly one pair");
            assert!(
                !pairs.contains(&None),
                "{kind:?} has a triple outside every pair"
            );
        }
        let unique: HashSet<_> = WHITELIST.iter().collect();
        assert_eq!(unique.len(), WHITELIST.len(), "duplicate WHITELIST triple");
        for pair in RelationPair::ALL {
            assert!(!pair.relation_kinds().is_empty(), "{pair:?} has no kind");
        }
    }

    #[test]
    fn validity_normalizes_like_postgres() {
        use Bound::{Excluded, Included, Unbounded};
        let at = Timestamp::Micros;
        let v = Validity::new(&[
            (Included(at(30)), Excluded(at(40))),
            (Included(at(10)), Excluded(at(20))),
            (Included(at(20)), Excluded(at(25))),
            (Included(at(35)), Unbounded),
        ])
        .unwrap();
        assert_eq!(v.segments(), &[(10, Some(25)), (30, None)]);
        assert!(Validity::new(&[]).unwrap().is_retracted());
        assert_eq!(
            Validity::new(&[(Included(at(5)), Excluded(at(5)))]),
            Err(ErrorCode::InvalidInput)
        );
    }

    #[test]
    fn decided_by_and_model_ref_round_trip_their_wire_forms() {
        let rule = DecidedBy::Rule(RuleRef::new("task_run", 1).unwrap());
        assert_eq!(rule.to_wire(), "rule:task_run@1");
        assert_eq!(DecidedBy::parse(&rule.to_wire()), Some(rule));
        let principal = DecidedBy::Principal(PrincipalId(Uuid::now_v7()));
        assert_eq!(DecidedBy::parse(&principal.to_wire()), Some(principal));
        for bad in [
            "rule:Task@1",
            "rule:x@",
            "rule:x@-1",
            "principal:nope",
            "model:m@1",
            "",
        ] {
            assert_eq!(DecidedBy::parse(bad), None, "{bad}");
        }
        let model = ModelRef::new("vendor/m-2.5", "2026-10").unwrap();
        assert_eq!(ModelRef::parse(&model.to_wire()), Some(model));
        assert_eq!(ModelRef::new("m@x", "1"), Err(ErrorCode::InvalidInput));
    }
}

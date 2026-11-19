//! `domain::grounding_read` — Retrieval's read contract for §8.8 grounding verdicts.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: [domain::grounding, retrieval::envelope, retrieval::signals, tests]
//! Invariants: [Readers cannot construct a verdict or change the owner's truth-eligibility decision]
//! Spec: Baseline §8.8; ADR-0130; ADR-0131

/// Reporting categories without the owner's severity ordering or eligibility policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroundingReadKind {
    Current,
    RecheckRequired,
    Unresolved,
    CannotEstablish,
}

/// Read-only projection of a verdict issued by the grounding owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroundingRead {
    kind: GroundingReadKind,
    revokes_current_truth_assumption: bool,
}

impl GroundingRead {
    pub(crate) const fn new(
        kind: GroundingReadKind,
        revokes_current_truth_assumption: bool,
    ) -> Self {
        Self {
            kind,
            revokes_current_truth_assumption,
        }
    }

    pub const fn kind(self) -> GroundingReadKind {
        self.kind
    }

    pub const fn revokes_current_truth_assumption(self) -> bool {
        self.revokes_current_truth_assumption
    }
}

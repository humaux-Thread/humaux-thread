//! `domain::knowledge` — candidate vocabulary; provenance never grants authority.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: [adapters::candidate_repo, adapters::dedup_repo, tests]
//! Invariants: [closed kinds and states; accepted candidates never apply Memory changes]
//! Spec: Baseline §6.1.4; §11.6; §78.2; ADR-0113

closed_set! { wire, parse_wire, slice;
    /// ADR-0113 D-B: the single carrier's nine proposal kinds.
    CandidateKind {
        /// Exact duplicate group, never an automatic merge.
        DuplicateGroup => "DUPLICATE_GROUP",
        /// A proposed contradiction, never a truth verdict.
        Contradiction => "CONTRADICTION",
        /// A proposed temporal change.
        TemporalChange => "TEMPORAL_CHANGE",
        /// A proposed stale input.
        Stale => "STALE",
        /// Repeated question provenance.
        RepeatedQuestion => "REPEATED_QUESTION",
        /// A rule draft, never an active rule.
        RuleProposal => "RULE_PROPOSAL",
        /// A lesson draft.
        LessonDraft => "LESSON_DRAFT",
        /// A follow-up draft.
        FollowUpPlan => "FOLLOW_UP_PLAN",
        /// A profile slot proposal.
        ProfileSlot => "PROFILE_SLOT",
    }
}
closed_set! { wire, parse_wire, slice;
    /// ADR-0113 D-C: terminal states cannot transition again.
    CandidateState {
        /// Awaiting a decision.
        Proposed => "PROPOSED",
        /// Manifest confirmation only; applying it requires M07.
        Accepted => "ACCEPTED",
        /// Explicit rejection.
        Rejected => "REJECTED",
        /// Explicit expiration.
        Expired => "EXPIRED",
        /// A stale proposal.
        Stale => "STALE",
    }
}

/// §78.2: the exact caller-requestable transition set, mirrored by the SQL predicate.
pub const CANDIDATE_TRANSITIONS: &[(CandidateState, CandidateState)] = &[
    (CandidateState::Proposed, CandidateState::Accepted),
    (CandidateState::Proposed, CandidateState::Rejected),
    (CandidateState::Proposed, CandidateState::Expired),
];

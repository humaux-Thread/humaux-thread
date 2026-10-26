//! `domain::applicability` — closed applicability vocabulary; no visibility authority.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: [adapters::applicability_repo, tests]
//! Invariants: [DB CHECK lists equal these closed sets; absence of a row means project-local]
//! Spec: Baseline §6.1.1; §78.2; ADR-0096 D-A/D-B.1

/// ADR-0096 D-A: where a memory may apply, independently of who may read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicabilityScope {
    /// One product or brand.
    ProductSpecific,
    /// Any project on the named channel.
    ChannelGeneric,
    /// Any project subject to qualifiers.
    Universal,
}

impl ApplicabilityScope {
    /// Complete DB CHECK vocabulary (§78.2).
    pub const ALL: [Self; 3] = [Self::ProductSpecific, Self::ChannelGeneric, Self::Universal];

    /// Stable DB label (§78.2).
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::ProductSpecific => "PRODUCT_SPECIFIC",
            Self::ChannelGeneric => "CHANNEL_GENERIC",
            Self::Universal => "UNIVERSAL",
        }
    }

    /// Unknown values never widen applicability (§78.2).
    #[must_use]
    pub fn parse_wire(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|item| item.wire() == value)
    }
}

/// ADR-0096 D-B: only a decision door can leave the proposed state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicabilityStatus {
    /// Candidate only; grants no reuse eligibility.
    Proposed,
    /// Explicitly approved with decision Evidence.
    Approved,
    /// Explicitly rejected with decision Evidence.
    Rejected,
}

impl ApplicabilityStatus {
    /// Complete DB CHECK vocabulary (§78.2).
    pub const ALL: [Self; 3] = [Self::Proposed, Self::Approved, Self::Rejected];

    /// Stable DB label (§78.2).
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Proposed => "PROPOSED",
            Self::Approved => "APPROVED",
            Self::Rejected => "REJECTED",
        }
    }

    /// Unknown values are refused (§78.2).
    #[must_use]
    pub fn parse_wire(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|item| item.wire() == value)
    }
}

/// ADR-0096 D-B.1: recorded provenance, never a caller authentication claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignmentMethod {
    /// Reserved for M14-5b; refused until trusted console binding exists.
    OwnerConsole,
    /// Relayed owner instruction, labelled 由聊天授权.
    AgentOnOwnerChat,
}

impl AssignmentMethod {
    /// Complete DB CHECK vocabulary, including the fail-closed console path (§78.2).
    pub const ALL: [Self; 2] = [Self::OwnerConsole, Self::AgentOnOwnerChat];

    /// Stable DB label (§78.2).
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::OwnerConsole => "OWNER_CONSOLE",
            Self::AgentOnOwnerChat => "AGENT_ON_OWNER_CHAT",
        }
    }

    /// Unknown methods never become owner confirmation (§78.2).
    #[must_use]
    pub fn parse_wire(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|item| item.wire() == value)
    }
}

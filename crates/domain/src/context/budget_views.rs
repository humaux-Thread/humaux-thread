//! `domain::context::budget_views` — retrieval budget inputs and results published by Project Continuity (§25.5).
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: [application::recall_read, domain::context, retrieval::brief, retrieval::compiler]
//! Invariants: [only the budget owner constructs these views after validation or reservation]
//! Spec: §25.5; §78.1

/// Validated caps carried by the Context read port.
#[derive(Debug, Clone, Copy)]
pub struct ContextBudgetLimits {
    pub(super) total_tokens: u32,
    pub(super) mandatory_cap_tokens: u32,
}

/// Balance published after the owner reserves for Mandatory and Pinned items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupplementalBudgetView(pub(super) u32);

impl SupplementalBudgetView {
    /// Remaining tokens reserved for the supplemental lane.
    #[must_use]
    pub const fn tokens(self) -> u32 {
        self.0
    }
}

/// Validated brief limits and the owner's computed optional prefix quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BriefBudgetView {
    pub(super) cap_tokens: u32,
    // Preserve the configured share in a rejected budget, even if rounding yields the same quota.
    pub(super) prefix_share_percent: u8,
    pub(super) optional_prefix_tokens: u64,
    pub(super) prevention_cap: usize,
    pub(super) reuse_cap: usize,
}

impl BriefBudgetView {
    /// Total cap shared by required and optional sections.
    #[must_use]
    pub const fn cap_tokens(self) -> u32 {
        self.cap_tokens
    }

    /// Token quota for optional prefix items.
    #[must_use]
    pub const fn optional_prefix_tokens(self) -> u64 {
        self.optional_prefix_tokens
    }

    /// Registry-supplied prevention limit.
    #[must_use]
    pub const fn prevention_cap(self) -> usize {
        self.prevention_cap
    }

    /// Registry-supplied reuse limit.
    #[must_use]
    pub const fn reuse_cap(self) -> usize {
        self.reuse_cap
    }
}

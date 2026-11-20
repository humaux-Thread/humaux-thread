//! `domain::context::budget_views` — retrieval budget inputs and results published by Project Continuity (§25.5).
//! Depends-on: crates=[]; services=[]; env=[]; modules=[domain::lifecycle_types]
//! Called-by: [application::recall_read, domain::context, retrieval::brief, retrieval::compiler, retrieval::completeness, retrieval::envelope, retrieval::handoff]
//! Invariants: [only the budget owner constructs these views after validation or reservation]
//! Spec: §25.5; §78.1

use crate::lifecycle_types::MemoryId;

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

/// §25.5 溢出。
///
/// **本类型不含任何 Context / rows / 可交付内容**，这是刻意的：调用方在这个臂里
/// 拿不到「截断后的前半段」，所以「截掉后半段还声称 complete」写不出来。
/// 它只带 §25.5 要求的 manifest/IDs 与缩减建议所需的量纲。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MandatoryOverflow {
    pub(super) expected: u64,
    pub(super) manifest: Vec<MemoryId>,
    pub(super) budget_tokens: u32,
    pub(super) required_tokens: u32,
}

impl MandatoryOverflow {
    /// 应有条数。
    #[must_use]
    pub const fn expected(&self) -> u64 {
        self.expected
    }

    /// §25.5 要求返回的 manifest/IDs，**全量**——分页建议要靠它才提得出来。
    #[must_use]
    pub fn manifest(&self) -> &[MemoryId] {
        &self.manifest
    }

    /// 硬上限。
    #[must_use]
    pub const fn budget_tokens(&self) -> u32 {
        self.budget_tokens
    }

    /// 实际需要。与上限之差就是缩减建议的量纲。
    #[must_use]
    pub const fn required_tokens(&self) -> u32 {
        self.required_tokens
    }
}

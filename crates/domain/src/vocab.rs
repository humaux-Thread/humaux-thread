//! `domain::vocab` — shared visibility and moderation labels (ADR-0131).
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: []
//! Invariants: [closed variant sets and stable database labels]
//! Spec: Baseline §6.1.1; §12; §78.2

/// The three intra-tenant visibility classes (§6.1.1), frozen closed set — no `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisibilityClass {
    /// Visible only to one specific user.
    UserPrivate,
    /// Visible to members of one specific workspace.
    WorkspaceShared,
    /// Visible tenant-wide.
    TenantShared,
}

/// Public-claim moderation closed set, derived from the §12 Quarantine/Promotion flow
/// (spec:2846-2852): `PUBLIC_STAGING -> trust evaluation -> ... -> supported claim ->
/// public searchable`, with "高风险/新 contributor 可以进入审核" as the review branch,
/// quarantine as the poisoning-check failure branch, and §13 revocation as the terminal
/// withdrawal. The spec freezes the flow, not a token list — this enum is that flow's
/// state set, one variant per distinguishable stage (DOD-053: "poisoning/quarantine
/// 状态可见").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModerationState {
    /// Entry state of every contribution (spec:2846 flow head).
    PublicStaging,
    /// Review branch for high-risk/new contributors (spec:2851-2852).
    UnderReview,
    /// Passed trust evaluation + poisoning/anomaly checks; publicly searchable.
    Supported,
    /// Failed poisoning/anomaly checks; held out of public retrieval.
    Quarantined,
    /// §13: the underlying release was revoked.
    Revoked,
}

impl ModerationState {
    /// All variants, declaration order (§78.2 contract-test iteration source).
    pub const ALL: [ModerationState; 5] = [
        ModerationState::PublicStaging,
        ModerationState::UnderReview,
        ModerationState::Supported,
        ModerationState::Quarantined,
        ModerationState::Revoked,
    ];

    /// SCREAMING_SNAKE wire form (migration CHECK literal for `moderation_state`).
    pub const fn as_db_str(self) -> &'static str {
        match self {
            ModerationState::PublicStaging => "PUBLIC_STAGING",
            ModerationState::UnderReview => "UNDER_REVIEW",
            ModerationState::Supported => "SUPPORTED",
            ModerationState::Quarantined => "QUARANTINED",
            ModerationState::Revoked => "REVOKED",
        }
    }
}

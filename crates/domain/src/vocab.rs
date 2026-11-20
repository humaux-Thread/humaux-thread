//! `domain::vocab` — shared cache, retrieval, visibility and moderation labels (ADR-0131).
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: [cache::bounded, gateway::cached_embedding, retrieval::request, telemetry::metrics]
//! Invariants: [closed variant sets and stable wire and database labels]
//! Spec: Baseline §6.1.1; §12; §41.2; §51; §78.2

/// A named cache instance; the `cache` label (§41.2). One value per cache the process runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheName {
    /// Query-embedding cache in the gateway (M12 design D2).
    EmbedQuery,
}

impl CacheName {
    /// Every variant, in label order.
    pub const ALL: [Self; 1] = [Self::EmbedQuery];

    /// The `cache` label value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmbedQuery => "embed_query",
        }
    }
}

/// How one cache lookup ended (§41.2 `result` label; §51.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheResult {
    /// Served from the cache (including a caller that joined an in-flight compute).
    Hit,
    /// Computed by this caller and admitted.
    Miss,
    /// Computed but not admitted: cache disabled, zero capacity or tenant over its byte cap.
    Bypass,
    /// The compute failed or the cache itself faulted; nothing was cached and the request went on.
    Error,
}

impl CacheResult {
    /// Every variant, in label order.
    pub const ALL: [Self; 4] = [Self::Hit, Self::Miss, Self::Bypass, Self::Error];

    /// The `result` label value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
            Self::Bypass => "bypass",
            Self::Error => "error",
        }
    }
}

/// Why an entry left the cache (§41.2 `cause` label); mirrors moka's removal causes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionCause {
    /// Time-to-live elapsed.
    Expired,
    /// Removed by an explicit invalidation.
    Explicit,
    /// Overwritten by a newer value for the same key.
    Replaced,
    /// Evicted to stay under the byte capacity.
    Size,
}

impl EvictionCause {
    /// Every variant, in label order.
    pub const ALL: [Self; 4] = [Self::Expired, Self::Explicit, Self::Replaced, Self::Size];

    /// The `cause` label value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::Explicit => "explicit",
            Self::Replaced => "replaced",
            Self::Size => "size",
        }
    }
}

/// §41.2 `humaux_retrieval_requests_total.intent`: a closed label for the request constructor (ADR-0061 D-C).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentKind {
    /// The Text request intent.
    Text,
    /// The Context request intent.
    Context,
    /// The DirectGet request intent.
    DirectGet,
    /// The MemoryEnumerate request intent.
    MemoryEnumerate,
}

impl IntentKind {
    /// Every value, in render order; the label's cardinality bound (ADR-0061 D-A).
    pub const ALL: [Self; 4] = [
        Self::Text,
        Self::Context,
        Self::DirectGet,
        Self::MemoryEnumerate,
    ];

    /// The `intent` label value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Context => "context",
            Self::DirectGet => "direct_get",
            Self::MemoryEnumerate => "memory_enumerate",
        }
    }
}

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

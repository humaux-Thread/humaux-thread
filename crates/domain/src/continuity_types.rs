//! `domain::continuity_types` — Published source-backed facet vocabulary.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[domain::error]
//! Called-by: [adapters::project_rollup]
//! Invariants: [15 source-backed facets in stable declaration order with exact storage labels]
//! Spec: Baseline §25.3.1; ADR-0131

use crate::error::ErrorCode;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContinuityFacetKind {
    Goal,
    CurrentState,
    Decisions,
    Rejections,
    Constraints,
    KnownIssues,
    NextActions,
    ActiveTasks,
    RecentChanges,
    Code,
    Tests,
    Config,
    Migrations,
    Procedures,
    Outcomes,
}

impl ContinuityFacetKind {
    pub const ALL: [Self; 15] = [
        Self::Goal,
        Self::CurrentState,
        Self::Decisions,
        Self::Rejections,
        Self::Constraints,
        Self::KnownIssues,
        Self::NextActions,
        Self::ActiveTasks,
        Self::RecentChanges,
        Self::Code,
        Self::Tests,
        Self::Config,
        Self::Migrations,
        Self::Procedures,
        Self::Outcomes,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Goal => "GOAL",
            Self::CurrentState => "CURRENT_STATE",
            Self::Decisions => "DECISIONS",
            Self::Rejections => "REJECTIONS",
            Self::Constraints => "CONSTRAINTS",
            Self::KnownIssues => "KNOWN_ISSUES",
            Self::NextActions => "NEXT_ACTIONS",
            Self::ActiveTasks => "ACTIVE_TASKS",
            Self::RecentChanges => "RECENT_CHANGES",
            Self::Code => "CODE",
            Self::Tests => "TESTS",
            Self::Config => "CONFIG",
            Self::Migrations => "MIGRATIONS",
            Self::Procedures => "PROCEDURES",
            Self::Outcomes => "OUTCOMES",
        }
    }
}

impl FromStr for ContinuityFacetKind {
    type Err = ErrorCode;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.as_str() == value)
            .ok_or(ErrorCode::InvalidInput)
    }
}

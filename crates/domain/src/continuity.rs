//! `domain::continuity` — Project Continuity W1 identities and the facet publication contract (§25.3.1).
//! Depends-on: crates=[uuid]; services=[]; env=[]; modules=[domain::error]
//! Called-by: [adapters::attribution_repo, adapters::continuity_read, adapters::continuity_repo, adapters::coord_task_repo, adapters::coord_tree_repo, adapters::exact_census, adapters::operation_receipt, adapters::remember, application::continuity, application::remember, domain::attribution, gateway::continuity, gateway::guard, gateway::mcp_application, tests]
//! Invariants: []
//! Spec: Baseline §25.3.1

pub use crate::continuity_types::ContinuityFacetKind;
use crate::error::ErrorCode;
pub use crate::ids::ProjectId;
#[cfg(test)]
use std::str::FromStr;
use uuid::Uuid;

macro_rules! continuity_uuid_v7 {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(pub Uuid);

        #[allow(clippy::new_without_default)]
        impl $name {
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            pub fn parse(value: &str) -> Result<Self, ErrorCode> {
                let id = Uuid::parse_str(value).map_err(|_| ErrorCode::InvalidInput)?;
                if id.get_version_num() != 7 {
                    return Err(ErrorCode::InvalidInput);
                }
                Ok(Self(id))
            }
        }
    };
}

continuity_uuid_v7!(ContinuityFacetVersionId);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinuityPublishState {
    Current,
    Conflicted,
}

impl ContinuityPublishState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Current => "CURRENT",
            Self::Conflicted => "CONFLICTED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuityPublishResult {
    pub facet_version_id: ContinuityFacetVersionId,
    pub facet_version: i64,
    pub slot_version: i64,
    pub body_sha256: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_ids_are_v7_and_reject_other_versions() {
        let id = ProjectId::new();
        assert_eq!(id.0.get_version_num(), 7);
        assert_eq!(ProjectId::parse(&id.0.to_string()), Ok(id));
        assert_eq!(
            ProjectId::parse("550e8400-e29b-41d4-a716-446655440000"),
            Err(ErrorCode::InvalidInput)
        );
    }

    #[test]
    fn source_backed_facet_census_is_exact_and_closed() {
        assert_eq!(ContinuityFacetKind::ALL.len(), 15);
        assert_eq!(
            ContinuityFacetKind::from_str("GOAL"),
            Ok(ContinuityFacetKind::Goal)
        );
        assert!(ContinuityFacetKind::from_str("HANDOFF").is_err());
        assert!(ContinuityFacetKind::from_str("COVERAGE").is_err());
    }
}

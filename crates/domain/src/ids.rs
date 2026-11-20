//! `domain::ids` — shared UUIDv7 newtype ids and `Scope` (§25.3.1; §59 core Rust types; id policy §49).
//! Depends-on: crates=[uuid]; services=[]; env=[]; modules=[domain::error]
//! Called-by: [adapters::affect_repo, adapters::attribution_repo, adapters::billing_processor_repo, adapters::byok, adapters::confirm_token_repo, adapters::consolidate_repo, adapters::context_repo, adapters::continuity_read, adapters::continuity_repo, adapters::contribution_eligibility, adapters::contribution_entry_repo, adapters::contribution_reasoner, adapters::contribution_repo, adapters::coord_repo, adapters::coord_task_repo, adapters::credential_repo, adapters::distill_repo, adapters::egress_policy, adapters::entitlement_repo, adapters::evidence_repo, adapters::exact_census, adapters::grep_repo, adapters::login_repo, adapters::membership_repo, adapters::memory_governance_repo, adapters::oauth_repo, adapters::operation_receipt, adapters::placement_repo, adapters::private_projection_registry, adapters::processing_status, adapters::project_rollup, adapters::projection_worker, adapters::provider_budget, adapters::provisioning, adapters::qdrant, adapters::quota_repo, adapters::read_gate, adapters::read_materialize, adapters::rebuild, adapters::remember, adapters::request_guard_repo, adapters::retrieval_provisioning, adapters::retrieval_query_source, adapters::retrieve, adapters::session_repo, adapters::structured_reasoning, application::api_key, application::auth, application::billing_process, application::confirm, application::continuity, application::coordination, application::correct, application::distill, application::entitlement, application::independent_audit, application::lifecycle_execution, application::login, application::membership_admin, application::notify, application::oauth, application::oauth_exchange, application::pin, application::processing_status, application::projection_maintenance, application::public_dispatch, application::recall_read, application::referral, application::remember, application::retrieval_embedding_port, application::session, billing-worker::creem_egress, billing-worker::normalize, cache::bounded, cache::key, domain::audit, domain::audit::write_view, domain::audit_types, domain::authority, domain::context, domain::egress, domain::identity, domain::policy, gateway::auth, gateway::bootstrap, gateway::context, gateway::continuity, gateway::guard, gateway::mcp_application, gateway::memory, gateway::recall, gateway::remember, maintenance::main, maintenance::member, maintenance::projection_serve, maintenance::serve, projection::card, projection::dense, projection::serving, projection::stream, public-pool::notice, public-pool::public_projection, public-pool::public_provenance, public-pool::public_repo, public-worker::main, retrieval-provider::adapters, retrieval-provider::admission, retrieval-provider::contract, retrieval-provider::router, retrieval-worker::rpc, tests, xtask::e2e_seed, xtask::soak]
//! Invariants: []
//! Spec: Baseline §49; §52; §52.1
//!
//! §49 freezes: all three layers (Evidence/Memory/Projection) mint new objects as UUIDv7
//! (native PostgreSQL 18) only; legacy ids do not participate in this module — they only
//! surface as `remember()`'s idempotency_key, landing in the `source.legacy_id` field
//! (queryable/reconcilable, never part of any join). This module therefore exposes exactly
//! two entry points, "mint a new id" and "parse an existing string" — no legacy uuid5/hash
//! formula compatibility (that formula retired with §49; no golden test may keep it alive).

use crate::error::ErrorCode;
use uuid::Uuid;

/// Generates the seven §59 UUID newtype ids: each wraps one `Uuid`, `new` goes through the
/// UUIDv7 minting entry point (§49: new objects are always UUIDv7), `parse` parses an
/// existing string (no legacy-formula compatibility).
macro_rules! uuid_newtype {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(pub Uuid);

        // clippy suggests forwarding `Default` to `new()`; deliberately omitted:
        // `Default::default()` reads to callers as "deterministic/zero value", but here it
        // would silently mint a fresh random id — a bigger trap than one extra `::new()` call.
        #[allow(clippy::new_without_default)]
        impl $name {
            /// Mints a new id (UUIDv7, §49).
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Parses an existing UUID string. Does not recognize the retired legacy
            /// uuid5/hash formula (§49). A malformed input is `INVALID_INPUT` by definition
            /// (§52.1) — the sole terminal error set, per §52's "only two error enums" rule.
            pub fn parse(s: &str) -> Result<Self, ErrorCode> {
                Uuid::parse_str(s)
                    .map(Self)
                    .map_err(|_| ErrorCode::InvalidInput)
            }
        }
    };
}

uuid_newtype!(
    TenantId,
    "Tenant id (§59 `Scope` top-level required field)."
);
uuid_newtype!(UserId, "User id (§59 `Scope`).");
uuid_newtype!(WorkspaceId, "Workspace id (§59 `Scope`).");
uuid_newtype!(RepositoryId, "Repository id (§59 `Scope`).");
uuid_newtype!(TaskId, "Task id (§59 `Scope`).");
uuid_newtype!(RunId, "Run id (§59 `Scope`).");
uuid_newtype!(AgentId, "Agent id (§59 `Scope`).");

/// Project Continuity identifier (§25.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProjectId(pub Uuid);

#[allow(clippy::new_without_default)]
impl ProjectId {
    /// Mints a new project identifier (UUIDv7).
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Parses an existing project identifier.
    ///
    /// # Errors
    /// Returns `InvalidInput` for malformed UUIDs and versions other than v7.
    pub fn parse(value: &str) -> Result<Self, ErrorCode> {
        let id = Uuid::parse_str(value).map_err(|_| ErrorCode::InvalidInput)?;
        if id.get_version_num() != 7 {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self(id))
    }
}

/// Request scope (§59): `tenant_id` is required, the rest narrow progressively by call
/// layer. Which layer it narrows to is filled in by the caller (HTTP/MCP adapter) — Domain
/// itself never derives it.
#[derive(Debug, Clone)]
pub struct Scope {
    /// Required: all adjudication and retrieval happens within the tenant boundary
    /// (§59.1 I6 — cross-tenant Evidence must never have its authority raised).
    pub tenant_id: TenantId,
    /// User layer, if narrowed to it (§59).
    pub user_id: Option<UserId>,
    /// Workspace layer, if narrowed to it (§59).
    pub workspace_id: Option<WorkspaceId>,
    /// Repository layer, if narrowed to it (§59).
    pub repository_id: Option<RepositoryId>,
    /// Task layer, if narrowed to it (§59).
    pub task_id: Option<TaskId>,
    /// Run layer, if narrowed to it (§59).
    pub run_id: Option<RunId>,
    /// Agent layer, if narrowed to it (§59).
    pub agent_id: Option<AgentId>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_ids_round_trip_through_parse() {
        let id = TenantId::new();
        let parsed = TenantId::parse(&id.0.to_string()).expect("valid uuid string parses");
        assert_eq!(id, parsed);
    }

    #[test]
    fn new_ids_are_v7() {
        // §49: new objects are always UUIDv7 — the version bits must read 7.
        assert_eq!(RunId::new().0.get_version_num(), 7);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(AgentId::parse("not-a-uuid").is_err());
    }

    #[test]
    fn parse_error_is_invalid_input() {
        // §52.1: a malformed id string is INVALID_INPUT, not a leaked `uuid::Error` (§52).
        assert_eq!(
            AgentId::parse("not-a-uuid").unwrap_err(),
            crate::error::ErrorCode::InvalidInput
        );
    }
}

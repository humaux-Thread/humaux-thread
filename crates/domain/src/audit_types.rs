//! `domain::audit_types` — shared security audit and disclosure vocabulary (§7.4, §77).
//! Depends-on: crates=[uuid]; services=[]; env=[]; modules=[domain::error, domain::ids]
//! Called-by: []
//! Invariants: [§78.2 closed audit actions and disclosure outcomes]
//! Spec: §7.4; §77; §78.2; ADR-0130

use crate::error::ErrorCode;
use crate::ids::TenantId;
use uuid::Uuid;

/// Audit event id (§77 `event_id`).
///
/// Minted locally rather than folded into `domain::ids`'s frozen seven (§59): this task's
/// assigned file is `crates/domain/src/audit.rs` only, and `AuditEventId` is not among that
/// fixed list. Mint/parse shape hand-matches `ids::uuid_newtype!` (private to `ids.rs`,
/// exporting it is outside this task's file scope) — same deviation already taken by
/// `domain::identity::PrincipalId` and `domain::authority`'s `MemoryId`/`EvidenceId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditEventId(pub Uuid);

#[allow(clippy::new_without_default)] // see ids::uuid_newtype!'s identical note
impl AuditEventId {
    /// Mints a new id (UUIDv7, §49).
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Parses an existing UUID string; a malformed input is `INVALID_INPUT` (§52.1).
    pub fn parse(s: &str) -> Result<Self, ErrorCode> {
        Uuid::parse_str(s)
            .map(Self)
            .map_err(|_| ErrorCode::InvalidInput)
    }
}

/// Reserved system tenant for a §77 security event that cannot be resolved to a real tenant
/// (e.g. a failed `MCP_AUTH_LOGIN` — the ten listed events include failed authentications,
/// which by definition have no established tenant identity). `control.audit_events.tenant_id`
/// is `NOT NULL` with an FK to `control.tenants`, so such an event needs *some* row to point
/// at; this is the nil UUID, matching the reserved `control.tenants` row the audit-hardening
/// migration seeds for it (`migrations/0041_audit_hardening.sql`). Single canonical constant
/// so no call site re-invents the sentinel (repo `CLAUDE.md` "唯一构造点模式" spirit); a
/// protocol-constant-shaped value, not hardcoded business config (§78.1 allows this class).
pub const SYSTEM_TENANT_ID: TenantId = TenantId(Uuid::nil());

/// §77 "MCP Security Audit Events" — the events MCP integration "至少记录" (closed set,
/// unlike the general `AuditEvent.action` string field above).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpAuditAction {
    McpGrantCreated,
    McpGrantRefreshed,
    McpGrantRevoked,
    McpScopeDenied,
    McpTenantBoundaryDenied,
    McpQuotaReserved,
    McpQuotaConsumed,
    McpQuotaReleased,
    McpClientRegistered,
    McpAuthLogin,
    McpRequestDenied,
    McpRequestFinished,
    McpRequestOutcomeUnknown,
}

impl McpAuditAction {
    /// All variants, §77 listing order.
    pub const ALL: [McpAuditAction; 13] = [
        McpAuditAction::McpGrantCreated,
        McpAuditAction::McpGrantRefreshed,
        McpAuditAction::McpGrantRevoked,
        McpAuditAction::McpScopeDenied,
        McpAuditAction::McpTenantBoundaryDenied,
        McpAuditAction::McpQuotaReserved,
        McpAuditAction::McpQuotaConsumed,
        McpAuditAction::McpQuotaReleased,
        McpAuditAction::McpClientRegistered,
        McpAuditAction::McpAuthLogin,
        McpAuditAction::McpRequestDenied,
        McpAuditAction::McpRequestFinished,
        McpAuditAction::McpRequestOutcomeUnknown,
    ];

    /// SCREAMING_SNAKE wire form — the value this variant is written into
    /// `AuditEvent.action` as (§77 lists these as literal event names).
    pub const fn as_str(self) -> &'static str {
        match self {
            McpAuditAction::McpGrantCreated => "MCP_GRANT_CREATED",
            McpAuditAction::McpGrantRefreshed => "MCP_GRANT_REFRESHED",
            McpAuditAction::McpGrantRevoked => "MCP_GRANT_REVOKED",
            McpAuditAction::McpScopeDenied => "MCP_SCOPE_DENIED",
            McpAuditAction::McpTenantBoundaryDenied => "MCP_TENANT_BOUNDARY_DENIED",
            McpAuditAction::McpQuotaReserved => "MCP_QUOTA_RESERVED",
            McpAuditAction::McpQuotaConsumed => "MCP_QUOTA_CONSUMED",
            McpAuditAction::McpQuotaReleased => "MCP_QUOTA_RELEASED",
            McpAuditAction::McpClientRegistered => "MCP_CLIENT_REGISTERED",
            McpAuditAction::McpAuthLogin => "MCP_AUTH_LOGIN",
            McpAuditAction::McpRequestDenied => "MCP_REQUEST_DENIED",
            McpAuditAction::McpRequestFinished => "MCP_REQUEST_FINISHED",
            McpAuditAction::McpRequestOutcomeUnknown => "MCP_REQUEST_OUTCOME_UNKNOWN",
        }
    }
}

/// §7.4 `outcome` — the three-way finalize() result, verbatim the `ops.data_disclosures`
/// CHECK literals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisclosureOutcome {
    Success,
    Failed,
    Denied,
}

impl DisclosureOutcome {
    /// Every outcome; `adapters::health` maps the DB literal back through it (§78.2 fail-closed).
    pub const ALL: [Self; 3] = [Self::Success, Self::Failed, Self::Denied];

    /// Database and wire literal for this outcome (§7.4).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "SUCCESS",
            Self::Failed => "FAILED",
            Self::Denied => "DENIED",
        }
    }
}

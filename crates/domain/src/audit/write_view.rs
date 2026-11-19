//! `domain::audit::write_view` — Identity Access inputs for §77 audit persistence.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[domain::audit_types, domain::ids]
//! Called-by: [adapters::confirm_token_repo, adapters::memory_governance_repo, adapters::request_guard_repo, application::auth, domain::audit]
//! Invariants: [only the audit owner can populate nonempty metadata]
//! Spec: Baseline §77

use std::borrow::Cow;

use crate::audit_types::AuditEventId;
use crate::ids::TenantId;

/// Read-only metadata whose nonempty entries have passed the owner's allowlist.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditMetadataView {
    pub(super) entries: Vec<(String, String)>,
}

impl AuditMetadataView {
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&str, &str)> {
        self.entries
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }
}

/// The §77 field set accepted by the audit writer in the caller's transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditWriteEvent {
    pub event_id: AuditEventId,
    pub ts: std::time::SystemTime,
    pub tenant_id: TenantId,
    pub actor_type: String,
    pub actor_id: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub result: String,
    pub request_id: String,
    pub trace_id: String,
    pub client_ip: String,
    pub user_agent_hash: String,
    pub risk_tags: Vec<String>,
    /// §77 `before_fingerprint?` — absent when the action has no prior-state comparison
    /// (e.g. a create).
    pub before_fingerprint: Option<String>,
    /// §77 `after_fingerprint?` — absent when the action has no resulting-state comparison
    /// (e.g. a delete/revoke read back as "gone").
    pub after_fingerprint: Option<String>,
    pub metadata: AuditMetadataView,
}

/// Projects an event into the writer's input without exposing the owner's domain type.
pub trait AuditWriteSource {
    fn audit_write_event(&self) -> Cow<'_, AuditWriteEvent>;
}

impl AuditWriteSource for AuditWriteEvent {
    fn audit_write_event(&self) -> Cow<'_, AuditWriteEvent> {
        Cow::Borrowed(self)
    }
}

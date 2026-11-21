//! `application::read_quota` — Commercial read charging from the effective entitlement projection (§72.2.1, §76).
//! Depends-on: crates=[async-trait, humaux-domain, serde_json, time]; services=[]; env=[]; modules=[domain::error, domain::identity]
//! Called-by: [adapters::audited_read_quota, adapters::entitlement_repo, gateway::bootstrap, gateway::guard, tests]
//! Invariants: [each quota transition and its audit share a commit; the projection clock comes from the database]
//! Spec: Baseline §72.2.1; §77; ADR-0130 D2/D5

use humaux_domain::{error::ErrorCode, identity::AuthorizationScope};
use std::time::Duration;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

/// Feature key of the projected BMO entitlement.
pub const BMO_ENTITLEMENT: &str = "mcp.billable_operations.per_period";

/// Commercial admission decision for one authorized OAuth candidate tenant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McpEntitlement {
    /// The effective BMO policy permits the connection.
    Enabled,
    /// The tenant has no currently valid BMO entitlement.
    EntitlementRequired,
}

/// Projected terms and the database times observed together with them (§76).
pub struct QuotaPolicyFacts {
    /// Effective projection, including a successor active at observation time.
    pub effective: serde_json::Value,
    /// Projection computation time.
    pub computed_at: OffsetDateTime,
    /// Clock sampled by the projection read.
    pub observed_at: OffsetDateTime,
}

/// An opaque reservation whose lease bounds the handler deadline.
pub trait ReservationLease: Send + Sync {
    /// Database-computed duration capped at the period boundary.
    fn valid_for(&self) -> Duration;
}

/// Persistence operations for §72.2.1 reads. The adapter binds the audit envelope.
#[async_trait::async_trait]
pub trait ReadQuotaStore: Send + Sync {
    /// Request audit supplied by the authenticated entry.
    type Audit: Sync;
    /// Only the store can issue the handle accepted at settlement.
    type Reservation: ReservationLease;
    /// Read the effective snapshot and database clock together.
    async fn policy_facts(&self, auth: &AuthorizationScope) -> Result<QuotaPolicyFacts, ErrorCode>;
    /// Persist a reservation and its reserved audit in one transaction.
    async fn reserve(
        &self,
        auth: &AuthorizationScope,
        operation: &str,
        fingerprint: &str,
        ttl: Duration,
        audit: &Self::Audit,
    ) -> Result<Self::Reservation, ErrorCode>;
    /// Commit the terminal transition and its required audits atomically.
    async fn settle(
        &self,
        auth: &AuthorizationScope,
        reservation: Option<&Self::Reservation>,
        consume: bool,
        audit: &Self::Audit,
    ) -> Result<bool, ErrorCode>;
}

/// Select the billing rule after reading this caller's projected facts.
pub async fn charge_policy_for(
    store: &impl ReadQuotaStore,
    auth: &AuthorizationScope,
    feature: &str,
) -> Result<ChargePolicy, ErrorCode> {
    quota_policy(&store.policy_facts(auth).await?, feature)
}

/// Reserve one BMO before a metered read (§72.2.1).
pub async fn reserve_read<S: ReadQuotaStore>(
    store: &S,
    auth: &AuthorizationScope,
    operation: &str,
    fingerprint: &str,
    ttl: Duration,
    audit: &S::Audit,
) -> Result<S::Reservation, ErrorCode> {
    store
        .reserve(auth, operation, fingerprint, ttl, audit)
        .await
}

/// Finish a read and its audit, returning the store's actual settlement outcome.
pub async fn settle_read<S: ReadQuotaStore>(
    store: &S,
    auth: &AuthorizationScope,
    reservation: Option<&S::Reservation>,
    consume: bool,
    audit: &S::Audit,
) -> Result<bool, ErrorCode> {
    store.settle(auth, reservation, consume, audit).await
}

/// §72.2.1 billing rule from the effective projected entitlement.
pub enum ChargePolicy {
    /// Only successful reads consume capacity.
    SuccessOnly,
    /// Includes the specified completed business failures.
    CompletedBusinessCalls,
}

impl ChargePolicy {
    /// Whether the completed handler result consumes its reservation.
    pub fn consumes<T>(&self, result: &Result<T, ErrorCode>) -> bool {
        result.is_ok()
            || (matches!(self, Self::CompletedBusinessCalls)
                && matches!(
                    result,
                    Err(ErrorCode::NotFound
                        | ErrorCode::Conflict
                        | ErrorCode::ProjectionLag
                        | ErrorCode::CannotEstablishCompleteness)
                ))
    }
}

/// Select the charge policy from already observed projection facts.
pub fn quota_policy(facts: &QuotaPolicyFacts, feature: &str) -> Result<ChargePolicy, ErrorCode> {
    if feature != BMO_ENTITLEMENT {
        return Err(ErrorCode::Internal);
    }
    let policy = facts
        .effective
        .get(feature)
        .and_then(|v| v.as_object())
        .ok_or(ErrorCode::EntitlementRequired)?;
    if policy
        .get("limit")
        .and_then(|v| v.as_u64())
        .is_none_or(|n| n > i64::MAX as u64)
        || !matches!(
            policy.get("period").and_then(|v| v.as_str()),
            Some("calendar_month" | "subscription_period")
        )
    {
        return Err(ErrorCode::EntitlementRequired);
    }
    let parse = |key| {
        policy
            .get(key)
            .and_then(|v| v.as_str())
            .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
            .ok_or(ErrorCode::EntitlementRequired)
    };
    let start = parse("period_start")?;
    let end = parse("period_end")?;
    if start >= end
        || facts.observed_at < start
        || facts.observed_at >= end
        || facts.computed_at > facts.observed_at
    {
        return Err(ErrorCode::EntitlementRequired);
    }
    match policy.get("charge_policy").and_then(|v| v.as_str()) {
        Some("success_only") => Ok(ChargePolicy::SuccessOnly),
        Some("completed_business_calls") => Ok(ChargePolicy::CompletedBusinessCalls),
        _ => Err(ErrorCode::EntitlementRequired),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn snapshot() -> QuotaPolicyFacts {
        let observed_at = OffsetDateTime::parse("2026-08-28T00:00:00Z", &Rfc3339).unwrap();
        QuotaPolicyFacts {
            effective: json!({BMO_ENTITLEMENT: {
                "limit": 50,
                "period": "subscription_period",
                "period_start": "2026-08-28T00:00:00Z",
                "period_end": "2026-09-28T00:00:00Z",
                "charge_policy": "success_only"
            }}),
            computed_at: observed_at,
            observed_at,
        }
    }

    #[test]
    fn entitlement_uses_projected_period_and_database_observation_time() {
        let mut facts = snapshot();
        assert!(quota_policy(&facts, BMO_ENTITLEMENT).is_ok());
        facts.computed_at += time::Duration::seconds(1);
        assert!(matches!(
            quota_policy(&facts, BMO_ENTITLEMENT),
            Err(ErrorCode::EntitlementRequired)
        ));
        facts = snapshot();
        facts.observed_at = OffsetDateTime::parse("2026-09-28T00:00:00Z", &Rfc3339).unwrap();
        assert!(matches!(
            quota_policy(&facts, BMO_ENTITLEMENT),
            Err(ErrorCode::EntitlementRequired)
        ));
        facts = snapshot();
        facts.effective[BMO_ENTITLEMENT] = json!(50);
        assert!(matches!(
            quota_policy(&facts, BMO_ENTITLEMENT),
            Err(ErrorCode::EntitlementRequired)
        ));
    }

    #[test]
    fn charge_policy_does_not_bill_infrastructure_or_authorization_failures() {
        let ok: Result<(), ErrorCode> = Ok(());
        assert!(ChargePolicy::SuccessOnly.consumes(&ok));
        assert!(!ChargePolicy::SuccessOnly.consumes(&Err::<(), _>(ErrorCode::NotFound)));
        assert!(ChargePolicy::CompletedBusinessCalls.consumes(&Err::<(), _>(ErrorCode::NotFound)));
        for code in [
            ErrorCode::Unauthorized,
            ErrorCode::InvalidInput,
            ErrorCode::Internal,
            ErrorCode::DependencyUnavailable,
        ] {
            assert!(!ChargePolicy::CompletedBusinessCalls.consumes(&Err::<(), _>(code)));
        }
    }
}

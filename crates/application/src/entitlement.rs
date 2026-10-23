//! `application::entitlement` — H5: §76 Entitlement Projector（Phase 2 wave 实现；判据出处见 spec 家章）.
//! Depends-on: crates=[humaux-domain, serde_json]; services=[]; env=[]; modules=[domain::ids, domain::plan]
//! Called-by: [adapters::entitlement_repo]
//! Invariants: [project is the only constructor of EntitlementSnapshot; carry_period_boundaries only rewrites the
//!   per-period window boundaries of a snapshot project built, from the snapshot it replaces, so a recompute never moves
//!   a window the renewal door has already advanced (§72.2.1)]
//! Spec: §76; §72.2.1
//!
//! §76 pipeline: Payment/Subscription feeds Base Entitlements, joined by Promotion/Coupon,
//! Referral Reward, and Manual Admin Grant; all four flow into one Effective Entitlement
//! Snapshot, which alone feeds Quota Window / Request Authorization.
//!
//! **Frozen (§76, rustdoc-enforced):** "运行时不读取散落的 coupon/referral 表计算权限" —
//! the *only* legitimate output of this module for an authorization/quota decision is
//! [`EntitlementSnapshot`], produced by [`project`]. There is no function here that answers
//! "what does grant X say" or "what is tenant Y's raw referral-reward-derived grant" in
//! isolation — [`EntitlementGrant`] exists only as `project`'s input type, never as
//! something a request-authorization code path queries directly. Any future authz/quota
//! module that imports `EntitlementGrant` (or reaches past this module into
//! `control.referral_rewards`/`control.credit_ledger`/a coupon table) to decide a live
//! request is violating this freeze — the fix is always "call [`project`] and read the
//! snapshot", never "add a second read path". Enforced at compile time only within this
//! crate: `crates/application` has no SQLx dependency at all (see this crate's `Cargo.toml`
//! — Phase 2 identity/entitlement modules are pure logic, not database-bound), so no
//! runtime code that could touch those raw tables exists in this crate to begin with; the
//! rule this comment freezes is for whichever adapter crate wires persistence later.

use humaux_domain::ids::TenantId;
use humaux_domain::plan::EntitlementKey;
use std::collections::BTreeMap;
use std::time::SystemTime;

/// §76: `source = PLAN | PROMOTION | REFERRAL | ADMIN | TRIAL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantSource {
    Plan,
    Promotion,
    Referral,
    Admin,
    Trial,
}

impl GrantSource {
    /// Every source, in the order of `control.entitlement_grants`' `source` CHECK; reconciled with it by contract test
    /// (§78.2).
    pub const ALL: [GrantSource; 5] = [
        Self::Plan,
        Self::Promotion,
        Self::Referral,
        Self::Admin,
        Self::Trial,
    ];

    /// The source a `control.entitlement_grants.source` value spells, or `None` for any other text.
    pub fn from_db_str(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|source| source.as_str() == text)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plan => "PLAN",
            Self::Promotion => "PROMOTION",
            Self::Referral => "REFERRAL",
            Self::Admin => "ADMIN",
            Self::Trial => "TRIAL",
        }
    }
}

/// One `control.entitlement_grants` row — §76's raw per-source fact, [`project`]'s only
/// input type. Deliberately not `pub` outside constructing a `Vec<EntitlementGrant>` to
/// hand to `project`: nothing in this module reads a single grant's `value` directly as an
/// authorization answer (see the module freeze note above).
#[derive(Debug, Clone)]
pub struct EntitlementGrant {
    pub grant_id: String,
    pub tenant_id: TenantId,
    pub source: GrantSource,
    pub feature: String,
    pub value: serde_json::Value,
    pub valid_from: SystemTime,
    pub valid_until: Option<SystemTime>,
    pub priority: i32,
    pub revoked_at: Option<SystemTime>,
}

impl EntitlementGrant {
    /// A grant is active exactly when: not revoked, `now` is within
    /// `[valid_from, valid_until)` (`valid_until = None` means no expiry). Half-open on the
    /// upper bound so a grant expiring at exactly `now` has already lapsed — matches
    /// `[valid_from, valid_until)` interval-membership convention used elsewhere in this
    /// workspace (temporal filtering, §9).
    fn is_active_at(&self, now: SystemTime) -> bool {
        self.revoked_at.is_none()
            && self.valid_from <= now
            && self.valid_until.is_none_or(|until| now < until)
    }
}

/// §76 Effective Entitlement Snapshot — the sole read surface for Quota Window / Request
/// Authorization (`migrations/0033_entitlement_projector.sql`'s `control.
/// entitlement_snapshots`, one row per tenant). `source_grant_ids` is audit/debug metadata
/// for the Projector itself, not a second way to look a feature up — `effective` is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntitlementSnapshot {
    pub tenant_id: TenantId,
    pub effective: BTreeMap<String, serde_json::Value>,
    pub source_grant_ids: Vec<String>,
    pub computed_at: SystemTime,
}

/// §76 Entitlement Projector — the sole constructor of [`EntitlementSnapshot`] (this
/// crate's "唯一构造点" convention, repo CLAUDE.md). For each `feature` name across every
/// grant active at `now`, keeps the single winning grant: highest `priority` first, ties
/// broken by the later `valid_from` (the more-recently-granted entitlement wins a same-
/// priority tie — deterministic and documented here, not left to iteration order).
///
/// Grants belonging to a different tenant than `tenant_id` are silently skipped rather than
/// trusted from the input slice — defense in depth matching §6.1.1's "调用方永远自己 AND
/// tenant filter" discipline, even though this function's own contract already puts that
/// filtering burden on the caller.
pub fn project(
    tenant_id: TenantId,
    grants: &[EntitlementGrant],
    now: SystemTime,
) -> EntitlementSnapshot {
    let mut winners: BTreeMap<&str, &EntitlementGrant> = BTreeMap::new();

    for grant in grants {
        if grant.tenant_id != tenant_id || !grant.is_active_at(now) {
            continue;
        }
        match winners.get(grant.feature.as_str()) {
            None => {
                winners.insert(&grant.feature, grant);
            }
            Some(current) => {
                let grant_wins = grant.priority > current.priority
                    || (grant.priority == current.priority
                        && grant.valid_from > current.valid_from);
                if grant_wins {
                    winners.insert(&grant.feature, grant);
                }
            }
        }
    }

    let effective = winners
        .iter()
        .map(|(feature, grant)| (feature.to_string(), grant.value.clone()))
        .collect();
    let mut source_grant_ids: Vec<String> = winners.values().map(|g| g.grant_id.clone()).collect();
    source_grant_ids.sort();

    EntitlementSnapshot {
        tenant_id,
        effective,
        source_grant_ids,
        computed_at: now,
    }
}

/// §72.2.1: a quota window the renewal door has already issued keeps its boundaries. The per-period entitlement of
/// `snapshot` takes `period_start` / `period_end` from `current` (the stored `effective` object) when both exist there,
/// replacing whatever the winning grant carried: grants name the plan's terms, the snapshot row names where the
/// subscription period stands. A snapshot without a per-period entitlement, or no stored snapshot, is returned as is.
///
/// ponytail: the stored boundaries always win, so a recompute cannot move a period; a subscription start that must move
/// it needs its own door, not a second path through here.
pub fn carry_period_boundaries(
    mut snapshot: EntitlementSnapshot,
    current: Option<&serde_json::Value>,
) -> EntitlementSnapshot {
    let key = EntitlementKey::PerPeriod.wire();
    let stored = current
        .and_then(|effective| effective.get(key))
        .and_then(|policy| Some((policy.get("period_start")?, policy.get("period_end")?)));
    if let (Some((start, end)), Some(serde_json::Value::Object(policy))) =
        (stored, snapshot.effective.get_mut(key))
    {
        policy.insert("period_start".to_owned(), start.clone());
        policy.insert("period_end".to_owned(), end.clone());
    }
    snapshot
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    fn grant(
        tenant_id: TenantId,
        feature: &str,
        priority: i32,
        source: GrantSource,
        valid_from: SystemTime,
        valid_until: Option<SystemTime>,
    ) -> EntitlementGrant {
        EntitlementGrant {
            grant_id: format!("{feature}-{priority}-{source:?}"),
            tenant_id,
            source,
            feature: feature.to_string(),
            value: json!(true),
            valid_from,
            valid_until,
            priority,
            revoked_at: None,
        }
    }

    #[test]
    fn active_grant_appears_in_snapshot() {
        let tenant = TenantId::new();
        let now = SystemTime::now();
        let grants = vec![grant(
            tenant,
            "advanced_search",
            0,
            GrantSource::Plan,
            now - Duration::from_secs(60),
            None,
        )];
        let snapshot = project(tenant, &grants, now);
        assert_eq!(
            snapshot.effective.get("advanced_search"),
            Some(&json!(true))
        );
    }

    #[test]
    fn expired_grant_does_not_enter_snapshot() {
        let tenant = TenantId::new();
        let now = SystemTime::now();
        let grants = vec![grant(
            tenant,
            "advanced_search",
            0,
            GrantSource::Trial,
            now - Duration::from_secs(3600),
            Some(now - Duration::from_secs(60)), // valid_until already in the past
        )];
        let snapshot = project(tenant, &grants, now);
        assert!(snapshot.effective.is_empty());
    }

    #[test]
    fn not_yet_valid_grant_does_not_enter_snapshot() {
        let tenant = TenantId::new();
        let now = SystemTime::now();
        let grants = vec![grant(
            tenant,
            "beta_feature",
            0,
            GrantSource::Promotion,
            now + Duration::from_secs(60), // starts in the future
            None,
        )];
        let snapshot = project(tenant, &grants, now);
        assert!(snapshot.effective.is_empty());
    }

    #[test]
    fn revoked_grant_does_not_enter_snapshot_even_within_valid_window() {
        let tenant = TenantId::new();
        let now = SystemTime::now();
        let mut g = grant(
            tenant,
            "advanced_search",
            0,
            GrantSource::Admin,
            now - Duration::from_secs(60),
            None,
        );
        g.revoked_at = Some(now - Duration::from_secs(1));
        let snapshot = project(tenant, &[g], now);
        assert!(snapshot.effective.is_empty());
    }

    #[test]
    fn grant_expiring_exactly_at_now_is_excluded_half_open_interval() {
        let tenant = TenantId::new();
        let now = SystemTime::now();
        let grants = vec![grant(
            tenant,
            "advanced_search",
            0,
            GrantSource::Trial,
            now - Duration::from_secs(60),
            Some(now), // valid_until == now
        )];
        let snapshot = project(tenant, &grants, now);
        assert!(snapshot.effective.is_empty());
    }

    #[test]
    fn higher_priority_grant_wins_conflict() {
        let tenant = TenantId::new();
        let now = SystemTime::now();
        let base = now - Duration::from_secs(60);
        let plan_grant = grant(tenant, "seats", 0, GrantSource::Plan, base, None);
        let mut admin_override = grant(tenant, "seats", 10, GrantSource::Admin, base, None);
        admin_override.value = json!(50);
        let snapshot = project(tenant, &[plan_grant, admin_override], now);
        assert_eq!(snapshot.effective.get("seats"), Some(&json!(50)));
    }

    #[test]
    fn equal_priority_tie_broken_by_later_valid_from() {
        let tenant = TenantId::new();
        let now = SystemTime::now();
        let mut older = grant(
            tenant,
            "seats",
            0,
            GrantSource::Promotion,
            now - Duration::from_secs(120),
            None,
        );
        older.value = json!(10);
        let mut newer = grant(
            tenant,
            "seats",
            0,
            GrantSource::Promotion,
            now - Duration::from_secs(30),
            None,
        );
        newer.value = json!(20);
        let snapshot = project(tenant, &[older, newer], now);
        assert_eq!(snapshot.effective.get("seats"), Some(&json!(20)));
    }

    #[test]
    fn grant_belonging_to_a_different_tenant_is_never_projected() {
        let tenant = TenantId::new();
        let other_tenant = TenantId::new();
        let now = SystemTime::now();
        let grants = vec![grant(
            other_tenant,
            "advanced_search",
            0,
            GrantSource::Plan,
            now - Duration::from_secs(60),
            None,
        )];
        let snapshot = project(tenant, &grants, now);
        assert!(snapshot.effective.is_empty());
        assert_eq!(snapshot.tenant_id, tenant);
    }

    #[test]
    fn source_grant_ids_records_exactly_the_winning_grants() {
        let tenant = TenantId::new();
        let now = SystemTime::now();
        let base = now - Duration::from_secs(60);
        let g1 = grant(tenant, "seats", 0, GrantSource::Plan, base, None);
        let g2 = grant(tenant, "advanced_search", 0, GrantSource::Trial, base, None);
        let expected_ids = {
            let mut v = vec![g1.grant_id.clone(), g2.grant_id.clone()];
            v.sort();
            v
        };
        let snapshot = project(tenant, &[g1, g2], now);
        assert_eq!(snapshot.source_grant_ids, expected_ids);
    }

    #[test]
    fn grant_source_spellings_round_trip_and_unknown_text_is_refused() {
        let spelled: Vec<&str> = GrantSource::ALL.map(GrantSource::as_str).to_vec();
        assert_eq!(spelled, ["PLAN", "PROMOTION", "REFERRAL", "ADMIN", "TRIAL"]);
        for source in GrantSource::ALL {
            assert_eq!(GrantSource::from_db_str(source.as_str()), Some(source));
        }
        assert_eq!(GrantSource::from_db_str("plan"), None);
        assert_eq!(GrantSource::from_db_str("COUPON"), None);
    }

    fn per_period_snapshot(tenant: TenantId, policy: serde_json::Value) -> EntitlementSnapshot {
        EntitlementSnapshot {
            tenant_id: tenant,
            effective: BTreeMap::from([
                (EntitlementKey::PerPeriod.wire().to_owned(), policy),
                (EntitlementKey::Byok.wire().to_owned(), json!(true)),
            ]),
            source_grant_ids: Vec::new(),
            computed_at: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn stored_period_boundaries_replace_the_grants_and_nothing_else_moves() {
        let tenant = TenantId::new();
        let from_grant = json!({
            "limit": 7, "period": "subscription_period", "charge_policy": "success_only",
            "period_start": "2030-01-01T00:00:00.000Z", "period_end": "2030-02-01T00:00:00.000Z",
        });
        let stored = json!({ "mcp.billable_operations.per_period": {
            "limit": 1, "period_start": "2030-03-01T00:00:00.000Z", "period_end": "2030-04-01T00:00:00.000Z",
        }});
        let carried =
            carry_period_boundaries(per_period_snapshot(tenant, from_grant), Some(&stored));
        assert_eq!(
            carried.effective,
            BTreeMap::from([
                (
                    "mcp.billable_operations.per_period".to_owned(),
                    json!({
                        "limit": 7, "period": "subscription_period", "charge_policy": "success_only",
                        "period_start": "2030-03-01T00:00:00.000Z", "period_end": "2030-04-01T00:00:00.000Z",
                    })
                ),
                ("feature.byok".to_owned(), json!(true)),
            ])
        );
    }

    #[test]
    fn without_a_stored_period_the_snapshot_is_returned_unchanged() {
        let tenant = TenantId::new();
        let policy = json!({ "limit": 7, "period_start": "a", "period_end": "b" });
        let snapshot = per_period_snapshot(tenant, policy);
        assert_eq!(carry_period_boundaries(snapshot.clone(), None), snapshot);
        let half = json!({ "mcp.billable_operations.per_period": { "period_start": "x" } });
        assert_eq!(
            carry_period_boundaries(snapshot.clone(), Some(&half)),
            snapshot
        );
        let other_key = json!({ "feature.byok": true });
        assert_eq!(
            carry_period_boundaries(snapshot.clone(), Some(&other_key)),
            snapshot
        );
    }
}

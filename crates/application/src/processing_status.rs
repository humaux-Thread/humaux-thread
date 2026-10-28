//! `application::processing_status` — Per-account processing-status admission (§78.1, ADR-0110 D-E).
//! Depends-on: crates=[humaux-domain]; services=[]; env=[];
//!   modules=[domain::error, domain::identity, domain::ids]
//! Called-by: [adapters::processing_status, tests]
//! Invariants: [clock and minimum interval are supplied by the caller; no account-wide total]
//! Spec: §15.6; §78.1; §78.3; ADR-0110 D-E

use std::collections::HashMap;
use std::time::{Duration, Instant};

use humaux_domain::error::ErrorCode;
use humaux_domain::identity::AuthorizationScope;
use humaux_domain::ids::TenantId;

/// ADR-0110 D-E: behind includes failures and is never a failure count.
pub const BEHIND_LABEL: &str = "not_yet_confirmed_processed";

/// §6.1: account means the caller's tenant; workspaces come from this authorization.
pub struct ProcessingStatusQuery<'a> {
    /// The authoritative tenant and permitted workspace set.
    pub authorization: &'a AuthorizationScope,
}

/// §78.1: one admission per account per caller-configured interval.
// ponytail: single-process admission; upgrade to the gateway limiter bucket (ADR-0100).
pub struct DetailedGate {
    min_interval: Duration,
    last_admit: HashMap<TenantId, Instant>,
}

impl DetailedGate {
    /// §78.1: there is no literal or default interval; zero refuses configuration.
    pub fn new(min_interval: Duration) -> Result<Self, ErrorCode> {
        if min_interval.is_zero() {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self {
            min_interval,
            last_admit: HashMap::new(),
        })
    }

    /// §78.3: the caller supplies monotonic time; refused calls do not move admission.
    pub fn admit(&mut self, account: TenantId, now: Instant) -> Result<(), ErrorCode> {
        if self.last_admit.get(&account).is_some_and(|last| {
            now.checked_duration_since(*last)
                .is_none_or(|age| age < self.min_interval)
        }) {
            return Err(ErrorCode::RateLimited);
        }
        self.last_admit.insert(account, now);
        Ok(())
    }
}

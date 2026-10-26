//! `gateway::limiter` — In-process hierarchical token buckets (§72.3; ADR-0100).
//! Depends-on: crates=[humaux-domain, tokio, uuid]; services=[]; env=[]; modules=[domain::error]
//! Called-by: [gateway::guard, gateway::bootstrap, tests]
//! Invariants: [no PG I/O; never an allow decision beyond rate; one mutex makes tier charges atomic;
//!   buckets start at one refill-second; only fully replenished buckets may be evicted]
//! Spec: Baseline §67.2; §72.3; §73.3; §78.1; ADR-0100

use humaux_domain::error::ErrorCode;
use std::{collections::HashMap, net::IpAddr, sync::Mutex};
use tokio::time::Instant;
use uuid::Uuid;

const TOKEN: u128 = 1_000_000_000;

/// A registered tier policy (§78.1); constructor rejects nonpositive bounds.
#[derive(Clone, Copy)]
pub struct RatePolicy {
    capacity: u128,
    refill: u128,
}

impl RatePolicy {
    /// Validate the same positive integer domain as the retired PG hot path (§72.3).
    pub fn new(capacity: i64, refill_per_second: i64) -> Result<Self, ErrorCode> {
        let capacity = u128::try_from(capacity).map_err(|_| ErrorCode::InvalidInput)?;
        let refill = u128::try_from(refill_per_second).map_err(|_| ErrorCode::InvalidInput)?;
        if capacity == 0 || refill == 0 {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self {
            capacity: capacity * TOKEN,
            refill,
        })
    }
}

/// Independent tier identities; operation keys retain credential isolation (§72.3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Subject {
    /// Trusted pre-auth source, IPv6 masked by [`Self::ip`] (§73.3).
    Ip(IpAddr),
    /// Tenant and authenticated credential id.
    Credential(Uuid, Uuid),
    /// Tenant and authenticated user id.
    User(Uuid, Uuid),
    /// The account is the tenant in the single-owner deployment (ADR-0100).
    Account(Uuid),
    /// Tenant, credential and server-classified operation.
    Operation(Uuid, Uuid, String),
}

impl Subject {
    /// Mask a trusted IPv6 source to the registered prefix; IPv4 is unchanged (§73.3).
    pub fn ip(ip: IpAddr, bits: u8) -> Result<Self, ErrorCode> {
        if !(1..=128).contains(&bits) {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self::Ip(match ip {
            IpAddr::V6(ip) => IpAddr::V6((u128::from(ip) & (u128::MAX << (128 - bits))).into()),
            ip => ip,
        }))
    }

    fn tier(&self) -> usize {
        match self {
            Self::Ip(_) => 0,
            Self::Credential(..) => 1,
            Self::User(..) => 2,
            Self::Account(_) => 3,
            Self::Operation(..) => 4,
        }
    }

    /// Existing bounded telemetry label for this tier (§41.2).
    pub fn scope(&self) -> &'static str {
        ["ip", "credential", "user", "tenant", "operation"][self.tier()]
    }
}

/// A rate decision, never authorization; capacity exhaustion fails closed (§52.1).
#[derive(Debug, PartialEq, Eq)]
pub struct RateLimited {
    /// Existing terminal error, with no third error enum (§52.1).
    pub code: ErrorCode,
    /// The exact tier that denied the request, or bounded-memory capacity.
    pub scope: &'static str,
}

struct Bucket {
    credit: u128,
    updated: Instant,
}
impl Bucket {
    fn credit(&self, now: Instant, policy: RatePolicy) -> u128 {
        self.credit
            .saturating_add(
                now.duration_since(self.updated)
                    .as_nanos()
                    .saturating_mul(policy.refill),
            )
            .min(policy.capacity)
    }
}

/// One gateway's bounded limiter; a second authority is forbidden by its boot lease (ADR-0100).
pub struct Limiter {
    policies: [RatePolicy; 5],
    max_subjects: usize,
    buckets: Mutex<HashMap<Subject, Bucket>>,
}

impl Limiter {
    /// Tier order is IP / credential / user / account / operation (§72.3).
    pub fn new(policies: [RatePolicy; 5], max_subjects: usize) -> Result<Self, ErrorCode> {
        if max_subjects == 0 {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self {
            policies,
            max_subjects,
            buckets: Mutex::new(HashMap::new()),
        })
    }

    /// Atomically charge every unique tier or none. Memory pressure cannot reset an active bucket (§72.3).
    pub fn check(&self, subjects: &[Subject]) -> Result<(), RateLimited> {
        let mut buckets = self.buckets.lock().map_err(|_| RateLimited {
            code: ErrorCode::Internal,
            scope: "capacity",
        })?;
        let now = Instant::now();
        let missing = subjects
            .iter()
            .enumerate()
            .filter(|(i, s)| !buckets.contains_key(*s) && !subjects[..*i].contains(s))
            .count();
        if buckets.len().saturating_add(missing) > self.max_subjects {
            // ponytail: idle eviction scans only under pressure; shard after certified gateway CPU exceeds 70%.
            buckets.retain(|s, b| {
                b.credit(now, self.policies[s.tier()]) < self.policies[s.tier()].capacity
            });
        }
        let missing = subjects
            .iter()
            .enumerate()
            .filter(|(i, s)| !buckets.contains_key(*s) && !subjects[..*i].contains(s))
            .count();
        if buckets.len().saturating_add(missing) > self.max_subjects {
            return Err(RateLimited {
                code: ErrorCode::DependencyUnavailable,
                scope: "capacity",
            });
        }
        for subject in subjects {
            let policy = self.policies[subject.tier()];
            let credit = buckets
                .get(subject)
                .map_or(policy.refill * TOKEN, |b| b.credit(now, policy))
                .min(policy.capacity);
            if credit < TOKEN {
                return Err(RateLimited {
                    code: ErrorCode::RateLimited,
                    scope: subject.scope(),
                });
            }
        }
        for (i, subject) in subjects.iter().enumerate() {
            if subjects[..i].contains(subject) {
                continue;
            }
            let policy = self.policies[subject.tier()];
            let b = buckets.entry(subject.clone()).or_insert(Bucket {
                credit: (policy.refill * TOKEN).min(policy.capacity),
                updated: now,
            });
            b.credit = b.credit(now, policy) - TOKEN;
            b.updated = now;
        }
        Ok(())
    }
}

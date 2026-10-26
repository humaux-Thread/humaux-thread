//! `gateway::limiter` — In-process hierarchical token buckets (§72.3; ADR-0100).
//! Depends-on: crates=[humaux-domain, tokio, uuid]; services=[]; env=[]; modules=[domain::error]
//! Called-by: [gateway::guard, gateway::bootstrap, tests]
//! Invariants: [no PG I/O; never an allow decision beyond rate; one mutex makes tier charges atomic;
//!   buckets start at one refill-second; per-tier caps; at most 32 idle probes per pressured tier; only replenished buckets may be evicted]
//! Spec: Baseline §67.2; §72.3; §73.3; §78.1; ADR-0100

use humaux_domain::error::ErrorCode;
use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    sync::Mutex,
};
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
    /// ADR-0065 W-10: canonical IPv4, /128 local IPv6, registered prefix otherwise (§73.3).
    pub fn ip(ip: IpAddr, bits: u8) -> Result<Self, ErrorCode> {
        if !(1..=128).contains(&bits) {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self::Ip(match ip.to_canonical() {
            // ADR-0065 W-10 / §73.3: loopback and link-local clients retain /128 identities.
            IpAddr::V6(ip) if !ip.is_loopback() && !ip.is_unicast_link_local() => {
                IpAddr::V6((u128::from(ip) & (u128::MAX << (128 - bits))).into())
            }
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

// ponytail: pressure probes at most 32 buckets per tier per request; replace with indexed idle deadlines
// if bounded false-capacity refusals under churn become material (§67.2; ADR-0100).
const EVICTION_PROBES: usize = 32;

#[derive(Default)]
struct Tier {
    buckets: HashMap<Subject, Bucket>,
    idle: VecDeque<Subject>,
}

impl Tier {
    fn make_room(
        &mut self,
        now: Instant,
        policy: RatePolicy,
        cap: usize,
        missing: usize,
        protected: &[Subject],
    ) -> bool {
        let probes = self.idle.len().min(EVICTION_PROBES);
        for _ in 0..probes {
            if self.buckets.len().saturating_add(missing) <= cap {
                break;
            }
            let Some(subject) = self.idle.pop_front() else {
                break;
            };
            if !protected.contains(&subject)
                && self.buckets[&subject].credit(now, policy) == policy.capacity
            {
                self.buckets.remove(&subject);
            } else {
                self.idle.push_back(subject);
            }
        }
        self.buckets.len().saturating_add(missing) <= cap
    }
}

/// One gateway's bounded limiter; a second authority is forbidden by its boot lease (ADR-0100).
pub struct Limiter {
    policies: [RatePolicy; 5],
    max_subjects: [usize; 5],
    tiers: Mutex<[Tier; 5]>,
}

impl Limiter {
    /// Policies and isolated caps in IP / credential / user / account / operation order (§72.3).
    pub fn new(policies: [RatePolicy; 5], max_subjects: [usize; 5]) -> Result<Self, ErrorCode> {
        if max_subjects.contains(&0) {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self {
            policies,
            max_subjects,
            tiers: Mutex::new(std::array::from_fn(|_| Tier::default())),
        })
    }

    /// Atomically charge every unique tier or none. Memory pressure cannot reset an active bucket (§72.3).
    pub fn check(&self, subjects: &[Subject]) -> Result<(), RateLimited> {
        let mut tiers = self.tiers.lock().map_err(|_| RateLimited {
            code: ErrorCode::Internal,
            scope: "capacity",
        })?;
        let now = Instant::now();
        for (index, tier) in tiers.iter_mut().enumerate() {
            let missing = subjects
                .iter()
                .enumerate()
                .filter(|(i, s)| {
                    s.tier() == index
                        && !tier.buckets.contains_key(*s)
                        && !subjects[..*i].contains(s)
                })
                .count();
            if !tier.make_room(
                now,
                self.policies[index],
                self.max_subjects[index],
                missing,
                subjects,
            ) {
                return Err(RateLimited {
                    code: ErrorCode::DependencyUnavailable,
                    scope: "capacity",
                });
            }
        }
        for subject in subjects {
            let policy = self.policies[subject.tier()];
            let credit = tiers[subject.tier()]
                .buckets
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
            let tier = &mut tiers[subject.tier()];
            if !tier.buckets.contains_key(subject) {
                tier.idle.push_back(subject.clone());
            }
            let b = tier.buckets.entry(subject.clone()).or_insert(Bucket {
                credit: (policy.refill * TOKEN).min(policy.capacity),
                updated: now,
            });
            b.credit = b.credit(now, policy) - TOKEN;
            b.updated = now;
        }
        Ok(())
    }
}

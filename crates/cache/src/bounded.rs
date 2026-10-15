//! `cache::bounded` — `BoundedCache`: a moka-backed cache with byte weights, TTL, single-flight, a per-tenant byte
//!   cap and the §51.3 failure rule.
//! Depends-on: crates=[moka, humaux-domain, humaux-telemetry]; services=[]; env=[]; modules=[cache::key, telemetry::cache]
//! Called-by: [tests]
//! Invariants: [concurrent identical misses run one compute (§51, M12 D7); an `Err` is never cached; an insert that
//!   would take a tenant over `per_tenant_bytes` is skipped as `bypass` and evicts nobody (M12 D5); a disabled or
//!   zero-capacity cache computes every call and reports `bypass`; every lookup is counted exactly once (§41.2)]
//! Spec: Baseline §51; §51.3; §67.2; §41.2; §78.1
//!
//! ponytail: per-tenant accounting is exact for admission (one mutex) but lags moka's eviction by its maintenance
//! interval, so a tenant just under its cap may be bypassed a little early; upgrade = per-tenant sub-caches if the
//! B23 load test shows skew. A caller cancelled between the reservation and moka's insert leaks its reservation until
//! restart (bounded by `per_tenant_bytes`).
//! ponytail: when a leader's value is not admitted or its compute fails, joined waiters compute for themselves
//! (no shared failure); upgrade = share the leader's `Result` if error storms show up in the B23 load test.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use humaux_domain::ids::TenantId;
use humaux_telemetry::cache::{
    CacheName, CacheResult, EvictionCause, count_cache_eviction, count_cache_request,
    set_cache_bytes, set_cache_singleflight_waiters,
};
use moka::notification::RemovalCause;

use crate::key::{CacheKey, CacheValue};

/// Sizes and switches of one cache; every value comes from the config registry (§78.1), never from here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheConfig {
    /// Total weighted bytes (value bytes + key bytes) the cache may hold; `0` makes it a pass-through.
    pub capacity_bytes: u64,
    /// Weighted bytes one tenant may hold; a larger insert is skipped, never made room for (M12 D5).
    pub per_tenant_bytes: u64,
    /// Time-to-live of an entry.
    pub ttl: Duration,
    /// `false` makes the cache a pass-through.
    pub enabled: bool,
}

/// Byte accounting, one critical section so reservation and release never interleave.
#[derive(Default)]
struct Accounts {
    per_tenant: HashMap<TenantId, u64>,
    total: u64,
}

/// Shared between the cache handle and moka's eviction listener.
struct State {
    name: CacheName,
    accounts: Mutex<Accounts>,
    in_flight: AtomicU64,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // The guarded data is plain counters, valid after any panic, so a poisoned lock is still usable.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl State {
    /// Charges `bytes` to `tenant` unless that takes it over `cap`; the check and the charge are one critical section.
    fn try_reserve(&self, tenant: TenantId, bytes: u64, cap: u64) -> bool {
        let mut accounts = lock(&self.accounts);
        let used = accounts.per_tenant.entry(tenant).or_insert(0);
        if used.saturating_add(bytes) > cap {
            return false;
        }
        *used += bytes;
        accounts.total = accounts.total.saturating_add(bytes);
        set_cache_bytes(self.name, accounts.total);
        true
    }

    fn release(&self, tenant: TenantId, bytes: u64) {
        let mut accounts = lock(&self.accounts);
        if let Some(used) = accounts.per_tenant.get_mut(&tenant) {
            *used = used.saturating_sub(bytes);
            if *used == 0 {
                accounts.per_tenant.remove(&tenant);
            }
        }
        accounts.total = accounts.total.saturating_sub(bytes);
        set_cache_bytes(self.name, accounts.total);
    }
}

/// Counts callers inside the single-flight section; dropping it (also on cancellation) leaves the section.
struct InFlight<'a>(&'a State);

impl<'a> InFlight<'a> {
    fn enter(state: &'a State) -> Self {
        let n = state.in_flight.fetch_add(1, Ordering::Relaxed) + 1;
        set_cache_singleflight_waiters(state.name, n);
        Self(state)
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        let n = self.0.in_flight.fetch_sub(1, Ordering::Relaxed) - 1;
        set_cache_singleflight_waiters(self.0.name, n);
    }
}

/// Marker error: "this caller must compute for itself" — the leader's value was not admitted or its compute failed.
/// It exists so `try_get_with` stores nothing for those outcomes.
struct NotCached;

fn weight<K: CacheKey, V: CacheValue>(key: &K, value: &V) -> u64 {
    (key.key_bytes() as u64).saturating_add(value.value_bytes() as u64)
}

fn cause_of(cause: RemovalCause) -> EvictionCause {
    match cause {
        RemovalCause::Expired => EvictionCause::Expired,
        RemovalCause::Explicit => EvictionCause::Explicit,
        RemovalCause::Replaced => EvictionCause::Replaced,
        RemovalCause::Size => EvictionCause::Size,
    }
}

/// A bounded, byte-weighted, single-flight computation cache (§51, §67.2).
pub struct BoundedCache<K: CacheKey, V: CacheValue> {
    /// `None` when disabled or zero-capacity: every call computes.
    cache: Option<moka::future::Cache<K, V>>,
    state: Arc<State>,
    per_tenant_bytes: u64,
}

impl<K: CacheKey, V: CacheValue> BoundedCache<K, V> {
    /// Builds the cache for `name`; a disabled or zero-capacity `config` yields a pass-through.
    pub fn new(name: CacheName, config: CacheConfig) -> Self {
        let state = Arc::new(State {
            name,
            accounts: Mutex::new(Accounts::default()),
            in_flight: AtomicU64::new(0),
        });
        let cache = (config.enabled && config.capacity_bytes > 0).then(|| {
            let listener_state = Arc::clone(&state);
            moka::future::Cache::builder()
                .max_capacity(config.capacity_bytes)
                .weigher(|k: &K, v: &V| u32::try_from(weight(k, v)).unwrap_or(u32::MAX))
                .time_to_live(config.ttl)
                .eviction_listener(move |k: Arc<K>, v: V, cause: RemovalCause| {
                    listener_state.release(k.tenant(), weight(k.as_ref(), &v));
                    count_cache_eviction(listener_state.name, cause_of(cause));
                })
                .build()
        });
        Self {
            cache,
            state,
            per_tenant_bytes: config.per_tenant_bytes,
        }
    }

    /// Weighted bytes held after moka's pending maintenance; `0` for a pass-through.
    pub async fn weighted_size(&self) -> u64 {
        match &self.cache {
            Some(c) => {
                c.run_pending_tasks().await;
                c.weighted_size()
            }
            None => 0,
        }
    }

    /// Returns the cached value for `key`, or runs `compute` once for all concurrent callers of the same key and
    /// caches an `Ok` (single-flight, M12 D7). An `Err` is returned to its caller and never cached; nothing here
    /// can fail the request (§51.3).
    pub async fn get_or_try_compute<E, F>(&self, key: K, compute: F) -> Result<V, E>
    where
        F: Future<Output = Result<V, E>>,
    {
        let name = self.state.name;
        let Some(cache) = &self.cache else {
            return Self::uncached(name, compute, CacheResult::Bypass).await;
        };
        let tenant = key.tenant();
        let key_bytes = key.key_bytes() as u64;
        let cap = self.per_tenant_bytes;
        let own = Mutex::new(Some(compute));
        let leader_outcome: Mutex<Option<Result<V, E>>> = Mutex::new(None);
        let ran = AtomicBool::new(false);
        let flight = InFlight::enter(&self.state);
        let got = cache
            .try_get_with(key, async {
                ran.store(true, Ordering::Relaxed);
                let compute = lock(&own).take();
                let Some(compute) = compute else {
                    return Err(NotCached);
                };
                match compute.await {
                    Ok(v)
                        if self.state.try_reserve(
                            tenant,
                            key_bytes + v.value_bytes() as u64,
                            cap,
                        ) =>
                    {
                        Ok(v)
                    }
                    other => {
                        *lock(&leader_outcome) = Some(other);
                        Err(NotCached)
                    }
                }
            })
            .await;
        drop(flight);
        match got {
            Ok(v) => {
                let result = if ran.load(Ordering::Relaxed) {
                    CacheResult::Miss
                } else {
                    CacheResult::Hit
                };
                count_cache_request(name, result);
                Ok(v)
            }
            Err(_) => {
                let outcome = lock(&leader_outcome).take();
                match outcome {
                    Some(Ok(v)) => {
                        count_cache_request(name, CacheResult::Bypass);
                        Ok(v)
                    }
                    Some(Err(e)) => {
                        count_cache_request(name, CacheResult::Error);
                        Err(e)
                    }
                    None => {
                        // Joined a leader that did not cache: compute for ourselves.
                        let compute = lock(&own).take();
                        match compute {
                            Some(compute) => {
                                Self::uncached(name, compute, CacheResult::Bypass).await
                            }
                            // moka runs a caller's init future at most once, and a leader that ran it recorded its
                            // outcome above, so this arm has no execution.
                            None => unreachable!(
                                "leader ran the init future without recording an outcome"
                            ),
                        }
                    }
                }
            }
        }
    }

    async fn uncached<E, F>(name: CacheName, compute: F, ok: CacheResult) -> Result<V, E>
    where
        F: Future<Output = Result<V, E>>,
    {
        let out = compute.await;
        count_cache_request(name, if out.is_ok() { ok } else { CacheResult::Error });
        out
    }
}

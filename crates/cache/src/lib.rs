//! `humaux-cache` — the one in-process, bounded, byte-weighted computation cache of a process (§51, §67.2).
//! Depends-on: crates=[humaux-domain, humaux-telemetry, moka]; services=[]; env=[]; modules=[telemetry::cache]
//! Called-by: []
//! Invariants: [a cache failure is a miss plus a named metric and the request continues (§51.3); compute errors are
//!   never cached; a private key carries tenant and user (M12 D3); a key carries every version that determines its
//!   value (§51); one tenant can never evict another tenant's entries (M12 D5)]
//! Spec: Baseline §51; §51.1; §51.2; §51.3; §67.2; §78.1; §20.0
//!
//! Never cached here (B23 never-cache list): authorization decisions, validated-key status, final private bodies,
//! exact user-visible counts, quota balances. This crate persists nothing, shares nothing across processes and reads
//! no configuration: sizes and TTL arrive in [`CacheConfig`] from the caller (§78.1).

pub mod bounded;
pub mod key;

pub use bounded::{BoundedCache, CacheConfig};
pub use key::{CacheKey, CacheValue, EmbeddingMode, EmbeddingQueryKey};

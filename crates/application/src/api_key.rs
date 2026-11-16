//! `application::api_key` — API credential validation policy (§73.5; ADR-0059 D-H).
//! Depends-on: crates=[hmac, humaux-domain, sha2]; services=[]; env=[]; modules=[domain::network]
//! Called-by: [tests]
//! Invariants: [caller-supplied clock and peppers; current pepper precedes previous]
//! Spec: §73.5; ADR-0130

use hmac::{Hmac, KeyInit, Mac};
use humaux_domain::network::Cidr;
use sha2::Sha256;
use std::net::IpAddr;
use std::time::SystemTime;

type HmacSha256 = Hmac<Sha256>;

/// §73.5 lifecycle: `CREATE -> ACTIVE -> ROTATING -> REVOKED/EXPIRED`. Wire form matches the
/// `control.api_keys.status` CHECK constraint (migration 0035) — [`ApiKeyStatus::as_db_str`]
/// / [`ApiKeyStatus::from_db_str`] are the only conversion points, kept next to the enum so
/// the two never drift independently. [`ApiKeyStatus::ALL`] + `contract_tests` below hold
/// this against the migration's literal CHECK list (§78.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyStatus {
    Create,
    Active,
    Rotating,
    Revoked,
    Expired,
}

impl ApiKeyStatus {
    /// Every variant, in the same order as `control.api_keys.status`'s CHECK list —
    /// order matters, `protocol::edge::contract_tests` diffs this positionally against the migration.
    pub const ALL: [ApiKeyStatus; 5] = [
        ApiKeyStatus::Create,
        ApiKeyStatus::Active,
        ApiKeyStatus::Rotating,
        ApiKeyStatus::Revoked,
        ApiKeyStatus::Expired,
    ];

    pub const fn as_db_str(self) -> &'static str {
        match self {
            ApiKeyStatus::Create => "CREATE",
            ApiKeyStatus::Active => "ACTIVE",
            ApiKeyStatus::Rotating => "ROTATING",
            ApiKeyStatus::Revoked => "REVOKED",
            ApiKeyStatus::Expired => "EXPIRED",
        }
    }

    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "CREATE" => Some(ApiKeyStatus::Create),
            "ACTIVE" => Some(ApiKeyStatus::Active),
            "ROTATING" => Some(ApiKeyStatus::Rotating),
            "REVOKED" => Some(ApiKeyStatus::Revoked),
            "EXPIRED" => Some(ApiKeyStatus::Expired),
            _ => None,
        }
    }
}

/// §73.5 lifecycle edges. `Active` may skip `Rotating` straight to `Revoked`/`Expired`
/// (rotation is optional); `Rotating` only ever concludes the *old* key via `Revoked`/`Expired`
/// once its overlap window ends — it never goes back to `Active`.
pub fn is_legal_api_key_transition(from: ApiKeyStatus, to: ApiKeyStatus) -> bool {
    use ApiKeyStatus::*;
    matches!(
        (from, to),
        (Create, Active)
            | (Active, Rotating)
            | (Active, Revoked)
            | (Active, Expired)
            | (Rotating, Revoked)
            | (Rotating, Expired)
    )
}

/// §73.5 keyed hash: `HMAC-SHA256(pepper, raw_key)`. A random-entropy API key (unlike a
/// user-chosen password, §74.3) does not need Argon2's deliberately-slow KDF — a fast keyed
/// hash keyed by a server-side pepper is the standard shape for this credential class, and
/// `hmac::Mac::verify_slice` gives constant-time comparison for free (no hand-rolled
/// timing-safe compare here — that would be reinventing a primitive the crate already owns).
pub fn compute_api_key_hash(pepper: &[u8], raw_key: &str) -> Vec<u8> {
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(pepper).expect("HMAC accepts any key length");
    mac.update(raw_key.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn verify_api_key_hash(pepper: &[u8], raw_key: &str, stored_hash: &[u8]) -> bool {
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(pepper).expect("HMAC accepts any key length");
    mac.update(raw_key.as_bytes());
    mac.verify_slice(stored_hash).is_ok()
}

/// One `control.api_keys` row's fields relevant to validation — not the full DB row shape,
/// just what [`validate_api_key`] needs.
pub struct ApiKeyRecord {
    pub key_hash: Vec<u8>,
    pub status: ApiKeyStatus,
    pub allowed_cidrs: Vec<Cidr>,
    pub expires_at: Option<SystemTime>,
    pub revoked_at: Option<SystemTime>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyRejection {
    /// Presented key does not verify against the stored keyed hash.
    HashMismatch,
    Revoked,
    Expired,
    /// `status` is not `Active`/`Rotating` (e.g. still `Create`, never activated).
    InactiveStatus,
    /// `allowed_cidrs` is non-empty and the request IP is not in it (§73.5 credential CIDR
    /// binding).
    CidrNotAllowed,
}

/// Which pepper verified the presented key (ADR-0059 D-H). A result, not an error: `Previous`
/// tells the caller to rehash the stored verifier under the current pepper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PepperMatch {
    Current,
    Previous,
}

/// §73.5 validation: keyed-hash compare, then lifecycle status, then `expires_at`/`revoked_at`
/// timestamps (belt-and-suspenders with `status` — a row can be `Active` in the DB with a
/// stale `expires_at` between the row's actual expiry and the next sweep), then CIDR binding.
/// `now` is caller-supplied (§78.1: no clock read baked into a pure function).
///
/// ADR-0059 D-H: `previous` is the rotation window's old pepper (`None` = window closed); it is
/// tried only after `current` fails.
pub fn validate_api_key(
    record: &ApiKeyRecord,
    presented_key: &str,
    current: &[u8],
    previous: Option<&[u8]>,
    request_ip: IpAddr,
    now: SystemTime,
) -> Result<PepperMatch, ApiKeyRejection> {
    let matched = if verify_api_key_hash(current, presented_key, &record.key_hash) {
        PepperMatch::Current
    } else if previous.is_some_and(|p| verify_api_key_hash(p, presented_key, &record.key_hash)) {
        PepperMatch::Previous
    } else {
        return Err(ApiKeyRejection::HashMismatch);
    };
    match record.status {
        ApiKeyStatus::Revoked => return Err(ApiKeyRejection::Revoked),
        ApiKeyStatus::Expired => return Err(ApiKeyRejection::Expired),
        ApiKeyStatus::Create => return Err(ApiKeyRejection::InactiveStatus),
        ApiKeyStatus::Active | ApiKeyStatus::Rotating => {}
    }
    if record.revoked_at.is_some_and(|at| at <= now) {
        return Err(ApiKeyRejection::Revoked);
    }
    if record.expires_at.is_some_and(|at| at <= now) {
        return Err(ApiKeyRejection::Expired);
    }
    if !record.allowed_cidrs.is_empty() {
        let ip = request_ip.to_canonical();
        if !record.allowed_cidrs.iter().any(|c| c.contains(ip)) {
            return Err(ApiKeyRejection::CidrNotAllowed);
        }
    }
    Ok(matched)
}

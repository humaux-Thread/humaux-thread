//! `application::session` — M02 D6 console session: the 32-byte cookie secret, its stored digest, the session's
//!   liveness decision and the session-bound CSRF token. Pure: no SQL, no clock, no HTTP.
//! Depends-on: crates=[hex, humaux-domain, rand, sha2, uuid]; services=[]; env=[]; modules=[application::auth, application::signed_token, domain::ids]
//! Called-by: [adapters::session_repo, gateway::auth_pages, tests]
//! Invariants: [the secret exists only in the cookie value and is never printed or stored, only its SHA-256 is; a session
//!   is live only while it is unrevoked, unexpired, inside its idle window AND its epoch snapshot equals the user's
//!   current epoch; a CSRF token is a function of its own session id, so one minted for session A is not valid for B]
//! Spec: §73.6; §74.4; §78.1; M02 D6
//!
//! The wire half of CSRF (`Sec-Fetch-Site`, header compare) is `protocol::edge::verify_csrf`; this file only mints the
//! expected token. Absolute lifetime is `AuthConfig::session_ttl` and idle lifetime `AuthConfig::session_idle_ttl`.

use std::time::{Duration, SystemTime};

use humaux_domain::ids::UserId;
use rand::TryRngCore as _;
use rand::rngs::OsRng;
use sha2::Digest as _;
use uuid::Uuid;

use crate::auth::{AuthConfig, SessionSnapshot, session_still_valid};
use crate::signed_token::TokenKeys;

/// §73.6: MAC domain of the CSRF token. Distinct from every [`crate::signed_token::TokenLabel`] MAC label, so a CSRF
/// token is never a valid RYW or access token under the shared key.
pub const CSRF_LABEL: &[u8] = b"csrf@1";

const SECRET_BYTES: usize = 32;

/// `control.sessions.session_id`. Internal: never the cookie value (§73.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionId(pub Uuid);

/// The 32-byte value carried by the session cookie. `Debug` is redacted; the type has no `Clone`.
pub struct SessionSecret([u8; SECRET_BYTES]);

impl std::fmt::Debug for SessionSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionSecret(<redacted>)")
    }
}

impl SessionSecret {
    /// 32 bytes from the OS CSPRNG. A failed read panics rather than fall back to a weaker source.
    pub fn generate() -> Self {
        let mut bytes = [0u8; SECRET_BYTES];
        OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OS CSPRNG unavailable");
        Self(bytes)
    }

    /// Lowercase hex of the secret: the value of the `__Host-humaux_session` cookie.
    #[must_use]
    pub fn cookie_value(&self) -> String {
        hex::encode(self.0)
    }

    /// Parses a cookie value; anything but exactly 64 hex digits is `None`.
    #[must_use]
    pub fn from_cookie_value(raw: &str) -> Option<Self> {
        let mut bytes = [0u8; SECRET_BYTES];
        hex::decode_to_slice(raw, &mut bytes).ok()?;
        Some(Self(bytes))
    }

    /// The SHA-256 the session row stores. The secret has 256 bits of entropy, so a plain digest needs no pepper.
    #[must_use]
    pub fn digest(&self) -> SecretDigest {
        SecretDigest(sha2::Sha256::digest(self.0).into())
    }
}

/// SHA-256 of a [`SessionSecret`]; `control.sessions.token_hash`. `Debug` is redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretDigest([u8; SECRET_BYTES]);

impl std::fmt::Debug for SecretDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretDigest(<redacted>)")
    }
}

impl SecretDigest {
    /// The bytes to store or look up.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Constant-time compare with a stored digest of any length (a wrong length is simply unequal).
    #[must_use]
    pub fn matches_stored(&self, stored: &[u8]) -> bool {
        if stored.len() != SECRET_BYTES {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in self.0.iter().zip(stored) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

/// §78.1 session lifetimes, both from [`AuthConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionPolicy {
    /// Lifetime from issue to `expires_at`.
    pub absolute_ttl: Duration,
    /// Longest gap between two uses.
    pub idle_ttl: Duration,
}

impl From<&AuthConfig> for SessionPolicy {
    fn from(config: &AuthConfig) -> Self {
        Self {
            absolute_ttl: config.session_ttl,
            idle_ttl: config.session_idle_ttl,
        }
    }
}

/// One `control.sessions` row joined with its user's current security epoch.
#[derive(Debug, Clone, Copy)]
pub struct SessionRecord {
    /// Row id.
    pub session_id: SessionId,
    /// Owner of the session.
    pub user_id: UserId,
    /// Epoch snapshot, expiry and revocation of the row.
    pub snapshot: SessionSnapshot,
    /// `control.users.security_epoch` right now.
    pub current_epoch: i64,
    /// Last use.
    pub last_seen_at: SystemTime,
}

/// A session that passed [`verify`]; constructed nowhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedSession {
    /// Row id, the CSRF binding.
    pub session_id: SessionId,
    /// Owner.
    pub user_id: UserId,
}

/// G-M02-4: a session is live only while it is unrevoked, unexpired, within its idle window and its epoch snapshot
/// equals the user's current epoch (`bump_user_security_epoch` kills every older session, §74.4).
#[must_use]
pub fn verify(
    record: &SessionRecord,
    policy: &SessionPolicy,
    now: SystemTime,
) -> Option<VerifiedSession> {
    let within_idle = record
        .last_seen_at
        .checked_add(policy.idle_ttl)
        .is_some_and(|idle_deadline| idle_deadline > now);
    (session_still_valid(record.snapshot, record.current_epoch, now) && within_idle).then_some(
        VerifiedSession {
            session_id: record.session_id,
            user_id: record.user_id,
        },
    )
}

/// G-M02-5: the CSRF token of one session, `hex(HMAC(auth key, "csrf@1" ‖ 0x00 ‖ session_id))`. Deterministic per
/// session and key, so the server keeps no token state.
///
/// ponytail: only the current key verifies, so a key rotation invalidates outstanding tokens until the page reloads;
/// upgrade path: also accept the previous key through `TokenKeys`.
#[must_use]
pub fn csrf_token(keys: &TokenKeys, session_id: SessionId) -> String {
    hex::encode(keys.current_labelled_hmac(CSRF_LABEL, session_id.0.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_700_000_000;

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn policy() -> SessionPolicy {
        SessionPolicy::from(&AuthConfig::default())
    }

    fn record() -> SessionRecord {
        SessionRecord {
            session_id: SessionId(Uuid::from_u128(1)),
            user_id: UserId(Uuid::from_u128(2)),
            snapshot: SessionSnapshot {
                session_epoch: 4,
                expires_at: at(T0 + 1000),
                revoked_at: None,
            },
            current_epoch: 4,
            last_seen_at: at(T0),
        }
    }

    fn keys() -> TokenKeys {
        TokenKeys::new(rand::random::<[u8; 32]>().to_vec(), None).unwrap()
    }

    #[test]
    fn a_fresh_session_verifies_and_names_its_owner() {
        assert_eq!(
            verify(&record(), &policy(), at(T0 + 1)),
            Some(VerifiedSession {
                session_id: SessionId(Uuid::from_u128(1)),
                user_id: UserId(Uuid::from_u128(2)),
            })
        );
    }

    #[test]
    fn each_of_the_four_conditions_alone_refuses() {
        let now = at(T0 + 1);
        let mut bumped = record();
        bumped.current_epoch = 5;
        let mut expired = record();
        expired.snapshot.expires_at = at(T0);
        let mut revoked = record();
        revoked.snapshot.revoked_at = Some(at(T0));
        let mut idle = record();
        idle.last_seen_at = at(T0);
        let idle_policy = SessionPolicy {
            idle_ttl: Duration::from_secs(1),
            ..policy()
        };
        assert_eq!(verify(&bumped, &policy(), now), None);
        assert_eq!(verify(&expired, &policy(), now), None);
        assert_eq!(verify(&revoked, &policy(), now), None);
        assert_eq!(verify(&idle, &idle_policy, now), None);
    }

    #[test]
    fn default_policy_is_both_nonzero_and_idle_is_shorter_than_absolute() {
        let p = policy();
        assert!(p.idle_ttl > Duration::ZERO);
        assert!(p.idle_ttl < p.absolute_ttl);
    }

    #[test]
    fn cookie_value_round_trips_to_the_same_digest_and_rejects_malformed_input() {
        let secret = SessionSecret::generate();
        let cookie = secret.cookie_value();
        assert_eq!(cookie.len(), 64);
        let parsed = SessionSecret::from_cookie_value(&cookie).expect("64 hex digits");
        assert!(secret.digest().matches_stored(parsed.digest().as_bytes()));
        let malformed = [
            String::new(),
            "ab".to_string(),
            cookie[..62].to_string(),
            format!("{cookie}00"),
            "zz".repeat(32),
        ];
        for bad in &malformed {
            assert!(SessionSecret::from_cookie_value(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn two_secrets_differ_and_debug_never_prints_one() {
        let a = SessionSecret::generate();
        let b = SessionSecret::generate();
        assert_ne!(a.cookie_value(), b.cookie_value());
        assert!(!a.digest().matches_stored(b.digest().as_bytes()));
        assert!(!a.digest().matches_stored(&[0u8; 5]));
        assert_eq!(format!("{a:?}"), "SessionSecret(<redacted>)");
        assert_eq!(format!("{:?}", a.digest()), "SecretDigest(<redacted>)");
        assert!(!format!("{a:?}{:?}", a.digest()).contains(&a.cookie_value()));
    }

    #[test]
    fn csrf_token_is_per_session_and_per_key() {
        let k = keys();
        let a = SessionId(Uuid::from_u128(10));
        let b = SessionId(Uuid::from_u128(11));
        assert_eq!(csrf_token(&k, a), csrf_token(&k, a));
        assert_ne!(csrf_token(&k, a), csrf_token(&k, b));
        assert_ne!(csrf_token(&k, a), csrf_token(&keys(), a));
        assert_eq!(csrf_token(&k, a).len(), 64);
    }
}

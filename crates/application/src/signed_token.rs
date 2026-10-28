//! `application::signed_token` — HMAC-SHA256 key set and the labelled sign/verify wire shared by every
//!   self-contained token the gateway issues (RYW `consistency_token` today; M02 access tokens and `context_ref` next).
//! Depends-on: crates=[hex, hmac, rand, sha2]; services=[]; env=[]; modules=[]
//! Called-by: [adapters::retrieve, application::oauth, application::session, gateway::auth_pages, gateway::billing_webhook, gateway::oauth_http, protocol::page, tests]
//! Invariants: [a key is ≥ 32 bytes and `previous != current`; `Debug` and every error name a key id or a rule, never
//!   key bytes; the token kind lives only in its [`TokenLabel`], so two kinds under one key never share a MAC or a kid;
//!   a token is MAC-verified before any caller sees one payload byte]
//! Spec: ADR-0059 D-G; M02 D3
//!
//! Pure: no clock, no I/O, no process-wide state. The `OnceLock` install and the claim fields of each token kind stay
//! with their callers; this file owns only `hex(payload ‖ U+0001 ‖ kid ‖ U+0001 ‖ mac)`.

use hmac::Mac as _;
use sha2::Digest as _;

/// Separates the payload, the kid and the MAC on the wire. Payloads of one token kind use the same byte between
/// their own fields, so a verifier splits from the right (`rsplitn(3)`), never from the left.
pub const FIELD_SEP: char = '\u{1}';

/// ADR-0059 D-G: a token key is ≥ 32 bytes, the HMAC-SHA256 block-security floor.
const MIN_TOKEN_KEY_BYTES: usize = 32;

/// Kid label used only by [`TokenKeys`]'s `Debug`; no token kind signs with it.
const DEBUG_KID_LABEL: &[u8] = b"humaux.signed_token.debug.kid.v1";

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// §71.3 invariant: the raw-body webhook MAC is unlabelled and must never be compared with a labelled one.
#[must_use]
pub fn verify_hmac_sha256_hex(secret: &[u8], body: &[u8], signature_hex: &str) -> bool {
    let Ok(tag) = hex::decode(signature_hex) else {
        return false;
    };
    let mut mac =
        <HmacSha256 as hmac::KeyInit>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(body);
    mac.verify_slice(&tag).is_ok()
}

/// One token kind's domain separation: the MAC label and the kid label. Two kinds that share a key must differ in
/// both, or one kind's token verifies as the other's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenLabel {
    mac: &'static [u8],
    kid: &'static [u8],
}

impl TokenLabel {
    /// A label from its MAC domain string and its kid domain string (both ASCII, versioned).
    #[must_use]
    pub const fn new(mac: &'static [u8], kid: &'static [u8]) -> Self {
        Self { mac, kid }
    }
}

/// ADR-0059 D-G: a token MAC key set — `current` signs and verifies, `previous` (rotation window only) verifies.
/// `Debug` prints key ids only, never key bytes.
pub struct TokenKeys {
    current: Vec<u8>,
    previous: Option<Vec<u8>>,
}

impl TokenKeys {
    /// Validates the set: each key ≥ 32 bytes and `previous != current`. The error names the failed rule, never a
    /// key byte; its text starts with `current` or `previous` so a caller can name the offending config key.
    pub fn new(current: Vec<u8>, previous: Option<Vec<u8>>) -> Result<Self, &'static str> {
        if current.len() < MIN_TOKEN_KEY_BYTES {
            return Err("current token key shorter than 32 bytes");
        }
        if let Some(prev) = &previous {
            if prev.len() < MIN_TOKEN_KEY_BYTES {
                return Err("previous token key shorter than 32 bytes");
            }
            if *prev == current {
                return Err("previous token key equals the current key");
            }
        }
        Ok(Self { current, previous })
    }

    /// Whether `other` holds exactly the same current and previous key bytes.
    #[must_use]
    pub fn same_keys(&self, other: &Self) -> bool {
        self.current == other.current && self.previous == other.previous
    }

    /// Whether any key of this set (current or previous) equals any key of `other`. Two token families must
    /// not share key material (M02 D3: one leak would mint both).
    #[must_use]
    pub fn shares_key_with(&self, other: &Self) -> bool {
        let mine = std::iter::once(&self.current).chain(self.previous.as_ref());
        mine.clone()
            .any(|key| *key == other.current || other.previous.as_ref() == Some(key))
    }

    /// The kid of the current key under `label`: first 8 hex chars of `SHA-256(label.kid ‖ 0x00 ‖ key)`.
    #[must_use]
    pub fn current_kid(&self, label: &TokenLabel) -> String {
        key_id(label.kid, &self.current)
    }

    /// `HMAC(current key, label ‖ 0x00 ‖ data)` — a derivation from the signing key that is not a token MAC.
    #[must_use]
    pub fn current_labelled_hmac(&self, label: &[u8], data: &[u8]) -> Vec<u8> {
        labelled_hmac(&self.current, label, data)
    }

    /// `hex(payload ‖ U+0001 ‖ kid ‖ U+0001 ‖ mac)` signed with the current key. The MAC covers the label, the
    /// payload and the kid; it proves that a holder of this key issued these bytes, not that anyone may act on them.
    #[must_use]
    pub fn sign(&self, label: &TokenLabel, payload: &str) -> String {
        let kid = self.current_kid(label);
        let mac = hex::encode(
            token_mac(&self.current, label, payload, &kid)
                .finalize()
                .into_bytes(),
        );
        hex::encode(format!("{payload}{FIELD_SEP}{kid}{FIELD_SEP}{mac}"))
    }

    /// Inverse of [`Self::sign`]: kid lookup (current, then previous), constant-time MAC check, and only then the
    /// payload is returned. Every failure is a fixed reason string and never panics on attacker-controlled input.
    pub fn verify(&self, label: &TokenLabel, token: &str) -> Result<String, &'static str> {
        if !token.len().is_multiple_of(2) || token.is_empty() {
            return Err("odd length or empty");
        }
        let bytes = hex::decode(token).map_err(|_| "not hex")?;
        let signed = String::from_utf8(bytes).map_err(|_| "not utf8")?;
        let mut tail = signed.rsplitn(3, FIELD_SEP);
        let (Some(mac_hex), Some(kid), Some(payload)) = (tail.next(), tail.next(), tail.next())
        else {
            return Err("wrong field count");
        };
        let key = std::iter::once(self.current.as_slice())
            .chain(self.previous.as_deref())
            .find(|key| key_id(label.kid, key) == kid)
            .ok_or("token key unknown")?;
        let tag = hex::decode(mac_hex)
            .ok()
            .filter(|t| t.len() == 32)
            .ok_or("token signature")?;
        token_mac(key, label, payload, kid)
            .verify_slice(&tag)
            .map_err(|_| "token signature")?;
        Ok(payload.to_owned())
    }
}

impl std::fmt::Debug for TokenKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenKeys")
            .field("current_kid", &key_id(DEBUG_KID_LABEL, &self.current))
            .field(
                "previous_kid",
                &self
                    .previous
                    .as_deref()
                    .map(|key| key_id(DEBUG_KID_LABEL, key)),
            )
            .finish()
    }
}

fn key_id(kid_label: &[u8], key: &[u8]) -> String {
    let digest = sha2::Sha256::new()
        .chain_update(kid_label)
        .chain_update([0u8])
        .chain_update(key)
        .finalize();
    hex::encode(&digest[..4])
}

fn token_mac(key: &[u8], label: &TokenLabel, payload: &str, kid: &str) -> HmacSha256 {
    let mut mac =
        <HmacSha256 as hmac::KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(label.mac);
    mac.update(&[0u8]);
    mac.update(payload.as_bytes());
    mac.update(FIELD_SEP.to_string().as_bytes());
    mac.update(kid.as_bytes());
    mac
}

/// `HMAC-SHA256(key, label ‖ 0x00 ‖ data)`; the building block of derivations keyed from a token key.
#[must_use]
pub fn labelled_hmac(key: &[u8], label: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac =
        <HmacSha256 as hmac::KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(label);
    mac.update(&[0u8]);
    mac.update(data);
    AsRef::<[u8]>::as_ref(&mac.finalize().into_bytes()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_webhook_hmac_rfc4231_case2() {
        let tag = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        let verify = |body: &[u8], tag: &str| verify_hmac_sha256_hex(b"Jefe", body, tag);
        let body = b"what do ya want for nothing?";
        assert!(verify(body, tag));
        assert!(verify(body, &tag.to_uppercase()));
        assert!(!verify(
            body,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3842"
        ));
        assert!(!verify(body, "0"));
        assert!(!verify(body, "zz"));
        assert!(!verify(body, ""));
        assert!(!verify(b"different bytes", tag));
    }

    const LABEL_A: TokenLabel = TokenLabel::new(b"humaux.test.a.v1", b"humaux.test.a.kid.v1");
    const LABEL_B: TokenLabel = TokenLabel::new(b"humaux.test.b.v1", b"humaux.test.b.kid.v1");

    /// A fresh random 32-byte key per call; tests never use a literal key.
    // `uuid`'s `v4` feature is only unified in by other workspace crates; `cargo test -p
    // humaux-application --lib` (the DOD verifier path) must compile on this crate's own deps.
    fn random_key() -> Vec<u8> {
        rand::random::<[u8; 32]>().to_vec()
    }

    #[test]
    fn sign_then_verify_returns_the_payload() {
        let keys = TokenKeys::new(random_key(), None).unwrap();
        let token = keys.sign(&LABEL_A, "a\u{1}b\u{1}c");
        assert_eq!(keys.verify(&LABEL_A, &token).unwrap(), "a\u{1}b\u{1}c");
    }

    /// A token of one kind never verifies as another kind under the same key (M02 D3 label separation).
    #[test]
    fn another_label_does_not_verify() {
        let keys = TokenKeys::new(random_key(), None).unwrap();
        let token = keys.sign(&LABEL_A, "payload");
        assert_eq!(keys.verify(&LABEL_B, &token), Err("token key unknown"));
        let same_kid = TokenLabel::new(b"humaux.test.b.v1", LABEL_A.kid);
        assert_eq!(keys.verify(&same_kid, &token), Err("token signature"));
    }

    #[test]
    fn previous_key_verifies_and_closed_window_refuses() {
        let old = TokenKeys::new(random_key(), None).unwrap();
        let token = old.sign(&LABEL_A, "payload");
        let old_bytes = old.current.clone();
        let rotated = TokenKeys::new(random_key(), Some(old_bytes)).unwrap();
        assert_eq!(rotated.verify(&LABEL_A, &token).unwrap(), "payload");
        let closed = TokenKeys::new(rotated.current.clone(), None).unwrap();
        assert_eq!(closed.verify(&LABEL_A, &token), Err("token key unknown"));
    }

    #[test]
    fn verify_refuses_garbage_with_fixed_reasons() {
        let keys = TokenKeys::new(random_key(), None).unwrap();
        assert_eq!(keys.verify(&LABEL_A, ""), Err("odd length or empty"));
        assert_eq!(keys.verify(&LABEL_A, "abc"), Err("odd length or empty"));
        assert_eq!(keys.verify(&LABEL_A, "zz"), Err("not hex"));
        assert_eq!(keys.verify(&LABEL_A, "ff"), Err("not utf8"));
        assert_eq!(
            keys.verify(&LABEL_A, &hex::encode("no separators")),
            Err("wrong field count")
        );
    }

    #[test]
    fn tampered_payload_fails_the_mac() {
        let keys = TokenKeys::new(random_key(), None).unwrap();
        let signed =
            String::from_utf8(hex::decode(keys.sign(&LABEL_A, "payload")).unwrap()).unwrap();
        let forged = hex::encode(signed.replacen("payload", "payloae", 1));
        assert_eq!(keys.verify(&LABEL_A, &forged), Err("token signature"));
    }

    #[test]
    fn keys_refuse_short_or_equal_previous() {
        assert!(TokenKeys::new(vec![7; 31], None).is_err());
        let k = random_key();
        assert!(TokenKeys::new(k.clone(), Some(k.clone())).is_err());
        assert!(TokenKeys::new(k, Some(vec![7; 31])).is_err());
    }

    #[test]
    fn debug_prints_kids_only() {
        let keys = TokenKeys::new(random_key(), Some(random_key())).unwrap();
        let shown = format!("{keys:?}");
        assert!(!shown.contains(&hex::encode(&keys.current)));
        assert!(!shown.contains(&hex::encode(keys.previous.as_ref().unwrap())));
        assert!(shown.contains(&key_id(DEBUG_KID_LABEL, &keys.current)));
    }

    #[test]
    fn key_comparisons_cover_current_and_previous() {
        let (a, b, c) = (random_key(), random_key(), random_key());
        let set = TokenKeys::new(a.clone(), Some(b.clone())).unwrap();
        assert!(set.same_keys(&TokenKeys::new(a.clone(), Some(b.clone())).unwrap()));
        assert!(!set.same_keys(&TokenKeys::new(a.clone(), None).unwrap()));
        assert!(set.shares_key_with(&TokenKeys::new(b, None).unwrap()));
        assert!(set.shares_key_with(&TokenKeys::new(c.clone(), Some(a)).unwrap()));
        assert!(!set.shares_key_with(&TokenKeys::new(c, None).unwrap()));
    }
}

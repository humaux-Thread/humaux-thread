//! `billing-worker::tests::signature` — raw-body authentication gate (§71.3).
//! Depends-on: crates=[hex, hmac, humaux-domain, sha2, uuid]; services=[]; env=[]; modules=[billing-worker::signature, domain::error]
//! Called-by: [cargo-test]
//! Invariants: [independent HMAC oracle; malformed signatures and altered bytes rejected]
//! Spec: Baseline §71.3; §79.4
use hmac::{Hmac, KeyInit, Mac};
use humaux_billing_worker::signature::verify;
use humaux_domain::error::ErrorCode;
use sha2::Sha256;
use uuid::Uuid;
fn random_key() -> Vec<u8> {
    let mut key = Uuid::new_v4().as_bytes().to_vec();
    key.extend_from_slice(Uuid::new_v4().as_bytes());
    key
}
#[test]
fn tampered_body_is_refused() {
    let secret = random_key();
    let mut oracle = <Hmac<Sha256> as KeyInit>::new_from_slice(&secret).unwrap();
    oracle.update(b"Hi There");
    let signature = hex::encode(oracle.finalize().into_bytes());
    assert_eq!(
        verify(Some(&signature), b"Hi There!", &secret),
        Err(ErrorCode::Unauthorized)
    );
}
#[test]
fn signature_contract() {
    let secret = random_key();
    let mut oracle = <Hmac<Sha256> as KeyInit>::new_from_slice(&secret).unwrap();
    oracle.update(b"Hi There");
    let signature = hex::encode(oracle.finalize().into_bytes());
    for header in [&signature, &signature.to_uppercase()] {
        assert_eq!(verify(Some(header), b"Hi There", &secret), Ok(()));
    }
    for header in [
        None,
        Some(""),
        Some("00"),
        Some("zz"),
        Some(&"00".repeat(32)),
        Some(&format!("{signature}00")),
    ] {
        assert_eq!(
            verify(header, b"Hi There", &secret),
            Err(ErrorCode::Unauthorized)
        );
    }
    assert_eq!(
        verify(Some(&signature), b"Hi There", &random_key()),
        Err(ErrorCode::Unauthorized)
    );
    assert_eq!(
        verify(Some(&signature), b"Hi There", &secret[..0]),
        Err(ErrorCode::Unauthorized)
    );
}

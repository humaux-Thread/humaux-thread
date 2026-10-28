//! `billing-worker::signature` — raw-body authentication boundary (§71.3).
//! Depends-on: crates=[hex, hmac, humaux-domain, sha2]; services=[]; env=[]; modules=[domain::error]
//! Called-by: [tests]
//! Invariants: [hex HMAC-SHA256; constant-time MAC comparison; no timestamp invented]
//! Spec: Baseline §71.3; §52

use hmac::{Hmac, KeyInit, Mac};
use humaux_domain::error::ErrorCode;
use sha2::Sha256;

/// §71.3: authenticate `creem-signature` against unmodified bytes before parsing.
pub fn verify(header_value: Option<&str>, raw_body: &[u8], secret: &[u8]) -> Result<(), ErrorCode> {
    if secret.is_empty() {
        return Err(ErrorCode::Unauthorized);
    }
    let header = header_value.ok_or(ErrorCode::Unauthorized)?;
    let mut signature = [0; 32];
    hex::decode_to_slice(header, &mut signature).map_err(|_| ErrorCode::Unauthorized)?;
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(secret).map_err(|_| ErrorCode::Unauthorized)?;
    mac.update(raw_body);
    mac.verify_slice(&signature)
        .map_err(|_| ErrorCode::Unauthorized)
}

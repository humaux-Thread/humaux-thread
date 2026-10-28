//! `billing-worker::tests::signature` — raw-body authentication gate (§71.3).
//! Depends-on: crates=[humaux-domain]; services=[]; env=[]; modules=[billing-worker::signature, domain::error]
//! Called-by: [cargo-test]
//! Invariants: [independent RFC 4231 vector; malformed signatures and altered bytes rejected]
//! Spec: Baseline §71.3; §79.4
use humaux_billing_worker::signature::verify;
use humaux_domain::error::ErrorCode;
// §79.4: RFC 4231 case 1 fixture, not a credential.
const SECRET: [u8; 20] = [0x0b; 20];
const SIGNATURE: &str = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
#[test]
fn tampered_body_is_refused() {
    assert_eq!(
        verify(Some(SIGNATURE), b"Hi There!", &SECRET),
        Err(ErrorCode::Unauthorized)
    );
}
#[test]
fn signature_contract() {
    assert_eq!(verify(Some(SIGNATURE), b"Hi There", &SECRET), Ok(()));
    for header in [
        None,
        Some(""),
        Some("00"),
        Some("zz"),
        Some(&"00".repeat(32)),
        Some(&format!("{SIGNATURE}00")),
    ] {
        assert_eq!(
            verify(header, b"Hi There", &SECRET),
            Err(ErrorCode::Unauthorized)
        );
    }
    assert_eq!(
        verify(Some(SIGNATURE), b"Hi There", b"wrong fixture"),
        Err(ErrorCode::Unauthorized)
    );
    assert_eq!(
        verify(Some(SIGNATURE), b"Hi There", b""),
        Err(ErrorCode::Unauthorized)
    );
}

//! `application::tests::api_key` — Fixed §73.5 HMAC byte contract through the published API.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[application::api_key]
//! Called-by: [cargo-test]
//! Invariants: [public fixed test vector; never deployment credential material]
//! Spec: §73.5; ADR-0130

use humaux_application::api_key::compute_api_key_hash;

#[test]
fn known_keyed_hash_bytes() {
    // Fixed pre-extraction HMAC-SHA256 vector, independently checked with Python hmac.
    assert_eq!(
        compute_api_key_hash(b"server-side-pepper", "raw-key-value"),
        vec![
            182, 123, 117, 67, 190, 123, 228, 7, 92, 229, 238, 188, 63, 231, 71, 81, 127, 130, 188,
            162, 144, 42, 7, 20, 105, 168, 53, 105, 174, 123, 145, 160
        ]
    );
}

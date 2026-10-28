//! `gateway::tests::as_metadata` — G-M02-14 exact native AS metadata golden and capability sets.
//! Depends-on: crates=[serde_json]; services=[]; env=[]; modules=[gateway::oauth_http]
//! Called-by: [cargo-test]
//! Invariants: [byte-equal golden; exact capability and scope sets; unsupported endpoints are absent]
//! Spec: M02 D9; RFC 8414; MCP 2026-07-28; ADR-0125

use humaux_gateway::oauth_http::metadata_document;
use serde_json::{Value, json};

#[test]
fn g_m02_14_metadata_matches_golden() {
    assert_eq!(
        metadata_document("https://humaux.com"),
        include_str!("../../../contracts/oauth/as_metadata.json").trim_end()
    );
}

#[test]
fn g_m02_14_metadata_capabilities_are_exact() {
    let value: Value = serde_json::from_str(&metadata_document("https://humaux.com")).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 9);
    assert_eq!(value["issuer"], "https://humaux.com");
    for (key, path) in [
        ("authorization_endpoint", "/oauth/authorize"),
        ("token_endpoint", "/oauth/token"),
    ] {
        assert_eq!(value[key], format!("https://humaux.com{path}"));
    }
    assert_eq!(value["response_types_supported"], json!(["code"]));
    assert_eq!(
        value["grant_types_supported"],
        json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(value["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(
        value["token_endpoint_auth_methods_supported"],
        json!(["none"])
    );
    assert_eq!(
        value["scopes_supported"],
        json!([
            "context:read",
            "memory:write",
            "artifact:manage",
            "code:manage",
            "coordination:manage"
        ])
    );
    assert_eq!(
        value["authorization_response_iss_parameter_supported"],
        true
    );
    for key in [
        "registration_endpoint",
        "revocation_endpoint",
        "client_id_metadata_document_supported",
    ] {
        assert_eq!(value.get(key), None);
    }
}

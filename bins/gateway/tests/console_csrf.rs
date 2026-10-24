//! `gateway::tests::console_csrf` — G-M02-5 (M02 D6): the session-bound CSRF token and the `Sec-Fetch-Site` gate, through
//!   `application::session::csrf_token` and `protocol::edge::verify_csrf`.
//! Depends-on: crates=[humaux-application, humaux-protocol, uuid]; services=[]; env=[]; modules=[application::session, application::signed_token, protocol::edge]
//! Called-by: [cargo-test]
//! Invariants: [a token minted for session A is refused on session B; a cross-site, same-site or header-less state-changing
//!   request is refused even with the right token; a safe method is never checked; the unsigned double-submit of the old
//!   protocol::edge is gone, not kept beside the new path]
//! Spec: Baseline §73.6; M02 D6
//!
//! Pure: no database, no socket. Keys are fixed test bytes, not secrets.

use humaux_application::session::{SessionId, csrf_token};
use humaux_application::signed_token::TokenKeys;
use humaux_protocol::edge::{CSRF_HEADER_NAME, FetchSite, verify_csrf};
use uuid::Uuid;

fn keys(fill: u8) -> TokenKeys {
    TokenKeys::new(vec![fill; 32], None).expect("32-byte key")
}

fn session(n: u128) -> SessionId {
    SessionId(Uuid::from_u128(n))
}

/// What the gateway would compute for a request: the expected token of the request's own session against the header.
fn accepts(
    keys: &TokenKeys,
    request_session: SessionId,
    method: &str,
    site: Option<&str>,
    header: Option<&str>,
) -> bool {
    verify_csrf(
        method,
        FetchSite::from_header(site),
        header,
        &csrf_token(keys, request_session),
    )
}

/// G-M02-5: a token minted for session A is accepted on A and refused on session B.
#[test]
fn g_m02_5_token_minted_for_session_a_fails_on_session_b() {
    let k = keys(7);
    let (a, b) = (session(1), session(2));
    let token_a = csrf_token(&k, a);
    assert!(accepts(&k, a, "POST", Some("same-origin"), Some(&token_a)));
    assert!(
        !accepts(&k, b, "POST", Some("same-origin"), Some(&token_a)),
        "a token must be bound to the session that minted it"
    );
    assert!(accepts(
        &k,
        b,
        "POST",
        Some("same-origin"),
        Some(&csrf_token(&k, b))
    ));
}

/// G-M02-5: a token minted under another key is refused.
#[test]
fn g_m02_5_token_of_another_key_is_refused() {
    let s = session(1);
    let foreign = csrf_token(&keys(9), s);
    assert!(!accepts(
        &keys(7),
        s,
        "POST",
        Some("same-origin"),
        Some(&foreign)
    ));
}

/// G-M02-5: with the correct token, only `same-origin` and `none` pass a state-changing method; every other
/// `Sec-Fetch-Site` state, header-less included, is refused.
#[test]
fn g_m02_5_cross_site_post_with_the_right_token_is_refused() {
    let k = keys(7);
    let s = session(1);
    let token = csrf_token(&k, s);
    let verdicts: Vec<(Option<&str>, bool)> = [
        Some("same-origin"),
        Some("none"),
        Some("cross-site"),
        Some("same-site"),
        Some("bogus"),
        None,
    ]
    .into_iter()
    .map(|site| (site, accepts(&k, s, "POST", site, Some(&token))))
    .collect();
    assert_eq!(
        verdicts,
        vec![
            (Some("same-origin"), true),
            (Some("none"), true),
            (Some("cross-site"), false),
            (Some("same-site"), false),
            (Some("bogus"), false),
            (None, false),
        ]
    );
}

/// G-M02-5: a missing, empty or truncated header is refused on every state-changing method; safe methods skip the check.
#[test]
fn g_m02_5_missing_or_wrong_header_is_refused_and_safe_methods_skip() {
    let k = keys(7);
    let s = session(1);
    let token = csrf_token(&k, s);
    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        for header in [None, Some(""), Some(&token[..token.len() - 1])] {
            assert!(
                !accepts(&k, s, method, Some("same-origin"), header),
                "{method} {header:?}"
            );
        }
    }
    for method in ["GET", "HEAD", "OPTIONS"] {
        assert!(accepts(&k, s, method, Some("cross-site"), None), "{method}");
    }
    assert_eq!(CSRF_HEADER_NAME, "x-humaux-csrf-token");
}

/// The unsigned cookie-vs-header double-submit is removed from `protocol::edge`, not kept as a second path.
#[test]
fn g_m02_5_unsigned_double_submit_is_gone() {
    let edge = include_str!("../../../crates/protocol/src/edge.rs");
    for retired in [
        "fn verify_csrf_token",
        "fn generate_csrf_token",
        "CSRF_COOKIE_NAME",
        "fn csrf_cookie_attributes",
    ] {
        assert_eq!(edge.matches(retired).count(), 0, "{retired}");
    }
    assert_eq!(edge.matches("pub fn verify_csrf(").count(), 1);
}

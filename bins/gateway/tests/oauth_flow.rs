//! `gateway::tests::oauth_flow` — G-M02-7/8/9/14 through real HTTP, role_gateway and PostgreSQL doors.
//! Depends-on: crates=[axum, hex, humaux-adapters, humaux-application, humaux-domain, humaux-protocol,
//!   humaux-testkit, postgres, rand, serde_json, time, tokio, url, uuid];
//!   services=[HTTP(loopback), PostgreSQL(any) r=[control.oauth_authorization_codes, control.oauth_client_registrations, ops.email_outbox] w=[control.email_challenges, control.entitlement_snapshots, control.memberships, control.oauth_authorization_codes, control.oauth_client_registrations,
//!   control.oauth_grants, control.oauth_refresh_tokens, control.sessions, control.tenants, control.user_emails, control.users, ops.email_outbox]
//!   x=[control.bump_user_security_epoch], PostgreSQL(role_gateway)]; env=[CI, HUMAUX_TEST_PG_DSN];
//!   modules=[adapters::oauth_repo, adapters::postgres, adapters::session_repo, application::auth, application::login, application::oauth, application::session, application::signed_token, domain::error,
//!   domain::ids, gateway::auth_pages, gateway::bootstrap, gateway::guard, gateway::limiter, gateway::oauth_http, humaux-testkit, protocol::edge]
//! Called-by: [cargo-test]
//! Invariants: [fixture rows are unique and cleaned; missing DB on CI fails; token comparisons use production
//!   verification and the live grant; every expected refusal checks the exact wire object and no-store]
//! Spec: §73.5; §78.1; §79.2; M02 D3; M02 D4; M02 D9; ADR-0125

use humaux_adapters::{
    oauth_repo::{self, ClientKind, CodeIssue, GrantRecord, SecretHash},
    postgres::RuntimeDbPool,
    session_repo,
};
use humaux_application::{
    auth::AuthConfig,
    login::LoginVerifyOutcome,
    oauth::{self, ACCESS_TOKEN_LABEL, AccessTerms, GrantView, OAuthReason},
    session::SessionPolicy,
    signed_token::TokenKeys,
};
use humaux_domain::{
    error::ErrorCode,
    ids::{TenantId, UserId},
};
use humaux_gateway::{
    auth_pages::{self, AuthPagesConfig},
    bootstrap::passwordless_login_port,
    guard::{GatewayGuard, GuardRatePolicies, GuardSettings},
    limiter::RatePolicy,
    oauth_http::{self, OAuthHttpConfig},
};
use humaux_protocol::edge::TrustedProxyConfig;
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use serde_json::Value;
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, time::Duration};
use time::OffsetDateTime;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use uuid::Uuid;

const ORIGIN: &str = "https://as.example.test";
const NATIVE_RESOURCE: &str = "https://as.example.test/mcp";
const REDIRECT: &str = "https://client.example.test/cb";
const RESOURCE: &str = "https://resource.example.test/mcp";
// RFC 7636 Appendix B: base64url(SHA256(VERIFIER)), without padding.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn keys() -> TokenKeys {
    TokenKeys::new(vec![7; 32], None).expect("test key")
}
fn config(max: u64) -> OAuthHttpConfig {
    OAuthHttpConfig {
        keys: keys(),
        issuer: ORIGIN.to_owned(),
        resource: NATIVE_RESOURCE.to_owned(),
        login_return_ttl: Duration::from_secs(900),
        code_ttl: Duration::from_secs(300),
        access_ttl: Duration::from_secs(3600),
        refresh_ttl: Duration::from_secs(3600),
        grant_max_ttl: Duration::from_secs(max),
    }
}
fn dsn_as_role(dsn: &str) -> String {
    let sep = if dsn.contains('?') { '&' } else { '?' };
    format!("{dsn}{sep}options=-c%20role%3Drole_gateway")
}
struct Handle {
    rt: tokio::runtime::Runtime,
    gateway: RuntimeDbPool,
    admin: Client,
    dsn: String,
    tenant_id: Uuid,
    user_id: Uuid,
    client_id: String,
    scopes: Vec<String>,
}
impl Drop for Handle {
    fn drop(&mut self) {
        for sql in [
            "DELETE FROM ops.email_outbox WHERE user_id=$1",
            "DELETE FROM control.email_challenges WHERE user_id=$1",
            "DELETE FROM control.user_emails WHERE user_id=$1",
        ] {
            let _ = self.admin.execute(sql, &[&self.user_id]);
        }
        let _ = self.admin.execute(
            "DELETE FROM control.sessions WHERE user_id=$1",
            &[&self.user_id],
        );
        for sql in [
            "DELETE FROM control.entitlement_snapshots WHERE tenant_id=$1",
            "DELETE FROM control.memberships WHERE tenant_id=$1",
            "DELETE FROM control.oauth_refresh_tokens WHERE grant_id IN (SELECT grant_id FROM control.oauth_grants WHERE tenant_id=$1)",
            "DELETE FROM control.oauth_grants WHERE tenant_id=$1",
            "DELETE FROM control.oauth_authorization_codes WHERE tenant_id=$1",
            "DELETE FROM control.tenants WHERE tenant_id=$1",
        ] {
            let _ = self.admin.execute(sql, &[&self.tenant_id]);
        }
        let _ = self.admin.execute(
            "DELETE FROM control.oauth_client_registrations WHERE client_id=$1",
            &[&self.client_id],
        );
        let _ = self.admin.execute(
            "DELETE FROM control.users WHERE user_id=$1",
            &[&self.user_id],
        );
    }
}
struct OAuthFixture;
impl DbIntegrationFixture for OAuthFixture {
    type Handle = Handle;
    fn isolate() -> Result<Handle, DbFixtureSkipReason> {
        let dsn = match std::env::var("HUMAUX_TEST_PG_DSN") {
            Ok(dsn) => dsn,
            Err(_) => {
                assert!(
                    std::env::var_os("CI").is_none(),
                    "CI missing HUMAUX_TEST_PG_DSN"
                );
                return Err(DbFixtureSkipReason::NoDatabaseUrl);
            }
        };
        // dep: PostgreSQL(any) — fixture setup and inspection only
        let mut admin = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        let setup = |e: postgres::Error| DbFixtureSkipReason::IsolationSetupFailed(e.to_string());
        let tenant_id = admin.query_one("INSERT INTO control.tenants(name,state) VALUES ('oauth_flow fixture','ACTIVE') RETURNING tenant_id", &[]).map_err(setup)?.get(0);
        let user_id = admin
            .query_one(
                "INSERT INTO control.users(state) VALUES ('ACTIVE') RETURNING user_id",
                &[],
            )
            .map_err(setup)?
            .get(0);
        let client_id = format!("client-{}", Uuid::new_v4());
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        // dep: PostgreSQL(role_gateway) — the production doors under test
        let gateway = rt
            .block_on(RuntimeDbPool::connect(&dsn_as_role(&dsn)))
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        let h = Handle {
            rt,
            gateway,
            admin,
            dsn,
            tenant_id,
            user_id,
            client_id,
            scopes: vec!["context:read".to_owned(), "memory:write".to_owned()],
        };
        h.rt.block_on(async {
            let mut txn = oauth_repo::begin(&h.gateway).await?;
            assert!(
                txn.register_client(
                    &h.client_id,
                    ClientKind::Static,
                    &[REDIRECT.to_owned()],
                    &serde_json::json!({}),
                    None
                )
                .await?
            );
            txn.commit().await
        })
        .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(format!("{e:?}")))?;
        Ok(h)
    }
}
fn guard_settings() -> GuardSettings {
    let rate = || RatePolicy::new(10_000, 10_000).expect("positive");
    GuardSettings {
        credential_pepper: vec![9; 32],
        credential_pepper_previous: None,
        trusted_proxies: TrustedProxyConfig {
            trusted_proxy_cidrs: vec![],
            max_forwarded_hops: 1,
        },
        global_denylist: vec![],
        global_emergency_allowlist: vec![],
        tenant_network: BTreeMap::new(),
        rate_max_subjects: [50_000; 5],
        rates: GuardRatePolicies {
            preauth_ip: rate(),
            credential: rate(),
            user: rate(),
            tenant: rate(),
            operation: rate(),
            lock_timeout: Duration::from_secs(2),
            preauth_ipv6_prefix_bits: 64,
        },
        reservation_ttl: Duration::from_secs(30),
        handler_timeout: Duration::from_secs(5),
        finalize_timeout: Duration::from_secs(2),
        replay_ttl: Duration::from_secs(60),
    }
}
fn serve(h: &Handle, max: u64) -> SocketAddr {
    // dep: PostgreSQL(role_gateway) — §79.2: exercise the runtime role.
    let pool =
        h.rt.block_on(RuntimeDbPool::connect(&dsn_as_role(&h.dsn)))
            .expect("gateway pool");
    let guard = Arc::new(GatewayGuard::new(pool, guard_settings()).expect("guard"));
    let pages = AuthPagesConfig {
        keys: keys(),
        public_origin: ORIGIN.to_owned(),
        auth: AuthConfig::default(),
        mail_from: "no-reply@as.example.test".to_owned(),
        code_pepper: b"oauth-flow-fixture-login-pepper".to_vec(),
        recipient_allowlist: String::new(),
    };
    let login = passwordless_login_port(&guard, &pages);
    let router = oauth_http::router(Arc::clone(&guard), config(max), Arc::clone(&login))
        .merge(auth_pages::router(guard, pages, login));
    h.rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("serve");
        });
        address
    })
}
struct Reply {
    status: u16,
    headers: BTreeMap<String, String>,
    cookies: Vec<String>,
    body: String,
}
async fn http(address: SocketAddr, method: &str, path: &str, body: &str) -> Reply {
    http_with(address, method, path, &[], body).await
}

async fn http_with(
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Reply {
    // dep: HTTP(loopback) — production router and pre-auth guard
    let mut stream = TcpStream::connect(address).await.expect("connect");
    let extra: String = headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect();
    let raw = format!(
        "{method} {path} HTTP/1.1\r\nHost: as.example.test\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n{extra}\r\n{body}",
        body.len()
    );
    stream.write_all(raw.as_bytes()).await.expect("write");
    let mut raw = String::new();
    stream.read_to_string(&mut raw).await.expect("read");
    let (head, body) = raw.split_once("\r\n\r\n").expect("complete response");
    let mut lines = head.lines();
    let status = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let mut cookies = Vec::new();
    let headers = lines
        .map(|line| {
            let (key, value) = line.split_once(": ").unwrap();
            if key.eq_ignore_ascii_case("set-cookie") {
                cookies.push(value.to_owned());
            }
            (key.to_ascii_lowercase(), value.to_owned())
        })
        .collect();
    Reply {
        status,
        headers,
        cookies,
        body: body.to_owned(),
    }
}
fn post(h: &Handle, address: SocketAddr, body: &str) -> Reply {
    h.rt.block_on(http(address, "POST", "/oauth/token", body))
}
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
fn form(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(k, v)| format!("{k}={}", encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}
fn code_form(h: &Handle, code: &str, overrides: &[(&str, Option<&str>)]) -> String {
    let mut fields = BTreeMap::from([
        ("grant_type", "authorization_code"),
        ("client_id", h.client_id.as_str()),
        ("code", code),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
        ("resource", RESOURCE),
    ]);
    for (key, value) in overrides {
        if let Some(value) = value {
            fields.insert(key, value);
        } else {
            fields.remove(key);
        }
    }
    form(&fields.into_iter().collect::<Vec<_>>())
}
fn issue_code(h: &Handle) -> String {
    let code = Uuid::new_v4().to_string();
    h.rt.block_on(async {
        let mut txn = oauth_repo::begin(&h.gateway).await?;
        assert!(
            txn.issue_code(
                &CodeIssue {
                    code_hash: &SecretHash::of_secret(&code),
                    client_id: &h.client_id,
                    redirect_uri: REDIRECT,
                    pkce_challenge: CHALLENGE,
                    resource: RESOURCE,
                    user_id: UserId(h.user_id),
                    tenant_id: TenantId(h.tenant_id),
                    workspace_id: None,
                    scopes: &h.scopes
                },
                Duration::from_secs(300)
            )
            .await?
            .is_some()
        );
        txn.commit().await
    })
    .expect("issue code");
    code
}
fn issued(h: &Handle, address: SocketAddr) -> Value {
    let code = issue_code(h);
    success(&post(h, address, &code_form(h, &code, &[])), 3600)
}
fn success(reply: &Reply, max: u64) -> Value {
    assert_eq!(reply.status, 200, "token response status");
    assert_eq!(
        reply.headers.get("cache-control").map(String::as_str),
        Some("no-store")
    );
    let value: Value = serde_json::from_str(&reply.body).expect("JSON");
    let fields = value
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        fields,
        [
            "access_token",
            "expires_in",
            "refresh_token",
            "scope",
            "token_type"
        ]
    );
    assert_eq!(value["token_type"], "Bearer");
    assert_eq!(value["scope"], "context:read memory:write");
    let expires = value["expires_in"]
        .as_u64()
        .expect("whole positive seconds");
    assert!((1..=max).contains(&expires));
    assert_eq!(value["refresh_token"].as_str().unwrap().len(), 64);
    let claims = decode(&value);
    assert_eq!(claims.resource, RESOURCE);
    assert_eq!(claims.scopes, ["context:read", "memory:write"]);
    value
}
fn denied(reply: &Reply, reason: OAuthReason) {
    assert_eq!(reply.status, 400, "refusal status");
    assert_eq!(
        reply.headers.get("cache-control").map(String::as_str),
        Some("no-store")
    );
    let value: Value = serde_json::from_str(&reply.body).expect("JSON");
    assert_eq!(
        value,
        serde_json::json!({"error": reason.row().unwrap().wire_error})
    );
}
fn decode(tokens: &Value) -> AccessTerms {
    let raw = keys()
        .verify(
            &ACCESS_TOKEN_LABEL,
            tokens["access_token"].as_str().unwrap(),
        )
        .expect("access MAC");
    oauth::parse_access_token_payload(&raw).expect("access claims")
}
fn refresh(h: &Handle, address: SocketAddr, tokens: &Value, client: &str) -> Reply {
    post(
        h,
        address,
        &form(&[
            ("grant_type", "refresh_token"),
            ("client_id", client),
            ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ("scope", "artifact:manage code:manage"),
        ]),
    )
}
fn grant_count(h: &mut Handle) -> i64 {
    h.admin
        .query_one(
            "SELECT count(*) FROM control.oauth_grants WHERE tenant_id=$1",
            &[&h.tenant_id],
        )
        .unwrap()
        .get(0)
}
fn lookup(h: &Handle, grant: Uuid) -> GrantRecord {
    h.rt.block_on(async {
        let mut txn = oauth_repo::begin(&h.gateway).await?;
        let grant = txn.lookup_grant(grant).await?.expect("grant");
        txn.commit().await?;
        Ok::<_, ErrorCode>(grant)
    })
    .expect("lookup")
}
fn view(grant: &GrantRecord) -> GrantView<'_> {
    GrantView {
        client_id: &grant.client_id,
        resource: &grant.resource,
        scopes: &grant.scopes,
        active: grant.status == Some(oauth_repo::GrantStatus::Active),
        revoked_at: grant.revoked_at,
        grant_max_expires_at: grant.grant_max_expires_at,
        user_epoch_snapshot: grant.user_epoch_snapshot,
        tenant_epoch_snapshot: grant.tenant_epoch_snapshot,
        live_user_epoch: grant.live_user_epoch,
        live_tenant_epoch: grant.live_tenant_epoch,
    }
}
fn revoked(h: &mut Handle, grant_id: Uuid, reason: &str) {
    let rows = h
        .admin
        .query(
            "SELECT status,revoke_reason FROM control.oauth_grants WHERE grant_id=$1",
            &[&grant_id],
        )
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].get::<_, String>(0), rows[0].get::<_, String>(1)),
        ("REVOKED".to_owned(), reason.to_owned())
    );
}

#[test]
fn g_m02_7_good_exchange_and_replay() {
    run_db_fixture::<OAuthFixture, _>("G-M02-7 exchange/replay", |mut h| {
        let address = serve(&h, 7200);
        let code = issue_code(&h);
        success(&post(&h, address, &code_form(&h, &code, &[])), 3600);
        let used: bool = h.admin.query_one("SELECT used_at IS NOT NULL FROM control.oauth_authorization_codes WHERE code_hash=$1", &[&SecretHash::of_secret(&code).as_bytes().as_slice()]).unwrap().get(0);
        assert!(used);
        assert_eq!(grant_count(&mut h), 1);
        let active: i64 = h
            .admin
            .query_one(
                "SELECT count(*) FROM control.oauth_grants WHERE tenant_id=$1 AND status='ACTIVE'",
                &[&h.tenant_id],
            )
            .unwrap()
            .get(0);
        assert_eq!(active, 1);
        denied(
            &post(&h, address, &code_form(&h, &code, &[])),
            OAuthReason::CODE_INVALID,
        );
        assert_eq!(grant_count(&mut h), 1);
    });
}
#[test]
fn g_m02_7_wrong_verifier_spends_the_code() {
    run_db_fixture::<OAuthFixture, _>("G-M02-7 verifier", |mut h| {
        let address = serve(&h, 7200);
        let code = issue_code(&h);
        denied(
            &post(
                &h,
                address,
                &code_form(
                    &h,
                    &code,
                    &[(
                        "code_verifier",
                        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                    )],
                ),
            ),
            OAuthReason::VERIFIER_MISMATCH,
        );
        denied(
            &post(&h, address, &code_form(&h, &code, &[])),
            OAuthReason::CODE_INVALID,
        );
        assert_eq!(grant_count(&mut h), 0);
    });
}
#[test]
fn g_m02_7_resource_redirect_and_client_are_bound() {
    run_db_fixture::<OAuthFixture, _>("G-M02-7 bindings", |mut h| {
        let address = serve(&h, 7200);
        for (key, value, reason) in [
            (
                "resource",
                Some("https://foreign.example.test/mcp"),
                OAuthReason::CODE_RESOURCE_MISMATCH,
            ),
            (
                "redirect_uri",
                Some("https://foreign.example.test/cb"),
                OAuthReason::CODE_REDIRECT_MISMATCH,
            ),
            ("redirect_uri", None, OAuthReason::CODE_REDIRECT_MISMATCH),
            (
                "client_id",
                Some("foreign"),
                OAuthReason::CODE_CLIENT_MISMATCH,
            ),
        ] {
            let code = issue_code(&h);
            denied(
                &post(&h, address, &code_form(&h, &code, &[(key, value)])),
                reason,
            );
            denied(
                &post(&h, address, &code_form(&h, &code, &[])),
                OAuthReason::CODE_INVALID,
            );
        }
        assert_eq!(grant_count(&mut h), 0);
    });
}
#[test]
fn g_m02_7_precheck_preserves_code_and_unsupported_grant_is_refused() {
    run_db_fixture::<OAuthFixture, _>("G-M02-7 precheck", |mut h| {
        let address = serve(&h, 7200);
        let code = issue_code(&h);
        denied(
            &post(
                &h,
                address,
                &code_form(&h, &code, &[("code_verifier", Some(&"a".repeat(42)))]),
            ),
            OAuthReason::VERIFIER_MALFORMED,
        );
        success(&post(&h, address, &code_form(&h, &code, &[])), 3600);
        denied(
            &post(&h, address, &form(&[("grant_type", "password")])),
            OAuthReason::GRANT_TYPE_UNSUPPORTED,
        );
        assert_eq!(grant_count(&mut h), 1);
    });
}
#[test]
fn g_m02_8_reuse_revokes_successor_and_both_access_tokens() {
    run_db_fixture::<OAuthFixture, _>("G-M02-8 reuse", |mut h| {
        let address = serve(&h, 7200);
        let first = issued(&h, address);
        let second = success(&refresh(&h, address, &first, &h.client_id), 3600);
        assert_ne!(first["refresh_token"], second["refresh_token"]);
        denied(
            &refresh(&h, address, &first, &h.client_id),
            OAuthReason::REFRESH_REUSED,
        );
        denied(
            &refresh(&h, address, &second, &h.client_id),
            OAuthReason::REFRESH_REJECTED,
        );
        revoked(&mut h, decode(&first).grant_id, "REFRESH_REUSE");
        for tokens in [&first, &second] {
            let claims = decode(tokens);
            let grant = lookup(&h, claims.grant_id);
            assert_eq!(
                oauth::check_grant(&view(&grant), OffsetDateTime::now_utc())
                    .unwrap_err()
                    .refusal
                    .reason,
                OAuthReason::GRANT_CLOSED
            );
        }
        assert_eq!(grant_count(&mut h), 1);
    });
}
#[test]
fn g_m02_8_reused_access_tokens_fail_the_live_grant_check() {
    run_db_fixture::<OAuthFixture, _>("G-M02-8 access reuse", |h| {
        let address = serve(&h, 7200);
        let first = issued(&h, address);
        let second = success(&refresh(&h, address, &first, &h.client_id), 3600);
        denied(
            &refresh(&h, address, &first, &h.client_id),
            OAuthReason::REFRESH_REUSED,
        );
        for tokens in [&first, &second] {
            let claims = decode(tokens);
            assert_eq!(
                oauth::check_grant(
                    &view(&lookup(&h, claims.grant_id)),
                    OffsetDateTime::now_utc()
                )
                .unwrap_err()
                .refusal
                .reason,
                OAuthReason::GRANT_CLOSED
            );
        }
    });
}
#[test]
fn g_m02_8_wrong_client_rolls_back_rotation() {
    run_db_fixture::<OAuthFixture, _>("G-M02-8 rollback", |mut h| {
        let address = serve(&h, 7200);
        let tokens = issued(&h, address);
        denied(
            &refresh(&h, address, &tokens, "foreign"),
            OAuthReason::REFRESH_CLIENT_MISMATCH,
        );
        success(&refresh(&h, address, &tokens, &h.client_id), 3600);
        assert_eq!(grant_count(&mut h), 1);
    });
}
fn epoch_test(tenant: bool) {
    run_db_fixture::<OAuthFixture, _>("G-M02-9 epoch", |mut h| {
        let address = serve(&h, 7200);
        let tokens = issued(&h, address);
        if tenant {
            h.admin
                .execute(
                    "UPDATE control.tenants SET security_epoch=security_epoch+1 WHERE tenant_id=$1",
                    &[&h.tenant_id],
                )
                .unwrap();
        } else {
            h.admin
                .query_one("SELECT control.bump_user_security_epoch($1)", &[&h.user_id])
                .unwrap();
        }
        denied(
            &refresh(&h, address, &tokens, &h.client_id),
            OAuthReason::GRANT_EPOCH_STALE,
        );
        revoked(&mut h, decode(&tokens).grant_id, "SECURITY_EPOCH");
        denied(
            &refresh(&h, address, &tokens, &h.client_id),
            OAuthReason::REFRESH_REJECTED,
        );
    });
}
#[test]
fn g_m02_9_user_epoch_revokes() {
    epoch_test(false);
}
#[test]
fn g_m02_9_tenant_epoch_revokes() {
    epoch_test(true);
}
#[test]
fn g_m02_9_absolute_grant_expiry_rejects_refresh() {
    run_db_fixture::<OAuthFixture, _>("G-M02-9 expiry", |mut h| {
        let address = serve(&h, 7200);
        let tokens = issued(&h, address);
        h.admin.execute("UPDATE control.oauth_grants SET issued_at=now()-interval '2 seconds', grant_max_expires_at=now()-interval '1 second' WHERE grant_id=$1", &[&decode(&tokens).grant_id]).unwrap();
        denied(
            &refresh(&h, address, &tokens, &h.client_id),
            OAuthReason::REFRESH_REJECTED,
        );
    });
}
#[test]
fn g_m02_9_access_expiry_never_exceeds_grant_ceiling() {
    run_db_fixture::<OAuthFixture, _>("G-M02-9 cap", |h| {
        let address = serve(&h, 120);
        let tokens = issued(&h, address);
        assert!(tokens["expires_in"].as_u64().unwrap() <= 120);
        let claims = decode(&tokens);
        assert!(claims.expires_at <= lookup(&h, claims.grant_id).grant_max_expires_at);
        let rotated = success(&refresh(&h, address, &tokens, &h.client_id), 120);
        assert!(decode(&rotated).expires_at <= lookup(&h, claims.grant_id).grant_max_expires_at);
    });
}
#[test]
fn g_m02_14_served_metadata_is_the_document() {
    run_db_fixture::<OAuthFixture, _>("G-M02-14 served metadata", |h| {
        let address = serve(&h, 7200);
        let reply = h.rt.block_on(http(
            address,
            "GET",
            "/.well-known/oauth-authorization-server",
            "",
        ));
        assert_eq!(reply.status, 200);
        assert_eq!(
            reply.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(reply.body, oauth_http::metadata_document(ORIGIN));
        assert_eq!(
            h.rt.block_on(http(
                address,
                "GET",
                "/.well-known/oauth-authorization-server/x",
                ""
            ))
            .status,
            404
        );
    });
}
#[test]
fn g_m02_7_duplicate_and_absent_parameters_fail_without_minting() {
    run_db_fixture::<OAuthFixture, _>("G-M02-7 absent and duplicate", |mut h| {
        let address = serve(&h, 7200);
        denied(&post(&h, address, ""), OAuthReason::GRANT_TYPE_UNSUPPORTED);
        denied(
            &post(&h, address, "grant_type=refresh_token"),
            OAuthReason::REFRESH_REJECTED,
        );
        let code = issue_code(&h);
        let body = code_form(&h, &code, &[]);
        denied(
            &post(&h, address, &format!("{body}&code={code}")),
            OAuthReason::CODE_INVALID,
        );
        denied(
            &post(&h, address, &code_form(&h, &code, &[("code", None)])),
            OAuthReason::CODE_INVALID,
        );
        denied(
            &post(&h, address, &format!("{body}&code_verifier={VERIFIER}")),
            OAuthReason::VERIFIER_MISSING,
        );
        assert_eq!(grant_count(&mut h), 0);
        success(&post(&h, address, &body), 3600);
        assert_eq!(grant_count(&mut h), 1);
    });
}

#[test]
fn g_m02_7_disabled_client_spends_code_without_issuing_grant() {
    run_db_fixture::<OAuthFixture, _>("G-M02-7 closed grant", |mut h| {
        let address = serve(&h, 7200);
        let code = issue_code(&h);
        h.admin.execute("UPDATE control.oauth_client_registrations SET disabled_at=now() WHERE client_id=$1", &[&h.client_id]).unwrap();
        denied(
            &post(&h, address, &code_form(&h, &code, &[])),
            OAuthReason::GRANT_CLOSED,
        );
        denied(
            &post(&h, address, &code_form(&h, &code, &[])),
            OAuthReason::CODE_INVALID,
        );
        assert_eq!(grant_count(&mut h), 0);
    });
}

#[test]
fn g_m02_8_wrong_resource_rolls_back_rotation() {
    run_db_fixture::<OAuthFixture, _>("G-M02-8 resource rollback", |mut h| {
        let address = serve(&h, 7200);
        let tokens = issued(&h, address);
        let body = form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ("client_id", &h.client_id),
            ("resource", "https://foreign.example.test/mcp"),
        ]);
        denied(
            &post(&h, address, &body),
            OAuthReason::REFRESH_RESOURCE_MISMATCH,
        );
        success(&refresh(&h, address, &tokens, &h.client_id), 3600);
        assert_eq!(grant_count(&mut h), 1);
    });
}

#[test]
fn g_m02_8_unknown_refresh_secret_cannot_mint() {
    run_db_fixture::<OAuthFixture, _>("G-M02-8 unknown secret", |mut h| {
        let address = serve(&h, 7200);
        let unknown = hex::encode(rand::random::<[u8; 32]>());
        let body = form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &unknown),
            ("client_id", &h.client_id),
            ("resource", RESOURCE),
        ]);
        denied(&post(&h, address, &body), OAuthReason::REFRESH_REJECTED);
        assert_eq!(grant_count(&mut h), 0);
    });
}

fn authorize_url(client: &str, redirect: &str, method: &str) -> String {
    format!(
        "/oauth/authorize?{}",
        form(&[
            ("client_id", client),
            ("redirect_uri", redirect),
            ("response_type", "code"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", method),
            ("resource", NATIVE_RESOURCE),
            ("scope", "context:read"),
            ("state", "state + & 東京"),
        ])
    )
}

fn session_cookie(h: &Handle) -> String {
    let session =
        h.rt.block_on(session_repo::issue(
            &h.gateway,
            &SessionPolicy::from(&AuthConfig::default()),
            LoginVerifyOutcome::Accepted(UserId(h.user_id)),
        ))
        .unwrap()
        .unwrap();
    format!("__Host-humaux_session={}", session.secret.cookie_value())
}

fn add_active_membership(h: &mut Handle, tenant: Uuid) {
    h.admin.execute("INSERT INTO control.memberships(tenant_id,user_id,role,state) VALUES($1,$2,'OWNER','ACTIVE')",
        &[&tenant, &h.user_id]).unwrap();
}

fn add_entitlement(h: &mut Handle, tenant: Uuid) {
    let feature = serde_json::json!({"mcp.billable_operations.per_period": {
        "limit": 50, "period": "calendar_month", "period_start": "2000-01-01T00:00:00Z",
        "period_end": "2100-01-01T00:00:00Z", "charge_policy": "success_only"
    }});
    h.admin.execute("INSERT INTO control.entitlement_snapshots(tenant_id,effective,source_grant_ids,computed_at) VALUES($1,$2,ARRAY[]::uuid[],clock_timestamp())",
        &[&tenant, &feature]).unwrap();
}

fn browser_get(h: &Handle, address: SocketAddr, path: &str, cookie: &str) -> Reply {
    h.rt.block_on(http_with(address, "GET", path, &[("Cookie", cookie)], ""))
}

fn hidden<'a>(reply: &'a Reply, name: &str) -> &'a str {
    reply
        .body
        .split_once(&format!(r#"name="{name}" value=""#))
        .unwrap()
        .1
        .split('"')
        .next()
        .unwrap()
}

fn consent_body(page: &Reply, decision: &str) -> String {
    form(&[
        ("ticket", hidden(page, "ticket")),
        ("csrf", hidden(page, "csrf")),
        ("decision", decision),
    ])
}

fn browser_consent(
    h: &Handle,
    address: SocketAddr,
    cookie: &str,
    origin: &str,
    body: &str,
) -> Reply {
    h.rt.block_on(http_with(
        address,
        "POST",
        "/oauth/authorize",
        &[
            ("Cookie", cookie),
            ("Origin", origin),
            ("Sec-Fetch-Site", "same-origin"),
        ],
        body,
    ))
}

fn callback(reply: &Reply) -> BTreeMap<String, String> {
    assert_eq!(reply.status, 303, "{}", reply.body);
    let url = url::Url::parse(&reply.headers["location"]).unwrap();
    assert_eq!(url.as_str().split('?').next(), Some(REDIRECT));
    url.query_pairs().into_owned().collect()
}

#[test]
fn m02_10b_rejects_zero_active_tenants() {
    run_db_fixture::<OAuthFixture, _>("m02_10b_rejects_zero_active_tenants", |mut h| {
        let tenant = h.tenant_id;
        add_active_membership(&mut h, tenant);
        add_entitlement(&mut h, tenant);
        h.admin.execute("UPDATE control.memberships SET state='SUSPENDED' WHERE tenant_id=$1 AND user_id=$2",
            &[&tenant, &h.user_id]).unwrap();
        let path = authorize_url(&h.client_id, REDIRECT, "S256");
        assert_eq!(
            browser_get(&h, serve(&h, 7200), &path, &session_cookie(&h)).status,
            403
        );
    });
}

#[test]
fn m02_10b_rejects_no_entitlement() {
    run_db_fixture::<OAuthFixture, _>("m02_10b_rejects_no_entitlement", |mut h| {
        let tenant = h.tenant_id;
        add_active_membership(&mut h, tenant);
        let path = authorize_url(&h.client_id, REDIRECT, "S256");
        assert_eq!(
            browser_get(&h, serve(&h, 7200), &path, &session_cookie(&h)).status,
            403
        );
    });
}

#[test]
fn m02_10b_rejects_multiple_active_tenants() {
    run_db_fixture::<OAuthFixture, _>("m02_10b_rejects_multiple_active_tenants", |mut h| {
        let address = serve(&h, 7200);
        let session = session_cookie(&h);
        let path = authorize_url(&h.client_id, REDIRECT, "S256");
        let tenant = h.tenant_id;
        add_active_membership(&mut h, tenant);
        add_entitlement(&mut h, tenant);
        let page = browser_get(&h, address, &path, &session);
        assert_eq!(page.status, 200, "sole entitled tenant");
        let second: Uuid = h.admin.query_one("INSERT INTO control.tenants(name,state) VALUES ('oauth second fixture','ACTIVE') RETURNING tenant_id", &[]).unwrap().get(0);
        add_active_membership(&mut h, second);
        add_entitlement(&mut h, second);
        let multiple = browser_get(&h, address, &path, &session);
        let stale = browser_consent(&h, address, &session, ORIGIN, &consent_body(&page, "allow"));
        h.admin
            .execute(
                "DELETE FROM control.entitlement_snapshots WHERE tenant_id=$1",
                &[&second],
            )
            .unwrap();
        h.admin
            .execute(
                "DELETE FROM control.memberships WHERE tenant_id=$1",
                &[&second],
            )
            .unwrap();
        h.admin
            .execute("DELETE FROM control.tenants WHERE tenant_id=$1", &[&second])
            .unwrap();
        assert_eq!(multiple.status, 403, "multiple active entitled tenants");
        assert_eq!(stale.status, 403, "changed authority after GET");
    });
}

#[test]
fn m02_10b_returns_to_authorize_after_real_login() {
    run_db_fixture::<OAuthFixture, _>("m02_10b_returns_to_authorize_after_real_login", |mut h| {
        let tenant = h.tenant_id;
        add_active_membership(&mut h, tenant);
        add_entitlement(&mut h, tenant);
        let email = format!("{}@as.example.test", h.user_id);
        h.admin.execute("INSERT INTO control.user_emails(user_id,original_email,canonical_email) VALUES($1,$2,$2)",
            &[&h.user_id, &email]).unwrap();
        let addr = serve(&h, 7200);
        let path = authorize_url(&h.client_id, REDIRECT, "S256");
        let redirect = browser_get(&h, addr, &path, "");
        assert_eq!(redirect.headers["location"], "/auth/login");
        let cookie = |reply: &Reply, prefix: &str| {
            reply
                .cookies
                .iter()
                .find(|line| line.starts_with(prefix))
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned()
        };
        let continuation = cookie(&redirect, "__Host-humaux_oauth_return=");
        let login = h.rt.block_on(http_with(
            addr,
            "POST",
            "/auth/login",
            &[("Origin", ORIGIN), ("Cookie", &continuation)],
            &form(&[("email", &email)]),
        ));
        let pending = cookie(&login, "__Host-humaux_login=");
        let code: String = h.admin.query_one("SELECT payload->>'code' FROM ops.email_outbox WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1",
            &[&h.user_id]).unwrap().get(0);
        let cookies = format!("{pending}; {continuation}");
        let reply = h.rt.block_on(http_with(
            addr,
            "POST",
            "/auth/code",
            &[("Origin", ORIGIN), ("Cookie", &cookies)],
            &form(&[("code", &code)]),
        ));
        assert_eq!(reply.status, 303);
        assert_eq!(reply.headers["location"], path);
        let session = cookie(&reply, "__Host-humaux_session=");
        assert_eq!(browser_get(&h, addr, &path, &session).status, 200);
    });
}

#[test]
fn m02_10b_authorize_and_consent() {
    run_db_fixture::<OAuthFixture, _>("m02_10b_authorize_and_consent", |mut h| {
        let tenant = h.tenant_id;
        add_active_membership(&mut h, tenant);
        add_entitlement(&mut h, tenant);
        let address = serve(&h, 7200);
        let session = session_cookie(&h);
        let path = authorize_url(&h.client_id, REDIRECT, "S256");
        let pending = browser_get(&h, address, &path, "");
        assert_eq!(pending.status, 303);
        assert_eq!(pending.headers["location"], "/auth/login");
        assert!(
            pending
                .cookies
                .iter()
                .any(|c| c.starts_with("__Host-humaux_oauth_return=") && c.contains("HttpOnly"))
        );
        let wrong = browser_get(
            &h,
            address,
            &authorize_url(&h.client_id, "https://invalid.example.test", "S256"),
            &session,
        );
        assert_eq!(wrong.status, 400);
        assert!(!wrong.headers.contains_key("location"));
        let invalid_pkce = browser_get(
            &h,
            address,
            &authorize_url(&h.client_id, REDIRECT, "plain"),
            &session,
        );
        let error = callback(&invalid_pkce);
        assert_eq!(error["iss"], ORIGIN);
        assert!(!error.contains_key("code"));
        let page = browser_get(&h, address, &path, &session);
        assert_eq!(page.status, 200);
        let body = consent_body(&page, "allow");
        assert_eq!(
            browser_consent(&h, address, &session, "https://wrong.example.test", &body).status,
            403
        );
        assert_eq!(
            browser_consent(&h, address, &session_cookie(&h), ORIGIN, &body).status,
            403
        );
        let denied = browser_consent(&h, address, &session, ORIGIN, &consent_body(&page, "deny"));
        assert_eq!(callback(&denied)["error"], "access_denied");
        let allowed = browser_consent(&h, address, &session, ORIGIN, &body);
        let params = callback(&allowed);
        assert_eq!(params["iss"], ORIGIN);
        assert_eq!(params["state"], "state + & 東京");
        let tokens = post(
            &h,
            address,
            &code_form(&h, &params["code"], &[("resource", Some(NATIVE_RESOURCE))]),
        );
        assert_eq!(tokens.status, 200, "{}", tokens.body);
    });
}

#[test]
fn m02_10b_preregistered_client_contract() {
    run_db_fixture::<OAuthFixture, _>("m02_10b_preregistered_client_contract", |mut h| {
        let tenant = h.tenant_id;
        add_active_membership(&mut h, tenant);
        add_entitlement(&mut h, tenant);
        let address = serve(&h, 7200);
        let session = session_cookie(&h);
        for name in ["claude-code", "codex", "claude-ai", "chatgpt"] {
            // These are server contract fixtures for already registered clients (M02 X-M02-2).
            let client = format!("{name}-{}", h.client_id);
            h.rt.block_on(async {
                let mut txn = oauth_repo::begin(&h.gateway).await.unwrap();
                assert!(
                    txn.register_client(
                        &client,
                        ClientKind::Static,
                        &[REDIRECT.to_owned()],
                        &serde_json::json!({}),
                        None
                    )
                    .await
                    .unwrap()
                );
                txn.commit().await.unwrap();
            });
            let page = browser_get(
                &h,
                address,
                &authorize_url(&client, REDIRECT, "S256"),
                &session,
            );
            let error = browser_get(
                &h,
                address,
                &authorize_url(&client, REDIRECT, "plain"),
                &session,
            );
            h.admin
                .execute(
                    "DELETE FROM control.oauth_client_registrations WHERE client_id=$1",
                    &[&client],
                )
                .unwrap();
            assert_eq!(page.status, 200, "{name}");
            assert_eq!(callback(&error)["iss"], ORIGIN, "{name}");
        }
    });
}

#[test]
fn m02_10b_revoke_is_client_bound_and_idempotent() {
    run_db_fixture::<OAuthFixture, _>("m02_10b_revoke_is_client_bound_and_idempotent", |h| {
        let address = serve(&h, 7200);
        let tokens = post(&h, address, &code_form(&h, &issue_code(&h), &[]));
        assert_eq!(tokens.status, 200);
        let value: Value = serde_json::from_str(&tokens.body).unwrap();
        let refresh = value["refresh_token"].as_str().unwrap();
        let revoke = |client: &str, token: &str| {
            h.rt.block_on(http(
                address,
                "POST",
                "/oauth/revoke",
                &form(&[("client_id", client), ("token", token)]),
            ))
        };
        assert_eq!(revoke("different-client", refresh).status, 200);
        let access = decode(&value);
        assert_eq!(
            lookup(&h, access.grant_id).status,
            Some(oauth_repo::GrantStatus::Active)
        );
        assert_eq!(revoke(&h.client_id, refresh).status, 200);
        assert_eq!(revoke(&h.client_id, refresh).status, 200);
        assert_eq!(
            lookup(&h, access.grant_id).status,
            Some(oauth_repo::GrantStatus::Revoked)
        );
    });
}

#[test]
fn m02_10b_review_entitlement_revocation_wins_pending_issuance() {
    run_db_fixture::<OAuthFixture, _>("M02-10b review: entitlement revocation", |mut h| {
        let tenant = h.tenant_id;
        add_active_membership(&mut h, tenant);
        add_entitlement(&mut h, tenant);
        let address = serve(&h, 7200);
        let session = session_cookie(&h);
        let path = authorize_url(&h.client_id, REDIRECT, "S256");
        let page = browser_get(&h, address, &path, &session);
        assert_eq!(page.status, 200);
        let body = consent_body(&page, "allow");

        // On the old path the plain entitlement read sees the prior row version, but
        // the code's client FK keeps issuance pending until the revocation commits.
        let mut revoke = h.admin.transaction().unwrap();
        revoke.query_one(
            "SELECT client_id FROM control.oauth_client_registrations WHERE client_id=$1 FOR UPDATE",
            &[&h.client_id],
        ).unwrap();
        assert_eq!(
            revoke
                .execute(
                    "UPDATE control.entitlement_snapshots SET effective='{}' WHERE tenant_id=$1",
                    &[&tenant]
                )
                .unwrap(),
            1
        );
        let request = h.rt.spawn(async move {
            http_with(
                address,
                "POST",
                "/oauth/authorize",
                &[
                    ("Cookie", &session),
                    ("Origin", ORIGIN),
                    ("Sec-Fetch-Site", "same-origin"),
                ],
                &body,
            )
            .await
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let waiting: bool = revoke.query_one(
                "SELECT EXISTS (SELECT FROM pg_locks WHERE locktype='transactionid' AND NOT granted \
                 AND pg_backend_pid() = ANY(pg_blocking_pids(pid)))",
                &[],
            ).unwrap().get(0);
            if waiting {
                break;
            }
            assert!(
                !request.is_finished() && std::time::Instant::now() < deadline,
                "issuance did not reach the DB barrier"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        revoke.commit().unwrap();
        let reply = h.rt.block_on(request).unwrap();
        assert_eq!(reply.status, 403, "revocation must prevent code issuance");
        assert!(!reply.headers.contains_key("location"));
        assert_eq!(authorization_code_count(&mut h), 0);
    });
}

#[test]
fn m02_10b_review_entitlement_expiry_wins_pending_issuance() {
    run_db_fixture::<OAuthFixture, _>("M02-10b review: entitlement expiry", |mut h| {
        let tenant = h.tenant_id;
        add_active_membership(&mut h, tenant);
        add_entitlement(&mut h, tenant);
        let address = serve(&h, 7200);
        let session = session_cookie(&h);
        let path = authorize_url(&h.client_id, REDIRECT, "S256");
        let page = browser_get(&h, address, &path, &session);
        assert_eq!(page.status, 200);
        let body = consent_body(&page, "allow");

        let expires_at: String = h
            .admin
            .query_one(
                r#"UPDATE control.entitlement_snapshots SET effective = jsonb_set(effective,
                 '{mcp.billable_operations.per_period,period_end}', to_jsonb(to_char(
                 (clock_timestamp() + interval '5 seconds') AT TIME ZONE 'UTC',
                 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))) WHERE tenant_id=$1
                 RETURNING effective #>> '{mcp.billable_operations.per_period,period_end}'"#,
                &[&tenant],
            )
            .unwrap()
            .get(0);
        // The client's FK blocks the insert after the consent entitlement check.
        let mut barrier = h.admin.transaction().unwrap();
        barrier.query_one(
            "SELECT client_id FROM control.oauth_client_registrations WHERE client_id=$1 FOR UPDATE",
            &[&h.client_id],
        ).unwrap();
        let request = h.rt.spawn(async move {
            http_with(
                address,
                "POST",
                "/oauth/authorize",
                &[
                    ("Cookie", &session),
                    ("Origin", ORIGIN),
                    ("Sec-Fetch-Site", "same-origin"),
                ],
                &body,
            )
            .await
        });
        wait_for_code_insert(&mut barrier, &request);
        let still_valid: bool = barrier
            .query_one(
                "SELECT clock_timestamp() < $1::text::timestamptz",
                &[&expires_at],
            )
            .unwrap()
            .get(0);
        assert!(still_valid, "issuance must reach the insert before expiry");
        barrier
            .query_one(
                "SELECT pg_sleep_until($1::text::timestamptz)",
                &[&expires_at],
            )
            .unwrap();
        barrier.commit().unwrap();
        let reply = h.rt.block_on(request).unwrap();
        assert_eq!(reply.status, 403, "expiry must prevent code issuance");
        assert!(!reply.headers.contains_key("location"));
        assert_eq!(authorization_code_count(&mut h), 0);
    });
}

#[test]
fn m02_10b_review_membership_deactivation_wins_pending_issuance() {
    membership_change_wins_pending_issuance(false);
}

#[test]
fn m02_10b_review_membership_second_tenant_wins_pending_issuance() {
    membership_change_wins_pending_issuance(true);
}

fn membership_change_wins_pending_issuance(add_second_tenant: bool) {
    run_db_fixture::<OAuthFixture, _>("M02-10b review: membership change", |mut h| {
        let tenant = h.tenant_id;
        let user = h.user_id;
        add_active_membership(&mut h, tenant);
        add_entitlement(&mut h, tenant);
        let address = serve(&h, 7200);
        let session = session_cookie(&h);
        let path = authorize_url(&h.client_id, REDIRECT, "S256");
        let page = browser_get(&h, address, &path, &session);
        assert_eq!(page.status, 200);
        let body = consent_body(&page, "allow");

        let mut barrier = h.admin.transaction().unwrap();
        barrier.query_one(
            "SELECT client_id FROM control.oauth_client_registrations WHERE client_id=$1 FOR UPDATE",
            &[&h.client_id],
        ).unwrap();
        let request = h.rt.spawn(async move {
            http_with(
                address,
                "POST",
                "/oauth/authorize",
                &[
                    ("Cookie", &session),
                    ("Origin", ORIGIN),
                    ("Sec-Fetch-Site", "same-origin"),
                ],
                &body,
            )
            .await
        });
        wait_for_code_insert(&mut barrier, &request);
        let second = if add_second_tenant {
            let second: Uuid = barrier.query_one(
                "INSERT INTO control.tenants(name,state) VALUES ('oauth second fixture','ACTIVE') RETURNING tenant_id",
                &[],
            ).unwrap().get(0);
            barrier.execute(
                "INSERT INTO control.memberships(tenant_id,user_id,role,state) VALUES($1,$2,'OWNER','ACTIVE')",
                &[&second, &user],
            ).unwrap();
            Some(second)
        } else {
            assert_eq!(barrier.execute(
                "UPDATE control.memberships SET state='SUSPENDED' WHERE tenant_id=$1 AND user_id=$2",
                &[&tenant, &user],
            ).unwrap(), 1);
            None
        };
        barrier.commit().unwrap();

        let reply = h.rt.block_on(request);
        if let Some(second) = second {
            h.admin
                .execute(
                    "DELETE FROM control.memberships WHERE tenant_id=$1",
                    &[&second],
                )
                .unwrap();
            h.admin
                .execute("DELETE FROM control.tenants WHERE tenant_id=$1", &[&second])
                .unwrap();
        }
        let reply = reply.unwrap();
        assert_eq!(
            reply.status, 403,
            "membership change must prevent code issuance"
        );
        assert!(!reply.headers.contains_key("location"));
        assert_eq!(authorization_code_count(&mut h), 0);
    });
}

fn wait_for_code_insert(
    barrier: &mut postgres::Transaction<'_>,
    request: &tokio::task::JoinHandle<Reply>,
) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let waiting: bool = barrier.query_one(
            "SELECT EXISTS (SELECT FROM pg_locks WHERE locktype='transactionid' AND NOT granted \
             AND pg_backend_pid() = ANY(pg_blocking_pids(pid)))",
            &[],
        ).unwrap().get(0);
        if waiting {
            break;
        }
        assert!(
            !request.is_finished() && std::time::Instant::now() < deadline,
            "issuance did not reach the DB barrier"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn authorization_code_count(h: &mut Handle) -> i64 {
    h.admin
        .query_one(
            "SELECT count(*) FROM control.oauth_authorization_codes WHERE tenant_id=$1",
            &[&h.tenant_id],
        )
        .unwrap()
        .get(0)
}

#[test]
fn m02_10b_review_revokes_refresh_for_disabled_client() {
    run_db_fixture::<OAuthFixture, _>("M02-10b review: disabled client revoke", |mut h| {
        let address = serve(&h, 7200);
        let tokens = issued(&h, address);
        h.admin.execute("UPDATE control.oauth_client_registrations SET disabled_at=now() WHERE client_id=$1",
            &[&h.client_id]).unwrap();
        let reply = h.rt.block_on(http(
            address,
            "POST",
            "/oauth/revoke",
            &form(&[
                ("client_id", &h.client_id),
                ("token", tokens["refresh_token"].as_str().unwrap()),
            ]),
        ));
        assert_eq!(reply.status, 200);
        h.admin
            .execute(
                "UPDATE control.oauth_client_registrations SET disabled_at=NULL WHERE client_id=$1",
                &[&h.client_id],
            )
            .unwrap();
        denied(
            &refresh(&h, address, &tokens, &h.client_id),
            OAuthReason::REFRESH_REJECTED,
        );
        assert_eq!(
            lookup(&h, decode(&tokens).grant_id).status,
            Some(oauth_repo::GrantStatus::Revoked)
        );
    });
}

#[test]
fn m02_10b_review_duplicate_authorize_parameters_are_invalid() {
    run_db_fixture::<OAuthFixture, _>("M02-10b review: duplicate authorize parameters", |mut h| {
        let tenant = h.tenant_id;
        add_active_membership(&mut h, tenant);
        add_entitlement(&mut h, tenant);
        let address = serve(&h, 7200);
        let session = session_cookie(&h);
        let path = authorize_url(&h.client_id, REDIRECT, "S256");
        for key in [
            "state",
            "redirect_uri",
            "response_type",
            "code_challenge",
            "code_challenge_method",
            "client_id",
            "resource",
            "scope",
        ] {
            let duplicate = format!("{path}&{key}=duplicate");
            let reply = browser_get(&h, address, &duplicate, &session);
            assert_eq!(reply.status, 400, "duplicate {key}");
            assert_eq!(
                serde_json::from_str::<Value>(&reply.body).unwrap(),
                serde_json::json!({"error": "invalid_request"})
            );
            assert!(!reply.headers.contains_key("location"));
        }
        assert_eq!(authorization_code_count(&mut h), 0);
        let page = browser_get(&h, address, &path, &session);
        assert_eq!(page.status, 200);
        let reply = browser_consent(&h, address, &session, ORIGIN, &consent_body(&page, "allow"));
        let params = callback(&reply);
        assert_eq!(params["state"], "state + & 東京");
        assert!(!params["code"].is_empty());
        assert_eq!(authorization_code_count(&mut h), 1);
    });
}

#[test]
fn m02_10b_consent_rejects_cross_origin() {
    run_db_fixture::<OAuthFixture, _>("m02_10b_consent_rejects_cross_origin", |mut h| {
        let tenant = h.tenant_id;
        add_active_membership(&mut h, tenant);
        add_entitlement(&mut h, tenant);
        let address = serve(&h, 7200);
        let session = session_cookie(&h);
        let path = authorize_url(&h.client_id, REDIRECT, "S256");
        let page = browser_get(&h, address, &path, &session);
        assert_eq!(page.status, 200);
        let body = consent_body(&page, "allow");
        assert_eq!(
            browser_consent(&h, address, &session, "https://wrong.example.test", &body).status,
            403
        );
    });
}

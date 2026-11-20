//! `gateway::tests::oauth_flow` — G-M02-7/8/9/14 through real HTTP, role_gateway and PostgreSQL doors.
//! Depends-on: crates=[axum, hex, humaux-adapters, humaux-application, humaux-contracts, humaux-domain, humaux-protocol,
//!   humaux-testkit, postgres, rand, serde_json, time, tokio, url, uuid];
//!   services=[HTTP(loopback), PostgreSQL(any) r=[control.oauth_authorization_codes, control.oauth_client_registrations, control.oauth_grants, ops.email_outbox] w=[control.workspaces, control.workspace_memberships, control.email_challenges, control.entitlement_snapshots, control.memberships, control.oauth_authorization_codes, control.oauth_client_registrations,
//!   control.oauth_grants, control.oauth_refresh_tokens, control.sessions, control.tenants, control.user_emails, control.users, ops.email_outbox]
//!   x=[control.bump_user_security_epoch], PostgreSQL(role_gateway)]; env=[CI, HUMAUX_TEST_PG_DSN];
//!   modules=[adapters::oauth_repo, adapters::postgres, adapters::session_repo, application::auth, application::login, application::oauth, application::session, application::signed_token, contracts::retrieval_config, domain::context, domain::dataclass, domain::error, domain::identity,
//!   domain::ids, gateway::auth, gateway::auth_pages, gateway::bootstrap, gateway::context, gateway::guard, gateway::limiter, gateway::mcp_application, gateway::oauth_http, gateway::remember, humaux-testkit, protocol::edge, protocol::mcp, protocol::mcp_catalog]
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
    context::ContextBudget,
    dataclass::DataClass,
    error::ErrorCode,
    identity::VisibilityClass,
    ids::{TenantId, UserId, WorkspaceId},
};
use humaux_gateway::{
    auth::AuthenticatedBearer,
    auth_pages::{self, AuthPagesConfig},
    bootstrap::{passwordless_login_port, provision_oauth_clients},
    context::ContextBootstrap,
    guard::{GatewayGuard, GuardRatePolicies, GuardSettings, OAuthRequestContext},
    limiter::RatePolicy,
    mcp_application::GatewayMcpApplication,
    oauth_http::{self, OAuthHttpConfig, RegistrationPolicy},
    remember::{ProcessFamily, RememberEventKind, RememberPolicy},
};
use humaux_protocol::{
    edge::TrustedProxyConfig,
    mcp::{McpAdapter, McpHttpConfig},
    mcp_catalog::CanonicalCatalog,
};
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use serde_json::Value;
use std::{cell::RefCell, collections::BTreeMap, net::SocketAddr, sync::Arc, time::Duration};
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
        keys: Arc::new(keys()),
        issuer: ORIGIN.to_owned(),
        resource: NATIVE_RESOURCE.to_owned(),
        login_return_ttl: Duration::from_secs(900),
        code_ttl: Duration::from_secs(300),
        access_ttl: Duration::from_secs(3600),
        refresh_ttl: Duration::from_secs(3600),
        grant_max_ttl: Duration::from_secs(max),
        registration: test_registration_policy(10_000, 10_000, 10_000),
    }
}
fn test_registration_policy(capacity: i64, refill: i64, max_unused: i64) -> RegistrationPolicy {
    RegistrationPolicy::new(
        RatePolicy::new(capacity, refill).unwrap(),
        50_000,
        max_unused,
    )
    .unwrap()
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
    registered_clients: Vec<String>,
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
            "DELETE FROM control.workspaces WHERE tenant_id=$1",
            "DELETE FROM control.tenants WHERE tenant_id=$1",
        ] {
            let _ = self.admin.execute(sql, &[&self.tenant_id]);
        }
        self.registered_clients.push(self.client_id.clone());
        let _ = self.admin.execute(
            "DELETE FROM control.oauth_client_registrations WHERE client_id=ANY($1)",
            &[&self.registered_clients],
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
            registered_clients: Vec::new(),
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
    serve_surface(h, Some(config(max)))
}

fn serve_surface(h: &Handle, config: Option<OAuthHttpConfig>) -> SocketAddr {
    // dep: PostgreSQL(role_gateway) — §79.2: exercise the runtime role.
    let pool =
        h.rt.block_on(RuntimeDbPool::connect(&dsn_as_role(&h.dsn)))
            .expect("gateway pool");
    let mut settings = guard_settings();
    settings.trusted_proxies.trusted_proxy_cidrs = vec!["127.0.0.1/32".parse().unwrap()];
    let guard = Arc::new(GatewayGuard::new(pool, settings).expect("guard"));
    let pages = AuthPagesConfig {
        keys: keys(),
        public_origin: ORIGIN.to_owned(),
        auth: AuthConfig::default(),
        mail_from: "no-reply@as.example.test".to_owned(),
        code_pepper: b"oauth-flow-fixture-login-pepper".to_vec(),
        recipient_allowlist: String::new(),
    };
    let login = passwordless_login_port(&guard, &pages);
    let enabled = config.is_some();
    let router = oauth_http::router(Arc::clone(&guard), config, Arc::clone(&login));
    let router = if enabled {
        router.merge(auth_pages::router(guard, pages, login))
    } else {
        router
    };
    serve_router(h, router)
}

fn serve_router(h: &Handle, router: axum::Router) -> SocketAddr {
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
    let content_type = headers
        .iter()
        .find_map(|(name, value)| name.eq_ignore_ascii_case("content-type").then_some(*value))
        .unwrap_or("application/x-www-form-urlencoded");
    let extra: String = headers
        .iter()
        .filter(|(name, _)| !name.eq_ignore_ascii_case("content-type"))
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect();
    let raw = format!(
        "{method} {path} HTTP/1.1\r\nHost: as.example.test\r\nConnection: close\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{extra}\r\n{body}",
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
    issue_code_for(h, RESOURCE)
}

fn issue_code_for(h: &Handle, resource: &str) -> String {
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
                    resource,
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

#[derive(Default)]
struct ResourceRequest<'a> {
    resource: Option<&'a str>,
    missing_scope: RefCell<Option<String>>,
}

impl OAuthRequestContext for ResourceRequest<'_> {
    fn expected_resource(&self) -> Option<&str> {
        self.resource
    }

    fn mark_insufficient_scope(&self, required_scope: &str) {
        self.missing_scope.replace(Some(required_scope.to_owned()));
    }
}

fn bearer_fixture(h: &mut Handle) -> (GatewayGuard, Value) {
    let tenant = h.tenant_id;
    add_active_membership(h, tenant);
    let address = serve(h, 7200);
    let tokens = issued(h, address);
    // dep: PostgreSQL(role_gateway) — the same role and guard entry as the gateway
    let pool =
        h.rt.block_on(RuntimeDbPool::connect(&dsn_as_role(&h.dsn)))
            .expect("gateway pool");
    let guard = GatewayGuard::new(pool, guard_settings())
        .expect("guard")
        .with_oauth_issuer(ORIGIN.to_owned(), Arc::new(keys()));
    (guard, tokens)
}

fn bearer(
    h: &Handle,
    guard: &GatewayGuard,
    token: &str,
    resource: Option<&str>,
) -> Result<AuthenticatedBearer, ErrorCode> {
    let header = format!("Bearer {token}");
    h.rt.block_on(guard.authenticate_bearer(
        Some(&header),
        "127.0.0.1".parse().unwrap(),
        &ResourceRequest {
            resource,
            ..Default::default()
        },
    ))
}

fn raw_access(tokens: &Value) -> &str {
    tokens["access_token"].as_str().unwrap()
}

fn signed_access(terms: &AccessTerms) -> String {
    keys().sign(&ACCESS_TOKEN_LABEL, &oauth::access_token_payload(terms))
}

#[test]
fn g_m02_10_bearer_good_and_requires_header() {
    run_db_fixture::<OAuthFixture, _>("G-M02-10 good", |mut h| {
        let (guard, tokens) = bearer_fixture(&mut h);
        assert_eq!(guard.oauth_issuer(), Some(ORIGIN));
        let request = ResourceRequest {
            resource: Some(RESOURCE),
            ..Default::default()
        };
        let credential = bearer(&h, &guard, raw_access(&tokens), request.resource).unwrap();
        let auth = GatewayGuard::authorize_bearer(&credential, "context:read", None, &request)
            .expect("authorized OAuth request");
        assert_eq!(auth.tenant_id(), TenantId(h.tenant_id));
        assert_eq!(auth.user_id(), Some(UserId(h.user_id)));
        assert_eq!(auth.principal().0, decode(&tokens).grant_id);
        assert_eq!(*request.missing_scope.borrow(), None);
        let no_header =
            h.rt.block_on(guard.authenticate_bearer(None, "127.0.0.1".parse().unwrap(), &request));
        assert_eq!(no_header.err(), Some(ErrorCode::Unauthorized));
        assert_eq!(
            bearer(&h, &guard, raw_access(&tokens), None).err(),
            Some(ErrorCode::Unauthorized)
        );
    });
}

#[test]
fn g_m02_10_bearer_resource_is_exact() {
    run_db_fixture::<OAuthFixture, _>("G-M02-10 exact audience", |mut h| {
        let (guard, tokens) = bearer_fixture(&mut h);
        let legacy_resource = format!("{RESOURCE}/legacy");
        let code = issue_code_for(&h, &legacy_resource);
        let reply = post(
            &h,
            serve(&h, 7200),
            &code_form(&h, &code, &[("resource", Some(&legacy_resource))]),
        );
        assert_eq!(reply.status, 200);
        let legacy_tokens: Value = serde_json::from_str(&reply.body).unwrap();
        assert_eq!(decode(&legacy_tokens).resource, legacy_resource);
        assert_eq!(
            bearer(&h, &guard, raw_access(&legacy_tokens), Some(RESOURCE)).err(),
            Some(ErrorCode::Unauthorized),
            "legacy token on the native resource"
        );
        for resource in [
            "/mcp",
            NATIVE_RESOURCE,
            &format!("{RESOURCE}/legacy"),
            &format!("{RESOURCE}/"),
        ] {
            assert_eq!(
                bearer(&h, &guard, raw_access(&tokens), Some(resource)).err(),
                Some(ErrorCode::Unauthorized),
                "audience {resource}"
            );
        }
    });
}

#[test]
fn g_m02_10_bearer_signature_and_issuer() {
    run_db_fixture::<OAuthFixture, _>("G-M02-10 issuer and MAC", |mut h| {
        let (guard, tokens) = bearer_fixture(&mut h);
        let payload = oauth::access_token_payload(&decode(&tokens));
        let foreign = TokenKeys::new(vec![8; 32], None)
            .unwrap()
            .sign(&ACCESS_TOKEN_LABEL, &payload);
        assert_eq!(
            bearer(&h, &guard, &foreign, Some(RESOURCE)).err(),
            Some(ErrorCode::Unauthorized)
        );
        let mut altered = hex::decode(raw_access(&tokens)).unwrap();
        let last = altered.last_mut().unwrap();
        *last = if *last == b'a' { b'b' } else { b'a' };
        assert_eq!(
            bearer(&h, &guard, &hex::encode(altered), Some(RESOURCE)).err(),
            Some(ErrorCode::Unauthorized)
        );
    });
}

#[test]
fn g_m02_10_bearer_expiry() {
    run_db_fixture::<OAuthFixture, _>("G-M02-10 token expired", |mut h| {
        let (guard, tokens) = bearer_fixture(&mut h);
        let mut terms = decode(&tokens);
        terms.expires_at = OffsetDateTime::now_utc() - time::Duration::seconds(1);
        assert_eq!(
            bearer(&h, &guard, &signed_access(&terms), Some(RESOURCE)).err(),
            Some(ErrorCode::Unauthorized)
        );
    });
}

#[test]
fn g_m02_10_bearer_revocation_is_live() {
    run_db_fixture::<OAuthFixture, _>("G-M02-10 grant revoked", |mut h| {
        let (guard, tokens) = bearer_fixture(&mut h);
        let token = raw_access(&tokens);
        assert!(bearer(&h, &guard, token, Some(RESOURCE)).is_ok());
        let reply = h.rt.block_on(http_with(
            serve(&h, 7200),
            "POST",
            "/oauth/revoke",
            &[],
            &form(&[
                ("token", tokens["refresh_token"].as_str().unwrap()),
                ("client_id", &h.client_id),
            ]),
        ));
        assert_eq!(reply.status, 200);
        assert_eq!(
            bearer(&h, &guard, token, Some(RESOURCE)).err(),
            Some(ErrorCode::Unauthorized)
        );
    });
}

#[test]
fn g_m02_10_bearer_epoch_is_live() {
    run_db_fixture::<OAuthFixture, _>("G-M02-10 epoch moved", |mut h| {
        let (guard, tokens) = bearer_fixture(&mut h);
        h.admin
            .query_one("SELECT control.bump_user_security_epoch($1)", &[&h.user_id])
            .unwrap();
        assert_eq!(
            bearer(&h, &guard, raw_access(&tokens), Some(RESOURCE)).err(),
            Some(ErrorCode::Unauthorized)
        );
    });
}

#[test]
fn g_m02_10_bearer_membership_is_live() {
    run_db_fixture::<OAuthFixture, _>("G-M02-10 removed membership", |mut h| {
        let (guard, tokens) = bearer_fixture(&mut h);
        h.admin.execute(
            "UPDATE control.memberships SET state='SUSPENDED' WHERE tenant_id=$1 AND user_id=$2",
            &[&h.tenant_id, &h.user_id],
        ).unwrap();
        assert_eq!(
            bearer(&h, &guard, raw_access(&tokens), Some(RESOURCE)).err(),
            Some(ErrorCode::Unauthorized)
        );
    });
}

#[test]
fn g_m02_10_bearer_scope_and_signal() {
    run_db_fixture::<OAuthFixture, _>("G-M02-10 least privilege", |mut h| {
        let (guard, tokens) = bearer_fixture(&mut h);
        let request = ResourceRequest {
            resource: Some(RESOURCE),
            ..Default::default()
        };
        let credential = bearer(&h, &guard, raw_access(&tokens), request.resource).unwrap();
        assert_eq!(
            GatewayGuard::authorize_bearer(&credential, "artifact:manage", None, &request),
            Err(ErrorCode::Forbidden)
        );
        assert_eq!(
            request.missing_scope.borrow().as_deref(),
            Some("artifact:manage")
        );

        let mut terms = decode(&tokens);
        terms.scopes.push("artifact:manage".to_owned());
        assert_eq!(
            bearer(&h, &guard, &signed_access(&terms), request.resource).err(),
            Some(ErrorCode::Unauthorized)
        );
    });
}

fn fixture_workspace(h: &mut Handle) -> WorkspaceId {
    WorkspaceId(h.admin.query_one(
        "INSERT INTO control.workspaces(tenant_id,name) VALUES ($1,'bearer fixture') RETURNING workspace_id",
        &[&h.tenant_id],
    ).unwrap().get(0))
}

#[test]
fn g_m02_10_bearer_cross_tenant_scope_is_not_widened() {
    run_db_fixture::<OAuthFixture, _>("G-M02-10 cross tenant", |mut h| {
        let (guard, tokens) = bearer_fixture(&mut h);
        let own = fixture_workspace(&mut h);
        h.admin.execute(
            "INSERT INTO control.workspace_memberships(tenant_id,workspace_id,user_id,role) VALUES ($1,$2,$3,'MEMBER')",
            &[&h.tenant_id, &own.0, &h.user_id],
        ).unwrap();
        run_db_fixture::<OAuthFixture, _>("G-M02-10 foreign tenant", |mut foreign| {
            let foreign_workspace = fixture_workspace(&mut foreign);
            let foreign_tenant = foreign.tenant_id;
            add_active_membership(&mut foreign, foreign_tenant);
            foreign.admin.execute(
                "INSERT INTO control.workspace_memberships(tenant_id,workspace_id,user_id,role) VALUES ($1,$2,$3,'MEMBER')",
                &[&foreign.tenant_id, &foreign_workspace.0, &foreign.user_id],
            ).unwrap();
            let request = ResourceRequest {
                resource: Some(RESOURCE),
                ..Default::default()
            };
            let credential = bearer(&h, &guard, raw_access(&tokens), request.resource).unwrap();
            assert!(
                GatewayGuard::authorize_bearer(&credential, "context:read", Some(own), &request)
                    .is_ok()
            );
            assert_eq!(
                GatewayGuard::authorize_bearer(
                    &credential,
                    "context:read",
                    Some(foreign_workspace),
                    &request
                ),
                Err(ErrorCode::Forbidden)
            );
            assert_eq!(*request.missing_scope.borrow(), None);
        });
    });
}

fn native_mcp_router(guard: GatewayGuard) -> axum::Router {
    let catalog = CanonicalCatalog::load().expect("canonical catalog");
    let advertised = catalog.trusted_catalog().expect("trusted catalog");
    let remember = RememberPolicy::new(
        ProcessFamily::new("workspace", "knowledge", "ingest", "v1").unwrap(),
        Uuid::new_v4(),
        Duration::from_secs(60),
        DataClass::Internal,
        VisibilityClass::WorkspaceShared,
    )
    .unwrap();
    let context = ContextBootstrap::new(
        ContextBudget::new(4_096, 512).unwrap(),
        humaux_contracts::retrieval_config::resolve_registered_retrieval_profile(
            &Default::default(),
        )
        .unwrap(),
        &remember,
        Duration::from_secs(60),
    )
    .unwrap();
    let app = GatewayMcpApplication::new(
        catalog,
        Arc::new(guard),
        remember,
        RememberEventKind::UserMessage,
        context,
    );
    let config = McpHttpConfig::new(
        vec!["as.example.test".into()],
        vec![ORIGIN.into()],
        64 * 1024,
    )
    .unwrap()
    .with_oauth_issuer(ORIGIN.to_owned());
    McpAdapter::new(Arc::new(app), advertised, config).router()
}

fn native_mcp_request(
    h: &Handle,
    address: SocketAddr,
    path: &str,
    token: Option<&str>,
    tool: Option<(&str, Value)>,
) -> Reply {
    let mut params = serde_json::json!({"_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "oauth-flow", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }});
    let method = if tool.is_some() {
        "tools/call"
    } else {
        "tools/list"
    };
    let mut headers = vec![
        ("Content-Type", "application/json"),
        ("Accept", "application/json, text/event-stream"),
        ("MCP-Protocol-Version", "2026-07-28"),
        ("Mcp-Method", method),
    ];
    if let Some((name, arguments)) = tool {
        headers.push(("Mcp-Name", name));
        params["name"] = name.into();
        params["arguments"] = arguments;
    }
    let authorization = token.map(|value| format!("Bearer {value}"));
    if let Some(header) = authorization.as_deref() {
        headers.push(("Authorization", header));
    }
    h.rt.block_on(http_with(
        address,
        "POST",
        path,
        &headers,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        })
        .to_string(),
    ))
}

#[test]
fn g_m02_10_bearer_native_http() {
    run_db_fixture::<OAuthFixture, _>("G-M02-10 real native OAuth", |mut h| {
        // A write-only token authenticates for protocol traffic. It cannot run memory.get.
        h.scopes = vec!["memory:write".to_owned()];
        let tenant = h.tenant_id;
        add_active_membership(&mut h, tenant);
        let as_address = serve(&h, 7200);
        let mint = |resource: &str| {
            let code = issue_code_for(&h, resource);
            let reply = post(
                &h,
                as_address,
                &code_form(&h, &code, &[("resource", Some(resource))]),
            );
            assert_eq!(reply.status, 200, "access token was not issued");
            let tokens: Value = serde_json::from_str(&reply.body).unwrap();
            let claims = decode(&tokens);
            assert_eq!(claims.resource, resource);
            assert_eq!(claims.scopes, ["memory:write"]);
            raw_access(&tokens).to_owned()
        };
        let native = mint(NATIVE_RESOURCE);
        let legacy = mint(&format!("{NATIVE_RESOURCE}/legacy"));
        // dep: PostgreSQL(role_gateway) — same role and guard as the real MCP listener.
        let pool =
            h.rt.block_on(RuntimeDbPool::connect(&dsn_as_role(&h.dsn)))
                .unwrap();
        let guard = GatewayGuard::new(pool, guard_settings())
            .unwrap()
            .with_oauth_issuer(ORIGIN.to_owned(), Arc::new(keys()));
        let address = serve_router(&h, native_mcp_router(guard));
        let good = native_mcp_request(&h, address, "/mcp", Some(&native), None);
        assert_eq!(good.status, 200, "native audience");
        let catalog: Value = serde_json::from_str(&good.body).unwrap();
        assert!(catalog["result"]["tools"].is_array());

        let wrong = native_mcp_request(&h, address, "/mcp", Some(&legacy), None);
        assert_eq!(wrong.status, 401, "legacy audience on native route");
        let challenge = format!(
            "Bearer resource_metadata=\"{ORIGIN}/.well-known/oauth-protected-resource/mcp\""
        );
        assert_eq!(
            wrong.headers["www-authenticate"],
            format!("{challenge}, error=\"invalid_token\"")
        );

        let scope = native_mcp_request(
            &h,
            address,
            "/mcp",
            Some(&native),
            Some((
                "memory",
                serde_json::json!({"action":"get","memory_id":Uuid::now_v7()}),
            )),
        );
        assert_eq!(scope.status, 403, "missing context:read");
        assert_eq!(
            scope.headers.get("www-authenticate"),
            Some(&format!(
                "{challenge}, error=\"insufficient_scope\", scope=\"context:read\""
            ))
        );

        let query = native_mcp_request(
            &h,
            address,
            &format!("/mcp?access_token={native}"),
            None,
            None,
        );
        assert_eq!(query.status, 401, "query transport cannot authenticate");
        assert_eq!(query.headers["www-authenticate"], challenge);
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

// The quota is cluster-wide. Keep the lock until fixture cleanup, including across nextest processes.
fn lock_registration_fixture(h: &mut Handle) {
    h.admin
        .execute(
            "SELECT pg_advisory_lock(hashtext('humaux.test.oauth_registration'))",
            &[],
        )
        .expect("serialize DCR fixtures");
}

fn registration_body(redirects: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "redirect_uris": redirects,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "client_name": "M02-10c fixture"
    })
}

fn register_client_http(h: &Handle, address: SocketAddr, path: &str, body: &str) -> Reply {
    h.rt.block_on(http_with(
        address,
        "POST",
        path,
        &[("Content-Type", "application/json")],
        body,
    ))
}

fn recorded_client(h: &Handle, client_id: &str) -> Option<oauth_repo::ClientRecord> {
    h.rt.block_on(async {
        let mut txn = oauth_repo::begin(&h.gateway).await.unwrap();
        txn.lookup_client(client_id).await.unwrap()
    })
}

#[test]
fn m02_10c_advertised_registration_persists_public_client() {
    run_db_fixture::<OAuthFixture, _>("M02-10c dynamic registration", |mut h| {
        lock_registration_fixture(&mut h);
        let address = serve(&h, 7200);
        let metadata = h.rt.block_on(http(
            address,
            "GET",
            "/.well-known/oauth-authorization-server",
            "",
        ));
        assert_eq!(metadata.status, 200);
        let metadata: Value = serde_json::from_str(&metadata.body).unwrap();
        let registration =
            url::Url::parse(metadata["registration_endpoint"].as_str().unwrap()).unwrap();
        assert_eq!(registration.origin().ascii_serialization(), ORIGIN);
        let input = registration_body(&[
            REDIRECT,
            "http://localhost:37123/cb",
            "http://127.0.0.1/cb",
            "http://[::1]/cb",
        ]);
        let reply = register_client_http(&h, address, registration.path(), &input.to_string());
        assert_eq!(reply.status, 201, "{}", reply.body);
        assert_eq!(reply.headers["cache-control"], "no-store");
        let mut response: Value = serde_json::from_str(&reply.body).unwrap();
        let client = response
            .as_object_mut()
            .unwrap()
            .remove("client_id")
            .unwrap();
        let client = client.as_str().unwrap();
        h.registered_clients.push(client.to_owned());
        assert!(Uuid::parse_str(client).is_ok());
        let record = recorded_client(&h, client).expect("committed client");
        assert_eq!(record.kind, Some(ClientKind::Dcr));
        assert_eq!(
            serde_json::json!(record.redirect_uris),
            input["redirect_uris"]
        );
        assert_eq!(record.metadata, response);
        assert_eq!(response["client_name"], input["client_name"]);
        assert_eq!(response["token_endpoint_auth_method"], "none");
        assert_eq!(response["grant_types"], input["grant_types"]);
        assert_eq!(response["response_types"], serde_json::json!(["code"]));
        assert!(response.get("client_secret").is_none());
        let tenant = h.tenant_id;
        add_active_membership(&mut h, tenant);
        add_entitlement(&mut h, tenant);
        let page = browser_get(
            &h,
            address,
            &authorize_url(client, "http://localhost:37124/cb", "S256"),
            &session_cookie(&h),
        );
        assert_eq!(page.status, 200, "dynamic authorize: {}", page.body);
    });
}

#[test]
fn m02_10c_disabled_surface_has_no_registration_or_advertisement() {
    run_db_fixture::<OAuthFixture, _>("M02-10c disabled auth surface", |h| {
        let address = serve_surface(&h, None);
        assert_eq!(
            h.rt.block_on(http(
                address,
                "GET",
                "/.well-known/oauth-authorization-server",
                ""
            ))
            .status,
            404
        );
        assert_eq!(
            register_client_http(
                &h,
                address,
                "/oauth/register",
                &registration_body(&[REDIRECT]).to_string()
            )
            .status,
            404
        );
    });
}

#[test]
fn m02_10c_rejects_invalid_registration_metadata_and_redirects() {
    run_db_fixture::<OAuthFixture, _>("M02-10c invalid registration", |mut h| {
        lock_registration_fixture(&mut h);
        let address = serve(&h, 7200);
        let valid = registration_body(&[REDIRECT]);
        let mut metadata = vec!["{".into(), r#"{"token_endpoint_auth_method":"none","token_endpoint_auth_method":"none","redirect_uris":["https://example.test/cb"]}"#.into()];
        for method in [
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
        ] {
            let mut body = valid.clone();
            body["token_endpoint_auth_method"] = method.into();
            metadata.push(body.to_string());
        }
        let mut body = valid.clone();
        body.as_object_mut()
            .unwrap()
            .remove("token_endpoint_auth_method");
        metadata.push(body.to_string());
        for (key, value) in [
            ("client_id", serde_json::json!(h.client_id)),
            ("client_secret", serde_json::json!("not-a-real-secret")),
            ("grant_types", serde_json::json!(["client_credentials"])),
            ("response_types", serde_json::json!(["token"])),
        ] {
            let mut body = valid.clone();
            body[key] = value;
            metadata.push(body.to_string());
        }
        let mut name = valid.clone();
        name["client_name"] = "control\0character".into();
        metadata.push(name.to_string());
        let mut too_large = valid.clone();
        too_large["ignored"] = "x".repeat(8192).into();
        metadata.push(too_large.to_string());
        let mut failures = Vec::new();
        for (error, bodies) in [
            ("invalid_client_metadata", metadata),
            (
                "invalid_redirect_uri",
                [
                    vec![],
                    vec![REDIRECT, REDIRECT],
                    vec![REDIRECT, "https://client.example.test/cb#fragment"],
                    vec!["javascript:ignored"],
                    vec!["com.example.app:/cb"],
                    vec!["http://client.example.test/cb"],
                    vec!["http://localhost.evil.test/cb"],
                    vec!["http://127.0.0.2/cb"],
                    vec!["http://[0:0:0:0:0:0:0:1]/cb"],
                    vec!["http://127.000.0.1/cb"],
                    vec!["https://client.example.test/cb?%73tate=old"],
                    vec!["https://username@client.example.test/cb"],
                    vec!["http://localhost:65536/cb"],
                    vec!["https://client.example.test:invalid/cb"],
                    vec!["https://client.example.test:0/cb"],
                ]
                .into_iter()
                .map(|uris| registration_body(&uris).to_string())
                .collect(),
            ),
        ] {
            for (index, body) in bodies.iter().enumerate() {
                let reply = register_client_http(&h, address, "/oauth/register", body);
                let value: Value = serde_json::from_str(&reply.body).unwrap();
                if let Some(id) = value["client_id"].as_str() {
                    h.registered_clients.push(id.to_owned());
                }
                if (reply.status, &value) != (400, &serde_json::json!({"error": error})) {
                    failures.push((error, index, reply.status, value));
                }
                assert_eq!(reply.headers["cache-control"], "no-store");
            }
        }
        assert!(failures.is_empty(), "{failures:?}");
    });
}

#[test]
fn m02_10c_operator_preregistration_is_atomic_and_authorizes() {
    run_db_fixture::<OAuthFixture, _>("M02-10c controlled registration", |mut h| {
        let id = format!("static-{}", h.client_id);
        h.registered_clients.push(id.clone());
        let mut registration = registration_body(&[REDIRECT]);
        registration["client_id"] = id.clone().into();
        let mut invalid = registration.clone();
        let invalid_id = format!("invalid-{id}");
        h.registered_clients.push(invalid_id.clone());
        invalid["client_id"] = invalid_id.into();
        invalid["token_endpoint_auth_method"] = "client_secret_basic".into();
        assert!(
            h.rt.block_on(provision_oauth_clients(
                &h.gateway,
                &serde_json::json!([registration, invalid]).to_string()
            ))
            .is_err()
        );
        assert!(recorded_client(&h, &id).is_none());

        h.admin.execute(
            "UPDATE control.oauth_client_registrations SET disabled_at = now() WHERE client_id = $1",
            &[&h.client_id],
        ).unwrap();
        let mut conflict = registration.clone();
        conflict["client_id"] = h.client_id.clone().into();
        let result = h.rt.block_on(provision_oauth_clients(
            &h.gateway,
            &serde_json::json!([registration, conflict]).to_string(),
        ));
        assert_eq!(result, Err(ErrorCode::Conflict));
        assert!(
            recorded_client(&h, &id).is_none(),
            "the first write rolled back"
        );

        h.rt.block_on(provision_oauth_clients(
            &h.gateway,
            &serde_json::json!([registration]).to_string(),
        ))
        .unwrap();
        let record = recorded_client(&h, &id).expect("committed static client");
        assert_eq!(record.kind, Some(ClientKind::Static));
        assert_eq!(record.redirect_uris, [REDIRECT]);
        assert_eq!(record.metadata["token_endpoint_auth_method"], "none");
        let tenant = h.tenant_id;
        add_active_membership(&mut h, tenant);
        add_entitlement(&mut h, tenant);
        let address = serve(&h, 7200);
        let session = session_cookie(&h);
        let page = browser_get(&h, address, &authorize_url(&id, REDIRECT, "S256"), &session);
        assert_eq!(page.status, 200, "{}", page.body);
    });
}

fn seed_loopback_client(h: &Handle) {
    h.rt.block_on(async {
        let mut txn = oauth_repo::begin(&h.gateway).await.unwrap();
        assert!(
            txn.register_client(
                &h.client_id,
                ClientKind::Static,
                &[
                    "http://localhost:31000/cb?mode=desktop",
                    "http://127.0.0.1/cb",
                    "http://[::1]:31000/cb",
                    REDIRECT
                ]
                .map(str::to_owned),
                &serde_json::json!({}),
                None,
            )
            .await
            .unwrap()
        );
        txn.commit().await.unwrap();
    });
}

#[test]
fn m02_10c_loopback_port_varies_but_code_binds_actual_uri() {
    run_db_fixture::<OAuthFixture, _>("M02-10c loopback issuance and exchange", |mut h| {
        seed_loopback_client(&h);
        let tenant = h.tenant_id;
        add_active_membership(&mut h, tenant);
        add_entitlement(&mut h, tenant);
        let address = serve(&h, 7200);
        let session = session_cookie(&h);
        for (uri, exchange_uri, status) in [
            (
                "http://localhost:36493/cb?mode=desktop",
                "http://localhost:31000/cb?mode=desktop",
                400,
            ),
            (
                "http://localhost:36494/cb?mode=desktop",
                "http://localhost:36494/cb?mode=desktop",
                200,
            ),
            (
                "http://127.0.0.1:36494/cb",
                "http://127.0.0.1:36494/cb",
                200,
            ),
            ("http://[::1]:36494/cb", "http://[::1]:36494/cb", 200),
        ] {
            let page = browser_get(
                &h,
                address,
                &authorize_url(&h.client_id, uri, "S256"),
                &session,
            );
            assert_eq!(page.status, 200, "authorize {uri}: {}", page.body);
            let consent =
                browser_consent(&h, address, &session, ORIGIN, &consent_body(&page, "allow"));
            assert_eq!(consent.status, 303, "consent {uri}: {}", consent.body);
            let target = &consent.headers["location"];
            assert!(target.starts_with(&format!(
                "{uri}{}",
                if uri.contains('?') { '&' } else { '?' }
            )));
            let callback = url::Url::parse(target).unwrap();
            let code = callback
                .query_pairs()
                .find(|(key, _)| key == "code")
                .unwrap()
                .1;
            let reply = post(
                &h,
                address,
                &code_form(
                    &h,
                    &code,
                    &[
                        ("redirect_uri", Some(exchange_uri)),
                        ("resource", Some(NATIVE_RESOURCE)),
                    ],
                ),
            );
            assert_eq!(
                reply.status, status,
                "{uri} to {exchange_uri}: {}",
                reply.body
            );
            if status == 400 {
                denied(&reply, OAuthReason::CODE_REDIRECT_MISMATCH);
            }
        }
    });
}

#[test]
fn m02_10c_refuses_unregistered_redirect_in_http_and_pg() {
    run_db_fixture::<OAuthFixture, _>("M02-10c callback matching bounds", |mut h| {
        seed_loopback_client(&h);
        let address = serve(&h, 7200);
        let mut accepted = Vec::new();
        for uri in [
            "https://client.example.test:444/cb",
            "http://127.0.0.2:36000/cb",
            "http://127.0.0.1:36000/cb?mode=desktop",
            "http://localhost:36000/cb",
            "http://localhost:36000/cb?mode=other",
            "http://[::1]:36000/other",
            "https://localhost:36000/cb?mode=desktop",
            "http://LOCALHOST:36000/cb?mode=desktop",
            "http://localhost:0/cb?mode=desktop",
        ] {
            let reply = browser_get(&h, address, &authorize_url(&h.client_id, uri, "S256"), "");
            if reply.status != 400 || reply.headers.contains_key("location") {
                accepted.push(("authorize", uri));
            }
            let result = h.rt.block_on(async {
                let mut txn = oauth_repo::begin(&h.gateway).await.unwrap();
                txn.issue_code(
                    &CodeIssue {
                        code_hash: &SecretHash::of_secret("negative loopback door probe"),
                        client_id: &h.client_id,
                        redirect_uri: uri,
                        pkce_challenge: CHALLENGE,
                        resource: NATIVE_RESOURCE,
                        user_id: UserId(h.user_id),
                        tenant_id: TenantId(h.tenant_id),
                        workspace_id: None,
                        scopes: &h.scopes,
                    },
                    Duration::from_secs(300),
                )
                .await
                .unwrap()
            });
            if result.is_some() {
                accepted.push(("issuing door", uri));
            }
        }
        assert!(accepted.is_empty(), "{accepted:?}");
        assert_eq!(grant_count(&mut h), 0);
    });
}

async fn registration_from(address: SocketAddr, forwarded: &str, body: &str) -> Reply {
    http_with(
        address,
        "POST",
        "/oauth/register",
        &[
            ("Content-Type", "application/json"),
            ("Forwarded", forwarded),
        ],
        body,
    )
    .await
}

fn limited_registration(h: &mut Handle, reply: &Reply) -> u16 {
    let value: Value = serde_json::from_str(&reply.body).expect("registration JSON");
    match reply.status {
        201 => {
            let id = value["client_id"].as_str().expect("issued client ID");
            h.registered_clients.push(id.to_owned());
            assert!(recorded_client(h, id).is_some(), "registration committed");
        }
        429 => assert_eq!(value["error"], ErrorCode::RateLimited.as_str()),
        _ => panic!(
            "unexpected registration status {}: {}",
            reply.status, reply.body
        ),
    }
    assert_eq!(reply.headers["cache-control"], "no-store");
    reply.status
}

#[test]
fn m02_10c_registration_ip_rate_is_separate() {
    run_db_fixture::<OAuthFixture, _>("M02-10c DCR per-source rate", |mut h| {
        lock_registration_fixture(&mut h);
        let mut limits = config(7200);
        limits.registration = test_registration_policy(1, 1, 10_000);
        let address = serve_surface(&h, Some(limits));
        let body = registration_body(&[REDIRECT]).to_string();
        let (one, two, separate_ip) = h.rt.block_on(async {
            tokio::join!(
                registration_from(address, "192.0.2.1", &body),
                registration_from(address, "192.0.2.1", &body),
                registration_from(address, "192.0.2.2", &body),
            )
        });
        let mut shared = [
            limited_registration(&mut h, &one),
            limited_registration(&mut h, &two),
        ];
        shared.sort_unstable();
        let independent = limited_registration(&mut h, &separate_ip);
        assert_eq!(shared, [201, 429], "same source must share a budget");
        assert_eq!(independent, 201, "another source keeps its own budget");
    });
}

#[test]
fn m02_10c_registration_unused_quota_is_atomic_across_ips() {
    run_db_fixture::<OAuthFixture, _>("M02-10c DCR durable quota", |mut h| {
        lock_registration_fixture(&mut h);
        let existing: i64 = h.admin.query_one(
            "SELECT count(*) FROM control.oauth_client_registrations r WHERE r.kind='DCR' AND NOT EXISTS (SELECT FROM control.oauth_grants g WHERE g.client_id=r.client_id)",
            &[],
        ).unwrap().get(0);
        let mut limits = config(7200);
        limits.registration = test_registration_policy(10_000, 10_000, existing + 1);
        let address = serve_surface(&h, Some(limits));
        let body = registration_body(&[REDIRECT]).to_string();
        let (one, two) = h.rt.block_on(async {
            tokio::join!(
                registration_from(address, "192.0.2.3", &body),
                registration_from(address, "192.0.2.4", &body),
            )
        });
        let mut result = [
            limited_registration(&mut h, &one),
            limited_registration(&mut h, &two),
        ];
        result.sort_unstable();
        assert_eq!(
            result,
            [201, 429],
            "one global slot for the two distinct sources"
        );

        let client = h.registered_clients[0].clone();
        let tenant = h.tenant_id;
        add_active_membership(&mut h, tenant);
        add_entitlement(&mut h, tenant);
        let session = session_cookie(&h);
        let page = browser_get(
            &h,
            address,
            &authorize_url(&client, REDIRECT, "S256"),
            &session,
        );
        assert_eq!(page.status, 200, "{}", page.body);
        let consent = browser_consent(&h, address, &session, ORIGIN, &consent_body(&page, "allow"));
        let code = callback(&consent);
        let exchange = post(
            &h,
            address,
            &code_form(
                &h,
                &code["code"],
                &[
                    ("client_id", Some(&client)),
                    ("resource", Some(NATIVE_RESOURCE)),
                ],
            ),
        );
        assert_eq!(exchange.status, 200, "{}", exchange.body);
        let freed =
            h.rt.block_on(registration_from(address, "192.0.2.5", &body));
        assert_eq!(
            limited_registration(&mut h, &freed),
            201,
            "first grant frees the unused slot"
        );
    });
}

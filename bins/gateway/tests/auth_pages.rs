//! `gateway::tests::auth_pages` — G-M02-3 HTTP half (M02 D2, ADR-0125): the `/auth/*` pages through the production router,
//!   a real socket, the real pre-auth guard and a real Postgres as role_gateway. Nothing is sent: the pages only enqueue
//!   into `ops.email_outbox`, and the test reads the code from that payload.
//! Depends-on: crates=[axum, humaux-adapters, humaux-application, humaux-protocol, humaux-testkit, postgres, tokio, uuid];
//!   services=[HTTP(loopback), PostgreSQL(any) w=[control.auth_events, control.email_challenges, control.sessions,
//!   control.user_emails, control.users, ops.email_delivery_events, ops.email_outbox]
//!   x=[control.login_challenge_issue, control.session_issue], PostgreSQL(role_gateway)];
//!   env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::email, adapters::postgres, adapters::session_repo, application::auth,
//!   application::session, application::signed_token, gateway::auth_pages, gateway::guard, gateway::limiter,
//!   humaux-testkit, protocol::edge]
//! Called-by: [cargo-test]
//! Invariants: [an existing, a cooling-down and an unknown mailbox get the same status, headers and body from a start;
//!   a consumed code and a code after the attempt cap are both rejected with the one rejection page and mint no session;
//!   a POST without the configured Origin is a 403 that writes nothing; logout needs the session-bound CSRF token and
//!   only then revokes and clears the cookie; every route, refusals included, carries the four hardening headers; the
//!   pre-auth limiter answers the third request of a capacity-two bucket with 429; each test owns one throwaway user;
//!   a missing database is a visible §79.2 skip, a FAIL under HUMAUX_REQUIRE_DB]
//! Spec: Baseline §73.6; §74.3; §79.2; ADR-0125
//!
//! Keys and the pepper are fixed test bytes, not secrets. The public origin is a name no browser resolves.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use humaux_adapters::email::RecipientAllowlist;
use humaux_adapters::postgres::RuntimeDbPool;
use humaux_adapters::session_repo;
use humaux_application::auth::AuthConfig;
use humaux_application::session::{SessionPolicy, SessionSecret, VerifiedSession, csrf_token};
use humaux_application::signed_token::TokenKeys;
use humaux_gateway::auth_pages::{self, AuthPagesConfig};
use humaux_gateway::guard::{GatewayGuard, GuardRatePolicies, GuardSettings};
use humaux_gateway::limiter::RatePolicy;
use humaux_protocol::edge::{CSRF_HEADER_NAME, SESSION_COOKIE_NAME, TrustedProxyConfig};
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use uuid::Uuid;

/// The configured public origin; the only `Origin` a POST may carry.
const ORIGIN: &str = "https://console.example.test";
const PENDING_COOKIE: &str = "__Host-humaux_login";
/// ADR-0125 ruling 5, spelled out so a change to the router's constant is a change here too.
const CSP: &str = "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/// Attempt cap of `AuthConfig::default().login_challenge`; the cap test sends this many wrong codes, then the right one.
const DEFAULT_ATTEMPTS: i32 = 5;

fn keys() -> TokenKeys {
    TokenKeys::new(vec![7; 32], None).expect("32-byte key")
}

fn policy() -> SessionPolicy {
    SessionPolicy::from(&AuthConfig::default())
}

fn dsn_as_role(admin_dsn: &str, role: &str) -> String {
    let sep = if admin_dsn.contains('?') { '&' } else { '?' };
    format!("{admin_dsn}{sep}options=-c%20role%3D{role}")
}

struct Handle {
    rt: tokio::runtime::Runtime,
    dsn: String,
    /// The test's own `role_gateway` pool for direct door calls; each guard under test owns another.
    reader: RuntimeDbPool,
    admin: Client,
    /// The throwaway fixture row every statement of the test is scoped to.
    owner: Uuid,
    email: String,
}

/// A `role_gateway` pool, opened on `rt` so it outlives any runtime the test later drives it from.
fn gateway_pool(rt: &tokio::runtime::Runtime, dsn: &str) -> Result<RuntimeDbPool, String> {
    // dep: PostgreSQL(role_gateway) — the pool under test
    rt.block_on(RuntimeDbPool::connect(&dsn_as_role(dsn, "role_gateway")))
        .map_err(|e| e.to_string())
}

/// Children first; each statement takes the fixture user as its one bound parameter.
const CLEANUP: [&str; 7] = [
    "DELETE FROM ops.email_delivery_events \
       WHERE outbox_id IN (SELECT outbox_id FROM ops.email_outbox WHERE user_id = $1)",
    "DELETE FROM ops.email_outbox WHERE user_id = $1",
    "DELETE FROM control.auth_events WHERE user_id = $1",
    "DELETE FROM control.email_challenges WHERE user_id = $1",
    "DELETE FROM control.sessions WHERE user_id = $1",
    "DELETE FROM control.user_emails WHERE user_id = $1",
    "DELETE FROM control.users WHERE user_id = $1",
];

impl Drop for Handle {
    fn drop(&mut self) {
        for statement in CLEANUP {
            let _ = self.admin.execute(statement, &[&self.owner]);
        }
    }
}

struct PagesFixture;

impl DbIntegrationFixture for PagesFixture {
    type Handle = Handle;

    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        let dsn =
            std::env::var("HUMAUX_TEST_PG_DSN").map_err(|_| DbFixtureSkipReason::NoDatabaseUrl)?;
        // dep: PostgreSQL(any) — the setup/inspection connection
        let mut admin = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        let migrated: bool = admin
            .query_one(
                "SELECT to_regprocedure('control.login_challenge_issue(text,text,integer,integer,integer)') IS NOT NULL \
                 AND to_regprocedure('control.session_issue(uuid,bytea,integer)') IS NOT NULL",
                &[],
            )
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?
            .get(0);
        if !migrated {
            return Err(DbFixtureSkipReason::IsolationSetupFailed(
                "the login and session doors are missing: apply migrations 0266 and 0270 first"
                    .to_string(),
            ));
        }
        let user_id = Uuid::new_v4();
        let email = mailbox();
        admin
            .execute(
                "INSERT INTO control.users (user_id) VALUES ($1)",
                &[&user_id],
            )
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        admin
            .execute(
                "INSERT INTO control.user_emails (user_id, original_email, canonical_email) VALUES ($1, $2, $2)",
                &[&user_id, &email],
            )
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        let reader = gateway_pool(&rt, &dsn).map_err(DbFixtureSkipReason::IsolationSetupFailed)?;
        Ok(Handle {
            rt,
            dsn,
            reader,
            admin,
            owner: user_id,
            email,
        })
    }
}

/// A mailbox no account owns until a fixture inserts it.
fn mailbox() -> String {
    format!("auth-pages-test-{}@example.invalid", Uuid::new_v4())
}

fn rate(capacity: i64) -> RatePolicy {
    RatePolicy::new(capacity, capacity).expect("positive policy")
}

/// Guard settings of the gateway integration tests, with the pre-auth IP bucket at `preauth_capacity`.
fn guard_settings(preauth_capacity: i64) -> GuardSettings {
    GuardSettings {
        credential_pepper: b"auth-pages-test-credential-pepper".to_vec(),
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
            preauth_ip: rate(preauth_capacity),
            credential: rate(10_000),
            user: rate(10_000),
            tenant: rate(10_000),
            operation: rate(10_000),
            lock_timeout: Duration::from_secs(2),
            preauth_ipv6_prefix_bits: 64,
        },
        reservation_ttl: Duration::from_secs(30),
        handler_timeout: Duration::from_secs(5),
        finalize_timeout: Duration::from_secs(2),
        replay_ttl: Duration::from_secs(60),
    }
}

fn guard(h: &Handle, preauth_capacity: i64) -> Arc<GatewayGuard> {
    let pool = gateway_pool(&h.rt, &h.dsn).expect("role_gateway pool");
    Arc::new(GatewayGuard::new(pool, guard_settings(preauth_capacity)).expect("guard settings"))
}

/// The production router on a loopback socket, with connect info as `main` serves it.
async fn start(guard: Arc<GatewayGuard>) -> (SocketAddr, JoinHandle<()>) {
    let config = AuthPagesConfig {
        keys: keys(),
        public_origin: ORIGIN.to_owned(),
        mail_from: "no-reply@humaux.example".to_owned(),
        code_pepper: b"auth-pages-test-login-code-pepper".to_vec(),
        allowlist: RecipientAllowlist::allow_all(),
        auth: AuthConfig::default(),
    };
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let address = listener.local_addr().expect("loopback address");
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            auth_pages::router(guard, config).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("serve loopback /auth/*");
    });
    (address, server)
}

fn serve(h: &Handle) -> SocketAddr {
    let guard = guard(h, 10_000);
    h.rt.block_on(start(guard)).0
}

/// One parsed HTTP/1.1 response: lowercase header names, in wire order.
#[derive(Clone, PartialEq, Eq)]
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

/// Status and header names only: header values and the body can carry cookies, so a failed assertion never logs them.
impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(key, _)| key.as_str()).collect();
        f.debug_struct("Reply")
            .field("status", &self.status)
            .field("header_names", &names)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl Reply {
    fn header(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }

    /// The full `Set-Cookie` line of cookie `name`.
    fn set_cookie(&self, name: &str) -> Option<&str> {
        self.header("set-cookie")
            .into_iter()
            .find(|line| line.starts_with(&format!("{name}=")))
    }

    /// The value of cookie `name` in this response's `Set-Cookie` lines.
    fn cookie_value(&self, name: &str) -> Option<String> {
        let line = self.set_cookie(name)?;
        let value = line.strip_prefix(&format!("{name}="))?;
        Some(value.split(';').next().unwrap_or_default().to_owned())
    }

    /// Everything a caller can compare across two answers: no `Date`, and the pending-login cookie's value (a function
    /// of the submitted address and the clock, never of the account) masked.
    fn comparable(&self) -> (u16, Vec<(String, String)>, String) {
        let headers = self
            .headers
            .iter()
            .filter(|(key, _)| key != "date")
            .map(|(key, value)| {
                let masked =
                    if key == "set-cookie" && value.starts_with(&format!("{PENDING_COOKIE}=")) {
                        let rest = value.find(';').map_or("", |at| &value[at..]);
                        format!("{PENDING_COOKIE}=<signed value>{rest}")
                    } else {
                        value.clone()
                    };
                (key.clone(), masked)
            })
            .collect();
        (self.status, headers, self.body.clone())
    }
}

async fn http(
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Reply {
    // dep: HTTP(loopback) — the production /auth/* router and pre-auth guard (ADR-0125)
    let mut stream = TcpStream::connect(address).await.expect("connect");
    let mut raw =
        format!("{method} {path} HTTP/1.1\r\nHost: console.example.test\r\nConnection: close\r\n");
    for (name, value) in headers {
        raw.push_str(&format!("{name}: {value}\r\n"));
    }
    if method == "POST" {
        raw.push_str(&format!(
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    raw.push_str("\r\n");
    raw.push_str(body);
    stream.write_all(raw.as_bytes()).await.expect("write");
    let mut text = String::new();
    stream.read_to_string(&mut text).await.expect("read");
    let (head, body) = text.split_once("\r\n\r\n").expect("a complete response");
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("status line");
    let headers = lines
        .filter_map(|line| line.split_once(": "))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.to_owned()))
        .collect();
    Reply {
        status,
        headers,
        body: body.to_owned(),
    }
}

fn call(
    h: &Handle,
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Reply {
    h.rt.block_on(http(address, method, path, headers, body))
}

fn post_login(h: &Handle, address: SocketAddr, email: &str) -> Reply {
    call(
        h,
        address,
        "POST",
        "/auth/login",
        &[("Origin", ORIGIN)],
        &format!("email={email}"),
    )
}

fn submit_code(h: &Handle, address: SocketAddr, pending: &str, code: &str) -> Reply {
    let cookie = format!("{PENDING_COOKIE}={pending}");
    call(
        h,
        address,
        "POST",
        "/auth/code",
        &[("Origin", ORIGIN), ("Cookie", &cookie)],
        &format!("code={code}"),
    )
}

/// The plaintext code of the user's newest outbox row: the one place it may exist.
fn emailed_code(h: &mut Handle) -> String {
    h.admin
        .query_one(
            "SELECT payload->>'code' FROM ops.email_outbox WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1",
            &[&h.owner],
        )
        .expect("an outbox row with a code must exist")
        .get(0)
}

/// A code that differs from `code` in its first digit.
fn wrong_code(code: &str) -> String {
    let first = code.as_bytes()[0] - b'0';
    format!("{}{}", (first + 1) % 10, &code[1..])
}

fn count(h: &mut Handle, table: &str) -> i64 {
    h.admin
        .query_one(
            &format!("SELECT count(*) FROM {table} WHERE user_id = $1"),
            &[&h.owner],
        )
        .expect("count rows")
        .get(0)
}

/// Signs the fixture user in through the pages and returns the session cookie value.
fn sign_in(h: &mut Handle, address: SocketAddr) -> String {
    let email = h.email.clone();
    let started = post_login(h, address, &email);
    assert_eq!(started.status, 303);
    let pending = started
        .cookie_value(PENDING_COOKIE)
        .expect("a pending-login cookie");
    let code = emailed_code(h);
    let signed_in = submit_code(h, address, &pending, &code);
    assert_eq!(signed_in.status, 303, "{signed_in:?}");
    signed_in
        .cookie_value(SESSION_COOKIE_NAME)
        .expect("a session cookie")
}

fn authenticate(h: &Handle, session: &str) -> Option<VerifiedSession> {
    let secret = SessionSecret::from_cookie_value(session).expect("a 64-digit cookie value");
    h.rt.block_on(session_repo::authenticate(&h.reader, &policy(), &secret))
        .expect("authenticate on a healthy database")
}

/// G-M02-3 HTTP half: an existing, a cooling-down and an unknown mailbox get the same status, headers and body, and the
/// unknown one enqueues nothing.
#[test]
fn g_m02_3_existing_cooling_down_and_unknown_mailbox_answer_identically() {
    run_db_fixture::<PagesFixture, _>("g_m02_3_http_uniform_start", |mut h| {
        let address = serve(&h);
        let email = h.email.clone();
        let issued = post_login(&h, address, &email);
        let cooling_down = post_login(&h, address, &email);
        let unknown = post_login(&h, address, &mailbox());

        assert_eq!(issued.status, 303);
        assert_eq!(issued.header("location"), vec!["/auth/code"]);
        assert_eq!(issued.comparable(), cooling_down.comparable());
        assert_eq!(
            issued.comparable(),
            unknown.comparable(),
            "an unknown mailbox must be indistinguishable from an existing one"
        );
        assert_eq!(
            count(&mut h, "ops.email_outbox"),
            1,
            "only the first start mails"
        );
    });
}

/// G-M02-3 HTTP half: the right code gives a 303 to the console root, a `__Host-` cookie with exactly the ruling-4
/// attributes, and a session that authenticates.
#[test]
fn g_m02_3_correct_code_sets_the_session_cookie_and_the_session_authenticates() {
    run_db_fixture::<PagesFixture, _>("g_m02_3_http_correct_code", |mut h| {
        let address = serve(&h);
        let email = h.email.clone();
        let pending = post_login(&h, address, &email)
            .cookie_value(PENDING_COOKIE)
            .expect("a pending-login cookie");
        let code = emailed_code(&mut h);
        let reply = submit_code(&h, address, &pending, &code);

        assert_eq!(reply.status, 303);
        assert_eq!(reply.header("location"), vec!["/"]);
        let line = reply
            .set_cookie(SESSION_COOKIE_NAME)
            .expect("a session cookie")
            .to_owned();
        let parts: Vec<&str> = line.split("; ").collect();
        let max_age = format!("Max-Age={}", AuthConfig::default().session_ttl.as_secs());
        assert_eq!(
            parts[1..],
            [
                max_age.as_str(),
                "Secure",
                "HttpOnly",
                "SameSite=Lax",
                "Path=/"
            ],
            "{SESSION_COOKIE_NAME} attributes"
        );
        assert!(!line.to_ascii_lowercase().contains("domain"));
        let cleared = reply
            .set_cookie(PENDING_COOKIE)
            .expect("pending cookie cleared");
        assert!(cleared.contains("Max-Age=0"), "{cleared}");

        let session = reply.cookie_value(SESSION_COOKIE_NAME).expect("value");
        assert!(
            authenticate(&h, &session).is_some(),
            "the cookie authenticates"
        );
        assert_eq!(count(&mut h, "control.sessions"), 1);
    });
}

/// G-M02-3 HTTP half: a consumed code replayed is rejected with the rejection page and mints no second session.
#[test]
fn g_m02_3_consumed_code_replayed_is_rejected() {
    run_db_fixture::<PagesFixture, _>("g_m02_3_http_consumed_code", |mut h| {
        let address = serve(&h);
        let email = h.email.clone();
        let pending = post_login(&h, address, &email)
            .cookie_value(PENDING_COOKIE)
            .expect("a pending-login cookie");
        let code = emailed_code(&mut h);

        assert_eq!(submit_code(&h, address, &pending, &code).status, 303);
        let replay = submit_code(&h, address, &pending, &code);
        assert_eq!(replay.status, 400, "{replay:?}");
        assert!(replay.set_cookie(SESSION_COOKIE_NAME).is_none());
        assert_eq!(count(&mut h, "control.sessions"), 1, "no second session");
    });
}

/// G-M02-3 HTTP half: after the attempt cap the right code is rejected too, every failure is the one rejection page,
/// and no session exists.
#[test]
fn g_m02_3_attempt_after_the_cap_is_rejected_even_with_the_right_code() {
    run_db_fixture::<PagesFixture, _>("g_m02_3_http_attempt_cap", |mut h| {
        let address = serve(&h);
        let email = h.email.clone();
        let pending = post_login(&h, address, &email)
            .cookie_value(PENDING_COOKIE)
            .expect("a pending-login cookie");
        let code = emailed_code(&mut h);
        let wrong = wrong_code(&code);

        let first = submit_code(&h, address, &pending, &wrong);
        assert_eq!(first.status, 400);
        for _ in 1..DEFAULT_ATTEMPTS {
            assert_eq!(
                submit_code(&h, address, &pending, &wrong).comparable(),
                first.comparable()
            );
        }
        let after_cap = submit_code(&h, address, &pending, &code);
        assert_eq!(
            after_cap.comparable(),
            first.comparable(),
            "the right code after the cap is the same rejection"
        );
        assert_eq!(count(&mut h, "control.sessions"), 0);
    });
}

/// ADR-0125 ruling 4: a POST without the configured Origin (none, foreign, `null`, a foreign Referer) is a 403 and
/// writes nothing; the configured Referer stands in only when Origin is absent.
#[test]
fn g_m02_3_post_without_the_configured_origin_is_forbidden_and_writes_nothing() {
    run_db_fixture::<PagesFixture, _>("g_m02_3_http_origin", |mut h| {
        let address = serve(&h);
        let body = format!("email={}", h.email);
        for headers in [
            vec![],
            vec![("Origin", "https://evil.example.test")],
            vec![("Origin", "null")],
            vec![("Origin", ORIGIN), ("Origin", ORIGIN)],
            vec![("Referer", "https://evil.example.test/auth/login")],
            vec![(
                "Referer",
                "https://console.example.test.evil.test/auth/login",
            )],
        ] {
            let reply = call(&h, address, "POST", "/auth/login", &headers, &body);
            assert_eq!(reply.status, 403, "{headers:?}: {reply:?}");
        }
        for path in ["/auth/code", "/auth/logout"] {
            let foreign = [("Origin", "https://evil.example.test")];
            assert_eq!(
                call(&h, address, "POST", path, &foreign, "code=1").status,
                403
            );
        }
        assert_eq!(count(&mut h, "ops.email_outbox"), 0);
        assert_eq!(count(&mut h, "control.email_challenges"), 0);

        let referer = format!("{ORIGIN}/auth/login");
        let reply = call(
            &h,
            address,
            "POST",
            "/auth/login",
            &[("Referer", &referer)],
            &body,
        );
        assert_eq!(
            reply.status, 303,
            "a same-origin Referer stands in for an absent Origin"
        );
        assert_eq!(count(&mut h, "control.email_challenges"), 1);
    });
}

/// ADR-0125 ruling 4: logout needs the CSRF token minted for the caller's own session; without it, with another
/// session's, or cross-site, it is a 403 and the session stays live; with it the session is revoked and the cookie cleared.
#[test]
fn g_m02_5_logout_needs_the_session_bound_csrf_token() {
    run_db_fixture::<PagesFixture, _>("g_m02_5_http_logout", |mut h| {
        let address = serve(&h);
        let session = sign_in(&mut h, address);
        let verified = authenticate(&h, &session).expect("live session");
        let token = csrf_token(&keys(), verified.session_id);
        let other = csrf_token(
            &keys(),
            humaux_application::session::SessionId(Uuid::new_v4()),
        );
        let cookie = format!("{SESSION_COOKIE_NAME}={session}");
        let logout = |h: &Handle, site: &str, header: Option<&str>| {
            let mut headers = vec![
                ("Origin", ORIGIN),
                ("Cookie", cookie.as_str()),
                ("Sec-Fetch-Site", site),
            ];
            if let Some(value) = header {
                headers.push((CSRF_HEADER_NAME, value));
            }
            call(h, address, "POST", "/auth/logout", &headers, "")
        };

        for (site, header) in [
            ("same-origin", None),
            ("same-origin", Some(other.as_str())),
            ("cross-site", Some(token.as_str())),
        ] {
            let reply = logout(&h, site, header);
            assert_eq!(reply.status, 403, "{site} {header:?}");
            assert!(
                authenticate(&h, &session).is_some(),
                "the session is still live"
            );
        }

        let reply = logout(&h, "same-origin", Some(&token));
        assert_eq!(reply.status, 303, "{reply:?}");
        assert_eq!(reply.header("location"), vec!["/auth/login"]);
        let cleared = reply
            .set_cookie(SESSION_COOKIE_NAME)
            .expect("cookie cleared");
        assert!(cleared.contains("Max-Age=0"), "{cleared}");
        assert!(
            authenticate(&h, &session).is_none(),
            "the session is revoked"
        );
    });
}

/// One request of the hardening sweep: method, path, extra request headers, form body.
type Case<'a> = (&'a str, &'a str, Vec<(&'a str, &'a str)>, &'a str);

/// ADR-0125 ruling 5: the four hardening headers are on every route and every outcome, refusals included.
#[test]
fn g_m02_3_every_route_carries_the_hardening_headers() {
    run_db_fixture::<PagesFixture, _>("g_m02_3_http_headers", |h| {
        let address = serve(&h);
        let form = format!("email={}", h.email);
        let cases: Vec<Case<'_>> = vec![
            ("GET", "/auth/login", vec![], ""),
            ("GET", "/auth/code", vec![], ""),
            ("GET", "/auth/logout", vec![], ""),
            ("POST", "/auth/login", vec![], form.as_str()),
            (
                "POST",
                "/auth/login",
                vec![("Origin", ORIGIN)],
                form.as_str(),
            ),
            (
                "POST",
                "/auth/login",
                vec![("Origin", ORIGIN)],
                "email=not-an-address",
            ),
            (
                "POST",
                "/auth/code",
                vec![("Origin", ORIGIN)],
                "code=123456",
            ),
            ("POST", "/auth/logout", vec![("Origin", ORIGIN)], ""),
            (
                "GET",
                "/auth/login",
                vec![("Forwarded", "1.1.1.1"), ("Forwarded", "2.2.2.2")],
                "",
            ),
        ];
        for (method, path, headers, body) in cases {
            let reply = call(&h, address, method, path, &headers, body);
            let label = format!("{method} {path} {headers:?} -> {}", reply.status);
            assert_eq!(reply.header("cache-control"), vec!["no-store"], "{label}");
            assert_eq!(
                reply.header("content-security-policy"),
                vec![CSP],
                "{label}"
            );
            assert_eq!(
                reply.header("x-content-type-options"),
                vec!["nosniff"],
                "{label}"
            );
            assert_eq!(
                reply.header("referrer-policy"),
                vec!["same-origin"],
                "{label}"
            );
        }
        let page = call(&h, address, "GET", "/auth/login", &[], "");
        assert_eq!(page.status, 200);
        assert!(page.body.contains("<html lang=\"en\">"));
        assert!(page.body.contains("<label for=\"email\">"));
        assert!(page.body.contains("autocomplete=\"email\""));
        let no_pending = call(&h, address, "GET", "/auth/code", &[], "");
        assert_eq!(
            (no_pending.status, no_pending.header("location")),
            (303, vec!["/auth/login"])
        );
    });
}

/// §72.3 / ADR-0100: the pre-auth IP bucket applies to `/auth/*` once per request: a capacity-two bucket answers the
/// third request with 429 and counts one `ip` refusal. Frozen time excludes refill during the database round trips.
#[test]
fn g_m03_1_the_pre_auth_limiter_applies_to_the_auth_pages() {
    run_db_fixture::<PagesFixture, _>("g_m03_1_http_preauth_limiter", |h| {
        let limited = guard(&h, 2);
        let rendered = Arc::clone(&limited);
        let frozen = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .expect("paused runtime");
        let statuses = frozen.block_on(async {
            // §79: runnable work keeps the paused clock from auto-advancing while Postgres is busy.
            let clock = tokio::spawn(async {
                loop {
                    tokio::task::yield_now().await;
                }
            });
            let (address, server) = start(limited).await;
            let mut statuses = Vec::new();
            for _ in 0..3 {
                statuses.push(http(address, "GET", "/auth/login", &[], "").await.status);
            }
            server.abort();
            clock.abort();
            statuses
        });
        assert_eq!(statuses, [200, 200, 429]);
        let mut metrics = String::new();
        rendered.metrics().render(&mut metrics);
        assert!(
            metrics.contains("rate_limit_rejected_total{scope=\"ip\"} 1"),
            "{metrics}"
        );
    });
}

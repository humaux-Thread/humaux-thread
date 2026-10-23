//! `adapters::tests::console_session` — G-M02-4 (M02 D6, migration 0270): the console session against a real Postgres as
//!   role_gateway through the four `control.session_*` doors.
//! Depends-on: crates=[humaux-adapters, humaux-application, humaux-domain, humaux-testkit, postgres, sqlx, tokio];
//!   services=[PostgreSQL(any) w=[control.sessions, control.users] x=[control.bump_user_security_epoch], PostgreSQL(role_gateway)];
//!   env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::postgres, adapters::session_repo, application::auth, application::login,
//!   application::session, domain::ids, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [a session survives nothing that changes its user's security epoch; a revoked, expired or idle session
//!   authenticates as None; only a successful login verify mints a session; the row stores the SHA-256 of the secret and
//!   never the secret; each test owns one throwaway user; a missing database is a visible §79.2 skip, a FAIL under
//!   HUMAUX_REQUIRE_DB]
//! Spec: Baseline §73.6; §74.4; §79.2

use humaux_adapters::postgres::RuntimeDbPool;
use humaux_adapters::session_repo::{self, IssuedSession};
use humaux_application::auth::AuthConfig;
use humaux_application::login::LoginVerifyOutcome;
use humaux_application::session::{SessionPolicy, SessionSecret, VerifiedSession};
use humaux_domain::ids::UserId;
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use sqlx::types::Uuid;

fn dsn_as_role(admin_dsn: &str, role: &str) -> String {
    let sep = if admin_dsn.contains('?') { '&' } else { '?' };
    format!("{admin_dsn}{sep}options=-c%20role%3D{role}")
}

fn policy() -> SessionPolicy {
    SessionPolicy::from(&AuthConfig::default())
}

struct Handle {
    rt: tokio::runtime::Runtime,
    gateway: RuntimeDbPool,
    admin: Client,
    user_id: Uuid,
}

impl Drop for Handle {
    fn drop(&mut self) {
        let _ = self.admin.batch_execute(&format!(
            "DELETE FROM control.sessions WHERE user_id = '{0}'; \
             DELETE FROM control.users WHERE user_id = '{0}';",
            self.user_id
        ));
    }
}

struct SessionFixture;

impl DbIntegrationFixture for SessionFixture {
    type Handle = Handle;

    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        let dsn =
            std::env::var("HUMAUX_TEST_PG_DSN").map_err(|_| DbFixtureSkipReason::NoDatabaseUrl)?;
        // dep: PostgreSQL(any) — the setup/inspection connection
        let mut admin = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        let migrated: bool = admin
            .query_one(
                "SELECT to_regprocedure('control.session_issue(uuid,bytea,integer)') IS NOT NULL",
                &[],
            )
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?
            .get(0);
        if !migrated {
            return Err(DbFixtureSkipReason::IsolationSetupFailed(
                "the session doors are missing: apply migration 0270 first".to_string(),
            ));
        }

        let user_id = Uuid::new_v4();
        admin
            .execute(
                "INSERT INTO control.users (user_id) VALUES ($1)",
                &[&user_id],
            )
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        // dep: PostgreSQL(role_gateway) — the pool under test
        let gateway = rt
            .block_on(RuntimeDbPool::connect(&dsn_as_role(&dsn, "role_gateway")))
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        Ok(Handle {
            rt,
            gateway,
            admin,
            user_id,
        })
    }
}

fn accepted(h: &Handle) -> LoginVerifyOutcome {
    LoginVerifyOutcome::Accepted(UserId(h.user_id))
}

fn issue_session(h: &Handle) -> IssuedSession {
    h.rt.block_on(session_repo::issue(&h.gateway, &policy(), accepted(h)))
        .expect("issue on a healthy database")
        .expect("a loginable user gets a session")
}

fn authenticate(h: &Handle, secret: &SessionSecret) -> Option<VerifiedSession> {
    h.rt.block_on(session_repo::authenticate(&h.gateway, &policy(), secret))
        .expect("authenticate on a healthy database")
}

fn session_count(h: &mut Handle) -> i64 {
    h.admin
        .query_one(
            "SELECT count(*) FROM control.sessions WHERE user_id = $1",
            &[&h.user_id],
        )
        .expect("count sessions")
        .get(0)
}

fn bump_epoch(h: &mut Handle) {
    h.admin
        .query_one("SELECT control.bump_user_security_epoch($1)", &[&h.user_id])
        .expect("bump_user_security_epoch");
}

fn expect_verified(h: &Handle, issued: &IssuedSession) -> VerifiedSession {
    let verified = authenticate(h, &issued.secret).expect("the session is live");
    assert_eq!(verified.session_id, issued.session_id);
    assert_eq!(verified.user_id, UserId(h.user_id));
    verified
}

/// G-M02-4: `bump_user_security_epoch` kills a session issued before it; a session issued after it is live.
#[test]
fn g_m02_4_session_does_not_survive_a_security_epoch_bump() {
    run_db_fixture::<SessionFixture, _>(
        "g_m02_4_session_does_not_survive_a_security_epoch_bump",
        |mut h| {
            let before = issue_session(&h);
            expect_verified(&h, &before);

            bump_epoch(&mut h);
            assert_eq!(
                authenticate(&h, &before.secret),
                None,
                "a session whose epoch snapshot is behind the user's epoch must not authenticate"
            );

            let after = issue_session(&h);
            expect_verified(&h, &after);
            assert_eq!(authenticate(&h, &before.secret), None);
            assert_eq!(session_count(&mut h), 2);
        },
    );
}

/// A revoked, an expired and an idle session each authenticate as None; revoke is idempotent.
#[test]
fn g_m02_4_revoked_expired_and_idle_sessions_are_refused() {
    run_db_fixture::<SessionFixture, _>(
        "g_m02_4_revoked_expired_and_idle_sessions_are_refused",
        |mut h| {
            let revoked = issue_session(&h);
            let expired = issue_session(&h);
            let idle = issue_session(&h);
            for s in [&revoked, &expired, &idle] {
                expect_verified(&h, s);
            }

            assert!(
                h.rt.block_on(session_repo::revoke(&h.gateway, revoked.session_id))
                    .unwrap()
            );
            assert!(
                !h.rt
                    .block_on(session_repo::revoke(&h.gateway, revoked.session_id))
                    .unwrap(),
                "a second revoke moves no row"
            );
            h.admin
                .execute(
                    "UPDATE control.sessions SET expires_at = now() - interval '1 minute' WHERE session_id = $1",
                    &[&expired.session_id.0],
                )
                .unwrap();
            h.admin
                .execute(
                    "UPDATE control.sessions SET last_seen_at = now() - make_interval(secs => $2) WHERE session_id = $1",
                    &[
                        &idle.session_id.0,
                        &(policy().idle_ttl.as_secs_f64() + 60.0),
                    ],
                )
                .unwrap();

            assert_eq!(authenticate(&h, &revoked.secret), None);
            assert_eq!(authenticate(&h, &expired.secret), None);
            assert_eq!(authenticate(&h, &idle.secret), None);
        },
    );
}

/// Only an accepted login mints a session; a rejected one writes nothing; an unknown secret and a non-loginable user get None.
#[test]
fn g_m02_4_only_an_accepted_login_mints_and_unknown_secrets_fail() {
    run_db_fixture::<SessionFixture, _>(
        "g_m02_4_only_an_accepted_login_mints_and_unknown_secrets_fail",
        |mut h| {
            let rejected =
                h.rt.block_on(session_repo::issue(
                    &h.gateway,
                    &policy(),
                    LoginVerifyOutcome::Rejected,
                ))
                .unwrap();
            assert!(rejected.is_none());
            assert_eq!(session_count(&mut h), 0);

            assert_eq!(authenticate(&h, &SessionSecret::generate()), None);

            h.admin
                .execute(
                    "UPDATE control.users SET state = 'SUSPENDED' WHERE user_id = $1",
                    &[&h.user_id],
                )
                .unwrap();
            let suspended =
                h.rt.block_on(session_repo::issue(&h.gateway, &policy(), accepted(&h)))
                    .unwrap();
            assert!(suspended.is_none(), "a suspended user is not loginable");
            assert_eq!(session_count(&mut h), 0);
        },
    );
}

/// The row holds the SHA-256 of the secret and nothing else of it; a use moves last_seen_at.
#[test]
fn g_m02_4_row_stores_only_the_digest_and_a_use_moves_last_seen() {
    run_db_fixture::<SessionFixture, _>(
        "g_m02_4_row_stores_only_the_digest_and_a_use_moves_last_seen",
        |mut h| {
            let issued = issue_session(&h);
            let stored: Vec<u8> = h
                .admin
                .query_one(
                    "SELECT token_hash FROM control.sessions WHERE session_id = $1",
                    &[&issued.session_id.0],
                )
                .unwrap()
                .get(0);
            assert_eq!(stored.as_slice(), issued.secret.digest().as_bytes());
            assert_ne!(
                hex::encode(&stored),
                issued.secret.cookie_value(),
                "the digest is not the secret"
            );

            h.admin
                .execute(
                    "UPDATE control.sessions SET last_seen_at = now() - interval '1 hour' WHERE session_id = $1",
                    &[&issued.session_id.0],
                )
                .unwrap();
            expect_verified(&h, &issued);
            let moved: bool = h
                .admin
                .query_one(
                    "SELECT last_seen_at > now() - interval '1 minute' FROM control.sessions WHERE session_id = $1",
                    &[&issued.session_id.0],
                )
                .unwrap()
                .get(0);
            assert!(moved, "an authenticated use must touch last_seen_at");
        },
    );
}

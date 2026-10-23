//! `adapters::tests::login_challenge` — G-M02-3 (M02 D2, migration 0266): the passwordless login code, against a real
//!   Postgres as role_gateway through the three `control.login_challenge_*` doors and the email door.
//! Depends-on: crates=[humaux-adapters, humaux-application, humaux-domain, humaux-testkit, postgres, sqlx, tokio];
//!   services=[PostgreSQL(any) w=[control.auth_events, control.email_challenges, control.user_emails, control.users,
//!   ops.email_delivery_events, ops.email_outbox] x=[control.login_challenge_issue], PostgreSQL(role_gateway)];
//!   env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::email, adapters::login_repo, adapters::postgres, application::auth,
//!   application::login, domain::ids, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [a consumed code fails on the second verify; the attempt after the cap fails even with the right code;
//!   an existing and an unknown mailbox get the identical response and an unknown one enqueues nothing; two concurrent
//!   verifies of one code yield exactly one acceptance; the code is stored only as a keyed hash and reaches only the
//!   outbox payload; each test owns one throwaway user and mailbox; a missing database is a visible §79.2 skip, a FAIL
//!   under HUMAUX_REQUIRE_DB]
//! Spec: Baseline §74.2; §74.3; §79.2

use std::sync::Barrier;
use std::time::Duration;

use humaux_adapters::email::RecipientAllowlist;
use humaux_adapters::login_repo::{self, LoginMail};
use humaux_adapters::postgres::RuntimeDbPool;
use humaux_application::auth::{AuthConfig, ChallengePolicy, CodeHash};
use humaux_application::login::{
    LoginStartReceipt, LoginStartResponse, LoginVerifyOutcome, StartDisposition,
};
use humaux_domain::ids::UserId;
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use sqlx::types::Uuid;

/// Not a secret: the keyed-hash pepper of these tests only.
const PEPPER: &[u8] = b"login-challenge-test-pepper";

const MAIL: LoginMail<'static> = LoginMail {
    from_email: "no-reply@humaux.example",
    subject: "Your sign-in code",
};

/// Attempt cap used by the cap test; every other test leaves the registry default.
const CAPPED_ATTEMPTS: i32 = 3;

fn dsn_as_role(admin_dsn: &str, role: &str) -> String {
    let sep = if admin_dsn.contains('?') { '&' } else { '?' };
    format!("{admin_dsn}{sep}options=-c%20role%3D{role}")
}

/// The registry default with the resend cooldown off, so a test can start twice in a row.
fn open_policy() -> ChallengePolicy {
    ChallengePolicy {
        send_cooldown: Duration::ZERO,
        ..AuthConfig::default().login_challenge
    }
}

struct Handle {
    rt: tokio::runtime::Runtime,
    gateway: RuntimeDbPool,
    admin: Client,
    user_id: Uuid,
    email: String,
}

impl Drop for Handle {
    fn drop(&mut self) {
        let _ = self.admin.batch_execute(&format!(
            "DELETE FROM ops.email_delivery_events \
               WHERE outbox_id IN (SELECT outbox_id FROM ops.email_outbox WHERE user_id = '{0}'); \
             DELETE FROM ops.email_outbox WHERE user_id = '{0}'; \
             DELETE FROM control.auth_events WHERE user_id = '{0}'; \
             DELETE FROM control.email_challenges WHERE user_id = '{0}'; \
             DELETE FROM control.user_emails WHERE user_id = '{0}'; \
             DELETE FROM control.users WHERE user_id = '{0}';",
            self.user_id
        ));
    }
}

struct LoginFixture;

impl DbIntegrationFixture for LoginFixture {
    type Handle = Handle;

    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        let dsn =
            std::env::var("HUMAUX_TEST_PG_DSN").map_err(|_| DbFixtureSkipReason::NoDatabaseUrl)?;
        // dep: PostgreSQL(any) — the setup/inspection connection
        let mut admin = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        let migrated: bool = admin
            .query_one(
                "SELECT to_regprocedure('control.login_challenge_issue(text,text,integer,integer,integer)') IS NOT NULL",
                &[],
            )
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?
            .get(0);
        if !migrated {
            return Err(DbFixtureSkipReason::IsolationSetupFailed(
                "the login challenge doors are missing: apply migration 0266 first".to_string(),
            ));
        }

        let user_id = Uuid::new_v4();
        let email = format!("login-challenge-test-{}@example.invalid", Uuid::new_v4());
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
        // dep: PostgreSQL(role_gateway) — the pool under test
        let gateway = rt
            .block_on(RuntimeDbPool::connect(&dsn_as_role(&dsn, "role_gateway")))
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        Ok(Handle {
            rt,
            gateway,
            admin,
            user_id,
            email,
        })
    }
}

fn start_for(h: &Handle, email: &str, policy: ChallengePolicy) -> LoginStartReceipt {
    h.rt.block_on(login_repo::start(
        &h.gateway,
        PEPPER,
        policy,
        &MAIL,
        &RecipientAllowlist::allow_all(),
        email,
    ))
    .expect("start never errors on a healthy database")
}

fn verify_for(h: &Handle, email: &str, candidate: &str) -> Result<LoginVerifyOutcome, String> {
    h.rt.block_on(login_repo::verify_code(
        &h.gateway, PEPPER, email, candidate,
    ))
    .map_err(|e| format!("{e:?}"))
}

/// The plaintext code of the user's newest outbox row, read from the payload: the one place it may exist.
fn emailed_code(h: &mut Handle) -> String {
    h.admin
        .query_one(
            "SELECT payload->>'code' FROM ops.email_outbox WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1",
            &[&h.user_id],
        )
        .expect("an outbox row with a code must exist")
        .get(0)
}

/// A code that differs from `code` in its first digit.
fn wrong_code(code: &str) -> String {
    let first = code.as_bytes()[0] - b'0';
    format!("{}{}", (first + 1) % 10, &code[1..])
}

fn challenge_state(h: &mut Handle) -> (i32, bool) {
    let row = h
        .admin
        .query_one(
            "SELECT attempts, consumed_at IS NOT NULL FROM control.email_challenges \
              WHERE user_id = $1 AND purpose = 'LOGIN' ORDER BY created_at DESC LIMIT 1",
            &[&h.user_id],
        )
        .expect("the login challenge row");
    (row.get(0), row.get(1))
}

fn accepted(h: &Handle) -> LoginVerifyOutcome {
    LoginVerifyOutcome::Accepted(UserId(h.user_id))
}

/// G-M02-3: a code that was accepted once is rejected on the second verify.
#[test]
fn g_m02_3_consumed_code_fails_on_the_second_verify() {
    run_db_fixture::<LoginFixture, _>(
        "g_m02_3_consumed_code_fails_on_the_second_verify",
        |mut h| {
            let email = h.email.clone();
            assert_eq!(
                start_for(&h, &email, open_policy()).disposition,
                StartDisposition::Issued
            );
            let code = emailed_code(&mut h);

            assert_eq!(verify_for(&h, &email, &code), Ok(accepted(&h)));
            assert_eq!(
                verify_for(&h, &email, &code),
                Ok(LoginVerifyOutcome::Rejected),
                "a consumed code must not verify twice"
            );
            assert_eq!(challenge_state(&mut h), (1, true));
        },
    );
}

/// G-M02-3: after the attempt cap, even the right code is rejected and the row stays unconsumed.
#[test]
fn g_m02_3_attempt_after_the_cap_fails_even_with_the_right_code() {
    run_db_fixture::<LoginFixture, _>(
        "g_m02_3_attempt_after_the_cap_fails_even_with_the_right_code",
        |mut h| {
            let email = h.email.clone();
            let policy = ChallengePolicy {
                max_attempts: CAPPED_ATTEMPTS,
                ..open_policy()
            };
            assert_eq!(
                start_for(&h, &email, policy).disposition,
                StartDisposition::Issued
            );
            let code = emailed_code(&mut h);
            let wrong = wrong_code(&code);

            for _ in 0..CAPPED_ATTEMPTS {
                assert_eq!(
                    verify_for(&h, &email, &wrong),
                    Ok(LoginVerifyOutcome::Rejected)
                );
            }
            assert_eq!(
                verify_for(&h, &email, &code),
                Ok(LoginVerifyOutcome::Rejected),
                "the attempt after the cap must fail even with the right code"
            );
            assert_eq!(challenge_state(&mut h), (CAPPED_ATTEMPTS, false));
        },
    );
}

/// G-M02-3: an existing, an unknown and a throttled mailbox get the byte-identical response and status; an unknown one
/// enqueues nothing.
#[test]
fn g_m02_3_existing_and_unknown_email_responses_are_identical() {
    run_db_fixture::<LoginFixture, _>(
        "g_m02_3_existing_and_unknown_email_responses_are_identical",
        |mut h| {
            let email = h.email.clone();
            let unknown = format!("nobody-{}@example.invalid", Uuid::new_v4());

            let existing = start_for(&h, &email, open_policy());
            let missing = start_for(&h, &unknown, open_policy());
            let throttled = start_for(
                &h,
                &email,
                ChallengePolicy {
                    send_cooldown: Duration::from_secs(3600),
                    ..open_policy()
                },
            );

            assert_eq!(existing.disposition, StartDisposition::Issued);
            assert_eq!(missing.disposition, StartDisposition::UnknownAccount);
            assert_eq!(throttled.disposition, StartDisposition::Throttled);
            for receipt in [&existing, &missing, &throttled] {
                assert_eq!(receipt.response, LoginStartResponse::UNIFORM);
            }
            assert_eq!(existing.response.http_status, missing.response.http_status);
            assert_eq!(
                existing.response.body.as_bytes(),
                missing.response.body.as_bytes()
            );

            let count = |h: &mut Handle, to: &str| -> i64 {
                h.admin
                    .query_one(
                        "SELECT count(*) FROM ops.email_outbox WHERE to_email = $1",
                        &[&to],
                    )
                    .expect("count outbox rows")
                    .get(0)
            };
            assert_eq!(
                count(&mut h, &email),
                1,
                "one mail: the throttled start sent none"
            );
            assert_eq!(
                count(&mut h, &unknown),
                0,
                "an unknown mailbox enqueues nothing"
            );
        },
    );
}

/// G-M02-3: two connections hold the same correct code between claim and settle; exactly one is accepted.
#[test]
fn g_m02_3_concurrent_double_verify_has_exactly_one_winner() {
    run_db_fixture::<LoginFixture, _>(
        "g_m02_3_concurrent_double_verify_has_exactly_one_winner",
        |mut h| {
            let email = h.email.clone();
            start_for(&h, &email, open_policy());
            let code = emailed_code(&mut h);

            let barrier = Barrier::new(2);
            let rt = &h.rt;
            let gateway = &h.gateway;
            let outcomes: Vec<LoginVerifyOutcome> = std::thread::scope(|scope| {
                let workers: Vec<_> = (0..2)
                    .map(|_| {
                        scope.spawn(|| {
                            let open = rt
                                .block_on(login_repo::begin_verify(gateway, &email))
                                .expect("claim");
                            barrier.wait();
                            rt.block_on(open.finish(PEPPER, &code)).expect("settle")
                        })
                    })
                    .collect();
                workers
                    .into_iter()
                    .map(|w| w.join().expect("worker thread"))
                    .collect()
            });

            let wins = outcomes.iter().filter(|o| **o == accepted(&h)).count();
            let losses = outcomes
                .iter()
                .filter(|o| **o == LoginVerifyOutcome::Rejected)
                .count();
            assert_eq!((wins, losses), (1, 1), "outcomes: {outcomes:?}");
            assert_eq!(challenge_state(&mut h), (1, true));
        },
    );
}

/// §74.2: the code is stored only as a keyed hash, and neither the subject nor the auth event carries it.
#[test]
fn g_m02_3_code_is_stored_only_as_a_keyed_hash() {
    run_db_fixture::<LoginFixture, _>("g_m02_3_code_is_stored_only_as_a_keyed_hash", |mut h| {
        let email = h.email.clone();
        start_for(&h, &email, open_policy());
        let code = emailed_code(&mut h);

        let stored: String = h
            .admin
            .query_one(
                "SELECT code_hash FROM control.email_challenges WHERE user_id = $1 AND purpose = 'LOGIN'",
                &[&h.user_id],
            )
            .expect("the stored hash")
            .get(0);
        assert_ne!(stored, code);
        assert_eq!(stored.len(), 64, "a hex HMAC-SHA256 digest");
        assert!(CodeHash::from_stored(stored.clone()).verify(PEPPER, &code));
        assert!(
            !CodeHash::from_stored(stored).verify(b"another pepper", &code),
            "the hash must be keyed"
        );

        let subject: String = h
            .admin
            .query_one(
                "SELECT subject FROM ops.email_outbox WHERE user_id = $1",
                &[&h.user_id],
            )
            .expect("the outbox subject")
            .get(0);
        assert!(!subject.contains(&code));

        let events: Vec<(String, String)> = h
            .admin
            .query(
                "SELECT event_type, metadata::text FROM control.auth_events WHERE user_id = $1",
                &[&h.user_id],
            )
            .expect("auth events")
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect();
        assert_eq!(
            events,
            vec![("LOGIN_CODE_SENT".to_string(), "{}".to_string())]
        );
    });
}

/// An expired code and an unknown mailbox are rejected; a newer code retires the older one.
#[test]
fn g_m02_3_expired_unknown_and_superseded_codes_are_rejected() {
    run_db_fixture::<LoginFixture, _>(
        "g_m02_3_expired_unknown_and_superseded_codes_are_rejected",
        |mut h| {
            let email = h.email.clone();
            start_for(&h, &email, open_policy());
            let first = emailed_code(&mut h);
            start_for(&h, &email, open_policy());
            let second = emailed_code(&mut h);
            assert_ne!(first, second, "two draws of a 6-digit code collided; rerun");

            assert_eq!(
                verify_for(&h, &email, &first),
                Ok(LoginVerifyOutcome::Rejected),
                "an older code is retired by the newer one"
            );
            h.admin
                .execute(
                    "UPDATE control.email_challenges SET expires_at = now() - interval '1 minute' \
                      WHERE user_id = $1 AND purpose = 'LOGIN' AND consumed_at IS NULL",
                    &[&h.user_id],
                )
                .expect("expire the live challenge");
            assert_eq!(
                verify_for(&h, &email, &second),
                Ok(LoginVerifyOutcome::Rejected),
                "an expired code must not verify"
            );
            let unknown = format!("nobody-{}@example.invalid", Uuid::new_v4());
            assert_eq!(
                verify_for(&h, &unknown, &second),
                Ok(LoginVerifyOutcome::Rejected)
            );
        },
    );
}

//! `adapters::tests::oauth_persistence` — M02-8 (M02 D3, D4, D5; migration 0268): the OAuth persistence doors against a real
//!   Postgres as role_gateway through `adapters::oauth_repo`: single-use code consume, grant issue and lookup, refresh rotation
//!   with reuse detection, revocation, and digest-only storage.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, postgres, serde_json, sqlx, time, tokio];
//!   services=[PostgreSQL(any) w=[control.oauth_authorization_codes, control.oauth_client_registrations,
//!   control.oauth_grants, control.oauth_refresh_tokens, control.tenants, control.users]
//!   x=[control.oauth_code_consume], PostgreSQL(role_gateway)]; env=[HUMAUX_TEST_PG_DSN];
//!   modules=[adapters::oauth_repo, adapters::postgres, domain::error, domain::ids, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [two connections consuming one code through a barrier yield exactly one winner, in every one of ROUNDS
//!   rounds; two concurrent rotations of one refresh token yield one rotation and one reuse, leaving no ACTIVE token;
//!   a replayed rotated token revokes the family and the grant; the stored digest is SHA-256 of the raw secret and the raw
//!   secret appears in no row; each test owns one throwaway tenant, user and client; a missing database is a visible §79.2
//!   skip, a FAIL under HUMAUX_REQUIRE_DB]
//! Spec: Baseline §6.2.1; §73.5; §79.2

use std::sync::Barrier;
use std::time::Duration;

use humaux_adapters::oauth_repo::{
    self, ClientKind, CodeIssue, ConsumedCode, GrantIssue, GrantRecord, GrantStatus, IssuedGrant,
    RefreshTokenStatus, RevokeReason, RotateOutcome, SecretHash,
};
use humaux_adapters::postgres::RuntimeDbPool;
use humaux_domain::error::ErrorCode;
use humaux_domain::ids::{TenantId, UserId};
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use sqlx::types::Uuid;
use time::OffsetDateTime;

/// Concurrent-consume rounds, each on a fresh code.
const ROUNDS: usize = 10;

/// Test policy values (the §78.1 registry owns the production ones).
const CODE_TTL: Duration = Duration::from_secs(300);
const REFRESH_TTL: Duration = Duration::from_secs(3600);
/// Shorter than [`REFRESH_TTL`] on purpose: the ceiling, not the refresh TTL, must then set every refresh expiry.
const GRANT_MAX_TTL: Duration = Duration::from_secs(600);

const REDIRECT_URI: &str = "https://client.example.invalid/callback";
const RESOURCE: &str = "https://resource.example.invalid/mcp";

fn dsn_as_role(admin_dsn: &str, role: &str) -> String {
    let sep = if admin_dsn.contains('?') { '&' } else { '?' };
    format!("{admin_dsn}{sep}options=-c%20role%3D{role}")
}

struct Handle {
    rt: tokio::runtime::Runtime,
    gateway: RuntimeDbPool,
    admin: Client,
    tenant_id: Uuid,
    user_id: Uuid,
    client_id: String,
    scopes: Vec<String>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        let _ = self.admin.batch_execute(&format!(
            "DELETE FROM control.oauth_refresh_tokens \
               WHERE grant_id IN (SELECT grant_id FROM control.oauth_grants WHERE tenant_id = '{tenant}'); \
             DELETE FROM control.oauth_grants WHERE tenant_id = '{tenant}'; \
             DELETE FROM control.oauth_authorization_codes WHERE tenant_id = '{tenant}'; \
             DELETE FROM control.oauth_client_registrations WHERE client_id = '{client}'; \
             DELETE FROM control.users WHERE user_id = '{user}'; \
             DELETE FROM control.tenants WHERE tenant_id = '{tenant}';",
            tenant = self.tenant_id,
            user = self.user_id,
            client = self.client_id,
        ));
    }
}

struct OauthFixture;

impl DbIntegrationFixture for OauthFixture {
    type Handle = Handle;

    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        let dsn =
            std::env::var("HUMAUX_TEST_PG_DSN").map_err(|_| DbFixtureSkipReason::NoDatabaseUrl)?;
        // dep: PostgreSQL(any) — the setup/inspection connection
        let mut admin = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        let migrated: bool = admin
            .query_one(
                "SELECT to_regprocedure('control.oauth_code_consume(bytea)') IS NOT NULL",
                &[],
            )
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?
            .get(0);
        if !migrated {
            return Err(DbFixtureSkipReason::IsolationSetupFailed(
                "the OAuth doors are missing: apply migration 0268 first".to_string(),
            ));
        }

        let setup = |e: postgres::Error| DbFixtureSkipReason::IsolationSetupFailed(e.to_string());
        let tenant_id: Uuid = admin
            .query_one(
                "INSERT INTO control.tenants (name, state) VALUES ($1, 'ACTIVE') RETURNING tenant_id",
                &[&"oauth_persistence.rs throwaway tenant"],
            )
            .map_err(setup)?
            .get(0);
        let user_id: Uuid = admin
            .query_one(
                "INSERT INTO control.users (state) VALUES ('ACTIVE') RETURNING user_id",
                &[],
            )
            .map_err(setup)?
            .get(0);
        let client_id = format!("https://client.example.invalid/{}", Uuid::new_v4());

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        // dep: PostgreSQL(role_gateway) — the pool under test
        let gateway = rt
            .block_on(RuntimeDbPool::connect(&dsn_as_role(&dsn, "role_gateway")))
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        let handle = Handle {
            rt,
            gateway,
            admin,
            tenant_id,
            user_id,
            client_id,
            scopes: vec!["memory:read".to_owned(), "memory:write".to_owned()],
        };
        let registered = handle
            .rt
            .block_on(async {
                let mut txn = oauth_repo::begin(&handle.gateway).await?;
                let registered = txn
                    .register_client(
                        &handle.client_id,
                        ClientKind::Dcr,
                        &[REDIRECT_URI.to_owned()],
                        &serde_json::json!({ "client_name": "oauth_persistence test" }),
                        None,
                    )
                    .await?;
                txn.commit().await?;
                Ok::<bool, ErrorCode>(registered)
            })
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(format!("{e:?}")))?;
        assert!(registered, "the fixture client registers");
        Ok(handle)
    }
}

/// A random secret and its digest; the raw value stays in the test.
fn secret(label: &str) -> (String, SecretHash) {
    let raw = format!("{label}-{}-{}", Uuid::new_v4(), Uuid::new_v4());
    let hash = SecretHash::of_secret(&raw);
    (raw, hash)
}

fn issue_code(h: &Handle, hash: &SecretHash, redirect_uri: &str) -> Option<OffsetDateTime> {
    h.rt.block_on(async {
        let mut txn = oauth_repo::begin(&h.gateway).await?;
        let expires = txn
            .issue_code(
                &CodeIssue {
                    code_hash: hash,
                    client_id: &h.client_id,
                    redirect_uri,
                    pkce_challenge: "challenge-not-a-secret",
                    resource: RESOURCE,
                    user_id: UserId(h.user_id),
                    tenant_id: TenantId(h.tenant_id),
                    workspace_id: None,
                    scopes: &h.scopes,
                },
                CODE_TTL,
            )
            .await?;
        txn.commit().await?;
        Ok::<_, ErrorCode>(expires)
    })
    .expect("issue_code never errors on a healthy database")
}

fn consume_code(h: &Handle, hash: &SecretHash) -> Option<ConsumedCode> {
    h.rt.block_on(async {
        let mut txn = oauth_repo::begin(&h.gateway).await?;
        let consumed = txn.consume_code(hash).await?;
        txn.commit().await?;
        Ok::<_, ErrorCode>(consumed)
    })
    .expect("consume_code never errors on a healthy database")
}

fn issue_grant(h: &Handle, refresh: &SecretHash) -> Option<IssuedGrant> {
    h.rt.block_on(async {
        let mut txn = oauth_repo::begin(&h.gateway).await?;
        let issued = txn
            .issue_grant(&GrantIssue {
                user_id: UserId(h.user_id),
                tenant_id: TenantId(h.tenant_id),
                workspace_id: None,
                client_id: &h.client_id,
                resource: RESOURCE,
                scopes: &h.scopes,
                refresh_hash: refresh,
                refresh_ttl: REFRESH_TTL,
                grant_max_ttl: GRANT_MAX_TTL,
            })
            .await?;
        txn.commit().await?;
        Ok::<_, ErrorCode>(issued)
    })
    .expect("issue_grant never errors on a healthy database")
}

fn lookup_grant(h: &Handle, grant_id: Uuid) -> Option<GrantRecord> {
    h.rt.block_on(async {
        let mut txn = oauth_repo::begin(&h.gateway).await?;
        let grant = txn.lookup_grant(grant_id).await?;
        txn.commit().await?;
        Ok::<_, ErrorCode>(grant)
    })
    .expect("lookup_grant never errors on a healthy database")
}

fn rotate(h: &Handle, presented: &SecretHash, successor: &SecretHash) -> RotateOutcome {
    h.rt.block_on(async {
        let mut txn = oauth_repo::begin(&h.gateway).await?;
        let outcome = txn
            .rotate_refresh(presented, successor, REFRESH_TTL)
            .await?;
        txn.commit().await?;
        Ok::<_, ErrorCode>(outcome)
    })
    .expect("rotate_refresh never errors on a healthy database")
}

fn revoke_grant(h: &Handle, grant_id: Uuid, reason: RevokeReason) -> bool {
    h.rt.block_on(async {
        let mut txn = oauth_repo::begin(&h.gateway).await?;
        let closed = txn.revoke_grant(grant_id, reason).await?;
        txn.commit().await?;
        Ok::<_, ErrorCode>(closed)
    })
    .expect("revoke_grant never errors on a healthy database")
}

fn revoke_family(h: &Handle, family_id: Uuid, reason: RevokeReason) -> bool {
    h.rt.block_on(async {
        let mut txn = oauth_repo::begin(&h.gateway).await?;
        let closed = txn.revoke_family(family_id, reason).await?;
        txn.commit().await?;
        Ok::<_, ErrorCode>(closed)
    })
    .expect("revoke_family never errors on a healthy database")
}

/// `(status, reuse_detected)` of one refresh token row, read as the owner.
fn token_state(h: &mut Handle, token: &SecretHash) -> (String, bool) {
    let row = h
        .admin
        .query_one(
            "SELECT status, reuse_detected_at IS NOT NULL FROM control.oauth_refresh_tokens WHERE token_hash = $1",
            &[&token.as_bytes().as_slice()],
        )
        .expect("the refresh token row");
    (row.get(0), row.get(1))
}

fn active_tokens_of(h: &mut Handle, grant_id: Uuid) -> i64 {
    h.admin
        .query_one(
            "SELECT count(*) FROM control.oauth_refresh_tokens WHERE grant_id = $1 AND status = 'ACTIVE'",
            &[&grant_id],
        )
        .expect("count active tokens")
        .get(0)
}

/// The spellings round-trip and nothing else parses.
#[test]
fn enum_spellings_round_trip_and_reject_unknown_input() {
    for v in ClientKind::ALL {
        assert_eq!(ClientKind::from_db_str(v.as_db_str()), Some(v));
    }
    for v in GrantStatus::ALL {
        assert_eq!(GrantStatus::from_db_str(v.as_db_str()), Some(v));
    }
    for v in RevokeReason::ALL {
        assert_eq!(RevokeReason::from_db_str(v.as_db_str()), Some(v));
    }
    for v in RefreshTokenStatus::ALL {
        assert_eq!(RefreshTokenStatus::from_db_str(v.as_db_str()), Some(v));
    }
    assert_eq!(ClientKind::from_db_str("static"), None);
    assert_eq!(GrantStatus::from_db_str(""), None);
}

/// A secret's hash never prints the secret or any digest byte.
#[test]
fn secret_hash_debug_is_redacted() {
    let (raw, hash) = secret("debug");
    let printed = format!("{hash:?}");
    assert_eq!(printed, "SecretHash(<redacted>)");
    assert!(!printed.contains(&raw));
    assert_eq!(hash.as_bytes().len(), 32);
}

/// A code is consumed once and returns the facts it was issued with; the replay gets nothing.
#[test]
fn code_is_consumed_once_and_returns_its_bound_facts() {
    run_db_fixture::<OauthFixture, _>("code_is_consumed_once_and_returns_its_bound_facts", |h| {
        let (_, hash) = secret("code");
        assert!(issue_code(&h, &hash, REDIRECT_URI).is_some());

        let first = consume_code(&h, &hash).expect("the first consume wins");
        assert_eq!(
            first,
            ConsumedCode {
                client_id: h.client_id.clone(),
                redirect_uri: REDIRECT_URI.to_owned(),
                pkce_challenge: "challenge-not-a-secret".to_owned(),
                resource: RESOURCE.to_owned(),
                user_id: UserId(h.user_id),
                tenant_id: TenantId(h.tenant_id),
                workspace_id: None,
                scopes: h.scopes.clone(),
            }
        );
        assert_eq!(
            consume_code(&h, &hash),
            None,
            "a consumed code never returns"
        );
        let unknown = SecretHash::of_secret("never issued");
        assert_eq!(consume_code(&h, &unknown), None);
    });
}

/// An expired code is not consumable.
#[test]
fn expired_code_is_not_consumable() {
    run_db_fixture::<OauthFixture, _>("expired_code_is_not_consumable", |mut h| {
        let (_, hash) = secret("expired");
        assert!(issue_code(&h, &hash, REDIRECT_URI).is_some());
        h.admin
            .execute(
                "UPDATE control.oauth_authorization_codes \
                    SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' \
                  WHERE code_hash = $1",
                &[&hash.as_bytes().as_slice()],
            )
            .expect("age the code");
        assert_eq!(consume_code(&h, &hash), None);
    });
}

/// A code is issued only for a live client and a registered redirect URI.
#[test]
fn code_issue_refuses_an_unregistered_redirect_and_a_disabled_client() {
    run_db_fixture::<OauthFixture, _>(
        "code_issue_refuses_an_unregistered_redirect_and_a_disabled_client",
        |mut h| {
            let (_, other_redirect) = secret("other-redirect");
            assert_eq!(
                issue_code(&h, &other_redirect, "https://evil.example.invalid/callback"),
                None
            );

            h.admin
                .execute(
                    "UPDATE control.oauth_client_registrations SET disabled_at = now() WHERE client_id = $1",
                    &[&h.client_id],
                )
                .expect("disable the client");
            let (_, disabled) = secret("disabled");
            assert_eq!(issue_code(&h, &disabled, REDIRECT_URI), None);

            let stored: i64 = h
                .admin
                .query_one(
                    "SELECT count(*) FROM control.oauth_authorization_codes WHERE tenant_id = $1",
                    &[&h.tenant_id],
                )
                .expect("count codes")
                .get(0);
            assert_eq!(stored, 0, "a refused issue stores nothing");
        },
    );
}

/// Two connections consume the same code at once; exactly one wins, in every round.
#[test]
// ponytail: nesting past clippy.toml's 5 (§78.4 / G-M01-8, flagged by PR #268 CI 39994974812 after #259 merged); refactor in a later card
#[allow(clippy::excessive_nesting)]
fn concurrent_double_consume_has_exactly_one_winner() {
    run_db_fixture::<OauthFixture, _>("concurrent_double_consume_has_exactly_one_winner", |h| {
        for round in 0..ROUNDS {
            let (_, hash) = secret("race");
            assert!(issue_code(&h, &hash, REDIRECT_URI).is_some());

            let barrier = Barrier::new(2);
            let (rt, gateway, hash) = (&h.rt, &h.gateway, &hash);
            let outcomes: Vec<Option<ConsumedCode>> = std::thread::scope(|scope| {
                let workers: Vec<_> = (0..2)
                    .map(|_| {
                        scope.spawn(|| {
                            let mut txn = rt.block_on(oauth_repo::begin(gateway)).expect("begin");
                            barrier.wait();
                            let consumed = rt.block_on(txn.consume_code(hash)).expect("consume");
                            rt.block_on(txn.commit()).expect("commit");
                            consumed
                        })
                    })
                    .collect();
                workers
                    .into_iter()
                    .map(|w| w.join().expect("worker thread"))
                    .collect()
            });
            let wins = outcomes.iter().filter(|o| o.is_some()).count();
            assert_eq!(wins, 1, "round {round}: exactly one consume may win");
            assert_eq!(outcomes.len(), 2, "round {round}: both connections ran");
        }
    });
}

/// A grant snapshots the live epochs, caps its refresh token by its ceiling, and is refused for a dead client or user.
#[test]
fn grant_issue_snapshots_live_epochs_and_caps_the_refresh_token() {
    run_db_fixture::<OauthFixture, _>(
        "grant_issue_snapshots_live_epochs_and_caps_the_refresh_token",
        |mut h| {
            h.admin
                .execute(
                    "UPDATE control.users SET security_epoch = 3 WHERE user_id = $1",
                    &[&h.user_id],
                )
                .expect("set the user epoch");
            let (_, refresh) = secret("refresh");
            let issued = issue_grant(&h, &refresh).expect("a grant for a live client and user");
            assert_eq!(
                issued.refresh_expires_at, issued.grant_max_expires_at,
                "the grant ceiling caps the first refresh token"
            );

            let grant = lookup_grant(&h, issued.grant_id).expect("the grant");
            assert_eq!(grant.status, Some(GrantStatus::Active));
            assert_eq!(grant.user_id, UserId(h.user_id));
            assert_eq!(grant.tenant_id, TenantId(h.tenant_id));
            assert_eq!(grant.client_id, h.client_id);
            assert_eq!(grant.resource, RESOURCE);
            assert_eq!(grant.scopes, h.scopes);
            assert_eq!(grant.revoked_at, None);
            assert_eq!(grant.user_epoch_snapshot, 3);
            assert_eq!(grant.live_user_epoch, 3);
            assert_eq!(grant.tenant_epoch_snapshot, grant.live_tenant_epoch);

            h.admin
                .execute(
                    "UPDATE control.users SET security_epoch = 4 WHERE user_id = $1",
                    &[&h.user_id],
                )
                .expect("bump the user epoch");
            let bumped = lookup_grant(&h, issued.grant_id).expect("the grant");
            assert_eq!(
                (bumped.user_epoch_snapshot, bumped.live_user_epoch),
                (3, 4),
                "the lookup reports snapshot and live epoch apart; the verdict is the caller's"
            );

            assert_eq!(lookup_grant(&h, Uuid::new_v4()), None, "unknown grant");

            h.admin
                .execute(
                    "UPDATE control.oauth_client_registrations SET disabled_at = now() WHERE client_id = $1",
                    &[&h.client_id],
                )
                .expect("disable the client");
            let (_, for_disabled) = secret("refresh-disabled");
            assert_eq!(issue_grant(&h, &for_disabled), None, "disabled client");

            h.admin
                .execute(
                    "UPDATE control.oauth_client_registrations SET disabled_at = NULL WHERE client_id = $1",
                    &[&h.client_id],
                )
                .expect("re-enable the client");
            h.admin
                .execute(
                    "UPDATE control.users SET state = 'SUSPENDED' WHERE user_id = $1",
                    &[&h.user_id],
                )
                .expect("suspend the user");
            let (_, for_suspended) = secret("refresh-suspended");
            assert_eq!(issue_grant(&h, &for_suspended), None, "inactive user");

            h.admin
                .execute(
                    "UPDATE control.users SET state = 'ACTIVE' WHERE user_id = $1",
                    &[&h.user_id],
                )
                .expect("reactivate the user");
            h.admin
                .execute(
                    "UPDATE control.tenants SET state = 'SUSPENDED' WHERE tenant_id = $1",
                    &[&h.tenant_id],
                )
                .expect("suspend the tenant");
            let (_, for_suspended_tenant) = secret("refresh-suspended-tenant");
            assert_eq!(
                issue_grant(&h, &for_suspended_tenant),
                None,
                "inactive tenant"
            );
        },
    );
}

/// Rotation hands the family on once; replaying the rotated token revokes the family and the grant.
#[test]
fn rotation_replay_revokes_the_family_and_the_grant() {
    run_db_fixture::<OauthFixture, _>(
        "rotation_replay_revokes_the_family_and_the_grant",
        |mut h| {
            let (_, first) = secret("refresh-1");
            let (_, second) = secret("refresh-2");
            let (_, third) = secret("refresh-3");
            let issued = issue_grant(&h, &first).expect("grant");

            match rotate(&h, &first, &second) {
                RotateOutcome::Rotated {
                    grant_id,
                    family_id,
                    expires_at,
                } => {
                    assert_eq!(grant_id, issued.grant_id);
                    assert_eq!(family_id, issued.family_id);
                    assert_eq!(
                        expires_at, issued.grant_max_expires_at,
                        "the grant ceiling caps the successor"
                    );
                }
                other => panic!("first rotation: {other:?}"),
            }
            assert_eq!(token_state(&mut h, &first), ("ROTATED".to_owned(), false));
            assert_eq!(token_state(&mut h, &second), ("ACTIVE".to_owned(), false));
            assert_eq!(active_tokens_of(&mut h, issued.grant_id), 1);

            assert_eq!(
                rotate(&h, &first, &third),
                RotateOutcome::ReuseDetected {
                    grant_id: issued.grant_id,
                    family_id: issued.family_id,
                },
                "the rotated token again is reuse"
            );
            assert_eq!(token_state(&mut h, &first), ("ROTATED".to_owned(), true));
            assert_eq!(token_state(&mut h, &second), ("REVOKED".to_owned(), false));
            assert_eq!(active_tokens_of(&mut h, issued.grant_id), 0);
            let grant = lookup_grant(&h, issued.grant_id).expect("the grant");
            assert_eq!(grant.status, Some(GrantStatus::Revoked));
            assert!(grant.revoked_at.is_some());
            let reason: String = h
                .admin
                .query_one(
                    "SELECT revoke_reason FROM control.oauth_grants WHERE grant_id = $1",
                    &[&issued.grant_id],
                )
                .expect("the revoke reason")
                .get(0);
            assert_eq!(reason, RevokeReason::RefreshReuse.as_db_str());

            assert_eq!(
                rotate(&h, &second, &third),
                RotateOutcome::Rejected,
                "the revoked successor no longer rotates"
            );
            let stored: i64 = h
                .admin
                .query_one(
                    "SELECT count(*) FROM control.oauth_refresh_tokens WHERE grant_id = $1",
                    &[&issued.grant_id],
                )
                .expect("count tokens")
                .get(0);
            assert_eq!(stored, 2, "a refused rotation stores no successor");
        },
    );
}

/// Unknown, expired and past-ceiling tokens are rejected without side effects.
#[test]
fn rotation_rejects_unknown_expired_and_past_ceiling_tokens() {
    run_db_fixture::<OauthFixture, _>(
        "rotation_rejects_unknown_expired_and_past_ceiling_tokens",
        |mut h| {
            let (_, unknown) = secret("unknown");
            let (_, next) = secret("next");
            assert_eq!(rotate(&h, &unknown, &next), RotateOutcome::Rejected);

            let (_, expiring) = secret("expiring");
            let issued = issue_grant(&h, &expiring).expect("grant");
            h.admin
                .execute(
                    "UPDATE control.oauth_refresh_tokens \
                        SET issued_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' \
                      WHERE token_hash = $1",
                    &[&expiring.as_bytes().as_slice()],
                )
                .expect("age the token");
            assert_eq!(rotate(&h, &expiring, &next), RotateOutcome::Rejected);
            assert_eq!(token_state(&mut h, &expiring), ("ACTIVE".to_owned(), false));
            assert_eq!(
                lookup_grant(&h, issued.grant_id).expect("grant").status,
                Some(GrantStatus::Active),
                "an expired token does not close its grant"
            );

            let (_, capped) = secret("capped");
            let capped_grant = issue_grant(&h, &capped).expect("grant");
            h.admin
                .execute(
                    "UPDATE control.oauth_grants \
                        SET issued_at = now() - interval '2 hours', grant_max_expires_at = now() - interval '1 hour' \
                      WHERE grant_id = $1",
                    &[&capped_grant.grant_id],
                )
                .expect("age the grant");
            assert_eq!(rotate(&h, &capped, &next), RotateOutcome::Rejected);
            assert_eq!(token_state(&mut h, &capped), ("ACTIVE".to_owned(), false));
        },
    );
}

/// Two connections rotate the same token at once: one rotation, one reuse, and no ACTIVE token is left.
#[test]
fn concurrent_double_rotation_is_one_rotation_and_one_reuse() {
    run_db_fixture::<OauthFixture, _>(
        "concurrent_double_rotation_is_one_rotation_and_one_reuse",
        |mut h| {
            let (_, first) = secret("race-refresh");
            let issued = issue_grant(&h, &first).expect("grant");
            let (_, succ_a) = secret("race-successor-a");
            let (_, succ_b) = secret("race-successor-b");

            let barrier = Barrier::new(2);
            let (rt, gateway, first) = (&h.rt, &h.gateway, &first);
            let outcomes: Vec<RotateOutcome> = std::thread::scope(|scope| {
                let workers: Vec<_> = [&succ_a, &succ_b]
                    .into_iter()
                    .map(|successor| {
                        let barrier = &barrier;
                        scope.spawn(move || {
                            let mut txn = rt.block_on(oauth_repo::begin(gateway)).expect("begin");
                            barrier.wait();
                            let outcome = rt
                                .block_on(txn.rotate_refresh(first, successor, REFRESH_TTL))
                                .expect("rotate");
                            rt.block_on(txn.commit()).expect("commit");
                            outcome
                        })
                    })
                    .collect();
                workers
                    .into_iter()
                    .map(|w| w.join().expect("worker thread"))
                    .collect()
            });

            let rotated = outcomes
                .iter()
                .filter(|o| matches!(o, RotateOutcome::Rotated { .. }))
                .count();
            let reused = outcomes
                .iter()
                .filter(|o| matches!(o, RotateOutcome::ReuseDetected { .. }))
                .count();
            assert_eq!((rotated, reused), (1, 1), "outcomes: {outcomes:?}");
            assert_eq!(active_tokens_of(&mut h, issued.grant_id), 0);
            assert_eq!(
                lookup_grant(&h, issued.grant_id).expect("grant").status,
                Some(GrantStatus::Revoked)
            );
        },
    );
}

/// Grant revoke and family revoke close the grant and every ACTIVE token; the second revoke reports nothing to close.
#[test]
fn revocation_closes_the_grant_and_its_active_tokens() {
    run_db_fixture::<OauthFixture, _>(
        "revocation_closes_the_grant_and_its_active_tokens",
        |mut h| {
            let (_, by_grant) = secret("by-grant");
            let grant = issue_grant(&h, &by_grant).expect("grant");
            assert!(revoke_grant(&h, grant.grant_id, RevokeReason::UserRequest));
            assert!(
                !revoke_grant(&h, grant.grant_id, RevokeReason::Operator),
                "a closed grant is not closed twice"
            );
            assert_eq!(
                token_state(&mut h, &by_grant),
                ("REVOKED".to_owned(), false)
            );
            let reason: String = h
                .admin
                .query_one(
                    "SELECT revoke_reason FROM control.oauth_grants WHERE grant_id = $1",
                    &[&grant.grant_id],
                )
                .expect("the revoke reason")
                .get(0);
            assert_eq!(
                reason,
                RevokeReason::UserRequest.as_db_str(),
                "first reason wins"
            );

            let (_, by_family) = secret("by-family");
            let family = issue_grant(&h, &by_family).expect("grant");
            assert!(revoke_family(&h, family.family_id, RevokeReason::Operator));
            assert!(!revoke_family(&h, family.family_id, RevokeReason::Operator));
            assert!(!revoke_family(&h, Uuid::new_v4(), RevokeReason::Operator));
            assert_eq!(
                token_state(&mut h, &by_family),
                ("REVOKED".to_owned(), false)
            );
            assert_eq!(
                lookup_grant(&h, family.grant_id).expect("grant").status,
                Some(GrantStatus::Revoked)
            );
            let (_, successor) = secret("after-revoke");
            assert_eq!(rotate(&h, &by_family, &successor), RotateOutcome::Rejected);
        },
    );
}

/// Client registration is create-or-refresh within one kind; another kind or a disabled client is refused; the metadata
/// bound holds; an unknown client is absent.
#[test]
fn client_registration_is_one_kind_per_id_and_bounded() {
    run_db_fixture::<OauthFixture, _>(
        "client_registration_is_one_kind_per_id_and_bounded",
        |mut h| {
            let uris = vec![
                REDIRECT_URI.to_owned(),
                "https://client.example.invalid/second".to_owned(),
            ];
            let outcome = h.rt.block_on(async {
                let mut txn = oauth_repo::begin(&h.gateway).await?;
                let refreshed = txn
                    .register_client(
                        &h.client_id,
                        ClientKind::Dcr,
                        &uris,
                        &serde_json::json!({}),
                        None,
                    )
                    .await?;
                let other_kind = txn
                    .register_client(
                        &h.client_id,
                        ClientKind::Cimd,
                        &uris,
                        &serde_json::json!({}),
                        None,
                    )
                    .await?;
                let record = txn.lookup_client(&h.client_id).await?;
                let absent = txn.lookup_client("https://absent.example.invalid/").await?;
                txn.commit().await?;
                Ok::<_, ErrorCode>((refreshed, other_kind, record, absent))
            });
            let (refreshed, other_kind, record, absent) = outcome.expect("registry round trip");
            assert!(refreshed, "same kind refreshes");
            assert!(!other_kind, "another kind is refused");
            let record = record.expect("the client");
            assert_eq!(record.kind, Some(ClientKind::Dcr));
            assert_eq!(record.redirect_uris, uris);
            assert_eq!(record.metadata, serde_json::json!({}));
            assert_eq!(record.disabled_at, None);
            assert_eq!(absent, None);

            let oversized = serde_json::json!({ "blob": "x".repeat(9000) });
            let refused = h.rt.block_on(async {
                let mut txn = oauth_repo::begin(&h.gateway).await?;
                txn.register_client(&h.client_id, ClientKind::Dcr, &uris, &oversized, None)
                    .await
            });
            assert_eq!(
                refused,
                Err(ErrorCode::InvalidInput),
                "metadata over 8 KiB is a CHECK violation"
            );

            h.admin
            .execute(
                "UPDATE control.oauth_client_registrations SET disabled_at = now() WHERE client_id = $1",
                &[&h.client_id],
            )
            .expect("disable the client");
            let after_disable = h.rt.block_on(async {
                let mut txn = oauth_repo::begin(&h.gateway).await?;
                let registered = txn
                    .register_client(
                        &h.client_id,
                        ClientKind::Dcr,
                        &uris,
                        &serde_json::json!({}),
                        None,
                    )
                    .await?;
                txn.commit().await?;
                Ok::<_, ErrorCode>(registered)
            });
            assert_eq!(
                after_disable,
                Ok(false),
                "a disabled client is not re-registered"
            );
        },
    );
}

/// Only the SHA-256 digest of a secret is stored, and the raw secret appears in no row.
#[test]
fn secrets_are_stored_only_as_digests() {
    run_db_fixture::<OauthFixture, _>("secrets_are_stored_only_as_digests", |mut h| {
        let (raw_code, code) = secret("digest-code");
        assert!(issue_code(&h, &code, REDIRECT_URI).is_some());
        let (raw_refresh, refresh) = secret("digest-refresh");
        issue_grant(&h, &refresh).expect("grant");

        let digest_matches = |h: &mut Handle, table: &str, column: &str, raw: &str| -> i64 {
            h.admin
                .query_one(
                    &format!(
                        "SELECT count(*) FROM {table} WHERE {column} = sha256(convert_to($1, 'UTF8'))"
                    ),
                    &[&raw],
                )
                .expect("digest comparison")
                .get(0)
        };
        let raw_in_rows = |h: &mut Handle, table: &str, raw: &str| -> i64 {
            h.admin
                .query_one(
                    &format!("SELECT count(*) FROM {table} t WHERE row_to_json(t)::text LIKE '%' || $1 || '%'"),
                    &[&raw],
                )
                .expect("raw secret scan")
                .get(0)
        };
        assert_eq!(
            digest_matches(
                &mut h,
                "control.oauth_authorization_codes",
                "code_hash",
                &raw_code
            ),
            1
        );
        assert_eq!(
            digest_matches(
                &mut h,
                "control.oauth_refresh_tokens",
                "token_hash",
                &raw_refresh
            ),
            1
        );
        for table in [
            "control.oauth_authorization_codes",
            "control.oauth_grants",
            "control.oauth_refresh_tokens",
            "control.oauth_client_registrations",
        ] {
            assert_eq!(
                raw_in_rows(&mut h, table, &raw_code),
                0,
                "{table}: raw code"
            );
            assert_eq!(
                raw_in_rows(&mut h, table, &raw_refresh),
                0,
                "{table}: raw refresh token"
            );
        }
    });
}

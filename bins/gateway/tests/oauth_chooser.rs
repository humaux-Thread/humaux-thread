//! `gateway::tests::oauth_chooser` — ADR-0137 candidate and atomic code acceptance with real PostgreSQL.
//! Depends-on: crates=[humaux-adapters, humaux-application, humaux-domain, humaux-testkit, postgres, serde_json, tokio, uuid]; services=[PostgreSQL(owner) r=[control.oauth_authorization_codes] w=[control.entitlement_snapshots, control.memberships, control.sessions, control.tenants, control.users, control.workspace_memberships, control.workspaces], PostgreSQL(role_gateway) x=[control.write_mcp_chooser_settings]]; env=[]; modules=[adapters::oauth_repo, adapters::postgres, adapters::session_repo, adapters::tests::support::throwaway_db, application::auth, application::login, application::oauth, application::oauth_exchange, application::session, domain::error, domain::identity, domain::ids, gateway::bootstrap, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [every test owns a migrated disposable database; decisions and issuance run through the gateway-role pool]
//! Spec: ADR-0137; Baseline §33; §73.6; §79.2

use std::time::Duration;

use humaux_adapters::{
    oauth_repo::{self, ClientKind, McpChooserChange},
    postgres::RuntimeDbPool,
    session_repo,
};
use humaux_application::{
    auth::AuthConfig,
    login::LoginVerifyOutcome,
    oauth::{
        AuthorizeRequest, ClientView, CodeExchangeRequest, ConsentTarget, OAuthPolicy,
        ValidatedAuthorize, authorize_request,
    },
    oauth_exchange::exchange_code,
    session::{SessionPolicy, VerifiedSession},
};
use humaux_domain::{
    error::ErrorCode,
    identity::{AuthorizationScope, BoundedSet, McpPolicyEffect, PrincipalId},
    ids::{TenantId, UserId, WorkspaceId},
};
use humaux_gateway::bootstrap::{issue_oauth_chooser_code, oauth_chooser_candidates};
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use serde_json::json;
use uuid::Uuid;

#[path = "../../../crates/adapters/tests/support/throwaway_db.rs"]
mod throwaway_db;

const CLIENT: &str = "https://client.example.invalid/chooser";
const REDIRECT: &str = "https://client.example.invalid/callback";
const RESOURCE: &str = "https://resource.example.invalid/mcp";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

struct Fixture;
impl DbIntegrationFixture for Fixture {
    type Handle = throwaway_db::ThrowawayDb;

    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        throwaway_db::create("atomic_chooser")
    }
}

struct Harness {
    owner: Client,
    gateway_dsn: String,
    pool: RuntimeDbPool,
    rt: tokio::runtime::Runtime,
    tenants: [TenantId; 3],
    workspaces: [WorkspaceId; 3],
    session: VerifiedSession,
    session_policy: SessionPolicy,
    validated: ValidatedAuthorize,
    resources: Vec<String>,
    scopes: Vec<String>,
    _db: throwaway_db::ThrowawayDb,
}

fn policy<'a>(resources: &'a [String], scopes: &'a [String]) -> OAuthPolicy<'a> {
    OAuthPolicy {
        code_ttl: Duration::from_secs(60),
        access_ttl: Duration::from_secs(60),
        refresh_ttl: Duration::from_secs(120),
        grant_max_ttl: Duration::from_secs(180),
        allowed_resources: resources,
        supported_scopes: scopes,
    }
}

fn seed_identity(
    owner: &mut Client,
    user: UserId,
    tenants: [TenantId; 3],
    workspaces: [WorkspaceId; 3],
) {
    let other_user = UserId(Uuid::new_v4());
    for actor in [user, other_user] {
        owner
            .execute(
                "INSERT INTO control.users (user_id, state) VALUES ($1, 'ACTIVE')",
                &[&actor.0],
            )
            .unwrap();
    }
    for tenant in tenants {
        owner.execute("INSERT INTO control.tenants (tenant_id, name, state) VALUES ($1, 'chooser fixture', 'ACTIVE')", &[&tenant.0]).unwrap();
        for actor in [user, other_user] {
            owner.execute("INSERT INTO control.memberships (tenant_id, user_id, state, role) VALUES ($1, $2, 'ACTIVE', 'ADMIN')", &[&tenant.0, &actor.0]).unwrap();
        }
    }
    for (tenant, workspace, actor) in [
        (tenants[0], workspaces[0], user),
        (tenants[0], workspaces[1], other_user),
        (tenants[1], workspaces[2], other_user),
    ] {
        owner.execute("INSERT INTO control.workspaces (tenant_id, workspace_id, name) VALUES ($1, $2, 'chooser workspace')", &[&tenant.0, &workspace.0]).unwrap();
        owner.execute("INSERT INTO control.workspace_memberships (tenant_id, workspace_id, user_id, role) VALUES ($1, $2, $3, 'MEMBER')",
            &[&tenant.0, &workspace.0, &actor.0]).unwrap();
    }
    for tenant in &tenants[..2] {
        owner.execute(
            "WITH clock AS (SELECT clock_timestamp() AS at)
             INSERT INTO control.entitlement_snapshots (tenant_id, effective, source_grant_ids, computed_at)
             SELECT $1, jsonb_build_object('mcp.billable_operations.per_period',
                 jsonb_build_object('limit',4,'period','subscription_period','charge_policy','success_only',
                 'period_start',at - interval '1 day','period_end',at + interval '1 day')),
                 ARRAY[]::uuid[],at FROM clock",
            &[&tenant.0],
        ).unwrap();
    }
}

impl Harness {
    fn new(db: throwaway_db::ThrowawayDb) -> Self {
        // dep: PostgreSQL(owner) — isolated fixture and post-commit readback.
        let mut owner = Client::connect(&db.dsn(), NoTls).unwrap();
        let user = UserId(Uuid::new_v4());
        let tenants = [1, 2, 3].map(|i| TenantId(Uuid::from_u128(i)));
        let workspaces = std::array::from_fn(|_| WorkspaceId(Uuid::new_v4()));
        seed_identity(&mut owner, user, tenants, workspaces);
        let sep = if db.dsn().contains('?') { '&' } else { '?' };
        let gateway_dsn = format!("{}{sep}options=-c%20role%3Drole_gateway", db.dsn());
        let rt = tokio::runtime::Runtime::new().unwrap();
        // dep: PostgreSQL(role_gateway) — production entry points through checked roles.
        let pool = rt.block_on(RuntimeDbPool::connect(&gateway_dsn)).unwrap();
        let session_policy = SessionPolicy::from(&AuthConfig::default());
        let redirects = vec![REDIRECT.to_owned()];
        let session = rt.block_on(async {
            let issued =
                session_repo::issue(&pool, &session_policy, LoginVerifyOutcome::Accepted(user))
                    .await
                    .unwrap()
                    .unwrap();
            let mut txn = oauth_repo::begin(&pool).await.unwrap();
            assert!(
                txn.register_client(CLIENT, ClientKind::Static, &redirects, &json!({}), None)
                    .await
                    .unwrap()
            );
            txn.commit().await.unwrap();
            session_repo::authenticate(&pool, &session_policy, &issued.secret)
                .await
                .unwrap()
                .unwrap()
        });
        let resources = vec![RESOURCE.to_owned()];
        let scopes = vec!["memory:read".to_owned()];
        let validated = authorize_request(
            &AuthorizeRequest {
                response_type: Some("code"),
                client_id: CLIENT,
                redirect_uri: Some(REDIRECT),
                code_challenge: Some(CHALLENGE),
                code_challenge_method: Some("S256"),
                resource: Some(RESOURCE),
                scope: Some("memory:read"),
                state: None,
            },
            Some(&ClientView {
                redirect_uris: &redirects,
                kind_recognized: true,
                disabled: false,
            }),
            &policy(&resources, &scopes),
        )
        .unwrap();
        Self {
            owner,
            gateway_dsn,
            pool,
            rt,
            tenants,
            workspaces,
            session,
            session_policy,
            validated,
            resources,
            scopes,
            _db: db,
        }
    }

    fn workspace(&self) -> ConsentTarget {
        (self.tenants[0], Some(self.workspaces[0]))
    }

    fn candidates(&self) -> Result<Vec<ConsentTarget>, ErrorCode> {
        self.rt
            .block_on(oauth_chooser_candidates(
                &self.pool,
                self.session,
                &self.session_policy,
                &self.validated,
            ))
            .map(|targets| targets.iter().copied().collect())
    }

    fn issue(&self, target: ConsentTarget) -> Result<String, ErrorCode> {
        self.issue_with_pool(&self.pool, target)
    }

    fn issue_with_pool(
        &self,
        pool: &RuntimeDbPool,
        target: ConsentTarget,
    ) -> Result<String, ErrorCode> {
        self.rt.block_on(issue_oauth_chooser_code(
            pool,
            self.session,
            &self.session_policy,
            target,
            &self.validated,
            &policy(&self.resources, &self.scopes),
        ))
    }

    fn assert_refused(&mut self, target: ConsentTarget, reason: ErrorCode, label: &str) {
        assert_eq!(self.issue(target).err(), Some(reason), "{label}");
        self.assert_no_codes();
    }

    fn assert_no_codes(&mut self) {
        let count: i64 = self
            .owner
            .query_one(
                "SELECT count(*) FROM control.oauth_authorization_codes",
                &[],
            )
            .unwrap()
            .get(0);
        assert_eq!(count, 0, "denied consent committed no code");
    }

    fn write(&self, change: McpChooserChange<'_>) {
        let actor = AuthorizationScope::new(
            self.tenants[0],
            PrincipalId(self.session.user_id.0),
            Some(self.session.user_id),
            BoundedSet::new([]).unwrap(),
        );
        self.rt
            .block_on(oauth_repo::write_settings(
                &self.pool,
                &actor,
                self.tenants[0],
                change,
            ))
            .unwrap();
    }

    fn configure(&self, policy_enabled: bool, groups_restricted: bool) {
        self.write(McpChooserChange::Configure {
            policy_enabled,
            groups_restricted,
        });
    }

    fn rule(&self, effect: McpPolicyEffect) {
        self.write(McpChooserChange::Rule {
            workspace_id: self.workspace().1,
            client_id: Some(CLIENT),
            effect,
            active: true,
        });
    }
}

#[test]
fn chooser_binds_exact_candidate_to_code_exchange_and_grant() {
    run_db_fixture::<Fixture, _>(
        "chooser_binds_exact_candidate_to_code_exchange_and_grant",
        |db| {
            let mut h = Harness::new(db);
            let target = h.workspace();
            assert_eq!(
                h.candidates().unwrap(),
                vec![(h.tenants[0], None), target, (h.tenants[1], None)],
                "multiple entitled tenants, only the subject's workspace, and a missing commercial entitlement excluded"
            );
            h.assert_refused(
                (h.tenants[0], Some(h.workspaces[1])),
                ErrorCode::Forbidden,
                "someone else's workspace",
            );
            h.assert_refused(
                (h.tenants[0], Some(h.workspaces[2])),
                ErrorCode::Forbidden,
                "foreign tenant workspace",
            );
            let code = h.issue(target).unwrap();
            let row = h.owner.query_one("SELECT tenant_id, workspace_id, user_id, used_at IS NOT NULL FROM control.oauth_authorization_codes", &[]).unwrap();
            assert_eq!(
                (
                    row.get::<_, Uuid>(0),
                    row.get::<_, Option<Uuid>>(1),
                    row.get::<_, Uuid>(2),
                    row.get::<_, bool>(3)
                ),
                (
                    target.0.0,
                    target.1.map(|id| id.0),
                    h.session.user_id.0,
                    false
                )
            );

            let grant = h.rt.block_on(async {
                let exchanged = exchange_code(
                    &h.pool,
                    &policy(&h.resources, &h.scopes),
                    CodeExchangeRequest {
                        grant_type: Some("authorization_code"),
                        client_id: CLIENT,
                        redirect_uri: Some(REDIRECT),
                        code_verifier: Some(VERIFIER),
                        resource: Some(RESOURCE),
                    },
                    Some(&code),
                )
                .await
                .unwrap()
                .unwrap();
                let mut txn = oauth_repo::begin(&h.pool).await.unwrap();
                let grant = txn
                    .lookup_grant(exchanged.access.grant_id)
                    .await
                    .unwrap()
                    .unwrap();
                txn.commit().await.unwrap();
                grant
            });
            assert_eq!(
                (grant.tenant_id, grant.workspace_id, grant.user_id),
                (target.0, target.1, h.session.user_id)
            );
            assert!(
                h.owner
                    .query_one(
                        "SELECT used_at IS NOT NULL FROM control.oauth_authorization_codes",
                        &[]
                    )
                    .unwrap()
                    .get::<_, bool>(0)
            );
        },
    );
}

#[test]
fn chooser_rechecks_session_and_active_identity() {
    run_db_fixture::<Fixture, _>("chooser_rechecks_session_and_active_identity", |db| {
        let mut h = Harness::new(db);
        let target = h.workspace();
        assert!(h.candidates().unwrap().contains(&target));
        let session_id = h.session.session_id.0;
        for change in [
            "UPDATE control.sessions SET revoked_at=clock_timestamp() WHERE session_id=$1",
            "UPDATE control.sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE session_id=$1",
            "UPDATE control.sessions SET last_seen_at=clock_timestamp()-interval '10 days' WHERE session_id=$1",
            "UPDATE control.sessions SET session_epoch=session_epoch+1 WHERE session_id=$1",
        ] {
            h.owner.execute(change, &[&session_id]).unwrap();
            h.assert_refused(
                target,
                ErrorCode::Forbidden,
                "session must be live at issuance",
            );
            assert_eq!(h.candidates(), Err(ErrorCode::Forbidden));
            h.owner.execute(
                "UPDATE control.sessions SET revoked_at=NULL, expires_at=clock_timestamp()+interval '1 hour',
                 last_seen_at=clock_timestamp(), session_epoch=0 WHERE session_id=$1",
                &[&session_id],
            ).unwrap();
        }
        h.owner
            .execute(
                "UPDATE control.users SET state='SUSPENDED' WHERE user_id=$1",
                &[&h.session.user_id.0],
            )
            .unwrap();
        assert_eq!(h.candidates(), Err(ErrorCode::Forbidden));
        h.assert_refused(target, ErrorCode::Forbidden, "inactive user");
    });
}

#[test]
fn chooser_rechecks_tenant_membership() {
    run_db_fixture::<Fixture, _>("chooser_rechecks_tenant_membership", |db| {
        let mut h = Harness::new(db);
        let target = (h.tenants[1], None);
        assert!(h.candidates().unwrap().contains(&target));
        h.owner.execute(
            "UPDATE control.memberships SET state='SUSPENDED' WHERE tenant_id=$1 AND user_id=$2",
            &[&target.0.0,&h.session.user_id.0],
        ).unwrap();
        assert!(!h.candidates().unwrap().contains(&target));
        h.assert_refused(
            target,
            ErrorCode::Forbidden,
            "tenant membership must be live",
        );
        h.owner
            .execute(
                "UPDATE control.tenants SET state='SUSPENDED' WHERE tenant_id=$1",
                &[&h.tenants[0].0],
            )
            .unwrap();
        h.assert_refused(h.workspace(), ErrorCode::Forbidden, "inactive tenant");
    });
}

#[test]
fn chooser_rechecks_workspace_membership_without_tenant_fallback() {
    run_db_fixture::<Fixture, _>(
        "chooser_rechecks_workspace_membership_without_tenant_fallback",
        |db| {
            let mut h = Harness::new(db);
            let target = h.workspace();
            assert!(h.candidates().unwrap().contains(&target));
            h.owner.execute(
            "UPDATE control.workspace_memberships SET state='REMOVED' WHERE workspace_id=$1 AND user_id=$2",
            &[&h.workspaces[0].0, &h.session.user_id.0],
        ).unwrap();
            let live = h.candidates().unwrap();
            assert!(!live.contains(&target));
            assert!(
                live.contains(&(target.0, None)),
                "tenant still eligible after workspace revocation"
            );
            h.assert_refused(
                target,
                ErrorCode::Forbidden,
                "revoked workspace must not fall back to tenant",
            );
        },
    );
}

#[test]
fn chooser_rechecks_policy_after_selection() {
    run_db_fixture::<Fixture, _>("chooser_rechecks_policy_after_selection", |db| {
        let mut h = Harness::new(db);
        h.configure(true, false);
        h.rule(McpPolicyEffect::Allow);
        let target = h.workspace();
        assert!(h.candidates().unwrap().contains(&target));
        h.rule(McpPolicyEffect::Deny);
        h.assert_refused(
            target,
            ErrorCode::Forbidden,
            "policy revocation after candidate list",
        );
    });
}

#[test]
fn chooser_rechecks_groups_after_selection() {
    run_db_fixture::<Fixture, _>("chooser_rechecks_groups_after_selection", |db| {
        let mut h = Harness::new(db);
        let group = Uuid::new_v4();
        let user = h.session.user_id;
        let member = |active| McpChooserChange::Member {
            group_id: group,
            user_id: user,
            active,
        };
        h.configure(false, true);
        h.write(McpChooserChange::Group {
            group_id: group,
            allowed: true,
        });
        h.write(member(true));
        let target = h.workspace();
        assert!(h.candidates().unwrap().contains(&target));
        h.write(member(false));
        h.assert_refused(
            target,
            ErrorCode::Forbidden,
            "group revocation after candidate list",
        );
    });
}

#[test]
fn chooser_rechecks_commercial_entitlement_after_selection() {
    run_db_fixture::<Fixture, _>(
        "chooser_rechecks_commercial_entitlement_after_selection",
        |db| {
            let mut h = Harness::new(db);
            let target = h.workspace();
            assert!(h.candidates().unwrap().contains(&target));
            h.owner
                .execute(
                    "UPDATE control.entitlement_snapshots SET effective='{}' WHERE tenant_id=$1",
                    &[&target.0.0],
                )
                .unwrap();
            h.assert_refused(
                target,
                ErrorCode::EntitlementRequired,
                "commercial revocation after candidate list",
            );
        },
    );
}

#[test]
fn chooser_serializes_first_deny_with_code_issuance() {
    run_db_fixture::<Fixture, _>("chooser_serializes_first_deny_with_code_issuance", |db| {
        let mut h = Harness::new(db);
        let target = h.workspace();
        assert!(h.candidates().unwrap().contains(&target));
        // dep: PostgreSQL(role_gateway) — retain the administrator's 0312 guard until the attempt finishes.
        let mut admin = Client::connect(&h.gateway_dsn, NoTls).unwrap();
        // dep: PostgreSQL(role_gateway) — hold the actual write door in one separate transaction.
        let mut writer = admin.transaction().unwrap();
        let sql = "SELECT control.write_mcp_chooser_settings($1,$2,$1,$3,$4)";
        let tenant = target.0.0;
        let user = h.session.user_id.0;
        for (action, values) in [
            (
                "configure",
                json!({"policy_enabled":true,"groups_restricted":false}),
            ),
            (
                "rule",
                json!({"workspace_id":h.workspaces[0].0,"client_id":CLIENT,"effect":"DENY","active":true}),
            ),
        ] {
            assert_eq!(
                writer
                    .query_one(sql, &[&tenant, &user, &action, &values])
                    .unwrap()
                    .get::<_, i64>(0),
                1
            );
        }
        // dep: PostgreSQL(role_gateway) — fail the blocked statement deterministically without a client sleep.
        let timed =
            h.rt.block_on(RuntimeDbPool::connect(&format!(
                "{}%20-c%20lock_timeout%3D150ms",
                h.gateway_dsn
            )))
            .unwrap();
        assert_eq!(
            h.issue_with_pool(&timed, target).err(),
            Some(ErrorCode::DependencyUnavailable),
            "uncommitted first deny must block issuance"
        );
        h.assert_no_codes();
        writer.commit().unwrap();
        h.assert_refused(
            target,
            ErrorCode::Forbidden,
            "committed first deny must refuse the stale selection",
        );
    });
}

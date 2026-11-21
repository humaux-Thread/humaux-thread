//! `adapters::tests::mcp_chooser_read` — ADR-0137 policy/group decisions and reader locks on real PostgreSQL.
//! Depends-on: crates=[humaux-adapters, humaux-application, humaux-domain, humaux-testkit, postgres, serde_json, tokio, uuid]; services=[PostgreSQL(owner) r=[control.mcp_group_members] w=[control.memberships, control.tenants, control.users, control.workspaces], PostgreSQL(role_gateway) x=[control.read_mcp_chooser_decisions, control.write_mcp_chooser_settings]]; env=[]; modules=[adapters::oauth_repo, adapters::postgres, adapters::tests::support::throwaway_db, application::oauth, domain::error, domain::identity, domain::ids, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [isolated migrated database per case; role_gateway invokes the production read and write doors]
//! Spec: ADR-0137; Baseline §79.2

use std::time::Duration;

use humaux_adapters::oauth_repo::{McpChooserChange, begin, write_settings};
use humaux_adapters::postgres::RuntimeDbPool;
use humaux_application::oauth::{
    AuthorizeRequest, ClientView, ConsentTarget, OAuthPolicy, ValidatedAuthorize, authorize_request,
};
use humaux_domain::error::ErrorCode;
use humaux_domain::identity::{AuthorizationScope, BoundedSet, McpPolicyEffect, PrincipalId};
use humaux_domain::ids::{TenantId, UserId, WorkspaceId};
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls, error::SqlState};
use serde_json::json;
use uuid::Uuid;

#[path = "support/throwaway_db.rs"]
mod throwaway_db;

const CLIENT: &str = "https://client.example.invalid/main";
const OTHER_CLIENT: &str = "https://client.example.invalid/other";

struct Fixture;

impl DbIntegrationFixture for Fixture {
    type Handle = throwaway_db::ThrowawayDb;

    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        throwaway_db::create("chooser_read")
    }
}

struct Harness {
    gateway: RuntimeDbPool,
    rt: tokio::runtime::Runtime,
    owner: Client,
    gateway_dsn: String,
    tenant: TenantId,
    first_tenant: TenantId,
    user: UserId,
    workspaces: [WorkspaceId; 2],
    _db: throwaway_db::ThrowawayDb,
}

impl Harness {
    fn new(db: throwaway_db::ThrowawayDb) -> Self {
        // dep: PostgreSQL(owner) — seed the isolated database.
        let mut owner = Client::connect(&db.dsn(), NoTls).unwrap();
        let tenant = TenantId(Uuid::from_u128(2));
        let first_tenant = TenantId(Uuid::from_u128(1));
        let user = UserId(Uuid::new_v4());
        let workspaces = std::array::from_fn(|_| WorkspaceId(Uuid::new_v4()));

        owner
            .execute(
                "INSERT INTO control.users (user_id, state) VALUES ($1, 'ACTIVE')",
                &[&user.0],
            )
            .unwrap();
        for id in [tenant, first_tenant] {
            owner.execute(
                "INSERT INTO control.tenants (tenant_id, name, state) VALUES ($1, 'chooser read fixture', 'ACTIVE')",
                &[&id.0],
            ).unwrap();
            owner.execute(
                "INSERT INTO control.memberships (tenant_id, user_id, state, role) VALUES ($1, $2, 'ACTIVE', 'ADMIN')",
                &[&id.0, &user.0],
            ).unwrap();
        }
        for workspace in workspaces {
            owner.execute(
                "INSERT INTO control.workspaces (tenant_id, workspace_id, name) VALUES ($1, $2, 'chooser read workspace')",
                &[&tenant.0, &workspace.0],
            ).unwrap();
        }

        let sep = if db.dsn().contains('?') { '&' } else { '?' };
        let gateway_dsn = format!("{}{sep}options=-c%20role%3Drole_gateway", db.dsn());
        let rt = tokio::runtime::Runtime::new().unwrap();
        // dep: PostgreSQL(role_gateway) — exercise the checked runtime pool.
        let gateway = rt.block_on(RuntimeDbPool::connect(&gateway_dsn)).unwrap();
        Self {
            gateway,
            rt,
            owner,
            gateway_dsn,
            tenant,
            first_tenant,
            user,
            workspaces,
            _db: db,
        }
    }

    fn write(&self, change: McpChooserChange<'_>) {
        let actor = AuthorizationScope::new(
            self.tenant,
            PrincipalId(self.user.0),
            Some(self.user),
            BoundedSet::new([]).unwrap(),
        );
        self.rt
            .block_on(write_settings(&self.gateway, &actor, self.tenant, change))
            .unwrap();
    }

    fn configure(&self, policy_enabled: bool, groups_restricted: bool) {
        self.write(McpChooserChange::Configure {
            policy_enabled,
            groups_restricted,
        });
    }

    fn read(
        &self,
        client_id: &str,
        candidates: &[ConsentTarget],
    ) -> Result<Vec<ConsentTarget>, ErrorCode> {
        let client = authorize_client(client_id);
        self.rt.block_on(async {
            let mut txn = begin(&self.gateway).await?;
            let targets = txn
                .allowed_mcp_targets(self.user, client.validated_client_id(), candidates)
                .await?;
            txn.commit().await?;
            Ok(targets.iter().copied().collect())
        })
    }
}

fn authorize_client(client_id: &str) -> ValidatedAuthorize {
    let redirect = "https://client.example.invalid/callback";
    let resource = "https://resource.example.invalid/mcp";
    let request = AuthorizeRequest {
        response_type: Some("code"),
        client_id,
        redirect_uri: Some(redirect),
        code_challenge: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        code_challenge_method: Some("S256"),
        resource: Some(resource),
        scope: Some("memory:read"),
        state: None,
    };
    authorize_request(
        &request,
        Some(&ClientView {
            redirect_uris: &[redirect.to_owned()],
            kind_recognized: true,
            disabled: false,
        }),
        &OAuthPolicy {
            code_ttl: Duration::from_secs(60),
            access_ttl: Duration::from_secs(60),
            refresh_ttl: Duration::from_secs(120),
            grant_max_ttl: Duration::from_secs(120),
            allowed_resources: &[resource.to_owned()],
            supported_scopes: &["memory:read".to_owned()],
        },
    )
    .unwrap()
}

#[test]
fn chooser_policy_matches_both_dimensions_and_deny_wins() {
    run_db_fixture::<Fixture, _>(
        "chooser_policy_matches_both_dimensions_and_deny_wins",
        |db| {
            let h = Harness::new(db);
            let [exact, other_workspace] =
                h.workspaces.map(|workspace| (h.tenant, Some(workspace)));
            let tenant_target = (h.tenant, None);
            let open = (h.first_tenant, None);
            let candidates = [exact, other_workspace, open, tenant_target];
            assert_eq!(
                h.read(CLIENT, &candidates),
                Ok(candidates.to_vec()),
                "absent policy"
            );

            let rule = |target: ConsentTarget, effect, active| McpChooserChange::Rule {
                workspace_id: target.1,
                client_id: Some(CLIENT),
                effect,
                active,
            };
            h.configure(false, false);
            h.write(rule(exact, McpPolicyEffect::Deny, true));
            assert_eq!(
                h.read(CLIENT, &candidates),
                Ok(candidates.to_vec()),
                "disabled policy ignores deny"
            );

            h.configure(true, false);
            h.write(rule(exact, McpPolicyEffect::Deny, false));
            h.write(rule(exact, McpPolicyEffect::Allow, true));
            assert_eq!(
                h.read(CLIENT, &candidates),
                Ok(vec![exact, open]),
                "exact workspace and unconfigured groups"
            );
            assert_eq!(
                h.read(OTHER_CLIENT, &candidates),
                Ok(vec![open]),
                "exact client"
            );
            h.write(rule(tenant_target, McpPolicyEffect::Allow, true));
            assert_eq!(
                h.read(CLIENT, &candidates),
                Ok(candidates.to_vec()),
                "NULL workspace rule admits every workspace for the exact client"
            );

            h.write(rule(exact, McpPolicyEffect::Deny, true));
            assert_eq!(
                h.read(CLIENT, &candidates),
                Ok(vec![other_workspace, open, tenant_target]),
                "deny overrides matching allow"
            );

            let overflow = vec![exact; BoundedSet::<ConsentTarget>::MAX_LEN + 1];
            assert_eq!(h.read(CLIENT, &overflow), Err(ErrorCode::InvalidInput));
        },
    );
}

#[test]
fn chooser_null_rule_dimensions_match_all_values_and_denies_win() {
    run_db_fixture::<Fixture, _>(
        "chooser_null_rule_dimensions_match_all_values_and_denies_win",
        |db| {
            let h = Harness::new(db);
            let [first, second] = h.workspaces.map(|workspace| (h.tenant, Some(workspace)));
            let candidates = [first, second, (h.tenant, None)];
            let rule = |workspace_id, client_id, effect| McpChooserChange::Rule {
                workspace_id,
                client_id,
                effect,
                active: true,
            };

            h.configure(true, false);
            h.write(rule(first.1, None, McpPolicyEffect::Allow));
            assert_eq!(
                h.read(CLIENT, &candidates),
                Ok(vec![first]),
                "NULL client matches the first client"
            );
            assert_eq!(
                h.read(OTHER_CLIENT, &candidates),
                Ok(vec![first]),
                "NULL client matches another client"
            );

            h.write(rule(None, None, McpPolicyEffect::Allow));
            assert_eq!(
                h.read(CLIENT, &candidates),
                Ok(candidates.to_vec()),
                "both NULL rule dimensions match all targets"
            );
            assert_eq!(
                h.read(OTHER_CLIENT, &candidates),
                Ok(candidates.to_vec()),
                "both NULL rule dimensions match all clients"
            );

            h.write(rule(first.1, Some(CLIENT), McpPolicyEffect::Allow));
            h.write(rule(None, None, McpPolicyEffect::Deny));
            assert_eq!(
                h.read(CLIENT, &candidates),
                Ok(vec![]),
                "wildcard deny overrides the exact allow"
            );
            assert_eq!(
                h.read(OTHER_CLIENT, &candidates),
                Ok(vec![]),
                "wildcard deny applies to the other client"
            );
        },
    );
}

#[test]
fn chooser_groups_require_any_allowed_active_membership() {
    run_db_fixture::<Fixture, _>(
        "chooser_groups_require_any_allowed_active_membership",
        |db| {
            let h = Harness::new(db);
            let target = (h.tenant, None);
            let [empty, disallowed, match_group] = std::array::from_fn(|_| Uuid::new_v4());
            let group = |group_id, allowed| McpChooserChange::Group { group_id, allowed };
            let member = |group_id, active| McpChooserChange::Member {
                group_id,
                user_id: h.user,
                active,
            };

            h.write(group(empty, true));
            h.configure(false, false);
            assert_eq!(
                h.read(CLIENT, &[target]),
                Ok(vec![target]),
                "group restrictions unset"
            );

            h.configure(false, true);
            assert_eq!(
                h.read(CLIENT, &[target]),
                Ok(vec![]),
                "empty allowed group admits nobody"
            );
            h.write(group(disallowed, false));
            h.write(member(disallowed, true));
            assert_eq!(
                h.read(CLIENT, &[target]),
                Ok(vec![]),
                "membership in a disallowed group cannot qualify"
            );

            h.write(group(match_group, true));
            h.write(member(match_group, true));
            assert_eq!(
                h.read(CLIENT, &[target]),
                Ok(vec![target]),
                "any allowed membership qualifies"
            );
            h.configure(true, true);
            h.write(McpChooserChange::Rule {
                workspace_id: None,
                client_id: Some(CLIENT),
                effect: McpPolicyEffect::Allow,
                active: true,
            });
            assert_eq!(h.read(CLIENT, &[target]), Ok(vec![target]));
            h.write(member(match_group, false));
            assert_eq!(
                h.read(CLIENT, &[target]),
                Ok(vec![]),
                "revoked membership cannot qualify"
            );
        },
    );
}

#[test]
fn chooser_read_failure_refuses_the_whole_batch() {
    run_db_fixture::<Fixture, _>("chooser_read_failure_refuses_the_whole_batch", |db| {
        let mut h = Harness::new(db);
        h.configure(false, true);
        let first = (h.first_tenant, None);
        let second = (h.tenant, None);
        assert_eq!(h.read(CLIENT, &[first, second]), Ok(vec![first]));

        // Only this fixture's schema is migrated into the disposable database.
        h.owner
            .batch_execute(
                "ALTER TABLE control.mcp_group_members RENAME TO unavailable_group_members",
            )
            .unwrap();
        assert_eq!(
            h.read(CLIENT, &[first, second]),
            Err(ErrorCode::DependencyUnavailable),
            "a failed group read cannot become no configuration or a partial result"
        );
    });
}

#[test]
fn chooser_shared_guard_blocks_first_configuration_until_commit() {
    run_db_fixture::<Fixture, _>(
        "chooser_shared_guard_blocks_first_configuration_until_commit",
        |db| {
            let h = Harness::new(db);
            let client = authorize_client(CLIENT);
            let mut reader = h.rt.block_on(begin(&h.gateway)).unwrap();
            let target = (h.tenant, None);
            let allowed =
                h.rt.block_on(reader.allowed_mcp_targets(
                    h.user,
                    client.validated_client_id(),
                    &[target],
                ))
                .unwrap();
            assert!(allowed.contains(&target));

            // dep: PostgreSQL(role_gateway) — a bounded attempt by the existing sole write door.
            let mut writer = Client::connect(&h.gateway_dsn, NoTls).unwrap();
            writer.batch_execute("SET lock_timeout = '150ms'").unwrap();
            let query = "SELECT control.write_mcp_chooser_settings($1,$2,$1,'configure',$3)";
            let values = json!({"policy_enabled": true, "groups_restricted": false});
            let error = writer
                .query_one(query, &[&h.tenant.0, &h.user.0, &values])
                .unwrap_err();
            assert_eq!(error.code(), Some(&SqlState::LOCK_NOT_AVAILABLE));

            h.rt.block_on(reader.commit()).unwrap();
            assert_eq!(
                writer
                    .query_one(query, &[&h.tenant.0, &h.user.0, &values])
                    .unwrap()
                    .get::<_, i64>(0),
                1
            );
            assert_eq!(
                h.read(CLIENT, &[target]),
                Ok(vec![]),
                "the new policy is visible after commit"
            );

            // dep: PostgreSQL(role_gateway) — exercise the decision door with a stale-snapshot isolation level.
            let mut stale = writer
                .build_transaction()
                .isolation_level(postgres::IsolationLevel::RepeatableRead)
                .start()
                .unwrap();
            let error = stale.query_one(
                "SELECT allowed FROM control.read_mcp_chooser_decisions($1,$2,ARRAY[$3::uuid],ARRAY[NULL::uuid])",
                &[&h.user.0, &CLIENT, &h.tenant.0],
            ).unwrap_err();
            assert_eq!(error.code(), Some(&SqlState::INVALID_TRANSACTION_STATE));

            // dep: PostgreSQL(role_gateway) — set non-default isolation on the checked pool.
            let serializable =
                h.rt.block_on(RuntimeDbPool::connect(&format!(
                    "{}%20-c%20default_transaction_isolation%3Dserializable",
                    h.gateway_dsn
                )))
                .unwrap();
            let result = h.rt.block_on(async {
                let mut txn = begin(&serializable).await?;
                txn.allowed_mcp_targets(h.user, client.validated_client_id(), &[target])
                    .await
            });
            assert_eq!(
                result,
                Err(ErrorCode::Internal),
                "invalid transaction isolation is an internal error"
            );
        },
    );
}

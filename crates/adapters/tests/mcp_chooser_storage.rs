//! `adapters::tests::mcp_chooser_storage` — ADR-0137 storage acceptance on PostgreSQL with isolated migrated control schema.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, postgres, serde_json, tokio, uuid]; services=[PostgreSQL(owner) r=[control.mcp_connection_policies, control.mcp_connection_rules, control.mcp_groups, control.mcp_group_members, control.tenants] w=[control.memberships, control.tenants, control.users, control.workspaces], PostgreSQL(role_gateway) x=[control.write_mcp_chooser_settings]]; env=[]; modules=[adapters::oauth_repo, adapters::postgres, adapters::tests::support::throwaway_db, domain::error, domain::identity, domain::ids, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [gateway-role results are checked against owner readback and the live PostgreSQL vocabulary]
//! Spec: ADR-0137; Baseline §78.2; §79.2

use humaux_adapters::oauth_repo::{McpChooserChange, write_settings};
use humaux_adapters::postgres::RuntimeDbPool;
use humaux_domain::error::ErrorCode;
use humaux_domain::identity::{AuthorizationScope, BoundedSet, McpPolicyEffect, PrincipalId};
use humaux_domain::ids::{TenantId, UserId, WorkspaceId};
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls, error::SqlState};
use serde_json::json;
use uuid::Uuid;

#[path = "support/throwaway_db.rs"]
mod throwaway_db;

struct Fixture;

impl DbIntegrationFixture for Fixture {
    type Handle = throwaway_db::ThrowawayDb;

    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        throwaway_db::create("mcp_chooser")
    }
}

fn scope(tenant: Uuid, user: Uuid) -> AuthorizationScope {
    AuthorizationScope::new(
        TenantId(tenant),
        PrincipalId(user),
        Some(UserId(user)),
        BoundedSet::new([]).unwrap(),
    )
}

fn configure(enabled: bool) -> McpChooserChange<'static> {
    McpChooserChange::Configure {
        policy_enabled: enabled,
        groups_restricted: true,
    }
}

#[test]
fn adr_0137_tenant_admin_write_contract() {
    run_db_fixture::<Fixture, _>("adr_0137_tenant_admin_write_contract", |db| {
        // dep: PostgreSQL(owner) — seed the isolated database and inspect committed rows.
        let mut owner = Client::connect(&db.dsn(), NoTls).unwrap();
        let [
            tenant,
            foreign_tenant,
            admin,
            member,
            foreign_admin,
            workspace,
            foreign_workspace,
            group,
        ] = std::array::from_fn(|_| Uuid::new_v4());
        for tenant in [tenant, foreign_tenant] {
            owner.execute("INSERT INTO control.tenants (tenant_id, name, state) VALUES ($1, 'chooser fixture', 'ACTIVE')", &[&tenant]).unwrap();
        }
        for (tenant, user, role) in [
            (tenant, admin, "ADMIN"),
            (tenant, member, "MEMBER"),
            (foreign_tenant, foreign_admin, "OWNER"),
        ] {
            owner
                .execute(
                    "INSERT INTO control.users (user_id, state) VALUES ($1, 'ACTIVE')",
                    &[&user],
                )
                .unwrap();
            owner.execute("INSERT INTO control.memberships (tenant_id, user_id, state, role) VALUES ($1, $2, 'ACTIVE', $3)", &[&tenant, &user, &role]).unwrap();
        }
        for (tenant, workspace) in [(tenant, workspace), (foreign_tenant, foreign_workspace)] {
            owner.execute("INSERT INTO control.workspaces (tenant_id, workspace_id, name) VALUES ($1, $2, 'chooser workspace')", &[&tenant, &workspace]).unwrap();
        }
        let sep = if db.dsn().contains('?') { '&' } else { '?' };
        let gateway_dsn = format!("{}{sep}options=-c%20role%3Drole_gateway", db.dsn());
        assert_contract_and_guard(&mut owner, &gateway_dsn, tenant, admin);

        let rt = tokio::runtime::Runtime::new().unwrap();
        // dep: PostgreSQL(role_gateway) — checked runtime pool, hitting the production write door.
        let pool = rt.block_on(RuntimeDbPool::connect(&gateway_dsn)).unwrap();
        let target = TenantId(tenant);
        let local_admin = scope(tenant, admin);
        let write = |actor: &AuthorizationScope, change| {
            rt.block_on(write_settings(&pool, actor, target, change))
        };
        let delegated_admin = AuthorizationScope::new(
            target,
            PrincipalId(Uuid::new_v4()),
            Some(UserId(admin)),
            BoundedSet::new([WorkspaceId(workspace)]).unwrap(),
        );
        assert_eq!(
            write(&delegated_admin, configure(true)),
            Err(ErrorCode::Forbidden),
            "delegated administrator principal must be refused"
        );
        assert_eq!(
            write(&scope(tenant, member), configure(true)),
            Err(ErrorCode::Forbidden),
            "ordinary member must be refused"
        );
        assert_eq!(
            write(&scope(foreign_tenant, foreign_admin), configure(true)),
            Err(ErrorCode::Forbidden),
            "foreign tenant administrator must be refused"
        );
        assert_eq!(
            owner
                .query_one("SELECT count(*) FROM control.mcp_connection_policies", &[])
                .unwrap()
                .get::<_, i64>(0),
            0,
            "refused writes left configuration absent"
        );

        assert_eq!(write(&local_admin, configure(true)), Ok(1));
        assert_eq!(
            write(&local_admin, configure(false)),
            Ok(2),
            "configuration version advances"
        );
        let stored = owner.query_one("SELECT policy_enabled, groups_restricted, version FROM control.mcp_connection_policies", &[]).unwrap();
        assert_eq!(
            (
                stored.get::<_, bool>(0),
                stored.get::<_, bool>(1),
                stored.get::<_, i64>(2)
            ),
            (false, true, 2)
        );

        assert_rules_and_groups(
            &mut owner,
            |change| write(&local_admin, change),
            [workspace, foreign_workspace],
            [member, foreign_admin],
            group,
        );
    });
}

fn assert_rules_and_groups(
    owner: &mut Client,
    write: impl Fn(McpChooserChange<'static>) -> Result<i64, ErrorCode>,
    [workspace, foreign_workspace]: [Uuid; 2],
    [member, foreign_admin]: [Uuid; 2],
    group: Uuid,
) {
    let rule = |workspace_id, effect, active| McpChooserChange::Rule {
        workspace_id,
        client_id: "chooser-test-client",
        effect,
        active,
    };
    assert_eq!(write(rule(None, McpPolicyEffect::Allow, true)), Ok(1));
    assert_eq!(write(rule(None, McpPolicyEffect::Allow, false)), Ok(2));
    assert_eq!(
        write(rule(
            Some(WorkspaceId(workspace)),
            McpPolicyEffect::Allow,
            true
        )),
        Ok(1)
    );
    assert_eq!(
        write(rule(
            Some(WorkspaceId(workspace)),
            McpPolicyEffect::Deny,
            true
        )),
        Ok(1)
    );
    assert_eq!(
        write(rule(
            Some(WorkspaceId(foreign_workspace)),
            McpPolicyEffect::Allow,
            true
        )),
        Err(ErrorCode::InvalidInput)
    );

    assert_eq!(
        write(McpChooserChange::Group {
            group_id: group,
            allowed: false
        }),
        Ok(1)
    );
    assert_eq!(
        write(McpChooserChange::Group {
            group_id: group,
            allowed: true
        }),
        Ok(2)
    );
    let group_member = |user_id, active| McpChooserChange::Member {
        group_id: group,
        user_id: UserId(user_id),
        active,
    };
    assert_eq!(write(group_member(member, true)), Ok(1));
    assert_eq!(write(group_member(member, false)), Ok(2));
    assert_eq!(
        write(group_member(foreign_admin, true)),
        Err(ErrorCode::InvalidInput)
    );

    let stored = owner.query_one("SELECT
        (SELECT count(*) FROM control.mcp_connection_rules),
        (SELECT version FROM control.mcp_connection_rules WHERE workspace_id IS NULL AND NOT active),
        (SELECT version FROM control.mcp_groups WHERE allowed),
        (SELECT version FROM control.mcp_group_members WHERE NOT active)", &[]).unwrap();
    assert_eq!(
        (
            stored.get::<_, i64>(0),
            stored.get::<_, i64>(1),
            stored.get::<_, i64>(2),
            stored.get::<_, i64>(3)
        ),
        (3, 2, 2, 2)
    );
}

fn assert_contract_and_guard(owner: &mut Client, gateway_dsn: &str, tenant: Uuid, admin: Uuid) {
    let pg_labels: Vec<String> = owner
        .query(
            "SELECT e.enumlabel::text FROM pg_catalog.pg_enum e
              JOIN pg_catalog.pg_type t ON t.oid = e.enumtypid
              JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
             WHERE n.nspname = 'control' AND t.typname = 'mcp_policy_effect'
             ORDER BY e.enumsortorder",
            &[],
        )
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(
        pg_labels,
        McpPolicyEffect::ALL.map(McpPolicyEffect::as_db_str)
    );

    // dep: PostgreSQL(role_gateway) — first configuration must conflict with an existing reader's guard.
    let mut gateway = Client::connect(gateway_dsn, NoTls).unwrap();
    {
        let mut reader = owner.transaction().unwrap();
        reader
            .query_one(
                "SELECT tenant_id FROM control.tenants WHERE tenant_id = $1 FOR SHARE",
                &[&tenant],
            )
            .unwrap();
        gateway.batch_execute("SET lock_timeout = '150ms'").unwrap();
        let err = gateway
            .query_one(
                "SELECT control.write_mcp_chooser_settings($1,$2,$1,'configure',$3)",
                &[
                    &tenant,
                    &admin,
                    &json!({"policy_enabled": true, "groups_restricted": true}),
                ],
            )
            .unwrap_err();
        assert_eq!(err.code(), Some(&SqlState::LOCK_NOT_AVAILABLE));
        reader.rollback().unwrap();
    }
}

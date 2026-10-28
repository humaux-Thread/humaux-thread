//! `public-pool::tests::notice` — G-M20-3 (ADR-0088 D-A..D-C, migration 0274): the AUTO policy selects nothing without a SHOWN
//!   on the current notice version; choice events are append-only and tenant-scoped; the Rust kind and channel sets equal the
//!   DB CHECK literals.
//! Depends-on: crates=[humaux-domain, humaux-testkit, postgres, sqlx, tokio, uuid];
//!   services=[PostgreSQL(any) r=[control.contribution_notice_events, control.contribution_policies, control.memberships]
//!   w=[control.contribution_notice_events, control.contribution_notices, control.contribution_policies, control.memberships,
//!   control.tenants, control.users] x=[control.toggle_contribution], PostgreSQL(role_gateway), PostgreSQL(role_maintenance)];
//!   env=[HUMAUX_TEST_PG_DSN];
//!   modules=[domain::error, domain::ids, humaux-testkit, public-pool::notice, public-pool::policy]
//! Called-by: [cargo-test]
//! Invariants: [every test owns one throwaway tenant, user and the notice versions it publishes, removed on drop; the notice
//!   table is global, so the binary runs in nextest's serial-public-notice group, and plain `cargo test` or targeted.yml must
//!   pass `-- --test-threads=1` (test (i) needs an empty notice table); a missing database is a visible §79.2 skip, a FAIL
//!   under HUMAUX_REQUIRE_DB; a notice's scope categories are unit-type names, so the fixture publishes 'FIX' (migration 0286,
//!   ADR-0088 amendment of M20-5)]
//! Spec: Baseline §12.1.1; §78.2; §79.2; ADR-0088 D-A; D-B; D-C

use std::collections::BTreeSet;

use humaux_domain::{
    error::{ConflictReason, ErrorCode},
    ids::{TenantId, UserId},
};
use humaux_public_pool::{
    notice::{self, NoticeChannel, NoticeEventKind, NoticeEventScope, Refusal},
    policy,
};
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use sqlx::{Connection, PgConnection, Postgres, Transaction};
use uuid::Uuid;

fn dsn_as_role(admin_dsn: &str, role: &str) -> String {
    let sep = if admin_dsn.contains('?') { '&' } else { '?' };
    format!("{admin_dsn}{sep}options=-c%20role%3D{role}")
}

struct Handle {
    rt: tokio::runtime::Runtime,
    gateway_dsn: String,
    maintenance_dsn: String,
    admin: Client,
    tenants: Vec<Uuid>,
    users: Vec<Uuid>,
    notices: Vec<i32>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        let tenants = self.tenants.clone();
        let users = self.users.clone();
        let notices = self.notices.clone();
        // Replica mode lets the owner past the append-only triggers of the events and the policy lifecycle.
        let _ = self
            .admin
            .batch_execute("SET session_replication_role = replica");
        let _ = self.admin.execute(
            "DELETE FROM control.contribution_notice_events WHERE tenant_id = ANY($1)",
            &[&tenants],
        );
        let _ = self.admin.execute(
            "DELETE FROM control.contribution_policies WHERE tenant_id = ANY($1)",
            &[&tenants],
        );
        let _ = self.admin.execute(
            "DELETE FROM control.contribution_notices WHERE notice_version = ANY($1)",
            &[&notices],
        );
        let _ = self.admin.execute(
            "DELETE FROM control.memberships WHERE tenant_id = ANY($1)",
            &[&tenants],
        );
        let _ = self
            .admin
            .batch_execute("SET session_replication_role = DEFAULT");
        let _ = self.admin.execute(
            "DELETE FROM control.users WHERE user_id = ANY($1)",
            &[&users],
        );
        let _ = self.admin.execute(
            "DELETE FROM control.tenants WHERE tenant_id = ANY($1)",
            &[&tenants],
        );
    }
}

struct NoticeFixture;

impl DbIntegrationFixture for NoticeFixture {
    type Handle = Handle;

    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        let dsn =
            std::env::var("HUMAUX_TEST_PG_DSN").map_err(|_| DbFixtureSkipReason::NoDatabaseUrl)?;
        // dep: PostgreSQL(any) — the setup/inspection connection
        let mut admin = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        let migrated: bool = admin
            .query_one(
                "SELECT to_regprocedure('control.toggle_contribution(boolean,text)') IS NOT NULL",
                &[],
            )
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?
            .get(0);
        if !migrated {
            return Err(DbFixtureSkipReason::IsolationSetupFailed(
                "the notice doors are missing: apply migration 0274 first".to_string(),
            ));
        }
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        // dep: PostgreSQL(role_gateway) — the request-path role the doors are granted to
        let gateway_dsn = dsn_as_role(&dsn, "role_gateway");
        // dep: PostgreSQL(role_maintenance) — the only role that may apply the cloud onboarding default
        let maintenance_dsn = dsn_as_role(&dsn, "role_maintenance");
        Ok(Handle {
            rt,
            gateway_dsn,
            maintenance_dsn,
            admin,
            tenants: Vec::new(),
            users: Vec::new(),
            notices: Vec::new(),
        })
    }
}

impl Handle {
    /// A throwaway tenant and its ACTIVE OWNER; all are removed on drop.
    fn new_tenant(&mut self) -> (Uuid, Uuid) {
        let tenant: Uuid = self
            .admin
            .query_one(
                "INSERT INTO control.tenants (name) VALUES ('m20-4a-notice') RETURNING tenant_id",
                &[],
            )
            .expect("insert tenant")
            .get(0);
        self.tenants.push(tenant);
        let user = self.new_member(tenant, "OWNER");
        (tenant, user)
    }

    /// A throwaway user holding an ACTIVE membership of `tenant` with `role`.
    fn new_member(&mut self, tenant: Uuid, role: &str) -> Uuid {
        let user = Uuid::new_v4();
        self.admin
            .execute("INSERT INTO control.users (user_id) VALUES ($1)", &[&user])
            .expect("insert user");
        self.users.push(user);
        self.admin
            .execute(
                "INSERT INTO control.memberships (tenant_id, user_id, role, state) VALUES ($1, $2, $3, 'ACTIVE')",
                &[&tenant, &user, &role],
            )
            .expect("insert membership");
        user
    }

    /// Publishes the next notice version, effective immediately: the greatest `published_at` so far.
    fn publish_notice(&mut self) -> i32 {
        let version: i32 = self
            .admin
            .query_one(
                "INSERT INTO control.contribution_notices \
                   (notice_version, text_sha256, scope_categories, licence_text, licence_code, published_at) \
                 SELECT coalesce(max(notice_version), 0) + 1, sha256(convert_to(gen_random_uuid()::text, 'UTF8')), \
                        ARRAY['FIX'], 'CC-BY-4.0', 'MIT', clock_timestamp() \
                   FROM control.contribution_notices RETURNING notice_version",
                &[],
            )
            .expect("publish notice")
            .get(0);
        self.notices.push(version);
        version
    }

    /// The open policy head as (version, mode), if the tenant has a policy row.
    fn head(&mut self, tenant: Uuid) -> Option<(i64, String)> {
        self.admin
            .query_opt(
                "SELECT policy_version, contribution_mode FROM control.contribution_policies \
                  WHERE tenant_id = $1 AND effective_to IS NULL",
                &[&tenant],
            )
            .expect("read policy head")
            .map(|row| (row.get(0), row.get(1)))
    }

    /// Every event kind of the tenant, oldest first.
    fn kinds(&mut self, tenant: Uuid) -> Vec<String> {
        self.admin
            .query(
                "SELECT kind FROM control.contribution_notice_events WHERE tenant_id = $1 ORDER BY at, event_id",
                &[&tenant],
            )
            .expect("read events")
            .iter()
            .map(|row| row.get(0))
            .collect()
    }

    /// A tenant on the cloud default (AUTO, version 1) with a SHOWN on the notice just published.
    fn auto_tenant_shown_on_first_notice(&mut self) -> (Uuid, Uuid, i32) {
        let (tenant, user) = self.new_tenant();
        let version = self.publish_notice();
        assert!(
            self.apply_default(tenant, user),
            "a tenant without a policy row gets AUTO"
        );
        self.shown(tenant, user, version)
            .expect("SHOWN on the current version");
        (tenant, user, version)
    }

    fn apply_default(&self, tenant: Uuid, user: Uuid) -> bool {
        self.rt.block_on(async {
            let mut conn = connect(&self.maintenance_dsn).await;
            let mut tx = begin(&mut conn, tenant, user).await;
            let written = policy::apply_cloud_default(&mut tx)
                .await
                .expect("apply the cloud default");
            tx.commit().await.expect("commit");
            written
        })
    }

    fn shown(&self, tenant: Uuid, user: Uuid, version: i32) -> Result<Uuid, Refusal> {
        self.rt.block_on(async {
            let mut conn = connect(&self.gateway_dsn).await;
            let mut tx = begin(&mut conn, tenant, user).await;
            let result = notice::record_shown(&mut tx, version, NoticeChannel::Popup).await;
            settle(tx, result.is_ok()).await;
            result
        })
    }

    fn toggle(&self, tenant: Uuid, user: Uuid, on: bool) -> Result<i64, Refusal> {
        self.rt.block_on(async {
            let mut conn = connect(&self.gateway_dsn).await;
            let mut tx = begin(&mut conn, tenant, user).await;
            let result = policy::toggle(&mut tx, on, NoticeChannel::Console).await;
            settle(tx, result.is_ok()).await;
            result
        })
    }

    fn toggle_member(&self, tenant: Uuid, user: Uuid, on: bool) -> Result<Uuid, Refusal> {
        self.rt.block_on(async {
            let mut conn = connect(&self.gateway_dsn).await;
            let mut tx = begin(&mut conn, tenant, user).await;
            let result = policy::toggle_member(&mut tx, on, NoticeChannel::Console).await;
            settle(tx, result.is_ok()).await;
            result
        })
    }

    /// SQLSTATE and refusal message of a tenant-level toggle that the door must refuse.
    fn toggle_error(&self, tenant: Uuid, user: Uuid, on: bool) -> (Option<String>, String) {
        self.rt.block_on(async {
            let mut conn = connect(&self.gateway_dsn).await;
            let mut tx = begin(&mut conn, tenant, user).await;
            let error = sqlx::query("SELECT control.toggle_contribution($1, 'CONSOLE')")
                .bind(on)
                .execute(&mut *tx)
                .await
                .expect_err("the toggle is refused");
            let message = error
                .as_database_error()
                .map(|db| db.message().to_owned())
                .expect("a database error");
            (sqlstate(&error), message)
        })
    }

    fn current(&self, tenant: Uuid, user: Uuid) -> Option<i32> {
        self.rt.block_on(async {
            let mut conn = connect(&self.gateway_dsn).await;
            let mut tx = begin(&mut conn, tenant, user).await;
            let current = notice::current_notice(&mut tx)
                .await
                .expect("the current notice");
            settle(tx, false).await;
            current
        })
    }

    fn acked(&self, tenant: Uuid, user: Uuid, version: i32) -> Result<Uuid, Refusal> {
        self.rt.block_on(async {
            let mut conn = connect(&self.gateway_dsn).await;
            let mut tx = begin(&mut conn, tenant, user).await;
            let result = notice::acknowledge(&mut tx, version, NoticeChannel::Console).await;
            settle(tx, result.is_ok()).await;
            result
        })
    }

    fn authorized(&self, tenant: Uuid, user: Uuid) -> bool {
        self.authorized_for(tenant, user, user)
    }

    /// The predicate for `subject`, asked from `session_user`'s session of `tenant`.
    fn authorized_for(&self, tenant: Uuid, session_user: Uuid, subject: Uuid) -> bool {
        self.rt.block_on(async {
            let mut conn = connect(&self.gateway_dsn).await;
            let mut tx = begin(&mut conn, tenant, session_user).await;
            let authorized =
                notice::contribution_authorized(&mut tx, TenantId(tenant), UserId(subject))
                    .await
                    .expect("the predicate");
            settle(tx, false).await;
            authorized
        })
    }

    /// SQLSTATE and text of a statement that `role_gateway` must not be allowed to run.
    fn gateway_statement_error(
        &self,
        tenant: Uuid,
        user: Uuid,
        statement: &str,
    ) -> (Option<String>, String) {
        self.rt.block_on(async {
            let mut conn = connect(&self.gateway_dsn).await;
            let mut tx = begin(&mut conn, tenant, user).await;
            let error = sqlx::query(statement)
                .bind(tenant)
                .execute(&mut *tx)
                .await
                .expect_err(statement);
            (sqlstate(&error), error.to_string())
        })
    }

    /// Events a gateway session of `tenant` sees: those of `of`, or all of them.
    fn visible_events(&self, tenant: Uuid, user: Uuid, of: Option<Uuid>) -> i64 {
        self.rt.block_on(async {
            let mut conn = connect(&self.gateway_dsn).await;
            let mut tx = begin(&mut conn, tenant, user).await;
            let count = sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM control.contribution_notice_events WHERE $1::uuid IS NULL OR tenant_id = $1",
            )
            .bind(of)
            .fetch_one(&mut *tx)
            .await
            .expect("count events");
            settle(tx, false).await;
            count
        })
    }
}

async fn connect(dsn: &str) -> PgConnection {
    // dep: PostgreSQL(any) — one connection per door call, as the role the DSN names
    PgConnection::connect(dsn).await.expect("connect")
}

async fn begin(conn: &mut PgConnection, tenant: Uuid, user: Uuid) -> Transaction<'_, Postgres> {
    // dep: PostgreSQL(any) — one transaction per door call
    let mut tx = conn.begin().await.expect("begin");
    notice::install_session(&mut tx, TenantId(tenant), UserId(user))
        .await
        .expect("install session");
    tx
}

/// Commits when `commit`, rolls back otherwise; consuming the transaction inside the runtime.
async fn settle(tx: Transaction<'_, Postgres>, commit: bool) {
    if commit {
        tx.commit().await.expect("commit");
    } else {
        tx.rollback().await.expect("rollback");
    }
}

fn refused(code: ErrorCode, reason: ConflictReason) -> Refusal {
    Refusal {
        code,
        reason: Some(reason),
    }
}

/// G-M20-3 (a): an AUTO policy without any SHOWN does not authorize contribution.
#[test]
fn g_m20_3_a_auto_without_shown_is_not_authorized() {
    run_db_fixture::<NoticeFixture, _>(
        "g_m20_3_a_auto_without_shown_is_not_authorized",
        |mut h| {
            let (tenant, user) = h.new_tenant();
            let version = h.publish_notice();
            assert!(
                h.apply_default(tenant, user),
                "a tenant without a policy row gets AUTO"
            );
            assert_eq!(
                h.head(tenant),
                Some((1, "AUTO_AFTER_USER_DISTILLATION".to_owned()))
            );
            assert_eq!(h.current(tenant, user), Some(version));
            assert!(!h.authorized(tenant, user));
            assert!(h.kinds(tenant).is_empty());
        },
    );
}

/// G-M20-3 (b): a SHOWN on version 1 authorizes; publishing version 2 withdraws that, and version 1 can no longer be shown.
#[test]
fn g_m20_3_b_notice_version_bump_revokes_authorization() {
    run_db_fixture::<NoticeFixture, _>(
        "g_m20_3_b_notice_version_bump_revokes_authorization",
        |mut h| {
            let (tenant, user, first) = h.auto_tenant_shown_on_first_notice();
            assert!(
                h.authorized(tenant, user),
                "SHOWN on the current version authorizes"
            );
            let second = h.publish_notice();
            assert_eq!(second, first + 1);
            assert!(
                !h.authorized(tenant, user),
                "a version bump re-gates the tenant"
            );
            assert_eq!(
                h.shown(tenant, user, first),
                Err(refused(
                    ErrorCode::Conflict,
                    ConflictReason::TARGET_NOT_CURRENT
                ))
            );
            assert_eq!(h.kinds(tenant), vec!["SHOWN".to_owned()]);
        },
    );
}

/// G-M20-3 (c): a SHOWN on version 2 authorizes again.
#[test]
fn g_m20_3_c_shown_on_new_version_authorizes_again() {
    run_db_fixture::<NoticeFixture, _>(
        "g_m20_3_c_shown_on_new_version_authorizes_again",
        |mut h| {
            let (tenant, user, first) = h.auto_tenant_shown_on_first_notice();
            let second = h.publish_notice();
            assert_eq!(second, first + 1);
            assert!(!h.authorized(tenant, user));
            h.shown(tenant, user, second).expect("SHOWN on version 2");
            assert!(h.authorized(tenant, user));
            assert_eq!(
                h.kinds(tenant),
                vec!["SHOWN".to_owned(), "SHOWN".to_owned()]
            );
        },
    );
}

/// G-M20-3 (d): toggle ON without a SHOWN on the current version is refused and writes nothing; with it, ON writes the AUTO
/// successor and OFF a DISABLED one, each beside its event.
#[test]
fn g_m20_3_d_toggle_on_without_shown_is_refused_and_writes_nothing() {
    run_db_fixture::<NoticeFixture, _>(
        "g_m20_3_d_toggle_on_without_shown_is_refused_and_writes_nothing",
        |mut h| {
            let (tenant, user) = h.new_tenant();
            let first = h.publish_notice();
            h.admin
                .execute(
                    "INSERT INTO control.contribution_policies \
                   (tenant_id, allow_public_contribution, policy_version, contribution_mode) \
                 VALUES ($1, true, 1, 'MANUAL')",
                    &[&tenant],
                )
                .expect("seed a MANUAL policy");
            let not_shown = Err(refused(
                ErrorCode::Conflict,
                ConflictReason::TRANSITION_NOT_ALLOWED,
            ));
            assert_eq!(h.toggle(tenant, user, true), not_shown);
            assert_eq!(h.head(tenant), Some((1, "MANUAL".to_owned())));
            assert!(h.kinds(tenant).is_empty());

            h.shown(tenant, user, first).expect("SHOWN on version 1");
            let version = h.publish_notice();
            assert_eq!(
                h.toggle(tenant, user, true),
                not_shown,
                "a SHOWN on the older version does not count"
            );
            assert_eq!(h.head(tenant), Some((1, "MANUAL".to_owned())));
            assert_eq!(h.kinds(tenant), vec!["SHOWN".to_owned()]);
            h.shown(tenant, user, version)
                .expect("SHOWN on the current version");
            assert_eq!(h.toggle(tenant, user, true), Ok(2));
            assert_eq!(
                h.head(tenant),
                Some((2, "AUTO_AFTER_USER_DISTILLATION".to_owned()))
            );
            assert!(h.authorized(tenant, user));
            assert_eq!(h.toggle(tenant, user, false), Ok(3));
            assert_eq!(h.head(tenant), Some((3, "DISABLED".to_owned())));
            assert!(!h.authorized(tenant, user));
            assert_eq!(
                h.kinds(tenant),
                vec![
                    "SHOWN".to_owned(),
                    "SHOWN".to_owned(),
                    "TOGGLED_ON".to_owned(),
                    "TOGGLED_OFF".to_owned()
                ]
            );
        },
    );
}

/// G-M20-3 (g): consent is per member: A's SHOWN authorizes A's memories and not B's; a version bump re-gates both until
/// each shows again.
#[test]
fn g_m20_3_g_authorization_is_per_member() {
    run_db_fixture::<NoticeFixture, _>("g_m20_3_g_authorization_is_per_member", |mut h| {
        let (tenant, user_a, first) = h.auto_tenant_shown_on_first_notice();
        let user_b = h.new_member(tenant, "MEMBER");
        assert!(h.authorized_for(tenant, user_a, user_a));
        assert!(
            !h.authorized_for(tenant, user_a, user_b),
            "A's SHOWN does not authorize B"
        );
        h.shown(tenant, user_b, first).expect("B SHOWN");
        assert!(h.authorized_for(tenant, user_a, user_b));
        let second = h.publish_notice();
        assert!(!h.authorized_for(tenant, user_a, user_a));
        assert!(!h.authorized_for(tenant, user_a, user_b));
        h.shown(tenant, user_a, second).expect("A SHOWN on v2");
        assert!(h.authorized_for(tenant, user_a, user_a));
        assert!(
            !h.authorized_for(tenant, user_a, user_b),
            "B has not shown v2"
        );
        h.shown(tenant, user_b, second).expect("B SHOWN on v2");
        assert!(h.authorized_for(tenant, user_a, user_b));
    });
}

/// G-M20-3 (h): only an ACTIVE OWNER toggles the tenant, in either direction; a refused member writes no event and no policy
/// row, and the refusal reason is exactly `toggle_owner_required`.
#[test]
fn g_m20_3_h_toggle_requires_an_owner() {
    run_db_fixture::<NoticeFixture, _>("g_m20_3_h_toggle_requires_an_owner", |mut h| {
        let (tenant, owner, version) = h.auto_tenant_shown_on_first_notice();
        let member = h.new_member(tenant, "MEMBER");
        h.shown(tenant, member, version).expect("member SHOWN");
        let forbidden = Err(Refusal {
            code: ErrorCode::Forbidden,
            reason: None,
        });
        for on in [false, true] {
            assert_eq!(
                h.toggle_error(tenant, member, on),
                (Some("42501".to_owned()), "toggle_owner_required".to_owned())
            );
        }
        assert_eq!(h.toggle(tenant, member, false), forbidden);
        assert_eq!(h.toggle(tenant, member, true), forbidden);
        assert_eq!(
            h.head(tenant),
            Some((1, "AUTO_AFTER_USER_DISTILLATION".to_owned()))
        );
        assert_eq!(
            h.kinds(tenant),
            vec!["SHOWN".to_owned(), "SHOWN".to_owned()]
        );
        assert_eq!(h.toggle(tenant, owner, false), Ok(2));
        assert_eq!(h.head(tenant), Some((2, "DISABLED".to_owned())));
    });
}

/// G-M20-3 (i): opting out needs no published notice: OFF writes a `TOGGLED_OFF` event without a version and the DISABLED
/// successor.
#[test]
fn g_m20_3_i_toggle_off_without_a_notice_succeeds() {
    run_db_fixture::<NoticeFixture, _>(
        "g_m20_3_i_toggle_off_without_a_notice_succeeds",
        |mut h| {
            let (tenant, owner) = h.new_tenant();
            assert!(h.apply_default(tenant, owner));
            assert_eq!(h.current(tenant, owner), None, "no notice is published");
            assert_eq!(h.toggle(tenant, owner, false), Ok(2));
            assert_eq!(h.head(tenant), Some((2, "DISABLED".to_owned())));
            assert_eq!(h.kinds(tenant), vec!["TOGGLED_OFF".to_owned()]);
        },
    );
}

/// G-M20-3 (k): a member's own OFF makes only that member's memories unselectable and leaves the policy head alone; their own
/// ON re-opts them in; a member's tenant-level ON is refused with `toggle_owner_required` and writes nothing.
#[test]
fn g_m20_3_k_member_opt_out_is_personal() {
    run_db_fixture::<NoticeFixture, _>("g_m20_3_k_member_opt_out_is_personal", |mut h| {
        let (tenant, owner, version) = h.auto_tenant_shown_on_first_notice();
        let member = h.new_member(tenant, "MEMBER");
        h.shown(tenant, member, version).expect("B SHOWN");
        let auto = Some((1, "AUTO_AFTER_USER_DISTILLATION".to_owned()));
        assert!(h.authorized_for(tenant, owner, owner));
        assert!(h.authorized_for(tenant, owner, member));

        h.toggle_member(tenant, member, false).expect("B OFF");
        assert!(!h.authorized_for(tenant, owner, member), "B opted out");
        assert!(h.authorized_for(tenant, owner, owner), "A is unchanged");
        assert_eq!(h.head(tenant), auto, "the tenant policy head is untouched");

        h.toggle_member(tenant, member, true).expect("B ON again");
        assert!(h.authorized_for(tenant, owner, member));
        assert!(h.authorized_for(tenant, owner, owner));
        assert_eq!(h.head(tenant), auto);

        let kinds_before = h.kinds(tenant);
        assert_eq!(
            kinds_before,
            vec![
                "SHOWN".to_owned(),
                "SHOWN".to_owned(),
                "TOGGLED_OFF".to_owned(),
                "TOGGLED_ON".to_owned()
            ]
        );
        assert_eq!(
            h.toggle_error(tenant, member, true),
            (Some("42501".to_owned()), "toggle_owner_required".to_owned())
        );
        assert_eq!(h.kinds(tenant), kinds_before, "nothing was written");
        assert_eq!(h.head(tenant), auto);
    });
}

/// G-M20-3 (l): a member's OFF needs no notice (NULL version), and ON needs a tenant policy that is already AUTO.
#[test]
fn g_m20_3_l_member_off_without_notice_and_on_needs_auto() {
    run_db_fixture::<NoticeFixture, _>(
        "g_m20_3_l_member_off_without_notice_and_on_needs_auto",
        |mut h| {
            let (tenant, owner) = h.new_tenant();
            let member = h.new_member(tenant, "MEMBER");
            assert!(h.apply_default(tenant, owner));
            assert_eq!(h.current(tenant, owner), None, "no notice is published");
            h.toggle_member(tenant, member, false)
                .expect("OFF before the first notice");
            assert_eq!(h.kinds(tenant), vec!["TOGGLED_OFF".to_owned()]);
            assert_eq!(
                h.head(tenant),
                Some((1, "AUTO_AFTER_USER_DISTILLATION".to_owned()))
            );
            assert_eq!(
                h.toggle_member(tenant, member, true),
                Err(refused(
                    ErrorCode::Conflict,
                    ConflictReason::TARGET_NOT_CURRENT
                )),
                "ON needs a published notice"
            );
            h.publish_notice();
            assert_eq!(h.toggle(tenant, owner, false), Ok(2));
            assert_eq!(
                h.toggle_member(tenant, member, true),
                Err(Refusal {
                    code: ErrorCode::Conflict,
                    reason: None
                }),
                "ON needs the tenant policy to be AUTO"
            );
            assert_eq!(
                h.kinds(tenant),
                vec!["TOGGLED_OFF".to_owned(), "TOGGLED_OFF".to_owned()]
            );
        },
    );
}

/// G-M20-3 (m): the version CHECK lets `TOGGLED_OFF` and `WITHDRAW_ALL` carry a NULL version and refuses every other kind;
/// `MEMBER` scope is refused for a kind that is not a toggle.
#[test]
fn g_m20_3_m_null_version_is_allowed_only_for_opt_out_kinds() {
    run_db_fixture::<NoticeFixture, _>(
        "g_m20_3_m_null_version_is_allowed_only_for_opt_out_kinds",
        |mut h| {
            let (tenant, user) = h.new_tenant();
            for kind in ["TOGGLED_OFF", "WITHDRAW_ALL"] {
                h.admin
                    .execute(
                        "INSERT INTO control.contribution_notice_events (tenant_id, user_id, notice_version, kind, channel) \
                         VALUES ($1, $2, NULL, $3, 'CONSOLE')",
                        &[&tenant, &user, &kind],
                    )
                    .unwrap_or_else(|e| panic!("{kind} with a NULL version: {e}"));
            }
            for kind in ["SHOWN", "ACKED", "TOGGLED_ON"] {
                let error = h
                    .admin
                    .execute(
                        "INSERT INTO control.contribution_notice_events (tenant_id, user_id, notice_version, kind, channel) \
                         VALUES ($1, $2, NULL, $3, 'CONSOLE')",
                        &[&tenant, &user, &kind],
                    )
                    .expect_err(kind);
                let db = error.as_db_error().expect("a database error");
                assert_eq!(db.code().code(), "23514", "{kind}: {error}");
                assert_eq!(
                    db.constraint(),
                    Some("contribution_notice_events_version_check")
                );
            }
            let version = h.publish_notice();
            let error = h
                .admin
                .execute(
                    "INSERT INTO control.contribution_notice_events (tenant_id, user_id, notice_version, kind, channel, scope) \
                     VALUES ($1, $2, $3, 'SHOWN', 'CONSOLE', 'MEMBER')",
                    &[&tenant, &user, &version],
                )
                .expect_err("MEMBER scope on SHOWN");
            assert_eq!(
                error.as_db_error().and_then(|db| db.constraint()),
                Some("contribution_notice_events_scope_kind_check")
            );
            assert_eq!(
                h.kinds(tenant),
                vec!["TOGGLED_OFF".to_owned(), "WITHDRAW_ALL".to_owned()]
            );
        },
    );
}

/// G-M20-3 (j): `ack_notice` records `ACKED` on the current version, never authorizes by itself, and refuses a version that
/// is no longer current.
#[test]
fn g_m20_3_j_ack_is_recorded_and_version_checked() {
    run_db_fixture::<NoticeFixture, _>("g_m20_3_j_ack_is_recorded_and_version_checked", |mut h| {
        let (tenant, user) = h.new_tenant();
        let first = h.publish_notice();
        assert!(h.apply_default(tenant, user));
        h.acked(tenant, user, first)
            .expect("ACKED on the current version");
        assert_eq!(h.kinds(tenant), vec!["ACKED".to_owned()]);
        assert!(!h.authorized(tenant, user), "ACKED is not SHOWN");
        let second = h.publish_notice();
        assert_eq!(
            h.acked(tenant, user, first),
            Err(refused(
                ErrorCode::Conflict,
                ConflictReason::TARGET_NOT_CURRENT
            ))
        );
        assert_eq!(h.kinds(tenant), vec!["ACKED".to_owned()]);
        h.acked(tenant, user, second).expect("ACKED on version 2");
        assert_eq!(
            h.kinds(tenant),
            vec!["ACKED".to_owned(), "ACKED".to_owned()]
        );
    });
}

fn sqlstate(error: &sqlx::Error) -> Option<String> {
    error
        .as_database_error()
        .and_then(|db| db.code())
        .map(|code| code.to_string())
}

/// G-M20-3 (e): `role_gateway` can neither update nor delete an event, and the trigger refuses the owner too.
#[test]
fn g_m20_3_e_events_are_append_only() {
    run_db_fixture::<NoticeFixture, _>("g_m20_3_e_events_are_append_only", |mut h| {
        let (tenant, user, _) = h.auto_tenant_shown_on_first_notice();
        for statement in [
            "UPDATE control.contribution_notice_events SET kind = 'ACKED' WHERE tenant_id = $1",
            "DELETE FROM control.contribution_notice_events WHERE tenant_id = $1",
        ] {
            let (state, error) = h.gateway_statement_error(tenant, user, statement);
            assert_eq!(state.as_deref(), Some("42501"), "{statement}: {error}");
        }
        for statement in [
            "UPDATE control.contribution_notice_events SET kind = 'ACKED' WHERE tenant_id = $1",
            "DELETE FROM control.contribution_notice_events WHERE tenant_id = $1",
        ] {
            let error = h.admin.execute(statement, &[&tenant]).expect_err(statement);
            assert_eq!(
                error
                    .as_db_error()
                    .map(|db| db.code().code().to_owned())
                    .as_deref(),
                Some("42501"),
                "{statement}: {error}"
            );
            let message = error.as_db_error().map(|db| db.message().to_owned());
            assert!(
                message
                    .as_deref()
                    .is_some_and(|m| m.contains("append-only")),
                "{statement}: {message:?}"
            );
        }
        assert_eq!(h.kinds(tenant), vec!["SHOWN".to_owned()]);
    });
}

/// G-M20-3 (f): a session of tenant B reads none of tenant A's events; tenant A's own session reads exactly its one.
#[test]
fn g_m20_3_f_events_are_tenant_isolated() {
    run_db_fixture::<NoticeFixture, _>("g_m20_3_f_events_are_tenant_isolated", |mut h| {
        let (tenant_a, user_a, _) = h.auto_tenant_shown_on_first_notice();
        let (tenant_b, user_b) = h.new_tenant();
        assert_eq!(h.visible_events(tenant_a, user_a, Some(tenant_a)), 1);
        assert_eq!(h.visible_events(tenant_b, user_b, Some(tenant_a)), 0);
        assert_eq!(h.visible_events(tenant_b, user_b, None), 0);
    });
}

/// §78.2: the Rust kind and channel sets equal the 0274 CHECK literals, both ways.
#[test]
fn kind_and_channel_checks_equal_the_rust_sets() {
    run_db_fixture::<NoticeFixture, _>("kind_and_channel_checks_equal_the_rust_sets", |mut h| {
        let kinds: BTreeSet<String> = NoticeEventKind::ALL
            .iter()
            .map(|k| k.as_str().to_owned())
            .collect();
        let channels: BTreeSet<String> = NoticeChannel::ALL
            .iter()
            .map(|c| c.as_str().to_owned())
            .collect();
        let scopes: BTreeSet<String> = NoticeEventScope::ALL
            .iter()
            .map(|s| s.as_str().to_owned())
            .collect();
        assert_eq!(kinds.len(), 5);
        assert_eq!(channels.len(), 3);
        assert_eq!(scopes.len(), 2);
        for (check, expected) in [
            ("contribution_notice_events_kind_check", &kinds),
            ("contribution_notice_events_channel_check", &channels),
            ("contribution_notice_events_scope_check", &scopes),
        ] {
            let def: String = h
                .admin
                .query_one(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
                      WHERE conname = $1 AND conrelid = 'control.contribution_notice_events'::regclass",
                    &[&check],
                )
                .expect(check)
                .get(0);
            let db: BTreeSet<String> = def
                .split('\'')
                .skip(1)
                .step_by(2)
                .map(str::to_owned)
                .collect();
            assert_eq!(&db, expected, "{check}: {def}");
        }
    });
}

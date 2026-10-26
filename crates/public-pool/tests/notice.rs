//! `public-pool::tests::notice` — G-M20-3 (ADR-0088 D-A..D-C, migration 0274): the AUTO policy selects nothing without a SHOWN
//!   on the current notice version; choice events are append-only and tenant-scoped; the Rust kind and channel sets equal the
//!   DB CHECK literals.
//! Depends-on: crates=[humaux-domain, humaux-testkit, postgres, sqlx, tokio, uuid];
//!   services=[PostgreSQL(any) r=[control.contribution_notice_events, control.contribution_policies]
//!   w=[control.contribution_notice_events, control.contribution_notices, control.contribution_policies, control.tenants,
//!   control.users] x=[control.toggle_contribution], PostgreSQL(role_gateway), PostgreSQL(role_maintenance)];
//!   env=[HUMAUX_TEST_PG_DSN];
//!   modules=[domain::error, domain::ids, humaux-testkit, public-pool::notice, public-pool::policy]
//! Called-by: [cargo-test]
//! Invariants: [every test owns one throwaway tenant, user and the notice versions it publishes, removed on drop; the notice
//!   table is global, so the binary runs in nextest's global-db group; a missing database is a visible §79.2 skip, a FAIL
//!   under HUMAUX_REQUIRE_DB]
//! Spec: Baseline §12.1.1; §78.2; §79.2; ADR-0088 D-A; D-B; D-C

use std::collections::BTreeSet;

use humaux_domain::{
    error::{ConflictReason, ErrorCode},
    ids::{TenantId, UserId},
};
use humaux_public_pool::{
    notice::{self, NoticeChannel, NoticeEventKind, Refusal},
    policy,
};
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

fn dsn_as_role(admin_dsn: &str, role: &str) -> String {
    let sep = if admin_dsn.contains('?') { '&' } else { '?' };
    format!("{admin_dsn}{sep}options=-c%20role%3D{role}")
}

struct Handle {
    rt: tokio::runtime::Runtime,
    gateway: PgPool,
    maintenance: PgPool,
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
        let gateway = rt
            .block_on(PgPool::connect(&dsn_as_role(&dsn, "role_gateway")))
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        // dep: PostgreSQL(role_maintenance) — the only role that may apply the cloud onboarding default
        let maintenance = rt
            .block_on(PgPool::connect(&dsn_as_role(&dsn, "role_maintenance")))
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        Ok(Handle {
            rt,
            gateway,
            maintenance,
            admin,
            tenants: Vec::new(),
            users: Vec::new(),
            notices: Vec::new(),
        })
    }
}

impl Handle {
    /// A throwaway tenant and user; both are removed on drop.
    fn new_tenant(&mut self) -> (Uuid, Uuid) {
        let tenant: Uuid = self
            .admin
            .query_one(
                "INSERT INTO control.tenants (name) VALUES ('m20-4a-notice') RETURNING tenant_id",
                &[],
            )
            .expect("insert tenant")
            .get(0);
        let user = Uuid::new_v4();
        self.admin
            .execute("INSERT INTO control.users (user_id) VALUES ($1)", &[&user])
            .expect("insert user");
        self.tenants.push(tenant);
        self.users.push(user);
        (tenant, user)
    }

    /// Publishes the next notice version, effective immediately: the greatest `published_at` so far.
    fn publish_notice(&mut self) -> i32 {
        let version: i32 = self
            .admin
            .query_one(
                "INSERT INTO control.contribution_notices \
                   (notice_version, text_sha256, scope_categories, licence_text, licence_code, published_at) \
                 SELECT coalesce(max(notice_version), 0) + 1, sha256(convert_to(gen_random_uuid()::text, 'UTF8')), \
                        ARRAY['PRIVATE_MEMORY'], 'CC-BY-4.0', 'MIT', clock_timestamp() \
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

    fn session(&self, pool: &PgPool, tenant: Uuid, user: Uuid) -> Transaction<'static, Postgres> {
        self.rt.block_on(async {
            // dep: PostgreSQL(any) — one transaction per door call, on the pool of the role under test
            let mut tx = pool.begin().await.expect("begin");
            notice::install_session(&mut tx, TenantId(tenant), UserId(user))
                .await
                .expect("install session");
            tx
        })
    }

    fn apply_default(&self, tenant: Uuid, user: Uuid) -> bool {
        let mut tx = self.session(&self.maintenance, tenant, user);
        let written = self
            .rt
            .block_on(policy::apply_cloud_default(&mut tx))
            .expect("apply the cloud default");
        self.rt.block_on(tx.commit()).expect("commit");
        written
    }

    fn shown(&self, tenant: Uuid, user: Uuid, version: i32) -> Result<Uuid, Refusal> {
        let mut tx = self.session(&self.gateway, tenant, user);
        let result = self
            .rt
            .block_on(notice::record_shown(&mut tx, version, NoticeChannel::Popup));
        if result.is_ok() {
            self.rt.block_on(tx.commit()).expect("commit");
        }
        result
    }

    fn toggle(&self, tenant: Uuid, user: Uuid, on: bool) -> Result<i64, Refusal> {
        let mut tx = self.session(&self.gateway, tenant, user);
        let result = self
            .rt
            .block_on(policy::toggle(&mut tx, on, NoticeChannel::Console));
        if result.is_ok() {
            self.rt.block_on(tx.commit()).expect("commit");
        }
        result
    }

    fn current(&self, tenant: Uuid, user: Uuid) -> Option<i32> {
        let mut tx = self.session(&self.gateway, tenant, user);
        self.rt
            .block_on(notice::current_notice(&mut tx))
            .expect("the current notice")
    }

    fn authorized(&self, tenant: Uuid, user: Uuid) -> bool {
        let mut tx = self.session(&self.gateway, tenant, user);
        self.rt
            .block_on(notice::contribution_authorized(&mut tx, TenantId(tenant)))
            .expect("the predicate")
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
            let mut tx = h.session(&h.gateway, tenant, user);
            let error =
                h.rt.block_on(sqlx::query(statement).bind(tenant).execute(&mut *tx))
                    .expect_err(statement);
            assert_eq!(
                sqlstate(&error).as_deref(),
                Some("42501"),
                "{statement}: {error}"
            );
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
            assert!(
                error.to_string().contains("append-only"),
                "{statement}: {error}"
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
        let count = |h: &Handle, tenant: Uuid, user: Uuid, of: Uuid| -> i64 {
            let mut tx = h.session(&h.gateway, tenant, user);
            h.rt.block_on(
                sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) FROM control.contribution_notice_events WHERE tenant_id = $1",
                )
                .bind(of)
                .fetch_one(&mut *tx),
            )
            .expect("count events")
        };
        assert_eq!(count(&h, tenant_a, user_a, tenant_a), 1);
        assert_eq!(count(&h, tenant_b, user_b, tenant_a), 0);
        let mut tx = h.session(&h.gateway, tenant_b, user_b);
        let visible: i64 =
            h.rt.block_on(
                sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) FROM control.contribution_notice_events",
                )
                .fetch_one(&mut *tx),
            )
            .expect("count visible events");
        assert_eq!(visible, 0);
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
        assert_eq!(kinds.len(), 5);
        assert_eq!(channels.len(), 3);
        for (check, expected) in [
            ("contribution_notice_events_kind_check", &kinds),
            ("contribution_notice_events_channel_check", &channels),
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

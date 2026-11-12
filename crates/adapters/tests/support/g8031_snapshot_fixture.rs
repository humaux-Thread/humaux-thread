//! Shared G80 test fixture: seeds and cleans one tenant; no production entry point.
//! Depends-on: crates=[humaux-domain, humaux-testkit, postgres, serde_json, sqlx, uuid]; services=[PostgreSQL(owner), PostgreSQL(role_gateway)]; env=[HUMAUX_TEST_PG_DSN, HUMAUX_GATEWAY_PG_DSN]; modules=[domain::context, domain::identity, domain::ids, humaux-testkit]
//! Called-by: [adapters::context_repo::g8031_snapshot_tests, adapters::tests::g80_31_handoff]
//! Invariants: [one fixture per process; full snapshot identity requires explicit import]
use humaux_domain::context::ContextBudget;
use humaux_domain::identity::{AuthorizationScope, BoundedSet, PrincipalId};
use humaux_domain::ids::{Scope, TenantId};
use humaux_testkit::{ExternalDep, skip_or_fail};
use postgres::{Client, NoTls};
use sqlx::postgres::PgConnectOptions;
use std::str::FromStr;
use uuid::Uuid;

pub(crate) const NAME: &str = "g80_31_handoff";
const REQUEST_GUARD_DB: &str = "humaux_thread_request_guard_20260828";

/// Uses the isolated fixture's real gateway LOGIN, never a privileged owner connection that
/// changes role after connecting. Invalid/missing configuration is a testkit skip-or-fail.
fn gateway_dsn() -> Option<String> {
    let Ok(dsn) = std::env::var("HUMAUX_GATEWAY_PG_DSN") else {
        skip_or_fail(
            NAME,
            "missing object: role_gateway PostgreSQL DSN",
            ExternalDep::Postgres,
        );
        return None;
    };
    let Ok(options) = PgConnectOptions::from_str(&dsn) else {
        skip_or_fail(
            NAME,
            "invalid object: role_gateway PostgreSQL DSN",
            ExternalDep::Postgres,
        );
        return None;
    };
    // card 23 (serial lane, class (a)): the target is whatever `HUMAUX_TEST_PG_DSN` names —
    // the repo-wide isolated test database (§79.2) — with the machine-local `61719 /
    // humaux_thread_request_guard_20260828` pair kept as an accepted legacy target. Pinning
    // only that pair made all 11 tests in this file skip on every standard environment while
    // `skip_or_fail` printed SKIP, i.e. a whole file of false green; the identical fix already
    // landed in `support/operation_receipt_fixture.rs` on 2026-09-03 and this is a read of the
    // same rule, not a second one.
    let legacy_target =
        options.get_port() == 61719 && options.get_database() == Some(REQUEST_GUARD_DB);
    let shared_target = std::env::var("HUMAUX_TEST_PG_DSN")
        .ok()
        .and_then(|admin| PgConnectOptions::from_str(&admin).ok())
        .is_some_and(|admin| {
            options.get_port() == admin.get_port() && options.get_database() == admin.get_database()
        });
    if options.get_username() != "role_gateway"
        || options.get_host() != "127.0.0.1"
        || !(legacy_target || shared_target)
        || dsn.contains(['?', '#'])
    {
        skip_or_fail(
            NAME,
            "invalid object: isolated role_gateway fixture DSN",
            ExternalDep::Postgres,
        );
        return None;
    }
    // dep: PostgreSQL(role_gateway) — HUMAUX_GATEWAY_PG_DSN: identity probe: LOGIN, non-superuser, non-bypassrls.
    // dep: PostgreSQL(any) — opens the role-scoped connection for `gateway_dsn`
    let Ok(mut gateway) = Client::connect(&dsn, NoTls) else {
        skip_or_fail(
            NAME,
            "missing object: role_gateway PostgreSQL login",
            ExternalDep::Postgres,
        );
        return None;
    };
    let Ok(role_ok) = gateway.query_one(
        "SELECT current_user='role_gateway' AND session_user='role_gateway' \
         AND NOT (SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user)",
        &[],
    ) else {
        skip_or_fail(
            NAME,
            "missing object: role_gateway session identity probe",
            ExternalDep::Postgres,
        );
        return None;
    };
    if !role_ok.get::<_, bool>(0) {
        skip_or_fail(
            NAME,
            "invalid object: role_gateway must be LOGIN, non-superuser, non-bypassrls",
            ExternalDep::Postgres,
        );
        return None;
    }
    Some(dsn)
}

pub(crate) struct Fixture {
    pub(crate) admin: Client,
    pub(crate) tenant_id: Uuid,
    pub(crate) evidence_id: Uuid,
    pub(crate) dsn: String,
    pub(crate) direct_get_barrier: Option<String>,
    /// Serializes fixture mutations within a process. Snapshot identity is established
    /// separately by the importing transaction harness, not by this mutex.
    _quiet: std::sync::MutexGuard<'static, ()>,
}

/// One fixture at a time inside this binary — see [`Fixture::_quiet`].
static QUIET: std::sync::Mutex<()> = std::sync::Mutex::new(());

impl Drop for Fixture {
    fn drop(&mut self) {
        // Card-31 pattern (card 33 leak fix): each seeded PRIMARY memory_evidence link enqueued a
        // DERIVED_CONSOLIDATE job (0164 trigger). They are deleted in their own autocommit
        // statement first, so a failure in the transaction below (which ends in the tenant delete)
        // cannot roll the job delete back.
        if let Err(error) = self.admin.execute(
            "DELETE FROM ops.jobs WHERE tenant_id = $1",
            &[&self.tenant_id],
        ) {
            eprintln!(
                "g80 handoff fixture job cleanup failed for tenant {}: {error}",
                self.tenant_id
            );
        }
        let cleanup = (|| -> Result<(), postgres::Error> {
            let mut txn = self.admin.transaction()?;
            if let Some(name) = self.direct_get_barrier.take() {
                txn.batch_execute(&format!(
                    "DROP POLICY IF EXISTS {name} ON private.memory_records; \
                     DROP FUNCTION IF EXISTS private.{name}()"
                ))?;
            }
            txn.batch_execute(&format!(
                "DELETE FROM private.context_bindings WHERE tenant_id = '{0}'; \
             DELETE FROM ops.selection_snapshot_items WHERE tenant_id = '{0}'; \
             DELETE FROM ops.selection_snapshots WHERE tenant_id = '{0}'; \
             DELETE FROM projection.stream_log WHERE tenant_id = '{0}'; \
             DELETE FROM projection.stream_checkpoints WHERE tenant_id = '{0}'; \
             DELETE FROM private.memory_evidence WHERE memory_id IN \
               (SELECT memory_id FROM private.memory_records WHERE tenant_id = '{0}'); \
             DELETE FROM private.memory_records WHERE tenant_id = '{0}'; \
             DELETE FROM private.events WHERE event_id IN \
               (SELECT evidence_id FROM private.evidence_objects WHERE tenant_id = '{0}'); \
             DELETE FROM private.evidence_objects WHERE tenant_id = '{0}'; \
             DELETE FROM control.private_reasoning_domains WHERE tenant_id = '{0}'; \
             DELETE FROM control.tenants WHERE tenant_id = '{0}';",
                self.tenant_id
            ))?;
            txn.commit()
        })();
        if let Err(error) = cleanup {
            if std::thread::panicking() {
                eprintln!("g80 handoff fixture cleanup failed: {error}");
            } else {
                panic!("g80 handoff fixture cleanup failed: {error}");
            }
        }
    }
}

pub(crate) fn setup() -> Option<Fixture> {
    // A test that panicked while holding the lock poisons it; the next fixture is still valid.
    let quiet = QUIET
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Ok(dsn) = std::env::var("HUMAUX_TEST_PG_DSN") else {
        skip_or_fail(NAME, "missing object: Postgres DSN", ExternalDep::Postgres);
        return None;
    };
    let Ok(options) = PgConnectOptions::from_str(&dsn) else {
        skip_or_fail(
            NAME,
            "invalid object: owner PostgreSQL DSN",
            ExternalDep::Postgres,
        );
        return None;
    };
    // ADR-0047 D-D / ADR-0050 D-B: the owner DSN *defines* the fixture target (any loopback
    // port/database); only loopback and a query-free DSN are enforced here, because this
    // fixture installs a RESTRICTIVE policy as the owner. Role DSNs must then name the same
    // target (`gateway_dsn`).
    if options.get_host() != "127.0.0.1" || dsn.contains(['?', '#']) {
        skip_or_fail(
            NAME,
            "invalid object: loopback owner fixture DSN",
            ExternalDep::Postgres,
        );
        return None;
    }
    // dep: PostgreSQL(owner) — HUMAUX_TEST_PG_DSN: seeds/cleans the fixture tenant and installs the barrier policy.
    // dep: PostgreSQL(any) — opens the role-scoped connection for `setup`
    let Ok(mut admin) = Client::connect(&dsn, NoTls) else {
        skip_or_fail(NAME, "missing object: live Postgres", ExternalDep::Postgres);
        return None;
    };
    let gateway_dsn = gateway_dsn()?;
    let tenant_id: Uuid = admin
        .query_one(
            "INSERT INTO control.tenants (name) VALUES ($1) RETURNING tenant_id",
            &[&"g80_31_handoff throwaway tenant"],
        )
        .expect("seed tenant")
        .get(0);
    let reasoning_domain_id: Uuid = admin
        .query_one(
            "INSERT INTO control.private_reasoning_domains (tenant_id, name) \
             VALUES ($1, 'g80_31 domain') RETURNING reasoning_domain_id",
            &[&tenant_id],
        )
        .expect("seed reasoning domain")
        .get(0);
    let evidence_id: Uuid = admin
        .query_one(
            "INSERT INTO private.evidence_objects \
               (tenant_id, evidence_kind, payload_sha256, data_class, origin_class, \
                visibility_class, reasoning_domain_id) \
             VALUES ($1, 'EVENT', $2, 'INTERNAL', 'DirectUserInput', 'TENANT_SHARED', $3) \
             RETURNING evidence_id",
            &[&tenant_id, &vec![0u8; 32], &reasoning_domain_id],
        )
        .expect("seed evidence")
        .get(0);
    admin
        .execute(
            "INSERT INTO private.events (event_id, event_kind, payload) \
             VALUES ($1, 'USER_MESSAGE', '{}'::jsonb)",
            &[&evidence_id],
        )
        .expect("seed event");
    Some(Fixture {
        admin,
        tenant_id,
        evidence_id,
        dsn: gateway_dsn,
        direct_get_barrier: None,
        _quiet: quiet,
    })
}

/// 批量播 memory（SNAPSHOT 档 evidence，进得了 lane）。返回 id。
pub(crate) fn seed_many(f: &mut Fixture, authority: &str, n: usize) -> Vec<Uuid> {
    let confidence: f32 = 0.9;
    let mut out = Vec::with_capacity(n);
    let mut txn = f.admin.transaction().expect("begin");
    for _ in 0..n {
        let id: Uuid = txn
            .query_one(
                "INSERT INTO private.memory_records \
                   (tenant_id, memory_type, content, visibility_class, \
                    authority_class, confidence, status, asserted_at) \
                 VALUES ($1, 'NOTE', $2, 'TENANT_SHARED', $3, $4, 'active', now()) \
                 RETURNING memory_id",
                &[
                    &f.tenant_id,
                    &serde_json::json!({"fixture": NAME}),
                    &authority,
                    &confidence,
                ],
            )
            .expect("insert memory")
            .get(0);
        // dep: PostgreSQL(any) — pool/txn query execution
        txn.execute(
            "INSERT INTO private.memory_evidence (memory_id, evidence_id, role, grounding_mode) \
             VALUES ($1, $2, 'PRIMARY', 'SNAPSHOT')",
            &[&id, &f.evidence_id],
        )
        .expect("link evidence");
        out.push(id);
    }
    txn.commit().expect("commit");
    out
}

pub(crate) fn scope_for(tenant_id: Uuid) -> Scope {
    Scope {
        tenant_id: TenantId(tenant_id),
        user_id: None,
        workspace_id: None,
        repository_id: None,
        task_id: None,
        run_id: None,
        agent_id: None,
    }
}

pub(crate) fn authorization_for(tenant_id: Uuid) -> AuthorizationScope {
    AuthorizationScope::new(
        TenantId(tenant_id),
        PrincipalId::new(),
        None,
        BoundedSet::new([]).expect("empty workspace grant set"),
    )
}

pub(crate) fn budget() -> ContextBudget {
    // 200 条噪声不进 mandatory（authority 不够），预算给足 constraint。
    ContextBudget::new(1_000_000, 500_000).expect("budget")
}

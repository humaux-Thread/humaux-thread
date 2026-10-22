//! `adapters::tests::ledger_frontier` — M09-2 / G-M09-3: `stream_repo::ledger_frontier` is one `stream_checkpoints`
//!   primary-key read and reports no count its row cannot supply.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-projection, humaux-testkit, postgres, sqlx, tokio];
//!   services=[PostgreSQL(owner) w=[control.tenants, projection.stream_checkpoints, projection.stream_log],
//!   PostgreSQL(role_gateway), PostgreSQL(role_retrieval_worker)]; env=[HUMAUX_TEST_PG_DSN];
//!   modules=[adapters::postgres, adapters::stream_repo, adapters::tests::support::throwaway_db, domain::egress,
//!   domain::identity, domain::ids, humaux-testkit, projection::stream]
//! Called-by: [cargo-test]
//! Invariants: [runs in its own throwaway database because it REVOKEs role_retrieval_worker's `stream_log` SELECT,
//!   which proves the O(1) claim by construction: a frontier that touched `stream_log` (or the closure) would fail
//!   with permission denied; no DSN or unreachable DB is a visible SKIP]
//! Spec: Baseline §15.3; §23.3; §79.2; M09 D3
//!
//! The red record for G-M09-3 is the same file with `ledger_frontier` implemented through
//! `close_ledger_in_txn` (see the PR body for the run id).

use std::time::SystemTime;

use humaux_adapters::postgres::RetrievalWorkerDbPool;
use humaux_adapters::stream_repo::{self, Frontier};
use humaux_domain::egress::ProcessorId;
use humaux_domain::identity::{AuthorizationScope, BoundedSet, PrincipalId};
use humaux_domain::ids::{TenantId, WorkspaceId};
use humaux_projection::stream::StreamKey;
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use sqlx::types::Uuid;

#[path = "support/throwaway_db.rs"]
#[allow(dead_code)]
mod throwaway_db;
use throwaway_db::ThrowawayDb;

struct Handle {
    rt: tokio::runtime::Runtime,
    retrieval: RetrievalWorkerDbPool,
    admin: Client,
    /// Owner-database DSN; the gateway-role test opens its own pool from it.
    dsn: String,
    tenant_id: Uuid,
    /// Dropped last: it drops the whole database.
    _db: ThrowawayDb,
}

struct FrontierFixture;

impl DbIntegrationFixture for FrontierFixture {
    type Handle = Handle;

    fn isolate() -> Result<Handle, DbFixtureSkipReason> {
        let db = throwaway_db::create("m09_frontier")?;
        let dsn = db.dsn();
        // dep: PostgreSQL(owner) — test opens a direct PG connection for setup/verification
        let mut admin = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        let tenant_id: Uuid = admin
            .query_one(
                "INSERT INTO control.tenants (name) VALUES ('ledger_frontier.rs throwaway tenant') \
                 RETURNING tenant_id",
                &[],
            )
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?
            .get(0);
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        let sep = if dsn.contains('?') { '&' } else { '?' };
        let retrieval = rt
            // dep: PostgreSQL(role_retrieval_worker) — the role the production frontier read runs as
            .block_on(RetrievalWorkerDbPool::connect(&format!(
                "{dsn}{sep}options=-c%20role%3Drole_retrieval_worker"
            )))
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        Ok(Handle {
            rt,
            retrieval,
            admin,
            dsn,
            tenant_id,
            _db: db,
        })
    }
}

fn key(h: &Handle) -> StreamKey {
    StreamKey::new(
        TenantId(h.tenant_id),
        "workspace",
        Uuid::new_v4(),
        "code",
        "retrieval_card",
        "v1",
    )
}

/// Three `DONE` tickets plus one `ISSUED` under a checkpoint that issued four, `projection_highwater` seeded to 2 and
/// `serving` true, so `issued_hw` (4), `projection_hw` (3 once advanced) and `serving` are all distinguishable and a
/// column swap in the SELECT goes red.
fn seed_settled_stream(admin: &mut Client, k: &StreamKey) {
    admin
        .execute(
            "INSERT INTO projection.stream_checkpoints \
               (tenant_id, scope_kind, scope_id, domain, projection_kind, projection_version, \
                issued_highwater, projection_highwater, serving) VALUES ($1,$2,$3,$4,$5,$6,4,2,true)",
            &[
                &k.tenant_id.0,
                &k.scope_kind,
                &k.scope_id,
                &k.domain,
                &k.projection_kind,
                &k.projection_version,
            ],
        )
        .expect("seed stream_checkpoints row");
    let now = SystemTime::now();
    for seq in 1..=3i64 {
        admin
            .execute(
                "INSERT INTO projection.stream_log \
                   (tenant_id, scope_kind, scope_id, domain, projection_kind, projection_version, \
                    stream_seq, commit_seq, state, settled_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$7,'DONE',$8)",
                &[
                    &k.tenant_id.0,
                    &k.scope_kind,
                    &k.scope_id,
                    &k.domain,
                    &k.projection_kind,
                    &k.projection_version,
                    &seq,
                    &now,
                ],
            )
            .expect("seed stream_log row");
    }
    admin
        .execute(
            "INSERT INTO projection.stream_log \
               (tenant_id, scope_kind, scope_id, domain, projection_kind, projection_version, \
                stream_seq, commit_seq, state) VALUES ($1,$2,$3,$4,$5,$6,4,4,'ISSUED')",
            &[
                &k.tenant_id.0,
                &k.scope_kind,
                &k.scope_id,
                &k.domain,
                &k.projection_kind,
                &k.projection_version,
            ],
        )
        .expect("seed pending stream_log row");
}

fn reader(h: &Handle) -> AuthorizationScope {
    AuthorizationScope::new(
        TenantId(h.tenant_id),
        PrincipalId::new(),
        None,
        BoundedSet::new(Vec::<WorkspaceId>::new()).expect("empty workspace set is valid"),
    )
}

/// G-M09-3: on a settled stream the frontier equals the closure's `expected` and the advanced prefix, and it is
/// still readable after the worker role loses every right on `stream_log` — the closure is not.
#[test]
fn frontier_matches_the_closure_and_reads_only_the_checkpoint_row() {
    run_db_fixture::<FrontierFixture, _>(
        "frontier_matches_the_closure_and_reads_only_the_checkpoint_row",
        |mut h| {
            let k = key(&h);
            seed_settled_stream(&mut h.admin, &k);
            let prefix =
                h.rt.block_on(stream_repo::advance_prefix(
                    &h.retrieval,
                    &k,
                    ProcessorId(Uuid::from_u128(0x0902)),
                ))
                .expect("a settled stream advances");
            let closure =
                h.rt.block_on(stream_repo::fetch_ledger_closure(
                    &h.retrieval,
                    &k,
                    &reader(&h),
                ))
                .expect("closure before the revoke");

            let before =
                h.rt.block_on(stream_repo::ledger_frontier(&h.retrieval, &k))
                    .expect("frontier")
                    .expect("the checkpoint row exists");
            // Compile-time: every field is named, so a `visible` (or any count) added to `Frontier` breaks this.
            let Frontier {
                issued_hw,
                projection_hw,
                serving,
                updated_at: _,
            } = before;
            assert_eq!(issued_hw, closure.counts().expected());
            assert_eq!((projection_hw, issued_hw), (prefix, 4));
            assert_eq!(prefix, 3, "the pending ticket 4 stops the prefix at 3");
            assert!(serving, "seeded serving = true");

            h.admin
                .batch_execute("REVOKE ALL ON projection.stream_log FROM role_retrieval_worker")
                .expect("revoke");
            let still_readable: bool = h
                .admin
                .query_one(
                    "SELECT NOT has_any_column_privilege('role_retrieval_worker', 'projection.stream_log', 'SELECT')",
                    &[],
                )
                .expect("privilege probe")
                .get(0);
            assert!(
                still_readable,
                "precondition: the worker role cannot read stream_log any more"
            );
            let denied = h.rt.block_on(stream_repo::fetch_ledger_closure(
                &h.retrieval,
                &k,
                &reader(&h),
            ));
            assert!(
                matches!(&denied, Err(stream_repo::StreamRepoError::Db(sqlx::Error::Database(e)))
                    if e.code().as_deref() == Some("42501")),
                "the O(stream) closure needs stream_log, so the revoke has teeth (SQLSTATE 42501): {denied:?}"
            );
            let after =
                h.rt.block_on(stream_repo::ledger_frontier(&h.retrieval, &k))
                    .expect("frontier without any stream_log right")
                    .expect("row");
            assert_eq!(after, before);
        },
    );
}

/// §23.3④: a key that never issued a ticket has no checkpoint row, and the frontier says so instead of a zero row.
#[test]
fn frontier_of_a_never_issued_stream_is_none() {
    run_db_fixture::<FrontierFixture, _>("frontier_of_a_never_issued_stream_is_none", |h| {
        let k = key(&h);
        let frontier =
            h.rt.block_on(stream_repo::ledger_frontier(&h.retrieval, &k))
                .expect("frontier");
        assert_eq!(frontier, None);
    });
}

/// C6: `memory.get` (M13) reads the frontier on the gateway pool inside its REPEATABLE READ READ ONLY snapshot, so the
/// `_in_txn` form must work as `role_gateway` there and return the same row the worker-pool form does.
#[test]
fn frontier_in_txn_reads_as_role_gateway_in_a_read_only_snapshot() {
    run_db_fixture::<FrontierFixture, _>(
        "frontier_in_txn_reads_as_role_gateway_in_a_read_only_snapshot",
        |mut h| {
            let k = key(&h);
            seed_settled_stream(&mut h.admin, &k);
            h.rt.block_on(stream_repo::advance_prefix(
                &h.retrieval,
                &k,
                ProcessorId(Uuid::from_u128(0x0902)),
            ))
            .expect("advance");
            let via_worker =
                h.rt.block_on(stream_repo::ledger_frontier(&h.retrieval, &k))
                    .expect("worker-pool frontier");

            let sep = if h.dsn.contains('?') { '&' } else { '?' };
            let gateway_dsn = format!("{}{sep}options=-c%20role%3Drole_gateway", h.dsn);
            // dep: PostgreSQL(role_gateway) — the role `memory.get` runs as; a bare pool because `RuntimeDbPool::pool()` is crate-private
            let gateway =
                h.rt.block_on(sqlx::Pool::<sqlx::Postgres>::connect(&gateway_dsn))
                    .expect("connect role_gateway");
            let via_gateway = h.rt.block_on(async {
                // dep: PostgreSQL(role_gateway) — transaction entry for the `memory.get`-shaped snapshot
                let mut txn = gateway.begin().await?;
                sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                    .execute(&mut *txn)
                    .await?;
                let frontier = stream_repo::ledger_frontier_in_txn(&mut txn, &k).await?;
                txn.commit().await?;
                Ok::<_, sqlx::Error>(frontier)
            });
            let via_gateway = via_gateway.expect("frontier as role_gateway");
            assert_eq!(via_gateway, via_worker);
            let frontier = via_gateway.expect("row");
            assert_eq!(
                (frontier.issued_hw, frontier.projection_hw, frontier.serving),
                (4, 3, true)
            );
        },
    );
}

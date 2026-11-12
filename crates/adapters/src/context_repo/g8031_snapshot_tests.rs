//! G80-31 real double-read harness in the owning module; no public production hooks.
//! Depends-on: crates=[humaux-domain, humaux-retrieval, postgres, sqlx, tokio, uuid]; services=[PostgreSQL(owner), PostgreSQL(role_gateway)]; env=[HUMAUX_TEST_PG_DSN, HUMAUX_GATEWAY_PG_DSN]; modules=[adapters::context_repo, adapters::postgres, domain::context, domain::identity, domain::ids, retrieval::handoff]
//! Called-by: [cargo-test]
//! Invariants: [exporter stays alive; import precedes every read; complete token and bytes are checked]
use super::g8031_snapshot_fixture::{authorization_for, budget, scope_for, seed_many, setup};
use crate::postgres::RuntimeDbPool;
use humaux_retrieval::handoff::{Handoff, assemble};
use postgres::{Client, NoTls};
use uuid::Uuid;

/// Each call opens and commits an independent real runtime transaction. The production
/// helper installs authorization GUCs and applies the usual tenant/RLS selectors.
async fn imported_read(dsn: &str, tenant: Uuid, snapshot: &str, import: bool) -> Handoff {
    let pool = RuntimeDbPool::connect(dsn).await.expect("runtime pool");
    let mut tx = pool.pool().begin().await.expect("independent reader begin");
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await
        .expect("reader RR before queries");
    // Server-produced snapshot ID, still validate before using SQL literal syntax.
    assert!(!snapshot.is_empty() && snapshot.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'));
    if import {
        sqlx::query(&format!("SET TRANSACTION SNAPSHOT '{snapshot}'"))
            .execute(&mut *tx)
            .await
            .expect("snapshot import before first SELECT");
    }
    eprintln!("G8031 reader import={import} snapshot={snapshot} acknowledged before helper");
    let frozen =
        super::fetch_frozen_in_txn(&mut tx, &authorization_for(tenant), &scope_for(tenant))
            .await
            .expect("real production frozen read");
    let row: (String, i32, String, Option<String>) = sqlx::query_as(
        "SELECT pg_current_snapshot()::text, pg_backend_pid(), current_setting('server_version'), pg_current_xact_id_if_assigned()::text",
    ).fetch_one(&mut *tx).await.expect("reader identity receipt");
    eprintln!(
        "G8031 reader raw={} pid={} version={} xid={:?} hash={}",
        row.0, row.1, row.2, row.3, frozen.snapshot_token_sha256
    );
    tx.commit().await.expect("reader commit acknowledgement");
    let handoff = assemble(frozen, budget());
    pool.pool().close().await;
    handoff
}

/// Migrated from the g80_31_handoff integration binary: two real independent reads,
/// now explicitly sharing the exporter snapshot even across a completed XID.
#[test]
fn same_snapshot_assembles_byte_identical_handoffs_with_the_constraint_present() {
    let Some(mut f) = setup() else { return };
    let constraint = seed_many(&mut f, "ProjectConstraint", 1)[0];
    let noise = seed_many(&mut f, "PrivateKnowledge", 200);
    let mut exporter = f.admin.transaction().expect("exporter begin");
    exporter
        .batch_execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .expect("exporter RR");
    let snapshot: String = exporter
        .query_one("SELECT pg_export_snapshot()", &[])
        .expect("snapshot export")
        .get(0);
    let raw: String = exporter
        .query_one("SELECT pg_current_snapshot()::text", &[])
        .expect("exporter raw token")
        .get(0);
    eprintln!("G8031 exporter snapshot={snapshot} raw={raw} alive through both readers");
    let rt = tokio::runtime::Runtime::new().expect("rt");
    let h1 = rt.block_on(imported_read(&f.dsn, f.tenant_id, &snapshot, true));
    // Synchronous SQL receipts establish ordering, not wall-clock sleeps.
    let owner = std::env::var("HUMAUX_TEST_PG_DSN").expect("owner configured by setup");
    let mut actor = Client::connect(&owner, NoTls).expect("controlled actor connection");
    let mut actor_tx = actor.transaction().expect("actor begin");
    let xid: String = actor_tx
        .query_one("SELECT pg_current_xact_id()::text", &[])
        .expect("explicit XID allocation")
        .get(0);
    actor_tx
        .commit()
        .expect("actor commit acknowledgement between reads");
    eprintln!("G8031 actor xid={xid} committed between independent readers; fixture untouched");
    // SINGLE_POINT_IMPORT_MUTATION: red ref omits only the second import.
    let h2 = rt.block_on(imported_read(&f.dsn, f.tenant_id, &snapshot, false));
    exporter
        .commit()
        .expect("exporter release only after both readers commit");
    eprintln!("G8031 exporter released after second reader commit");
    // Full-token precondition, preserved before every byte/business assertion.
    assert_eq!(
        h1.snapshot_token_sha256, h2.snapshot_token_sha256,
        "G8031 imported snapshot token precondition"
    );

    // §57.1 Phase 8 前半：逐字节相同。
    assert_eq!(
        h1.canonical_bytes(),
        h2.canonical_bytes(),
        "同一快照两次装配必须逐字节相同（G80-31）"
    );
    assert_eq!(h1.sha256(), h2.sha256());

    // 后半（G25-1 的 e2e 面）：constraint 在，200 噪声一条都不进。
    let ids: Vec<String> = h1.mandatory.iter().map(|i| i.memory_id.clone()).collect();
    assert!(
        ids.contains(&constraint.to_string()),
        "ProjectConstraint 必须在 mandatory 里"
    );
    for n in &noise {
        assert!(
            !ids.contains(&n.to_string()),
            "PrivateKnowledge 噪声不得进 mandatory（选取是机械 authority 规则）"
        );
    }
    assert_eq!(h1.counts.mandatory_returned, 1);
    assert!(!h1.counts.overflow);
}

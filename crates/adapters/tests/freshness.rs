//! `adapters::tests::freshness` — G-M13-4 Evidence-time wiring through the shared final materializer.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-projection, humaux-retrieval, humaux-testkit,
//!   sqlx]; services=[PostgreSQL(owner) w=[private.evidence_objects, private.events,
//!   private.memory_records] r=[private.memory_evidence], PostgreSQL(role_gateway)]; env=[HUMAUX_TEST_PG_DSN];
//!   modules=[adapters::read_materialize, adapters::tests::support::operation_receipt_fixture,
//!   domain::ids, humaux-testkit, projection::serving, retrieval::completeness]
//! Called-by: [cargo-test]
//! Invariants: [real role_gateway reads; owner mutates only fixture audit timestamps; missing DB fails in CI;
//!   the classifier is M13-4a's, never a second policy]
//! Spec: §9; §21.5; §23.3; §57.1; ADR-0111 D-A/D-D

use humaux_adapters::read_materialize::{MaterializedBodies, materialize_final_bodies};
use humaux_domain::ids::TenantId;
use humaux_projection::serving::StreamFamily;
use humaux_retrieval::completeness::FreshnessClass;
use humaux_testkit::run_db_fixture;
use sqlx::types::Uuid;
use std::collections::BTreeSet;

#[allow(dead_code)]
#[path = "support/operation_receipt_fixture.rs"]
mod operation_receipt_fixture;
use operation_receipt_fixture::{DOMAIN, Fixture, Handle, PROJECTION_KIND, PROJECTION_VERSION};

fn read(handle: &Handle, ids: &[Uuid]) -> MaterializedBodies {
    let family = StreamFamily::new(
        TenantId(handle.tenant_id),
        "workspace",
        handle.workspace_id,
        DOMAIN,
        PROJECTION_KIND,
    );
    handle
        .rt
        .block_on(materialize_final_bodies(
            &handle.runtime,
            &handle.auth,
            &family,
            &family.with_version(PROJECTION_VERSION),
            ids,
            &[],
        ))
        .expect("role_gateway materializes")
}

fn seed(handle: &mut Handle) -> Vec<Uuid> {
    let cases = [
        ("STATE", Some(1)),
        ("STATE", Some(14)),
        ("STATE", Some(60)),
        ("STATE", None),
        ("DECISION", Some(60)),
    ];
    let mut ids = Vec::new();
    for (kind, days) in cases {
        let record = handle.seed_workspace_visible_context_record();
        handle
            .admin
            .execute(
                "UPDATE private.memory_records SET memory_type=$2 WHERE memory_id=$1",
                &[&record.memory_id, &kind],
            )
            .expect("fixture type");
        handle
            .admin
            .execute(
                "UPDATE private.evidence_objects SET occurred_at=\
            now()-make_interval(days => $2::int) WHERE evidence_id=$1",
                &[&record.evidence_id, &days],
            )
            .expect("fixture Evidence time");
        handle
            .admin
            .execute(
                "INSERT INTO private.events(event_id,event_kind,payload) \
            VALUES($1,'SYSTEM_IMPORT','{}')",
                &[&record.evidence_id],
            )
            .expect("fixture event");
        ids.push(record.memory_id);
    }
    ids
}

fn assert_annotations(bodies: &MaterializedBodies, ids: &[Uuid]) {
    assert_eq!(bodies.items.len(), 5);
    assert_eq!(bodies.freshness.len(), 5);
    assert_eq!(
        bodies.freshness.keys().copied().collect::<BTreeSet<_>>(),
        ids.iter().copied().collect::<BTreeSet<_>>()
    );
    let expected = [
        FreshnessClass::Fresh,
        FreshnessClass::Aging,
        FreshnessClass::Stale,
        FreshnessClass::Unknown,
        FreshnessClass::Fresh,
    ];
    for (id, class) in ids.iter().zip(expected) {
        let reading = &bodies.freshness[id];
        assert_eq!(reading.class, class);
        assert_eq!(
            (reading.policy_id, reading.policy_version),
            (Some("evidence-per-type"), Some(1))
        );
    }
    assert_eq!(bodies.freshness[&ids[3]].latest_evidence_at, None);
    assert_eq!(bodies.freshness[&ids[3]].state_age_seconds, None);
    for (id, days) in ids
        .iter()
        .zip([Some(1), Some(14), Some(60), None, Some(60)])
    {
        if let Some(days) = days {
            let age = bodies.freshness[id]
                .state_age_seconds
                .expect("known Evidence age");
            assert!(
                (days * 86400..days * 86400 + 60).contains(&age),
                "DB snapshot age"
            );
        }
    }
    assert_eq!(bodies.freshness_summary().class, FreshnessClass::Stale);
}

#[test]
fn g_m13_4_reads_reembed_and_reimport_never_launder_evidence_time() {
    run_db_fixture::<Fixture, _>("G-M13-4 freshness laundering", |mut handle| {
        let ids = seed(&mut handle);
        let before = read(&handle, &ids);
        assert_annotations(&before, &ids);
        let reread = read(&handle, &ids);
        assert_annotations(&reread, &ids);
        // ponytail: surrogate re-embed timestamps until a callable re-embed adapter exists (§9).
        handle
            .admin
            .execute(
                "UPDATE private.memory_records SET updated_at=now(), \
            occurred_at=now() WHERE memory_id=ANY($1)",
                &[&ids],
            )
            .expect("fixture re-embed audit");
        // §8.2: only the isolated fixture owner may simulate historical import audit timestamps.
        handle
            .admin
            .batch_execute("SET session_replication_role=replica")
            .expect("fixture owner");
        handle
            .admin
            .execute(
                "UPDATE private.events SET recorded_at=now()+interval '1 day' \
            WHERE event_id IN (SELECT evidence_id FROM private.memory_evidence \
            WHERE memory_id=ANY($1))",
                &[&ids],
            )
            .expect("fixture re-import audit");
        handle
            .admin
            .batch_execute("SET session_replication_role=origin")
            .expect("restore triggers");
        let after = read(&handle, &ids);
        for id in &ids {
            assert_eq!(
                reread.freshness[id].latest_evidence_at,
                before.freshness[id].latest_evidence_at
            );
            assert_eq!(
                after.freshness[id].latest_evidence_at, before.freshness[id].latest_evidence_at,
                "G-M13-4: audit updates must not move latest_evidence_at"
            );
        }
        assert_annotations(&after, &ids);
        let mut selected = read(&handle, &ids);
        selected.items.retain(|item| {
            matches!(item,
            humaux_adapters::read_materialize::MaterializedItem::Memory { memory_id, .. }
                if [ids[0], ids[3]].contains(memory_id))
        });
        assert_eq!(selected.items.len(), 2);
        assert_eq!(selected.freshness_summary().class, FreshnessClass::Unknown);
        selected.items.clear();
        assert_eq!(selected.freshness_summary().class, FreshnessClass::Unknown);
    });
}

//! `adapters::tests::dedup` — G-M15-14: repeated bytes never collapse two genuine messages.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, postgres, sqlx, uuid]; services=[PostgreSQL(owner) w=[private.evidence_objects, private.evidence_sources, private.memory_evidence, private.memory_records], PostgreSQL(role_gateway) r=[private.memory_records]]; env=[]; modules=[adapters::candidate_repo, adapters::dedup_repo, adapters::tests::support::operation_receipt_fixture, domain::evidence, domain::identity, domain::knowledge, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [owner only seeds; real gateway scan and observations; exact candidate counts and target sets]
//! Spec: Baseline §11.6; §57.1; §79.2; §80.1; ADR-0050; ADR-0113; M15 D3/D10

use humaux_adapters::{candidate_repo, dedup_repo};
use humaux_domain::{
    evidence::payload_sha256,
    identity::{AuthorizationScope, BoundedSet, PrincipalId},
    ids::{TenantId, UserId, WorkspaceId},
    knowledge::{CandidateKind, CandidateState},
};
use humaux_testkit::run_db_fixture;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

#[allow(dead_code)]
#[path = "support/operation_receipt_fixture.rs"]
mod operation_receipt_fixture;
use operation_receipt_fixture::{Fixture, Handle, SyntheticCredentialScopes};

fn auth(h: &mut Handle) -> AuthorizationScope {
    h.assert_gateway_login();
    let key = h.seed_synthetic_service_credential(
        SyntheticCredentialScopes::RememberWrite,
        &Uuid::new_v4().to_string(),
        "dedup-fixture",
        &[7; 32],
    );
    AuthorizationScope::new(
        TenantId(h.tenant_id),
        PrincipalId(key.api_key_id),
        Some(UserId(h.user_id)),
        BoundedSet::new([WorkspaceId(h.workspace_id)]).expect("one workspace"),
    )
}

fn seed(h: &mut Handle, bytes: &[u8], sourced: bool, target: Option<Uuid>) -> (Uuid, Uuid) {
    let mut tx = h.admin.transaction().expect("owner seed transaction");
    let digest = payload_sha256(bytes).as_bytes().to_vec();
    let evidence: Uuid = tx.query_one(
        "INSERT INTO private.evidence_objects
           (tenant_id,evidence_kind,payload_sha256,data_class,origin_class,visibility_class,visibility_workspace_id,reasoning_domain_id)
         VALUES($1,'EVENT',$2,'INTERNAL','DirectUserInput','WORKSPACE_SHARED',$3,$4) RETURNING evidence_id",
        &[&h.tenant_id,&digest,&h.workspace_id,&h.reasoning_domain_id],
    ).expect("owner seeds exact-byte evidence").get(0);
    let memory = target.unwrap_or_else(|| tx.query_one(
        "INSERT INTO private.memory_records
           (tenant_id,memory_type,content,visibility_class,visibility_workspace_id,authority_class,confidence,status,asserted_at)
         VALUES($1,'NOTE','{}','WORKSPACE_SHARED',$2,'ProjectConstraint',0.9,'active',clock_timestamp()) RETURNING memory_id",
        &[&h.tenant_id,&h.workspace_id],
    ).expect("owner seeds active non-identity-note memory").get::<_, Uuid>(0));
    assert_eq!(tx.execute(
        "INSERT INTO private.memory_evidence(memory_id,evidence_id,role,grounding_mode) VALUES($1,$2,'PRIMARY','SNAPSHOT')",
        &[&memory,&evidence],
    ).expect("owner seeds PRIMARY link"), 1);
    if sourced {
        assert_eq!(tx.execute(
            "INSERT INTO private.evidence_sources(tenant_id,owner_user_id,source_kind,object_key_d16,evidence_id,payload_sha256)
             VALUES($1,$2,1,$3,$4,$5)",
            &[&h.tenant_id,&h.user_id,&evidence.as_bytes().as_slice(),&evidence,&digest],
        ).expect("owner seeds distinct source key"), 1);
    }
    tx.commit().expect("commit seed");
    (memory, evidence)
}

fn scan(h: &Handle, a: &AuthorizationScope, commit: bool) -> dedup_repo::DedupScan {
    h.rt.block_on(async {
        let mut conn = PgConnection::connect(h.gateway_dsn_for_process())
            .await
            .expect("actual gateway connection");
        let mut tx = conn.begin().await.expect("gateway transaction");
        let result = dedup_repo::scan_and_propose_in_txn(&mut tx, a)
            .await
            .expect("scan");
        if commit {
            tx.commit().await.expect("commit proposals");
        } else {
            tx.rollback().await.expect("rollback proposals");
        }
        result
    })
}

fn assert_active(h: &Handle, a: &AuthorizationScope, targets: &[Uuid]) {
    let mut gateway = h.gateway_client().expect("gateway observation login");
    let mut tx = gateway.transaction().expect("observation transaction");
    tx.query_one(
        "SELECT set_config('humaux.tenant_id',$1,true),set_config('humaux.user_id',$2,true)",
        &[
            &a.tenant_id().0.to_string(),
            &a.user_id().expect("owner").0.to_string(),
        ],
    )
    .expect("owner scope");
    let rows = tx.query(
        "SELECT memory_id,status,archived_at IS NULL FROM private.memory_records WHERE memory_id=ANY($1) ORDER BY memory_id",
        &[&targets],
    ).expect("read both genuine memories");
    let mut expected = targets.to_vec();
    expected.sort_unstable();
    let actual: Vec<(Uuid, String, bool)> = rows
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect();
    assert_eq!(
        actual,
        expected
            .into_iter()
            .map(|id| (id, "active".into(), true))
            .collect::<Vec<_>>(),
        "G-M15-14: both genuine identical messages remain active and unarchived"
    );
}

#[test]
fn g_m15_14_two_genuine_messages_remain_active() {
    run_db_fixture::<Fixture, _>("g_m15_14_positive", |mut h| {
        let a = auth(&mut h);
        let (first, _) = seed(&mut h, b"same message", true, None);
        let (second, _) = seed(&mut h, b"same message", true, None);
        let result = scan(&h, &a, true);
        assert_eq!(result.proposed.len(), 1);
        assert_eq!(result.skipped, 0);
        let candidates =
            h.rt.block_on(candidate_repo::list(&h.runtime, &a))
                .expect("list");
        assert_eq!(candidates.len(), 1);
        let candidate = &candidates[0];
        assert_eq!(candidate.candidate_id, result.proposed[0]);
        assert_eq!(candidate.kind, CandidateKind::DuplicateGroup);
        assert_eq!(candidate.state, CandidateState::Proposed);
        assert_eq!(candidate.proposed_by, "rule:exact-duplicate@1");
        assert_eq!(candidate.score.to_bits(), 1.0_f64.to_bits());
        let mut targets = vec![first, second];
        targets.sort_unstable();
        assert_eq!(
            candidate
                .targets
                .iter()
                .map(|t| t.memory_id)
                .collect::<Vec<_>>(),
            targets
        );
        assert_active(&h, &a, &targets);
        let mut manifest = b"rule:exact-duplicate@1\0".to_vec();
        manifest.extend_from_slice(payload_sha256(b"same message").as_bytes());
        for id in &targets {
            manifest.extend_from_slice(id.as_bytes());
        }
        assert_eq!(
            candidate.payload_hash,
            payload_sha256(&manifest).as_bytes().to_vec()
        );
        assert_eq!(scan(&h, &a, false).proposed.len(), 1);
        assert_eq!(
            h.rt.block_on(candidate_repo::list(&h.runtime, &a))
                .expect("rollback list"),
            candidates
        );
    });
}

#[test]
fn different_payloads_and_unsourced_evidence_yield_no_candidate() {
    run_db_fixture::<Fixture, _>("g_m15_14_negative", |mut h| {
        let a = auth(&mut h);
        seed(&mut h, b"first", true, None);
        seed(&mut h, b"different", true, None);
        seed(&mut h, b"first", false, None);
        assert_eq!(
            scan(&h, &a, true),
            dedup_repo::DedupScan {
                proposed: vec![],
                skipped: 0
            }
        );
        assert_eq!(
            h.rt.block_on(candidate_repo::list(&h.runtime, &a))
                .expect("list"),
            vec![]
        );
    });
}

#[test]
fn one_distinct_target_is_skipped() {
    run_db_fixture::<Fixture, _>("g_m15_14_skipped", |mut h| {
        let a = auth(&mut h);
        let (first, _) = seed(&mut h, b"same", true, None);
        seed(&mut h, b"same", true, Some(first));
        assert_eq!(
            scan(&h, &a, true),
            dedup_repo::DedupScan {
                proposed: vec![],
                skipped: 1
            }
        );
        assert_eq!(
            h.rt.block_on(candidate_repo::list(&h.runtime, &a))
                .expect("list"),
            vec![]
        );
    });
}

#[test]
fn ineligible_targets_are_excluded() {
    for statement in [
        "UPDATE private.memory_records SET archived_at=clock_timestamp() WHERE memory_id=$1",
        "UPDATE private.memory_records SET status='expired' WHERE memory_id=$1",
        "UPDATE private.memory_records SET note_kind='note' WHERE memory_id=$1",
        "UPDATE private.memory_evidence SET role='SUPPORTING' WHERE memory_id=$1",
    ] {
        run_db_fixture::<Fixture, _>("g_m15_14_ineligible", |mut h| {
            let a = auth(&mut h);
            seed(&mut h, b"same", true, None);
            let (excluded, _) = seed(&mut h, b"same", true, None);
            assert_eq!(
                h.admin
                    .execute(statement, &[&excluded])
                    .expect("owner seeds exclusion"),
                1
            );
            assert_eq!(
                scan(&h, &a, true),
                dedup_repo::DedupScan {
                    proposed: vec![],
                    skipped: 1
                }
            );
            assert_eq!(
                h.rt.block_on(candidate_repo::list(&h.runtime, &a))
                    .expect("list"),
                vec![]
            );
        });
    }
}

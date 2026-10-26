//! `adapters::tests::candidates` — G-M15-2 manifest CAS and non-application through role_gateway.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-projection, humaux-testkit, postgres, uuid]; services=[PostgreSQL(role_gateway) r=[private.curation_candidates, private.curation_candidate_targets, private.memory_records, ops.memory_lifecycle_events, control.confirm_tokens] x=[private.curation_transition_allowed]]; env=[]; modules=[adapters::candidate_repo, adapters::tests::support::operation_receipt_fixture, adapters::tests::support::governance_ops, domain::knowledge]
//! Called-by: [cargo-test]
//! Invariants: [exact counts and sets; owner only seeds fixture data; operations and observations use gateway login]
//! Spec: Baseline §6.1.4; §11.6; §78.2; §79.2; ADR-0113

use humaux_adapters::candidate_repo::{self, CandidateFailure, Proposal};
use humaux_domain::{
    confirm::DestructiveOp,
    error::ErrorCode,
    identity::{AuthorizationScope, BoundedSet, PrincipalId},
    ids::{TenantId, UserId, WorkspaceId},
    knowledge::{CANDIDATE_TRANSITIONS, CandidateKind, CandidateState},
};
use humaux_projection::stream::StreamKey;
use humaux_testkit::run_db_fixture;
use postgres::Transaction;
use uuid::Uuid;

#[allow(dead_code)]
#[path = "support/governance_ops.rs"]
mod governance_ops;
#[allow(dead_code)]
#[path = "support/operation_receipt_fixture.rs"]
mod operation_receipt_fixture;
use operation_receipt_fixture::{Fixture, Handle, SyntheticCredentialScopes};

fn auth(handle: &mut Handle) -> AuthorizationScope {
    let key = handle
        .seed_synthetic_service_credential(
            SyntheticCredentialScopes::RememberWrite,
            &Uuid::new_v4().to_string(),
            "candidate-fixture",
            &[7; 32],
        )
        .api_key_id;
    AuthorizationScope::new(
        TenantId(handle.tenant_id),
        PrincipalId(key),
        Some(UserId(handle.user_id)),
        BoundedSet::new([WorkspaceId(handle.workspace_id)]).expect("one workspace"),
    )
}

fn proposal(targets: Vec<Uuid>) -> Proposal {
    Proposal {
        proposed_by: "rule:fixture@1".into(),
        kind: CandidateKind::DuplicateGroup,
        payload_hash: [3; 32],
        score: 1.0,
        targets,
    }
}

fn session<'a>(
    client: &'a mut postgres::Client,
    auth: &AuthorizationScope,
    workspace: Uuid,
) -> Transaction<'a> {
    let mut txn = client.transaction().expect("gateway transaction");
    txn.query_one("SELECT set_config('humaux.tenant_id',$1,true),set_config('humaux.user_id',$2,true),set_config('humaux.candidate_workspace_id',$3,true)",
        &[&auth.tenant_id().0.to_string(), &auth.user_id().expect("user").0.to_string(), &workspace.to_string()]).expect("session scope");
    txn
}

fn snapshot(handle: &Handle, auth: &AuthorizationScope, target: Uuid, id: Uuid) -> Vec<String> {
    let mut client = handle.gateway_client().expect("actual gateway login");
    let mut txn = session(&mut client, auth, handle.workspace_id);
    let memory: String = txn
        .query_one(
            "SELECT row_to_json(m)::text FROM private.memory_records m WHERE memory_id=$1",
            &[&target],
        )
        .expect("memory row")
        .get(0);
    let candidate: String = txn
        .query_one(
            "SELECT row_to_json(c)::text FROM private.curation_candidates c WHERE candidate_id=$1",
            &[&id],
        )
        .expect("candidate row")
        .get(0);
    let targets: String = txn.query_one("SELECT json_agg(t ORDER BY memory_id)::text FROM private.curation_candidate_targets t WHERE candidate_id=$1", &[&id]).expect("target rows").get(0);
    let events: i64 = txn
        .query_one("SELECT count(*) FROM ops.memory_lifecycle_events", &[])
        .expect("event count")
        .get(0);
    let tokens: i64 = txn
        .query_one("SELECT count(*) FROM control.confirm_tokens", &[])
        .expect("token count")
        .get(0);
    vec![
        memory,
        candidate,
        targets,
        events.to_string(),
        tokens.to_string(),
    ]
}

fn stale(reason: &'static str) -> Result<CandidateState, CandidateFailure> {
    Err(CandidateFailure {
        code: ErrorCode::Conflict,
        reason,
    })
}

#[test]
fn g_m15_2_decide_accept_never_applies_and_payload_cas() {
    run_db_fixture::<Fixture, _>("g_m15_2_accept", |mut h| {
        h.assert_gateway_login();
        let a = auth(&mut h);
        let target = h.seed_workspace_visible_context_record().memory_id;
        let p = proposal(vec![target]);
        let id =
            h.rt.block_on(candidate_repo::propose(&h.runtime, &a, &p))
                .expect("propose");
        let before = snapshot(&h, &a, target, id);
        assert_eq!(
            h.rt.block_on(candidate_repo::decide(
                &h.runtime,
                &a,
                id,
                &[4; 32],
                CandidateState::Accepted
            )),
            stale("candidate_stale_payload")
        );
        assert_eq!(snapshot(&h, &a, target, id), before, "STALE writes nothing");
        assert_eq!(
            h.rt.block_on(candidate_repo::decide(
                &h.runtime,
                &a,
                id,
                &p.payload_hash,
                CandidateState::Accepted
            )),
            Ok(CandidateState::Accepted)
        );
        let after = snapshot(&h, &a, target, id);
        assert_eq!(
            (&after[0], &after[2..]),
            (&before[0], &before[2..]),
            "G-M15-2: target row/snapshots unchanged; zero new events or tokens"
        );
        let rows =
            h.rt.block_on(candidate_repo::list(&h.runtime, &a))
                .expect("list");
        assert_eq!(rows.len(), 1);
        assert_eq!(
            (rows[0].candidate_id, rows[0].state),
            (id, CandidateState::Accepted)
        );
        assert_eq!(
            h.rt.block_on(candidate_repo::decide(
                &h.runtime,
                &a,
                id,
                &p.payload_hash,
                CandidateState::Rejected
            )),
            Err(CandidateFailure {
                code: ErrorCode::InvalidInput,
                reason: "candidate_transition_invalid"
            })
        );
        assert_eq!(snapshot(&h, &a, target, id), after);
    });
}

#[test]
fn g_m15_2_decide_archived_revision_is_stale_without_updated_at_change() {
    run_db_fixture::<Fixture, _>("g_m15_2_archive", |mut h| {
        let governor = governance_ops::Governor::seed(&mut h.admin, h.tenant_id);
        governor.join(&mut h.admin, h.workspace_id);
        let a = governor.scope(h.workspace_id);
        let record = h.seed_workspace_visible_context_record();
        let p = proposal(vec![record.memory_id]);
        let id =
            h.rt.block_on(candidate_repo::propose(&h.runtime, &a, &p))
                .expect("propose");
        let before = snapshot(&h, &a, record.memory_id, id);
        let stream = StreamKey::new(
            TenantId(h.tenant_id),
            "WORKSPACE",
            h.workspace_id,
            "knowledge",
            "ingest",
            "v1",
        );
        let result = governance_ops::archive(
            &h.rt,
            &h.runtime,
            &a,
            &stream,
            record.memory_id,
            DestructiveOp::MemoryArchive,
        )
        .expect("archive");
        assert!(matches!(
            result,
            humaux_adapters::memory_governance_repo::ArchiveResult::Done(_)
        ));
        let archived = snapshot(&h, &a, record.memory_id, id);
        let old: serde_json::Value = serde_json::from_str(&before[0]).expect("before JSON");
        let new: serde_json::Value = serde_json::from_str(&archived[0]).expect("after JSON");
        assert_eq!(new["updated_at"], old["updated_at"]);
        assert_eq!(new["status"], old["status"]);
        assert_ne!(
            new["lifecycle_head_event_id"],
            old["lifecycle_head_event_id"]
        );
        assert_eq!(
            h.rt.block_on(candidate_repo::decide(
                &h.runtime,
                &a,
                id,
                &p.payload_hash,
                CandidateState::Accepted
            )),
            stale("candidate_stale_target")
        );
        assert_eq!(
            snapshot(&h, &a, record.memory_id, id),
            archived,
            "STALE writes nothing"
        );
    });
}

#[test]
fn g_m15_1_gateway_tenant_workspace_isolation() {
    run_db_fixture::<Fixture, _>("g_m15_1_isolation", |mut h| {
        let first = auth(&mut h);
        let target = h.seed_workspace_visible_context_record().memory_id;
        let p = proposal(vec![target]);
        let id =
            h.rt.block_on(candidate_repo::propose(&h.runtime, &first, &p))
                .expect("propose");
        let original = h.workspace_id;
        h.workspace_id = h.seed_workspace();
        let second = auth(&mut h);
        assert_eq!(
            h.rt.block_on(candidate_repo::list(&h.runtime, &second))
                .expect("other workspace")
                .len(),
            0
        );
        assert_eq!(
            h.rt.block_on(candidate_repo::decide(
                &h.runtime,
                &second,
                id,
                &p.payload_hash,
                CandidateState::Accepted
            )),
            Err(CandidateFailure {
                code: ErrorCode::Forbidden,
                reason: "candidate_unavailable"
            })
        );
        assert_eq!(
            h.rt.block_on(candidate_repo::propose(&h.runtime, &second, &p)),
            Err(CandidateFailure {
                code: ErrorCode::Forbidden,
                reason: "candidate_target_unavailable"
            })
        );
        h.workspace_id = original;
        let mut client = h.gateway_client().expect("gateway");
        let mut txn = session(&mut client, &first, original);
        let count: i64 = txn
            .query_one("SELECT count(*) FROM private.curation_candidates", &[])
            .expect("same tenant")
            .get(0);
        assert_eq!(count, 1);
        txn.query_one(
            "SELECT set_config('humaux.tenant_id',$1,true)",
            &[&Uuid::new_v4().to_string()],
        )
        .expect("other tenant");
        for table in ["curation_candidates", "curation_candidate_targets"] {
            let count: i64 = txn
                .query_one(&format!("SELECT count(*) FROM private.{table}"), &[])
                .expect("RLS")
                .get(0);
            assert_eq!(count, 0);
        }
    });
}

#[test]
fn candidate_closed_sets_and_transition_cartesian_product_match_database() {
    use std::collections::BTreeSet;
    run_db_fixture::<Fixture, _>("g_m15_contract", |mut h| {
        let a = auth(&mut h);
        let mut client = h.gateway_client().expect("gateway");
        let mut txn = session(&mut client, &a, h.workspace_id);
        let kinds: BTreeSet<_> = CandidateKind::ALL
            .iter()
            .map(|x| x.wire().to_owned())
            .collect();
        let states: BTreeSet<_> = CandidateState::ALL
            .iter()
            .map(|x| x.wire().to_owned())
            .collect();
        assert_eq!(kinds.len(), 9);
        assert_eq!(states.len(), 5);
        for (constraint, expected) in [
            ("curation_candidate_kind", kinds),
            ("curation_candidate_state", states),
        ] {
            let actual: BTreeSet<String>=txn.query("SELECT (regexp_matches(pg_get_constraintdef(oid), '''([^'']+)''', 'g'))[1] FROM pg_constraint WHERE conrelid='private.curation_candidates'::regclass AND conname=$1",&[&constraint]).expect("CHECK closed set").into_iter().map(|row|row.get(0)).collect();
            assert_eq!(actual, expected, "DB and Rust exact set both ways");
        }
        let expected: BTreeSet<_> = CANDIDATE_TRANSITIONS
            .iter()
            .map(|(from, to)| (from.wire().to_owned(), to.wire().to_owned()))
            .collect();
        assert_eq!(expected.len(), 3);
        let mut actual = BTreeSet::new();
        let mut cells = 0;
        for from in CandidateState::ALL {
            for to in CandidateState::ALL {
                let allowed: bool = txn
                    .query_one(
                        "SELECT private.curation_transition_allowed($1,$2)",
                        &[&from.wire(), &to.wire()],
                    )
                    .expect("transition predicate")
                    .get(0);
                if allowed {
                    actual.insert((from.wire().to_owned(), to.wire().to_owned()));
                }
                cells += 1;
            }
        }
        assert_eq!(cells, 25);
        assert_eq!(actual, expected);
    });
}

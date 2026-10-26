//! `adapters::tests::candidates` — G-M15-2 manifest CAS and non-application through role_gateway.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, postgres, serde_json, uuid]; services=[PostgreSQL(role_gateway) r=[private.curation_candidates, private.curation_candidate_targets, private.memory_records, ops.memory_lifecycle_events, control.confirm_tokens] w=[private.memory_records] x=[ops.append_memory_lifecycle, private.curation_transition_allowed]]; env=[]; modules=[adapters::candidate_repo, adapters::tests::support::operation_receipt_fixture, domain::authority, domain::error, domain::identity, domain::ids, domain::knowledge, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [exact counts and sets; owner only seeds fixture data; operations and observations use gateway login]
//! Spec: Baseline §6.1.4; §11.6; §78.2; §79.2; ADR-0113

use humaux_adapters::candidate_repo::{self, CandidateFailure, Proposal};
use humaux_domain::{
    error::ErrorCode,
    identity::{AuthorizationScope, BoundedSet, PrincipalId},
    ids::{TenantId, UserId, WorkspaceId},
    knowledge::{CANDIDATE_TRANSITIONS, CandidateKind, CandidateState},
};
use humaux_testkit::run_db_fixture;
use postgres::Transaction;
use uuid::Uuid;

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

fn snapshot(handle: &Handle, auth: &AuthorizationScope, id: Uuid) -> Vec<String> {
    let mut client = handle.gateway_client().expect("actual gateway login");
    let mut txn = session(&mut client, auth, handle.workspace_id);
    let memory: String = txn
        .query_one(
            "SELECT json_agg(m ORDER BY m.memory_id)::text FROM private.memory_records m JOIN private.curation_candidate_targets t ON t.memory_id=m.memory_id WHERE t.candidate_id=$1",
            &[&id],
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

fn archive_target(handle: &Handle, auth: &AuthorizationScope, target: Uuid) {
    let mut client = handle
        .gateway_client()
        .expect("actual gateway archive fixture");
    let mut txn = session(&mut client, auth, handle.workspace_id);
    let event: Uuid = txn.query_one(
        "SELECT ops.append_memory_lifecycle($1,'MEMORY',$2,'ARCHIVE','USER_ARCHIVE',$3,NULL,NULL,NULL,NULL,$4,'candidate-revision-fixture',NULL,NULL)",
        &[&auth.tenant_id().0,&target,&auth.principal().0,&Uuid::new_v4().to_string()],
    ).expect("real lifecycle append door").get(0);
    let affected=txn.execute(
        "UPDATE private.memory_records SET archived_at=clock_timestamp(),lifecycle_head_event_id=$2 WHERE memory_id=$1",
        &[&target,&event],
    ).expect("archive fixture and stamp its head atomically");
    assert_eq!(affected, 1);
    txn.commit().expect("commit changed target revision");
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
        let other = h.seed_workspace_visible_context_record().memory_id;
        let p = proposal(vec![target, other]);
        let id =
            h.rt.block_on(candidate_repo::propose(&h.runtime, &a, &p))
                .expect("propose");
        let before = snapshot(&h, &a, id);
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
        assert_eq!(snapshot(&h, &a, id), before, "STALE writes nothing");
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
        let after = snapshot(&h, &a, id);
        assert_eq!(
            (&after[0], &after[2..]),
            (&before[0], &before[2..]),
            "G-M15-2: target row/snapshots unchanged; zero new events or tokens"
        );
        let rows =
            h.rt.block_on(candidate_repo::list(&h.runtime, &a))
                .expect("list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].proposed_by, p.proposed_by);
        assert_eq!(rows[0].score.to_bits(), p.score.to_bits());
        let mut expected_targets = vec![
            candidate_repo::TargetRevision {
                memory_id: target,
                status: humaux_domain::authority::AuthorityStatus::Active,
                lifecycle_head: None,
            },
            candidate_repo::TargetRevision {
                memory_id: other,
                status: humaux_domain::authority::AuthorityStatus::Active,
                lifecycle_head: None,
            },
        ];
        expected_targets.sort_by_key(|revision| revision.memory_id);
        assert_eq!(rows[0].targets, expected_targets);
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
        assert_eq!(snapshot(&h, &a, id), after);
    });
}

#[test]
fn g_m15_2_decide_archived_revision_is_stale_without_updated_at_change() {
    run_db_fixture::<Fixture, _>("g_m15_2_archive", |mut h| {
        let a = auth(&mut h);
        let record = h.seed_workspace_visible_context_record();
        let p = proposal(vec![record.memory_id]);
        let id =
            h.rt.block_on(candidate_repo::propose(&h.runtime, &a, &p))
                .expect("propose");
        let before = snapshot(&h, &a, id);
        archive_target(&h, &a, record.memory_id);
        let archived = snapshot(&h, &a, id);
        let old: serde_json::Value = serde_json::from_str(&before[0]).expect("before JSON");
        let new: serde_json::Value = serde_json::from_str(&archived[0]).expect("after JSON");
        assert_eq!(old[0]["archived_at"], serde_json::Value::Null);
        assert!(new[0]["archived_at"].is_string());
        assert_eq!((before[3].as_str(), archived[3].as_str()), ("0", "1"));
        assert_eq!(new[0]["updated_at"], old[0]["updated_at"]);
        assert_eq!(new[0]["status"], old[0]["status"]);
        assert_ne!(
            new[0]["lifecycle_head_event_id"],
            old[0]["lifecycle_head_event_id"]
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
        assert_eq!(snapshot(&h, &a, id), archived, "STALE writes nothing");
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
        let original_user = h.user_id;
        h.user_id = h.seed_peer_user();
        let peer = auth(&mut h);
        assert_eq!(
            h.rt.block_on(candidate_repo::list(&h.runtime, &peer))
                .expect("other user")
                .len(),
            0
        );
        h.user_id = original_user;
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
        {
            let mut other = session(
                &mut client,
                &second,
                second
                    .allowed_workspace_ids()
                    .iter()
                    .next()
                    .expect("workspace")
                    .0,
            );
            for table in ["curation_candidates", "curation_candidate_targets"] {
                let count: i64 = other
                    .query_one(&format!("SELECT count(*) FROM private.{table}"), &[])
                    .expect("other workspace RLS")
                    .get(0);
                assert_eq!(count, 0);
            }
        }
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
        assert_eq!(
            expected,
            BTreeSet::from([
                ("PROPOSED".to_owned(), "ACCEPTED".to_owned()),
                ("PROPOSED".to_owned(), "REJECTED".to_owned()),
                ("PROPOSED".to_owned(), "EXPIRED".to_owned()),
            ])
        );
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

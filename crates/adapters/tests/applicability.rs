//! `adapters::tests::applicability` — G-M14-8 SQL door outcomes through the Rust adapter.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, serde_json, uuid]; services=[PostgreSQL(owner) r=[private.memory_applicability] w=[control.api_keys, control.memberships, private.memory_applicability, private.evidence_objects, private.subjects], PostgreSQL(role_gateway) x=[private.propose_memory_applicability]]; env=[]; modules=[adapters::applicability_repo, adapters::tests::support::operation_receipt_fixture, domain::applicability, domain::error, domain::identity, domain::ids, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [every refused decision preserves the entire row; every principal/method/evidence/status cell has an exact outcome]
//! Spec: Baseline §6.1.1; §78.2; §79.2; ADR-0096 D-B.1

use humaux_adapters::applicability_repo::{self, ApplicabilityFailure, Decision, Proposal};
use humaux_domain::{
    applicability::{ApplicabilityScope, ApplicabilityStatus, AssignmentMethod},
    error::ErrorCode,
    identity::{AuthorizationScope, BoundedSet, PrincipalId},
    ids::{TenantId, UserId, WorkspaceId},
};
use humaux_testkit::run_db_fixture;
use uuid::Uuid;

#[allow(dead_code)]
#[path = "support/operation_receipt_fixture.rs"]
mod operation_receipt_fixture;
use operation_receipt_fixture::{Fixture, Handle, SyntheticCredentialScopes};

fn proposal(memory_id: Uuid) -> Proposal {
    Proposal {
        memory_id,
        scope: ApplicabilityScope::Universal,
        product_subject_id: None,
        channel_key: None,
        implementation_languages: Vec::new(),
        exclusions: Vec::new(),
    }
}

fn scope(handle: &Handle, key: Uuid, user: Option<Uuid>) -> AuthorizationScope {
    AuthorizationScope::new(
        TenantId(handle.tenant_id),
        PrincipalId(key),
        user.map(UserId),
        BoundedSet::new([WorkspaceId(handle.workspace_id)]).expect("one workspace"),
    )
}

fn owner_key(handle: &mut Handle) -> Uuid {
    handle
        .admin
        .execute(
            "UPDATE control.memberships SET role='OWNER' WHERE tenant_id=$1 AND user_id=$2",
            &[&handle.tenant_id, &handle.user_id],
        )
        .expect("seed owner membership");
    handle
        .seed_synthetic_service_credential(
            SyntheticCredentialScopes::RememberWrite,
            "m14fixture",
            "m14-fixture-only",
            &[1_u8; 32],
        )
        .api_key_id
}

fn extra_key(handle: &mut Handle, source: Uuid, user: Option<Uuid>) -> Uuid {
    let key = Uuid::new_v4();
    handle.admin.execute(
        "INSERT INTO control.api_keys \
         (api_key_id,tenant_id,prefix,key_hash,status,scopes,authorization_version,user_id,workspace_id,tenant_security_epoch,user_security_epoch) \
         SELECT $1::uuid,tenant_id,($1::uuid)::text,key_hash,'ACTIVE',scopes,1,$2::uuid,workspace_id,0,CASE WHEN $2::uuid IS NULL THEN NULL ELSE 0 END \
         FROM control.api_keys WHERE api_key_id=$3",
        &[&key, &user, &source],
    ).expect("seed distinct caller key");
    key
}

fn evidence(handle: &mut Handle, author: Uuid, origin: &str) -> Uuid {
    handle.admin.query_one(
        "INSERT INTO private.evidence_objects \
         (tenant_id,evidence_kind,payload_sha256,data_class,origin_class,origin_principal_id,visibility_class,visibility_workspace_id,reasoning_domain_id) \
         VALUES($1,'EVENT',$2,'INTERNAL',$3,$4,'WORKSPACE_SHARED',$5,$6) RETURNING evidence_id",
        &[&handle.tenant_id, &vec![5_u8;32], &origin, &author, &handle.workspace_id, &handle.reasoning_domain_id],
    ).expect("seed decision Evidence").get(0)
}

fn row(handle: &mut Handle, memory: Uuid) -> String {
    let rows = handle.admin.query(
        "SELECT row_to_json(a)::text FROM private.memory_applicability a WHERE tenant_id=$1 AND memory_id=$2",
        &[&handle.tenant_id, &memory],
    ).expect("read exact applicability row");
    assert_eq!(rows.len(), 1);
    rows[0].get(0)
}

fn refused(reason: &'static str) -> Result<ApplicabilityStatus, ApplicabilityFailure> {
    Err(ApplicabilityFailure {
        code: ErrorCode::Forbidden,
        reason,
    })
}

fn assert_decision(
    handle: &mut Handle,
    auth: &AuthorizationScope,
    decision: &Decision,
    expected: Result<ApplicabilityStatus, ApplicabilityFailure>,
) {
    let before = row(handle, decision.memory_id);
    let result = handle
        .rt
        .block_on(applicability_repo::decide(&handle.runtime, auth, decision));
    assert_eq!(
        result, expected,
        "G-M14-8: {:?} {:?}",
        decision.assignment_method, decision.status
    );
    let after = row(handle, decision.memory_id);
    if result.is_err() {
        assert_eq!(after, before, "G-M14-8: refusal must preserve every column");
    } else {
        let actual: serde_json::Value = serde_json::from_str(&after).expect("row JSON");
        assert_eq!(actual["status"], decision.status.wire());
        assert_eq!(
            actual["assignment_method"],
            decision.assignment_method.wire()
        );
        assert_eq!(
            actual["decision_evidence_id"],
            decision
                .decision_evidence_id
                .expect("decision Evidence")
                .to_string()
        );
    }
}

/// G-M14-8: 3 principals × 2 methods × 6 Evidence conditions × 2 decisions = exactly 72 outcomes.
#[test]
fn g_m14_8_approval_provenance_matrix() {
    run_db_fixture::<Fixture, _>("g_m14_8", |mut handle| {
        let key = owner_key(&mut handle);
        let owner = scope(&handle, key, Some(handle.user_id));
        let peer = handle.seed_peer_user();
        let member_key = extra_key(&mut handle, key, Some(peer));
        let machine_key = extra_key(&mut handle, key, None);
        let authors_key = extra_key(&mut handle, key, Some(owner.user_id().expect("owner").0));
        let other = evidence(&mut handle, authors_key, "AuthenticatedAgent");
        let mut foreign =
            <Fixture as humaux_testkit::DbIntegrationFixture>::isolate().expect("foreign fixture");
        let foreign_evidence = evidence(&mut foreign, key, "AuthenticatedAgent");
        let actors = [
            owner,
            scope(&handle, member_key, Some(peer)),
            scope(&handle, machine_key, None),
        ];
        let mut count = 0;
        for (actor, auth) in actors.iter().enumerate() {
            let same = evidence(&mut handle, auth.principal().0, "AuthenticatedAgent");
            let wrong = evidence(&mut handle, auth.principal().0, "DirectUserInput");
            let conditions = [
                Some(same),
                None,
                Some(Uuid::new_v4()),
                Some(foreign_evidence),
                Some(other),
                Some(wrong),
            ];
            count += matrix_actor(&mut handle, &actors[0], actor, auth, &conditions);
        }
        assert_eq!(count, 72);
        let counts = handle.admin.query_one(
            "SELECT count(*),count(*) FILTER (WHERE status='APPROVED'),count(*) FILTER (WHERE status='REJECTED'),count(*) FILTER (WHERE status='PROPOSED') \
             FROM private.memory_applicability WHERE tenant_id=$1", &[&handle.tenant_id],
        ).expect("exact outcome totals");
        assert_eq!(
            (
                counts.get::<_, i64>(0),
                counts.get::<_, i64>(1),
                counts.get::<_, i64>(2),
                counts.get::<_, i64>(3)
            ),
            (72, 1, 1, 70)
        );
        handle
            .admin
            .execute(
                "DELETE FROM private.memory_applicability WHERE tenant_id=$1",
                &[&handle.tenant_id],
            )
            .expect("remove fixture decisions before Evidence teardown");
    });
}

fn matrix_actor(
    handle: &mut Handle,
    proposer: &AuthorizationScope,
    actor: usize,
    auth: &AuthorizationScope,
    conditions: &[Option<Uuid>; 6],
) -> usize {
    let mut count = 0;
    for method in AssignmentMethod::ALL {
        for (condition, evidence_id) in conditions.iter().enumerate() {
            for status in [ApplicabilityStatus::Approved, ApplicabilityStatus::Rejected] {
                let memory = handle.seed_workspace_visible_context_record().memory_id;
                assert_eq!(
                    handle.rt.block_on(applicability_repo::propose(
                        &handle.runtime,
                        proposer,
                        &proposal(memory)
                    )),
                    Ok(ApplicabilityStatus::Proposed)
                );
                let expected = matrix_expected(actor, method, condition, status);
                assert_decision(
                    handle,
                    auth,
                    &Decision {
                        memory_id: memory,
                        decision_evidence_id: *evidence_id,
                        assignment_method: method,
                        status,
                    },
                    expected,
                );
                count += 1;
            }
        }
    }
    count
}

fn matrix_expected(
    actor: usize,
    method: AssignmentMethod,
    condition: usize,
    status: ApplicabilityStatus,
) -> Result<ApplicabilityStatus, ApplicabilityFailure> {
    if method == AssignmentMethod::OwnerConsole {
        return refused("applicability_console_unavailable");
    }
    if actor != 0 {
        return refused("applicability_owner_required");
    }
    if condition != 0 {
        return refused("applicability_evidence_required");
    }
    Ok(status)
}

/// G-M14-8: replacing a proposal cannot manufacture an approval, including after a prior chat approval.
#[test]
fn g_m14_8_proposals_and_closed_shape() {
    run_db_fixture::<Fixture, _>("g_m14_8_proposals", |mut handle| {
        let key = owner_key(&mut handle);
        let auth = scope(&handle, key, Some(handle.user_id));
        let memory = handle.seed_workspace_visible_context_record().memory_id;
        let mut input = proposal(memory);
        for scope in ApplicabilityScope::ALL {
            input.scope = scope;
            input.channel_key =
                (scope == ApplicabilityScope::ChannelGeneric).then(|| "example_channel".into());
            input.product_subject_id = (scope == ApplicabilityScope::ProductSpecific).then(|| {
                handle.admin.query_one("INSERT INTO private.subjects(tenant_id,kind,display_name) VALUES($1,'PRODUCT','fixture product') RETURNING subject_id", &[&handle.tenant_id]).expect("fixture product").get(0)
            });
            assert_eq!(
                handle
                    .rt
                    .block_on(applicability_repo::propose(&handle.runtime, &auth, &input)),
                Ok(ApplicabilityStatus::Proposed)
            );
            let current: serde_json::Value =
                serde_json::from_str(&row(&mut handle, memory)).expect("row");
            assert_eq!(current["status"], "PROPOSED");
            assert_eq!(current["assignment_method"], serde_json::Value::Null);
            assert_eq!(current["decision_evidence_id"], serde_json::Value::Null);
        }
        let id = evidence(&mut handle, key, "AuthenticatedAgent");
        assert_decision(
            &mut handle,
            &auth,
            &Decision {
                memory_id: memory,
                decision_evidence_id: Some(id),
                assignment_method: AssignmentMethod::AgentOnOwnerChat,
                status: ApplicabilityStatus::Approved,
            },
            Ok(ApplicabilityStatus::Approved),
        );
        assert_eq!(
            handle
                .rt
                .block_on(applicability_repo::propose(&handle.runtime, &auth, &input)),
            Ok(ApplicabilityStatus::Proposed)
        );
        let before = row(&mut handle, memory);
        input.channel_key = Some("invalid for universal".into());
        let result =
            handle
                .rt
                .block_on(applicability_repo::propose(&handle.runtime, &auth, &input));
        assert_eq!(
            result.map_err(|failure| failure.code),
            Err(ErrorCode::InvalidInput)
        );
        assert_eq!(row(&mut handle, memory), before);
        assert_decision(
            &mut handle,
            &auth,
            &Decision {
                memory_id: memory,
                decision_evidence_id: Some(id),
                assignment_method: AssignmentMethod::AgentOnOwnerChat,
                status: ApplicabilityStatus::Proposed,
            },
            Err(ApplicabilityFailure {
                code: ErrorCode::InvalidInput,
                reason: "applicability_decision_invalid",
            }),
        );
        handle
            .admin
            .execute(
                "DELETE FROM private.memory_applicability WHERE tenant_id=$1",
                &[&handle.tenant_id],
            )
            .expect("fixture cleanup");
    });
}

/// G-M14-8: a member can propose but cannot decide; malformed qualifier JSON and direct DML are refused.
#[test]
fn g_m14_8_sql_write_boundary_and_qualifiers() {
    run_db_fixture::<Fixture, _>("g_m14_8_sql_boundary", |mut handle| {
        let key = owner_key(&mut handle);
        let peer = handle.seed_peer_user();
        let member_key = extra_key(&mut handle, key, Some(peer));
        let auth = scope(&handle, member_key, Some(peer));
        let memory = handle.seed_workspace_visible_context_record().memory_id;
        assert_eq!(
            handle.rt.block_on(applicability_repo::propose(
                &handle.runtime,
                &auth,
                &proposal(memory)
            )),
            Ok(ApplicabilityStatus::Proposed)
        );
        let before = row(&mut handle, memory);
        let invalid = [
            serde_json::json!([]),
            serde_json::json!({"implementation_languages": [], "exclusions": [], "extra": true}),
            serde_json::json!({"implementation_languages": [1], "exclusions": []}),
            serde_json::json!({"implementation_languages": [], "exclusions": "none"}),
            serde_json::json!({"implementation_languages": []}),
        ];
        assert_eq!(invalid.len(), 5);
        let mut gateway = handle.gateway_client().expect("real gateway login");
        for qualifiers in invalid {
            let mut txn = gateway
                .transaction()
                .expect("malformed request transaction");
            txn.query_one("SELECT set_config('humaux.tenant_id',$1,true),set_config('humaux.user_id',$2,true)", &[&handle.tenant_id.to_string(), &peer.to_string()]).expect("request GUCs");
            let error = txn.query_one(
                "SELECT private.propose_memory_applicability($1,$2,$3,'UNIVERSAL',NULL,NULL,$4)",
                &[&member_key, &handle.workspace_id, &memory, &qualifiers],
            ).expect_err("closed qualifier schema refuses malformed JSON");
            assert_eq!(error.code().map(|code| code.code()), Some("23514"));
            txn.rollback().expect("failed request rollback");
            assert_eq!(row(&mut handle, memory), before);
        }
        let error = gateway
            .execute(
                "UPDATE private.memory_applicability SET status='APPROVED' WHERE memory_id=$1",
                &[&memory],
            )
            .expect_err("no direct write grant");
        assert_eq!(error.code().map(|code| code.code()), Some("42501"));
        assert_eq!(row(&mut handle, memory), before);
        let absent = gateway
            .query(
                "SELECT memory_id FROM private.memory_applicability WHERE memory_id=$1",
                &[&memory],
            )
            .expect("no tenant GUC is fail-closed");
        assert_eq!(absent.len(), 0);
        handle
            .admin
            .execute(
                "DELETE FROM private.memory_applicability WHERE tenant_id=$1",
                &[&handle.tenant_id],
            )
            .expect("fixture cleanup");
    });
}

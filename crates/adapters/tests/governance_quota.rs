//! `adapters::tests::governance_quota` — the five governance operations drive the four PostgreSQL write transactions (§36).
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-projection, humaux-testkit, serde_json, sqlx];
//!   services=[PostgreSQL(role_gateway) r=[control.audit_events, control.quota_windows, control.usage_reservations, private.memory_records]]; env=[];
//!   modules=[adapters::attribution_repo, adapters::confirm_token_repo, adapters::memory_governance_repo, adapters::postgres, adapters::quota_reservation_port, adapters::request_guard_repo, adapters::tests::support::governance_ops, adapters::tests::support::operation_receipt_fixture, adapters::tests::support::quota_expiry, domain::audit, domain::authority, domain::confirm, domain::error, domain::evidence, domain::identity, humaux-testkit, projection::stream]
//! Called-by: [cargo-test]
//! Invariants: [the runtime uses the real commercial adapter; each fault rolls back facts, quota, audit and confirmation together]
//! Spec: Baseline §34.0.1; §36; ADR-0130 D5

// Both support modules include the idempotent token-key fixture.
#![allow(clippy::duplicate_mod)]

use std::time::Duration;

use humaux_adapters::{
    confirm_token_repo::ConfirmationClaim,
    memory_governance_repo::{
        self as governance, ArchiveRequest, ArchiveResult, CorrectRequest, RestoreRequest,
        RestoreResult, SupersedeRequest,
    },
    postgres::{RuntimeDbPool, commercial_write_quota},
    quota_reservation_port::QuotaReservationPort,
    request_guard_repo::{self, AuditTenant},
};
use humaux_domain::{
    audit::AuditEvent, authority::MemoryId, confirm::DestructiveOp, error::ErrorCode,
    evidence::payload_sha256, identity::AuthorizationScope,
};
use humaux_projection::stream::StreamKey;
use humaux_testkit::run_db_fixture;
use sqlx::types::Uuid;

#[allow(dead_code)]
#[path = "support/operation_receipt_fixture.rs"]
mod operation_receipt_fixture;

#[allow(dead_code)]
#[path = "support/governance_ops.rs"]
mod governance_ops;

#[path = "support/quota_expiry.rs"]
mod quota_expiry;

use governance_ops::Governor;
use operation_receipt_fixture::{Fixture, Handle, Residue, plain_memory, residue};
use quota_expiry::ExpireSettledQuota;

type GovernanceQuotaState = (Residue, Vec<i64>, String, bool);

fn governance_quota_state(handle: &mut Handle, target: Uuid) -> GovernanceQuotaState {
    let facts = residue(handle);
    let row = handle
        .admin
        .query_one(
            "SELECT ARRAY[
             (SELECT count(*) FROM control.usage_reservations WHERE tenant_id=$1),
             (SELECT reserved FROM control.quota_windows WHERE tenant_id=$1),
             (SELECT consumed FROM control.quota_windows WHERE tenant_id=$1),
             (SELECT count(*) FROM control.audit_events WHERE tenant_id=$1)
         ], status, archived_at IS NOT NULL
         FROM private.memory_records WHERE tenant_id=$1 AND memory_id=$2",
            &[&handle.tenant_id, &target],
        )
        .expect("read the fixture's business, quota and audit state");
    (facts, row.get(0), row.get(1), row.get(2))
}

async fn execute_confirmed_governance(
    pool: &RuntimeDbPool,
    quota: &dyn QuotaReservationPort,
    auth: &AuthorizationScope,
    stream: &StreamKey,
    claim: &ConfirmationClaim,
    (request_id, fingerprint): (Uuid, &str),
    finished_audit: AuditEvent,
) -> Result<(i64, i64), ErrorCode> {
    let request_fingerprint = fingerprint.to_owned();
    let target = MemoryId(claim.target_id);
    let op = claim.op;
    let claim = claim.clone();
    let stream = stream.clone();
    let reservation_ttl = Duration::from_secs(2);
    let undo_window = Duration::from_secs(600);
    let consistency_token_ttl = Duration::from_secs(600);
    match op {
        DestructiveOp::MemorySupersede => {
            let successor = MemoryId(claim.successor_id.expect("supersede binds a successor"));
            let request = SupersedeRequest {
                request_id,
                request_fingerprint,
                reservation_ttl,
                target,
                successor,
                stream,
                claim,
                finished_audit: finished_audit.into(),
                undo_window,
            };
            let result = governance::supersede_atomically(pool, quota, auth, request).await?;
            Ok((result.stream_seq, result.commit_seq))
        }
        DestructiveOp::MemoryRestore => {
            let request = RestoreRequest {
                request_id,
                request_fingerprint,
                reservation_ttl,
                target,
                stream,
                claim,
                finished_audit: finished_audit.into(),
                consistency_token_ttl,
            };
            let RestoreResult::Restored(result) =
                governance::restore_atomically(pool, quota, auth, request).await?
            else {
                panic!("restore refused a valid request")
            };
            Ok((result.stream_seq, result.commit_seq))
        }
        DestructiveOp::MemoryArchive | DestructiveOp::MemoryUnarchive => {
            let request = ArchiveRequest {
                request_id,
                request_fingerprint,
                reservation_ttl,
                target,
                stream,
                claim,
                finished_audit: finished_audit.into(),
                op,
            };
            let ArchiveResult::Done(result) =
                governance::archive_or_unarchive_atomically(pool, quota, auth, request).await?
            else {
                panic!("archive/unarchive refused a valid request")
            };
            Ok((result.stream_seq, result.commit_seq))
        }
        DestructiveOp::MemoryCorrect => {
            let content = serde_json::Value::String("governance correction".into());
            let request = CorrectRequest {
                request_id,
                request_fingerprint,
                reservation_ttl,
                target,
                payload_sha256: payload_sha256(&serde_json::to_vec(&content).unwrap()),
                content,
                stream,
                claim,
                finished_audit: finished_audit.into(),
                undo_window,
                consistency_token_ttl,
                subjects: Default::default(),
                affects: Vec::new(),
                mood_half_life: None,
            };
            let result = governance::correct_atomically(
                pool,
                quota,
                auth,
                request,
                &humaux_adapters::attribution_repo::AttributionLadder,
            )
            .await?;
            Ok((result.stream_seq, result.commit_seq))
        }
        _ => unreachable!("this test drives the four governance transactions"),
    }
}

fn assert_single_governance_commit(
    op: DestructiveOp,
    before: &GovernanceQuotaState,
    after: &GovernanceQuotaState,
) {
    assert_eq!(
        after.0.lifecycle_events,
        before.0.lifecycle_events + 1,
        "{op:?}"
    );
    assert_eq!(
        after.0.consumed_tokens,
        before.0.consumed_tokens + 1,
        "{op:?}"
    );
    assert_eq!(after.0.consumed_bmo, before.0.consumed_bmo + 1, "{op:?}");
    assert_eq!(
        after.0.receipts, before.0.receipts,
        "{op:?} has no operation receipt"
    );
    assert_eq!(
        after.1,
        [
            before.1[0] + 1,
            before.1[1],
            before.1[2] + 1,
            before.1[3] + 3
        ],
        "{op:?}"
    );
}

fn assert_governance_quota_case(
    handle: &mut Handle,
    auth: &AuthorizationScope,
    stream: &StreamKey,
    op: DestructiveOp,
    target: Uuid,
    successor: Uuid,
) {
    let claim = governance_ops::confirm(
        &handle.rt,
        &handle.runtime,
        auth,
        op,
        target,
        (op == DestructiveOp::MemorySupersede).then_some(successor),
    );
    let request_id = Uuid::now_v7();
    let finished_audit = governance_ops::audit(auth, op, request_id, false);
    let duplicate_id = governance_ops::audit(auth, op, Uuid::now_v7(), false);
    handle
        .rt
        .block_on(request_guard_repo::audit_event_insert(
            &handle.runtime,
            AuditTenant::Authenticated(auth),
            &duplicate_id,
        ))
        .expect("seed an audit ID that the final audit cannot insert a second time");
    let fingerprint = governance_ops::fingerprint();
    let execute = |handle: &Handle, quota: &dyn QuotaReservationPort, finished_audit| {
        handle.rt.block_on(execute_confirmed_governance(
            &handle.runtime,
            quota,
            auth,
            stream,
            &claim,
            (request_id, &fingerprint),
            finished_audit,
        ))
    };

    let before = governance_quota_state(handle, target);
    let mut fault = finished_audit.clone();
    fault.event_id = duplicate_id.event_id;
    for (label, quota, audit) in [
        ("final audit", commercial_write_quota(), fault),
        (
            "expiry after settlement",
            &ExpireSettledQuota,
            finished_audit.clone(),
        ),
    ] {
        assert_eq!(
            execute(handle, quota, audit),
            Err(ErrorCode::Conflict),
            "{op:?} {label}"
        );
        assert_eq!(
            governance_quota_state(handle, target),
            before,
            "{op:?} {label} must roll back all writes"
        );
    }

    let success = execute(handle, commercial_write_quota(), finished_audit.clone())
        .expect("the same confirmation and reservation can succeed after rollback");
    let after = governance_quota_state(handle, target);
    assert_single_governance_commit(op, &before, &after);

    let replay = execute(handle, commercial_write_quota(), finished_audit);
    assert_eq!(
        replay,
        if op == DestructiveOp::MemorySupersede {
            Err(ErrorCode::Conflict)
        } else {
            Ok(success)
        },
        "{op:?}"
    );
    assert_eq!(
        governance_quota_state(handle, target),
        after,
        "{op:?} replay writes nothing"
    );
}

#[test]
fn governance_quota_rolls_back_audit_failure_and_expired_lease_and_replays_once() {
    run_db_fixture::<Fixture, _>("governance_quota_atomicity", |mut handle| {
        let governor = Governor::seed(&mut handle.admin, handle.tenant_id);
        governor.join(&mut handle.admin, handle.workspace_id);
        let auth = &governor.scope(handle.workspace_id);
        let target = plain_memory(&mut handle);
        let successor = plain_memory(&mut handle);
        let stream = governance_ops::stream(handle.tenant_id, handle.workspace_id);
        for op in [
            DestructiveOp::MemorySupersede,
            DestructiveOp::MemoryRestore,
            DestructiveOp::MemoryArchive,
            DestructiveOp::MemoryUnarchive,
            DestructiveOp::MemoryCorrect,
        ] {
            assert_governance_quota_case(&mut handle, auth, &stream, op, target, successor);
        }
    });
}

//! `adapters::tests::evidence_task_runs` — M29 T04c (design v0.2 §15, §30.2): `remember.put` with a task run verifies it
//!   in the receipt transaction and writes the `private.evidence_task_runs` carrier, or is refused whole.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, serde_json, sqlx];
//!   services=[PostgreSQL(role_gateway) r=[control.quota_windows, control.usage_reservations, private.evidence_objects,
//!   private.memory_evidence, private.memory_records] w=[coord.task_runs, private.evidence_task_runs]]; env=[];
//!   modules=[adapters::coord_repo, adapters::operation_receipt, adapters::remember,
//!   adapters::tests::support::operation_receipt_fixture, domain::audit, domain::coordination, domain::error,
//!   domain::evidence, domain::identity, domain::ids, domain::subject, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [every runtime write uses a real role_gateway login; leases expire by SQL on the DB clock, never by
//!   sleep; the owner connection only seeds, expires leases, reads outcomes and removes this fixture's rows]
//! Spec: §30.2; §34.0.1; §52; design v0.2 §15 T04c
//!
//! G-T04c-1: a failed verification (stale token after a re-claim, expired lease, another principal's lease) is the
//! T04a `ErrorCode` and moves none of the tenant's Evidence, Memory, `memory_evidence`, carrier or BMO counts.
//! G-T04c-2: a verified put writes exactly one carrier row naming its run, token and Evidence; a put without a run
//! writes none; a replay of the verified put answers its stored outcome after the lease expired.
//!
//! called-by: `cargo test -p humaux-adapters --test evidence_task_runs`.

use std::time::{Duration, SystemTime};

use humaux_adapters::{
    coord_repo,
    operation_receipt::{self, AtomicRememberRequest, AtomicRememberResult},
    remember::RememberCommand,
};
use humaux_domain::{
    audit::{AuditEvent, AuditEventId, AuditMetadata, McpAuditAction},
    coordination::{FencingToken, TaskRunId},
    error::ErrorCode,
    evidence::{EvidenceOriginClass, payload_sha256},
    identity::{AuthorizationScope, BoundedSet, PrincipalId},
    ids::{TenantId, WorkspaceId},
};
use humaux_testkit::run_db_fixture;
use sqlx::types::{Uuid, time::OffsetDateTime};

#[allow(dead_code)]
#[path = "support/operation_receipt_fixture.rs"]
mod operation_receipt_fixture;

use operation_receipt_fixture::{
    DOMAIN, Fixture, Handle, OPERATION, PROJECTION_KIND, PROJECTION_VERSION,
};

const TTL: Duration = Duration::from_secs(300);

fn request(handle: &Handle, key: &str, content: &str) -> AtomicRememberRequest {
    let request_id = Uuid::new_v4();
    let key_hex: String = key.bytes().map(|b| format!("{b:02x}")).collect();
    let mut metadata = AuditMetadata::new();
    metadata
        .insert("role", "member")
        .expect("allowlisted audit metadata");
    AtomicRememberRequest {
        request_id,
        idempotency_key: key.into(),
        // One fingerprint per key (keys here are under 32 bytes): a replay of the same key is the same request.
        request_fingerprint: format!("{key_hex:0>64}"),
        workspace_id: Some(WorkspaceId(handle.workspace_id)),
        reservation_ttl: Duration::from_secs(30),
        replay_ttl: Duration::from_secs(60),
        command: RememberCommand {
            tenant_id: handle.tenant_id,
            authorization_user_id: Some(handle.user_id),
            scope_kind: "workspace".into(),
            scope_id: handle.workspace_id,
            domain: DOMAIN.into(),
            projection_kind: PROJECTION_KIND.into(),
            projection_version: PROJECTION_VERSION.into(),
            consistency_token_expires_at: OffsetDateTime::now_utc() + Duration::from_secs(45),
            batch_id: None,
            payload_sha256: payload_sha256(content.as_bytes()),
            data_class: "INTERNAL".into(),
            origin_class: EvidenceOriginClass::AuthenticatedAgent,
            origin_principal_id: Some(handle.principal_id),
            origin_connector_id: None,
            visibility_class: "WORKSPACE_SHARED".into(),
            visibility_user_id: None,
            visibility_workspace_id: Some(handle.workspace_id),
            reasoning_domain_id: handle.reasoning_domain_id,
            occurred_at: None,
            event_kind: "TASK_EVENT".into(),
            event_payload: serde_json::json!({"content": content}),
            subjects: humaux_domain::subject::SubjectDeclaration::default(),
            affects: Vec::new(),
            mood_half_life: None,
        },
        finished_audit: AuditEvent {
            event_id: AuditEventId::new(),
            ts: SystemTime::now(),
            tenant_id: TenantId(handle.tenant_id),
            actor_type: "user".into(),
            actor_id: handle.principal_id.to_string(),
            action: McpAuditAction::McpRequestFinished.as_str().into(),
            resource_type: "mcp".into(),
            resource_id: OPERATION.into(),
            result: "OK".into(),
            request_id: request_id.to_string(),
            trace_id: format!("evidence-task-runs-{request_id}"),
            client_ip: "127.0.0.1".into(),
            user_agent_hash: "evidence-task-runs-fixture".into(),
            risk_tags: vec!["fixture".into()],
            before_fingerprint: None,
            after_fingerprint: None,
            metadata,
        },
    }
}

fn put(
    handle: &Handle,
    key: &str,
    task_run: Option<(TaskRunId, FencingToken)>,
) -> Result<AtomicRememberResult, ErrorCode> {
    handle
        .rt
        .block_on(operation_receipt::remember_for_task_run_atomically(
            &handle.runtime,
            &handle.auth,
            request(handle, key, &format!("evidence-task-runs {key}")),
            task_run,
        ))
}

/// A fresh task in the fixture tenant, claimed by `owner`: `(run, token)`.
fn claimed(handle: &Handle, owner: &AuthorizationScope) -> (TaskRunId, FencingToken) {
    let task = handle
        .rt
        .block_on(coord_repo::submit(
            &handle.runtime,
            owner,
            "evidence_task_runs",
        ))
        .expect("submit");
    let run = handle
        .rt
        .block_on(coord_repo::claim(&handle.runtime, owner, task, TTL))
        .expect("claim");
    (run.task_run_id, run.fencing_token)
}

/// Moves the run's lease into the past on the DB clock (no sleep).
fn expire(handle: &mut Handle, run: TaskRunId) {
    let n = handle
        .admin
        .execute(
            "UPDATE coord.task_runs SET lease_expires_at = clock_timestamp() - interval '1 second' \
             WHERE task_run_id = $1",
            &[&run.0],
        )
        .expect("expire lease");
    assert_eq!(n, 1);
}

/// `[Evidence, Memory, memory_evidence, carrier, BMO reservations, BMO consumed]` for the fixture tenant.
fn counts(handle: &mut Handle) -> [i64; 6] {
    let row = handle
        .admin
        .query_one(
            "SELECT \
               (SELECT count(*) FROM private.evidence_objects WHERE tenant_id = $1), \
               (SELECT count(*) FROM private.memory_records WHERE tenant_id = $1), \
               (SELECT count(*) FROM private.memory_evidence me \
                  JOIN private.memory_records m ON m.memory_id = me.memory_id WHERE m.tenant_id = $1), \
               (SELECT count(*) FROM private.evidence_task_runs WHERE tenant_id = $1), \
               (SELECT count(*) FROM control.usage_reservations WHERE tenant_id = $1), \
               (SELECT coalesce(sum(consumed), 0)::bigint FROM control.quota_windows WHERE tenant_id = $1)",
            &[&handle.tenant_id],
        )
        .expect("owner reads fixture outcomes");
    [0usize, 1, 2, 3, 4, 5].map(|i| row.get(i))
}

/// The fixture's teardown deletes Evidence and `coord.tasks` but knows neither the carrier nor `coord.task_runs`.
fn purge_runs(handle: &mut Handle) {
    handle
        .admin
        .execute(
            "DELETE FROM private.evidence_task_runs WHERE tenant_id = $1",
            &[&handle.tenant_id],
        )
        .expect("purge carrier");
    handle
        .admin
        .execute(
            "DELETE FROM coord.task_runs WHERE tenant_id = $1",
            &[&handle.tenant_id],
        )
        .expect("purge runs");
}

/// G-T04c-1: every failed verification is the T04a ErrorCode with zero writes, never a degraded put without the run.
#[test]
fn g_t04c_1_failed_verification_writes_nothing() {
    run_db_fixture::<Fixture, _>(
        "g_t04c_1_failed_verification_writes_nothing",
        |mut handle| {
            handle.seed_current_entitlement_and_window(10);
            let owner = handle.auth.clone();

            // Stale token after a re-claim: the old run (now closed) and the new run with the old token.
            let (run1, token1) = claimed(&handle, &owner);
            expire(&mut handle, run1);
            let task_of_run1: Uuid = handle
                .admin
                .query_one(
                    "SELECT task_id FROM coord.task_runs WHERE task_run_id = $1",
                    &[&run1.0],
                )
                .expect("task of run1")
                .get(0);
            let run2 = handle
                .rt
                .block_on(coord_repo::claim(
                    &handle.runtime,
                    &owner,
                    humaux_domain::ids::TaskId(task_of_run1),
                    TTL,
                ))
                .expect("re-claim after expiry");
            assert!(run2.fencing_token > token1);

            // Expired lease.
            let (run3, token3) = claimed(&handle, &owner);
            expire(&mut handle, run3);

            // Another principal's lease in the same tenant.
            let other = AuthorizationScope::new(
                TenantId(handle.tenant_id),
                PrincipalId::new(),
                None,
                BoundedSet::new([WorkspaceId(handle.workspace_id)]).expect("one workspace"),
            );
            let (run4, token4) = claimed(&handle, &other);

            let cases = [
                ("stale-old-run", (run1, token1), ErrorCode::Conflict),
                (
                    "stale-token",
                    (run2.task_run_id, token1),
                    ErrorCode::Conflict,
                ),
                ("expired-lease", (run3, token3), ErrorCode::Conflict),
                ("non-owner", (run4, token4), ErrorCode::Forbidden),
            ];
            for (name, task_run, expected) in cases {
                let before = counts(&mut handle);
                let outcome = put(&handle, &format!("t04c-1-{name}"), Some(task_run));
                assert_eq!(outcome.err(), Some(expected), "{name}");
                assert_eq!(counts(&mut handle), before, "{name}: zero writes");
            }
            purge_runs(&mut handle);
        },
    );
}

/// G-T04c-2: a verified put writes exactly one carrier row; a put without a run writes none and is otherwise the same.
#[test]
fn g_t04c_2_verified_put_writes_one_carrier_row() {
    run_db_fixture::<Fixture, _>(
        "g_t04c_2_verified_put_writes_one_carrier_row",
        |mut handle| {
            handle.seed_current_entitlement_and_window(10);
            let owner = handle.auth.clone();
            let (run, token) = claimed(&handle, &owner);

            let before = counts(&mut handle);
            let with_run =
                put(&handle, "t04c-2-with-run", Some((run, token))).expect("verified put");
            let after_with = counts(&mut handle);
            assert!(!with_run.replayed);
            let carrier = handle
            .admin
            .query(
                "SELECT task_run_id, fencing_token, evidence_id FROM private.evidence_task_runs \
                 WHERE tenant_id = $1",
                &[&handle.tenant_id],
            )
            .expect("read carrier");
            assert_eq!(carrier.len(), 1);
            assert_eq!(carrier[0].get::<_, Uuid>(0), run.0);
            assert_eq!(carrier[0].get::<_, i64>(1), token.0);
            assert_eq!(carrier[0].get::<_, Uuid>(2), with_run.accepted.evidence_id);

            let without_run = put(&handle, "t04c-2-without-run", None).expect("plain put");
            let after_without = counts(&mut handle);
            assert!(!without_run.replayed);
            let delta = |a: [i64; 6], b: [i64; 6]| [0usize, 1, 2, 3, 4, 5].map(|i| b[i] - a[i]);
            assert_eq!(delta(before, after_with), [1, 0, 0, 1, 1, 1]);
            assert_eq!(delta(after_with, after_without), [1, 0, 0, 0, 1, 1]);

            // §34.0.1: the committed key replays its stored outcome without re-verifying the (now expired) lease.
            expire(&mut handle, run);
            let replay = put(&handle, "t04c-2-with-run", Some((run, token))).expect("replay");
            assert!(replay.replayed);
            assert_eq!(replay.accepted.evidence_id, with_run.accepted.evidence_id);
            assert_eq!(counts(&mut handle), after_without);
            purge_runs(&mut handle);
        },
    );
}

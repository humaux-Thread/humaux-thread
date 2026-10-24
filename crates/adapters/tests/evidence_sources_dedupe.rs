//! `adapters::tests::evidence_sources_dedupe` — M06-1b (ADR-0098 D1/D3): `remember_sourced_atomically` against a real
//!   Postgres: one Evidence per source identity across agents, `SOURCE_VERSION_CONFLICT`, and the 0265 receipt trigger.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, hex, serde_json, sqlx, tokio];
//!   services=[PostgreSQL(role_gateway) r=[control.audit_events, control.operation_receipts, control.usage_reservations,
//!   ops.outbox, private.evidence_objects, private.evidence_sources, private.events, projection.stream_log]];
//!   env=[]; modules=[adapters::operation_receipt, adapters::postgres, adapters::remember,
//!   adapters::tests::support::operation_receipt_fixture, domain::audit, domain::error, domain::evidence,
//!   domain::identity, domain::ids, domain::source, domain::subject, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [every runtime write uses a real role_gateway login (one connection per concurrent agent); the owner
//!   connection only seeds, counts and removes this fixture's tenant rows; the two agents share one owner user and have
//!   distinct principals and operation keys]
//! Spec: Baseline §34.0.1; §60; §79.2; ADR-0098
//!
//! G-M06-1 `two_agents_one_message`: concurrent puts of one message from two principals → 1 Evidence, 2 receipts, 1 ticket.
//! G-M06-2 `same_key_new_bytes_conflicts`: same identity, new bytes → SOURCE_VERSION_CONFLICT, original bytes untouched.
//! G-M06-3 `sourced_put_waits_on_identity_lock`: a held identity advisory lock parks the put at `Lock/advisory` until commit.

use std::sync::{Arc, Barrier};

use humaux_adapters::{
    operation_receipt::{
        self, AtomicRememberRequest, AtomicRememberResult, Dedupe, SourcedPutError,
    },
    postgres::RuntimeDbPool,
    remember::RememberCommand,
};
use humaux_domain::{
    audit::{AuditEvent, AuditEventId, AuditMetadata, McpAuditAction},
    error::{ConflictReason, ErrorCode},
    evidence::{EvidenceOriginClass, payload_sha256},
    identity::{AuthorizationScope, BoundedSet, PrincipalId},
    ids::{TenantId, UserId, WorkspaceId},
    source::{IngestSourceKind, SourceIdentity},
};
use humaux_testkit::run_db_fixture;
use sqlx::types::{Uuid, time::OffsetDateTime};
use std::time::{Duration, SystemTime};

#[allow(dead_code)]
#[path = "support/operation_receipt_fixture.rs"]
mod operation_receipt_fixture;

use operation_receipt_fixture::{
    DOMAIN, Fixture, Handle, OPERATION, PROJECTION_KIND, PROJECTION_VERSION,
};

// §79.2: fixture cleanup must run outside the owner's lock transaction, including during unwinding.
struct RollbackOnPanic<'a>(&'a mut Handle);

impl std::ops::Deref for RollbackOnPanic<'_> {
    type Target = Handle;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl std::ops::DerefMut for RollbackOnPanic<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

impl Drop for RollbackOnPanic<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.0.admin.batch_execute("ROLLBACK") {
            eprintln!("identity-lock transaction rollback failed: {error}");
        }
    }
}

/// `[evidence_objects, evidence_sources, stream_log, outbox, operation_receipts, usage_reservations, audit_events]`.
type Counts = [i64; 7];

fn counts(handle: &mut Handle) -> Counts {
    let row = handle
        .admin
        .query_one(
            "SELECT \
               (SELECT count(*) FROM private.evidence_objects WHERE tenant_id=$1), \
               (SELECT count(*) FROM private.evidence_sources WHERE tenant_id=$1), \
               (SELECT count(*) FROM projection.stream_log WHERE tenant_id=$1), \
               (SELECT count(*) FROM ops.outbox WHERE tenant_id=$1), \
               (SELECT count(*) FROM control.operation_receipts WHERE tenant_id=$1), \
               (SELECT count(*) FROM control.usage_reservations WHERE tenant_id=$1), \
               (SELECT count(*) FROM control.audit_events WHERE tenant_id=$1)",
            &[&handle.tenant_id],
        )
        .expect("owner counts the fixture tenant's rows");
    std::array::from_fn(|i| row.get(i))
}

fn delta(after: Counts, before: Counts) -> Counts {
    std::array::from_fn(|i| after[i] - before[i])
}

fn auth_for(handle: &Handle, principal: Uuid) -> AuthorizationScope {
    AuthorizationScope::new(
        TenantId(handle.tenant_id),
        PrincipalId(principal),
        Some(UserId(handle.user_id)),
        BoundedSet::new([WorkspaceId(handle.workspace_id)]).expect("one workspace"),
    )
}

fn finished_audit(handle: &Handle, principal: Uuid, request_id: Uuid) -> AuditEvent {
    let mut metadata = AuditMetadata::new();
    metadata
        .insert("role", "member")
        .expect("allowlisted audit metadata");
    AuditEvent {
        event_id: AuditEventId::new(),
        ts: SystemTime::now(),
        tenant_id: TenantId(handle.tenant_id),
        actor_type: "user".into(),
        actor_id: principal.to_string(),
        action: McpAuditAction::McpRequestFinished.as_str().into(),
        resource_type: "mcp".into(),
        resource_id: OPERATION.into(),
        result: "OK".into(),
        request_id: request_id.to_string(),
        trace_id: format!("evidence-sources-dedupe-{request_id}"),
        client_ip: "127.0.0.1".into(),
        user_agent_hash: "operation-receipt-fixture".into(),
        risk_tags: vec!["fixture".into()],
        before_fingerprint: None,
        after_fingerprint: None,
        metadata,
    }
}

/// One agent's put of `content` under operation key `key`: the weakest classification a caller can ask for, so every
/// stored value that differs from it was decided by the source classification.
fn request(handle: &Handle, principal: Uuid, key: &str, content: &str) -> AtomicRememberRequest {
    let request_id = Uuid::new_v4();
    AtomicRememberRequest {
        request_id,
        idempotency_key: key.into(),
        request_fingerprint: payload_sha256(format!("{key}:{content}").as_bytes()).to_hex(),
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
            origin_principal_id: Some(principal),
            origin_connector_id: None,
            visibility_class: "USER_PRIVATE".into(),
            visibility_user_id: Some(handle.user_id),
            visibility_workspace_id: None,
            reasoning_domain_id: handle.reasoning_domain_id,
            occurred_at: None,
            event_kind: "USER_MESSAGE".into(),
            event_payload: serde_json::json!({ "content": content }),
            subjects: humaux_domain::subject::SubjectDeclaration::default(),
            affects: Vec::new(),
            mood_half_life: None,
        },
        finished_audit: finished_audit(handle, principal, request_id),
    }
}

fn identity(kind: IngestSourceKind, object_key: &str, version: Option<&str>) -> SourceIdentity {
    SourceIdentity::new(kind, object_key, version, Some("thread-1")).expect("a valid identity")
}

/// One sequential sourced put on the fixture's shared pool.
fn put(
    handle: &Handle,
    principal: Uuid,
    source: &SourceIdentity,
    key: &str,
    content: &str,
) -> Result<AtomicRememberResult, SourcedPutError> {
    handle
        .rt
        .block_on(operation_receipt::remember_sourced_atomically(
            &handle.runtime,
            &auth_for(handle, principal),
            request(handle, principal, key, content),
            source,
        ))
}

fn stored(
    outcome: Result<AtomicRememberResult, SourcedPutError>,
    what: &str,
) -> AtomicRememberResult {
    match outcome {
        Ok(result) => result,
        Err(error) => panic!("{what}: expected a stored result, got {error:?}"),
    }
}

/// Puts from several agents at once: one thread, runtime and `role_gateway` connection each, released together by a
/// barrier that every thread reaches even when its connection failed.
fn put_concurrently(
    handle: &Handle,
    jobs: Vec<(Uuid, AtomicRememberRequest, SourceIdentity)>,
) -> Vec<Result<AtomicRememberResult, SourcedPutError>> {
    let barrier = Arc::new(Barrier::new(jobs.len()));
    let threads: Vec<_> = jobs
        .into_iter()
        .map(|(principal, request, source)| {
            let dsn = handle.gateway_application_dsn(&format!(
                "evidence-sources-dedupe-{}",
                Uuid::new_v4().simple()
            ));
            let auth = auth_for(handle, principal);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().expect("runtime");
                // dep: PostgreSQL(role_gateway) — RuntimeDbPool under test, one real connection per agent.
                let pool = rt
                    .block_on(RuntimeDbPool::connect(&dsn))
                    .map_err(|error| error.to_string());
                barrier.wait();
                let pool = pool.expect("agent connection");
                rt.block_on(operation_receipt::remember_sourced_atomically(
                    &pool, &auth, request, &source,
                ))
            })
        })
        .collect();
    threads
        .into_iter()
        .map(|thread| thread.join().expect("agent thread"))
        .collect()
}

/// G-M06-1 (§34.0.1, ADR-0098 D1): two agents of one user relay the same message at the same instant under different
/// operation keys. The identity is shared, so exactly one Evidence, one identity row, one ticket and one outbox row exist,
/// and each agent holds its own receipt, reservation and audit rows. Both an AgentNote (the old receipt predicate holds
/// for the first agent only) and an EmailMessage (ExternalContent: the old predicate holds for neither) are covered.
#[test]
fn two_agents_one_message() {
    run_db_fixture::<Fixture, _>("two_agents_one_message", |mut handle| {
        handle.seed_current_entitlement_and_window(10);
        let agent_a = handle.principal_id;
        let agent_b = Uuid::new_v4();
        for kind in [IngestSourceKind::AgentNote, IngestSourceKind::EmailMessage] {
            let before = counts(&mut handle);
            let source = identity(kind, "message-1", Some("v1"));
            // The receipt table is append-only: each round has its own operation keys.
            let key_a = format!("key-agent-a-{kind:?}");
            let key_b = format!("key-agent-b-{kind:?}");
            let outcomes = put_concurrently(
                &handle,
                vec![
                    (
                        agent_a,
                        request(&handle, agent_a, &key_a, "hello"),
                        source.clone(),
                    ),
                    (
                        agent_b,
                        request(&handle, agent_b, &key_b, "hello"),
                        source.clone(),
                    ),
                ],
            );
            let results: Vec<AtomicRememberResult> = outcomes
                .into_iter()
                .enumerate()
                .map(|(agent, outcome)| stored(outcome, &format!("{kind:?}, agent {agent}")))
                .collect();
            assert_eq!(results.len(), 2, "{kind:?}");
            assert_eq!(
                results.iter().filter(|r| r.dedupe == Dedupe::New).count(),
                1,
                "{kind:?}: exactly one agent wrote the Evidence"
            );
            assert_eq!(
                results
                    .iter()
                    .filter(|r| r.dedupe == Dedupe::Existing)
                    .count(),
                1,
                "{kind:?}: exactly one agent hit the existing Evidence"
            );
            assert_eq!(
                results[0].accepted.evidence_id,
                results[1].accepted.evidence_id
            );
            assert!(results.iter().all(|r| !r.replayed), "{kind:?}");

            assert_eq!(
                delta(counts(&mut handle), before),
                [1, 1, 1, 1, 2, 2, 6],
                "{kind:?}: 1 Evidence, 1 identity row, 1 ticket, 1 outbox row, 2 receipts, 2 reservations, 6 audit rows"
            );
            let receipts = handle
                .admin
                .query_one(
                    "SELECT count(DISTINCT principal_id), count(DISTINCT evidence_id), count(DISTINCT idempotency_key) \
                       FROM control.operation_receipts \
                      WHERE tenant_id=$1 AND idempotency_key = ANY($2) AND evidence_id = $3",
                    &[
                        &handle.tenant_id,
                        &vec![key_a.clone(), key_b.clone()],
                        &results[0].accepted.evidence_id,
                    ],
                )
                .expect("receipt shape");
            assert_eq!(
                (
                    receipts.get::<_, i64>(0),
                    receipts.get::<_, i64>(1),
                    receipts.get::<_, i64>(2)
                ),
                (2, 1, 2),
                "{kind:?}: two principals, one Evidence, two operation keys"
            );
        }
    });
}

/// The stored bytes of every Evidence in the fixture tenant, as `(evidence payload sha, identity-row sha, event payload)`:
/// what a conflict must leave untouched.
fn stored_bytes(handle: &mut Handle) -> Vec<(Vec<u8>, Vec<u8>, serde_json::Value)> {
    handle
        .admin
        .query(
            "SELECT eo.payload_sha256, s.payload_sha256, e.payload::text \
               FROM private.evidence_objects eo \
               JOIN private.events e ON e.event_id = eo.evidence_id \
               JOIN private.evidence_sources s ON s.tenant_id = eo.tenant_id AND s.evidence_id = eo.evidence_id \
              WHERE eo.tenant_id = $1",
            &[&handle.tenant_id],
        )
        .expect("owner reads the stored bytes")
        .iter()
        .map(|row| {
            (
                row.get::<_, Vec<u8>>(0),
                row.get::<_, Vec<u8>>(1),
                serde_json::from_str(&row.get::<_, String>(2)).expect("event payload is JSON"),
            )
        })
        .collect()
}

/// G-M06-2 (ADR-0098 D1): the same identity with new bytes is `SOURCE_VERSION_CONFLICT` for the original agent and for
/// another agent alike, writes nothing (no Evidence, receipt, reservation or audit row, so the operation key stays unused)
/// and leaves the first message's bytes identical. The same bytes are still a dedupe hit afterwards, and a new version
/// of the message is a new identity.
#[test]
fn same_key_new_bytes_conflicts() {
    run_db_fixture::<Fixture, _>("same_key_new_bytes_conflicts", |mut handle| {
        handle.seed_current_entitlement_and_window(10);
        let agent_a = handle.principal_id;
        let agent_b = Uuid::new_v4();
        let source = identity(IngestSourceKind::EmailMessage, "mail-1", Some("v1"));

        let first = stored(
            put(&handle, agent_a, &source, "k-first", "original body"),
            "first put",
        );
        assert_eq!(first.dedupe, Dedupe::New);
        let original = stored_bytes(&mut handle);
        let expected = (
            payload_sha256(b"original body").as_bytes().to_vec(),
            payload_sha256(b"original body").as_bytes().to_vec(),
            serde_json::json!({ "content": "original body" }),
        );
        assert_eq!(original, vec![expected.clone()]);
        let before = counts(&mut handle);
        assert_eq!(before, [1, 1, 1, 1, 1, 1, 3]);

        for (agent, key) in [(agent_b, "k-other-agent"), (agent_a, "k-same-agent")] {
            let conflict = put(&handle, agent, &source, key, "edited body");
            assert_eq!(
                conflict.as_ref().err(),
                Some(&SourcedPutError {
                    code: ErrorCode::Conflict,
                    conflict_reason: Some(ConflictReason::SOURCE_VERSION_CONFLICT),
                }),
                "{key}: {conflict:?}"
            );
            assert_eq!(
                conflict
                    .err()
                    .and_then(|e| e.conflict_reason)
                    .map(ConflictReason::code),
                Some(1301),
                "{key}: the D-B numeric code"
            );
            assert_eq!(
                counts(&mut handle),
                before,
                "{key}: a conflict writes nothing"
            );
            assert_eq!(
                stored_bytes(&mut handle),
                vec![expected.clone()],
                "{key}: the original bytes are untouched"
            );
        }

        let again = stored(
            put(&handle, agent_b, &source, "k-again", "original body"),
            "same bytes",
        );
        assert_eq!(again.dedupe, Dedupe::Existing);
        assert_eq!(again.accepted.evidence_id, first.accepted.evidence_id);
        assert_eq!(delta(counts(&mut handle), before), [0, 0, 0, 0, 1, 1, 3]);

        let v2 = identity(IngestSourceKind::EmailMessage, "mail-1", Some("v2"));
        let edited = stored(
            put(&handle, agent_a, &v2, "k-v2", "edited body"),
            "new version",
        );
        assert_eq!(edited.dedupe, Dedupe::New);
        assert_ne!(edited.accepted.evidence_id, first.accepted.evidence_id);
        let all = stored_bytes(&mut handle);
        assert_eq!(all.len(), 2);
        assert_eq!(
            all.iter().filter(|stored| **stored == expected).count(),
            1,
            "the first message is still byte-identical"
        );
    });
}

/// G-M06-3 (ADR-0098 D1): a sourced put queues on the identity's advisory lock. An owner transaction holds the lock key
/// of the identity; the put's backend must reach `Lock/advisory` and stay there until the holder commits, then store.
/// The key text mirrors `source_lock_key` in `operation_receipt.rs`: the principal is not part of it, so one agent's put
/// queues behind any other holder of the identity.
#[test]
fn sourced_put_waits_on_identity_lock() {
    run_db_fixture::<Fixture, _>("sourced_put_waits_on_identity_lock", |mut handle| {
        handle.seed_current_entitlement_and_window(10);
        let agent = handle.principal_id;
        let source = identity(IngestSourceKind::EmailMessage, "mail-lock", Some("v1"));
        let lock_text = format!(
            "evidence-source:{}:{}:{}:{}:{}",
            handle.tenant_id,
            handle.user_id,
            source.kind().db_code(),
            hex::encode(source.object_key_d16().as_bytes()),
            source.version()
        );
        let dsn = handle.gateway_application_dsn("evidence-sources-lock");
        let auth = auth_for(&handle, agent);
        let put_request = request(&handle, agent, "k-lock", "locked body");
        let before = counts(&mut handle);

        let mut handle = RollbackOnPanic(&mut handle);
        handle
            .admin
            .batch_execute("BEGIN")
            .expect("owner opens a transaction");
        handle
            .admin
            .execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                &[&lock_text],
            )
            .expect("owner takes the identity lock");

        let putter = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("runtime");
            // dep: PostgreSQL(role_gateway) — RuntimeDbPool under test.
            let pool = rt
                .block_on(RuntimeDbPool::connect(&dsn))
                .expect("agent connection");
            rt.block_on(operation_receipt::remember_sourced_atomically(
                &pool,
                &auth,
                put_request,
                &source,
            ))
        });

        // (ungranted advisory requests on exactly this key, of which those the backend reports as `Lock/advisory`,
        // and the wait events seen for diagnostics)
        let waiting = |handle: &mut Handle| -> (i64, i64, String) {
            let row = handle
                .admin
                .query_one(
                    "SELECT count(*), \
                            count(*) FILTER (WHERE a.wait_event_type = 'Lock' AND a.wait_event = 'advisory'), \
                            coalesce(string_agg(coalesce(a.wait_event_type, 'NULL') || '/' || coalesce(a.wait_event, 'NULL'), ','), '') \
                       FROM pg_locks l LEFT JOIN pg_stat_activity a ON a.pid = l.pid \
                      WHERE l.locktype = 'advisory' AND NOT l.granted \
                        AND ((l.classid::bigint << 32) | l.objid::bigint) = hashtextextended($1,0)",
                    &[&lock_text],
                )
                .expect("pg_locks / pg_stat_activity");
            (row.get(0), row.get(1), row.get(2))
        };
        let mut seen = (0, 0, String::new());
        for _ in 0..50 {
            seen = waiting(&mut handle);
            if seen.0 == 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(
            seen,
            (1, 1, "Lock/advisory".to_string()),
            "the put's backend is waiting on the identity's advisory lock (finished: {})",
            putter.is_finished()
        );
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            waiting(&mut handle),
            (1, 1, "Lock/advisory".to_string()),
            "the put is still waiting"
        );
        assert!(
            !putter.is_finished(),
            "the put has not completed while the lock is held"
        );
        assert_eq!(
            counts(&mut handle),
            before,
            "a waiting put has written nothing"
        );

        handle
            .admin
            .batch_execute("COMMIT")
            .expect("owner releases the lock");
        let stored = stored(putter.join().expect("put thread"), "put after release");
        assert_eq!(stored.dedupe, Dedupe::New);
        assert_eq!(delta(counts(&mut handle), before), [1, 1, 1, 1, 1, 1, 3]);
    });
}

/// §79.2: unwinding releases the identity lock while the owner's connection remains alive for cleanup.
#[test]
fn identity_lock_guard_rolls_back_on_panic() {
    run_db_fixture::<Fixture, _>("identity_lock_guard_rolls_back_on_panic", |mut handle| {
        let mut observer = handle.owner_client().expect("fresh owner connection");
        let lock_text = format!("evidence-source:panic:{}", handle.tenant_id);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let rollback = RollbackOnPanic(&mut handle);
            rollback
                .0
                .admin
                .batch_execute("BEGIN")
                .expect("owner transaction");
            rollback
                .0
                .admin
                .execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                    &[&lock_text],
                )
                .expect("owner takes the identity lock");
            panic!("deliberate panic after taking the identity lock");
        }));
        assert!(panic.is_err(), "the lock holder panicked");
        let free: bool = observer
            .query_one(
                "SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))",
                &[&lock_text],
            )
            .expect("fresh connection probes the identity lock")
            .get(0);
        assert!(
            free,
            "unwinding released the identity lock before fixture cleanup"
        );
    });
}

//! `adapters::tests::forget_confirm` — ADR-0092 D-B/D-C round-2 atomicity and scope isolation, on disposable PG.
//! Depends-on: crates=[humaux-adapters, humaux-application, humaux-domain, humaux-projection, humaux-retrieval, humaux-testkit, postgres, serde_json, sqlx]; services=[PostgreSQL(owner) r=[ops.commit_seq_seq] w=[control.confirm_tokens, control.deletion_requests, control.deletion_targets, ops.deletion_plan_steps, ops.memory_lifecycle_events, ops.outbox, private.memory_evidence, private.memory_records, projection.embedding_fingerprints, projection.rebuild_runs, projection.rebuild_tickets, projection.stream_checkpoints, projection.stream_log], PostgreSQL(role_gateway), PostgreSQL(role_maintenance)]; env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::forget_repo, adapters::confirm_token_repo, adapters::context_repo, adapters::grep_repo, adapters::read_gate, adapters::read_materialize, adapters::exact_census, adapters::tests::support::operation_receipt_fixture, application::forget, domain::confirm, domain::authority, domain::context, domain::error, domain::identity, domain::ids, humaux-testkit, projection::serving, projection::stream, retrieval::predicate_registry, testkit::disposable]
//! Called-by: [cargo-test]
//! Invariants: [refusals leave token/request/lifecycle/stream state unchanged; every read uses role_gateway; exact ids and counts; fixture writes require disposable PG]
//! Spec: Baseline §37.2; §33.10 rule 9; §41.2; §78.2; ADR-0092 D-B/D-C; G-M19-2; G-M19-3; G-M19-17; G-DOC-13

use humaux_adapters::{
    confirm_token_repo::ConfirmationClaim,
    context_repo::assemble_materialized,
    forget_repo::{self, ForgetRepoError, FrozenDeletion},
    grep_repo::{GrepQuery, grep},
    read_gate::{
        MemoryEnumerationParams, NoteEnumerationFilter, materialize_memory_enumeration,
        materialize_memory_enumeration_filtered, materialize_memory_get,
    },
    read_materialize::{Lifecycle, MaterializedItem, materialize_final_bodies},
};
use humaux_application::forget::{DeletionScopeKind, confirmation_digest};
use humaux_domain::{
    authority::MemoryId,
    confirm::{ConfirmToken, DestructiveOp},
    context::ContextBudget,
    error::ErrorCode,
    identity::{AuthorizationScope, BoundedSet, PrincipalId},
    ids::{Scope, TenantId, UserId, WorkspaceId},
};
use humaux_projection::{serving::StreamFamily, stream::StreamKey};
use humaux_testkit::disposable::require_disposable;
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use serde_json::json;
use sqlx::Connection;
use sqlx::types::Uuid;
use std::collections::BTreeSet;
use std::time::Duration;

#[allow(dead_code)]
#[path = "support/operation_receipt_fixture.rs"]
mod operation_receipt_fixture;
use operation_receipt_fixture::{
    DOMAIN, Handle, PROJECTION_KIND, PROJECTION_VERSION, SyntheticCredentialScopes,
};
const TOKEN: &str = "m19confirmtoken";
const MAC_KEY: &[u8] = b"synthetic-m19-confirm-fixture-key";

struct Fixture;
struct TestHandle(Handle);
impl std::ops::Deref for TestHandle {
    type Target = Handle;
    fn deref(&self) -> &Handle {
        &self.0
    }
}
impl std::ops::DerefMut for TestHandle {
    fn deref_mut(&mut self) -> &mut Handle {
        &mut self.0
    }
}
impl DbIntegrationFixture for Fixture {
    type Handle = TestHandle;
    fn isolate() -> Result<TestHandle, DbFixtureSkipReason> {
        let dsn =
            std::env::var("HUMAUX_TEST_PG_DSN").map_err(|_| DbFixtureSkipReason::NoDatabaseUrl)?;
        // dep: PostgreSQL(owner) — §37 disposable database guard before fixture writes
        let mut client = postgres::Client::connect(&dsn, postgres::NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        require_disposable(&mut client).unwrap_or_else(|e| panic!("{e}"));
        let mut handle = operation_receipt_fixture::Fixture::isolate()?;
        let key_hash = [*Uuid::new_v4().as_bytes(), *Uuid::new_v4().as_bytes()].concat();
        let credential = handle.seed_synthetic_service_credential(
            SyntheticCredentialScopes::RememberWrite,
            &Uuid::new_v4().to_string(),
            "m19-confirm-fixture-only",
            &key_hash,
        );
        handle.principal_id = credential.api_key_id;
        handle.auth = AuthorizationScope::new(
            TenantId(handle.tenant_id),
            PrincipalId(credential.api_key_id),
            Some(UserId(handle.user_id)),
            BoundedSet::new([WorkspaceId(handle.workspace_id)]).expect("one fixture workspace"),
        );
        Ok(TestHandle(handle))
    }
}
impl Drop for TestHandle {
    fn drop(&mut self) {
        let tenant = self.0.tenant_id;
        for sql in [
            "DELETE FROM projection.rebuild_tickets WHERE tenant_id=$1",
            "DELETE FROM projection.rebuild_runs WHERE tenant_id=$1",
            "DELETE FROM ops.deletion_plan_steps WHERE tenant_id=$1",
            "DELETE FROM control.deletion_targets WHERE tenant_id=$1",
            "DELETE FROM control.deletion_requests WHERE tenant_id=$1",
            "DELETE FROM control.confirm_tokens WHERE tenant_id=$1",
            "DELETE FROM ops.memory_lifecycle_events WHERE tenant_id=$1",
        ] {
            self.0
                .admin
                .execute(sql, &[&tenant])
                .expect("cleanup own deletion fixture rows");
        }
        self.0
            .admin
            .execute(
                "DELETE FROM projection.embedding_fingerprints WHERE embedding_version=$1",
                &[&tenant.to_string()],
            )
            .expect("cleanup fingerprint");
    }
}

/// What one op returned for the two seeded memories.
#[derive(Default)]
struct Seen {
    /// Memories the op admitted.
    ids: BTreeSet<Uuid>,
    /// Every count the op reported about its result, by name.
    counts: Vec<(&'static str, u64)>,
    /// Everything the op returned that could carry a body, id or snippet.
    text: String,
    /// `memory.get` only: the code of each id it refused.
    refused: Vec<(Uuid, ErrorCode)>,
}

impl Seen {
    fn absorb(&mut self, items: &[MaterializedItem]) {
        for item in items {
            if let MaterializedItem::Memory { memory_id, .. } = item {
                self.ids.insert(*memory_id);
            }
        }
        self.text.push_str(&format!("{items:?}"));
    }

    fn count(&mut self, name: &'static str, value: i64) {
        self.counts.push((
            name,
            u64::try_from(value).expect("a count is never negative"),
        ));
    }
}

struct World {
    /// Two readable backing Evidence rows.
    ctrl: Uuid,
    /// Two backing Evidence rows, the second unreadable to the caller until flipped.
    gated: Uuid,
    scope: Scope,
    family: StreamFamily,
    key: StreamKey,
}

type Op = fn(&World, &Handle) -> Seen;

const OPS: [(&str, Op); 7] = [
    ("memory.get", op_get),
    ("memory.enumerate", op_enumerate),
    ("memory.grep", op_grep),
    ("recall materialize", op_recall_materialize),
    ("context.assemble", op_context),
    ("enumerate history", op_history),
    ("EXACT ids", op_exact),
];

fn op_get(world: &World, handle: &Handle) -> Seen {
    let mut seen = Seen::default();
    for id in [world.ctrl, world.gated] {
        match handle.rt.block_on(materialize_memory_get(
            &handle.runtime,
            &handle.auth,
            &world.scope,
            &world.family,
            &world.key,
            MemoryId(id),
        )) {
            Ok(memory) => seen.absorb(&memory.bodies.items),
            Err(code) => seen.refused.push((id, code)),
        }
    }
    seen
}

fn op_enumerate(world: &World, handle: &Handle) -> Seen {
    let page = handle
        .rt
        .block_on(materialize_memory_enumeration(
            &handle.runtime,
            &handle.auth,
            &world.scope,
            &world.family,
            &world.key,
            MemoryEnumerationParams {
                cursor: None,
                page_size: 100,
                ttl: Duration::from_secs(60),
                manifest_cap: 1000,
                mac_key: MAC_KEY,
                subject_id: None,
            },
        ))
        .expect("enumerate succeeds for the caller's own workspace");
    let mut seen = Seen::default();
    seen.absorb(&page.memory.bodies.items);
    let total = page
        .census
        .as_ref()
        .expect("enumeration census")
        .census
        .enumeration()
        .expect("exact enumeration")
        .total();
    seen.counts.push(("census total", total));
    seen
}

fn op_grep(_world: &World, handle: &Handle) -> Seen {
    let query = GrepQuery::new(TOKEN, Lifecycle::CURRENT, 100, None, None).expect("grep query");
    let page = handle
        .rt
        .block_on(grep(
            &handle.runtime,
            &handle.auth,
            WorkspaceId(handle.workspace_id),
            &query,
        ))
        .expect("grep succeeds for the caller's own workspace");
    let mut seen = Seen::default();
    for hit in &page.items {
        seen.ids.insert(hit.memory_id);
        seen.text.push_str(&format!("{hit:?}"));
    }
    seen.count("matching lines", page.total_matching_lines);
    seen.count("matching memories", page.total_memories);
    seen
}

fn op_recall_materialize(world: &World, handle: &Handle) -> Seen {
    let bodies = handle
        .rt
        .block_on(materialize_final_bodies(
            &handle.runtime,
            &handle.auth,
            &world.family,
            &world.key,
            &[world.ctrl, world.gated],
            &[],
        ))
        .expect("final bodies");
    let mut seen = Seen::default();
    seen.absorb(&bodies.items);
    seen
}

fn op_context(world: &World, handle: &Handle) -> Seen {
    let context = handle
        .rt
        .block_on(assemble_materialized(
            &handle.runtime,
            &handle.auth,
            &world.scope,
            ContextBudget::new(2_048, 1_024).expect("budget"),
            &world.family,
            &world.key,
        ))
        .expect("context assembles for the caller's own workspace");
    let mut seen = Seen::default();
    seen.absorb(&context.bodies.items);
    for item in context
        .handoff
        .mandatory
        .iter()
        .chain(&context.handoff.pinned)
    {
        seen.ids
            .insert(Uuid::parse_str(&item.memory_id).expect("handoff memory id"));
    }
    seen.counts.push((
        "mandatory expected",
        context.handoff.counts.mandatory_expected,
    ));
    seen.counts.push((
        "mandatory returned",
        context.handoff.counts.mandatory_returned,
    ));
    seen.counts.push((
        "mandatory missing",
        context.handoff.counts.mandatory_missing,
    ));
    seen.text
        .push_str(&serde_json::to_string(&context.handoff).expect("handoff serializes"));
    seen
}

fn op_history(world: &World, handle: &Handle) -> Seen {
    let notes = NoteEnumerationFilter {
        lifecycle: Lifecycle::for_enumerate(Some(&["active", "superseded"]), Some("include"))
            .expect("history"),
        ..NoteEnumerationFilter::default()
    };
    let page = handle
        .rt
        .block_on(materialize_memory_enumeration_filtered(
            &handle.runtime,
            &handle.auth,
            &world.scope,
            &world.family,
            &world.key,
            MemoryEnumerationParams {
                cursor: None,
                page_size: 100,
                ttl: Duration::from_secs(60),
                manifest_cap: 1000,
                mac_key: MAC_KEY,
                subject_id: None,
            },
            &notes,
        ))
        .expect("history enumeration");
    let mut seen = Seen::default();
    seen.absorb(&page.memory.bodies.items);
    seen.counts.push((
        "history census",
        page.census
            .expect("census")
            .census
            .enumeration()
            .expect("exact")
            .total(),
    ));
    seen
}

fn op_exact(world: &World, handle: &Handle) -> Seen {
    use humaux_retrieval::predicate_registry::{PredicateRow, load_registry};
    let entries = load_registry(vec![PredicateRow {
        predicate_id: "m19-fixture".into(),
        sql_predicate: "TRUE".into(),
        required_columns: vec!["memory_id".into()],
        enumerable_scope:
            "private.memory_records WHERE tenant_id = $1 AND visibility_workspace_id = $2".into(),
        surface_patterns: vec!["m19-fixture".into()],
        owner_module: "M19".into(),
    }])
    .expect("registry");
    assert_eq!(entries.len(), 1);
    let out = handle
        .rt
        .block_on(humaux_adapters::exact_census::exact_enumerate(
            &handle.runtime,
            &entries[0],
            &handle.auth,
            WorkspaceId(handle.workspace_id),
            &world.key,
        ))
        .expect("EXACT census");
    Seen {
        ids: out.returned_ids.into_iter().collect(),
        ..Seen::default()
    }
}

fn seed(handle: &mut Handle) -> World {
    let tenant = handle.tenant_id;
    let ws = handle.workspace_id;
    handle.admin.execute(
        "INSERT INTO projection.stream_checkpoints (tenant_id,scope_kind,scope_id,domain,projection_kind,projection_version,serving) VALUES ($1,'workspace',$2,$3,$4,$5,false)",
        &[&tenant,&ws,&DOMAIN,&PROJECTION_KIND,&PROJECTION_VERSION],
    ).expect("checkpoint");
    let content = json!({"title": "M19 confirmation fixture", "key_claim": TOKEN});
    let ctrl = handle.seed_workspace_visible_context_record_with_content(&content);
    let gated = handle.seed_workspace_visible_context_record_with_content(&content);
    let family = StreamFamily::new(TenantId(tenant), "workspace", ws, DOMAIN, PROJECTION_KIND);
    World {
        ctrl: ctrl.memory_id,
        gated: gated.memory_id,
        scope: Scope {
            tenant_id: TenantId(tenant),
            user_id: Some(UserId(handle.user_id)),
            workspace_id: Some(WorkspaceId(ws)),
            repository_id: None,
            task_id: None,
            run_id: None,
            agent_id: None,
        },
        key: family.with_version(PROJECTION_VERSION),
        family,
    }
}

fn primary(h: &mut Handle, memory: Uuid) -> Uuid {
    h.admin
        .query_one(
            "SELECT evidence_id FROM private.memory_evidence WHERE memory_id=$1 AND role='PRIMARY'",
            &[&memory],
        )
        .expect("primary")
        .get(0)
}

fn check(world: &World, handle: &Handle, expected: BTreeSet<Uuid>) {
    for (name, op) in OPS {
        let seen = op(world, handle);
        assert_eq!(seen.ids, expected, "{name}");
        for (count, value) in seen.counts {
            let want = if count == "mandatory missing" {
                0
            } else {
                expected.len() as u64
            };
            assert_eq!(value, want, "{name}: {count}");
        }
        if name == "memory.get" {
            let absent: Vec<_> = [world.ctrl, world.gated]
                .into_iter()
                .filter(|id| !expected.contains(id))
                .map(|id| (id, ErrorCode::NotFound))
                .collect();
            assert_eq!(seen.refused, absent);
        }
    }
}

fn freeze(h: &Handle, root: Uuid, evidence: bool) -> FrozenDeletion {
    h.rt.block_on(async {
        // dep: PostgreSQL(role_gateway) — §33.10 caller transaction with session authorization
        let mut connection =
            sqlx::PgConnection::connect(&h.gateway_application_dsn("forget_confirm"))
                .await
                .expect("gateway connection");
        let mut txn = connection.begin().await.expect("begin");
        let frozen = if evidence {
            forget_repo::freeze_evidence_closure_in_txn(&mut txn, &h.auth, &[root]).await
        } else {
            forget_repo::freeze_memory_in_txn(&mut txn, &h.auth, root).await
        }
        .expect("freeze");
        txn.commit().await.expect("commit freeze");
        frozen
    })
}

fn token(
    h: &mut Handle,
    request: &FrozenDeletion,
    scope: DeletionScopeKind,
    manifest: [u8; 32],
) -> ConfirmationClaim {
    let mut nonce = [0u8; 32];
    nonce[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    let digest = ConfirmToken::from_bytes(nonce).sha256();
    let intent = confirmation_digest(scope, &manifest);
    h.admin.execute(
        "INSERT INTO control.confirm_tokens (tenant_id,user_id,operation,target_id,nonce_sha256,expires_at,workspace_id,request_sha256) VALUES ($1,$2,'memory.forget',$3,$4,clock_timestamp()+interval '1 hour',$5,$6)",
        &[&h.tenant_id,&h.user_id,&request.request_id,&&digest[..],&h.workspace_id,&&intent[..]],
    ).expect("seed a round-one token");
    ConfirmationClaim {
        op: DestructiveOp::MemoryForget,
        target_id: request.request_id,
        successor_id: None,
        nonce_sha256: digest,
        request_sha256: Some(intent),
    }
}

fn accept(
    h: &Handle,
    request: &FrozenDeletion,
    claim: Option<&ConfirmationClaim>,
) -> Result<(), ForgetRepoError> {
    h.rt.block_on(async {
        // dep: PostgreSQL(role_gateway) — §33.10 caller transaction with session authorization
        let mut connection =
            sqlx::PgConnection::connect(&h.gateway_application_dsn("forget_confirm"))
                .await
                .expect("gateway connection");
        let mut txn = connection.begin().await.expect("begin");
        let result = forget_repo::accept_in_txn(&mut txn, &h.auth, request.request_id, claim).await;
        if result.is_ok() {
            txn.commit().await.expect("commit accept");
        } else {
            txn.rollback().await.expect("rollback refusal");
        }
        result
    })
}

fn footprint(h: &mut Handle) -> (i64, i64, i64, i64, i64) {
    let row = h.admin.query_one(
        "SELECT (SELECT count(*) FROM control.confirm_tokens WHERE tenant_id=$1 AND consumed_at IS NOT NULL), (SELECT count(*) FROM control.deletion_requests WHERE tenant_id=$1 AND logical_deleted_at IS NOT NULL), (SELECT count(*) FROM ops.memory_lifecycle_events WHERE tenant_id=$1), (SELECT count(*) FROM private.memory_records WHERE tenant_id=$1 AND status='revoked'), (SELECT count(*) FROM projection.stream_log WHERE tenant_id=$1 AND state='TOMBSTONED')",
        &[&h.tenant_id],
    ).expect("write footprint");
    (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4))
}

#[test]
fn g_m19_2_refusals_write_nothing() {
    run_db_fixture::<Fixture, _>("g_m19_2_refusals_write_nothing", |mut h| {
        let world = seed(&mut h);
        let request = freeze(&h, world.gated, false);
        let before = footprint(&mut h);
        assert_eq!(before, (0, 0, 0, 0, 0));
        assert!(matches!(
            accept(&h, &request, None),
            Err(ForgetRepoError::Refused {
                code: ErrorCode::Conflict,
                reason: "confirmation_required"
            })
        ));
        assert_eq!(footprint(&mut h), before);
        for (scope, manifest) in [
            (DeletionScopeKind::Memory, [7u8; 32]),
            (DeletionScopeKind::EvidenceClosure, request.manifest_hash),
        ] {
            let bad = token(&mut h, &request, scope, manifest);
            assert!(matches!(
                accept(&h, &request, Some(&bad)),
                Err(ForgetRepoError::Refused {
                    code: ErrorCode::Conflict,
                    reason: "confirmation_binding"
                })
            ));
            assert_eq!(footprint(&mut h), before);
        }
    });
}

#[test]
fn g_m19_2_closure_grew_is_refused_before_writes() {
    run_db_fixture::<Fixture, _>("g_m19_2_closure_grew_is_refused_before_writes", |mut h| {
        let world = seed(&mut h);
        let root = primary(&mut h, world.gated);
        let request = freeze(&h, root, true);
        let claim = token(
            &mut h,
            &request,
            DeletionScopeKind::EvidenceClosure,
            request.manifest_hash,
        );
        h.admin.execute("INSERT INTO private.memory_evidence (memory_id,evidence_id,role,grounding_mode) VALUES ($1,$2,'SUPPORTING','SNAPSHOT')", &[&world.ctrl,&root]).expect("closure grows");
        assert!(matches!(
            accept(&h, &request, Some(&claim)),
            Err(ForgetRepoError::Refused {
                code: ErrorCode::Conflict,
                reason: "manifest_changed"
            })
        ));
        assert_eq!(footprint(&mut h), (0, 0, 0, 0, 0));
        check(&world, &h, BTreeSet::from([world.ctrl, world.gated]));
    });
}

#[test]
fn g_m19_3_memory_forget_keeps_shared_evidence_survivor() {
    run_db_fixture::<Fixture, _>(
        "g_m19_3_memory_forget_keeps_shared_evidence_survivor",
        |mut h| {
            let world = seed(&mut h);
            let shared = primary(&mut h, world.ctrl);
            h.admin.execute("UPDATE private.memory_evidence SET evidence_id=$2 WHERE memory_id=$1 AND role='PRIMARY'", &[&world.gated,&shared]).expect("shared Evidence");
            check(&world, &h, BTreeSet::from([world.ctrl, world.gated]));
            let request = freeze(&h, world.gated, false);
            let claim = token(
                &mut h,
                &request,
                DeletionScopeKind::Memory,
                request.manifest_hash,
            );
            accept(&h, &request, Some(&claim)).expect("MEMORY accept");
            check(&world, &h, BTreeSet::from([world.ctrl]));
            assert_eq!(footprint(&mut h), (1, 1, 1, 1, 0));
            let tenant = h.tenant_id;
            let events: Vec<(Uuid,String,String)> = h.admin.query("SELECT memory_id,op,reason_code FROM ops.memory_lifecycle_events WHERE tenant_id=$1", &[&tenant]).expect("events").iter().map(|r|(r.get(0),r.get(1),r.get(2))).collect();
            assert_eq!(
                events,
                vec![(world.gated, "TOMBSTONE".into(), "USER_DELETE".into())]
            );
            assert!(accept(&h, &request, Some(&claim)).is_err());
            assert_eq!(footprint(&mut h), (1, 1, 1, 1, 0));
        },
    );
}
fn seed_ticket(h: &mut Handle, evidence: Uuid, seq: i64, event: &str) -> i64 {
    let commit: i64 = h
        .admin
        .query_one("SELECT nextval('ops.commit_seq_seq')", &[])
        .expect("commit sequence")
        .get(0);
    h.admin.execute(
        "INSERT INTO projection.stream_log (tenant_id,scope_kind,scope_id,domain,projection_kind,projection_version,stream_seq,commit_seq,state,settled_at) VALUES ($1,'workspace',$2,$3,$4,$5,$6,$7,'DONE',now())",
        &[&h.tenant_id,&h.workspace_id,&DOMAIN,&PROJECTION_KIND,&PROJECTION_VERSION,&seq,&commit],
    ).expect("seed original ticket");
    h.admin.execute("INSERT INTO ops.outbox (tenant_id,commit_seq,stream_seq,event_type,evidence_id,status) VALUES ($1,$2,$3,$4,$5,'DONE')", &[&h.tenant_id,&commit,&seq,&event,&evidence]).expect("seed outbox");
    h.admin.execute("UPDATE projection.stream_checkpoints SET issued_highwater=$3 WHERE tenant_id=$1 AND scope_id=$2", &[&h.tenant_id,&h.workspace_id,&seq]).expect("highwater");
    commit
}

fn seed_generation(h: &mut Handle, commit: i64) {
    let version = h.tenant_id.to_string();
    let fingerprint: Vec<u8> = h
        .admin
        .query_one("SELECT sha256(uuid_send($1::uuid))", &[&h.tenant_id])
        .expect("fingerprint")
        .get(0);
    h.admin.execute(
        "INSERT INTO projection.embedding_fingerprints (fingerprint_sha256,embedding_version,provider,model_id,model_revision,dimension,task_type,preprocessing_version,projection_contract_version,dtype,normalization,distance) VALUES ($1,$2,'fixture','fixture','fixture',4,'document','fixture','fixture','float32','l2','Cosine')",
        &[&fingerprint,&version],
    ).expect("fingerprint row");
    let run: Uuid = h.admin.query_one(
        "INSERT INTO projection.rebuild_runs (tenant_id,scope_kind,scope_id,domain,projection_kind,projection_version,generation,fingerprint_sha256,boundary_seq) VALUES ($1,'workspace',$2,$3,$4,$5,2,$6,3) RETURNING run_id",
        &[&h.tenant_id,&h.workspace_id,&DOMAIN,&PROJECTION_KIND,&PROJECTION_VERSION,&fingerprint],
    ).expect("generation run").get(0);
    h.admin.execute(
        "INSERT INTO projection.stream_log (tenant_id,scope_kind,scope_id,domain,projection_kind,projection_version,stream_seq,commit_seq,state) VALUES ($1,'workspace',$2,$3,$4,$5,4,$6,'ISSUED')",
        &[&h.tenant_id,&h.workspace_id,&DOMAIN,&PROJECTION_KIND,&PROJECTION_VERSION,&commit],
    ).expect("generation ticket");
    h.admin.execute(
        "INSERT INTO projection.rebuild_tickets (tenant_id,scope_kind,scope_id,domain,projection_kind,projection_version,stream_seq,generation,commit_seq,run_id) VALUES ($1,'workspace',$2,$3,$4,$5,4,2,$6,$7)",
        &[&h.tenant_id,&h.workspace_id,&DOMAIN,&PROJECTION_KIND,&PROJECTION_VERSION,&commit,&run],
    ).expect("ticket attribution");
    h.admin.execute("UPDATE projection.stream_checkpoints SET issued_highwater=4 WHERE tenant_id=$1 AND scope_id=$2", &[&h.tenant_id,&h.workspace_id]).expect("highwater");
}

#[test]
fn g_doc_13_supporting_evidence_accept_tombstones_generation_and_keeps_primary_survivor() {
    run_db_fixture::<Fixture, _>(
        "g_doc_13_supporting_evidence_accept_tombstones_generation_and_keeps_primary_survivor",
        |mut h| {
            let world = seed(&mut h);
            let x = primary(&mut h, world.ctrl);
            let r = primary(&mut h, world.gated);
            h.admin.execute("UPDATE private.memory_evidence SET evidence_id=$2 WHERE memory_id=$1 AND role='PRIMARY'", &[&world.gated,&x]).expect("M PRIMARY X");
            h.admin.execute("INSERT INTO private.memory_evidence (memory_id,evidence_id,role,grounding_mode) VALUES ($1,$2,'SUPPORTING','SNAPSHOT')", &[&world.gated,&r]).expect("M SUPPORTING R");
            seed_ticket(&mut h, x, 1, "EVIDENCE_ACCEPTED");
            let commit = seed_ticket(&mut h, r, 2, "EVIDENCE_ACCEPTED");
            seed_ticket(&mut h, r, 3, "MEMORY_LIFECYCLE");
            seed_generation(&mut h, commit);
            check(&world, &h, BTreeSet::from([world.ctrl, world.gated]));
            let request = freeze(&h, r, true);
            assert_eq!(request.targets.len(), 2);
            assert_eq!(
                request.targets.iter().copied().collect::<BTreeSet<_>>(),
                BTreeSet::from([
                    humaux_application::forget::DeletionTarget {
                        kind: humaux_application::forget::DeletionTargetKind::Evidence,
                        id: r
                    },
                    humaux_application::forget::DeletionTarget {
                        kind: humaux_application::forget::DeletionTargetKind::Memory,
                        id: world.gated
                    },
                ])
            );
            let claim = token(
                &mut h,
                &request,
                DeletionScopeKind::EvidenceClosure,
                request.manifest_hash,
            );
            accept(&h, &request, Some(&claim))
                .expect("EVIDENCE_CLOSURE accept must pass the 0278 owner arm, not SQLSTATE 23514");
            check(&world, &h, BTreeSet::from([world.ctrl]));
            assert_eq!(footprint(&mut h), (1, 1, 1, 1, 3));
            let tenant = h.tenant_id;
            let states: Vec<(i64,String)> = h.admin.query("SELECT stream_seq,state FROM projection.stream_log WHERE tenant_id=$1 ORDER BY stream_seq", &[&tenant]).expect("states").iter().map(|r|(r.get(0),r.get(1))).collect();
            assert_eq!(
                states,
                vec![
                    (1, "DONE".into()),
                    (2, "TOMBSTONED".into()),
                    (3, "TOMBSTONED".into()),
                    (4, "TOMBSTONED".into())
                ]
            );
        },
    );
}

#[test]
fn owner_arm_keeps_gateway_update_refused_and_maintenance_tombstone_working() {
    run_db_fixture::<Fixture, _>(
        "owner_arm_keeps_gateway_update_refused_and_maintenance_tombstone_working",
        |mut h| {
            let world = seed(&mut h);
            let root = primary(&mut h, world.ctrl);
            seed_ticket(&mut h, root, 1, "EVIDENCE_ACCEPTED");
            h.rt.block_on(async {
                // dep: PostgreSQL(role_gateway) — §33.10 caller transaction with session authorization
                let mut connection =
                    sqlx::PgConnection::connect(&h.gateway_application_dsn("forget_confirm"))
                        .await
                        .expect("gateway connection");
                let mut txn = connection.begin().await.expect("begin");
                sqlx::query("SELECT set_config('humaux.tenant_id',$1,true)")
                    .bind(h.tenant_id.to_string())
                    .execute(&mut *txn)
                    .await
                    .expect("tenant");
                let error = sqlx::query(
                    "UPDATE projection.stream_log SET state='TOMBSTONED' WHERE tenant_id=$1",
                )
                .bind(h.tenant_id)
                .execute(&mut *txn)
                .await
                .expect_err("gateway direct UPDATE refused");
                assert_eq!(
                    error
                        .as_database_error()
                        .expect("database error")
                        .code()
                        .as_deref(),
                    Some("42501")
                );
                txn.rollback().await.expect("rollback");
            });
            assert!(
                h.rt.block_on(forget_repo::tombstone(&h.maintenance, &world.key, 1))
                    .expect("maintenance path")
            );
            assert_eq!(footprint(&mut h), (0, 0, 0, 0, 1));
        },
    );
}

#[test]
fn superseded_target_is_revoked_without_mutating_successor() {
    run_db_fixture::<Fixture, _>(
        "superseded_target_is_revoked_without_mutating_successor",
        |mut h| {
            let world = seed(&mut h);
            let request = freeze(&h, world.gated, false);
            let claim = token(
                &mut h,
                &request,
                DeletionScopeKind::Memory,
                request.manifest_hash,
            );
            h.admin.execute("UPDATE private.memory_records SET status='superseded',superseded_by=$2 WHERE memory_id=$1", &[&world.gated,&world.ctrl]).expect("superseded target");
            let before: serde_json::Value = h
                .admin
                .query_one(
                    "SELECT to_jsonb(m) FROM private.memory_records m WHERE memory_id=$1",
                    &[&world.ctrl],
                )
                .expect("successor before")
                .get(0);
            accept(&h, &request, Some(&claim)).expect("superseded accept");
            let after: serde_json::Value = h
                .admin
                .query_one(
                    "SELECT to_jsonb(m) FROM private.memory_records m WHERE memory_id=$1",
                    &[&world.ctrl],
                )
                .expect("successor after")
                .get(0);
            assert_eq!(after, before);
            let row = h
                .admin
                .query_one(
                    "SELECT status,superseded_by FROM private.memory_records WHERE memory_id=$1",
                    &[&world.gated],
                )
                .expect("target");
            assert_eq!(
                (row.get::<_, String>(0), row.get::<_, Option<Uuid>>(1)),
                ("revoked".into(), None)
            );
            assert_eq!(footprint(&mut h), (1, 1, 1, 1, 0));
            check(&world, &h, BTreeSet::from([world.ctrl]));
        },
    );
}

#[test]
fn g_m19_17_confirmation_operations_match_rust_db_check_and_catalog_exactly() {
    run_db_fixture::<Fixture, _>(
        "g_m19_17_confirmation_operations_match_rust_db_check_and_catalog_exactly",
        |mut h| {
            let rust: BTreeSet<_> = DestructiveOp::ALL
                .iter()
                .map(|op| op.operation_key().to_owned())
                .collect();
            assert_eq!(DestructiveOp::ALL.len(), 14);
            assert_eq!(rust.len(), 14);
            let rows = h.admin.query("SELECT (regexp_matches(pg_get_constraintdef(oid), '''([^'']+)''', 'g'))[1] FROM pg_constraint WHERE conrelid='control.confirm_tokens'::regclass AND conname='confirm_tokens_operation_closed_set'", &[]).expect("closed CHECK");
            let db: BTreeSet<String> = rows.iter().map(|r| r.get(0)).collect();
            assert_eq!(rows.len(), 14);
            assert_eq!(db, rust, "G-M19-17 DB CHECK");
            let schema: serde_json::Value = serde_json::from_str(include_str!(
                "../../../contracts/mcp/memory.output.schema.json"
            ))
            .expect("catalog");
            let values = schema["$defs"]["ConfirmationRequired"]["properties"]["operation"]["enum"]
                .as_array()
                .expect("enum");
            assert_eq!(values.len(), 14);
            let catalog: BTreeSet<_> = values
                .iter()
                .map(|v| v.as_str().expect("key").to_owned())
                .collect();
            assert_eq!(catalog, rust, "G-M19-17 catalog");
        },
    );
}

#[test]
fn gauge_counts_memory_targets_without_any_stream_tombstone() {
    run_db_fixture::<Fixture, _>(
        "gauge_counts_memory_targets_without_any_stream_tombstone",
        |mut h| {
            let world = seed(&mut h);
            let request = freeze(&h, world.gated, false);
            let claim = token(
                &mut h,
                &request,
                DeletionScopeKind::Memory,
                request.manifest_hash,
            );
            accept(&h, &request, Some(&claim)).expect("MEMORY accept");
            h.admin.execute("UPDATE control.deletion_requests SET logical_deleted_at=now()-interval '1 hour' WHERE deletion_request_id=$1", &[&request.request_id]).expect("age request");
            assert_eq!(
                h.rt.block_on(forget_repo::tombstoned_unpurged_over_sla(
                    &h.maintenance,
                    h.tenant_id,
                    Duration::from_secs(60)
                ))
                .expect("gauge"),
                1
            );
            h.rt.block_on(forget_repo::record_step(
                &h.maintenance,
                h.tenant_id,
                request.request_id,
                humaux_application::forget::DeletionStep::QdrantPoints,
                "DONE",
                None,
            ))
            .expect("purge receipt");
            assert_eq!(
                h.rt.block_on(forget_repo::tombstoned_unpurged_over_sla(
                    &h.maintenance,
                    h.tenant_id,
                    Duration::from_secs(60)
                ))
                .expect("gauge"),
                0
            );
        },
    );
}

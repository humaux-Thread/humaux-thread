//! `adapters::tests::memory_attribution` — M29 T06a (ADR-0078 D-D, §6.1.4): the ladder behind M07's attribution port
//!   writes exactly the formal `memory_projects` rows that rungs A1 and A3 ground on the Memory's attribution Evidence,
//!   and nothing when no rung holds; M29 T06b (migration 0255): A3' copies a corrected memory's live rows to its
//!   successor, and a project_task relation correction revokes its derived rows, down the inheritance chain, in its
//!   own transaction; M29 T06c: a `remember.put` `project_id` reaches A1 end to end.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, serde_json, sqlx];
//!   services=[PostgreSQL(owner) r=[private.evidence_objects, private.memory_project_revocations,
//!   private.memory_projects, private.memory_subjects] w=[control.tenants, control.workspaces, coord.task_runs,
//!   private.continuity_projects, private.distill_candidates, private.evidence_projects, private.evidence_task_runs,
//!   private.memory_project_revocations, private.memory_projects, private.project_task_relations, private.subjects]
//!   x=[private.link_memory_subjects], PostgreSQL(role_gateway) x=[private.declared_project_visible],
//!   PostgreSQL(role_private_worker)];
//!   env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::attribution_repo, adapters::coord_repo, adapters::distill_repo,
//!   adapters::memory_repo, adapters::operation_receipt, adapters::relation_repo, adapters::remember,
//!   adapters::tests::support::governance_ops, adapters::tests::support::operation_receipt_fixture,
//!   domain::attribution, domain::audit, domain::authority, domain::confirm, domain::continuity, domain::error,
//!   domain::evidence, domain::identity, domain::ids,
//!   domain::memory, domain::relation, domain::subject, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [Evidence enters through the real `remember.put` (the T04c path when it carries a run); the Memory
//!   enters through the real door (role_private_worker's distill hop, or role_gateway's `memory.confirm`) with the real
//!   ladder; the owner seeds projects, relations, declared rows and candidates, and counts rows, so no RLS can hide
//!   one; whatever a test commits it purges before asserting]
//! Spec: Baseline §6.1.4; §6.1.3; §78.2; §79.2; §80.1; ADR-0078 D-D
//!
//! | test | gate | injected fault that turns it red |
//! |---|---|---|
//! | `g_m29_1_source_kind_and_rule_checks_match_domain` | G-M29-1 (source_kind part) | a DB-only `source_kind` value |
//! | `g_t06a_a3_inherits_only_current_contains` | G-T06a-A3 | drop `valid @> occurred_at`, the task leg, the NULL guard or `ON CONFLICT` |
//! | `g_t06a_a1_declared_project` | G-T06a-A1 | skip A1, or drop its Evidence or `source_kind` filter |
//! | `g_n09_3_unknown_stays_unknown` | G-N09-3 | A1 takes the most recently related project |
//! | `g_t06a_confirm_reads_the_source_evidence` | G-T06a-confirm | the confirm caller names E2 |
//! | `g_m29_5b_correction_inherits_supersede_does_not` | G-M29-5(b) | drop the A3' trigger |
//! | `g_m29_5b_correction_inherits_live_links_only` | G-M29-5(b), read path | the live view drops its `NOT EXISTS` |
//! | `g_m29_5b_inheritance_keys_on_the_correction_transition` | G-M29-5(b), the transition (design v0.2 revision 2) | A3' drops the event's reason_code leg |
//! | `g_109_subject_inheritance_keys_on_the_correction_transition` | issue #109, §6.1.3 rule 3b | `private.is_correction_transition` drops the event's reason_code leg, or the subjects trigger stops testing it |
//! | `g_m29_6_relation_correction_revokes_in_its_transaction` | G-M29-6 | drop the trigger, the `occurred_at` test or the task match; the revocation as SECURITY INVOKER, or joining `evidence_objects` again |
//! | `g_m29_6_revocation_follows_the_inheritance_chain` | G-M29-6, transitive | drop the transitive trigger |
//! | `revocation_definers_refuse_another_session_tenant` | definer tenant pin | neutralise the pin |
//! | `backfill_restates_the_a3_ground_and_the_check_requires_it` | 0255 ⑥ A3 ground, backfill and CHECK | the backfill takes another task; the CHECK accepts a task_run@1 row without ground, or a declared@1 row with one |
//! | `g_t06c_2_declared_project_end_to_end` | G-T06c-2 | skip the `evidence_projects` INSERT |
//! | `g_t06c_1_reader_tenant_leg` | G-T06c-1 (tenant leg) | drop the reader's tenant predicate |
//!
//! called-by: `cargo test -p humaux-adapters --test memory_attribution`.

// Both fixtures (`operation_receipt_fixture`, `governance_ops`) carry their own `#[path] mod token_keys`; this test loads
// both, and `token_keys::install` is idempotent per process, so the second copy is inert.
#![allow(clippy::duplicate_mod)]

use std::collections::BTreeSet;
use std::ops::Bound::{Excluded, Included};
use std::time::{Duration, SystemTime};

use humaux_adapters::{
    attribution_repo::AttributionLadder,
    coord_repo::{self, ClaimedTaskRun},
    distill_repo::{self, ConfirmOutcome, ConfirmRequest},
    memory_repo::{self, AttributionSource, NewMemory},
    operation_receipt::{self, AtomicRememberRequest},
    relation_repo,
    remember::RememberCommand,
};
use humaux_domain::{
    attribution::{RuleId, SourceKind},
    audit::{AuditEvent, AuditEventId, AuditMetadata, McpAuditAction},
    authority::AuthorityClass,
    confirm::DestructiveOp,
    continuity::ProjectId,
    error::ErrorCode,
    evidence::{EvidenceOriginClass, payload_sha256},
    identity::PrincipalId,
    ids::{TaskId, TenantId, WorkspaceId},
    memory::MemoryType,
    relation::{DecidedBy, RelationEdge, RelationId, RelationKind, Timestamp, Validity},
};
use humaux_testkit::run_db_fixture;
use sqlx::types::{Uuid, time::OffsetDateTime};
use sqlx::{Connection, PgConnection};

#[allow(dead_code)]
#[path = "support/operation_receipt_fixture.rs"]
mod operation_receipt_fixture;

#[allow(dead_code)]
#[path = "support/governance_ops.rs"]
mod governance_ops;

use governance_ops::Governor;
use operation_receipt_fixture::{
    DOMAIN, Fixture, Handle, OPERATION, PROJECTION_KIND, PROJECTION_VERSION,
};

/// `(project_id, source_kind, rule_id_ver, decision_evidence_id)` of one `memory_projects` row.
type Row = (Uuid, String, String, Uuid);

/// 2026-01-15T00:00:00Z: inside the CONTAINS window `[2026-01-01, 2026-02-01)`.
const INSIDE: i64 = 1_768_435_200;
/// 2026-03-01T00:00:00Z: after the CONTAINS window, still inside the open window.
const OUTSIDE: i64 = 1_772_323_200;
const CONTAINS_WINDOW: &str = "{[2026-01-01 00:00:00+00,2026-02-01 00:00:00+00)}";
const OPEN_WINDOW: &str = "{[2026-01-01 00:00:00+00,)}";

fn row(project: Uuid, kind: SourceKind, rule: RuleId, evidence: Uuid) -> Row {
    (
        project,
        kind.as_str().to_owned(),
        rule.as_str().to_owned(),
        evidence,
    )
}

fn request(handle: &Handle, key: &str, occurred_at: Option<i64>) -> AtomicRememberRequest {
    let request_id = Uuid::new_v4();
    let key_hex: String = key.bytes().map(|b| format!("{b:02x}")).collect();
    let mut metadata = AuditMetadata::new();
    metadata
        .insert("role", "member")
        .expect("allowlisted audit metadata");
    let content = format!("memory-attribution {key}");
    AtomicRememberRequest {
        request_id,
        idempotency_key: key.into(),
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
            occurred_at: occurred_at
                .map(|t| OffsetDateTime::from_unix_timestamp(t).expect("fixture instant")),
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
            trace_id: format!("memory-attribution-{request_id}"),
            client_ip: "127.0.0.1".into(),
            user_agent_hash: "memory-attribution-fixture".into(),
            risk_tags: vec!["fixture".into()],
            before_fingerprint: None,
            after_fingerprint: None,
            metadata,
        },
    }
}

/// `remember.put` (with `run`: the T04c path, verified in the receipt transaction); returns the Evidence id.
fn put(handle: &Handle, key: &str, occurred_at: Option<i64>, run: Option<&ClaimedTaskRun>) -> Uuid {
    put_with(handle, key, occurred_at, run, None)
}

/// [`put`] that may also declare a project (T06c: resolved in the receipt transaction, DECLARED on the Evidence).
fn put_with(
    handle: &Handle,
    key: &str,
    occurred_at: Option<i64>,
    run: Option<&ClaimedTaskRun>,
    project: Option<Uuid>,
) -> Uuid {
    handle
        .rt
        .block_on(operation_receipt::remember_for_task_run_atomically(
            &handle.runtime,
            &handle.auth,
            request(handle, key, occurred_at),
            run.map(|r| (r.task_run_id, r.fencing_token)),
            project.map(ProjectId),
        ))
        .expect("remember.put")
        .accepted
        .evidence_id
}

/// [`put`] of a `USER_PRIVATE` Evidence of the fixture user on `run`.
fn put_private(handle: &Handle, key: &str, occurred_at: i64, run: &ClaimedTaskRun) -> Uuid {
    let mut request = request(handle, key, Some(occurred_at));
    request.command.visibility_class = "USER_PRIVATE".into();
    request.command.visibility_user_id = Some(handle.user_id);
    request.command.visibility_workspace_id = None;
    request.command.data_class = "PRIVATE".into();
    handle
        .rt
        .block_on(operation_receipt::remember_for_task_run_atomically(
            &handle.runtime,
            &handle.auth,
            request,
            Some((run.task_run_id, run.fencing_token)),
            None,
        ))
        .expect("remember.put")
        .accepted
        .evidence_id
}

/// A fresh task in the fixture tenant, submitted by the fixture principal.
fn task(handle: &Handle) -> TaskId {
    handle
        .rt
        .block_on(coord_repo::submit(
            &handle.runtime,
            &handle.auth,
            "memory_attribution",
            "M29 T06a gate",
        ))
        .expect("submit")
}

/// A claimed run of `task` by the fixture principal (the one `put` verifies).
fn claim(handle: &Handle, task: TaskId) -> ClaimedTaskRun {
    handle
        .rt
        .block_on(coord_repo::claim(
            &handle.runtime,
            &handle.auth,
            task,
            Duration::from_secs(300),
        ))
        .expect("claim")
}

fn project(handle: &Handle, project: Uuid) -> String {
    // N09-3's ambiguity: every fixture project has the same title in the same workspace.
    format!(
        "INSERT INTO private.continuity_projects (project_id, tenant_id, workspace_id, title) \
         VALUES ('{project}', '{}', '{}', 'Same title')",
        handle.tenant_id, handle.workspace_id
    )
}

/// One `project_task_relations` revision; `valid` is a multirange literal (`{}` retracts). Its authorisation
/// Evidence (0253's FK) is the tenant's lowest Evidence id: every caller seeds after a put, and the ordered pick keeps
/// the fixture deterministic without widening every call site.
fn relation(
    tenant: Uuid,
    relation: Uuid,
    revision: i64,
    project: Uuid,
    task: TaskId,
    kind: RelationKind,
    valid: &str,
) -> String {
    format!(
        "INSERT INTO private.project_task_relations (tenant_id, relation_id, revision, src_id, dst_id, \
           relation_kind, valid, decided_by, factual_evidence_ids, authorization_evidence_id) \
         VALUES ('{tenant}', '{relation}', {revision}, '{project}', '{}', '{}', '{valid}', 'rule:fixture@1', \
           '{{}}', (SELECT evidence_id FROM private.evidence_objects WHERE tenant_id = '{tenant}' \
                    ORDER BY evidence_id LIMIT 1))",
        task.0,
        kind.as_str()
    )
}

/// One `evidence_projects` row (its writer is T06c, so fixture SQL stands in).
fn declared(handle: &Handle, evidence: Uuid, project: Uuid, kind: SourceKind) -> String {
    format!(
        "INSERT INTO private.evidence_projects (tenant_id, evidence_id, project_id, source_kind) \
         VALUES ('{}', '{evidence}', '{project}', '{}')",
        handle.tenant_id,
        kind.as_str()
    )
}

/// One rolled-back transaction: the owner runs `seed`, then the private worker's distill hop loads `evidence` and
/// inserts one Memory through the door (attribution Evidence = that PRIMARY Evidence) with the real ladder. Returns
/// that Memory's rows, read back as the owner, or the door's error.
fn attribute(handle: &Handle, evidence: Uuid, seed: &[String]) -> Result<Vec<Row>, String> {
    let dsn = std::env::var("HUMAUX_TEST_PG_DSN").expect("the fixture ran, so the DSN is set");
    handle.rt.block_on(async {
        // dep: PostgreSQL(owner) — test opens a direct PG connection for setup/verification
        let mut conn = PgConnection::connect(&dsn).await.expect("owner connection");
        // dep: PostgreSQL(any) — pool/txn query execution
        let mut txn = conn.begin().await.expect("begin");
        // 0255's revocation definers refuse a row of any tenant but the session's, and a seed may append a revision.
        sqlx::query("SELECT set_config('humaux.tenant_id', $1, true)")
            .bind(handle.tenant_id.to_string())
            .execute(&mut *txn)
            .await
            .expect("session tenant");
        for sql in seed {
            sqlx::query(sql)
                .execute(&mut *txn)
                .await
                .expect("owner seeds the attribution fixture");
        }
        let memory = door(&mut txn, handle, evidence)
            .await
            .map_err(|e| e.to_string())?;
        let rows = sqlx::query_as::<_, Row>(
            "SELECT project_id, source_kind, rule_id_ver, decision_evidence_id \
               FROM private.memory_projects WHERE memory_id = $1 ORDER BY project_id",
        )
        .bind(memory)
        .fetch_all(&mut *txn)
        .await
        .expect("owner reads memory_projects");
        txn.rollback().await.expect("rollback");
        Ok::<_, String>(rows)
    })
}

/// The private worker's distill hop in `txn`: loads `evidence` and inserts one Memory through the door (attribution
/// Evidence = that PRIMARY Evidence) with the real ladder, then returns to the owner. The Memory takes the Evidence's
/// visibility.
async fn door(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    handle: &Handle,
    evidence: Uuid,
) -> Result<Uuid, sqlx::Error> {
    // dep: PostgreSQL(role_private_worker) — test switches PG role to exercise RLS
    sqlx::query("SET LOCAL ROLE role_private_worker")
        .execute(&mut **txn)
        .await?;
    let loaded = distill_repo::load_evidence(
        txn,
        handle.tenant_id,
        handle.reasoning_domain_id,
        handle.user_id,
        evidence,
    )
    .await?
    .expect("the put's Evidence");
    let content = serde_json::json!({"fact": "memory-attribution fixture"});
    let memory = memory_repo::insert_memory_in_txn(
        txn,
        handle.tenant_id,
        &loaded,
        &NewMemory {
            content: &content,
            memory_type: MemoryType::Fact,
            class: AuthorityClass::PrivateKnowledge,
            confidence: 0.9,
            note_kind: None,
            note_id: None,
            attribution: AttributionSource::Primary,
        },
        &AttributionLadder,
    )
    .await?;
    sqlx::query("RESET ROLE").execute(&mut **txn).await?;
    Ok(memory)
}

/// The fixture's teardown knows neither the carriers, `coord.task_runs`, nor the append-only attribution and relation
/// rows a committed test leaves (replica mode lets the owner past their append-only triggers).
fn purge(handle: &mut Handle) {
    let t = handle.tenant_id;
    handle
        .admin
        .batch_execute(&format!(
            "SET session_replication_role = replica; \
             DELETE FROM private.memory_project_revocations WHERE tenant_id = '{t}'; \
             DELETE FROM private.memory_projects WHERE tenant_id = '{t}'; \
             DELETE FROM private.project_task_relations WHERE tenant_id = '{t}'; \
             SET session_replication_role = DEFAULT; \
             DELETE FROM private.evidence_projects WHERE tenant_id = '{t}'; \
             DELETE FROM private.evidence_task_runs WHERE tenant_id = '{t}'; \
             DELETE FROM coord.task_runs WHERE tenant_id = '{t}';"
        ))
        .expect("purge attribution, relations, carrier and runs");
}

/// G-M29-1, `source_kind` part (§78.2): each 0252 CHECK literal set equals its Rust closed set.
#[test]
fn g_m29_1_source_kind_and_rule_checks_match_domain() {
    run_db_fixture::<Fixture, _>(
        "g_m29_1_source_kind_and_rule_checks_match_domain",
        |mut handle| {
            let kinds: BTreeSet<String> = SourceKind::ALL
                .iter()
                .map(|k| k.as_str().to_owned())
                .collect();
            let rules: BTreeSet<String> =
                RuleId::ALL.iter().map(|r| r.as_str().to_owned()).collect();
            for (check, expected) in [
                ("evidence_projects_source_kind_check", &kinds),
                ("memory_projects_source_kind_check", &kinds),
                ("memory_projects_rule_id_ver_check", &rules),
            ] {
                let def: String = handle
                    .admin
                    .query_one(
                        "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = $1",
                        &[&check],
                    )
                    .expect(check)
                    .get(0);
                let db: BTreeSet<String> = def
                    .split('\'')
                    .skip(1)
                    .step_by(2)
                    .map(str::to_owned)
                    .collect();
                assert_eq!(&db, expected, "{check}: {def}");
            }
        },
    );
}

/// G-T06a-A3: a put on a claimed run of T1 inherits P1 (CONTAINS T1), never P2 (REFERENCES T1) or P3 (CONTAINS
/// another task). An Evidence outside P1's window, after P1's relation was retracted, or with no `occurred_at` at all
/// inherits nothing; a project A1 also grounds keeps its A1 row.
#[test]
fn g_t06a_a3_inherits_only_current_contains() {
    run_db_fixture::<Fixture, _>("g_t06a_a3_inherits_only_current_contains", |mut handle| {
        handle.seed_current_entitlement_and_window(10);
        let (t1, t2) = (task(&handle), task(&handle));
        let run = claim(&handle, t1);
        let inside = put(&handle, "t06a-a3-inside", Some(INSIDE), Some(&run));
        let outside = put(&handle, "t06a-a3-outside", Some(OUTSIDE), Some(&run));
        let timeless = put(&handle, "t06a-a3-timeless", None, Some(&run));

        let [p1, p2, p3, r1, r2, r3] = [(); 6].map(|()| Uuid::now_v7());
        let t = handle.tenant_id;
        let seed = vec![
            project(&handle, p1),
            project(&handle, p2),
            project(&handle, p3),
            relation(t, r1, 1, p1, t1, RelationKind::Contains, CONTAINS_WINDOW),
            relation(t, r2, 1, p2, t1, RelationKind::References, OPEN_WINDOW),
            relation(t, r3, 1, p3, t2, RelationKind::Contains, CONTAINS_WINDOW),
        ];
        assert_eq!(
            attribute(&handle, inside, &seed),
            Ok(vec![row(
                p1,
                SourceKind::Inherited,
                RuleId::TaskRun1,
                inside
            )]),
            "P1 only, INHERITED / task_run@1, decided by the put's Evidence"
        );
        assert_eq!(
            attribute(&handle, outside, &seed),
            Ok(Vec::new()),
            "occurred_at outside P1's CONTAINS window"
        );
        let mut retracted = seed.clone();
        retracted.push(relation(t, r1, 2, p1, t1, RelationKind::Contains, "{}"));
        assert_eq!(
            attribute(&handle, inside, &retracted),
            Ok(Vec::new()),
            "P1's current revision is retracted"
        );
        let mut both = seed.clone();
        both.push(declared(&handle, inside, p1, SourceKind::Declared));
        assert_eq!(
            attribute(&handle, inside, &both),
            Ok(vec![row(
                p1,
                SourceKind::Declared,
                RuleId::Declared1,
                inside
            )]),
            "A1 and A3 on one project: the A1 row stands"
        );
        let now = [
            project(&handle, p1),
            relation(t, r1, 1, p1, t1, RelationKind::Contains, OPEN_WINDOW),
        ];
        assert_eq!(
            attribute(&handle, timeless, &now),
            Ok(Vec::new()),
            "N09 R3: no occurred_at, no A3, even under a currently valid CONTAINS"
        );
        purge(&mut handle);
    });
}

/// G-T06a-A1: only this Evidence's DECLARED `evidence_projects` row becomes a DECLARED / declared@1 row; another
/// Evidence's declaration and a non-DECLARED row on this Evidence do not.
#[test]
fn g_t06a_a1_declared_project() {
    run_db_fixture::<Fixture, _>("g_t06a_a1_declared_project", |mut handle| {
        handle.seed_current_entitlement_and_window(10);
        let evidence = put(&handle, "t06a-a1", Some(INSIDE), None);
        let other = put(&handle, "t06a-a1-other", Some(INSIDE), None);
        let [p, p4, p5] = [(); 3].map(|()| Uuid::now_v7());
        let seed = vec![
            project(&handle, p),
            project(&handle, p4),
            project(&handle, p5),
            declared(&handle, evidence, p, SourceKind::Declared),
            declared(&handle, other, p4, SourceKind::Declared),
            declared(&handle, evidence, p5, SourceKind::Inherited),
        ];
        assert_eq!(
            attribute(&handle, evidence, &seed),
            Ok(vec![row(
                p,
                SourceKind::Declared,
                RuleId::Declared1,
                evidence
            )])
        );
    });
}

/// G-N09-3: two same-title projects in one workspace, both related to a task, and an Evidence with neither a
/// declared project nor a task run: the Memory stays unattributed (no title, recency or default guess).
#[test]
fn g_n09_3_unknown_stays_unknown() {
    run_db_fixture::<Fixture, _>("g_n09_3_unknown_stays_unknown", |mut handle| {
        handle.seed_current_entitlement_and_window(10);
        let t1 = task(&handle);
        let evidence = put(&handle, "n09-3", Some(INSIDE), None);
        let [pa, pb] = [(); 2].map(|()| Uuid::now_v7());
        let t = handle.tenant_id;
        let seed = vec![
            project(&handle, pa),
            project(&handle, pb),
            relation(
                t,
                Uuid::now_v7(),
                1,
                pa,
                t1,
                RelationKind::Contains,
                OPEN_WINDOW,
            ),
            relation(
                t,
                Uuid::now_v7(),
                1,
                pb,
                t1,
                RelationKind::Contains,
                OPEN_WINDOW,
            ),
        ];
        assert_eq!(attribute(&handle, evidence, &seed), Ok(Vec::new()));
    });
}

/// G-T06a-confirm (ADR-0078 D-D attribution Evidence): a candidate distilled from a task-run Evidence E1, confirmed
/// through `distill_repo::confirm_candidate_atomically`, inherits E1's CONTAINS project, decided by E1, although its
/// PRIMARY Evidence is the confirmation E2 (which carries no task run).
#[test]
fn g_t06a_confirm_reads_the_source_evidence() {
    run_db_fixture::<Fixture, _>("g_t06a_confirm_reads_the_source_evidence", |mut handle| {
        // The governor's BMO window is the tenant's only one (quota_repo takes exactly one current window).
        let governor = Governor::seed(&mut handle.admin, handle.tenant_id);
        governor.join(&mut handle.admin, handle.workspace_id);
        let auth = governor.scope(handle.workspace_id);
        let t1 = task(&handle);
        let run = claim(&handle, t1);
        let e1 = put(&handle, "t06a-confirm-e1", Some(INSIDE), Some(&run));
        let (p1, r1, t) = (Uuid::now_v7(), Uuid::now_v7(), handle.tenant_id);
        let seed = [
            project(&handle, p1),
            relation(t, r1, 1, p1, t1, RelationKind::Contains, CONTAINS_WINDOW),
        ];
        for sql in &seed {
            handle
                .admin
                .batch_execute(sql)
                .expect("owner commits P1 CONTAINS T1");
        }
        let candidate = handle
            .admin
            .query_one(
                &format!(
                    "INSERT INTO private.distill_candidates (tenant_id, source_evidence_id, candidate_body, \
                       candidate_sha256, rejection_reason, requested_class, memory_type, confidence, data_class, \
                       visibility_class, visibility_workspace_id, reasoning_domain_id, occurred_at, state, expires_at) \
                     SELECT $1, $2, b, sha256(convert_to(b::text, 'UTF8')), 'origin_authority_ceiling', \
                       'ProjectDecision', 'DECISION', 0.7, 'INTERNAL', 'WORKSPACE_SHARED', $3, $4, \
                       to_timestamp({INSIDE}), 'PENDING', clock_timestamp() + interval '7 days' \
                       FROM (SELECT '{{\"title\": \"t06a\", \"key_claim\": \"confirm reads E1\"}}'::jsonb AS b) s \
                     RETURNING candidate_id, candidate_sha256"
                ),
                &[
                    &handle.tenant_id,
                    &e1,
                    &handle.workspace_id,
                    &handle.reasoning_domain_id,
                ],
            )
            .expect("owner seeds a PENDING candidate distilled from E1");
        let (candidate_id, candidate_sha256): (Uuid, Vec<u8>) =
            (candidate.get(0), candidate.get(1));
        let op = DestructiveOp::MemoryConfirm;
        let claim =
            governance_ops::confirm(&handle.rt, &handle.runtime, &auth, op, candidate_id, None);
        let request_id = Uuid::now_v7();
        let outcome = handle
            .rt
            .block_on(distill_repo::confirm_candidate_atomically(
                &handle.runtime,
                &auth,
                ConfirmRequest {
                    request_id,
                    request_fingerprint: governance_ops::fingerprint(),
                    reservation_ttl: Duration::from_secs(30),
                    candidate_id,
                    candidate_sha256,
                    stream: governance_ops::stream(handle.tenant_id, handle.workspace_id),
                    claim,
                    finished_audit: governance_ops::audit(&auth, op, request_id, false),
                    consistency_token_ttl: Duration::from_secs(600),
                    subjects: humaux_domain::subject::SubjectDeclaration::default(),
                },
                &AttributionLadder,
            ))
            .expect("memory.confirm");
        let ConfirmOutcome::Confirmed(done) = outcome else {
            panic!("memory.confirm refused the candidate");
        };
        let rows: Vec<Row> = handle
            .admin
            .query(
                "SELECT project_id, source_kind, rule_id_ver, decision_evidence_id \
                   FROM private.memory_projects WHERE memory_id = $1",
                &[&done.memory_id],
            )
            .expect("owner reads memory_projects")
            .iter()
            .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
            .collect();
        purge(&mut handle);
        Governor::cleanup(&mut handle.admin, handle.tenant_id);
        assert_ne!(done.evidence_id, e1, "E2 is the confirmation, not E1");
        assert_eq!(
            rows,
            [row(p1, SourceKind::Inherited, RuleId::TaskRun1, e1)],
            "decided by E1, the candidate's source Evidence"
        );
    });
}

/// `(project_id, source_kind, rule_id_ver, decision_evidence_id, inherited_from_memory_id)` of one `memory_projects`
/// row.
type Link = (Uuid, String, String, Uuid, Option<Uuid>);
/// `(memory_id, project_id, revoked_by, reason)` of one `memory_project_revocations` row.
type Revocation = (Uuid, Uuid, String, String);

/// 2026-01-05T00:00:00Z: inside the CONTAINS window, before the narrowed one.
const EARLY: i64 = 1_767_571_200;
/// 2026-01-25T00:00:00Z: inside both the CONTAINS window and the narrowed one.
const LATE: i64 = 1_769_299_200;
/// The narrowed CONTAINS window `[2026-01-20, 2026-02-01)`, in seconds.
const NARROWED: (i64, i64) = (1_768_867_200, 1_769_904_000);

fn link(project: Uuid, kind: SourceKind, rule: RuleId, evidence: Uuid, from: Option<Uuid>) -> Link {
    let (project, kind, rule, evidence) = row(project, kind, rule, evidence);
    (project, kind, rule, evidence, from)
}

/// One Memory of `evidence` through the real door, committed (see [`door`]).
fn commit_memory(handle: &Handle, evidence: Uuid) -> Uuid {
    let dsn = std::env::var("HUMAUX_TEST_PG_DSN").expect("the fixture ran, so the DSN is set");
    handle.rt.block_on(async {
        // dep: PostgreSQL(owner) — test opens a direct PG connection for setup/verification
        let mut conn = PgConnection::connect(&dsn).await.expect("owner connection");
        // dep: PostgreSQL(any) — pool/txn query execution
        let mut txn = conn.begin().await.expect("begin");
        let memory = door(&mut txn, handle, evidence)
            .await
            .expect("the door writes the Memory");
        txn.commit().await.expect("commit");
        memory
    })
}

/// Every `memory_projects` row of `memory`, read as the owner, by project.
fn links(handle: &mut Handle, memory: Uuid) -> Vec<Link> {
    handle
        .admin
        .query(
            "SELECT project_id, source_kind, rule_id_ver, decision_evidence_id, inherited_from_memory_id \
               FROM private.memory_projects WHERE memory_id = $1 ORDER BY project_id",
            &[&memory],
        )
        .expect("owner reads memory_projects")
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4)))
        .collect()
}

fn commit(handle: &mut Handle, seed: &[String]) {
    for sql in seed {
        handle
            .admin
            .batch_execute(sql)
            .expect("owner commits the fixture");
    }
}

/// `[start, end)` in seconds as a relation validity.
fn window((start, end): (i64, i64)) -> Validity {
    Validity::new(&[(
        Included(Timestamp::Micros(start * 1_000_000)),
        Excluded(Timestamp::Micros(end * 1_000_000)),
    )])
    .expect("fixture window")
}

/// The T06b world, committed: the governor (who corrects), task T1 with a claimed run, Evidence E1 put on that run
/// at `INSIDE`, P1 CONTAINS T1 over `CONTAINS_WINDOW` (relation r1, revision 1) and P2 declared on E1.
struct World {
    governor: Governor,
    t1: TaskId,
    run: ClaimedTaskRun,
    e1: Uuid,
    p1: Uuid,
    p2: Uuid,
    r1: Uuid,
}

impl World {
    fn new(handle: &mut Handle) -> Self {
        // The governor's BMO window is the tenant's only one (quota_repo takes exactly one current window).
        let governor = Governor::seed(&mut handle.admin, handle.tenant_id);
        governor.join(&mut handle.admin, handle.workspace_id);
        let t1 = task(handle);
        let run = claim(handle, t1);
        let e1 = put(handle, "t06b-e1", Some(INSIDE), Some(&run));
        let [p1, p2, r1] = [(); 3].map(|()| Uuid::now_v7());
        let seed = vec![
            project(handle, p1),
            project(handle, p2),
            relation(
                handle.tenant_id,
                r1,
                1,
                p1,
                t1,
                RelationKind::Contains,
                CONTAINS_WINDOW,
            ),
            declared(handle, e1, p2, SourceKind::Declared),
        ];
        commit(handle, &seed);
        Self {
            governor,
            t1,
            run,
            e1,
            p1,
            p2,
            r1,
        }
    }

    /// `memory.correct` of `memory` by the governor; returns `(M2, E2)`.
    fn correct(&self, handle: &Handle, memory: Uuid) -> (Uuid, Uuid) {
        let done = governance_ops::correct(
            &handle.rt,
            &handle.runtime,
            &self.governor.scope(handle.workspace_id),
            &governance_ops::stream(handle.tenant_id, handle.workspace_id),
            memory,
            "t06b corrected",
        )
        .expect("memory.correct");
        (done.new_memory_id.0, done.evidence_id)
    }

    /// The rows the governor's revision 2 of r1 revokes, as `(memory, P1, principal:<governor>, r1@2)`, sorted.
    fn revoked(&self, memories: &[Uuid]) -> Vec<Revocation> {
        let by = format!("principal:{}", self.governor.user_id);
        let reason = format!("project_task_relations:{}@2", self.r1);
        let mut rows: Vec<Revocation> = memories
            .iter()
            .map(|m| (*m, self.p1, by.clone(), reason.clone()))
            .collect();
        rows.sort();
        rows
    }

    /// Revision 2 of r1 with `valid`, through `relation_repo::append_revision`, decided by the governor in a
    /// `role_gateway` transaction with the visibility GUCs the caller installs (ADR-0078 T06d). Returns every
    /// revocation of `tenants` as that transaction sees it before it ends, then commits or rolls back.
    fn revise(
        &self,
        handle: &Handle,
        valid: &Validity,
        tenants: &[Uuid],
        keep: bool,
    ) -> Result<Vec<Revocation>, ErrorCode> {
        let dsn = std::env::var("HUMAUX_TEST_PG_DSN").expect("the fixture ran, so the DSN is set");
        let by = self.governor.user_id;
        handle.rt.block_on(async {
            // dep: PostgreSQL(owner) — test opens a direct PG connection for setup/verification
            let mut conn = PgConnection::connect(&dsn).await.expect("owner connection");
            // dep: PostgreSQL(any) — pool/txn query execution
            let mut txn = conn.begin().await.expect("begin");
            // dep: PostgreSQL(role_gateway) — test switches PG role to exercise RLS
            sqlx::query("SET LOCAL ROLE role_gateway")
                .execute(&mut *txn)
                .await
                .expect("gateway role");
            sqlx::query(
                "SELECT set_config('humaux.tenant_id', $1, true), set_config('humaux.user_id', $2, true)",
            )
            .bind(handle.tenant_id.to_string())
            .bind(by.to_string())
            .execute(&mut *txn)
            .await
            .expect("session GUCs");
            let edge = RelationEdge {
                src_id: self.p1,
                kind: RelationKind::Contains,
                dst_id: self.t1.0,
            };
            relation_repo::append_revision(
                &mut txn,
                &edge,
                RelationId(self.r1),
                1,
                valid,
                &DecidedBy::Principal(PrincipalId(by)),
                None,
                &[],
                self.e1,
            )
            .await?;
            sqlx::query("RESET ROLE")
                .execute(&mut *txn)
                .await
                .expect("back to the owner");
            let seen = sqlx::query_as::<_, Revocation>(
                "SELECT memory_id, project_id, revoked_by, reason FROM private.memory_project_revocations \
                  WHERE tenant_id = ANY($1) ORDER BY memory_id",
            )
            .bind(tenants)
            .fetch_all(&mut *txn)
            .await
            .expect("owner reads the revocations");
            if keep {
                txn.commit().await
            } else {
                txn.rollback().await
            }
            .expect("end the correcting transaction");
            Ok(seen)
        })
    }

    fn cleanup(handle: &mut Handle) {
        purge(handle);
        Governor::cleanup(&mut handle.admin, handle.tenant_id);
    }
}

/// G-M29-5(b): `memory.correct` (through `correct_atomically`) of a memory with one A3 and one A1 row gives the
/// successor both as INHERITED / correction@1, decided by the correction's Evidence and naming the predecessor; a
/// `memory.supersede` of the same shape gives its successor nothing.
#[test]
fn g_m29_5b_correction_inherits_supersede_does_not() {
    run_db_fixture::<Fixture, _>(
        "g_m29_5b_correction_inherits_supersede_does_not",
        |mut handle| {
            let w = World::new(&mut handle);
            let plain = put(&handle, "t06b-a3p-plain", Some(INSIDE), None);
            let m1 = commit_memory(&handle, w.e1);
            let ma = commit_memory(&handle, w.e1);
            let mb = commit_memory(&handle, plain);
            let before = links(&mut handle, m1);
            let (m2, e2) = w.correct(&handle, m1);
            let inherited = links(&mut handle, m2);
            governance_ops::supersede(
                &handle.rt,
                &handle.runtime,
                &w.governor.scope(handle.workspace_id),
                &governance_ops::stream(handle.tenant_id, handle.workspace_id),
                ma,
                mb,
            )
            .expect("memory.supersede");
            let superseded = links(&mut handle, mb);
            World::cleanup(&mut handle);
            assert_eq!(
                before,
                [
                    link(w.p1, SourceKind::Inherited, RuleId::TaskRun1, w.e1, None),
                    link(w.p2, SourceKind::Declared, RuleId::Declared1, w.e1, None),
                ],
                "M1: one A3 and one A1 row"
            );
            assert_eq!(
                inherited,
                [
                    link(
                        w.p1,
                        SourceKind::Inherited,
                        RuleId::Correction1,
                        e2,
                        Some(m1)
                    ),
                    link(
                        w.p2,
                        SourceKind::Inherited,
                        RuleId::Correction1,
                        e2,
                        Some(m1)
                    ),
                ],
                "M2 inherits both, decided by E2, naming M1"
            );
            assert!(
                superseded.is_empty(),
                "an explicit supersede inherits nothing: {superseded:?}"
            );
        },
    );
}

/// G-M29-5(b), design v0.2 §15.7 revision 2: A3' keys on the correction transition, not on the successor's origin.
/// (ii) `memory.restore` of the correction-born M1 (undoing M1 -> M2) sets M2's superseded_by to M1, and M1 gains
/// nothing from M2 although M2 carries P3, which M1 lacks; (i) a `memory.supersede` of X (declared to P3) onto the
/// correction-born M1 gives M1 nothing either.
#[test]
fn g_m29_5b_inheritance_keys_on_the_correction_transition() {
    run_db_fixture::<Fixture, _>(
        "g_m29_5b_inheritance_keys_on_the_correction_transition",
        |mut handle| {
            let w = World::new(&mut handle);
            let p3 = Uuid::now_v7();
            let e3 = put(&handle, "t06b-a3p-x", Some(INSIDE), None);
            let seed = vec![
                project(&handle, p3),
                declared(&handle, e3, p3, SourceKind::Declared),
            ];
            commit(&mut handle, &seed);
            let m0 = commit_memory(&handle, w.e1);
            let x = commit_memory(&handle, e3);
            let (m1, _) = w.correct(&handle, m0);
            let (m2, e2) = w.correct(&handle, m1);
            handle
                .admin
                .batch_execute(&format!(
                    "SET session_replication_role = replica; \
                     INSERT INTO private.memory_projects (tenant_id, memory_id, project_id, relation, source_kind, \
                       rule_id_ver, decision_evidence_id) \
                     VALUES ('{}', '{m2}', '{p3}', 'ATTRIBUTED_TO', 'DECLARED', 'declared@1', '{e2}'); \
                     SET session_replication_role = DEFAULT;",
                    handle.tenant_id
                ))
                .expect("owner plants M2's P3 row");
            let before = links(&mut handle, m1);
            let scope = w.governor.scope(handle.workspace_id);
            let stream = governance_ops::stream(handle.tenant_id, handle.workspace_id);
            governance_ops::restore(&handle.rt, &handle.runtime, &scope, &stream, m1)
                .expect("memory.restore");
            let restored = links(&mut handle, m1);
            let supersede =
                governance_ops::supersede(&handle.rt, &handle.runtime, &scope, &stream, x, m1)
                    .map(|_| ());
            let superseded = links(&mut handle, m1);
            let x_links = links(&mut handle, x);
            World::cleanup(&mut handle);
            assert_eq!(
                before.len(),
                2,
                "M1 inherited P1 and P2 from M0: {before:?}"
            );
            assert_eq!(
                x_links,
                [link(p3, SourceKind::Declared, RuleId::Declared1, e3, None)],
                "X: one A1 row, on P3"
            );
            assert_eq!(
                restored, before,
                "(ii) restoring the correction-born M1 gives it nothing from M2"
            );
            assert_eq!(
                (supersede, superseded),
                (Ok(()), before),
                "(i) a supersede onto the correction-born M1 commits and gives it nothing"
            );
        },
    );
}

/// A PERSON subject of the fixture tenant, seeded by the owner.
fn subject(handle: &mut Handle, name: &str) -> Uuid {
    handle
        .admin
        .query_one(
            "INSERT INTO private.subjects (tenant_id, kind, display_name) VALUES ($1, 'PERSON', $2) \
             RETURNING subject_id",
            &[&handle.tenant_id, &name],
        )
        .expect("owner seeds a subject")
        .get(0)
}

/// Links `memory` to `subject` as DECLARED through the hook, as the owner (no RLS in the way).
fn declare_subject(handle: &mut Handle, memory: Uuid, subject: Uuid) {
    handle
        .admin
        .execute(
            "SELECT private.link_memory_subjects($1, $2, ARRAY[$3]::uuid[], ARRAY['DECLARED']::text[])",
            &[&handle.tenant_id, &memory, &subject],
        )
        .expect("owner links a subject");
}

/// `(subject_id, source_kind)` of every `memory_subjects` row of `memory`, read as the owner, by subject.
fn subject_links(handle: &mut Handle, memory: Uuid) -> Vec<(Uuid, String)> {
    handle
        .admin
        .query(
            "SELECT subject_id, source_kind FROM private.memory_subjects WHERE memory_id = $1 ORDER BY subject_id",
            &[&memory],
        )
        .expect("owner reads memory_subjects")
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect()
}

/// Issue #109, §6.1.3 rule 3b (migration 0256): subject inheritance keys on the correction transition, the predicate
/// A3' uses, through the real governance ops. M0 -> M1 -> M2 are two corrections, so M1 and M2 are correction-born;
/// M2 carries a subject M1 lacks and X carries one M1 lacks. (iii) the correction M0 -> M1 inherits M0's subject;
/// (ii) `memory.restore` of M1 (M2 superseded by M1) gives M1 nothing from M2; (i) `memory.supersede` of X onto the
/// correction-born M1 gives it nothing from X.
#[test]
fn g_109_subject_inheritance_keys_on_the_correction_transition() {
    run_db_fixture::<Fixture, _>(
        "g_109_subject_inheritance_keys_on_the_correction_transition",
        |mut handle| {
            let governor = Governor::seed(&mut handle.admin, handle.tenant_id);
            governor.join(&mut handle.admin, handle.workspace_id);
            let [shared, extra, other] =
                ["g109 shared", "g109 extra", "g109 other"].map(|name| subject(&mut handle, name));
            let e0 = put(&handle, "g109-e0", Some(INSIDE), None);
            let ex = put(&handle, "g109-ex", Some(INSIDE), None);
            let m0 = commit_memory(&handle, e0);
            let x = commit_memory(&handle, ex);
            declare_subject(&mut handle, m0, shared);
            declare_subject(&mut handle, x, other);
            let scope = governor.scope(handle.workspace_id);
            let stream = governance_ops::stream(handle.tenant_id, handle.workspace_id);
            let correct = |handle: &Handle, memory: Uuid| {
                governance_ops::correct(
                    &handle.rt,
                    &handle.runtime,
                    &scope,
                    &stream,
                    memory,
                    "g109 corrected",
                )
                .expect("memory.correct")
                .new_memory_id
                .0
            };
            let m1 = correct(&handle, m0);
            let before = subject_links(&mut handle, m1);
            let m2 = correct(&handle, m1);
            declare_subject(&mut handle, m2, extra);
            governance_ops::restore(&handle.rt, &handle.runtime, &scope, &stream, m1)
                .expect("memory.restore");
            let restored = subject_links(&mut handle, m1);
            let supersede =
                governance_ops::supersede(&handle.rt, &handle.runtime, &scope, &stream, x, m1)
                    .map(|_| ());
            let superseded = subject_links(&mut handle, m1);
            let x_links = subject_links(&mut handle, x);
            purge(&mut handle);
            Governor::cleanup(&mut handle.admin, handle.tenant_id);
            assert_eq!(
                before,
                [(shared, "INHERITED".to_owned())],
                "(iii) the correction M0 -> M1 inherits M0's subject"
            );
            assert_eq!(
                x_links,
                [(other, "DECLARED".to_owned())],
                "X: one DECLARED subject, which M1 lacks"
            );
            assert_eq!(
                restored, before,
                "(ii) restoring the correction-born M1 gives it nothing from M2 ({extra})"
            );
            assert_eq!(
                (supersede, superseded),
                (Ok(()), before),
                "(i) a supersede of X onto the correction-born M1 commits and gives it nothing ({other})"
            );
        },
    );
}

/// G-M29-5(b), read path: a predecessor link revoked before the correction (P1, by retracting P1 CONTAINS T1) is not
/// inherited; the live one (P2) is.
#[test]
fn g_m29_5b_correction_inherits_live_links_only() {
    run_db_fixture::<Fixture, _>(
        "g_m29_5b_correction_inherits_live_links_only",
        |mut handle| {
            let w = World::new(&mut handle);
            let m1 = commit_memory(&handle, w.e1);
            let revoked = w.revise(&handle, &Validity::retracted(), &[handle.tenant_id], true);
            let (m2, e2) = w.correct(&handle, m1);
            let inherited = links(&mut handle, m2);
            World::cleanup(&mut handle);
            assert_eq!(
                revoked,
                Ok(w.revoked(&[m1])),
                "M1's P1 link is revoked first"
            );
            assert_eq!(
                inherited,
                [link(
                    w.p2,
                    SourceKind::Inherited,
                    RuleId::Correction1,
                    e2,
                    Some(m1)
                )],
                "only the live P2 link is inherited"
            );
        },
    );
}

/// G-M29-6: a CONTAINS correction of P1 → T1 revokes, inside its own transaction, every live task_run@1 row it
/// derived whose Evidence leaves the new window, including a private memory of another user whose decision Evidence
/// is that user's `USER_PRIVATE` Evidence (the owner definer sees neither through the Evidence tables, 0255 ⑥), and
/// nothing after a rollback. Decoys: a row whose Evidence stays inside the window, a row derived from T2, a DECLARED
/// row for P1 on E1, and another tenant's row on the same project, Evidence and task. A retraction revokes every
/// derived row.
#[test]
#[allow(clippy::too_many_lines)] // one fixture, its four decoys and three phases, read top to bottom
fn g_m29_6_relation_correction_revokes_in_its_transaction() {
    run_db_fixture::<Fixture, _>(
        "g_m29_6_relation_correction_revokes_in_its_transaction",
        |mut handle| {
            let w = World::new(&mut handle);
            let t2 = task(&handle);
            let run2 = claim(&handle, t2);
            let early = put(&handle, "t06b-g6-early", Some(EARLY), Some(&w.run));
            let late = put(&handle, "t06b-g6-late", Some(LATE), Some(&w.run));
            let via_t2 = put(&handle, "t06b-g6-t2", Some(INSIDE), Some(&run2));
            let private = put_private(&handle, "t06b-g6-private", INSIDE, &w.run);
            let seed = vec![relation(
                handle.tenant_id,
                Uuid::now_v7(),
                1,
                w.p1,
                t2,
                RelationKind::Contains,
                CONTAINS_WINDOW,
            )];
            commit(&mut handle, &seed);
            let targets = [
                commit_memory(&handle, w.e1),
                commit_memory(&handle, early),
                commit_memory(&handle, private),
            ];
            let inside = commit_memory(&handle, late);
            let other_task = commit_memory(&handle, via_t2);
            // Seeded after the targets, so only this Memory's A1 row wins over A3 on P1.
            let seed = vec![declared(&handle, w.e1, w.p1, SourceKind::Declared)];
            commit(&mut handle, &seed);
            let declared_row = commit_memory(&handle, w.e1);
            let other_tenant = Uuid::now_v7();
            handle
                .admin
                .batch_execute(&format!(
                    "SET session_replication_role = replica; \
                     INSERT INTO private.memory_projects (tenant_id, memory_id, project_id, relation, source_kind, \
                       rule_id_ver, decision_evidence_id, derived_task_id, derived_occurred_at) \
                     VALUES ('{other_tenant}', '{}', '{}', 'ATTRIBUTED_TO', 'INHERITED', 'task_run@1', '{}', '{}', \
                       to_timestamp({INSIDE})); \
                     SET session_replication_role = DEFAULT;",
                    Uuid::now_v7(),
                    w.p1,
                    w.e1,
                    w.t1.0
                ))
                .expect("owner plants another tenant's row");
            let decoys = [inside, other_task, declared_row].map(|m| links(&mut handle, m));
            let tenants = [handle.tenant_id, other_tenant];
            let narrowed = w.revise(&handle, &window(NARROWED), &tenants, false);
            let after_rollback: i64 = handle
                .admin
                .query_one(
                    "SELECT count(*) FROM private.memory_project_revocations WHERE tenant_id = ANY($1)",
                    &[&tenants.to_vec()],
                )
                .expect("owner counts revocations")
                .get(0);
            let retracted = w.revise(&handle, &Validity::retracted(), &tenants, false);
            handle
                .admin
                .batch_execute(&format!(
                    "SET session_replication_role = replica; \
                     DELETE FROM private.memory_projects WHERE tenant_id = '{other_tenant}'; \
                     SET session_replication_role = DEFAULT;"
                ))
                .expect("owner removes the planted row");
            World::cleanup(&mut handle);
            assert_eq!(
                decoys,
                [
                    vec![link(
                        w.p1,
                        SourceKind::Inherited,
                        RuleId::TaskRun1,
                        late,
                        None
                    )],
                    vec![link(
                        w.p1,
                        SourceKind::Inherited,
                        RuleId::TaskRun1,
                        via_t2,
                        None
                    )],
                    vec![
                        link(w.p1, SourceKind::Declared, RuleId::Declared1, w.e1, None),
                        link(w.p2, SourceKind::Declared, RuleId::Declared1, w.e1, None),
                    ],
                ],
                "the decoys hold the rows they decoy"
            );
            assert_eq!(
                narrowed,
                Ok(w.revoked(&targets)),
                "before COMMIT: exactly the derived rows whose Evidence left the window, the private one included"
            );
            assert_eq!(
                after_rollback, 0,
                "a rolled-back correction leaves no revocation"
            );
            assert_eq!(
                retracted,
                Ok(w.revoked(&[targets[0], targets[1], targets[2], inside])),
                "a retraction revokes every row the edge derived"
            );
        },
    );
}

/// G-M29-6, transitive: correcting first (A3' copies the P1 link) and then retracting P1 CONTAINS T1 revokes the
/// inherited rows as well, at both levels of a two-correction chain, with the same `revoked_by` and `reason`.
#[test]
fn g_m29_6_revocation_follows_the_inheritance_chain() {
    run_db_fixture::<Fixture, _>(
        "g_m29_6_revocation_follows_the_inheritance_chain",
        |mut handle| {
            let w = World::new(&mut handle);
            let m1 = commit_memory(&handle, w.e1);
            let (m2, e2) = w.correct(&handle, m1);
            let (m3, e3) = w.correct(&handle, m2);
            let chain = [m2, m3].map(|m| links(&mut handle, m).remove(0));
            let revoked = w.revise(&handle, &Validity::retracted(), &[handle.tenant_id], false);
            World::cleanup(&mut handle);
            assert_eq!(
                chain,
                [
                    link(
                        w.p1,
                        SourceKind::Inherited,
                        RuleId::Correction1,
                        e2,
                        Some(m1)
                    ),
                    link(
                        w.p1,
                        SourceKind::Inherited,
                        RuleId::Correction1,
                        e3,
                        Some(m2)
                    ),
                ],
                "the chain M1 -> M2 -> M3 carries P1"
            );
            assert_eq!(
                revoked,
                Ok(w.revoked(&[m1, m2, m3])),
                "the A3 row and both inherited levels are revoked"
            );
        },
    );
}

/// The SQLSTATE `sql` fails with as the owner when the session tenant is a fresh uuid, or `None` when it succeeds.
fn refusal_under_another_session_tenant(handle: &mut Handle, sql: &str) -> Option<String> {
    let mut txn = handle.admin.transaction().expect("owner transaction");
    let outcome = txn.batch_execute(&format!(
        "SELECT set_config('humaux.tenant_id', '{}', true); {sql}",
        Uuid::now_v7()
    ));
    drop(txn);
    outcome
        .err()
        .and_then(|e| e.code().map(|c| c.code().to_owned()))
}

/// Both 0255 definers refuse a row whose tenant is not the session tenant (42501) before reading anything with the
/// owner's rights: a relation correction and a revocation, each written by the owner (who passes the tables' RLS)
/// under another session tenant.
#[test]
fn revocation_definers_refuse_another_session_tenant() {
    run_db_fixture::<Fixture, _>(
        "revocation_definers_refuse_another_session_tenant",
        |mut handle| {
            let w = World::new(&mut handle);
            let m1 = commit_memory(&handle, w.e1);
            let t = handle.tenant_id;
            let probes = [
                relation(t, w.r1, 2, w.p1, w.t1, RelationKind::Contains, "{}"),
                format!(
                    "INSERT INTO private.memory_project_revocations (tenant_id, memory_id, project_id, revoked_by, \
                       reason) VALUES ('{t}', '{m1}', '{}', 'rule:fixture@1', 'pin probe')",
                    w.p1
                ),
            ];
            let refused = probes.map(|sql| refusal_under_another_session_tenant(&mut handle, &sql));
            World::cleanup(&mut handle);
            assert_eq!(
                refused,
                [Some("42501".to_owned()), Some("42501".to_owned())],
                "relation correction, then revocation"
            );
        },
    );
}

/// `(memory, project, rule, derived_task_id, derived_occurred_at in epoch seconds)` of one `memory_projects` row.
type Ground = (Uuid, Uuid, String, Option<Uuid>, Option<i64>);

/// 0255 ⑥: A3 records its ground on the row (A1 records none); the migration's backfill UPDATE, run verbatim on this
/// tenant's rows (the CI database is empty when 0255 runs), restates exactly that ground; and the CHECK refuses a
/// task_run@1 row without one and a declared@1 row with one. Replica mode stands in for the migration's DISABLE TRIGGER memory_projects_immutable.
#[test]
fn backfill_restates_the_a3_ground_and_the_check_requires_it() {
    const GROUND: &str = "SELECT memory_id, project_id, rule_id_ver, derived_task_id, \
           extract(epoch FROM derived_occurred_at)::bigint \
           FROM private.memory_projects WHERE tenant_id = $1 ORDER BY memory_id, project_id";
    let migration = include_str!("../../../migrations/0255_attribution_correction_revocation.sql");
    assert_eq!(
        migration
            .matches("UPDATE private.memory_projects mp")
            .count(),
        1
    );
    let (_, rest) = migration
        .split_once("UPDATE private.memory_projects mp")
        .expect("0255's backfill");
    let (body, _) = rest.split_once(';').expect("one statement");
    let backfill = format!("UPDATE private.memory_projects mp{body} AND mp.tenant_id = $1");
    run_db_fixture::<Fixture, _>(
        "backfill_restates_the_a3_ground_and_the_check_requires_it",
        |mut handle| {
            let w = World::new(&mut handle);
            let early = put(&handle, "t06b-bf-early", Some(EARLY), Some(&w.run));
            let m1 = commit_memory(&handle, w.e1);
            let m2 = commit_memory(&handle, early);
            let t = handle.tenant_id;
            let ran = |rule: RuleId| rule.as_str().to_owned();
            let mut expected: Vec<Ground> = vec![
                (m1, w.p1, ran(RuleId::TaskRun1), Some(w.t1.0), Some(INSIDE)),
                (m1, w.p2, ran(RuleId::Declared1), None, None),
                (m2, w.p1, ran(RuleId::TaskRun1), Some(w.t1.0), Some(EARLY)),
            ];
            expected.sort();
            let mut txn = handle.admin.transaction().expect("owner transaction");
            txn.batch_execute("SET LOCAL session_replication_role = replica")
                .expect("replica mode");
            let before: Vec<Ground> = txn
                .query(GROUND, &[&t])
                .expect("ground before")
                .iter()
                .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4)))
                .collect();
            let updated = txn.execute(backfill.as_str(), &[&t]).expect("the backfill");
            let after: Vec<Ground> = txn
                .query(GROUND, &[&t])
                .expect("ground after")
                .iter()
                .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4)))
                .collect();
            // Each probe in its own savepoint, so the first refusal does not abort the second.
            let refused: Vec<Option<String>> = [
                format!(
                    "UPDATE private.memory_projects SET derived_task_id = NULL, derived_occurred_at = NULL \
                      WHERE tenant_id = '{t}' AND memory_id = '{m1}' AND project_id = '{}'",
                    w.p1
                ),
                format!(
                    "UPDATE private.memory_projects SET derived_task_id = '{}', \
                       derived_occurred_at = to_timestamp({INSIDE}) \
                      WHERE tenant_id = '{t}' AND memory_id = '{m1}' AND project_id = '{}'",
                    w.t1.0, w.p2
                ),
            ]
            .iter()
            .map(|sql| {
                let mut savepoint = txn.transaction().expect("savepoint");
                savepoint
                    .batch_execute(sql)
                    .err()
                    .and_then(|e| e.code().map(|c| c.code().to_owned()))
            })
            .collect();
            drop(txn);
            World::cleanup(&mut handle);
            assert_eq!(
                before, expected,
                "A3 records task and occurred_at, A1 nothing"
            );
            assert_eq!(
                (updated, after),
                (2, expected),
                "the backfill restates both task_run@1 rows"
            );
            assert_eq!(
                refused,
                [Some("23514".to_owned()), Some("23514".to_owned())],
                "a task_run@1 row without ground; a declared@1 row with one"
            );
        },
    );
}

/// G-T06c-2 (ADR-0078 D-D rung A1, end to end): a put declaring a visible project writes its one DECLARED
/// `evidence_projects` row through T06c's door, and the Memory the Distill door then makes from that Evidence carries
/// exactly one `memory_projects` row: that project, DECLARED / declared@1, decided by that Evidence. A second visible
/// project of the tenant, declared by nothing, stays out.
#[test]
fn g_t06c_2_declared_project_end_to_end() {
    run_db_fixture::<Fixture, _>("g_t06c_2_declared_project_end_to_end", |mut handle| {
        handle.seed_current_entitlement_and_window(10);
        let [p, decoy] = [(); 2].map(|()| Uuid::now_v7());
        for sql in [project(&handle, p), project(&handle, decoy)] {
            handle
                .admin
                .batch_execute(&sql)
                .expect("owner commits a visible project");
        }
        let evidence = put_with(&handle, "t06c-2", Some(INSIDE), None, Some(p));
        let declared: Vec<(Uuid, Uuid, String)> = handle
            .admin
            .query(
                "SELECT evidence_id, project_id, source_kind FROM private.evidence_projects WHERE tenant_id = $1",
                &[&handle.tenant_id],
            )
            .expect("owner reads evidence_projects")
            .iter()
            .map(|r| (r.get(0), r.get(1), r.get(2)))
            .collect();
        let rows = attribute(&handle, evidence, &[]);
        handle
            .admin
            .batch_execute(&format!(
                "DELETE FROM private.evidence_projects WHERE tenant_id = '{}'",
                handle.tenant_id
            ))
            .expect("purge evidence_projects");
        assert_eq!(
            declared,
            [(evidence, p, SourceKind::Declared.as_str().to_owned())]
        );
        assert_eq!(
            rows,
            Ok(vec![row(
                p,
                SourceKind::Declared,
                RuleId::Declared1,
                evidence
            )]),
            "the declared project only, DECLARED / declared@1, decided by the put's Evidence"
        );
    });
}

/// One call of 0254's reader with a one-workspace authorized set.
async fn visible(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: Uuid,
    project: Uuid,
    workspace: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT private.declared_project_visible($1, $2, $3)")
        .bind(tenant)
        .bind(project)
        .bind(vec![workspace])
        .fetch_one(&mut **txn)
        .await
}

/// G-T06c-1, tenant leg (0254 `private.declared_project_visible`). On the wire a foreign project's workspace is never
/// in the caller's set, so the workspace predicate alone already refuses it; here the reader is called as
/// `role_gateway` with the foreign workspace in the set, so only the tenant predicate refuses it. The tenant's own
/// project in its own workspace is the positive control, and a tenant argument other than the transaction's
/// `humaux.tenant_id` is 42501. All rows live in one rolled-back transaction.
#[test]
fn g_t06c_1_reader_tenant_leg() {
    run_db_fixture::<Fixture, _>("g_t06c_1_reader_tenant_leg", |handle| {
        let dsn = std::env::var("HUMAUX_TEST_PG_DSN").expect("the fixture ran, so the DSN is set");
        let (foreign_tenant, foreign_workspace) = (Uuid::new_v4(), Uuid::new_v4());
        let [own, foreign] = [(); 2].map(|()| Uuid::now_v7());
        let seed = [
            project(&handle, own),
            format!(
                "INSERT INTO control.tenants (tenant_id, name, state) \
                 VALUES ('{foreign_tenant}', 't06c-foreign-{foreign_tenant}', 'ACTIVE')"
            ),
            format!(
                "INSERT INTO control.workspaces (workspace_id, tenant_id, name) \
                 VALUES ('{foreign_workspace}', '{foreign_tenant}', 't06c foreign')"
            ),
            format!(
                "INSERT INTO private.continuity_projects (project_id, tenant_id, workspace_id, title) \
                 VALUES ('{foreign}', '{foreign_tenant}', '{foreign_workspace}', 'Same title')"
            ),
        ];
        let (own_visible, foreign_visible, wrong_tenant) = handle.rt.block_on(async {
            // dep: PostgreSQL(owner) — test opens a direct PG connection for setup/verification
            let mut conn = PgConnection::connect(&dsn).await.expect("owner connection");
            // dep: PostgreSQL(any) — pool/txn query execution
            let mut txn = conn.begin().await.expect("begin");
            for sql in &seed {
                sqlx::query(sql)
                    .execute(&mut *txn)
                    .await
                    .expect("owner seeds the reader fixture");
            }
            // dep: PostgreSQL(role_gateway) — test switches PG role to exercise the reader's EXECUTE grant
            sqlx::query("SET LOCAL ROLE role_gateway")
                .execute(&mut *txn)
                .await
                .expect("gateway role");
            sqlx::query("SELECT set_config('humaux.tenant_id', $1, true)")
                .bind(handle.tenant_id.to_string())
                .execute(&mut *txn)
                .await
                .expect("tenant GUC");
            let own_visible = visible(&mut txn, handle.tenant_id, own, handle.workspace_id)
                .await
                .expect("own project");
            let foreign_visible = visible(&mut txn, handle.tenant_id, foreign, foreign_workspace)
                .await
                .expect("foreign project under the caller's tenant");
            let wrong_tenant = visible(&mut txn, foreign_tenant, foreign, foreign_workspace)
                .await
                .err()
                .and_then(|e| {
                    e.as_database_error()
                        .and_then(|d| d.code())
                        .map(|c| c.into_owned())
                });
            txn.rollback().await.expect("rollback");
            (own_visible, foreign_visible, wrong_tenant)
        });
        assert!(
            own_visible,
            "positive control: the tenant's ACTIVE project in its own workspace"
        );
        assert!(
            !foreign_visible,
            "another tenant's project, its workspace in the set: refused by the tenant leg"
        );
        assert_eq!(
            wrong_tenant.as_deref(),
            Some("42501"),
            "tenant argument != humaux.tenant_id"
        );
    });
}

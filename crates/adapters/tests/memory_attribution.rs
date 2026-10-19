//! `adapters::tests::memory_attribution` — M29 T06a (ADR-0078 D-D, §6.1.4): the ladder behind M07's attribution port
//!   writes exactly the formal `memory_projects` rows that rungs A1 and A3 ground on the Memory's attribution Evidence,
//!   and nothing when no rung holds.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, serde_json, sqlx];
//!   services=[PostgreSQL(owner) r=[private.memory_projects] w=[coord.task_runs, private.continuity_projects,
//!   private.distill_candidates, private.evidence_projects, private.evidence_task_runs, private.memory_projects,
//!   private.project_task_relations], PostgreSQL(role_gateway), PostgreSQL(role_private_worker)];
//!   env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::attribution_repo, adapters::coord_repo, adapters::distill_repo,
//!   adapters::memory_repo, adapters::operation_receipt, adapters::remember,
//!   adapters::tests::support::governance_ops, adapters::tests::support::operation_receipt_fixture,
//!   domain::attribution, domain::audit, domain::authority, domain::confirm, domain::evidence, domain::ids,
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
//!
//! called-by: `cargo test -p humaux-adapters --test memory_attribution`.

// Both fixtures (`operation_receipt_fixture`, `governance_ops`) carry their own `#[path] mod token_keys`; this test loads
// both, and `token_keys::install` is idempotent per process, so the second copy is inert.
#![allow(clippy::duplicate_mod)]

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

use humaux_adapters::{
    attribution_repo::AttributionLadder,
    coord_repo::{self, ClaimedTaskRun},
    distill_repo::{self, ConfirmOutcome, ConfirmRequest},
    memory_repo::{self, AttributionSource, NewMemory},
    operation_receipt::{self, AtomicRememberRequest},
    remember::RememberCommand,
};
use humaux_domain::{
    attribution::{RuleId, SourceKind},
    audit::{AuditEvent, AuditEventId, AuditMetadata, McpAuditAction},
    authority::AuthorityClass,
    confirm::DestructiveOp,
    evidence::{EvidenceOriginClass, payload_sha256},
    ids::{TaskId, TenantId, WorkspaceId},
    memory::MemoryType,
    relation::RelationKind,
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
    handle
        .rt
        .block_on(operation_receipt::remember_for_task_run_atomically(
            &handle.runtime,
            &handle.auth,
            request(handle, key, occurred_at),
            run.map(|r| (r.task_run_id, r.fencing_token)),
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

/// One `project_task_relations` revision; `valid` is a multirange literal (`{}` retracts). `authorization` must be an
/// Evidence of `tenant` (0253's FK): the test's put.
#[allow(clippy::too_many_arguments)] // one argument per fixture column
fn relation(
    tenant: Uuid,
    relation: Uuid,
    revision: i64,
    project: Uuid,
    task: TaskId,
    kind: RelationKind,
    valid: &str,
    authorization: Uuid,
) -> String {
    format!(
        "INSERT INTO private.project_task_relations (tenant_id, relation_id, revision, src_id, dst_id, \
           relation_kind, valid, decided_by, factual_evidence_ids, authorization_evidence_id) \
         VALUES ('{tenant}', '{relation}', {revision}, '{project}', '{}', '{}', '{valid}', 'rule:fixture@1', \
           '{{}}', '{authorization}')",
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
        for sql in seed {
            sqlx::query(sql)
                .execute(&mut *txn)
                .await
                .expect("owner seeds the attribution fixture");
        }
        // dep: PostgreSQL(role_private_worker) — test switches PG role to exercise RLS
        sqlx::query("SET LOCAL ROLE role_private_worker")
            .execute(&mut *txn)
            .await
            .expect("private worker role");
        let loaded = distill_repo::load_evidence(
            &mut txn,
            handle.tenant_id,
            handle.reasoning_domain_id,
            handle.user_id,
            evidence,
        )
        .await
        .expect("load_evidence")
        .expect("the put's Evidence");
        let content = serde_json::json!({"fact": "memory-attribution fixture"});
        let memory = memory_repo::insert_memory_in_txn(
            &mut txn,
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
        .await
        .map_err(|e| e.to_string())?;
        sqlx::query("RESET ROLE")
            .execute(&mut *txn)
            .await
            .expect("back to the owner");
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

/// The fixture's teardown knows neither the carrier, `coord.task_runs`, nor the append-only attribution and relation
/// rows a committed test leaves (replica mode lets the owner past their append-only triggers).
fn purge(handle: &mut Handle) {
    let t = handle.tenant_id;
    handle
        .admin
        .batch_execute(&format!(
            "SET session_replication_role = replica; \
             DELETE FROM private.memory_projects WHERE tenant_id = '{t}'; \
             DELETE FROM private.project_task_relations WHERE tenant_id = '{t}'; \
             SET session_replication_role = DEFAULT; \
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
            relation(
                t,
                r1,
                1,
                p1,
                t1,
                RelationKind::Contains,
                CONTAINS_WINDOW,
                inside,
            ),
            relation(
                t,
                r2,
                1,
                p2,
                t1,
                RelationKind::References,
                OPEN_WINDOW,
                inside,
            ),
            relation(
                t,
                r3,
                1,
                p3,
                t2,
                RelationKind::Contains,
                CONTAINS_WINDOW,
                inside,
            ),
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
        retracted.push(relation(
            t,
            r1,
            2,
            p1,
            t1,
            RelationKind::Contains,
            "{}",
            inside,
        ));
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
            relation(
                t,
                r1,
                1,
                p1,
                t1,
                RelationKind::Contains,
                OPEN_WINDOW,
                inside,
            ),
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
                evidence,
            ),
            relation(
                t,
                Uuid::now_v7(),
                1,
                pb,
                t1,
                RelationKind::Contains,
                OPEN_WINDOW,
                evidence,
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
            relation(
                t,
                r1,
                1,
                p1,
                t1,
                RelationKind::Contains,
                CONTAINS_WINDOW,
                e1,
            ),
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

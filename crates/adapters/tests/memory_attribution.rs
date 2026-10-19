//! `adapters::tests::memory_attribution` — M29 T06a (ADR-0078 D-D, §6.1.4): the ladder behind M07's attribution port
//!   writes exactly the formal `memory_projects` rows that rungs A1 and A3 ground, and nothing when no rung holds.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, postgres, serde_json, sqlx];
//!   services=[PostgreSQL(owner) r=[private.memory_projects] w=[coord.task_runs,
//!   private.continuity_projects, private.evidence_projects, private.evidence_task_runs,
//!   private.project_task_relations], PostgreSQL(role_gateway), PostgreSQL(role_private_worker)];
//!   env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::attribution_repo, adapters::coord_repo, adapters::distill_repo,
//!   adapters::memory_repo, adapters::operation_receipt, adapters::remember,
//!   adapters::tests::support::operation_receipt_fixture, domain::attribution, domain::audit, domain::authority,
//!   domain::evidence, domain::ids, domain::memory, domain::relation, domain::subject, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [Evidence enters through the real `remember.put` (the T04c path when it carries a run); the Memory
//!   enters through the real door under role_private_worker with the real ladder; projects, relations and declared
//!   rows are seeded by the owner inside the same rolled-back transaction, and rows are counted by the owner so no
//!   RLS can hide one]
//! Spec: Baseline §6.1.4; §78.2; §79.2; §80.1; ADR-0078 D-D
//!
//! | test | gate | injected fault that turns it red |
//! |---|---|---|
//! | `g_m29_1_source_kind_and_rule_checks_match_domain` | G-M29-1 (source_kind part) | a DB-only `source_kind` value |
//! | `g_t06a_a3_inherits_only_current_contains` | G-T06a-A3 | drop `valid @> occurred_at` from A3 |
//! | `g_t06a_a1_declared_project` | G-T06a-A1 | skip A1 |
//! | `g_n09_3_unknown_stays_unknown` | G-N09-3 | A1 takes the most recently related project |
//!
//! called-by: `cargo test -p humaux-adapters --test memory_attribution`.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

use humaux_adapters::{
    attribution_repo::AttributionLadder,
    coord_repo, distill_repo,
    memory_repo::{self, NewMemory},
    operation_receipt::{self, AtomicRememberRequest},
    remember::RememberCommand,
};
use humaux_domain::{
    attribution::{RuleId, SourceKind},
    audit::{AuditEvent, AuditEventId, AuditMetadata, McpAuditAction},
    authority::AuthorityClass,
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

use operation_receipt_fixture::{
    DOMAIN, Fixture, Handle, OPERATION, PROJECTION_KIND, PROJECTION_VERSION,
};

/// `(project_id, source_kind, rule_id_ver, decision_evidence_id)` of one `memory_projects` row.
type Row = (Uuid, String, String, Uuid);

/// 2026-01-15T00:00:00Z: inside P1's CONTAINS window `[2026-01-01, 2026-02-01)`.
const INSIDE: i64 = 1_768_435_200;
/// 2026-03-01T00:00:00Z: after P1's window, still inside P2's open REFERENCES window.
const OUTSIDE: i64 = 1_772_323_200;
const CONTAINS_WINDOW: &str = "{[2026-01-01 00:00:00+00,2026-02-01 00:00:00+00)}";
const OPEN_WINDOW: &str = "{[2026-01-01 00:00:00+00,)}";

fn request(handle: &Handle, key: &str, occurred_at: i64) -> AtomicRememberRequest {
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
            occurred_at: Some(
                OffsetDateTime::from_unix_timestamp(occurred_at).expect("fixture instant"),
            ),
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
fn put(
    handle: &Handle,
    key: &str,
    occurred_at: i64,
    run: Option<&coord_repo::ClaimedTaskRun>,
) -> Uuid {
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

fn project(handle: &Handle, project: Uuid) -> String {
    // N09-3's ambiguity: every fixture project has the same title in the same workspace.
    format!(
        "INSERT INTO private.continuity_projects (project_id, tenant_id, workspace_id, title) \
         VALUES ('{project}', '{}', '{}', 'Same title')",
        handle.tenant_id, handle.workspace_id
    )
}

/// One `project_task_relations` revision; `valid` is a multirange literal (`{}` retracts).
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
           '{{}}', '{relation}')",
        task.0,
        kind.as_str()
    )
}

/// One rolled-back transaction: the owner runs `seed`, then the private worker's distill hop loads `evidence` and
/// inserts one Memory through the door with the real ladder; returns that Memory's rows, read back as the owner.
fn attribute(handle: &Handle, evidence: Uuid, seed: &[String]) -> Vec<Row> {
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
            },
            &AttributionLadder,
        )
        .await
        .expect("door");
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
        rows
    })
}

/// The fixture's teardown knows neither the carrier nor `coord.task_runs`.
fn purge_runs(handle: &mut Handle) {
    for sql in [
        "DELETE FROM private.evidence_task_runs WHERE tenant_id = $1",
        "DELETE FROM coord.task_runs WHERE tenant_id = $1",
    ] {
        handle
            .admin
            .execute(sql, &[&handle.tenant_id])
            .expect("purge carrier and runs");
    }
}

/// G-M29-1, source_kind part (§78.2): each 0252 CHECK literal set equals its Rust closed set.
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

/// G-T06a-A3: a put on a claimed run of T1 inherits P1 (CONTAINS) and never P2 (REFERENCES); an Evidence outside P1's
/// window, or after P1's relation was retracted, inherits nothing.
#[test]
fn g_t06a_a3_inherits_only_current_contains() {
    run_db_fixture::<Fixture, _>("g_t06a_a3_inherits_only_current_contains", |mut handle| {
        handle.seed_current_entitlement_and_window(10);
        let task = handle
            .rt
            .block_on(coord_repo::submit(
                &handle.runtime,
                &handle.auth,
                "memory_attribution",
                "M29 T06a gate",
            ))
            .expect("submit T1");
        let run = handle
            .rt
            .block_on(coord_repo::claim(
                &handle.runtime,
                &handle.auth,
                task,
                Duration::from_secs(300),
            ))
            .expect("claim T1");
        let inside = put(&handle, "t06a-a3-inside", INSIDE, Some(&run));
        let outside = put(&handle, "t06a-a3-outside", OUTSIDE, Some(&run));

        let (p1, p2, r1, r2) = (
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
        );
        let t = handle.tenant_id;
        let seed = vec![
            project(&handle, p1),
            project(&handle, p2),
            relation(t, r1, 1, p1, task, RelationKind::Contains, CONTAINS_WINDOW),
            relation(t, r2, 1, p2, task, RelationKind::References, OPEN_WINDOW),
        ];
        assert_eq!(
            attribute(&handle, inside, &seed),
            [(
                p1,
                SourceKind::Inherited.as_str().to_owned(),
                RuleId::TaskRun1.as_str().to_owned(),
                inside,
            )],
            "P1 only, INHERITED / task_run@1, decided by the put's Evidence"
        );
        assert_eq!(
            attribute(&handle, outside, &seed),
            Vec::<Row>::new(),
            "occurred_at outside P1's CONTAINS window"
        );
        let mut retracted = seed.clone();
        retracted.push(relation(t, r1, 2, p1, task, RelationKind::Contains, "{}"));
        assert_eq!(
            attribute(&handle, inside, &retracted),
            Vec::<Row>::new(),
            "P1's current revision is retracted"
        );
        purge_runs(&mut handle);
    });
}

/// G-T06a-A1: a DECLARED `evidence_projects` row (fixture SQL; its writer is T06c) is one DECLARED / declared@1 row.
#[test]
fn g_t06a_a1_declared_project() {
    run_db_fixture::<Fixture, _>("g_t06a_a1_declared_project", |mut handle| {
        handle.seed_current_entitlement_and_window(10);
        let evidence = put(&handle, "t06a-a1", INSIDE, None);
        let p = Uuid::now_v7();
        let seed = vec![
            project(&handle, p),
            format!(
                "INSERT INTO private.evidence_projects (tenant_id, evidence_id, project_id, source_kind) \
                 VALUES ('{}', '{evidence}', '{p}', '{}')",
                handle.tenant_id,
                SourceKind::Declared.as_str()
            ),
        ];
        assert_eq!(
            attribute(&handle, evidence, &seed),
            [(
                p,
                SourceKind::Declared.as_str().to_owned(),
                RuleId::Declared1.as_str().to_owned(),
                evidence,
            )]
        );
    });
}

/// G-N09-3: two same-title projects in one workspace, both related to a task, and an Evidence with neither a
/// declared project nor a task run: the Memory stays unattributed (no title, recency or default guess).
#[test]
fn g_n09_3_unknown_stays_unknown() {
    run_db_fixture::<Fixture, _>("g_n09_3_unknown_stays_unknown", |mut handle| {
        handle.seed_current_entitlement_and_window(10);
        let task = handle
            .rt
            .block_on(coord_repo::submit(
                &handle.runtime,
                &handle.auth,
                "memory_attribution",
                "M29 T06a gate",
            ))
            .expect("submit");
        let evidence = put(&handle, "n09-3", INSIDE, None);
        let (pa, pb) = (Uuid::now_v7(), Uuid::now_v7());
        let t = handle.tenant_id;
        let seed = vec![
            project(&handle, pa),
            project(&handle, pb),
            relation(
                t,
                Uuid::now_v7(),
                1,
                pa,
                task,
                RelationKind::Contains,
                OPEN_WINDOW,
            ),
            relation(
                t,
                Uuid::now_v7(),
                1,
                pb,
                task,
                RelationKind::Contains,
                OPEN_WINDOW,
            ),
        ];
        assert_eq!(attribute(&handle, evidence, &seed), Vec::<Row>::new());
    });
}

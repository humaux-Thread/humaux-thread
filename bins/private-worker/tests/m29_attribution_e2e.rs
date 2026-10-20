//! `private-worker::tests::m29_attribution_e2e` — M29 T07 (ADR-0078 D-D / D-E, design v0.2 §15.8): the first end to
//!   end run of the work-attribution axis. Real `remember.put`s (`operation_receipt::remember_*_atomically`) feed the
//!   real Distill hop (`distill::dispatch_pass`, key-free provider), the ladder writes `memory_projects`, a real
//!   correction and a real relation correction move it, and the one reader (`attribution_repo::read_memory_attribution`)
//!   reports it from `private.memory_projects_live`.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-gateway, humaux-private-worker, humaux-protocol,
//!   humaux-testkit, postgres, serde_json, sqlx, tokio]; services=[PostgreSQL(owner) r=[control.operation_receipts,
//!   ops.model_call_ledger, private.evidence_objects, private.evidence_projects, private.memory_evidence,
//!   private.memory_project_revocations, private.memory_projects, private.memory_records,
//!   private.project_task_relations] w=[control.private_reasoning_domains,
//!   control.tenants, ops.jobs, ops.provider_slots, private.continuity_projects] x=[control.set_workspace_membership],
//!   PostgreSQL(role_gateway), PostgreSQL(role_private_worker)]; env=[HUMAUX_PRIVATE_WORKER_CANDIDATE_TTL_SECONDS,
//!   HUMAUX_TEST_PG_DSN]; modules=[adapters::attribution_repo, adapters::coord_repo, adapters::operation_receipt,
//!   adapters::postgres, adapters::relation_repo, adapters::remember, adapters::tests::support::governance_ops,
//!   adapters::tests::support::operation_receipt_fixture, domain::attribution, domain::audit, domain::authority,
//!   domain::continuity, domain::error, domain::evidence, domain::identity, domain::ids, domain::relation,
//!   domain::subject,
//!   gateway::auth, humaux-testkit, private-worker::distill, private-worker::tests::support::dispatch_fence,
//!   private-worker::tests::support::distill_lane, private-worker::tests::support::live_minimax,
//!   private-worker::tests::support::live_provider, protocol::edge, testkit::fixture_purge]
//! Called-by: [cargo-test]
//! Invariants: [every write goes through its production path (put, Distill, correction, relation revision, PAT
//!   authentication); the owner only seeds projects and the admission lane and counts rows; one test, run alone
//!   (nextest global-db), with foreign scheduler rows fenced; the fixture tenants are purged before their handles drop]
//! Spec: Baseline §6.1.4; §52; §79.2; §80.1; ADR-0078 D-D, D-E
//!
//! | step | gate | injected fault that turns it red (ADR-0078 "Red records", M29 T07) |
//! |---|---|---|
//! | 2: M3 stays unresolved, P3 has no row | G-N09-3 | A1 falls back to the most recently created project |
//! | 2: M2 gets P1 and P2 | A3 shared task | A3 keeps only the first project |
//! | 4: M2 / M2' lose P2 | reader reads the live view only | the reader reads `private.memory_projects` |
//! | 2, 7, end: provider calls == Distill jobs run | G-N09-4(b) | one more provider call before the Memory INSERT |
//! | end: tenant A == tenant B per message | G-N09-4(a) | A3 skips a project named in the memory text |
//! | 5: replay changes nothing | §34.0.1 replay | see ADR-0078 "Red records" |
//!
//! called-by: `cargo nextest run -p humaux-private-worker --test m29_attribution_e2e`.

// Both adapters fixtures carry their own `#[path] mod token_keys`; `token_keys::install` is idempotent per process.
#![allow(clippy::duplicate_mod)]

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::ops::Bound::{Included, Unbounded};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use humaux_adapters::{
    attribution_repo,
    coord_repo::{self, ClaimedTaskRun},
    operation_receipt::{self, AtomicRememberRequest, AtomicRememberResult},
    postgres::PrivateWorkerDbPool,
    relation_repo,
    remember::RememberCommand,
};
use humaux_domain::{
    attribution::{MemoryAttribution, ProjectLink, RuleId, SourceKind},
    audit::{AuditEvent, AuditEventId, AuditMetadata, McpAuditAction},
    authority::{EvidenceId, MemoryId},
    continuity::ProjectId,
    error::ErrorCode,
    evidence::{EvidenceOriginClass, payload_sha256},
    identity::{AuthorizationScope, PrincipalId},
    ids::{TaskId, TenantId, WorkspaceId},
    relation::{DecidedBy, RelationEdge, RelationId, RelationKind, Timestamp, Validity},
};
use humaux_gateway::auth::{CredentialScope, authenticate_service_credential};
use humaux_private_worker::distill::{DistillDispatchReport, dispatch_pass};
use humaux_protocol::edge::compute_api_key_hash;
use humaux_testkit::fixture_purge::purge_tenant_fixture_sql;
use humaux_testkit::{DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use sqlx::types::{Uuid, time::OffsetDateTime};
use sqlx::{Connection, PgConnection};

#[allow(dead_code)]
#[path = "support/dispatch_fence.rs"]
mod dispatch_fence;
#[allow(dead_code)]
#[path = "support/distill_lane.rs"]
mod distill_lane;
#[allow(dead_code)]
#[path = "../../../crates/adapters/tests/support/governance_ops.rs"]
mod governance_ops;
#[allow(dead_code)]
#[path = "support/live_minimax.rs"]
mod live_minimax;
#[allow(dead_code)]
#[path = "support/live_provider.rs"]
mod live_provider;
#[allow(dead_code)]
#[path = "../../../crates/adapters/tests/support/operation_receipt_fixture.rs"]
mod operation_receipt_fixture;

use distill_lane::{
    FAKE_RETRY_WAIT, FakeProvider, contribution_config, dispatch_config, dsn_as_role, routes,
};
use governance_ops::Governor;
use operation_receipt_fixture::{
    DOMAIN, Fixture, Handle, OPERATION, PROJECTION_KIND, PROJECTION_VERSION,
    SYNTHETIC_CREDENTIAL_PEPPER, SyntheticCredentialScopes, SyntheticServiceCredential,
};

const NAME: &str = "m29_attribution_e2e";
/// 2026-01-01T00:00:00Z: where both CONTAINS relations start (open-ended).
const OPEN_FROM: i64 = 1_767_225_600;
/// 2026-01-15T00:00:00Z: every message's occurrence time, inside the relations.
const INSIDE: i64 = 1_768_435_200;
/// Tenant A's memory text: names no project.
const REPLY_A: &str = r#"{"memories":[{"content":"Ship the landing page copy by Friday.","memory_type":"Decision","class":"PrivateKnowledge","confidence":0.9}]}"#;
/// Tenant B's memory text (G-N09-4(a)): different, and it names P1 / P3 ("Website A").
const REPLY_B: &str = r#"{"memories":[{"content":"Website A launch checklist reviewed.","memory_type":"Decision","class":"PrivateKnowledge","confidence":0.9}]}"#;

/// One `remember.put` message: idempotency key and text.
struct Msg {
    key: &'static str,
    text: &'static str,
}

/// m1 declares P1 (A1).
const M1: Msg = Msg {
    key: "m29-t07-m1",
    text: "Kickoff notes for the redesign.",
};
/// m2 carries the T1 run (A3, shared task).
const M2: Msg = Msg {
    key: "m29-t07-m2",
    text: "Drafted the hero section.",
};
/// m3 has no ground, and its text names P1 / P3 (G-N09-3).
const M3: Msg = Msg {
    key: "m29-t07-m3",
    text: "Website A needs a new footer.",
};
/// m4 carries the T1 run after P2 CONTAINS T1 was retracted (the fault step).
const M4: Msg = Msg {
    key: "m29-t07-m4",
    text: "Fixed the footer links.",
};
/// The refused puts of step 6 (never written).
const M5: Msg = Msg {
    key: "m29-t07-m5",
    text: "Written with a revoked key.",
};
const M6: Msg = Msg {
    key: "m29-t07-m6",
    text: "Written while suspended from the workspace.",
};

/// One tenant's fixture: P1 "Website A", P2, the same-name trap P3 (no relation), T1 with a live run of U.
struct World {
    p1: Uuid,
    p2: Uuid,
    p3: Uuid,
    t1: TaskId,
    run: ClaimedTaskRun,
}

impl World {
    /// The fixture role of `project`.
    fn role(&self, project: ProjectId) -> &'static str {
        match project.0 {
            p if p == self.p1 => "P1",
            p if p == self.p2 => "P2",
            p if p == self.p3 => "P3",
            _ => "foreign",
        }
    }
}

fn admin_dsn() -> String {
    std::env::var("HUMAUX_TEST_PG_DSN").expect("the fixture ran, so the DSN is set")
}

/// Step 1 for one tenant: the purgeable name, the Distill admission lane on the tenant's reasoning domain, the three
/// projects (P3 last) and T1 with a live run claimed by U.
fn fixture(h: &mut Handle) -> World {
    h.admin
        .execute(
            "UPDATE control.tenants SET name = $2 WHERE tenant_id = $1",
            &[&h.tenant_id, &format!("e2e-fixture {NAME} {}", h.tenant_id)],
        )
        .expect("fixture tenant name (fixture_purge predicate)");
    h.admin
        .execute(
            "UPDATE control.private_reasoning_domains SET owner_user_id = $2 WHERE reasoning_domain_id = $1",
            &[&h.reasoning_domain_id, &h.user_id],
        )
        .expect("reasoning domain owner");
    distill_lane::seed_admission_lane(
        &mut h.admin,
        h.tenant_id,
        h.user_id,
        h.reasoning_domain_id,
        NAME,
    );
    let [p1, p2, p3] = [(); 3].map(|()| Uuid::now_v7());
    for (project, title) in [(p1, "Website A"), (p2, "Website B"), (p3, "Website A")] {
        h.admin
            .execute(
                "INSERT INTO private.continuity_projects (project_id, tenant_id, workspace_id, title) \
                 VALUES ($1, $2, $3, $4)",
                &[&project, &h.tenant_id, &h.workspace_id, &title],
            )
            .expect("project");
    }
    let t1 =
        h.rt.block_on(coord_repo::submit(
            &h.runtime,
            &h.auth,
            NAME,
            "Website A launch",
        ))
        .expect("submit T1");
    let run =
        h.rt.block_on(coord_repo::claim(
            &h.runtime,
            &h.auth,
            t1,
            Duration::from_secs(900),
        ))
        .expect("claim T1");
    World {
        p1,
        p2,
        p3,
        t1,
        run,
    }
}

/// A `remember.put` request of `msg` by `auth` in the fixture workspace, occurring at [`INSIDE`].
fn request(h: &Handle, auth: &AuthorizationScope, msg: &Msg) -> AtomicRememberRequest {
    let request_id = Uuid::new_v4();
    let key_hex: String = msg.key.bytes().map(|b| format!("{b:02x}")).collect();
    let mut metadata = AuditMetadata::new();
    metadata
        .insert("role", "member")
        .expect("allowlisted audit metadata");
    AtomicRememberRequest {
        request_id,
        idempotency_key: msg.key.into(),
        request_fingerprint: format!("{key_hex:0>64}"),
        workspace_id: Some(WorkspaceId(h.workspace_id)),
        reservation_ttl: Duration::from_secs(30),
        replay_ttl: Duration::from_secs(600),
        command: RememberCommand {
            tenant_id: h.tenant_id,
            authorization_user_id: auth.user_id().map(|u| u.0),
            scope_kind: "workspace".into(),
            scope_id: h.workspace_id,
            domain: DOMAIN.into(),
            projection_kind: PROJECTION_KIND.into(),
            projection_version: PROJECTION_VERSION.into(),
            consistency_token_expires_at: OffsetDateTime::now_utc() + Duration::from_secs(45),
            batch_id: None,
            payload_sha256: payload_sha256(msg.text.as_bytes()),
            data_class: "INTERNAL".into(),
            origin_class: EvidenceOriginClass::AuthenticatedAgent,
            origin_principal_id: Some(auth.principal().0),
            origin_connector_id: None,
            visibility_class: "WORKSPACE_SHARED".into(),
            visibility_user_id: None,
            visibility_workspace_id: Some(h.workspace_id),
            reasoning_domain_id: h.reasoning_domain_id,
            occurred_at: Some(OffsetDateTime::from_unix_timestamp(INSIDE).expect("instant")),
            event_kind: "TASK_EVENT".into(),
            event_payload: serde_json::json!({ "content": msg.text }),
            subjects: humaux_domain::subject::SubjectDeclaration::default(),
            affects: Vec::new(),
            mood_half_life: None,
        },
        finished_audit: AuditEvent {
            event_id: AuditEventId::new(),
            ts: SystemTime::now(),
            tenant_id: TenantId(h.tenant_id),
            actor_type: "user".into(),
            actor_id: auth.principal().0.to_string(),
            action: McpAuditAction::McpRequestFinished.as_str().into(),
            resource_type: "mcp".into(),
            resource_id: OPERATION.into(),
            result: "OK".into(),
            request_id: request_id.to_string(),
            trace_id: format!("{NAME}-{request_id}"),
            client_ip: "127.0.0.1".into(),
            user_agent_hash: "m29-attribution-e2e".into(),
            risk_tags: vec!["fixture".into()],
            before_fingerprint: None,
            after_fingerprint: None,
            metadata,
        },
    }
}

/// The real `remember.put` receipt transaction (T04c run verification, T06c project resolution).
fn put(
    h: &Handle,
    auth: &AuthorizationScope,
    msg: &Msg,
    run: Option<&ClaimedTaskRun>,
    project: Option<Uuid>,
) -> Result<AtomicRememberResult, ErrorCode> {
    h.rt.block_on(operation_receipt::remember_for_task_run_atomically(
        &h.runtime,
        auth,
        request(h, auth, msg),
        run.map(|r| (r.task_run_id, r.fencing_token)),
        project.map(ProjectId),
    ))
}

/// [`put`] by U's session scope, which must succeed; returns the Evidence id.
fn accept(h: &Handle, msg: &Msg, run: Option<&ClaimedTaskRun>, project: Option<Uuid>) -> Uuid {
    put(h, &h.auth, msg, run, project)
        .expect("remember.put")
        .accepted
        .evidence_id
}

/// A synthetic PAT of U bound to the fixture workspace.
fn pat(h: &mut Handle) -> SyntheticServiceCredential {
    let prefix = format!("m29t07{}", Uuid::new_v4().simple());
    let wire = format!(
        "{prefix}.{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );
    h.seed_synthetic_service_credential(
        SyntheticCredentialScopes::RememberWrite,
        &prefix,
        &wire,
        &compute_api_key_hash(SYNTHETIC_CREDENTIAL_PEPPER, &wire),
    )
}

/// What the gateway does before the receipt transaction: the real PAT authentication against current DB facts, then
/// the operation's scope for the routed workspace.
fn authenticate(
    h: &Handle,
    credential: &SyntheticServiceCredential,
) -> Result<AuthorizationScope, ErrorCode> {
    h.rt.block_on(authenticate_service_credential(
        &h.runtime,
        &credential.bearer,
        SYNTHETIC_CREDENTIAL_PEPPER,
        None,
        IpAddr::from([127, 0, 0, 1]),
        SystemTime::now(),
    ))?
    .authorize(
        CredentialScope::MemoryWrite,
        Some(WorkspaceId(h.workspace_id)),
    )
}

/// A put through PAT `credential`: authentication, then the receipt transaction.
fn put_with_pat(
    h: &Handle,
    credential: &SyntheticServiceCredential,
    msg: &Msg,
    project: Option<Uuid>,
) -> Result<Uuid, ErrorCode> {
    let auth = authenticate(h, credential)?;
    put(h, &auth, msg, None, project).map(|r| r.accepted.evidence_id)
}

/// U's workspace membership through its sole writer (0162), as the §6.3 admin path calls it.
fn workspace_membership(h: &mut Handle, state: &str) {
    let mut txn = h.admin.transaction().expect("begin");
    txn.execute(
        "SELECT set_config('humaux.tenant_id', $1, true)",
        &[&h.tenant_id.to_string()],
    )
    .expect("tenant GUC");
    txn.execute(
        "SELECT control.set_workspace_membership($1, $2, $3, 'MEMBER', $4)",
        &[&h.tenant_id, &h.workspace_id, &h.user_id, &state],
    )
    .expect("set_workspace_membership");
    txn.commit().expect("commit");
}

/// One owner connection switched to `role_gateway` with U's request GUCs, as the gateway runs a request.
async fn gateway_txn<'c>(
    conn: &'c mut PgConnection,
    h: &Handle,
) -> sqlx::Transaction<'c, sqlx::Postgres> {
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
    .bind(h.tenant_id.to_string())
    .bind(h.user_id.to_string())
    .execute(&mut *txn)
    .await
    .expect("request GUCs");
    txn
}

/// Revision `expected + 1` of `relation` (`src` CONTAINS T1) through the real `append_revision`, decided by U and
/// authorised by Evidence `authz` (ADR-0078 T06d).
fn relate(
    h: &Handle,
    w: &World,
    relation: Uuid,
    src: Uuid,
    expected: i64,
    valid: &Validity,
    authz: Uuid,
) -> i64 {
    h.rt.block_on(async {
        // dep: PostgreSQL(owner) — test opens a direct PG connection for setup/verification
        let mut conn = PgConnection::connect(&admin_dsn())
            .await
            .expect("owner connection");
        let mut txn = gateway_txn(&mut conn, h).await;
        let edge = RelationEdge {
            src_id: src,
            kind: RelationKind::Contains,
            dst_id: w.t1.0,
        };
        let revision = relation_repo::append_revision(
            &mut txn,
            &edge,
            RelationId(relation),
            expected,
            valid,
            &DecidedBy::Principal(PrincipalId(h.user_id)),
            None,
            &[],
            authz,
        )
        .await
        .expect("append_revision");
        txn.commit().await.expect("commit the revision");
        revision
    })
}

/// The one reader, as U through `role_gateway`.
fn read(h: &Handle, memory: Uuid) -> MemoryAttribution {
    h.rt.block_on(async {
        // dep: PostgreSQL(owner) — test opens a direct PG connection for setup/verification
        let mut conn = PgConnection::connect(&admin_dsn())
            .await
            .expect("owner connection");
        let mut txn = gateway_txn(&mut conn, h).await;
        let attribution = attribution_repo::read_memory_attribution(&mut txn, h.tenant_id, memory)
            .await
            .expect("read_memory_attribution");
        txn.rollback().await.expect("rollback");
        attribution
    })
}

fn link(
    project: Uuid,
    kind: SourceKind,
    rule: RuleId,
    decision: Uuid,
    from: Option<Uuid>,
) -> ProjectLink {
    ProjectLink {
        project_id: ProjectId(project),
        source_kind: kind,
        rule_id_ver: rule,
        decision_evidence_id: EvidenceId(decision),
        inherited_from_memory_id: from.map(MemoryId),
    }
}

/// The reader's answer for `links`, in its order (by project).
fn resolved(mut links: Vec<ProjectLink>) -> MemoryAttribution {
    links.sort_by_key(|l| l.project_id.0);
    MemoryAttribution::Resolved(links)
}

/// The Memories distilled from `evidence`, read as the owner.
fn memories_of(h: &mut Handle, evidence: Uuid) -> Vec<Uuid> {
    h.admin
        .query(
            "SELECT memory_id FROM private.memory_evidence WHERE evidence_id = $1 ORDER BY memory_id",
            &[&evidence],
        )
        .expect("memory_evidence")
        .iter()
        .map(|r| r.get(0))
        .collect()
}

/// The one Memory of `evidence`.
fn memory_of(h: &mut Handle, evidence: Uuid) -> Uuid {
    let memories = memories_of(h, evidence);
    assert_eq!(memories.len(), 1, "one Memory per Evidence: {memories:?}");
    memories[0]
}

/// Tenant-wide `(receipts, Evidence, evidence_projects, memory_projects, Memories)`, read as the owner.
fn counts(h: &mut Handle) -> (i64, i64, i64, i64, i64) {
    let row = h
        .admin
        .query_one(
            "SELECT (SELECT count(*) FROM control.operation_receipts WHERE tenant_id = $1), \
                    (SELECT count(*) FROM private.evidence_objects WHERE tenant_id = $1), \
                    (SELECT count(*) FROM private.evidence_projects WHERE tenant_id = $1), \
                    (SELECT count(*) FROM private.memory_projects WHERE tenant_id = $1), \
                    (SELECT count(*) FROM private.memory_records WHERE tenant_id = $1)",
            &[&h.tenant_id],
        )
        .expect("counts");
    (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4))
}

fn scalar(h: &mut Handle, sql: &str, id: Uuid) -> i64 {
    h.admin.query_one(sql, &[&id]).expect(sql).get(0)
}

/// Every `ops.model_call_ledger` row of the tenant.
fn ledger(h: &mut Handle) -> i64 {
    let tenant = h.tenant_id;
    scalar(
        h,
        "SELECT count(*) FROM ops.model_call_ledger WHERE tenant_id = $1",
        tenant,
    )
}

/// Makes the Evidence's backed-off Distill job claimable now.
fn ready_now(h: &mut Handle, evidence: Uuid) {
    h.admin
        .execute(
            "UPDATE ops.jobs SET next_retry_at = clock_timestamp() - interval '1 second' \
             WHERE idempotency_key = 'derived-work:DERIVED_DISTILL:' || $1::uuid::text",
            &[&evidence],
        )
        .expect("ready now");
}

/// One `--distill-once` drain with `provider` (foreign tenants are fenced).
fn pass(
    rt: &tokio::runtime::Runtime,
    pool: &PrivateWorkerDbPool,
    provider: &Arc<FakeProvider>,
) -> DistillDispatchReport {
    rt.block_on(dispatch_pass(
        pool,
        &routes(provider),
        contribution_config(),
        &dispatch_config(NAME, 30.0),
    ))
    .expect("distill dispatch pass")
}

/// The Distill jobs a pass ran: each reached the provider once (settled DONE, RETRY or FAILED).
fn jobs_run(report: &DistillDispatchReport) -> u32 {
    report.completed + report.deferred + report.failed
}

/// G-N09-4(a): per message key, the attribution projection with uuids replaced by fixture roles and message keys.
type Projection = BTreeMap<&'static str, Vec<(&'static str, SourceKind, RuleId, &'static str)>>;

fn projection(h: &mut Handle, w: &World, evidence: &[(&'static str, Uuid)]) -> Projection {
    let message = |id: EvidenceId| {
        evidence
            .iter()
            .find(|(_, e)| *e == id.0)
            .map_or("foreign", |(key, _)| *key)
    };
    evidence
        .iter()
        .map(|(key, e)| {
            let memory = memory_of(h, *e);
            let links = match read(h, memory) {
                MemoryAttribution::Resolved(links) => links,
                MemoryAttribution::Unresolved => Vec::new(),
            };
            let mut rows: Vec<_> = links
                .into_iter()
                .map(|l| {
                    (
                        w.role(l.project_id),
                        l.source_kind,
                        l.rule_id_ver,
                        message(l.decision_evidence_id),
                    )
                })
                .collect();
            rows.sort_by_key(|r| r.0);
            (*key, rows)
        })
        .collect()
}

/// Steps 1–2 for one tenant: the fixture, m1–m3 through the real put, both relations through `append_revision`
/// (authorised by m1's Evidence, the first one in the tenant), and one Distill pass with `provider`. Returns the world,
/// the Evidence of each message and the pass.
fn steps_1_2(
    h: &mut Handle,
    rt: &tokio::runtime::Runtime,
    pool: &PrivateWorkerDbPool,
    provider: &Arc<FakeProvider>,
) -> (World, [(&'static str, Uuid); 3], DistillDispatchReport) {
    let w = fixture(h);
    let e1 = accept(h, &M1, None, Some(w.p1));
    let e2 = accept(h, &M2, Some(&w.run), None);
    let e3 = accept(h, &M3, None, None);
    let open = Validity::new(&[(
        Included(Timestamp::Micros(OPEN_FROM * 1_000_000)),
        Unbounded,
    )])
    .expect("open window");
    for project in [w.p1, w.p2] {
        assert_eq!(relate(h, &w, Uuid::now_v7(), project, 0, &open, e1), 1);
    }
    let report = pass(rt, pool, provider);
    (w, [(M1.key, e1), (M2.key, e2), (M3.key, e3)], report)
}

/// Purges the fixture tenants before their handles drop (their teardown knows neither Distill's rows nor the
/// append-only attribution and relation rows), releasing the global slots their jobs hold first.
struct Purge {
    admin: Client,
    tenants: Vec<Uuid>,
}

impl Drop for Purge {
    fn drop(&mut self) {
        for tenant in &self.tenants {
            if let Err(error) = self.admin.execute(
                "UPDATE ops.provider_slots SET job_id = NULL, claim_generation = NULL, bound_until = NULL \
                 WHERE job_id IN (SELECT job_id FROM ops.jobs WHERE tenant_id = $1)",
                &[tenant],
            ) {
                eprintln!("{NAME}: slot release for tenant {tenant} failed: {error}");
            }
            let purged = purge_tenant_fixture_sql(&tenant.to_string())
                .and_then(|sql| self.admin.batch_execute(&sql).map_err(|e| e.to_string()));
            if let Err(error) = purged {
                eprintln!("{NAME}: fixture purge of tenant {tenant} failed: {error}");
            }
        }
    }
}

/// ADR-0078 G-N09-3 / G-N09-4 and design v0.2 §15.8, in order, with exact counts at every step.
#[test]
#[allow(clippy::too_many_lines)] // one scenario, seven steps and the cross-tenant comparison, read top to bottom
fn m29_attribution_end_to_end() {
    run_db_fixture::<Fixture, _>("m29_attribution_end_to_end", |mut ha| {
        // SAFETY: nextest runs this binary's one test in its own process, and nothing else reads this variable.
        unsafe {
            std::env::set_var("HUMAUX_PRIVATE_WORKER_CANDIDATE_TTL_SECONDS", "604800");
        }
        let Ok(mut hb) = Fixture::isolate() else {
            panic!("missing object: a second operation_receipt fixture tenant (G-N09-4(a))");
        };
        let dsn = admin_dsn();
        let fence = dispatch_fence::open(&mut ha.admin, &dsn).expect("dispatch fence");
        // dep: PostgreSQL(owner) — test opens a direct PG connection for setup/verification
        let purge_admin = Client::connect(&dsn, NoTls).expect("purge connection");
        let _purge = Purge {
            admin: purge_admin,
            tenants: vec![ha.tenant_id, hb.tenant_id],
        };
        // The worker's own runtime and pool, as in production; the handles keep theirs.
        let rt = tokio::runtime::Runtime::new().expect("worker runtime");
        let pool = rt
            // dep: PostgreSQL(role_private_worker) — role-scoped pool call
            .block_on(PrivateWorkerDbPool::connect(&dsn_as_role(
                &dsn,
                "role_private_worker",
            )))
            .expect("private worker pool");
        // The governor corrects M2; its BMO window is tenant A's only one (quota_repo takes exactly one).
        let governor = Governor::seed(&mut ha.admin, ha.tenant_id);
        governor.join(&mut ha.admin, ha.workspace_id);
        let mut calls = 0u32;
        let mut jobs = 0u32;

        // Steps 1–2: m1 → A1, m2 → A3 over the shared task, m3 → nothing (G-N09-3).
        let provider = FakeProvider::new(vec![REPLY_A; 6]);
        let (w, evidence, report) = steps_1_2(&mut ha, &rt, &pool, &provider);
        let [(_, e1), (_, e2), (_, e3)] = evidence;
        assert_eq!(
            (report.claimed, report.completed, report.memories),
            (3, 3, 3),
            "{report:?}"
        );
        assert_eq!(
            provider.calls(),
            jobs_run(&report),
            "G-N09-4(b): attribution makes no provider call"
        );
        calls += provider.calls();
        jobs += jobs_run(&report);
        let (m1, m2, m3) = (
            memory_of(&mut ha, e1),
            memory_of(&mut ha, e2),
            memory_of(&mut ha, e3),
        );
        assert_eq!(
            read(&ha, m1),
            resolved(vec![link(
                w.p1,
                SourceKind::Declared,
                RuleId::Declared1,
                e1,
                None
            )]),
            "M1: P1 declared"
        );
        assert_eq!(
            read(&ha, m2),
            resolved(vec![
                link(w.p1, SourceKind::Inherited, RuleId::TaskRun1, e2, None),
                link(w.p2, SourceKind::Inherited, RuleId::TaskRun1, e2, None),
            ]),
            "M2: both projects of the shared task"
        );
        assert_eq!(read(&ha, m3), MemoryAttribution::Unresolved, "G-N09-3: M3");
        assert_eq!(
            scalar(
                &mut ha,
                "SELECT count(*) FROM private.memory_projects WHERE project_id = $1",
                w.p3
            ),
            0,
            "G-N09-3: the same-name trap P3 has no row"
        );
        assert_eq!(counts(&mut ha), (3, 3, 1, 3, 3), "after step 2");

        // Steps 3–4 and the reader calls: no provider call, no ledger row (G-N09-4(c)).
        let ledger_before = ledger(&mut ha);
        let done = governance_ops::correct(
            &ha.rt,
            &ha.runtime,
            &governor.scope(ha.workspace_id),
            &governance_ops::stream(ha.tenant_id, ha.workspace_id),
            m2,
            "Drafted the hero section and the footer.",
        )
        .expect("memory.correct");
        let (m2c, ec) = (done.new_memory_id.0, done.evidence_id);
        assert_eq!(
            read(&ha, m2c),
            resolved(vec![
                link(
                    w.p1,
                    SourceKind::Inherited,
                    RuleId::Correction1,
                    ec,
                    Some(m2)
                ),
                link(
                    w.p2,
                    SourceKind::Inherited,
                    RuleId::Correction1,
                    ec,
                    Some(m2)
                ),
            ]),
            "step 3: M2' inherits P1 and P2 (A3')"
        );
        let r2 = ha
            .admin
            .query_one(
                "SELECT relation_id FROM private.project_task_relations WHERE src_id = $1",
                &[&w.p2],
            )
            .expect("P2 CONTAINS T1")
            .get(0);
        assert_eq!(relate(&ha, &w, r2, w.p2, 1, &Validity::retracted(), e1), 2);
        assert_eq!(
            read(&ha, m2),
            resolved(vec![link(
                w.p1,
                SourceKind::Inherited,
                RuleId::TaskRun1,
                e2,
                None
            )]),
            "step 4: M2 keeps P1 only"
        );
        assert_eq!(
            read(&ha, m2c),
            resolved(vec![link(
                w.p1,
                SourceKind::Inherited,
                RuleId::Correction1,
                ec,
                Some(m2)
            )]),
            "step 4: M2' keeps P1 only"
        );
        assert_eq!(
            read(&ha, m1),
            resolved(vec![link(
                w.p1,
                SourceKind::Declared,
                RuleId::Declared1,
                e1,
                None
            )]),
            "step 4: a relation never revokes the DECLARED link"
        );
        let tenant_a = ha.tenant_id;
        assert_eq!(
            scalar(
                &mut ha,
                "SELECT count(*) FROM private.memory_project_revocations WHERE tenant_id = $1",
                tenant_a
            ),
            2,
            "step 4: M2/P2 and M2'/P2 revoked"
        );
        assert_eq!(
            (provider.calls(), ledger(&mut ha)),
            (calls, ledger_before),
            "G-N09-4(c): steps 3-4 and the reads"
        );

        // Step 5: replaying m1 changes nothing, and a second pass creates nothing.
        let before = counts(&mut ha);
        let replay =
            put(&ha, &ha.auth, &M1, None, Some(w.p1)).map(|r| (r.replayed, r.accepted.evidence_id));
        assert_eq!(replay, Ok((true, e1)), "step 5: m1 replays");
        assert_eq!(counts(&mut ha), before, "step 5: the replay wrote nothing");
        let idle = FakeProvider::new(vec![REPLY_A; 2]);
        let again = pass(&rt, &pool, &idle);
        assert_eq!(
            (again.claimed, idle.calls()),
            (0, 0),
            "step 5: nothing to distill: {again:?}"
        );
        assert_eq!(
            counts(&mut ha),
            before,
            "step 5: the second pass wrote nothing"
        );

        // Step 6: a revoked PAT, and a live PAT of a suspended member, are refused with nothing written.
        let revoked = pat(&mut ha);
        assert!(authenticate(&ha, &revoked).is_ok(), "the PAT works first");
        ha.revoke_service_credential(&revoked);
        assert_eq!(
            put_with_pat(&ha, &revoked, &M5, None),
            Err(ErrorCode::Unauthorized),
            "step 6: revoked PAT"
        );
        assert_eq!(counts(&mut ha), before, "step 6: nothing written (revoked)");
        let live = pat(&mut ha);
        workspace_membership(&mut ha, "SUSPENDED");
        let suspended = put_with_pat(&ha, &live, &M6, Some(w.p1));
        workspace_membership(&mut ha, "ACTIVE");
        assert_eq!(
            suspended,
            Err(ErrorCode::Forbidden),
            "step 6: suspended membership"
        );
        assert_eq!(
            counts(&mut ha),
            before,
            "step 6: nothing written (suspended)"
        );

        // Step 7: m4's first provider call fails; the retry writes one Memory with exactly {P1 task_run@1}.
        let e4 = accept(&ha, &M4, Some(&w.run), None);
        let flaky = FakeProvider::new(vec![FAKE_RETRY_WAIT, REPLY_A, REPLY_A]);
        let failed = pass(&rt, &pool, &flaky);
        assert_eq!(
            (failed.claimed, failed.deferred, failed.memories),
            (1, 1, 0),
            "{failed:?}"
        );
        assert_eq!(
            flaky.calls(),
            jobs_run(&failed),
            "G-N09-4(b): the failed attempt"
        );
        assert!(
            memories_of(&mut ha, e4).is_empty(),
            "step 7: the failed attempt wrote no Memory"
        );
        assert_eq!(
            counts(&mut ha),
            (before.0 + 1, before.1 + 1, before.2, before.3, before.4),
            "step 7: only m4's receipt and Evidence before the retry"
        );
        ready_now(&mut ha, e4);
        let retried = pass(&rt, &pool, &flaky);
        assert_eq!(
            (retried.claimed, retried.completed, retried.memories),
            (1, 1, 1),
            "{retried:?}"
        );
        assert_eq!(
            flaky.calls(),
            jobs_run(&failed) + jobs_run(&retried),
            "G-N09-4(b): the retry"
        );
        calls += flaky.calls();
        jobs += jobs_run(&failed) + jobs_run(&retried);
        let m4 = memory_of(&mut ha, e4);
        assert_eq!(
            read(&ha, m4),
            resolved(vec![link(
                w.p1,
                SourceKind::Inherited,
                RuleId::TaskRun1,
                e4,
                None
            )]),
            "step 7: M4 = {{P1 task_run@1}}"
        );
        assert_eq!(
            counts(&mut ha),
            (
                before.0 + 1,
                before.1 + 1,
                before.2,
                before.3 + 1,
                before.4 + 1
            ),
            "step 7: one Memory and one link, nothing from the failed attempt"
        );

        // G-N09-4(a): steps 1–2 in tenant B, whose provider writes other memory text, project the same per message.
        let projection_a = projection(&mut ha, &w, &evidence);
        hb.seed_current_entitlement_and_window(100);
        let provider_b = FakeProvider::new(vec![REPLY_B; 6]);
        let (wb, evidence_b, report_b) = steps_1_2(&mut hb, &rt, &pool, &provider_b);
        assert_eq!(
            (report_b.claimed, report_b.completed, report_b.memories),
            (3, 3, 3),
            "{report_b:?}"
        );
        assert_eq!(
            provider_b.calls(),
            jobs_run(&report_b),
            "G-N09-4(b): tenant B"
        );
        calls += provider_b.calls();
        jobs += jobs_run(&report_b);
        let projection_b = projection(&mut hb, &wb, &evidence_b);
        assert_eq!(
            projection_b, projection_a,
            "G-N09-4(a): attribution does not follow the memory text"
        );
        assert_eq!(
            (calls, jobs),
            (8, 8),
            "G-N09-4(b): provider calls == Distill jobs run, the fault retry counted"
        );
        drop(fence);
    });
}

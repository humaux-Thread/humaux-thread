//! `adapters::tests::note_put` — ADR-0067 card 40a acceptance for `memory.note_put`'s storage path (G01-G10, G16, G17, G22,
//!   the fault pair lives in G16 and the worker test d13), against a real PostgreSQL and an actual `role_gateway` login.
//! Depends-on: crates=[hex, humaux-adapters, humaux-domain, humaux-testkit, postgres, serde_json, sqlx, tokio];
//!   services=[PostgreSQL(owner), PostgreSQL(role_gateway) r=[control.audit_events, control.operation_receipts, control.usage_reservations,
//!   ops.distill_calls, ops.model_call_ledger, private.distill_candidates, private.events, private.evidence_objects,
//!   private.identity_note_materializations, projection.stream_log] w=[ops.distill_tenant_scheduler, ops.jobs, ops.outbox,
//!   private.memory_evidence, private.memory_records]]; env=[]; modules=[adapters::attribution_repo, adapters::note_repo, adapters::operation_receipt,
//!   adapters::postgres, adapters::remember, adapters::tests::support::operation_receipt_fixture, domain::audit,
//!   domain::authority, domain::error, domain::evidence, domain::identity, domain::ids, domain::memory, domain::note,
//!   domain::subject, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [every runtime write is a real role_gateway login; the owner connection only seeds, reads back and injects
//!   failures into this fixture's tenant; every assertion that guards a decision has a recorded red]
//! Spec: ADR-0067; ADR-0047
//!
//! Read-back is always from the database row, and the digest is recomputed by PostgreSQL's `sha256` over the read-back text,
//! so neither the write path nor the Rust digest function can vouch for itself.

use std::sync::{Arc, Barrier, mpsc};
use std::time::{Duration, Instant, SystemTime};

use humaux_adapters::{
    note_repo::NoteIntake,
    operation_receipt::{self, AtomicRememberRequest, Dedupe, NOTE_OPERATION},
    postgres::RuntimeDbPool,
    remember::RememberCommand,
};
use humaux_domain::{
    audit::{AuditEvent, AuditEventId, AuditMetadata, McpAuditAction},
    authority::AuthorityClass,
    error::ErrorCode,
    evidence::{EvidenceOriginClass, payload_sha256},
    identity::{AuthorizationScope, BoundedSet, PrincipalId},
    ids::{TenantId, UserId, WorkspaceId},
    memory::{MemoryType, facet_for},
    note::{DEFAULT_AUTHORITY, MAX_BODY_BYTES, NoteBody, NoteKind, note_title},
};
use humaux_testkit::run_db_fixture;
use postgres::Client;
use sqlx::types::{Uuid, time::OffsetDateTime};

#[allow(dead_code)]
#[path = "support/operation_receipt_fixture.rs"]
mod operation_receipt_fixture;

use operation_receipt_fixture::{DOMAIN, Fixture, Handle, PROJECTION_KIND, PROJECTION_VERSION};

/// The finished audit row for a chosen principal: the M06-3 gate runs two agents under one owner user.
fn finished_audit_for(handle: &Handle, principal: Uuid, request_id: Uuid) -> AuditEvent {
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
        resource_id: NOTE_OPERATION.into(),
        result: "OK".into(),
        request_id: request_id.to_string(),
        trace_id: format!("note-put-{request_id}"),
        client_ip: "127.0.0.1".into(),
        user_agent_hash: "note-put-test".into(),
        risk_tags: vec!["fixture".into()],
        before_fingerprint: None,
        after_fingerprint: None,
        metadata,
    }
}

/// What the gateway edge builds for one note: the MANUAL_NOTE command (payload = the JSON string of the body) and the intake.
fn note_request(
    handle: &Handle,
    key: &str,
    fingerprint: &str,
    body: &str,
    kind: NoteKind,
    requested: AuthorityClass,
) -> (AtomicRememberRequest, NoteIntake) {
    note_request_for(
        handle,
        handle.principal_id,
        "WORKSPACE_SHARED",
        None,
        key,
        fingerprint,
        body,
        kind,
        requested,
    )
}

/// [`note_request`] for a chosen principal and visibility: M06-3's two agents share one owner user, and a `USER_PRIVATE`
/// note's visibility user is that owner.
#[allow(clippy::too_many_arguments)]
fn note_request_for(
    handle: &Handle,
    principal: Uuid,
    visibility_class: &str,
    visibility_user_id: Option<Uuid>,
    key: &str,
    fingerprint: &str,
    body: &str,
    kind: NoteKind,
    requested: AuthorityClass,
) -> (AtomicRememberRequest, NoteIntake) {
    let raw = serde_json::to_vec(&serde_json::Value::String(body.to_owned())).expect("string");
    let request_id = Uuid::new_v4();
    let command = RememberCommand {
        tenant_id: handle.tenant_id,
        authorization_user_id: Some(handle.user_id),
        scope_kind: "workspace".into(),
        scope_id: handle.workspace_id,
        domain: DOMAIN.into(),
        projection_kind: PROJECTION_KIND.into(),
        projection_version: PROJECTION_VERSION.into(),
        consistency_token_expires_at: OffsetDateTime::now_utc() + Duration::from_secs(45),
        batch_id: None,
        payload_sha256: payload_sha256(&raw),
        data_class: "INTERNAL".into(),
        origin_class: EvidenceOriginClass::AuthenticatedAgent,
        origin_principal_id: Some(principal),
        origin_connector_id: None,
        visibility_class: visibility_class.into(),
        visibility_user_id,
        visibility_workspace_id: if visibility_class == "WORKSPACE_SHARED" {
            Some(handle.workspace_id)
        } else {
            None
        },
        reasoning_domain_id: handle.reasoning_domain_id,
        occurred_at: Some(OffsetDateTime::now_utc()),
        event_kind: "MANUAL_NOTE".into(),
        event_payload: serde_json::Value::String(body.to_owned()),
        subjects: humaux_domain::subject::SubjectDeclaration::default(),
        affects: Vec::new(),
        mood_half_life: None,
    };
    let verbatim = NoteBody::new(body).expect("test body is valid");
    let title = note_title(None, &verbatim).expect("derived title");
    (
        AtomicRememberRequest {
            request_id,
            idempotency_key: key.into(),
            request_fingerprint: fingerprint.into(),
            workspace_id: Some(WorkspaceId(handle.workspace_id)),
            reservation_ttl: Duration::from_secs(30),
            replay_ttl: Duration::from_secs(60),
            command,
            finished_audit: finished_audit_for(handle, principal, request_id),
        },
        NoteIntake {
            kind,
            title,
            body: verbatim,
            requested,
        },
    )
}

fn put(
    handle: &Handle,
    key: &str,
    fingerprint: &str,
    body: &str,
    kind: NoteKind,
    requested: AuthorityClass,
) -> Result<operation_receipt::AtomicRememberResult, ErrorCode> {
    let (request, note) = note_request(handle, key, fingerprint, body, kind, requested);
    handle.rt.block_on(operation_receipt::note_put_atomically(
        &handle.runtime,
        &handle.auth,
        request,
        note,
        &humaux_adapters::attribution_repo::AttributionLadder,
    ))
}

fn put_default(
    handle: &Handle,
    body: &str,
    kind: NoteKind,
) -> operation_receipt::AtomicRememberResult {
    put(
        handle,
        &format!("note-{}", Uuid::new_v4()),
        &"a".repeat(64),
        body,
        kind,
        DEFAULT_AUTHORITY,
    )
    .expect("note commits")
}

/// Every row family a note (or a failed note) can leave behind, for this tenant.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct Residue {
    evidence: i64,
    events: i64,
    memories: i64,
    links: i64,
    contracts: i64,
    outbox: i64,
    stream_log: i64,
    receipts: i64,
    reservations: i64,
    audits: i64,
    candidates: i64,
    distill_jobs: i64,
}

fn residue(handle: &mut Handle) -> Residue {
    let row = handle
        .admin
        .query_one(
            "SELECT \
               (SELECT count(*) FROM private.evidence_objects WHERE tenant_id=$1), \
               (SELECT count(*) FROM private.events ev JOIN private.evidence_objects e ON e.evidence_id=ev.event_id WHERE e.tenant_id=$1), \
               (SELECT count(*) FROM private.memory_records WHERE tenant_id=$1), \
               (SELECT count(*) FROM private.memory_evidence me JOIN private.memory_records m ON m.memory_id=me.memory_id WHERE m.tenant_id=$1), \
               (SELECT count(*) FROM private.identity_note_materializations WHERE tenant_id=$1), \
               (SELECT count(*) FROM ops.outbox WHERE tenant_id=$1), \
               (SELECT count(*) FROM projection.stream_log WHERE tenant_id=$1), \
               (SELECT count(*) FROM control.operation_receipts WHERE tenant_id=$1), \
               (SELECT count(*) FROM control.usage_reservations WHERE tenant_id=$1), \
               (SELECT count(*) FROM control.audit_events WHERE tenant_id=$1), \
               (SELECT count(*) FROM private.distill_candidates WHERE tenant_id=$1), \
               (SELECT count(*) FROM ops.jobs WHERE tenant_id=$1 \
                  AND job_type IN ('DERIVED_DISTILL','DERIVED_CONSOLIDATE'))",
            &[&handle.tenant_id],
        )
        .expect("owner reads this tenant's rows");
    Residue {
        evidence: row.get(0),
        events: row.get(1),
        memories: row.get(2),
        links: row.get(3),
        contracts: row.get(4),
        outbox: row.get(5),
        stream_log: row.get(6),
        receipts: row.get(7),
        reservations: row.get(8),
        audits: row.get(9),
        candidates: row.get(10),
        distill_jobs: row.get(11),
    }
}

/// The note's Memory as stored, read back through the owner connection.
struct Stored {
    title: String,
    key_claim: String,
    representation: String,
    memory_type: String,
    note_kind: Option<String>,
    authority_class: String,
    status: String,
    facet: Option<String>,
    /// `sha256(convert_to(key_claim, 'UTF8'))` computed by PostgreSQL over the read-back text.
    pg_digest: Vec<u8>,
    contract_digest: Vec<u8>,
    contract_strategy: String,
}

fn stored(handle: &mut Handle, memory_id: Uuid) -> Stored {
    let row = handle
        .admin
        .query_one(
            "SELECT m.content->>'title', m.content->>'key_claim', m.content->>'representation', \
                    m.memory_type, m.note_kind, m.authority_class, m.status, m.facet, \
                    sha256(convert_to(m.content->>'key_claim', 'UTF8')), c.body_sha256, c.strategy \
             FROM private.memory_records m \
             JOIN private.identity_note_materializations c \
               ON c.tenant_id = m.tenant_id AND c.output_memory_id = m.memory_id \
             WHERE m.memory_id = $1 AND m.tenant_id = $2",
            &[&memory_id, &handle.tenant_id],
        )
        .expect("note and its contract are readable");
    Stored {
        title: row.get(0),
        key_claim: row.get(1),
        representation: row.get(2),
        memory_type: row.get(3),
        note_kind: row.get(4),
        authority_class: row.get(5),
        status: row.get(6),
        facet: row.get(7),
        pg_digest: row.get(8),
        contract_digest: row.get(9),
        contract_strategy: row.get(10),
    }
}

/// An owner-installed trigger that fails one INSERT stage for this tenant only; dropped on every exit.
struct FailInsert {
    admin: Client,
    trigger: String,
    function: String,
    table: &'static str,
}

impl Drop for FailInsert {
    fn drop(&mut self) {
        if let Err(error) = self.admin.batch_execute(&format!(
            "DROP TRIGGER IF EXISTS {} ON {}; DROP FUNCTION IF EXISTS private.{}();",
            self.trigger, self.table, self.function
        )) {
            eprintln!("note_put fixture trigger cleanup failed: {error}");
        }
    }
}

fn fail_insert_on(handle: &Handle, table: &'static str, tenant_column: &str) -> FailInsert {
    let suffix = format!(
        "{}_{}",
        handle.tenant_id.simple(),
        table.replace(['.', '_'], "")
    );
    let name = format!("note_put_fail_{}", &suffix[..40.min(suffix.len())]);
    let mut admin = handle.owner_client().expect("owner connection");
    admin
        .batch_execute(&format!(
            "CREATE FUNCTION private.{name}() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN \
               IF NEW.{tenant_column} = '{tenant}'::uuid THEN \
                 RAISE EXCEPTION 'note_put injected failure' USING ERRCODE = '22023'; \
               END IF; \
               RETURN NEW; \
             END; $$; \
             CREATE TRIGGER {name} BEFORE INSERT ON {table} \
             FOR EACH ROW EXECUTE FUNCTION private.{name}();",
            tenant = handle.tenant_id,
        ))
        .expect("owner installs the injected failure");
    FailInsert {
        admin,
        trigger: name.clone(),
        function: name,
        table,
    }
}

/// A plain `remember.put` of this tenant (Evidence intake, no contract) — the control the note gates are compared with.
fn ordinary_remember(handle: &Handle, key: &str) -> operation_receipt::AtomicRememberResult {
    let (mut ordinary, _) = note_request(
        handle,
        key,
        &"e".repeat(64),
        "ordinary evidence",
        NoteKind::Note,
        DEFAULT_AUTHORITY,
    );
    ordinary.finished_audit.resource_id = "remember.put".into();
    handle
        .rt
        .block_on(operation_receipt::remember_atomically(
            &handle.runtime,
            &handle.auth,
            ordinary,
        ))
        .expect("ordinary remember.put commits")
}

// ---------------------------------------------------------------------------------------------------------------------
// G16 / G17 / G22 / G10: the stored body is the sent body, byte for byte, with a digest PostgreSQL recomputes.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn g16_g17_bodies_round_trip_byte_exact_with_an_independent_digest() {
    run_db_fixture::<Fixture, _>("g16_g17_bodies_round_trip", |mut handle| {
        handle.seed_current_entitlement_and_window(64);
        let edge = "x".repeat(MAX_BODY_BYTES);
        let composed = "caf\u{e9}";
        let decomposed = "cafe\u{301}";
        let cases: Vec<(&str, String)> = vec![
            ("whitespace", "  leading, trailing \t \n\n ".into()),
            ("crlf", "line one\r\nline two\r\n".into()),
            ("cjk", "\u{4e2d}\u{6587}\u{ff0c}\u{6d4b}\u{8bd5}".into()),
            (
                "emoji",
                "ship it \u{1F680}\u{1F9D1}\u{200D}\u{1F4BB}".into(),
            ),
            ("combining", decomposed.into()),
            ("precomposed", composed.into()),
            ("quotes", r#"she said "hi" and 'bye'"#.into()),
            ("backslashes", r"C:\dir\new\table \n \u0041".into()),
            ("64KiB edge", edge),
        ];
        let mut digests = std::collections::BTreeMap::new();
        for (label, body) in &cases {
            let result = put_default(&handle, body, NoteKind::Note);
            let memory_id = result.memory_id.expect("stored note names its memory");
            let row = stored(&mut handle, memory_id);
            assert_eq!(
                row.key_claim.as_bytes(),
                body.as_bytes(),
                "{label}: stored body must equal the sent body byte for byte"
            );
            assert_eq!(
                row.pg_digest, row.contract_digest,
                "{label}: the contract digest equals PostgreSQL's SHA-256 of the stored text"
            );
            assert_eq!(row.representation, "verbatim_assertion");
            digests.insert(*label, row.contract_digest);
        }
        // G17: different normal forms of the same visible text digest differently.
        assert_ne!(digests["combining"], digests["precomposed"]);
        // The edge body is the longest allowed and still exact.
        assert_eq!(cases[8].1.len(), MAX_BODY_BYTES);
    });
}

#[test]
fn g22_a_three_statement_note_is_one_memory_and_no_candidates() {
    run_db_fixture::<Fixture, _>("g22_three_statement_note", |mut handle| {
        handle.seed_current_entitlement_and_window(8);
        let before = residue(&mut handle);
        let body = "Prefer Rust for services. The deploy host is arm64. Never vendor the SDK.";
        let result = put_default(&handle, body, NoteKind::Note);
        let after = residue(&mut handle);
        assert_eq!(after.memories - before.memories, 1, "exactly one Memory");
        assert_eq!(after.evidence - before.evidence, 1);
        assert_eq!(after.contracts - before.contracts, 1);
        assert_eq!(after.candidates, 0, "no PENDING candidate");
        assert_eq!(after.distill_jobs, 0, "no derivation job");
        let row = stored(&mut handle, result.memory_id.unwrap());
        assert_eq!(row.key_claim, body);
        assert_eq!(
            row.title, body,
            "74 scalars < 80: the derived title is the whole first line"
        );
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// G09 / G10: NoteKind <-> DB CHECKs <-> memory_type mapping <-> generated facet.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn g09_g10_note_kind_enum_check_mapping_and_facet_agree() {
    run_db_fixture::<Fixture, _>("g09_g10_note_kind", |mut handle| {
        handle.seed_current_entitlement_and_window(32);
        // The live CHECK definitions name exactly the enum's nine labels and its nine (kind, memory_type) pairs.
        let defs: Vec<(String, String)> = handle
            .admin
            .query(
                "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint \
                 WHERE conrelid = 'private.memory_records'::regclass \
                   AND conname IN ('memory_records_note_kind_check','memory_records_note_kind_memory_type_check')",
                &[],
            )
            .expect("read CHECK definitions")
            .iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect();
        let check = &defs
            .iter()
            .find(|(name, _)| name == "memory_records_note_kind_check")
            .expect("note_kind CHECK exists")
            .1;
        let mapping = &defs
            .iter()
            .find(|(name, _)| name == "memory_records_note_kind_memory_type_check")
            .expect("mapping CHECK exists")
            .1;
        for kind in NoteKind::ALL {
            assert!(
                check.contains(&format!("'{}'", kind.wire())),
                "CHECK lists {}",
                kind.wire()
            );
            assert!(
                mapping.contains(&format!("'{}'", kind.wire()))
                    && mapping.contains(&format!("'{}'", kind.memory_type().wire())),
                "mapping CHECK binds {} to {}",
                kind.wire(),
                kind.memory_type().wire()
            );
        }
        assert_eq!(
            check.matches('\'').count() / 2,
            NoteKind::ALL.len(),
            "the CHECK names no label the enum does not"
        );

        // One note per kind (card baseline counts: rejected/decision/fix/problem/lesson x2, the rest x1 here).
        let mut ids = Vec::new();
        for kind in NoteKind::ALL {
            let result = put_default(&handle, &format!("a {} note", kind.wire()), kind);
            ids.push((kind, result.memory_id.expect("memory")));
        }
        for (kind, memory_id) in &ids {
            let row = stored(&mut handle, *memory_id);
            assert_eq!(row.note_kind.as_deref(), Some(kind.wire()));
            assert_eq!(row.memory_type, kind.memory_type().wire());
            assert_eq!(
                row.facet.as_deref(),
                facet_for(kind.memory_type()).map(|facet| facet.wire()),
                "the generated facet follows memory_type for {}",
                kind.wire()
            );
            assert_eq!(row.contract_strategy, "identity_note_v1");
        }
        // G10: research and note are both NOTE, and counted apart by note_kind.
        let counts: Vec<(String, String, i64)> = handle
            .admin
            .query(
                "SELECT note_kind, memory_type, count(*) FROM private.memory_records \
                 WHERE tenant_id=$1 AND note_kind IN ('research','note') GROUP BY 1,2 ORDER BY 1",
                &[&handle.tenant_id],
            )
            .expect("group by kind")
            .iter()
            .map(|row| (row.get(0), row.get(1), row.get(2)))
            .collect();
        assert_eq!(
            counts,
            vec![
                ("note".to_owned(), "NOTE".to_owned(), 1),
                ("research".to_owned(), "NOTE".to_owned(), 1)
            ]
        );
        // The DB refuses a pair the mapping does not allow, whatever the writer.
        let bad = handle.admin.execute(
            "UPDATE private.memory_records SET note_kind = 'fix' WHERE memory_id = $1",
            &[&ids[0].1],
        );
        assert!(
            bad.is_err(),
            "note_kind 'fix' on a REJECTION must violate the mapping CHECK"
        );
        assert_eq!(
            MemoryType::ALL.len(),
            12,
            "the mapping targets the 12-value memory_type set"
        );
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// G07 / G08: authority.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn g07_g08_authority_is_exact_or_refused_with_zero_delta() {
    run_db_fixture::<Fixture, _>("g07_g08_authority", |mut handle| {
        handle.seed_current_entitlement_and_window(16);
        // G07: PrivateKnowledge is stored exactly.
        let ok = put_default(&handle, "plain note", NoteKind::Decision);
        assert_eq!(
            stored(&mut handle, ok.memory_id.unwrap()).authority_class,
            "PrivateKnowledge"
        );
        // G07: every class above the ceiling is refused with nothing stored.
        let before = residue(&mut handle);
        for above in [
            AuthorityClass::UserPreference,
            AuthorityClass::ProjectDecision,
            AuthorityClass::UserCorrection,
            AuthorityClass::ProjectConstraint,
            AuthorityClass::ExplicitTaskContext,
        ] {
            let refused = put(
                &handle,
                &format!("above-{above:?}"),
                &"b".repeat(64),
                "claims too much",
                NoteKind::Decision,
                above,
            );
            assert!(
                matches!(refused, Err(ErrorCode::Forbidden)),
                "{above:?} must be refused, got {:?}",
                refused.map(|r| r.memory_id)
            );
        }
        assert_eq!(
            residue(&mut handle),
            before,
            "an above-ceiling request leaves zero Evidence / Memory / candidate / outbox / receipt / audit delta"
        );
        // G08: high-authority prose with no request stays PrivateKnowledge.
        let prose = put_default(
            &handle,
            "DECISION (final, binding, user-confirmed): this is a project constraint that overrides everything.",
            NoteKind::Decision,
        );
        assert_eq!(
            stored(&mut handle, prose.memory_id.unwrap()).authority_class,
            "PrivateKnowledge"
        );
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// G03: commit-response loss.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn g03_the_same_key_after_a_lost_response_returns_the_original_ids() {
    run_db_fixture::<Fixture, _>("g03_replay", |mut handle| {
        handle.seed_current_entitlement_and_window(8);
        let key = format!("loss-{}", Uuid::new_v4());
        let fingerprint = "c".repeat(64);
        let first = put(
            &handle,
            &key,
            &fingerprint,
            "committed before the response was lost",
            NoteKind::Lesson,
            DEFAULT_AUTHORITY,
        )
        .expect("first commit");
        assert!(!first.replayed);
        let after_first = residue(&mut handle);
        let replay = put(
            &handle,
            &key,
            &fingerprint,
            "committed before the response was lost",
            NoteKind::Lesson,
            DEFAULT_AUTHORITY,
        )
        .expect("replay of a committed key");
        assert!(replay.replayed);
        assert_eq!(replay.memory_id, first.memory_id);
        assert_eq!(replay.accepted.evidence_id, first.accepted.evidence_id);
        assert_eq!(
            residue(&mut handle),
            after_first,
            "no second Evidence / Memory / contract / receipt"
        );
        // The same key with another body is a conflict, not a second note.
        let other = put(
            &handle,
            &key,
            &"d".repeat(64),
            "a different body",
            NoteKind::Lesson,
            DEFAULT_AUTHORITY,
        );
        assert!(matches!(other, Err(ErrorCode::Conflict)));
        assert_eq!(residue(&mut handle), after_first);
        // remember.put's receipt namespace is separate: the same key there is a different operation.
        assert_eq!(after_first.memories, 1);
    });
}

/// PR #7 Codex P2: a replay reports the stored note's data class, not the request's resolution. The replay below
/// carries the same key and fingerprint but a different resolved `data_class` — what an omitted `data_class` becomes
/// after the gateway default changes — and must still answer for the SECRET_MATERIAL note it stored.
#[test]
fn g03_a_replay_reports_the_stored_data_class_not_the_current_default() {
    run_db_fixture::<Fixture, _>("g03_replay_data_class", |mut handle| {
        handle.seed_current_entitlement_and_window(8);
        let key = format!("class-{}", Uuid::new_v4());
        let fingerprint = "e".repeat(64);
        let attempt = |data_class: &str| {
            let (mut request, note) = note_request(
                &handle,
                &key,
                &fingerprint,
                "stored under the old default",
                NoteKind::Note,
                DEFAULT_AUTHORITY,
            );
            request.command.data_class = data_class.into();
            handle.rt.block_on(operation_receipt::note_put_atomically(
                &handle.runtime,
                &handle.auth,
                request,
                note,
                &humaux_adapters::attribution_repo::AttributionLadder,
            ))
        };
        let first = attempt("SECRET_MATERIAL").expect("first commit");
        assert!(!first.replayed && first.secret_material);
        let replay = attempt("INTERNAL").expect("replay of a committed key");
        assert!(replay.replayed);
        assert_eq!(replay.memory_id, first.memory_id);
        assert!(
            replay.secret_material,
            "the replay must report the stored SECRET_MATERIAL class, not the replaying request's"
        );
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// G04 / G05: no derivation, no provider, outbox replay enqueues nothing.
// ---------------------------------------------------------------------------------------------------------------------

fn provider_traces(handle: &mut Handle) -> (i64, i64, i64) {
    let row = handle
        .admin
        .query_one(
            "SELECT (SELECT count(*) FROM ops.distill_calls WHERE tenant_id=$1), \
                    (SELECT count(*) FROM ops.distill_tenant_scheduler WHERE tenant_id=$1), \
                    (SELECT count(*) FROM ops.model_call_ledger WHERE tenant_id=$1)",
            &[&handle.tenant_id],
        )
        .expect("owner reads provider traces");
    (row.get(0), row.get(1), row.get(2))
}

/// Gate: a note must leave no derivation job and no provider trace. A provider that is called even once makes it red.
fn assert_no_provider_traces(label: &str, jobs: i64, traces: (i64, i64, i64)) {
    // D-I: both derivation jobs call the LLM — a note enqueues neither (0235 skips distill by the contract and
    // consolidate by note_kind).
    assert_eq!(
        jobs, 0,
        "{label}: DERIVED_DISTILL jobs (and DERIVED_CONSOLIDATE)"
    );
    assert_eq!(
        traces,
        (0, 0, 0),
        "{label}: distill calls / scheduler turns / model ledger rows"
    );
}

#[test]
fn g04_g05_a_note_creates_no_distill_job_and_an_outbox_replay_creates_none() {
    run_db_fixture::<Fixture, _>("g04_g05_no_distill", |mut handle| {
        handle.seed_current_entitlement_and_window(8);
        // Control: remember.put for this tenant DOES enqueue a distill job (the assertion below can fail).
        ordinary_remember(&handle, "ordinary");
        assert_eq!(
            residue(&mut handle).distill_jobs,
            1,
            "control: ordinary evidence enqueues distill"
        );
        handle
            .admin
            .execute(
                "DELETE FROM ops.jobs WHERE tenant_id=$1",
                &[&handle.tenant_id],
            )
            .expect("clear the control job");
        handle
            .admin
            .execute(
                "DELETE FROM ops.distill_tenant_scheduler WHERE tenant_id=$1",
                &[&handle.tenant_id],
            )
            .expect("clear the control scheduler turn");

        let result = put_default(&handle, "verbatim, no model in the loop", NoteKind::Fix);
        let evidence_id = result.accepted.evidence_id;
        let after = residue(&mut handle);
        assert_no_provider_traces(
            "after note_put",
            after.distill_jobs,
            provider_traces(&mut handle),
        );
        // The EVIDENCE_ACCEPTED ticket exists and is already settled: projection must not wait on an open row.
        let outbox: Vec<(String, String)> = handle
            .admin
            .query(
                "SELECT event_type, status FROM ops.outbox WHERE tenant_id=$1 AND evidence_id=$2",
                &[&handle.tenant_id, &evidence_id],
            )
            .unwrap()
            .iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect();
        assert_eq!(
            outbox,
            vec![("EVIDENCE_ACCEPTED".to_owned(), "DONE".to_owned())]
        );
        // The ticket is claimable by projection (its EVIDENCE_ACCEPTED row is not open) and resolves, through the same
        // outbox -> memory_evidence join `projection_worker::resolve_memories` uses, to the note's Memory: recall
        // indexes it through the existing path, with no event of its own.
        let resolved: Vec<Uuid> = handle
            .admin
            .query(
                "SELECT me.memory_id FROM ops.outbox ob \
                   JOIN private.memory_evidence me ON me.evidence_id = ob.evidence_id \
                   JOIN projection.stream_log s ON s.tenant_id = ob.tenant_id AND s.commit_seq = ob.commit_seq \
                  WHERE ob.tenant_id = $1 AND ob.evidence_id = $2 AND ob.event_type = 'EVIDENCE_ACCEPTED' \
                    AND ob.status NOT IN ('PENDING','PROCESSING') AND s.state = 'ISSUED'",
                &[&handle.tenant_id, &evidence_id],
            )
            .unwrap()
            .iter()
            .map(|row| row.get(0))
            .collect();
        assert_eq!(resolved, vec![result.memory_id.unwrap()]);

        // G05: replay the outbox insert (twice, as a redriver would) — still one Memory, still no job.
        for n in 0..2_i64 {
            handle
                .admin
                .execute(
                    "INSERT INTO ops.outbox (tenant_id, commit_seq, stream_seq, event_type, evidence_id, status) \
                     SELECT tenant_id, commit_seq + 1000000000 + $3, stream_seq + 1000 + $3, 'EVIDENCE_ACCEPTED', evidence_id, 'PENDING' \
                       FROM ops.outbox WHERE tenant_id=$1 AND evidence_id=$2 LIMIT 1",
                    &[&handle.tenant_id, &evidence_id, &n],
                )
                .expect("replayed EVIDENCE_ACCEPTED row");
        }
        let replayed = residue(&mut handle);
        assert_eq!(replayed.memories, 1);
        let open_rows: i64 = handle
            .admin
            .query_one(
                "SELECT count(*) FROM ops.outbox WHERE tenant_id=$1 AND evidence_id=$2 AND status <> 'DONE'",
                &[&handle.tenant_id, &evidence_id],
            )
            .unwrap()
            .get(0);
        assert_eq!(
            open_rows, 0,
            "a replayed EVIDENCE_ACCEPTED row of a contracted Evidence is born settled"
        );
        assert_no_provider_traces(
            "after outbox replay",
            replayed.distill_jobs,
            provider_traces(&mut handle),
        );
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// G06: a contracted Evidence has exactly one PRIMARY output; ordinary distill may still make two.
// ---------------------------------------------------------------------------------------------------------------------

/// One extra PRIMARY Memory for `evidence_id`, written the way the distill hop writes it
/// (`distill_repo::insert_memory`'s two INSERTs), as a real role_gateway login.
fn forge_second_output(handle: &Handle, evidence_id: Uuid) -> Result<(), postgres::Error> {
    let mut client = handle.gateway_client().expect("gateway login");
    let mut txn = client.transaction()?;
    txn.execute(
        "SELECT set_config('humaux.tenant_id',$1,true), set_config('humaux.user_id',$2,true)",
        &[&handle.tenant_id.to_string(), &handle.user_id.to_string()],
    )?;
    let content = serde_json::json!({"title": "second", "key_claim": "a forged second output"});
    let memory_id: Uuid = txn
        .query_one(
            "INSERT INTO private.memory_records \
               (tenant_id, memory_type, content, visibility_class, visibility_user_id, \
                visibility_workspace_id, authority_class, confidence, status, asserted_at) \
             VALUES ($1, 'FACT', $2, 'WORKSPACE_SHARED', NULL, $3, 'PrivateKnowledge', 1.0, 'active', now()) \
             RETURNING memory_id",
            &[&handle.tenant_id, &content, &handle.workspace_id],
        )?
        .get(0);
    txn.execute(
        "INSERT INTO private.memory_evidence \
           (memory_id, evidence_id, role, ordinal, grounding_mode, recorded_version) \
         VALUES ($1, $2, 'PRIMARY', 0, 'IMMUTABLE', 'forged')",
        &[&memory_id, &evidence_id],
    )?;
    txn.commit()
}

#[test]
fn g06_a_second_primary_output_for_a_contracted_evidence_fails() {
    run_db_fixture::<Fixture, _>("g06_single_output", |mut handle| {
        handle.seed_current_entitlement_and_window(8);
        let note = put_default(&handle, "one note, one memory", NoteKind::Note);
        let before = residue(&mut handle);
        let forged = forge_second_output(&handle, note.accepted.evidence_id);
        let error = forged.expect_err("the contract admits no second output");
        let message = error
            .as_db_error()
            .map(|db| db.message().to_owned())
            .unwrap_or_default();
        assert!(
            message.contains("exactly one output Memory"),
            "refused by the identity-contract trigger, got: {error:?}"
        );
        assert_eq!(
            residue(&mut handle),
            before,
            "the refused output left nothing behind"
        );

        // Ordinary two-memory distill stays green: remember.put Evidence takes two PRIMARY outputs.
        let accepted = ordinary_remember(&handle, "ordinary-two");
        forge_second_output(&handle, accepted.accepted.evidence_id).expect("first ordinary output");
        forge_second_output(&handle, accepted.accepted.evidence_id)
            .expect("second ordinary output");
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// G02: a failure at any write point leaves nothing behind.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn g02_a_failure_at_each_write_point_leaves_no_residue() {
    run_db_fixture::<Fixture, _>("g02_no_residue", |mut handle| {
        handle.seed_current_entitlement_and_window(16);
        let baseline = residue(&mut handle);
        // Evidence, event, Memory, evidence link, contract, outbox, stream ticket, receipt, audit: each is a write point.
        for (table, column) in [
            ("private.evidence_objects", "tenant_id"),
            ("private.memory_records", "tenant_id"),
            ("private.identity_note_materializations", "tenant_id"),
            ("ops.outbox", "tenant_id"),
            ("projection.stream_log", "tenant_id"),
            ("control.operation_receipts", "tenant_id"),
        ] {
            let guard = fail_insert_on(&handle, table, column);
            let outcome = put(
                &handle,
                &format!("fail-{}", Uuid::new_v4()),
                &"1".repeat(64),
                "this write must vanish",
                NoteKind::Problem,
                DEFAULT_AUTHORITY,
            );
            assert!(
                outcome.is_err(),
                "{table}: the injected failure must surface"
            );
            assert_eq!(
                residue(&mut handle),
                baseline,
                "{table}: a failure at this write point leaves no Evidence / Memory / contract / outbox / receipt / audit"
            );
            drop(guard);
        }
        // With the injections gone the same path commits (the failures above were the injected ones).
        let ok = put_default(&handle, "now it works", NoteKind::Problem);
        assert!(ok.memory_id.is_some());
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// G01: nothing half-made is visible before COMMIT; the Memory is readable right after.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn g01_nothing_is_visible_or_stored_before_commit_and_the_memory_is_readable_after() {
    run_db_fixture::<Fixture, _>("g01_barrier", |mut handle| {
        handle.seed_current_entitlement_and_window(8);
        let before = residue(&mut handle);
        let application_name = format!("note-barrier-{}", Uuid::new_v4().simple());
        let actor_dsn = handle.gateway_application_dsn(&application_name);
        let (request, note) = note_request(
            &handle,
            &format!("barrier-{}", Uuid::new_v4()),
            &"2".repeat(64),
            "held before COMMIT",
            NoteKind::State,
            DEFAULT_AUTHORITY,
        );
        let auth: AuthorizationScope = handle.auth.clone();
        let (done_tx, done_rx) = mpsc::sync_channel(1);

        let mut owner_holder = handle.owner_client().expect("owner lock holder");
        let mut holder = owner_holder
            .transaction()
            .expect("begin barrier transaction");
        // The receipt INSERT is the last write before COMMIT: everything else is already done, uncommitted.
        holder
            .batch_execute("LOCK TABLE control.operation_receipts IN SHARE ROW EXCLUSIVE MODE")
            .expect("hold the receipt insert lock");
        let actor = std::thread::spawn(move || {
            let outcome = (|| -> Result<_, String> {
                let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
                // dep: PostgreSQL(role_gateway) — the actor's own real gateway pool
                let pool = rt
                    .block_on(RuntimeDbPool::connect(&actor_dsn))
                    .map_err(|e| e.to_string())?;
                Ok(rt.block_on(operation_receipt::note_put_atomically(
                    &pool,
                    &auth,
                    request,
                    note,
                    &humaux_adapters::attribution_repo::AttributionLadder,
                )))
            })();
            let _ = done_tx.send(outcome);
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let waiting: bool = handle
                .admin
                .query_one(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name=$1 \
                       AND wait_event_type='Lock')",
                    &[&application_name],
                )
                .expect("inspect actor")
                .get(0);
            if waiting {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the note transaction never reached the barrier"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        // The actor is parked after every other write: no `stored` yet, and another session sees nothing half-made.
        assert!(
            done_rx.try_recv().is_err(),
            "no response (no `stored`) may exist before COMMIT"
        );
        assert_eq!(
            residue(&mut handle),
            before,
            "another connection sees no Evidence / Memory / contract / outbox before COMMIT"
        );
        holder.rollback().expect("release the barrier");
        drop(owner_holder);
        let result = done_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("actor finishes after the barrier")
            .expect("actor ran")
            .expect("the note commits");
        actor.join().expect("actor joined");
        let memory_id = result.memory_id.expect("stored names its memory");
        // Right after COMMIT the Memory is there: active, with its contract and PRIMARY link.
        let row = stored(&mut handle, memory_id);
        assert_eq!(row.status, "active");
        assert_eq!(row.key_claim, "held before COMMIT");
        let after = residue(&mut handle);
        assert_eq!(
            (after.evidence, after.memories, after.contracts, after.links),
            (
                before.evidence + 1,
                before.memories + 1,
                before.contracts + 1,
                before.links + 1
            )
        );
    });
}

// ---------------------------------------------------------------------------------------------------------------------
// G-M06-5 / M06-3: exact-duplicate identity notes (ADR-0067 D3).
// ---------------------------------------------------------------------------------------------------------------------

/// The caller's own scope for one of the gate's two agents: same tenant/user/workspace, distinct principal.
fn scope_for(handle: &Handle, principal: Uuid) -> AuthorizationScope {
    AuthorizationScope::new(
        TenantId(handle.tenant_id),
        PrincipalId(principal),
        Some(UserId(handle.user_id)),
        BoundedSet::new([WorkspaceId(handle.workspace_id)]).expect("one workspace"),
    )
}

/// Issue #251: the admin transaction that holds the advisory lock must roll back on a panic. Without this, `Handle::drop`
/// runs its cleanup DELETEs inside the still-open transaction and the fixture tenant's rows are left behind.
struct RollbackOnPanic {
    client: Client,
    open: bool,
}

impl RollbackOnPanic {
    fn begin(mut client: Client) -> Self {
        client
            .batch_execute("BEGIN")
            .expect("owner opens a transaction");
        Self { client, open: true }
    }

    fn commit(mut self) {
        self.client
            .batch_execute("COMMIT")
            .expect("owner releases the lock");
        self.open = false;
    }
}

impl Drop for RollbackOnPanic {
    fn drop(&mut self) {
        if self.open {
            let _ = self.client.batch_execute("ROLLBACK");
        }
    }
}

/// G-M06-5: two principals write the same body, kind and visibility concurrently → exactly 1 Memory and 2 receipts. Both
/// calls return the one Memory; exactly one is [`Dedupe::Existing`]. The counts are read from the rows, not the results.
#[allow(clippy::too_many_lines)] // one gate: two live connections, a barrier, row counts, then both results
#[test]
fn identical_note_two_agents() {
    run_db_fixture::<Fixture, _>("identical_note_two_agents", |mut handle| {
        handle.seed_current_entitlement_and_window(10);
        let body = "one decision, restated by two agents";
        let kind = NoteKind::Decision;
        let principals = [Uuid::new_v4(), Uuid::new_v4()];
        let barrier = Arc::new(Barrier::new(principals.len()));
        let before = residue(&mut handle);

        let mut workers = Vec::new();
        for (index, principal) in principals.into_iter().enumerate() {
            // dep: PostgreSQL(role_gateway) — one real connection per concurrent agent.
            let dsn = handle.gateway_application_dsn(&format!("note-dedupe-{index}"));
            let auth = scope_for(&handle, principal);
            let fingerprint = payload_sha256(format!("{index}:{body}").as_bytes()).to_hex();
            let (request, note) = note_request_for(
                &handle,
                principal,
                "USER_PRIVATE",
                Some(handle.user_id),
                &format!("dedupe-key-{index}"),
                &fingerprint,
                body,
                kind,
                DEFAULT_AUTHORITY,
            );
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().expect("runtime");
                // dep: PostgreSQL(role_gateway) — the agent's own connection under test.
                let pool = rt
                    .block_on(RuntimeDbPool::connect(&dsn))
                    .expect("agent connection");
                barrier.wait();
                rt.block_on(operation_receipt::note_put_atomically(
                    &pool,
                    &auth,
                    request,
                    note,
                    &humaux_adapters::attribution_repo::AttributionLadder,
                ))
            }));
        }
        let outcomes: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker joined"))
            .collect();

        let after = residue(&mut handle);
        assert_eq!(
            after.memories - before.memories,
            1,
            "two identical notes are exactly one Memory"
        );
        assert_eq!(
            after.receipts - before.receipts,
            2,
            "each agent's operation has its own receipt"
        );
        assert_eq!(
            after.evidence - before.evidence,
            1,
            "only the first call wrote Evidence"
        );
        assert_eq!(
            after.contracts - before.contracts,
            1,
            "only the first call wrote a contract"
        );
        // The 0269 UNIQUE keys `private.identity_note_body_sha256(content)`; the lookup keys the contract's
        // `body_sha256`. The backstop only holds while both name one digest, so compare them on the stored rows.
        let split: i64 = handle
            .admin
            .query_one(
                "SELECT count(*) FROM private.memory_records m \
                   JOIN private.identity_note_materializations c \
                     ON c.tenant_id = m.tenant_id AND c.output_memory_id = m.memory_id \
                  WHERE m.tenant_id = $1 AND m.note_kind IS NOT NULL \
                    AND private.identity_note_body_sha256(m.content) <> c.body_sha256",
                &[&handle.tenant_id],
            )
            .expect("owner compares the index expression with the stored digest")
            .get(0);
        assert_eq!(split, 0, "the index expression and the lookup hash agree");

        let stored: Vec<operation_receipt::AtomicRememberResult> = outcomes
            .into_iter()
            .map(|outcome| outcome.expect("both notes commit"))
            .collect();
        assert_eq!(
            stored[0].memory_id, stored[1].memory_id,
            "both calls answer the same Memory"
        );
        assert!(
            stored[0].memory_id.is_some(),
            "a note call always names its Memory"
        );
        assert_eq!(
            stored
                .iter()
                .filter(|result| result.dedupe == Dedupe::Existing)
                .count(),
            1,
            "exactly one call is the dedupe hit"
        );
    });
}

#[allow(clippy::too_many_lines)] // one causal chain: hold, poll, still held, release, commit
/// M06-3 deterministic lock-wait test: an admin transaction holds the exact-duplicate key, the put must park on
/// `Lock/advisory`, write nothing, and finish after the holder commits. The key text is built here independently of the
/// production constructor, so adding a principal to that constructor makes this assertion see zero waiters.
#[test]
fn note_put_waits_on_exact_dedupe_lock() {
    run_db_fixture::<Fixture, _>("note_put_waits_on_exact_dedupe_lock", |mut handle| {
        handle.seed_current_entitlement_and_window(10);
        let body = "held before the exact-duplicate lock";
        let kind = NoteKind::Decision;
        let principal = Uuid::new_v4();
        let digest = hex::encode(NoteBody::new(body).expect("valid body").sha256());
        // ADR-0067 D3: tenant, visibility scope, note_kind, body SHA-256; no principal.
        let lock_text = format!(
            "identity-note:{}:USER_PRIVATE:{}::{kind}:{digest}",
            handle.tenant_id,
            handle.user_id,
            kind = kind.wire(),
        );
        // dep: PostgreSQL(role_gateway) — the put's own connection.
        let dsn = handle.gateway_application_dsn("note-dedupe-lock");
        let auth = scope_for(&handle, principal);
        let (request, note) = note_request_for(
            &handle,
            principal,
            "USER_PRIVATE",
            Some(handle.user_id),
            "dedupe-lock-key",
            &"b".repeat(64),
            body,
            kind,
            DEFAULT_AUTHORITY,
        );
        let before = residue(&mut handle);

        // dep: PostgreSQL(owner) — a second session holds the same key; the guard rolls it back on any panic (#251).
        let mut lock = RollbackOnPanic::begin(handle.owner_client().expect("owner connection"));
        lock.client
            .execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                &[&lock_text],
            )
            .expect("owner takes the exact-duplicate key");

        let putter = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("runtime");
            // dep: PostgreSQL(role_gateway) — the put's own connection under test.
            let pool = rt
                .block_on(RuntimeDbPool::connect(&dsn))
                .expect("agent connection");
            rt.block_on(operation_receipt::note_put_atomically(
                &pool,
                &auth,
                request,
                note,
                &humaux_adapters::attribution_repo::AttributionLadder,
            ))
        });

        // (ungranted advisory requests on exactly this key, of which those the backend reports as `Lock/advisory`, and the
        // wait events seen for diagnostics)
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
            "the note put's backend is waiting on the exact-duplicate key (finished: {})",
            putter.is_finished()
        );
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            waiting(&mut handle),
            (1, 1, "Lock/advisory".to_string()),
            "the note put is still waiting"
        );
        assert!(
            !putter.is_finished(),
            "the note put has not completed while the lock is held"
        );
        assert_eq!(
            residue(&mut handle),
            before,
            "a waiting note put has written nothing"
        );

        lock.commit();
        let stored = putter
            .join()
            .expect("put thread")
            .expect("the note commits after release");
        assert_eq!(stored.dedupe, Dedupe::New);
        let after = residue(&mut handle);
        assert_eq!(after.memories - before.memories, 1);
        assert_eq!(after.evidence - before.evidence, 1);
        assert_eq!(after.contracts - before.contracts, 1);
        assert_eq!(after.receipts - before.receipts, 1);
    });
}

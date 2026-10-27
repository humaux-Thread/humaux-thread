//! `adapters::note_repo` — the verbatim note lane's write half: the identity contract and the one authorised Memory of
//!   `memory.note_put`, written inside the caller's Evidence transaction (ADR-0067 D-A/D-B/D-C/D-E), plus the exact-duplicate
//!   key of a create (M06-3).
//! Depends-on: crates=[hex, humaux-domain, serde_json, sqlx]; services=[PostgreSQL(any) r=[ops.outbox, private.evidence_objects, private.identity_note_materializations, private.memory_records, projection.stream_log] w=[private.identity_note_materializations, private.memory_records, private.note_heads]]; env=[]; modules=[adapters::memory_repo, adapters::remember, domain::authority, domain::error, domain::evidence, domain::note]
//! Called-by: [adapters::operation_receipt, adapters::remember, gateway::guard, gateway::mcp_application, tests]
//! Invariants: [no SQL here commits; the Memory is written only through memory_repo::insert_memory_in_txn (the workspace's single
//!   memory INSERT); the contract row is written after the Memory and before the EVIDENCE_ACCEPTED outbox row so the 0235
//!   enqueue trigger skips distill; the authority decision precedes every write; a replacement supersedes exactly the
//!   CAS-checked head in one guarded UPDATE and moves the head row in the same transaction (ADR-0067 D-J); an exact-duplicate
//!   note is the same tenant, visibility scope, note_kind and body SHA-256 with an active unarchived first version, and the
//!   advisory-lock text of that key has exactly one constructor here and carries no principal (ADR-0067 D3, M06-3); the
//!   Memory's producer is `NotePut`, so its epistemic status is SOURCE_REPORTED whatever the fixed origin class
//!   `AuthenticatedAgent` or the granted authority (ADR-0124)]
//! Spec: Baseline §8.5; §10.1; §34; ADR-0067; ADR-0124
//!
//! [`NoteIntake`] is everything the gateway edge decided about one note (kind, title, validated body, requested authority);
//! [`authorize`] is the pure ADR-0067 D-C decision and [`materialize_in_txn`] the two INSERTs that follow the Evidence
//! rows. Both are called by `remember::remember_in_txn_with` only — a note is never written outside the receipt
//! transaction, so there is no second write path to keep in step.

use humaux_domain::authority::AuthorityClass;
use humaux_domain::error::ErrorCode;
use humaux_domain::evidence::EvidenceOriginClass;
use humaux_domain::note::{
    NoteBody, NoteKind, POLICY_VERSION, REPRESENTATION, STRATEGY_IDENTITY_NOTE_V1, authorize_note,
};
use sqlx::Row;
use sqlx::types::Uuid;

use crate::memory_repo::{self, AttributionSource, LoadedEvidence, MemoryProducer, NewMemory};
use crate::remember::{RememberCommand, RememberError};

/// One note as the gateway edge validated it (ADR-0067 D-C/D-D/D-E).
#[derive(Debug, Clone)]
pub struct NoteIntake {
    /// The author's classification; selects the stored `memory_type`.
    pub kind: NoteKind,
    /// The stored title: explicit or derived (`domain::note::note_title`).
    pub title: String,
    /// The validated verbatim body and its digest.
    pub body: NoteBody,
    /// The exact authority the caller asked for (default `PrivateKnowledge`); granted as asked or refused.
    pub requested: AuthorityClass,
}

/// ADR-0067 D-J: which note a `memory.note_put` writes a version of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteLineage {
    /// A fresh note: its `note_id` is its own first `memory_id`, and its `note_heads` row is born pointing at it.
    Create,
    /// A new version of `note_id` superseding `supersedes`, the head the caller CAS-checked under the head-row lock.
    Replace {
        /// The note's identity (its first version's `memory_id`).
        note_id: Uuid,
        /// The current head version this one replaces.
        supersedes: Uuid,
    },
}

/// ADR-0067 D-C: `Ok(class)` when the server-fixed origin's ceiling grants exactly `requested`, else
/// [`RememberError::Note`]`(FORBIDDEN)` — raised before the first write, so nothing is stored.
pub(crate) fn authorize(note: &NoteIntake) -> Result<AuthorityClass, RememberError> {
    authorize_note(note.kind, note.requested).map_err(|_| RememberError::Note(ErrorCode::Forbidden))
}

/// §34.0.1 / ADR-0067 D3: the exact-duplicate note of a create as the receipt and its stream coordinates name it. `None`
/// from [`find_exact_note_in_txn`] means the key is unused (or its EVIDENCE_ACCEPTED ticket is tombstoned, so a receipt
/// could not point at it; the 0269 UNIQUE then refuses the duplicate insert).
#[derive(Debug)]
pub(crate) struct ExactNoteHit {
    /// The existing first version's Evidence.
    pub evidence_id: Uuid,
    /// The Memory that Evidence materialised; for a first version this is also the note's `note_id`.
    pub memory_id: Uuid,
    /// `private.evidence_objects.data_class` of the existing Evidence (the hit's answer, not the request's default).
    pub data_class: String,
    /// `projection.stream_log.scope_kind` of the existing Evidence's accepted ticket (0114 repeats it in the receipt).
    pub scope_kind: String,
    /// `projection.stream_log.scope_id`.
    pub scope_id: Uuid,
    /// `projection.stream_log.domain`.
    pub domain: String,
    /// `projection.stream_log.projection_kind`.
    pub projection_kind: String,
    /// `projection.stream_log.projection_version`.
    pub projection_version: String,
    /// `projection.stream_log.stream_seq`.
    pub stream_seq: i64,
    /// `projection.stream_log.commit_seq`.
    pub commit_seq: i64,
}

/// ADR-0067 D3 / M06-3: the one advisory-lock text of an exact-duplicate note key. D3's owner is the note's visibility
/// user (a note row stores no separate owner column; for `USER_PRIVATE` that user is the owner, and a wider class is owned
/// by its workspace/tenant scope), so the text is the full D3 key: tenant, visibility scope, note_kind, body SHA-256. No
/// principal, operation key, project, title or time appears, so every agent writing one body queues on one key.
pub(crate) fn exact_dedupe_lock_key(
    tenant_id: Uuid,
    visibility_class: &str,
    visibility_user_id: Option<Uuid>,
    visibility_workspace_id: Option<Uuid>,
    kind: NoteKind,
    body_sha256: &[u8; 32],
) -> String {
    format!(
        "identity-note:{tenant_id}:{visibility_class}:{}:{}:{}:{}",
        visibility_user_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
        visibility_workspace_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
        kind.wire(),
        hex::encode(body_sha256)
    )
}

/// ADR-0067 D3 / M06-3: the active, unarchived first version of a note with exactly this tenant, visibility scope,
/// `note_kind` and body SHA-256, with the live `EVIDENCE_ACCEPTED` ticket a receipt can repeat. A replacement head is not
/// a candidate: its `note_id <> memory_id`, and a create that matched it would answer a `memory_id` its caller reads as
/// `note_id` (the response carries no second id). The caller holds [`exact_dedupe_lock_key`] in this transaction; the 0269
/// UNIQUE index is the backstop.
pub(crate) async fn find_exact_note_in_txn(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    cmd: &RememberCommand,
    note: &NoteIntake,
) -> Result<Option<ExactNoteHit>, sqlx::Error> {
    let Some(row) = sqlx::query(
        "SELECT c.evidence_id, m.memory_id, e.data_class, l.scope_kind, l.scope_id, l.domain, \
                l.projection_kind, l.projection_version, l.stream_seq, l.commit_seq \
           FROM private.memory_records m \
           JOIN private.identity_note_materializations c \
             ON c.tenant_id = m.tenant_id AND c.output_memory_id = m.memory_id \
           JOIN private.evidence_objects e \
             ON e.tenant_id = c.tenant_id AND e.evidence_id = c.evidence_id \
           JOIN ops.outbox o \
             ON o.tenant_id = e.tenant_id AND o.evidence_id = e.evidence_id \
            AND o.event_type = 'EVIDENCE_ACCEPTED' \
           JOIN projection.stream_log l \
             ON l.tenant_id = o.tenant_id AND l.commit_seq = o.commit_seq \
          WHERE m.tenant_id = $1 AND m.status = 'active' AND m.archived_at IS NULL \
            AND m.note_kind = $2 AND m.note_id = m.memory_id \
            AND m.visibility_class = $3 \
            AND m.visibility_user_id IS NOT DISTINCT FROM $4 \
            AND m.visibility_workspace_id IS NOT DISTINCT FROM $5 \
            AND c.body_sha256 = $6 AND l.state <> 'TOMBSTONED' \
          ORDER BY o.commit_seq LIMIT 1",
    )
    .bind(tenant_id)
    .bind(note.kind.wire())
    .bind(&cmd.visibility_class)
    .bind(cmd.visibility_user_id)
    .bind(cmd.visibility_workspace_id)
    .bind(note.body.sha256().as_slice())
    .fetch_optional(&mut **txn)
    .await?
    else {
        return Ok(None);
    };
    Ok(Some(ExactNoteHit {
        evidence_id: row.try_get("evidence_id")?,
        memory_id: row.try_get("memory_id")?,
        data_class: row.try_get("data_class")?,
        scope_kind: row.try_get("scope_kind")?,
        scope_id: row.try_get("scope_id")?,
        domain: row.try_get("domain")?,
        projection_kind: row.try_get("projection_kind")?,
        projection_version: row.try_get("projection_version")?,
        stream_seq: row.try_get("stream_seq")?,
        commit_seq: row.try_get("commit_seq")?,
    }))
}

/// The Memory's `content` jsonb (ADR-0067 D-E): the body is `key_claim`, byte for byte.
fn memory_content(note: &NoteIntake) -> serde_json::Value {
    serde_json::json!({
        "title": note.title,
        "key_claim": note.body.text(),
        "representation": REPRESENTATION,
    })
}

/// Writes the note's Memory (through the workspace's single `insert_memory_in_txn`, PRIMARY `memory_evidence` link included) and
/// its identity-contract row, in the caller's transaction. `class` is [`authorize`]'s grant. Returns the new `memory_id`.
/// ADR-0067 D-J steps 3-6: a [`NoteLineage::Create`] also writes the note's head row; a [`NoteLineage::Replace`] then
/// supersedes the old head and moves the head row to the new version (0 rows on either = `CONFLICT`, rolled back).
pub(crate) async fn materialize_in_txn(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    cmd: &RememberCommand,
    evidence_id: Uuid,
    note: &NoteIntake,
    lineage: NoteLineage,
    class: AuthorityClass,
    attribution: &dyn memory_repo::MemoryAttribution,
) -> Result<Uuid, RememberError> {
    let loaded = LoadedEvidence {
        evidence_id,
        reasoning_domain_id: cmd.reasoning_domain_id,
        origin_class: EvidenceOriginClass::AuthenticatedAgent,
        origin_class_wire: "AuthenticatedAgent".to_owned(),
        origin_principal_id: cmd.origin_principal_id,
        data_class: cmd.data_class.clone(),
        visibility_class: cmd.visibility_class.clone(),
        visibility_user_id: cmd.visibility_user_id,
        visibility_workspace_id: cmd.visibility_workspace_id,
        occurred_at: cmd.occurred_at,
        payload_sha256: hex::decode(cmd.payload_sha256.to_hex())
            .map_err(|_| RememberError::Note(ErrorCode::Internal))?,
        event_kind: cmd.event_kind.clone(),
        payload: cmd.event_payload.clone(),
        rls_user_id: cmd.authorization_user_id.unwrap_or_else(Uuid::nil),
    };
    let memory_id = memory_repo::insert_memory_in_txn(
        txn,
        cmd.tenant_id,
        &loaded,
        &NewMemory {
            content: &memory_content(note),
            memory_type: note.kind.memory_type(),
            class,
            // A verbatim assertion is recorded exactly; the author's classification certifies no truth (D-D).
            confidence: 1.0,
            note_kind: Some(note.kind),
            note_id: match lineage {
                NoteLineage::Create => None,
                NoteLineage::Replace { note_id, .. } => Some(note_id),
            },
            attribution: AttributionSource::Primary,
            // ADR-0124 D-B: the caller's verbatim assertion; the fixed AuthenticatedAgent origin above is not the key.
            producer: MemoryProducer::NotePut,
        },
        attribution,
    )
    .await?;
    sqlx::query(
        "INSERT INTO private.identity_note_materializations \
           (tenant_id, evidence_id, strategy, output_memory_id, body_sha256, policy_version) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(cmd.tenant_id)
    .bind(evidence_id)
    .bind(STRATEGY_IDENTITY_NOTE_V1)
    .bind(memory_id)
    .bind(note.body.sha256().as_slice())
    .bind(POLICY_VERSION)
    .execute(&mut **txn)
    .await?;
    let moved = match lineage {
        NoteLineage::Create => sqlx::query(
            "INSERT INTO private.note_heads (tenant_id, note_id, head_memory_id) VALUES ($1, $2, $2)",
        )
        .bind(cmd.tenant_id)
        .bind(memory_id)
        .execute(&mut **txn)
        .await?
        .rows_affected(),
        NoteLineage::Replace {
            note_id,
            supersedes,
        } => {
            // ADR-0067 D-J step 5: one statement, guarded on `active`; superseded_by names a row that already exists.
            let superseded = sqlx::query(
                "UPDATE private.memory_records \
                    SET status = 'superseded', superseded_by = $3, superseded_at = clock_timestamp() \
                  WHERE tenant_id = $1 AND memory_id = $2 AND note_id = $4 AND status = 'active'",
            )
            .bind(cmd.tenant_id)
            .bind(supersedes)
            .bind(memory_id)
            .bind(note_id)
            .execute(&mut **txn)
            .await?
            .rows_affected();
            // Step 6: the head moves only from the version just superseded.
            let head = sqlx::query(
                "UPDATE private.note_heads SET head_memory_id = $3 \
                  WHERE tenant_id = $1 AND note_id = $2 AND head_memory_id = $4",
            )
            .bind(cmd.tenant_id)
            .bind(note_id)
            .bind(memory_id)
            .bind(supersedes)
            .execute(&mut **txn)
            .await?
            .rows_affected();
            superseded.min(head)
        }
    };
    if moved != 1 {
        return Err(RememberError::Note(ErrorCode::Conflict));
    }
    Ok(memory_id)
}

/// The Memory an identity-contracted Evidence materialised and the Evidence's stored `data_class`, if any — used to
/// replay a committed `memory.note_put`: the replay answers from the stored row, never from the gateway's current
/// default (PR #7 Codex P2). Runs under the caller's RLS context.
pub(crate) async fn output_memory(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    evidence_id: Uuid,
) -> Result<Option<(Uuid, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT c.output_memory_id, e.data_class FROM private.identity_note_materializations c \
         JOIN private.evidence_objects e ON e.tenant_id = c.tenant_id AND e.evidence_id = c.evidence_id \
         WHERE c.tenant_id = $1 AND c.evidence_id = $2",
    )
    .bind(tenant_id)
    .bind(evidence_id)
    .fetch_optional(&mut **txn)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_repo::authority_class_to_db_str;
    use humaux_domain::note::requested_authority_wire;

    /// §78.2: the wire spelling of `requested_authority` is `private.memory_records.authority_class` verbatim — the
    /// domain table and the adapter's one DB mapping may not drift apart.
    #[test]
    fn requested_authority_wire_is_the_db_spelling() {
        for (wire, class) in requested_authority_wire() {
            assert_eq!(*wire, authority_class_to_db_str(*class));
        }
    }

    /// D-C: an above-ceiling request is refused before any write, and the grant is exactly what was asked.
    #[test]
    fn authorize_grants_exactly_or_refuses() {
        let mut note = NoteIntake {
            kind: NoteKind::Decision,
            title: "t".into(),
            body: NoteBody::new("b").unwrap(),
            requested: AuthorityClass::PrivateKnowledge,
        };
        assert!(matches!(
            authorize(&note),
            Ok(AuthorityClass::PrivateKnowledge)
        ));
        note.requested = AuthorityClass::ProjectDecision;
        assert!(matches!(
            authorize(&note),
            Err(RememberError::Note(ErrorCode::Forbidden))
        ));
    }
}

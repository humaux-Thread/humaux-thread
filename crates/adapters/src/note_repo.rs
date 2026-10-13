//! `adapters::note_repo` — the verbatim note lane's write half: the identity contract and the one authorised Memory of
//!   `memory.note_put`, written inside the caller's Evidence transaction (ADR-0067 D-A/D-B/D-C/D-E).
//! Depends-on: crates=[hex, humaux-domain, serde_json, sqlx]; services=[PostgreSQL(any) r=[private.identity_note_materializations] w=[private.identity_note_materializations, private.memory_records, private.note_heads]]; env=[]; modules=[adapters::distill_repo, adapters::remember, domain::authority, domain::error, domain::evidence, domain::note]
//! Called-by: [adapters::operation_receipt, adapters::remember, gateway::guard, gateway::mcp_application, tests]
//! Invariants: [no SQL here commits; the Memory is written only through distill_repo::insert_memory (the workspace's single
//!   memory INSERT); the contract row is written after the Memory and before the EVIDENCE_ACCEPTED outbox row so the 0235
//!   enqueue trigger skips distill; the authority decision precedes every write; a replacement supersedes exactly the
//!   CAS-checked head in one guarded UPDATE and moves the head row in the same transaction (ADR-0067 D-J)]
//! Spec: Baseline §8.5; §10.1; §34; ADR-0067
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
use sqlx::types::Uuid;

use crate::distill_repo::{self, LoadedEvidence, NewMemory};
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

/// The Memory's `content` jsonb (ADR-0067 D-E): the body is `key_claim`, byte for byte.
fn memory_content(note: &NoteIntake) -> serde_json::Value {
    serde_json::json!({
        "title": note.title,
        "key_claim": note.body.text(),
        "representation": REPRESENTATION,
    })
}

/// Writes the note's Memory (through the workspace's single `insert_memory`, PRIMARY `memory_evidence` link included) and
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
    let memory_id = distill_repo::insert_memory(
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
        },
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
    use crate::consolidate_repo::authority_class_to_db_str;
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

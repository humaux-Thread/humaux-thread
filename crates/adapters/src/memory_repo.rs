//! `adapters::memory_repo` — the sole `INSERT INTO private.memory_records` door (M07 D9, gate G-M07-1): one authorized Memory plus its PRIMARY
//!   `memory_evidence` link, written in the caller's transaction.
//! Depends-on: crates=[async-trait, hex, humaux-domain, serde_json, sqlx]; services=[PostgreSQL(any) r=[private.memory_text_v] w=[private.memory_evidence, private.memory_records]]; env=[]; modules=[adapters::subject_repo, domain::authority, domain::evidence, domain::memory, domain::note]
//! Called-by: [adapters::attribution_repo, adapters::consolidate_repo, adapters::consolidation_reasoner, adapters::distill_reasoner, adapters::distill_repo, adapters::memory_governance_repo, adapters::note_repo, adapters::operation_receipt, adapters::remember, tests]
//! Invariants: [every non-test Memory INSERT in the workspace is this one statement (xtask architecture-check G-M07-1, counted `== 1`); the
//!   Memory row and its PRIMARY `memory_evidence` link are written together, because 0004's deferred `memory_records_requires_evidence` trigger
//!   needs both by COMMIT; visibility is the Evidence's own three columns verbatim and a Memory's authority class is the caller's
//!   `AuthorizedAuthority`, never the raw candidate class; the deterministic subject resolve hook runs here exactly once per Memory;
//!   the attribution port runs here exactly once per Memory, after the subject hook, and is a required argument (ADR-0078 D-D,
//!   xtask G-M29-5(a)); this module never imports its M29 implementation (no L3 -> L4 edge);
//!   the statement runs inside the caller's transaction and never commits; this module imports no Distill-hop code, the hop imports it;
//!   this module reads a Memory's canonical text only through `private.memory_text_v` ([`memory_texts_in_txn`], M07 D1)]
//! Spec: Baseline §8.5; §8.6; §6.1.3; §6.1.4; §10.1; ADR-0016; ADR-0028; ADR-0067; ADR-0078; ADR-0085
//!
//! [`insert_memory_in_txn`] writes one Memory (ADR-0016 D4 visibility copy, ADR-0067 D-J note lineage, ADR-0028 subject hook) from the two
//! types it takes: [`NewMemory`] (what to write) and [`LoadedEvidence`] (the Evidence row it is grounded on and inherits visibility from).
//! Callers are the Distill confirm path, the private worker's write leg (through `distill_repo`'s re-exports), `memory.correct` and
//! `memory.note_put`; each passes the [`MemoryAttribution`] its process's composition root built.
//!
//! [`memory_texts_in_txn`] is the Rust half of the one place a Memory's text is resolved (M07 D1, ADR-0085): it selects from
//! `private.memory_text_v`; SQL readers join that view.

use humaux_domain::authority::AuthorityClass;
use humaux_domain::evidence::EvidenceOriginClass;
use humaux_domain::memory::MemoryType;
use humaux_domain::note::NoteKind;
use serde_json::Value;
use sqlx::types::Uuid;
use sqlx::types::time::OffsetDateTime;

/// One Evidence as the Distill hop reads it: the `evidence_objects` row plus its `events` subtype.
#[derive(Debug, Clone)]
pub struct LoadedEvidence {
    pub evidence_id: Uuid,
    pub reasoning_domain_id: Uuid,
    pub origin_class: EvidenceOriginClass,
    /// The DB CHECK literal of `origin_class` (what the envelope shows the model).
    pub origin_class_wire: String,
    pub origin_principal_id: Option<Uuid>,
    pub data_class: String,
    pub visibility_class: String,
    pub visibility_user_id: Option<Uuid>,
    pub visibility_workspace_id: Option<Uuid>,
    pub occurred_at: Option<OffsetDateTime>,
    /// `private.evidence_objects.payload_sha256` verbatim (what `processing_runs.
    /// evidence_payload_sha256[]` records).
    pub payload_sha256: Vec<u8>,
    pub event_kind: String,
    pub payload: Value,
    /// The acting user installed for RLS while reading `payload` — the Evidence's own user
    /// for USER_PRIVATE, else `owner_user_id`; the write leg reuses it.
    pub rls_user_id: Uuid,
}

/// One authorized memory to insert — `class` is the `AuthorizedAuthority` §10.1 returned, never
/// the raw candidate class.
#[derive(Debug, Clone)]
pub struct NewMemory<'a> {
    pub content: &'a Value,
    pub memory_type: MemoryType,
    pub class: AuthorityClass,
    pub confidence: f32,
    /// ADR-0067 D-D: `Some` only for a verbatim note written by `memory.note_put`; every distilled,
    /// confirmed or corrected Memory is `None`.
    pub note_kind: Option<NoteKind>,
    /// ADR-0067 D-J, with `note_kind` only: `None` = a fresh note, whose `note_id` is its own new `memory_id`;
    /// `Some(note_id)` = a new version of that note. A non-note Memory stores NULL whatever this says (0236 CHECK).
    pub note_id: Option<Uuid>,
    /// ADR-0078 D-D (attribution Evidence): which Evidence the §6.1.4 ladder reads and every row's
    /// `decision_evidence_id` names. Required and without a default, so every caller chooses a variant.
    pub attribution: AttributionSource,
}

/// ADR-0078 D-D (attribution Evidence): a closed choice, not a free id, so no caller can hand
/// [`insert_memory_in_txn`] an Evidence it did not mean; the door resolves it to the id the port reads.
#[derive(Debug, Clone, Copy)]
pub enum AttributionSource {
    /// The PRIMARY Evidence the door links itself (distill, `memory.correct`, `memory.note_put`).
    Primary,
    /// `memory.confirm` only: the candidate's `source_evidence_id` (E1), the provenance §6.1.3 rule 3a reads.
    /// Taken from the stored candidate row, never derived from request input.
    CandidateSource(Uuid),
}

/// ADR-0078 D-D (Q1 ruling): the attribution port M07 defines next to its Memory INSERT door. M29 implements it
/// (`adapters::attribution_repo`) and composition roots supply the implementation, so M07 never depends on M29.
/// [`insert_memory_in_txn`] takes it as a required argument and invokes it exactly once (xtask G-M29-5(a)).
#[async_trait::async_trait]
pub trait MemoryAttribution: Send + Sync {
    /// §6.1.4: writes the formal `private.memory_projects` rows of `memory_id`, whose attribution Evidence
    /// ([`NewMemory::attribution`], resolved) is `evidence_id`, in the caller's transaction; when no rung holds, or the
    /// Evidence is invisible under the caller's RLS, it writes nothing (N09 R3).
    ///
    /// # Errors
    /// Any `sqlx::Error`; the door returns it unchanged to its caller, which owns the transaction and its mapping.
    async fn link_memory_projects(
        &self,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant_id: Uuid,
        memory_id: Uuid,
        evidence_id: Uuid,
    ) -> Result<(), sqlx::Error>;
}

/// `private.memory_records.memory_type` CHECK literal of every [`MemoryType`] (write-side inverse of
/// `projection_worker::parse_memory_type`).
pub(crate) const fn memory_type_db_str(memory_type: MemoryType) -> &'static str {
    match memory_type {
        MemoryType::Fact => "FACT",
        MemoryType::Preference => "PREFERENCE",
        MemoryType::Decision => "DECISION",
        MemoryType::Rejection => "REJECTION",
        MemoryType::State => "STATE",
        MemoryType::Issue => "ISSUE",
        MemoryType::Lesson => "LESSON",
        MemoryType::Constraint => "CONSTRAINT",
        MemoryType::Procedure => "PROCEDURE",
        MemoryType::Outcome => "OUTCOME",
        MemoryType::Reference => "REFERENCE",
        MemoryType::Note => "NOTE",
    }
}

/// `AuthorityClass`'s DB text encoding (`private.memory_records.authority_class` and
/// `private.memory_rollups.authority_class` are `text`, not a dedicated Postgres enum) — the one
/// write-side mapping for the whole crate (§78.2); the read-side inverse is
/// `consolidate_repo::authority_class_from_db_str`.
pub(crate) const fn authority_class_to_db_str(class: AuthorityClass) -> &'static str {
    match class {
        AuthorityClass::PublicKnowledge => "PublicKnowledge",
        AuthorityClass::PrivateKnowledge => "PrivateKnowledge",
        AuthorityClass::UserPreference => "UserPreference",
        AuthorityClass::ProjectDecision => "ProjectDecision",
        AuthorityClass::UserCorrection => "UserCorrection",
        AuthorityClass::ProjectConstraint => "ProjectConstraint",
        AuthorityClass::ExplicitTaskContext => "ExplicitTaskContext",
    }
}

/// `memory_records` + its PRIMARY `memory_evidence` link (ordinal 0) in the caller's
/// transaction (0004's deferred `memory_records_requires_evidence` trigger needs both by
/// COMMIT). Visibility is the Evidence's own three columns verbatim (ADR-0016 D4).
/// Grounding: the link is `IMMUTABLE` against the Evidence's `payload_sha256` — an EVENT
/// payload is content-addressed and never rewritten (§8.1), so the recorded version is that
/// digest's hex (§8.8: IMMUTABLE edges are excluded from the recheck derivation).
///
/// §6.1.3 / ADR-0028: this is the workspace's single `INSERT INTO private.memory_records`
/// (Distill hop, `memory.confirm`, `memory.correct`, `memory.note_put` all route here), so the
/// deterministic subject resolve hook runs here once — after the PRIMARY link exists, because
/// the hook reads it — and no sibling writer can forget it. Explicit links (rules 1/2) are the
/// caller's; the hook adds rule 3 (Evidence declaration / correction predecessor) and
/// byte-span mentions.
///
/// §6.1.4 / ADR-0078 D-D: `attribution` (rungs A1 and A3) runs once, last, after the PRIMARY link and the subject hook.
///
/// # Errors
/// Any `sqlx::Error` from these statements or from `attribution`; the caller owns the transaction and its mapping.
pub async fn insert_memory_in_txn(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    evidence: &LoadedEvidence,
    memory: &NewMemory<'_>,
    attribution: &dyn MemoryAttribution,
) -> Result<Uuid, sqlx::Error> {
    // ADR-0067 D-J: the id is drawn once (the column's own uuidv7()) so a fresh note's note_id can equal it in the same
    // statement; `$11` names the note a new version joins.
    let memory_id: Uuid = sqlx::query_scalar(
        "INSERT INTO private.memory_records \
           (memory_id, tenant_id, memory_type, content, visibility_class, visibility_user_id, \
            visibility_workspace_id, authority_class, confidence, status, asserted_at, occurred_at, \
            note_kind, note_id) \
         SELECT g.id, $1, $2, $3, $4, $5, $6, $7, $8, 'active', now(), $9, $10, \
                CASE WHEN $10::text IS NULL THEN NULL ELSE COALESCE($11::uuid, g.id) END \
           FROM (SELECT uuidv7() AS id) AS g \
         RETURNING memory_id",
    )
    .bind(tenant_id)
    .bind(memory_type_db_str(memory.memory_type))
    .bind(memory.content)
    .bind(&evidence.visibility_class)
    .bind(evidence.visibility_user_id)
    .bind(evidence.visibility_workspace_id)
    .bind(authority_class_to_db_str(memory.class))
    .bind(memory.confidence)
    .bind(evidence.occurred_at)
    .bind(memory.note_kind.map(NoteKind::wire))
    .bind(memory.note_id)
    .fetch_one(&mut **txn)
    .await?;
    sqlx::query(
        "INSERT INTO private.memory_evidence \
           (memory_id, evidence_id, role, ordinal, grounding_mode, recorded_version) \
         VALUES ($1, $2, 'PRIMARY', 0, 'IMMUTABLE', $3)",
    )
    .bind(memory_id)
    .bind(evidence.evidence_id)
    .bind(hex::encode(&evidence.payload_sha256))
    .execute(&mut **txn)
    .await?;
    crate::subject_repo::link_memory_in_txn(txn, tenant_id, memory_id, &[]).await?;
    let attribution_evidence_id = match memory.attribution {
        AttributionSource::Primary => evidence.evidence_id,
        AttributionSource::CandidateSource(source_evidence_id) => source_evidence_id,
    };
    attribution
        .link_memory_projects(txn, tenant_id, memory_id, attribution_evidence_id)
        .await?;
    Ok(memory_id)
}

/// One row of `private.memory_text_v`: the canonical text of one Memory (M07 D1, ADR-0085 D-A). `None` is SQL NULL: a Memory
/// whose `content` has no `title` / `key_claim` (a non-note kind), or an identity note whose Evidence payload is not a JSON
/// string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryText {
    /// The Memory this text belongs to.
    pub memory_id: Uuid,
    /// `content ->> 'title'`.
    pub title: Option<String>,
    /// The identity note's Evidence payload text, or `content ->> 'key_claim'` for any other Memory (ADR-0085 D-A).
    pub body: Option<String>,
}

/// Reads the canonical text of `memory_ids` from `private.memory_text_v` in the caller's transaction, ordered by `memory_id`.
/// The view is `security_invoker`, so a Memory the caller's role and RLS context cannot read is absent from the result, never
/// returned with a NULL body. Empty input runs no query.
///
/// # Errors
/// Any `sqlx::Error` from the statement; the caller owns the transaction and its mapping.
pub async fn memory_texts_in_txn(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    memory_ids: &[Uuid],
) -> Result<Vec<MemoryText>, sqlx::Error> {
    if memory_ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows: Vec<(Uuid, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT memory_id, title, body FROM private.memory_text_v \
          WHERE tenant_id = $1 AND memory_id = ANY($2) ORDER BY memory_id",
    )
    .bind(tenant_id)
    .bind(memory_ids)
    .fetch_all(&mut **txn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(memory_id, title, body)| MemoryText {
            memory_id,
            title,
            body,
        })
        .collect())
}

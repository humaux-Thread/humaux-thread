//! `adapters::evidence_repo` — the sole `INSERT INTO private.evidence_objects` door (M07 D9, gate G-M07-1): one `evidence_kind = 'EVENT'`
//!   identity row, written in the caller's transaction.
//! Depends-on: crates=[humaux-domain, sqlx]; services=[PostgreSQL(any) w=[private.evidence_objects]]; env=[CARGO_MANIFEST_DIR]; modules=[domain::evidence]
//! Called-by: [adapters::context_repo, adapters::remember]
//! Invariants: [every non-test Evidence INSERT in the workspace is this one statement (xtask architecture-check G-M07-1, counted `== 1`); the
//!   statement runs inside the caller's transaction and never commits, so a caller's rollback discards the row; `evidence_id` and `created_at`
//!   are the table's own defaults, never bound; the digest is bound as the hex of an `EvidencePayloadSha256`, so no caller can hand in bytes that
//!   skipped `evidence::payload_sha256`; `origin_class` is written as the CHECK literal that the contract test below pins against migration 0004]
//! Spec: Baseline §8.1; §10.1; §34.2; ADR-0046
//!
//! The event subtype row (`private.events`, 1:1 on `evidence_id`) is not this door's: `remember::insert_event_subtype` writes it. Callers
//! pass what they already resolved ([`NewEvidence`]); this module decides nothing about visibility, authority or reasoning domain.

use sqlx::types::Uuid;
use sqlx::types::time::OffsetDateTime;

use humaux_domain::evidence::{EvidenceOriginClass, EvidencePayloadSha256};

/// How the row's `occurred_at` is stamped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OccurredAt {
    /// Bound verbatim; `At(None)` stores NULL (a source that named no time).
    At(Option<OffsetDateTime>),
    /// The database's `clock_timestamp()` at the statement, not the application clock.
    DatabaseClock,
}

/// One Evidence identity row to insert. Borrowed, so a caller holding a larger command (`RememberCommand`) maps fields without cloning.
#[derive(Debug, Clone)]
pub struct NewEvidence<'a> {
    /// Owning tenant (RLS key).
    pub tenant_id: Uuid,
    /// §48.0①: the already-hashed payload digest, never raw bytes.
    pub payload_sha256: &'a EvidencePayloadSha256,
    /// `private.evidence_objects.data_class` literal.
    pub data_class: &'a str,
    /// §8.7 origin; written as its CHECK literal.
    pub origin_class: EvidenceOriginClass,
    /// The principal the ingress path stamped, if any.
    pub origin_principal_id: Option<Uuid>,
    /// The connector the ingress path stamped, if any.
    pub origin_connector_id: Option<Uuid>,
    /// `private.evidence_objects.visibility_class` literal.
    pub visibility_class: &'a str,
    /// Set with `USER_PRIVATE` visibility.
    pub visibility_user_id: Option<Uuid>,
    /// Set with `WORKSPACE_SHARED` visibility.
    pub visibility_workspace_id: Option<Uuid>,
    /// §11.2.1: the reasoning domain this Evidence is processed under.
    pub reasoning_domain_id: Uuid,
    /// When the Evidence's subject event happened.
    pub occurred_at: OccurredAt,
}

/// `origin_class` DB wire form — literally the domain enum's variant name (§8.7's 9-variant
/// closed set doubles as `private.evidence_objects.origin_class`'s `CHECK (... IN (...))`
/// list). Kept next to the INSERT that writes it rather than added as an
/// `EvidenceOriginClass::as_db_str` method on the domain type: that type's own doc says
/// verbatim-string pinning "is deferred to the §78.2 DB↔Rust contract-test card", and the
/// contract test below pins this mapping against the live CHECK list, satisfying §78.2.
fn origin_class_db_str(c: EvidenceOriginClass) -> &'static str {
    match c {
        EvidenceOriginClass::DirectUserInput => "DirectUserInput",
        EvidenceOriginClass::UserConfirmed => "UserConfirmed",
        EvidenceOriginClass::TenantAdmin => "TenantAdmin",
        EvidenceOriginClass::AuthenticatedAgent => "AuthenticatedAgent",
        EvidenceOriginClass::TrustedConnector => "TrustedConnector",
        EvidenceOriginClass::ToolResult => "ToolResult",
        EvidenceOriginClass::UploadedArtifact => "UploadedArtifact",
        EvidenceOriginClass::ExternalContent => "ExternalContent",
        EvidenceOriginClass::SystemMigration => "SystemMigration",
    }
}

/// Inserts one `private.evidence_objects` row (`evidence_kind = 'EVENT'` fixed) in the caller's transaction and returns its
/// `evidence_id`. `evidence_id` / `created_at` are the table's own `DEFAULT uuidv7()` / `DEFAULT now()`, never bound here — same
/// reasoning `begin_batch` gives for asking Postgres for `uuidv7()` rather than minting client-side.
///
/// # Errors
/// Any `sqlx::Error` from the statement (CHECK / FK / RLS refusals included); the caller owns the transaction and its mapping.
pub async fn insert_evidence_in_txn(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    new: &NewEvidence<'_>,
) -> Result<Uuid, sqlx::Error> {
    let (occurred_at, database_clock) = match new.occurred_at {
        OccurredAt::At(at) => (at, false),
        OccurredAt::DatabaseClock => (None, true),
    };
    sqlx::query_scalar(
        "INSERT INTO private.evidence_objects \
           (tenant_id, evidence_kind, payload_sha256, data_class, origin_class, \
            origin_principal_id, origin_connector_id, visibility_class, visibility_user_id, \
            visibility_workspace_id, reasoning_domain_id, occurred_at) \
         VALUES ($1, 'EVENT', decode($2, 'hex'), $3, $4, $5, $6, $7, $8, $9, $10, \
                 CASE WHEN $12 THEN clock_timestamp() ELSE $11 END) \
         RETURNING evidence_id",
    )
    .bind(new.tenant_id)
    // `decode(hex, 'hex')` round-trips `EvidencePayloadSha256::to_hex()` back into `bytea` —
    // the type has no raw-byte accessor by design (§48.0①'s doc only exposes `to_hex()`), so
    // binding through its one public projection is the only option, not a workaround.
    .bind(new.payload_sha256.to_hex())
    .bind(new.data_class)
    .bind(origin_class_db_str(new.origin_class))
    .bind(new.origin_principal_id)
    .bind(new.origin_connector_id)
    .bind(new.visibility_class)
    .bind(new.visibility_user_id)
    .bind(new.visibility_workspace_id)
    .bind(new.reasoning_domain_id)
    .bind(occurred_at)
    .bind(database_clock)
    .fetch_one(&mut **txn)
    .await
}

/// §78.2 "DB enum 与 Rust enum 走 contract test 对账", scoped to [`origin_class_db_str`] (see
/// its doc for why the mapping lives here rather than on the domain type). Runs against the
/// real migration file text, no live DB needed.
#[cfg(test)]
mod contract_tests {
    use super::*;

    const MIGRATION_SQL: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../migrations/0004_private_evidence_memory.sql"
    ));

    fn origin_class_check_values() -> Vec<String> {
        let needle = "origin_class IN (";
        let start = MIGRATION_SQL
            .find(needle)
            .expect("migration must define an origin_class CHECK (origin_class IN (...))")
            + needle.len();
        let close = MIGRATION_SQL[start..]
            .find(')')
            .expect("unterminated origin_class CHECK list")
            + start;
        MIGRATION_SQL[start..close]
            .split(',')
            .map(|s| s.trim().trim_matches('\'').to_string())
            .collect()
    }

    #[test]
    fn origin_class_db_str_matches_check_constraint_for_every_variant() {
        let db = origin_class_check_values();
        let rust: Vec<String> = [
            EvidenceOriginClass::DirectUserInput,
            EvidenceOriginClass::UserConfirmed,
            EvidenceOriginClass::TenantAdmin,
            EvidenceOriginClass::AuthenticatedAgent,
            EvidenceOriginClass::TrustedConnector,
            EvidenceOriginClass::ToolResult,
            EvidenceOriginClass::UploadedArtifact,
            EvidenceOriginClass::ExternalContent,
            EvidenceOriginClass::SystemMigration,
        ]
        .into_iter()
        .map(|c| origin_class_db_str(c).to_string())
        .collect();
        assert_eq!(
            db, rust,
            "origin_class_db_str must list every CHECK value, in DB order"
        );
    }
}

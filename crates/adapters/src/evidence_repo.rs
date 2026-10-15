//! `adapters::evidence_repo` — the sole `INSERT INTO private.evidence_objects` door (M07 D9, gate G-M07-1): one `evidence_kind = 'EVENT'`
//!   identity row, written in the caller's transaction.
//! Depends-on: crates=[humaux-domain, sqlx]; services=[PostgreSQL(any) w=[private.evidence_objects]]; env=[CARGO_MANIFEST_DIR]; modules=[domain::dataclass, domain::evidence, domain::identity]
//! Called-by: [adapters::context_repo, adapters::remember]
//! Invariants: [every non-test Evidence INSERT in the workspace is this one statement (xtask architecture-check G-M07-1, counted `== 1`); the
//!   statement runs inside the caller's transaction and never commits, so a caller's rollback discards the row; `evidence_id` and `created_at`
//!   are the table's own defaults, never bound; the digest comes from an `EvidencePayloadSha256`, so no caller can hand in bytes that
//!   skipped `evidence::payload_sha256`; `data_class`, `origin_class` and `visibility_class` are typed and written as the CHECK literals that
//!   the contract tests below pin against migration 0004]
//! Spec: Baseline §8.1; §10.1; §34.2; ADR-0046
//!
//! The event subtype row (`private.events`, 1:1 on `evidence_id`) is not this door's: `remember::insert_event_subtype` writes it. Callers
//! pass what they already resolved ([`NewEvidence`]); this module decides nothing about visibility, authority or reasoning domain.

use sqlx::types::Uuid;
use sqlx::types::time::OffsetDateTime;

use humaux_domain::dataclass::DataClass;
use humaux_domain::evidence::{EvidenceOriginClass, EvidencePayloadSha256};
use humaux_domain::identity::VisibilityClass;

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
    /// §7.5.1 data class; written as its CHECK literal.
    pub data_class: DataClass,
    /// §8.7 origin; written as its CHECK literal.
    pub origin_class: EvidenceOriginClass,
    /// The principal the ingress path stamped, if any.
    pub origin_principal_id: Option<Uuid>,
    /// The connector the ingress path stamped, if any.
    pub origin_connector_id: Option<Uuid>,
    /// §6.1.1 visibility class; written as its CHECK literal.
    pub visibility_class: VisibilityClass,
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

/// `visibility_class` DB wire form (the CHECK list of `private.evidence_objects.visibility_class`, §6.1.1), pinned by the
/// contract test below. `domain::identity` carries no wire form for [`VisibilityClass`].
fn visibility_class_db_str(c: VisibilityClass) -> &'static str {
    match c {
        VisibilityClass::UserPrivate => "USER_PRIVATE",
        VisibilityClass::WorkspaceShared => "WORKSPACE_SHARED",
        VisibilityClass::TenantShared => "TENANT_SHARED",
    }
}

/// Strict inverse of [`DataClass::as_str`]: only the five CHECK literals. `None` for anything else, because
/// `DataClass::parse_or_secret` would store an unknown string as `SECRET_MATERIAL` where the CHECK used to refuse it.
pub(crate) fn data_class_from_db_str(s: &str) -> Option<DataClass> {
    DataClass::ALL.into_iter().find(|c| c.as_str() == s)
}

/// Strict inverse of [`visibility_class_db_str`]: only the three CHECK literals.
pub(crate) fn visibility_class_from_db_str(s: &str) -> Option<VisibilityClass> {
    [
        VisibilityClass::UserPrivate,
        VisibilityClass::WorkspaceShared,
        VisibilityClass::TenantShared,
    ]
    .into_iter()
    .find(|c| visibility_class_db_str(*c) == s)
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
         VALUES ($1, 'EVENT', $2, $3, $4, $5, $6, $7, $8, $9, $10, \
                 CASE WHEN $12 THEN clock_timestamp() ELSE $11 END) \
         RETURNING evidence_id",
    )
    .bind(new.tenant_id)
    .bind(new.payload_sha256.as_bytes().as_slice())
    .bind(new.data_class.as_str())
    .bind(origin_class_db_str(new.origin_class))
    .bind(new.origin_principal_id)
    .bind(new.origin_connector_id)
    .bind(visibility_class_db_str(new.visibility_class))
    .bind(new.visibility_user_id)
    .bind(new.visibility_workspace_id)
    .bind(new.reasoning_domain_id)
    .bind(occurred_at)
    .bind(database_clock)
    .fetch_one(&mut **txn)
    .await
}

/// §78.2 "DB enum 与 Rust enum 走 contract test 对账", scoped to the three typed columns this door writes
/// (`origin_class`, `visibility_class`, `data_class`; see [`origin_class_db_str`] for why the mappings live here
/// rather than on the domain types). Runs against the real migration file text, no live DB needed.
#[cfg(test)]
mod contract_tests {
    use super::*;

    const MIGRATION_SQL: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../migrations/0004_private_evidence_memory.sql"
    ));

    fn check_values(column: &str) -> Vec<String> {
        let needle = format!("{column} IN (");
        let start = MIGRATION_SQL
            .find(&needle)
            .unwrap_or_else(|| panic!("migration must define a CHECK ({column} IN (...))"))
            + needle.len();
        let close = MIGRATION_SQL[start..]
            .find(')')
            .unwrap_or_else(|| panic!("unterminated {column} CHECK list"))
            + start;
        MIGRATION_SQL[start..close]
            .split(',')
            .map(|s| s.trim().trim_matches('\'').to_string())
            .collect()
    }

    #[test]
    fn origin_class_db_str_matches_check_constraint_for_every_variant() {
        let db = check_values("origin_class");
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

    #[test]
    fn visibility_class_db_str_matches_check_constraint_for_every_variant() {
        let rust: Vec<String> = [
            VisibilityClass::UserPrivate,
            VisibilityClass::WorkspaceShared,
            VisibilityClass::TenantShared,
        ]
        .into_iter()
        .map(|c| visibility_class_db_str(c).to_string())
        .collect();
        assert_eq!(
            check_values("visibility_class"),
            rust,
            "visibility_class_db_str must list every CHECK value, in DB order"
        );
    }

    #[test]
    fn data_class_literals_match_check_constraint() {
        let rust: Vec<String> = DataClass::ALL
            .into_iter()
            .map(|c| c.as_str().to_string())
            .collect();
        assert_eq!(check_values("data_class"), rust);
    }

    #[test]
    fn strict_parsers_round_trip_every_literal_and_refuse_the_rest() {
        for c in DataClass::ALL {
            assert_eq!(data_class_from_db_str(c.as_str()), Some(c));
        }
        for c in [
            VisibilityClass::UserPrivate,
            VisibilityClass::WorkspaceShared,
            VisibilityClass::TenantShared,
        ] {
            assert_eq!(
                visibility_class_from_db_str(visibility_class_db_str(c)),
                Some(c)
            );
        }
        assert_eq!(data_class_from_db_str("private"), None);
        assert_eq!(data_class_from_db_str(""), None);
        assert_eq!(visibility_class_from_db_str("user_private"), None);
        assert_eq!(visibility_class_from_db_str("PUBLIC"), None);
    }
}

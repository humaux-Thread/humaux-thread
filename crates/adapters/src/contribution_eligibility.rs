//! `adapters::contribution_eligibility` — sole eligibility reader; applicability never a licence (ADR-0090 D-A, ADR-0096): the
//!   thin wrapper over the migration 0286 predicate `private.contribution_eligibility` and the closed verdict set it returns.
//! Depends-on: crates=[humaux-domain, sqlx]; services=[PostgreSQL(any) x=[private.contribution_eligibility]]; env=[];
//!   modules=[domain::authority, domain::error, domain::ids]
//! Called-by: [tests]
//! Invariants: [lives here, not in public-pool, because that crate may not name `private.` (G-M20-23b); the Rust side holds
//!   no copy of the predicate or of the note-kind to unit-type map: both are SQL (`private.contribution_eligibility`,
//!   `private.contribution_unit_type`), and the verdict wire is the SQL text; the verdict set equals the literals the
//!   function returns (§78.2); a verdict string outside the set is `Internal` (the terminal `ErrorCode`, no new error enum)
//!   and never becomes `Eligible`; the tenant is the caller's session tenant, a mismatch is `Forbidden`, and a memory of
//!   another tenant reads `NotFound` like an absent id (no existence oracle); the call runs in the caller's transaction and
//!   writes nothing]
//! Spec: Baseline §12.1.1; §52; §78.2; ADR-0088 D-A; ADR-0090 D-A; ADR-0096 D-F

use humaux_domain::{authority::MemoryId, error::ErrorCode, ids::TenantId};
use sqlx::PgConnection;

/// The answer of `private.contribution_eligibility`: the first failure of the fixed check order below, else `Eligible`
/// (ADR-0090 D-A). The variants are declared in that order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EligibilityVerdict {
    /// No memory of this tenant carries the id; a memory of another tenant answers the same.
    NotFound,
    /// The memory is not the live version: revoked, expired, superseded or archived.
    NotActive,
    /// The note kind has no phase-1 unit type, or the memory is not a note.
    KindNotMapped,
    /// No contribution notice is published.
    NoNotice,
    /// The current notice's scope does not list the memory's unit type.
    CategoryNotInNotice,
    /// The memory has no backing Evidence (an empty closure fails closed).
    NoEvidence,
    /// Some closure Evidence is above INTERNAL, or its class cannot be read.
    DataClass,
    /// The memory or some closure Evidence carries an affect row.
    Affect,
    /// The memory or some closure Evidence links to a person or to a customer.
    PersonOrCustomerLink,
    /// Every check passed; F1 authorisation and the admission rules still apply (M20-6, ADR-0090 D-C).
    Eligible,
}

impl EligibilityVerdict {
    /// Every variant, in check order: the §78.2 contract-test surface.
    pub const ALL: [Self; 10] = [
        Self::NotFound,
        Self::NotActive,
        Self::KindNotMapped,
        Self::NoNotice,
        Self::CategoryNotInNotice,
        Self::NoEvidence,
        Self::DataClass,
        Self::Affect,
        Self::PersonOrCustomerLink,
        Self::Eligible,
    ];

    /// The text the SQL function returns, verbatim.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::NotFound => "NOT_FOUND",
            Self::NotActive => "NOT_ACTIVE",
            Self::KindNotMapped => "KIND_NOT_MAPPED",
            Self::NoNotice => "NO_NOTICE",
            Self::CategoryNotInNotice => "CATEGORY_NOT_IN_NOTICE",
            Self::NoEvidence => "NO_EVIDENCE",
            Self::DataClass => "DATA_CLASS",
            Self::Affect => "AFFECT",
            Self::PersonOrCustomerLink => "PERSON_OR_CUSTOMER_LINK",
            Self::Eligible => "ELIGIBLE",
        }
    }

    /// Inverse of [`Self::wire`]; `None` outside the closed set, so an unknown string is never defaulted.
    #[must_use]
    pub fn parse_wire(wire: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.wire() == wire)
    }
}

/// ADR-0090 D-A: whether `memory` of `tenant` may enter the public pool's selection, judged over the M07 closure by the SQL
/// predicate in the caller's open transaction. Private applicability is never read (ADR-0096 D-F). Closure Evidence the
/// session cannot see is unknown and reads `DataClass`, so the sweep must run each candidate under its author's session.
///
/// # Errors
/// `Forbidden` when `tenant` is not the session tenant or the role may not execute the predicate; `DependencyUnavailable`
/// when the connection fails; `Internal` for any other PostgreSQL refusal and for a verdict string outside
/// [`EligibilityVerdict`].
pub async fn contribution_eligibility(
    conn: &mut PgConnection,
    tenant: TenantId,
    memory: MemoryId,
) -> Result<EligibilityVerdict, ErrorCode> {
    let wire = sqlx::query_scalar::<_, String>("SELECT private.contribution_eligibility($1, $2)")
        .bind(tenant.0)
        .bind(memory.0)
        .fetch_one(conn)
        .await
        .map_err(|e| error_code(&e))?;
    decode(&wire)
}

/// §52: a PostgreSQL failure as the existing terminal vocabulary.
fn error_code(error: &sqlx::Error) -> ErrorCode {
    let Some(db) = error.as_database_error() else {
        return ErrorCode::DependencyUnavailable;
    };
    match db.code().as_deref() {
        Some("42501") => ErrorCode::Forbidden,
        _ => ErrorCode::Internal,
    }
}

/// The fail-closed decode: a string outside the set is `Internal`, never a default verdict.
fn decode(wire: &str) -> Result<EligibilityVerdict, ErrorCode> {
    EligibilityVerdict::parse_wire(wire).ok_or(ErrorCode::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §78.2 fail-closed decode: every verdict round-trips, and anything else, however close to `ELIGIBLE`, is `Internal`.
    #[test]
    fn an_unknown_verdict_string_is_internal_never_eligible() {
        for verdict in EligibilityVerdict::ALL {
            assert_eq!(decode(verdict.wire()), Ok(verdict));
        }
        for wire in [
            "",
            "eligible",
            "ELIGIBLE ",
            "ELIGIBLE\n",
            "NOT_FOUND2",
            "PUBLIC",
        ] {
            assert_eq!(
                decode(wire),
                Err(ErrorCode::Internal),
                "{wire:?} must not decode"
            );
        }
    }
}

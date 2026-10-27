//! `public-pool::eligibility` — sole eligibility reader; applicability never a licence (ADR-0090 D-A, ADR-0096): the thin
//!   wrapper over the migration 0286 predicate `private.contribution_eligibility` and the closed verdict set it returns.
//! Depends-on: crates=[humaux-domain, sqlx]; services=[PostgreSQL(any) r=[] x=[private.contribution_eligibility]]; env=[];
//!   modules=[domain::authority, domain::ids, public-pool::notice]
//! Called-by: [tests]
//! Invariants: [the Rust side holds no copy of the predicate or of the note-kind to unit-type map: both are SQL
//!   (`private.contribution_eligibility`, `private.contribution_unit_type`), and the verdict wire is the SQL text; the
//!   verdict set equals the literals the function returns (§78.2); a verdict string outside the set is a decode error
//!   through `notice::refusal_of` (no new error enum) and never becomes `Eligible`; the tenant is the caller's session
//!   tenant, a mismatch is a refusal, and a memory of another tenant reads `NotFound` like an absent id (no existence
//!   oracle); the call runs in the caller's transaction and writes nothing]
//! Spec: Baseline §12.1.1; §78.2; ADR-0088 D-A; ADR-0090 D-A; ADR-0096 D-F

use humaux_domain::{authority::MemoryId, ids::TenantId};
use sqlx::PgConnection;

use crate::notice::{Refusal, refusal_of};

// ponytail: third mirrored closed_set! (notice.rs and completeness.rs hold the others, neither exports its macro), hoist one
// shared macro into a common module when a fourth set needs it.
// §78.2: one closed set from one list, so the enum, its `ALL`, its wire labels and `parse` cannot drift from the variants.
macro_rules! closed_set {
    ($(#[$meta:meta])* $name:ident { $($(#[$vmeta:meta])* $variant:ident => $wire:literal,)+ }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $($(#[$vmeta])* $variant,)+
        }

        impl $name {
            /// Every variant, in declaration order: the §78.2 contract-test surface.
            pub const ALL: &[$name] = &[$($name::$variant,)+];

            /// The text the SQL function returns, verbatim.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $wire,)+
                }
            }

            /// Inverse of [`Self::as_str`]; `None` outside the closed set, so an unknown string is never defaulted.
            pub fn parse(wire: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|v| v.as_str() == wire)
            }
        }
    };
}

closed_set! {
    /// The answer of `private.contribution_eligibility`: the first failure of the fixed check order below, else `Eligible`
    /// (ADR-0090 D-A). The variants are declared in that order.
    EligibilityVerdict {
        /// No memory of this tenant carries the id; a memory of another tenant answers the same.
        NotFound => "NOT_FOUND",
        /// The memory is not the live version: revoked, expired, superseded or archived.
        NotActive => "NOT_ACTIVE",
        /// The note kind has no phase-1 unit type, or the memory is not a note.
        KindNotMapped => "KIND_NOT_MAPPED",
        /// No contribution notice is published.
        NoNotice => "NO_NOTICE",
        /// The current notice's scope does not list the memory's unit type.
        CategoryNotInNotice => "CATEGORY_NOT_IN_NOTICE",
        /// The memory has no backing Evidence (an empty closure fails closed).
        NoEvidence => "NO_EVIDENCE",
        /// Some closure Evidence is above INTERNAL, or its class cannot be read.
        DataClass => "DATA_CLASS",
        /// The memory or some closure Evidence carries an affect row.
        Affect => "AFFECT",
        /// The memory or some closure Evidence links to a person or to a customer.
        PersonOrCustomerLink => "PERSON_OR_CUSTOMER_LINK",
        /// Every check passed; F1 authorisation and the admission rules still apply (M20-6, ADR-0090 D-C).
        Eligible => "ELIGIBLE",
    }
}

/// ADR-0090 D-A: whether `memory` of `tenant` may enter the public pool's selection, judged over the M07 closure by the SQL
/// predicate in the caller's open transaction. Private applicability is never read (ADR-0096 D-F). Closure Evidence the
/// session cannot see is unknown and reads `DataClass`, so the sweep must run each candidate under its author's session.
///
/// # Errors
/// `Forbidden` when `tenant` is not the session tenant or the role may not execute the predicate; `DependencyUnavailable` when
/// PostgreSQL refuses the call and for a verdict string outside [`EligibilityVerdict`].
pub async fn contribution_eligibility(
    conn: &mut PgConnection,
    tenant: TenantId,
    memory: MemoryId,
) -> Result<EligibilityVerdict, Refusal> {
    let wire = sqlx::query_scalar::<_, String>("SELECT private.contribution_eligibility($1, $2)")
        .bind(tenant.0)
        .bind(memory.0)
        .fetch_one(conn)
        .await
        .map_err(|e| refusal_of(&e))?;
    decode(&wire)
}

/// The fail-closed decode: a string outside the set is a decode error through the one existing error path.
fn decode(wire: &str) -> Result<EligibilityVerdict, Refusal> {
    EligibilityVerdict::parse(wire).ok_or_else(|| {
        refusal_of(&sqlx::Error::Decode(
            format!("unknown eligibility verdict {wire:?}").into(),
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §78.2 fail-closed decode: every verdict round-trips, and anything else, however close to `ELIGIBLE`, is a refusal.
    #[test]
    fn an_unknown_verdict_string_is_a_refusal_never_eligible() {
        for verdict in EligibilityVerdict::ALL {
            assert_eq!(decode(verdict.as_str()), Ok(*verdict));
        }
        for wire in [
            "",
            "eligible",
            "ELIGIBLE ",
            "ELIGIBLE\n",
            "NOT_FOUND2",
            "PUBLIC",
        ] {
            assert!(decode(wire).is_err(), "{wire:?} must not decode");
        }
    }
}

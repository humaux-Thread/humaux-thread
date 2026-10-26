//! `public-pool::policy` — the cloud edition's contribution policy writes: the onboarding default and the user toggle
//!   (ADR-0088 D-A, D-C, M20-4a).
//! Depends-on: crates=[sqlx, uuid]; services=[PostgreSQL(any) r=[]
//!   x=[control.apply_cloud_contribution_default, control.toggle_contribution, control.toggle_member_contribution]]; env=[]; modules=[public-pool::notice]
//! Called-by: [tests]
//! Invariants: [this module is the only caller of `control.apply_cloud_contribution_default`, so the AUTO onboarding default
//!   exists only in the cloud edition (G-M20-1); the default writes version 1 only for a tenant with no policy row and the
//!   sweep still selects nothing until a SHOWN exists on the current notice (`notice::contribution_authorized`); a toggle ON
//!   without a SHOWN on the current version writes nothing and is refused as CONFLICT / TRANSITION_NOT_ALLOWED]
//! Spec: Baseline §12.1.1; ADR-0088 D-A; D-C

use sqlx::PgConnection;
use uuid::Uuid;

use crate::notice::{NoticeChannel, Refusal, refusal_of};

/// The cloud onboarding default: appends the AUTO policy (version 1) for the session tenant when it has no policy row.
/// Returns whether a row was written. The caller runs it inside the onboarding transaction as `role_maintenance`, with the
/// tenant context installed.
///
/// # Errors
/// `Forbidden` without a tenant context; `DependencyUnavailable` when PostgreSQL refuses the call.
pub async fn apply_cloud_default(conn: &mut PgConnection) -> Result<bool, Refusal> {
    sqlx::query_scalar::<_, bool>("SELECT control.apply_cloud_contribution_default()")
        .fetch_one(conn)
        .await
        .map_err(|e| refusal_of(&e))
}

/// ADR-0088 D-C: switches contribution on or off for the session tenant (tenant ON stays OWNER-only; a member's own OFF is
/// [`toggle_member`]). The session user must be an ACTIVE OWNER of the tenant in both directions. ON requires a SHOWN for the session tenant and user on the current notice version; OFF needs no
/// notice. The event and the policy successor are one transaction. Returns the open head's version.
///
/// # Errors
/// `Forbidden` for a non-owner or without a session context; `Conflict` / `TRANSITION_NOT_ALLOWED` for ON without SHOWN;
/// `Conflict` / `TARGET_NOT_CURRENT` for ON while no notice is published.
pub async fn toggle(
    conn: &mut PgConnection,
    on: bool,
    channel: NoticeChannel,
) -> Result<i64, Refusal> {
    sqlx::query_scalar::<_, i64>("SELECT control.toggle_contribution($1, $2)")
        .bind(on)
        .bind(channel.as_str())
        .fetch_one(conn)
        .await
        .map_err(|e| refusal_of(&e))
}

/// ADR-0088 D-C, personal: the session user, any ACTIVE member of the tenant, records a MEMBER-scope `TOGGLED_OFF` or
/// `TOGGLED_ON` for themselves. It never writes the policy head. OFF needs no notice; ON needs a published notice and a
/// tenant policy that is already AUTO, and re-opts in only that member. Returns the event id.
///
/// # Errors
/// `Forbidden` for a non-member or without a session context; `Conflict` / `TARGET_NOT_CURRENT` for ON while no notice is
/// published; `Conflict` without a sub-reason for ON while the tenant policy is not AUTO.
pub async fn toggle_member(
    conn: &mut PgConnection,
    on: bool,
    channel: NoticeChannel,
) -> Result<Uuid, Refusal> {
    sqlx::query_scalar::<_, Uuid>("SELECT control.toggle_member_contribution($1, $2)")
        .bind(on)
        .bind(channel.as_str())
        .fetch_one(conn)
        .await
        .map_err(|e| refusal_of(&e))
}

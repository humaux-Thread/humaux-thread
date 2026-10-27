//! `public-pool::notice` — the contribution notice's choice events and the one authorization predicate, as thin wrappers over
//!   the migration 0274 doors (ADR-0088 D-A..D-C, M20-4a).
//! Depends-on: crates=[humaux-domain, sqlx, uuid]; services=[PostgreSQL(any) r=[]
//!   x=[control.ack_notice, control.contribution_authorized, control.current_contribution_notice,
//!   control.record_notice_shown]]; env=[]; modules=[domain::error, domain::ids]
//! Called-by: [public-pool::eligibility, public-pool::policy, tests]
//! Invariants: [the Rust side never recomputes "current notice" or the predicate: both are the SQL functions
//!   `control.current_contribution_notice` and `control.contribution_authorized`; tenant and user come from the caller's
//!   session context (`humaux.tenant_id` / `humaux.user_id`), never from a parameter; a refusal is an `ErrorCode` plus an
//!   existing `ConflictReason`, no new error enum; the kind, channel and scope sets equal the 0274 CHECK literals exactly (§78.2)]
//! Spec: Baseline §12.1.1; §78.2; ADR-0088 D-A; D-B
//!
//! | Rust | DB (migration `0274_contribution_notice.sql`) |
//! |---|---|
//! | [`NoticeEventKind`] | `contribution_notice_events_kind_check` |
//! | [`NoticeChannel`] | `contribution_notice_events_channel_check` |
//! | [`NoticeEventScope`] | `contribution_notice_events_scope_check` |

use humaux_domain::{
    error::{ConflictReason, ErrorCode},
    ids::{TenantId, UserId},
};
use sqlx::PgConnection;
use uuid::Uuid;

/// One closed set from one list: the enum, its `ALL` and its wire labels cannot drift from the variants (§78.2).
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

            /// The migration 0274 CHECK literal.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $wire,)+
                }
            }
        }
    };
}

closed_set! {
    /// `kind` of `control.contribution_notice_events` (ADR-0088 D-B).
    NoticeEventKind {
        /// The notice text was displayed to the user.
        Shown => "SHOWN",
        /// The user acknowledged the notice.
        Acked => "ACKED",
        /// The user switched contribution on.
        ToggledOn => "TOGGLED_ON",
        /// The user switched contribution off.
        ToggledOff => "TOGGLED_OFF",
        /// The user withdrew everything (written by M20-4b).
        WithdrawAll => "WITHDRAW_ALL",
    }
}

closed_set! {
    /// `scope` of `control.contribution_notice_events`: whether a toggle event belongs to the tenant-wide flow or is one
    /// member's personal choice.
    NoticeEventScope {
        /// The tenant-wide flow; every event written by the owner toggle, `SHOWN` and `ACKED`.
        Tenant => "TENANT",
        /// A member's personal toggle for themselves; never changes the policy head.
        Member => "MEMBER",
    }
}

closed_set! {
    /// `channel` of `control.contribution_notice_events`: the surface the choice came through.
    NoticeChannel {
        /// The in-product popup (M02 / M26 render it; M20 owns the record).
        Popup => "POPUP",
        /// The console settings page.
        Console => "CONSOLE",
        /// An MCP tool call.
        Mcp => "MCP",
    }
}

/// A door refusal: the terminal [`ErrorCode`] and, for `CONFLICT`, the existing sub-reason (ADR-0020). A struct, not an
/// error enum: `ErrorCode` stays the only terminal set (§52).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    /// The terminal code.
    pub code: ErrorCode,
    /// The `CONFLICT` sub-reason; `None` for every other code.
    pub reason: Option<ConflictReason>,
}

/// 0274 refusal message: the version is not `control.current_contribution_notice()`.
const NOTICE_NOT_CURRENT: &str = "notice_version_not_current";
/// 0274 refusal message: toggle ON without a SHOWN for tenant and user on the current version.
const NOTICE_NOT_SHOWN: &str = "notice_not_shown";
/// SQLSTATE `object_not_in_prerequisite_state`, the 0186 refusal convention the 0274 doors follow.
const PREREQUISITE_STATE: &str = "55000";

fn conflict(reason: Option<ConflictReason>) -> Refusal {
    Refusal {
        code: ErrorCode::Conflict,
        reason,
    }
}

/// Maps a door failure to its refusal: the two 0274 reasons to their `ConflictReason`, a missing session context to
/// `Forbidden`, a constraint violation to `InvalidInput`, anything else to `DependencyUnavailable`.
pub(crate) fn refusal_of(error: &sqlx::Error) -> Refusal {
    let Some(db) = error.as_database_error() else {
        return Refusal {
            code: ErrorCode::DependencyUnavailable,
            reason: None,
        };
    };
    match db.code().as_deref() {
        Some(PREREQUISITE_STATE) if db.message() == NOTICE_NOT_CURRENT => {
            conflict(Some(ConflictReason::TARGET_NOT_CURRENT))
        }
        Some(PREREQUISITE_STATE) if db.message() == NOTICE_NOT_SHOWN => {
            conflict(Some(ConflictReason::TRANSITION_NOT_ALLOWED))
        }
        Some(PREREQUISITE_STATE) => conflict(None),
        Some("42501") => Refusal {
            code: ErrorCode::Forbidden,
            reason: None,
        },
        Some(code) if code.starts_with("22") || code == "23514" || code == "23503" => Refusal {
            code: ErrorCode::InvalidInput,
            reason: None,
        },
        _ => Refusal {
            code: ErrorCode::DependencyUnavailable,
            reason: None,
        },
    }
}

/// Installs the session context every 0274 door reads, for the caller's open transaction (`set_config(.., true)`).
///
/// # Errors
/// `DependencyUnavailable` when PostgreSQL refuses the statement.
pub async fn install_session(
    conn: &mut PgConnection,
    tenant: TenantId,
    user: UserId,
) -> Result<(), Refusal> {
    sqlx::query(
        "SELECT set_config('humaux.tenant_id', $1, true), set_config('humaux.user_id', $2, true)",
    )
    .bind(tenant.0.to_string())
    .bind(user.0.to_string())
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(|e| refusal_of(&e))
}

/// The current notice version: the answer of `control.current_contribution_notice()`, `None` while none is published.
///
/// # Errors
/// `DependencyUnavailable` when PostgreSQL refuses the call.
pub async fn current_notice(conn: &mut PgConnection) -> Result<Option<i32>, Refusal> {
    sqlx::query_scalar::<_, Option<i32>>("SELECT control.current_contribution_notice()")
        .fetch_one(conn)
        .await
        .map_err(|e| refusal_of(&e))
}

/// Appends `SHOWN` for the session tenant and user on `notice_version`, which must be the current one.
///
/// # Errors
/// `Conflict` / `TARGET_NOT_CURRENT` when the version is not the current one; `Forbidden` without a session context.
pub async fn record_shown(
    conn: &mut PgConnection,
    notice_version: i32,
    channel: NoticeChannel,
) -> Result<Uuid, Refusal> {
    sqlx::query_scalar::<_, Uuid>("SELECT control.record_notice_shown($1, $2)")
        .bind(notice_version)
        .bind(channel.as_str())
        .fetch_one(conn)
        .await
        .map_err(|e| refusal_of(&e))
}

/// Appends `ACKED` under the same current-version rule as [`record_shown`].
///
/// # Errors
/// As [`record_shown`].
pub async fn acknowledge(
    conn: &mut PgConnection,
    notice_version: i32,
    channel: NoticeChannel,
) -> Result<Uuid, Refusal> {
    sqlx::query_scalar::<_, Uuid>("SELECT control.ack_notice($1, $2)")
        .bind(notice_version)
        .bind(channel.as_str())
        .fetch_one(conn)
        .await
        .map_err(|e| refusal_of(&e))
}

/// ADR-0088 D-A, per member: whether the sweep (M20-6) and finalize (M20-4b) may select `user`'s memories (they pass the
/// memory's author): the tenant's current policy is AUTO, `user` has a SHOWN on the current notice version, and `user`'s
/// latest MEMBER-scope toggle event (if any) is not `TOGGLED_OFF` (a member's own OFF makes that member's memories
/// unselectable). The one predicate; the caller's session tenant must equal `tenant`.
///
/// # Errors
/// `Forbidden` when `tenant` is not the session tenant; `DependencyUnavailable` when PostgreSQL refuses the call.
pub async fn contribution_authorized(
    conn: &mut PgConnection,
    tenant: TenantId,
    user: UserId,
) -> Result<bool, Refusal> {
    sqlx::query_scalar::<_, bool>("SELECT control.contribution_authorized($1, $2)")
        .bind(tenant.0)
        .bind(user.0)
        .fetch_one(conn)
        .await
        .map_err(|e| refusal_of(&e))
}

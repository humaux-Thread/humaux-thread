//! `adapters::session_repo` — the console session over the four `control.session_*` doors (migration 0270). Writes only
//!   through definers; role_gateway has SELECT only on `control.sessions`.
//! Depends-on: crates=[humaux-application, humaux-domain, sqlx]; services=[PostgreSQL(any) x=[control.session_issue, control.session_lookup, control.session_revoke, control.session_touch]]; env=[]; modules=[adapters::postgres, application::auth, application::login, application::session, domain::error, domain::ids]
//! Called-by: [gateway::auth_pages, tests]
//! Invariants: [a session is minted only from LoginVerifyOutcome::Accepted; only the SHA-256 of the cookie secret reaches
//!   the database; a lookup is judged by application::session::verify on the database clock, so a session whose epoch
//!   snapshot differs from the user's current epoch, or that is revoked, expired or idle, authenticates as None; the
//!   stored digest is compared again in constant time; a database failure is DependencyUnavailable, a policy that does
//!   not fit the door is Internal]
//! Spec: §73.6; §74.4; §52; §78.1
//!
//! The caller owns the §78.1 policy (`SessionPolicy::from(&AuthConfig)`) and the cookie; this file never sees a header.

use std::time::{Duration, SystemTime};

use humaux_application::auth::SessionSnapshot;
use humaux_application::login::LoginVerifyOutcome;
use humaux_application::session::{
    SessionId, SessionPolicy, SessionRecord, SessionSecret, VerifiedSession, verify,
};
use humaux_domain::error::ErrorCode;
use humaux_domain::ids::UserId;
use sqlx::Row;
use sqlx::types::Uuid;

use crate::postgres::RuntimeDbPool;

/// A freshly minted session. The secret leaves the server once, in the `Set-Cookie` of the response that carries this.
#[derive(Debug)]
pub struct IssuedSession {
    /// The value for the session cookie.
    pub secret: SessionSecret,
    /// Row id; the CSRF binding.
    pub session_id: SessionId,
    /// Absolute expiry on the database clock.
    pub expires_at: SystemTime,
}

fn db_failure(_: sqlx::Error) -> ErrorCode {
    ErrorCode::DependencyUnavailable
}

fn unix_time(seconds: f64) -> Result<SystemTime, ErrorCode> {
    let since_epoch = Duration::try_from_secs_f64(seconds).map_err(|_| ErrorCode::Internal)?;
    Ok(SystemTime::UNIX_EPOCH + since_epoch)
}

fn whole_seconds(duration: Duration) -> Result<i32, ErrorCode> {
    i32::try_from(duration.as_secs()).map_err(|_| ErrorCode::Internal)
}

/// Mints a session for the user a successful login verify named; `None` for [`LoginVerifyOutcome::Rejected`] (nothing is
/// written) or for a user the door will not log in.
pub async fn issue(
    pool: &RuntimeDbPool,
    policy: &SessionPolicy,
    login: LoginVerifyOutcome,
) -> Result<Option<IssuedSession>, ErrorCode> {
    let LoginVerifyOutcome::Accepted(user_id) = login else {
        return Ok(None);
    };
    let ttl_seconds = whole_seconds(policy.absolute_ttl)?;
    let secret = SessionSecret::generate();
    let digest = secret.digest();

    let row = sqlx::query(
        "SELECT out_session_id, out_expires_at_unix FROM control.session_issue($1, $2, $3)",
    )
    .bind(user_id.0)
    .bind(digest.as_bytes())
    .bind(ttl_seconds)
    // dep: PostgreSQL(any) — calls the session_issue door
    .fetch_optional(pool.pool())
    .await
    .map_err(db_failure)?;

    let Some(row) = row else {
        return Ok(None);
    };
    let session_id: Uuid = row.try_get("out_session_id").map_err(db_failure)?;
    let expires_at: f64 = row.try_get("out_expires_at_unix").map_err(db_failure)?;
    Ok(Some(IssuedSession {
        secret,
        session_id: SessionId(session_id),
        expires_at: unix_time(expires_at)?,
    }))
}

/// Resolves a cookie secret to a live session and records the use, or `None` when no row matches or
/// `application::session::verify` refuses it (revoked, expired, idle, or epoch snapshot != the user's current epoch).
pub async fn authenticate(
    pool: &RuntimeDbPool,
    policy: &SessionPolicy,
    secret: &SessionSecret,
) -> Result<Option<VerifiedSession>, ErrorCode> {
    let digest = secret.digest();
    let row = sqlx::query(
        "SELECT out_session_id, out_user_id, out_token_hash, out_session_epoch, out_current_epoch, \
                out_expires_at_unix, out_last_seen_at_unix, out_revoked_at_unix, out_db_now_unix \
         FROM control.session_lookup($1)",
    )
    .bind(digest.as_bytes())
    // dep: PostgreSQL(any) — calls the session_lookup door
    .fetch_optional(pool.pool())
    .await
    .map_err(db_failure)?;
    let Some(row) = row else {
        return Ok(None);
    };

    let stored: Vec<u8> = row.try_get("out_token_hash").map_err(db_failure)?;
    if !digest.matches_stored(&stored) {
        return Ok(None);
    }
    let revoked_at: Option<f64> = row.try_get("out_revoked_at_unix").map_err(db_failure)?;
    let record = SessionRecord {
        session_id: SessionId(row.try_get("out_session_id").map_err(db_failure)?),
        user_id: UserId(row.try_get("out_user_id").map_err(db_failure)?),
        snapshot: SessionSnapshot {
            session_epoch: row.try_get("out_session_epoch").map_err(db_failure)?,
            expires_at: unix_time(row.try_get("out_expires_at_unix").map_err(db_failure)?)?,
            revoked_at: revoked_at.map(unix_time).transpose()?,
        },
        current_epoch: row.try_get("out_current_epoch").map_err(db_failure)?,
        last_seen_at: unix_time(row.try_get("out_last_seen_at_unix").map_err(db_failure)?)?,
    };
    let db_now = unix_time(row.try_get("out_db_now_unix").map_err(db_failure)?)?;

    let Some(verified) = verify(&record, policy, db_now) else {
        return Ok(None);
    };
    let touched = sqlx::query_scalar::<_, bool>("SELECT control.session_touch($1, $2)")
        .bind(verified.session_id.0)
        .bind(whole_seconds(policy.idle_ttl)?)
        // dep: PostgreSQL(any) — calls the session_touch door
        .fetch_one(pool.pool())
        .await
        .map_err(db_failure)?;
    Ok(touched.then_some(verified))
}

/// Revokes one session; `true` when a live row was revoked, `false` when it was unknown or already revoked.
pub async fn revoke(pool: &RuntimeDbPool, session_id: SessionId) -> Result<bool, ErrorCode> {
    sqlx::query_scalar::<_, bool>("SELECT control.session_revoke($1)")
        .bind(session_id.0)
        // dep: PostgreSQL(any) — calls the session_revoke door
        .fetch_one(pool.pool())
        .await
        .map_err(db_failure)
}

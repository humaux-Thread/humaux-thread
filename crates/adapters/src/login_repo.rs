//! `adapters::login_repo` — the passwordless login challenge over the three `control.login_challenge_*` doors (migration 0266)
//!   and the §74.6 email door. Writes only through definers; role_gateway has SELECT only on `control.email_challenges`.
//! Depends-on: crates=[humaux-application, humaux-domain, serde_json, sqlx]; services=[PostgreSQL(any) x=[control.login_challenge_claim, control.login_challenge_issue, control.login_challenge_settle]]; env=[]; modules=[adapters::email, adapters::postgres, application::auth, application::login, domain::error, domain::ids]
//! Called-by: [tests]
//! Invariants: [a start answers LoginStartResponse::UNIFORM on every path and enqueues mail only for a stored code; the
//!   code goes to the outbox payload and nowhere else, only its keyed hash is stored; a verify counts or consumes through
//!   one conditional UPDATE inside one transaction, so a consumed, expired or exhausted challenge never accepts and two
//!   concurrent verifies of one code cannot both succeed; a database failure is DependencyUnavailable, a policy that does
//!   not fit the door is Internal]
//! Spec: §74.2; §74.3; §74.6; §52; §78.1
//!
//! The door names the mailbox by its canonical form (`application::auth::canonicalize_email`); the caller
//! owns the §78.1 policy (`AuthConfig::login_challenge`) and the sender identity.

use humaux_application::auth::{ChallengePolicy, CodeHash, generate_verification_code};
use humaux_application::login::{
    LoginStartReceipt, LoginStartResponse, LoginVerifyOutcome, StartDisposition,
};
use humaux_domain::error::ErrorCode;
use humaux_domain::ids::UserId;
use sqlx::Row;
use sqlx::types::Uuid;

use crate::email::outbox::{self, EnqueueOutcome, EnqueueRequest};
use crate::email::{EmailPriority, EmailStream, RecipientAllowlist};
use crate::postgres::RuntimeDbPool;

/// `template_id` of the outbox row a login code rides on.
pub const LOGIN_CODE_TEMPLATE_ID: &str = "LOGIN_CODE";

/// Sender identity and subject of the login mail; both come from the caller's config (§78.1). The subject never
/// carries the code.
#[derive(Debug, Clone, Copy)]
pub struct LoginMail<'a> {
    /// Sender address of the login mail.
    pub from_email: &'a str,
    /// Subject line; must not contain the code.
    pub subject: &'a str,
}

/// Digest a verify compares against when the mailbox has no challenge, so that path runs the same keyed hash and
/// constant-time compare as a real one. It matches no candidate: the outcome is forced to rejected.
const ABSENT_CHALLENGE_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

fn db_failure(_: sqlx::Error) -> ErrorCode {
    ErrorCode::DependencyUnavailable
}

/// Starts a login: stores a fresh code's keyed hash for a loginable mailbox and enqueues its mail in the same
/// transaction (priority AUTH on the transactional stream), or does nothing for an unknown mailbox or one inside its
/// cooldown. Every path answers [`LoginStartResponse::UNIFORM`]; [`LoginStartReceipt::disposition`] is for logs only.
///
/// ponytail: the unknown-mailbox path skips the outbox INSERT, so it answers about one statement faster than an
/// issued one; upgrade path: pad every start to a fixed latency floor.
pub async fn start(
    pool: &RuntimeDbPool,
    pepper: &[u8],
    policy: ChallengePolicy,
    mail: &LoginMail<'_>,
    allowlist: &RecipientAllowlist,
    canonical_email: &str,
) -> Result<LoginStartReceipt, ErrorCode> {
    // Generated before the lookup so a known and an unknown mailbox pay the same CSPRNG and HMAC work.
    let (code, hash) = generate_verification_code(pepper);
    let ttl_seconds = i32::try_from(policy.ttl.as_secs()).map_err(|_| ErrorCode::Internal)?;
    let cooldown_seconds =
        i32::try_from(policy.send_cooldown.as_secs()).map_err(|_| ErrorCode::Internal)?;

    // dep: PostgreSQL(any) — opens a PostgreSQL transaction
    let mut txn = pool.pool().begin().await.map_err(db_failure)?;
    let issued = sqlx::query(
        "SELECT out_challenge_id, out_user_id, out_issued \
         FROM control.login_challenge_issue($1, $2, $3, $4, $5)",
    )
    .bind(canonical_email)
    .bind(hash.as_str())
    .bind(ttl_seconds)
    .bind(policy.max_attempts)
    .bind(cooldown_seconds)
    // dep: PostgreSQL(any) — calls the login_challenge_issue door
    .fetch_optional(&mut *txn)
    .await
    .map_err(db_failure)?;

    let disposition = match issued {
        None => StartDisposition::UnknownAccount,
        Some(row) => {
            let issued: bool = row.try_get("out_issued").map_err(db_failure)?;
            if issued {
                let challenge_id: Uuid = row.try_get("out_challenge_id").map_err(db_failure)?;
                let user_id: Uuid = row.try_get("out_user_id").map_err(db_failure)?;
                let request = EnqueueRequest {
                    user_id,
                    to_email: canonical_email.to_string(),
                    from_email: mail.from_email.to_string(),
                    stream: EmailStream::Transactional,
                    template_id: LOGIN_CODE_TEMPLATE_ID.to_string(),
                    subject: mail.subject.to_string(),
                    payload: serde_json::json!({ "code": code.reveal() }),
                    priority: EmailPriority::Auth,
                    idempotency_key: Some(format!("login-code:{challenge_id}")),
                };
                let queued = outbox::enqueue_in_txn(&mut txn, &request, allowlist)
                    .await
                    .map_err(|_| ErrorCode::DependencyUnavailable)?;
                if queued == EnqueueOutcome::Queued {
                    StartDisposition::Issued
                } else {
                    StartDisposition::MailNotQueued
                }
            } else {
                StartDisposition::Throttled
            }
        }
    };
    // dep: PostgreSQL(any) — commits the challenge row, its event and its mail together
    txn.commit().await.map_err(db_failure)?;

    Ok(LoginStartReceipt {
        response: LoginStartResponse::UNIFORM,
        disposition,
    })
}

/// An open verify transaction holding the claimed challenge. Split from [`VerifyTxn::finish`] so a test can hold two
/// verifies of one code between claim and settle.
pub struct VerifyTxn {
    txn: sqlx::Transaction<'static, sqlx::Postgres>,
    claimed: Option<(Uuid, String)>,
}

/// Opens a verify: claims the mailbox's latest login challenge, if any.
pub async fn begin_verify(
    pool: &RuntimeDbPool,
    canonical_email: &str,
) -> Result<VerifyTxn, ErrorCode> {
    // dep: PostgreSQL(any) — opens a PostgreSQL transaction
    let mut txn = pool.pool().begin().await.map_err(db_failure)?;
    let claimed = sqlx::query(
        "SELECT out_challenge_id, out_code_hash FROM control.login_challenge_claim($1)",
    )
    .bind(canonical_email)
    // dep: PostgreSQL(any) — calls the login_challenge_claim door
    .fetch_optional(&mut *txn)
    .await
    .map_err(db_failure)?
    .map(|row| -> Result<(Uuid, String), sqlx::Error> {
        Ok((
            row.try_get("out_challenge_id")?,
            row.try_get("out_code_hash")?,
        ))
    })
    .transpose()
    .map_err(db_failure)?;
    Ok(VerifyTxn { txn, claimed })
}

impl VerifyTxn {
    /// Compares `candidate` in constant time and settles the attempt through the one conditional UPDATE: the row is
    /// consumed only on a match while it is unconsumed, unexpired and under its attempt cap.
    pub async fn finish(
        mut self,
        pepper: &[u8],
        candidate: &str,
    ) -> Result<LoginVerifyOutcome, ErrorCode> {
        let (challenge_id, stored) = match &self.claimed {
            Some((id, digest)) => (Some(*id), digest.clone()),
            None => (None, ABSENT_CHALLENGE_DIGEST.to_string()),
        };
        let matched = CodeHash::from_stored(stored).verify(pepper, candidate);

        let accepted = match challenge_id {
            Some(id) => {
                sqlx::query_scalar::<_, Option<Uuid>>(
                    "SELECT control.login_challenge_settle($1, $2)",
                )
                .bind(id)
                .bind(matched)
                // dep: PostgreSQL(any) — calls the login_challenge_settle door
                .fetch_one(&mut *self.txn)
                .await
                .map_err(db_failure)?
            }
            None => None,
        };
        // dep: PostgreSQL(any) — commits the attempt count or the consumption
        self.txn.commit().await.map_err(db_failure)?;

        Ok(match accepted {
            Some(user_id) => LoginVerifyOutcome::Accepted(UserId(user_id)),
            None => LoginVerifyOutcome::Rejected,
        })
    }
}

/// Verifies a login code: [`begin_verify`] then [`VerifyTxn::finish`].
pub async fn verify_code(
    pool: &RuntimeDbPool,
    pepper: &[u8],
    canonical_email: &str,
    candidate: &str,
) -> Result<LoginVerifyOutcome, ErrorCode> {
    begin_verify(pool, canonical_email)
        .await?
        .finish(pepper, candidate)
        .await
}

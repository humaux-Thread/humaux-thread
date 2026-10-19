//! `adapters::coord_repo` — M18 task-run lifecycle: submit, claim, heartbeat, complete, fail, and the
//!   `verify_task_run` port (§30.1 state, §30.2 lease and fencing token).
//! Depends-on: crates=[humaux-domain, sqlx]; services=[PostgreSQL(any) w=[coord.task_runs, coord.tasks]]; env=[];
//!   modules=[adapters::context_repo, adapters::postgres, domain::coordination, domain::error, domain::identity,
//!   domain::ids]
//! Called-by: [tests]
//! Invariants: [lease_owner is always AuthorizationScope::principal, never a caller-supplied value; every lease time
//!   is read and compared on the DB clock (clock_timestamp()), never the application clock; claim, heartbeat,
//!   complete and fail take the task row FOR UPDATE before judging the lease, so they serialize per task; a run passes
//!   verification only if it is open, its lease is unexpired, its owner is the caller and its token equals the task's
//!   current fencing_seq; every rejection is an existing ErrorCode variant]
//! Spec: Baseline §30; §30.1; §30.2; §52; §62; §6.2.1
//!
//! Runs on [`RuntimeDbPool`] (`role_gateway`, which holds SELECT, INSERT, UPDATE on `coord.*`,
//! §6.2.1). Each pool-level operation opens its own transaction with the scope's tenant GUCs
//! (FORCE RLS on both tables, §62); [`verify_task_run`] runs inside the caller's transaction
//! instead, which must already carry them.
//!
//! The lease TTL is caller-supplied configuration (§78.1); this module holds no default.
//!
//! Rejections (§52, no new variant):
//! - run or task absent, or in another tenant: [`ErrorCode::NotFound`];
//! - caller is not the run's `lease_owner`: [`ErrorCode::Forbidden`];
//! - run finished, lease expired, stale token, task not claimable, or claim against an
//!   unexpired lease: [`ErrorCode::Conflict`];
//! - zero TTL or blank title: [`ErrorCode::InvalidInput`];
//! - PG failure: [`ErrorCode::DependencyUnavailable`]; an unknown `state` label: [`ErrorCode::Internal`].

use std::time::Duration;

use humaux_domain::coordination::{FencingToken, TaskRunId, TaskState};
use humaux_domain::error::ErrorCode;
use humaux_domain::identity::{AuthorizationScope, PrincipalId};
use humaux_domain::ids::TaskId;
use sqlx::Row;
use sqlx::types::Uuid;
use sqlx::types::time::OffsetDateTime;

use crate::context_repo::set_authorization_local;
use crate::postgres::RuntimeDbPool;

type Txn<'c> = sqlx::Transaction<'c, sqlx::Postgres>;

/// A lease opened by [`claim`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimedTaskRun {
    /// The new run.
    pub task_run_id: TaskRunId,
    /// §30.2 token for every later heartbeat, close or verification of this run.
    pub fencing_token: FencingToken,
    /// DB-clock expiry of the lease.
    pub lease_expires_at: OffsetDateTime,
}

/// Proof that [`verify_task_run`] passed inside the caller's transaction. Fields are private:
/// that function is the only constructor, so holding one means the five §30.2 checks ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedTaskRun {
    task_id: TaskId,
    task_run_id: TaskRunId,
    fencing_token: FencingToken,
    lease_owner: PrincipalId,
}

impl VerifiedTaskRun {
    /// The run's task.
    pub fn task_id(&self) -> TaskId {
        self.task_id
    }

    /// The verified run.
    pub fn task_run_id(&self) -> TaskRunId {
        self.task_run_id
    }

    /// The token that matched the task's current `fencing_seq`.
    pub fn fencing_token(&self) -> FencingToken {
        self.fencing_token
    }

    /// The lease owner, equal to the verifying scope's principal.
    pub fn lease_owner(&self) -> PrincipalId {
        self.lease_owner
    }
}

fn db(_: sqlx::Error) -> ErrorCode {
    ErrorCode::DependencyUnavailable
}

fn lease_seconds(lease_ttl: Duration) -> Result<f64, ErrorCode> {
    if lease_ttl.is_zero() {
        return Err(ErrorCode::InvalidInput);
    }
    Ok(lease_ttl.as_secs_f64())
}

async fn begin(
    pool: &RuntimeDbPool,
    scope: &AuthorizationScope,
) -> Result<Txn<'static>, ErrorCode> {
    let mut txn = pool.pool().begin().await.map_err(db)?;
    set_authorization_local(&mut txn, scope).await?;
    Ok(txn)
}

/// Inserts a task in `SUBMITTED` (§30.1) under the scope's tenant.
pub async fn submit(
    pool: &RuntimeDbPool,
    scope: &AuthorizationScope,
    title: &str,
) -> Result<TaskId, ErrorCode> {
    if title.trim().is_empty() {
        return Err(ErrorCode::InvalidInput);
    }
    let mut txn = begin(pool, scope).await?;
    let task_id: Uuid = sqlx::query_scalar(
        "INSERT INTO coord.tasks (tenant_id, title, state) VALUES ($1, $2, $3) RETURNING task_id",
    )
    .bind(scope.tenant_id().0)
    .bind(title)
    .bind(TaskState::Submitted.as_db_str())
    .fetch_one(&mut *txn)
    .await
    .map_err(db)?;
    txn.commit().await.map_err(db)?;
    Ok(TaskId(task_id))
}

/// Opens a lease on `task_id` for the scope's principal (§30.2). Allowed from `SUBMITTED`, or
/// from `CLAIMED` / `WORKING` once the open run's lease has expired on the DB clock; that run is
/// closed in the same transaction. The task moves to `CLAIMED`, `fencing_seq` increments, and
/// the new run carries the incremented value as its token.
pub async fn claim(
    pool: &RuntimeDbPool,
    scope: &AuthorizationScope,
    task_id: TaskId,
    lease_ttl: Duration,
) -> Result<ClaimedTaskRun, ErrorCode> {
    let seconds = lease_seconds(lease_ttl)?;
    let mut txn = begin(pool, scope).await?;
    let state: String = sqlx::query_scalar(
        "SELECT state FROM coord.tasks WHERE task_id = $1 AND tenant_id = $2 FOR UPDATE",
    )
    .bind(task_id.0)
    .bind(scope.tenant_id().0)
    .fetch_optional(&mut *txn)
    .await
    .map_err(db)?
    .ok_or(ErrorCode::NotFound)?;
    match TaskState::from_db_str(&state).ok_or(ErrorCode::Internal)? {
        TaskState::Submitted | TaskState::Claimed | TaskState::Working => {}
        _ => return Err(ErrorCode::Conflict),
    }
    // A fresh statement under the row lock: sees every run the previous lock holder committed.
    let held: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM coord.task_runs \
         WHERE task_id = $1 AND finished_at IS NULL AND lease_expires_at > clock_timestamp())",
    )
    .bind(task_id.0)
    .fetch_one(&mut *txn)
    .await
    .map_err(db)?;
    if held {
        return Err(ErrorCode::Conflict);
    }
    sqlx::query(
        "UPDATE coord.task_runs SET finished_at = clock_timestamp() \
         WHERE task_id = $1 AND finished_at IS NULL",
    )
    .bind(task_id.0)
    .execute(&mut *txn)
    .await
    .map_err(db)?;
    let token: i64 = sqlx::query_scalar(
        "UPDATE coord.tasks SET state = $2, fencing_seq = fencing_seq + 1 \
         WHERE task_id = $1 RETURNING fencing_seq",
    )
    .bind(task_id.0)
    .bind(TaskState::Claimed.as_db_str())
    .fetch_one(&mut *txn)
    .await
    .map_err(db)?;
    let row = sqlx::query(
        "INSERT INTO coord.task_runs (tenant_id, task_id, lease_owner, lease_expires_at, fencing_token) \
         VALUES ($1, $2, $3, clock_timestamp() + make_interval(secs => $4), $5) \
         RETURNING task_run_id, lease_expires_at",
    )
    .bind(scope.tenant_id().0)
    .bind(task_id.0)
    .bind(scope.principal().0)
    .bind(seconds)
    .bind(token)
    .fetch_one(&mut *txn)
    .await
    .map_err(db)?;
    txn.commit().await.map_err(db)?;
    Ok(ClaimedTaskRun {
        task_run_id: TaskRunId(row.get("task_run_id")),
        fencing_token: FencingToken(token),
        lease_expires_at: row.get("lease_expires_at"),
    })
}

/// Extends a verified lease to DB-clock now + `lease_ttl` and moves `CLAIMED` to `WORKING`.
/// Returns the new expiry.
pub async fn heartbeat(
    pool: &RuntimeDbPool,
    scope: &AuthorizationScope,
    task_run_id: TaskRunId,
    fencing_token: FencingToken,
    lease_ttl: Duration,
) -> Result<OffsetDateTime, ErrorCode> {
    let seconds = lease_seconds(lease_ttl)?;
    let mut txn = begin(pool, scope).await?;
    let run = lock_and_verify(&mut txn, scope, task_run_id, fencing_token).await?;
    let expires: OffsetDateTime = sqlx::query_scalar(
        "UPDATE coord.task_runs SET lease_expires_at = clock_timestamp() + make_interval(secs => $2) \
         WHERE task_run_id = $1 RETURNING lease_expires_at",
    )
    .bind(task_run_id.0)
    .bind(seconds)
    .fetch_one(&mut *txn)
    .await
    .map_err(db)?;
    sqlx::query("UPDATE coord.tasks SET state = $2 WHERE task_id = $1 AND state = $3")
        .bind(run.task_id.0)
        .bind(TaskState::Working.as_db_str())
        .bind(TaskState::Claimed.as_db_str())
        .execute(&mut *txn)
        .await
        .map_err(db)?;
    txn.commit().await.map_err(db)?;
    Ok(expires)
}

/// Closes a verified run and moves its task to `COMPLETED`.
pub async fn complete(
    pool: &RuntimeDbPool,
    scope: &AuthorizationScope,
    task_run_id: TaskRunId,
    fencing_token: FencingToken,
) -> Result<(), ErrorCode> {
    close(
        pool,
        scope,
        task_run_id,
        fencing_token,
        TaskState::Completed,
    )
    .await
}

/// Closes a verified run and moves its task to `FAILED`.
pub async fn fail(
    pool: &RuntimeDbPool,
    scope: &AuthorizationScope,
    task_run_id: TaskRunId,
    fencing_token: FencingToken,
) -> Result<(), ErrorCode> {
    close(pool, scope, task_run_id, fencing_token, TaskState::Failed).await
}

async fn close(
    pool: &RuntimeDbPool,
    scope: &AuthorizationScope,
    task_run_id: TaskRunId,
    fencing_token: FencingToken,
    outcome: TaskState,
) -> Result<(), ErrorCode> {
    let mut txn = begin(pool, scope).await?;
    let run = lock_and_verify(&mut txn, scope, task_run_id, fencing_token).await?;
    sqlx::query(
        "UPDATE coord.task_runs SET finished_at = clock_timestamp() WHERE task_run_id = $1",
    )
    .bind(task_run_id.0)
    .execute(&mut *txn)
    .await
    .map_err(db)?;
    sqlx::query("UPDATE coord.tasks SET state = $2 WHERE task_id = $1")
        .bind(run.task_id.0)
        .bind(outcome.as_db_str())
        .execute(&mut *txn)
        .await
        .map_err(db)?;
    txn.commit().await.map_err(db)
}

/// Takes the run's task row FOR UPDATE (the lock [`claim`] takes), then verifies in a fresh
/// statement so the judgement reads the lease as the last lock holder committed it.
async fn lock_and_verify(
    txn: &mut Txn<'_>,
    scope: &AuthorizationScope,
    task_run_id: TaskRunId,
    fencing_token: FencingToken,
) -> Result<VerifiedTaskRun, ErrorCode> {
    sqlx::query(
        "SELECT 1 FROM coord.tasks \
         WHERE task_id = (SELECT task_id FROM coord.task_runs WHERE task_run_id = $1) FOR UPDATE",
    )
    .bind(task_run_id.0)
    .execute(&mut **txn)
    .await
    .map_err(db)?;
    verify_task_run(txn, scope, task_run_id, fencing_token).await
}

/// §30.2 verification port, run inside the caller's transaction (which carries the scope's
/// tenant GUCs). Passes only if the run is in the scope's tenant, is not finished, its lease is
/// unexpired on the DB clock at this statement, its `lease_owner` is the scope's principal, and
/// `fencing_token` equals both the run's token and the task's current `fencing_seq`. Holds the
/// task row FOR SHARE until the caller's transaction ends, so no claim, heartbeat or close can
/// interleave with the caller's writes.
pub async fn verify_task_run(
    txn: &mut Txn<'_>,
    scope: &AuthorizationScope,
    task_run_id: TaskRunId,
    fencing_token: FencingToken,
) -> Result<VerifiedTaskRun, ErrorCode> {
    let row = sqlx::query(
        "SELECT r.task_id, r.lease_owner, r.fencing_token, t.fencing_seq, \
                r.finished_at IS NOT NULL AS finished, \
                r.lease_expires_at > clock_timestamp() AS live \
         FROM coord.task_runs r \
         JOIN coord.tasks t ON t.task_id = r.task_id AND t.tenant_id = r.tenant_id \
         WHERE r.task_run_id = $1 AND r.tenant_id = $2 \
         FOR SHARE OF t",
    )
    .bind(task_run_id.0)
    .bind(scope.tenant_id().0)
    .fetch_optional(&mut **txn)
    .await
    .map_err(db)?
    .ok_or(ErrorCode::NotFound)?;
    let lease_owner: Option<Uuid> = row.get("lease_owner");
    let run_token: Option<i64> = row.get("fencing_token");
    let fencing_seq: i64 = row.get("fencing_seq");
    let finished: bool = row.get("finished");
    let live: Option<bool> = row.get("live");
    if lease_owner != Some(scope.principal().0) {
        return Err(ErrorCode::Forbidden);
    }
    if finished {
        return Err(ErrorCode::Conflict);
    }
    if live != Some(true) {
        return Err(ErrorCode::Conflict);
    }
    if run_token != Some(fencing_token.0) || fencing_seq != fencing_token.0 {
        return Err(ErrorCode::Conflict);
    }
    Ok(VerifiedTaskRun {
        task_id: TaskId(row.get("task_id")),
        task_run_id,
        fencing_token,
        lease_owner: scope.principal(),
    })
}

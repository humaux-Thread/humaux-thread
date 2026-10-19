//! `domain::coordination` — M18 task-run vocabulary: the §30.1 task state closed set and the §30.2 fencing token.
//! Depends-on: crates=[uuid]; services=[]; env=[]; modules=[]
//! Called-by: [adapters::coord_repo, adapters::operation_receipt, gateway::guard, gateway::mcp_application, tests]
//! Invariants: [TaskState is the §30.1 seven-value closed set and its DB spelling equals the coord.tasks.state CHECK
//!   (§78.2, adapters/tests/coord_task_run.rs); a FencingToken is only meaningful against the same task's current
//!   coord.tasks.fencing_seq]
//! Spec: Baseline §30; §30.1; §30.2; §78.2
//!
//! Zero IO. The lease itself (owner, expiry, token comparison on the DB clock) is judged in
//! `adapters::coord_repo`, because §30.2's comparisons are only sound inside the transaction
//! that reads the row.

use uuid::Uuid;

/// §30.1 task state, verbatim seven-value closed set, in spec order. No `Other` arm: a value
/// outside this set is a schema drift, not a state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskState {
    /// Submitted, not yet claimed by any agent.
    Submitted,
    /// Claimed: a live lease exists, no heartbeat yet.
    Claimed,
    /// Working: the lease owner has heartbeated at least once.
    Working,
    /// Blocked (§30.1); no T04a operation enters or leaves it.
    Blocked,
    /// Completed by the lease owner.
    Completed,
    /// Failed by the lease owner.
    Failed,
    /// Cancelled (§30.1); no T04a operation enters it.
    Cancelled,
}

impl TaskState {
    /// Every variant, in §30.1 order.
    pub const ALL: [Self; 7] = [
        Self::Submitted,
        Self::Claimed,
        Self::Working,
        Self::Blocked,
        Self::Completed,
        Self::Failed,
        Self::Cancelled,
    ];

    /// The `coord.tasks.state` spelling (§78.2: must equal the `tasks_state_check` labels).
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Submitted => "SUBMITTED",
            Self::Claimed => "CLAIMED",
            Self::Working => "WORKING",
            Self::Blocked => "BLOCKED",
            Self::Completed => "COMPLETED",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
        }
    }

    /// Inverse of [`Self::as_db_str`]; `None` for any other string.
    pub fn from_db_str(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|state| state.as_db_str() == s)
    }
}

/// `coord.task_runs.task_run_id`: one lease tenure on a task (§30).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaskRunId(pub Uuid);

/// §30.2 fencing token: the task's `fencing_seq` at the claim that opened the run. Strictly
/// increases on every claim of the same task, so a holder of an older value is a stale writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FencingToken(pub i64);

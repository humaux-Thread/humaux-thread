//! `adapters::read_gate` — the one home of the final read gate: the all-backing-evidence closure (`readable_memory_ids`) and the
//!   `memory.get` / `memory.enumerate` materializers that read only through it.
//! Depends-on: crates=[humaux-domain, sqlx]; services=[PostgreSQL(any) r=[private.evidence_objects, private.memory_evidence, private.memory_records]]; env=[]; modules=[domain::error, domain::identity, domain::ids]
//! Called-by: [adapters::context_repo, adapters::continuity_read, adapters::contribution_entry_repo, adapters::exact_census, adapters::forget_repo, adapters::memory_governance_repo, adapters::operation_receipt, adapters::read_materialize]
//! Invariants: [a Memory is readable only when all six conjuncts hold: (1) tenant, the Memory row and each Evidence
//!   row are read under the caller's tenant_id and RLS (§6.1.1); (2) visibility, `identity::can_read` over the
//!   Memory's own descriptor (§6.1.1); (3) lifecycle selection, one bound `Lifecycle` (ADR-0067 D-J2); (4) subject
//!   guard, any-of over the requested subjects (§6.1.3); (5) secret-backed and tombstoned exclusion (ADR-0071);
//!   (6) all-backing-evidence closure, a Memory with zero Evidence rows, or with any Evidence row unreadable or
//!   hidden by RLS, fails closed (§8.6); (1), (2) and (6) are computed here by `readable_memory_ids`, (3) to (5) by
//!   the anti-join SQL of `read_materialize::final_memory_ids_with_readable_in_txn`, which calls it first; the
//!   materializers here read under one REPEATABLE READ snapshot and surface absent, hidden and gated rows alike as
//!   NotFound, a PG error as DependencyUnavailable or Internal, never an empty page; no cached allow decision, and
//!   the only write is the enumeration manifest a first page mints through `context_repo` and `selection_repo`;
//!   `memory.get` goes through `materialize_memory_get_frontier_target`, which reads the stream frontier (one
//!   `stream_checkpoints` primary-key lookup) in its snapshot and never the ledger closure, `stream_log` or an index
//!   count, and `frontier_pipeline_block` is the one mapping from that read to the wire, where no checkpoint row is
//!   `projection: null` with `no_checkpoint`, never a zero frontier (ADR-0110 D-A, §15.5, §23.1④)]
//! Spec: Baseline §6.1.1; §6.1.3; §8.6; §15.5; §22.1; §23.1④; ADR-0067 D-J2; ADR-0071; ADR-0110 D-A
//!
//! M08 D1 (module design "one gate, one home"): every read op passes the shared final gate before any body leaves
//! PostgreSQL, and the closure it rests on lives in this file, so a change to the readability rule edits one module.
//! `can_read` is named in this file only, inside [`visibility_readable`]; the `G-M08-2` sentinel in
//! `xtask/src/architecture_check.rs` pins this file's `can_read` count with `==` and, with the same `==` per file and a
//! reason per row, every caller of [`visibility_readable`] outside it, so a read op that judges visibility itself is
//! red until it goes through [`readable_memory_ids`] (a Memory and its backing Evidence) or is declared there as a
//! row-level caller (a row its own SQL already fetched).
//!
use humaux_domain::error::ErrorCode;
use humaux_domain::identity::{
    AuthorizationScope, VisibilityClass, VisibilityDescriptor, can_read,
};
use humaux_domain::ids::{UserId, WorkspaceId};
use sqlx::{Row, types::Uuid};
use std::collections::{HashMap, HashSet};
type Txn<'c> = sqlx::Transaction<'c, sqlx::Postgres>;

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::AuthorizationScope {}
}

/// A trusted scope accepted by the canonical PostgreSQL read gates.
pub trait ReadAuthorization: sealed::Sealed + Sync {
    #[doc(hidden)]
    fn read_gate_scope(&self) -> &AuthorizationScope;
}

impl ReadAuthorization for AuthorizationScope {
    fn read_gate_scope(&self) -> &AuthorizationScope {
        self
    }
}

/// Whether `authorization` may read an object that carries `visibility` (§6.1.1): the one `can_read` call in adapters
/// and bins. A caller whose own SQL already fetched the Memory or Evidence row (the RYW overlay, a contribution source,
/// a receipt replay, a continuity fact) judges that row's descriptor here and keeps its tenant filter, lifecycle,
/// secret and subject guards in that SQL; `can_read` is only the visibility term. A Memory read goes through
/// [`readable_memory_ids`], which adds the all-backing-evidence closure (§8.6); each caller outside this file is a
/// declared row of `G-M08-2`, never an undeclared use.
pub(crate) fn visibility_readable(
    authorization: &impl ReadAuthorization,
    visibility: &VisibilityDescriptor,
) -> bool {
    can_read(authorization.read_gate_scope(), visibility)
}

/// Runs the visibility judgement against real Memory and backing Evidence rows. A Memory without a backing
/// Evidence row, or with any Evidence row hidden by RLS, fails closed (§6.1.1/§8.6).
pub(crate) async fn readable_memory_ids(
    txn: &mut Txn<'_>,
    authorization: &AuthorizationScope,
    candidate_ids: &[Uuid],
) -> Result<HashSet<Uuid>, ErrorCode> {
    if candidate_ids.is_empty() {
        return Ok(HashSet::new());
    }
    let memories = sqlx::query(
        "SELECT memory_id, visibility_class, visibility_user_id, visibility_workspace_id \
         FROM private.memory_records WHERE tenant_id = $1 AND memory_id = ANY($2)",
    )
    .bind(authorization.tenant_id().0)
    .bind(candidate_ids)
    .fetch_all(&mut **txn)
    .await
    .map_err(|_| ErrorCode::Internal)?;
    let mut memory_visibility = HashMap::with_capacity(memories.len());
    for row in memories {
        let memory_id = row.try_get("memory_id").map_err(|_| ErrorCode::Internal)?;
        memory_visibility.insert(memory_id, visibility_from_row(&row)?);
    }

    // `memory_evidence` remains visible through its Memory RLS policy; the LEFT JOIN exposes
    // a hidden Evidence row as NULL, so a tenant-visible Memory cannot smuggle a private source
    // into Context merely because the Evidence table's RLS omitted it from the join.
    let evidence = sqlx::query(
        "SELECT me.memory_id, eo.evidence_id AS visible_evidence_id, eo.visibility_class, \
                eo.visibility_user_id, eo.visibility_workspace_id \
         FROM private.memory_evidence me \
         LEFT JOIN private.evidence_objects eo \
           ON eo.evidence_id = me.evidence_id AND eo.tenant_id = $1 \
         WHERE me.memory_id = ANY($2)",
    )
    .bind(authorization.tenant_id().0)
    .bind(candidate_ids)
    .fetch_all(&mut **txn)
    .await
    .map_err(|_| ErrorCode::Internal)?;
    let mut evidence_by_memory: HashMap<Uuid, Vec<Option<VisibilityDescriptor>>> = HashMap::new();
    for row in evidence {
        let memory_id = row.try_get("memory_id").map_err(|_| ErrorCode::Internal)?;
        let visible: Option<Uuid> = row
            .try_get("visible_evidence_id")
            .map_err(|_| ErrorCode::Internal)?;
        let descriptor = visible.map(|_| visibility_from_row(&row)).transpose()?;
        evidence_by_memory
            .entry(memory_id)
            .or_default()
            .push(descriptor);
    }

    Ok(memory_visibility
        .into_iter()
        .filter_map(|(memory_id, descriptor)| {
            let evidence = evidence_by_memory.get(&memory_id)?;
            (visibility_readable(authorization, &descriptor)
                && !evidence.is_empty()
                && evidence.iter().all(|descriptor| {
                    descriptor.is_some_and(|value| visibility_readable(authorization, &value))
                }))
            .then_some(memory_id)
        })
        .collect())
}

/// Converts the database's closed visibility wire values into the actual descriptor on that
/// row. The visibility decision itself remains [`humaux_domain::identity::can_read`]'s single implementation.
pub(crate) fn visibility_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<VisibilityDescriptor, ErrorCode> {
    let class: String = row
        .try_get("visibility_class")
        .map_err(|_| ErrorCode::Internal)?;
    let class = match class.as_str() {
        "USER_PRIVATE" => VisibilityClass::UserPrivate,
        "WORKSPACE_SHARED" => VisibilityClass::WorkspaceShared,
        "TENANT_SHARED" => VisibilityClass::TenantShared,
        _ => return Err(ErrorCode::Internal),
    };
    let user_id = row
        .try_get::<Option<Uuid>, _>("visibility_user_id")
        .map_err(|_| ErrorCode::Internal)?
        .map(UserId);
    let workspace_id = row
        .try_get::<Option<Uuid>, _>("visibility_workspace_id")
        .map_err(|_| ErrorCode::Internal)?
        .map(WorkspaceId);
    Ok(VisibilityDescriptor {
        class,
        user_id,
        workspace_id,
    })
}

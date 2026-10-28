//! Per-workspace frontier sums and optional ledger detail (ADR-0110 D-E).
//! Depends-on: crates=[humaux-application, humaux-domain, humaux-projection, humaux-retrieval, serde, sqlx, time];
//!   services=[PostgreSQL(role_retrieval_worker) r=[projection.stream_checkpoints, projection.stream_log]
//!   x=[projection.stream_point_ledger]]; env=[];
//!   modules=[application::processing_status, domain::error, domain::ids, projection::stream,
//!   retrieval::envelope, adapters::postgres, adapters::stream_repo]
//! Called-by: [adapters::tests::processing_status]
//! Invariants: [summary never closes a ledger; absent checkpoints never become zero readings;
//!   caller supplies the stream inventory; only authorized workspace keys are accepted]
//! Spec: §15.3; §15.6; §23.1④; §78.1; ADR-0110 D-E

use crate::{
    postgres::RetrievalWorkerDbPool,
    stream_repo::{self, Frontier},
};
use humaux_application::processing_status::{BEHIND_LABEL, DetailedGate, ProcessingStatusQuery};
use humaux_domain::{error::ErrorCode, ids::WorkspaceId};
use humaux_projection::stream::StreamKey;
use humaux_retrieval::envelope::{FrontierBlock, ProjectionAbsence};
use serde::Serialize;
use sqlx::{Postgres, Row, Transaction};
use std::collections::HashSet;
use std::time::Instant;

/// §23.1④: a workspace without checkpoint rows has no numeric reading.
#[derive(Debug, Serialize)]
pub struct WorkspaceStatus {
    workspace_id: WorkspaceId,
    projection: Option<FrontierBlock>,
    reason: Option<ProjectionAbsence>,
    behind_label: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detailed: Option<DetailedStatus>,
}

/// §15.6: exact ticket-state counts from the same snapshot; behind supplies none of them.
#[derive(Debug, Default, Serialize)]
pub struct DetailedStatus {
    expected: u64,
    done: u64,
    pending: u64,
    failed: u64,
    waiting_key: u64,
    retry_wait: u64,
}

/// Summary on one caller-owned transaction: one primary-key read per supplied stream (§15.3).
/// The inventory must contain every requested family/version, including row-less keys.
pub async fn processing_status(
    txn: &mut Transaction<'_, Postgres>,
    query: &ProcessingStatusQuery<'_>,
    streams: &[StreamKey],
) -> Result<Vec<WorkspaceStatus>, ErrorCode> {
    read(txn, query, streams, false)
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)
}

/// ADR-0110 D-E: admission precedes all reads; one worker-role REPEATABLE READ READ ONLY snapshot.
pub async fn processing_status_detailed(
    pool: &RetrievalWorkerDbPool,
    query: &ProcessingStatusQuery<'_>,
    streams: &[StreamKey],
    gate: &mut DetailedGate,
    now: Instant,
) -> Result<Vec<WorkspaceStatus>, ErrorCode> {
    gate.admit(query.authorization.tenant_id(), now)?;
    let mut txn = pool
        .pool()
        .begin()
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *txn)
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    let result = read(&mut txn, query, streams, true)
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    txn.commit()
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    Ok(result)
}

async fn read(
    txn: &mut Transaction<'_, Postgres>,
    query: &ProcessingStatusQuery<'_>,
    streams: &[StreamKey],
    detailed: bool,
) -> Result<Vec<WorkspaceStatus>, sqlx::Error> {
    let auth = query.authorization;
    stream_repo::set_tenant_local(txn, auth.tenant_id().0).await?;
    let mut unique = HashSet::new();
    if streams.iter().any(|k| {
        k.tenant_id != auth.tenant_id()
            || k.scope_kind != "workspace"
            || !auth
                .allowed_workspace_ids()
                .contains(&WorkspaceId(k.scope_id))
            || !unique.insert(k)
    }) {
        return Err(sqlx::Error::Protocol(
            "unauthorized or duplicate processing-status stream".into(),
        ));
    }
    sqlx::query("SELECT set_config('humaux.user_id', $1, true)")
        .bind(auth.user_id().map(|u| u.0.to_string()).unwrap_or_default())
        .execute(&mut **txn)
        .await?;
    let mut output = Vec::new();
    for workspace_id in auth.allowed_workspace_ids().iter() {
        let mut sum: Option<Frontier> = None;
        let mut counts = DetailedStatus::default();
        for key in streams.iter().filter(|k| k.scope_id == workspace_id.0) {
            let Some(row) = stream_repo::ledger_frontier_in_txn(txn, key).await? else {
                continue;
            };
            sum = Some(match sum {
                None => row,
                Some(prev) => Frontier {
                    issued_hw: prev
                        .issued_hw
                        .checked_add(row.issued_hw)
                        .ok_or(sqlx::Error::Protocol("frontier overflow".into()))?,
                    projection_hw: prev
                        .projection_hw
                        .checked_add(row.projection_hw)
                        .ok_or(sqlx::Error::Protocol("frontier overflow".into()))?,
                    serving: prev.serving && row.serving,
                    updated_at: prev.updated_at.min(row.updated_at),
                },
            });
            if detailed {
                add_detail(txn, query, key, &mut counts).await?;
            }
        }
        let projection = sum
            .map(|f| {
                let observed = f
                    .updated_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
                Ok::<_, sqlx::Error>(FrontierBlock::new(
                    f.issued_hw,
                    f.projection_hw,
                    f.serving,
                    observed,
                ))
            })
            .transpose()?;
        output.push(WorkspaceStatus {
            workspace_id: *workspace_id,
            reason: projection
                .is_none()
                .then_some(ProjectionAbsence::NoCheckpoint),
            projection,
            behind_label: BEHIND_LABEL,
            detailed: (detailed && sum.is_some()).then_some(counts),
        });
    }
    Ok(output)
}

async fn add_detail(
    txn: &mut Transaction<'_, Postgres>,
    query: &ProcessingStatusQuery<'_>,
    key: &StreamKey,
    out: &mut DetailedStatus,
) -> Result<(), sqlx::Error> {
    // ponytail: O(stream) detail; upgrade to real highwater writers (ADR-0110 D-E).
    let closure = stream_repo::close_ledger_in_txn(txn, key, query.authorization).await?;
    out.expected += closure.counts().expected();
    out.done += closure.counts().done();
    out.pending += closure.counts().pending();
    let row = sqlx::query("SELECT count(*) FILTER (WHERE state='FAILED') AS failed,
        count(*) FILTER (WHERE state='WAITING_KEY') AS waiting_key,
        count(*) FILTER (WHERE state='RETRY_WAIT') AS retry_wait FROM projection.stream_log
        WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND domain=$4 AND projection_kind=$5 AND projection_version=$6")
        .bind(key.tenant_id.0).bind(&key.scope_kind).bind(key.scope_id).bind(&key.domain)
        .bind(&key.projection_kind).bind(&key.projection_version).fetch_one(&mut **txn).await?;
    out.failed += row.try_get::<i64, _>("failed")? as u64;
    out.waiting_key += row.try_get::<i64, _>("waiting_key")? as u64;
    out.retry_wait += row.try_get::<i64, _>("retry_wait")? as u64;
    Ok(())
}

//! `adapters::processing_status` — Per-workspace frontier sums and optional ledger detail (ADR-0110 D-E).
//! Depends-on: crates=[humaux-application, humaux-domain, humaux-projection, humaux-retrieval, serde, sqlx, time];
//!   services=[PostgreSQL(role_retrieval_worker) r=[projection.stream_log]]; env=[];
//!   modules=[application::processing_status, domain::error, domain::ids, projection::stream,
//!   retrieval::envelope, adapters::postgres, adapters::stream_repo]
//! Called-by: [tests]
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
use std::{collections::HashSet, time::Instant};
use time::format_description::well_known::Rfc3339;

/// §23.1④: a workspace without checkpoint rows has no numeric reading.
#[derive(Debug, Serialize)]
pub struct WorkspaceStatus {
    workspace_id: sqlx::types::Uuid,
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

/// §15.3: one caller transaction, one PK read per stream; inventory includes row-less family/version keys.
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
    async {
        // dep: PostgreSQL(role_retrieval_worker) — isolated detailed snapshot (§79.2)
        let mut txn = pool.pool().begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *txn)
            .await?;
        let result = read(&mut txn, query, streams, true).await?;
        txn.commit().await?;
        Ok::<_, sqlx::Error>(result)
    }
    .await
    .map_err(|_| ErrorCode::DependencyUnavailable)
}

async fn read(
    txn: &mut Transaction<'_, Postgres>,
    query: &ProcessingStatusQuery<'_>,
    streams: &[StreamKey],
    detailed: bool,
) -> Result<Vec<WorkspaceStatus>, sqlx::Error> {
    let auth = query.authorization;
    sqlx::query(
        "SELECT set_config('humaux.tenant_id', $1, true), set_config('humaux.user_id', $2, true)",
    )
    .bind(auth.tenant_id().0.to_string())
    .bind(auth.user_id().map(|u| u.0.to_string()).unwrap_or_default())
    .execute(&mut **txn)
    .await?;
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
                    issued_hw: add_count(prev.issued_hw, row.issued_hw)?,
                    projection_hw: add_count(prev.projection_hw, row.projection_hw)?,
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
                Ok::<_, sqlx::Error>(FrontierBlock::new(
                    f.issued_hw,
                    f.projection_hw,
                    f.serving,
                    f.updated_at
                        .format(&Rfc3339)
                        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?,
                ))
            })
            .transpose()?;
        output.push(WorkspaceStatus {
            workspace_id: workspace_id.0,
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

fn add_count(a: u64, b: u64) -> Result<u64, sqlx::Error> {
    a.checked_add(b)
        .ok_or(sqlx::Error::Protocol("frontier overflow".into()))
}

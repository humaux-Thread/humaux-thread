//! `adapters::dedup_repo` — M15 D3/D10 exact-duplicate proposals, never identity changes.
//! Depends-on: crates=[humaux-domain, sqlx, uuid]; services=[PostgreSQL(any) r=[private.evidence_sources, private.memory_evidence, private.memory_records] x=[private.memory_subject_visibility_ok, private.visibility_allowed]]; env=[]; modules=[adapters::candidate_repo, adapters::confirm_token_repo, domain::error, domain::evidence, domain::identity, domain::knowledge]
//! Called-by: [tests]
//! Invariants: [caller-owned transaction and owner scope; PRIMARY non-note active targets; no Memory/Evidence writes]
//! Spec: Baseline §6.1.4; §11.6; §52; ADR-0113; M15 D3/D10

use humaux_domain::{
    error::ErrorCode, evidence::payload_sha256, identity::AuthorizationScope,
    knowledge::CandidateKind,
};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{candidate_repo, confirm_token_repo};

/// §11.6: proposals and source groups without two eligible distinct memories.
#[derive(Debug, PartialEq, Eq)]
pub struct DedupScan {
    /// Candidate ids created through the isolated proposal door.
    pub proposed: Vec<Uuid>,
    /// Duplicate source groups with fewer than two eligible distinct targets.
    pub skipped: usize,
}

/// M15 D3/D10: scan only the caller's owner/workspace visibility and propose without applying.
/// The caller must roll back on error; re-running intentionally permits another proposal (G6).
pub async fn scan_and_propose_in_txn(
    txn: &mut Transaction<'_, Postgres>,
    auth: &AuthorizationScope,
) -> Result<DedupScan, ErrorCode> {
    let workspace = confirm_token_repo::set_write_authorization_local(txn, auth).await?;
    // §11.6: lock eligible rows before proposing; a concurrent expiry must recheck the scan predicate.
    // dep: PostgreSQL(any) — source identities are unique per owner; RLS bounds both source and target reads
    let groups = sqlx::query(
        "WITH groups AS (
           SELECT tenant_id,owner_user_id,payload_sha256 FROM private.evidence_sources
           GROUP BY tenant_id,owner_user_id,payload_sha256 HAVING count(*) > 1
         ) SELECT g.payload_sha256, ARRAY(
           SELECT m.memory_id FROM private.memory_records m
           WHERE m.tenant_id=g.tenant_id
             AND EXISTS (
               SELECT 1 FROM private.evidence_sources s
               JOIN private.memory_evidence me ON me.evidence_id=s.evidence_id AND me.role='PRIMARY'
               WHERE me.memory_id=m.memory_id AND s.tenant_id=g.tenant_id
                 AND s.owner_user_id=g.owner_user_id AND s.payload_sha256=g.payload_sha256
             )
             AND m.status='active' AND m.archived_at IS NULL AND m.note_kind IS NULL
             AND private.memory_subject_visibility_ok(m.tenant_id,m.memory_id)
             AND private.visibility_allowed(m.visibility_class,true,
                   m.visibility_user_id=$1,m.visibility_workspace_id=$2)
           ORDER BY m.memory_id FOR UPDATE OF m
         ) AS targets FROM groups g ORDER BY g.payload_sha256",
    )
    .bind(auth.user_id().map(|id| id.0))
    .bind(workspace.0)
    .fetch_all(&mut **txn)
    .await
    .map_err(db_error)?;
    let mut scan = DedupScan {
        proposed: Vec::new(),
        skipped: 0,
    };
    for group in groups {
        let targets: Vec<Uuid> = group.try_get("targets").map_err(db_error)?;
        if targets.len() < 2 {
            scan.skipped += 1;
            continue;
        }
        let digest: Vec<u8> = group.try_get("payload_sha256").map_err(db_error)?;
        let mut manifest = b"rule:exact-duplicate@1\0".to_vec();
        manifest.extend_from_slice(&digest);
        for target in &targets {
            manifest.extend_from_slice(target.as_bytes());
        }
        let proposal = candidate_repo::Proposal {
            proposed_by: "rule:exact-duplicate@1".into(),
            kind: CandidateKind::DuplicateGroup,
            payload_hash: *payload_sha256(&manifest).as_bytes(),
            score: 1.0,
            targets,
        };
        scan.proposed.push(
            candidate_repo::propose_in_txn(txn, auth, &proposal)
                .await
                .map_err(|failure| failure.code)?,
        );
    }
    Ok(scan)
}

fn db_error(error: sqlx::Error) -> ErrorCode {
    match error {
        sqlx::Error::Database(_) | sqlx::Error::ColumnDecode { .. } => ErrorCode::Internal,
        _ => ErrorCode::DependencyUnavailable,
    }
}

//! `application::knowledge_backup` — backup verification receipts and read-only status facts (ADR-0064, ADR-0130).
//! Depends-on: crates=[async-trait, serde_json, time, uuid]; services=[]; env=[]; modules=[]
//! Called-by: [adapters::knowledge_backup_repo, adapters::maintenance_repo, application::knowledge_backup::drill_projection, maintenance::backup, maintenance::drill]
//! Invariants: [each verification appends one receipt; status observes one read-only snapshot]
//! Spec: §44; ADR-0064 D-J, D-V

pub mod drill_projection;

use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;

use time::OffsetDateTime;
use uuid::Uuid;

/// The newest receipt that measured the repository (a budget refusal qualifies, 10.11 D / F4), with the limits the
/// arm used then; the daemon reads no budget key (10.11 C / F10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeasuredBudget {
    /// `du -sk` of the repository at that run.
    pub repo_bytes: i64,
    /// `HUMAUX_MAINTENANCE_BACKUP_REPO_MAX_BYTES` as that run used it.
    pub repo_max_bytes: Option<i64>,
    /// `HUMAUX_MAINTENANCE_BACKUP_MIN_FREE_BYTES` as that run used it.
    pub min_free_bytes: Option<i64>,
    /// The next set's estimate: newest VERIFIED `set_repo_bytes` × 1.25, else that receipt's `estimate_bytes`.
    pub estimate_bytes: Option<i64>,
}

/// One DR_EVIDENCE reading from the database (ADR-0064 10.11 D). Timestamps are unix seconds.
#[derive(Debug, Clone, PartialEq)]
pub struct DrEvidence {
    /// `max(backup_stopped_at)` over the labels whose latest receipt is VERIFIED; `None` before the first.
    pub backup_last_success: Option<f64>,
    /// `finished_at` of the newest drill the table derived as succeeded.
    pub restore_drill_last_success: Option<f64>,
    /// `None` before the first measuring receipt.
    pub budget: Option<MeasuredBudget>,
    /// The latch (a row observed after the newest VERIFIED start) or archiving failing now.
    pub wal_archive_failing: bool,
}

/// One `ops.backup_receipts` row as a backup arm writes it. The arm CLAIMS `VERIFIED` by leaving `failure` empty;
/// the table refuses the claim unless verify exited 0 and the verified manifest is the label's first-verified one
/// (`backup_receipts_verified_derived`, FK to `ops.backup_sets`) and the row is shaped (`backup_receipts_shape`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackupReceipt {
    /// pgBackRest's set label; `None` for a refusal before any write (10.11 A).
    pub backup_label: Option<String>,
    /// The set's start / stop as pgBackRest's `info` reports them.
    pub backup_started_at: Option<OffsetDateTime>,
    /// See `backup_started_at`.
    pub backup_stopped_at: Option<OffsetDateTime>,
    /// sha256 of the set's `backup.manifest` pulled back now with `repo-get`.
    pub manifest_sha256: Option<Vec<u8>>,
    /// `pgbackrest verify --set` exit code; `None` when verify did not run.
    pub verify_exit: Option<i32>,
    /// The manifest sha256 this verification proved: set only when every verify step passed.
    pub verified_manifest_sha256: Option<Vec<u8>>,
    /// The named failure; `None` claims VERIFIED.
    pub failure: Option<String>,
    /// Live `du -sk` of the repository (backup arms only; D-K reads the newest non-NULL one).
    pub repo_bytes: Option<i64>,
    /// Live `df -Pk` free bytes of the repository filesystem.
    pub repo_free_bytes: Option<i64>,
    /// The set's repository size from `info` (`backup[].info.repository.size`, spike SP-11).
    pub set_repo_bytes: Option<i64>,
    /// `HUMAUX_MAINTENANCE_BACKUP_REPO_MAX_BYTES` as the arm used it (10.11 C: the daemon reads no budget key).
    pub repo_max_bytes: Option<i64>,
    /// `HUMAUX_MAINTENANCE_BACKUP_MIN_FREE_BYTES` as the arm used it.
    pub min_free_bytes: Option<i64>,
    /// The D-V estimate the budget precheck used.
    pub estimate_bytes: Option<i64>,
}

/// The latest verification verdict of one backup set (the newest receipt under its label).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetVerdict {
    /// pgBackRest's set label.
    pub label: String,
    /// The newest receipt of the label is VERIFIED.
    pub verified: bool,
    /// The set's start as the receipt recorded it.
    pub started_at: Option<OffsetDateTime>,
    /// The set's stop as the receipt recorded it.
    pub stopped_at: Option<OffsetDateTime>,
}

/// What `backup status` reads from the database, in one READ ONLY snapshot (status writes nothing, T-J4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupStatusFacts {
    /// Every labelled set's latest verdict (D-K's `latest` CTE: `DISTINCT ON (backup_label)`, newest first).
    pub sets: Vec<SetVerdict>,
    /// The oldest `ops.wal_archive_failures` row newer than the newest VERIFIED start (10.11 D's `v`): the latch.
    pub latched_since: Option<OffsetDateTime>,
    /// The newest `ops.wal_archive_failures` row (the PITR window starts after it, 10.11 E).
    pub newest_failure: Option<OffsetDateTime>,
    /// `pg_stat_archiver.last_failed_time` when it is newer than `last_archived_time`: failing right now.
    pub failing_now_since: Option<OffsetDateTime>,
}

/// Append-only receipt storage and the operator's read-only status snapshot.
#[async_trait::async_trait(?Send)]
pub trait BackupEvidencePort {
    /// Preserve database errors, including rejected verification claims.
    type Error;

    /// Append the claimed outcome and let the database enforce the verified manifest binding.
    async fn append_receipt(&self, receipt: &BackupReceipt) -> Result<Uuid, Self::Error>;

    /// Read all status facts in the adapter's read-only transaction.
    async fn status_snapshot(&self) -> Result<BackupStatusFacts, Self::Error>;
}

/// Record one backup attempt (§44, ADR-0064 D-J).
pub async fn record_receipt<P: BackupEvidencePort>(
    port: &P,
    receipt: &BackupReceipt,
) -> Result<Uuid, P::Error> {
    port.append_receipt(receipt).await
}

/// Obtain the facts used by the operator's status report (ADR-0064 10.11 E).
pub async fn read_status<P: BackupEvidencePort>(port: &P) -> Result<BackupStatusFacts, P::Error> {
    port.status_snapshot().await
}

/// The set a drill or `restore pitr` restores: the newest set whose LATEST receipt is VERIFIED (D-K's rule).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSet {
    /// pgBackRest's set label.
    pub label: String,
    /// The label's identity (`ops.backup_sets.manifest_sha256`, the first verification's manifest).
    pub manifest_sha256: Vec<u8>,
    /// The set's stop as its receipt recorded it.
    pub stopped_at: Option<OffsetDateTime>,
}

/// What one tenant holds, read as role_maintenance under the tenant GUC (D-N (f) ranking, (h), restored state).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TenantFacts {
    /// `private.memory_records` rows visible under the GUC (the (f) ranking).
    pub memories: i64,
    /// D-N (h): sha256 over the sorted `evidence_id:payload_sha256` pairs, `created_at <= at` when `at` was given.
    pub evidence_digest: Vec<u8>,
    /// Restored in-flight state the drill leaves untouched (R-37 quarantine): ISSUED tickets that are not
    /// generation tickets, non-terminal `ops.jobs`, RESERVED `ops.model_call_ledger` rows.
    pub issued_g1: i64,
    /// See `issued_g1`.
    pub open_jobs: i64,
    /// See `issued_g1`.
    pub reserved_calls: i64,
    /// Distinct `embedding_version` of live registry rows.
    pub labels: BTreeSet<String>,
    /// D-L step 0 / 10.11 H: live registry rows × (4 × dimension + 2,048) bytes.
    pub vector_bytes: i64,
}

/// One `ops.restore_drills` row (D-O as 0234 shaped it). `succeeded` is NOT a field: the receipt claims it only by
/// leaving `failure` empty, and `restore_drills_succeeded_derived` refuses a claim any check contradicts.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DrillReceipt {
    /// The drill id (`restore_drill_id`).
    pub drill_id: Uuid,
    /// The restored set.
    pub backup_label: Option<String>,
    /// Its identity as the drill read it.
    pub backup_manifest_sha256: Option<Vec<u8>>,
    /// T (between the witnesses).
    pub target_time: Option<OffsetDateTime>,
    /// Drill start / end.
    pub started_at: Option<OffsetDateTime>,
    /// See `started_at`.
    pub finished_at: Option<OffsetDateTime>,
    /// D-N (a).
    pub manifest_matches: Option<bool>,
    /// D-N (b).
    pub witness_a_present: Option<bool>,
    /// D-N (b).
    pub witness_b_absent: Option<bool>,
    /// D-N (c).
    pub server_version_matches: Option<bool>,
    /// D-N (d).
    pub migrations_drift: Option<i32>,
    /// D-N (e).
    pub rls_unforced: Option<i32>,
    /// D-N (f).
    pub isolation_violations: Option<i32>,
    /// D-N (f).
    pub isolation_pairs: Option<i32>,
    /// D-N (h).
    pub payload_digest_mismatches: Option<i32>,
    /// D-M: refused embedder attempts.
    pub provider_calls: Option<i64>,
    /// D-N (j).
    pub drill_archiver_attempts: Option<i64>,
    /// D-N (g).
    pub rebuild_equivalent: Option<bool>,
    /// D-N (g).
    pub rebuild_points: Option<i64>,
    /// D-G.
    pub legacy_points_without_vector: Option<i64>,
    /// D-N (g): memories distilled but unprojected at T.
    pub unprojected_at_target: Option<i64>,
    /// R-37 quarantine counts.
    pub restored_in_flight: Option<serde_json::Value>,
    /// D-O: labelled resources left after destroy.
    pub residue: Option<i32>,
    /// D-Q RTO.
    pub rto_seconds: Option<f64>,
    /// Every phase, timed.
    pub phase_seconds: Option<serde_json::Value>,
    /// The first named failure; `None` claims success.
    pub failure: Option<String>,
    /// 10.11 H.
    pub repo_intact: Option<bool>,
}

/// The cluster facts a drill reads through role_maintenance (D-N (c), (e), (j)). D-N (d) is not here:
/// `ops.schema_migrations` is owner-only (0201 D-C), so the drill reads it as the image superuser over each
/// container's socket.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClusterFacts {
    /// `server_version_num`.
    pub server_version_num: i32,
    /// D-N (e): tenant tables (`relkind` r/p with a `tenant_id` column) lacking `relrowsecurity AND
    /// relforcerowsecurity` or lacking a policy.
    pub rls_unforced: i64,
    /// D-N (j): `archived_count + failed_count` of `pg_stat_archiver` (0 when `--archive-mode=off` held).
    pub archiver_attempts: i64,
}

/// Role-gateway visibility facts from the restored pool.
#[async_trait::async_trait(?Send)]
pub trait DrillGatewayProbe {
    /// Database errors are preserved for the isolation failure receipt.
    type Error: std::fmt::Display;
    /// Count other-tenant and same-tenant facts in the role-scoped transaction.
    async fn gateway_isolation(&self, tenant: Uuid) -> Result<(i64, i64), Self::Error>;
}

/// Role-retrieval-worker visibility facts from the restored pool.
#[async_trait::async_trait(?Send)]
pub trait DrillVectorProbe {
    /// The shared database error surface.
    type Error: std::fmt::Display;
    /// Count visible other-tenant vectors in the role-scoped transaction.
    async fn vector_isolation(&self, tenant: Uuid) -> Result<i64, Self::Error>;
}

impl DrillReceipt {
    /// Records the first named failure (a later one never overwrites it).
    pub fn fail(&mut self, failure: impl Into<String>) {
        if self.failure.is_none() {
            self.failure = Some(failure.into());
        }
    }

    /// R-37 quarantine: what the restored cluster still had in flight at T, left untouched (it is destroyed).
    pub fn restored_in_flight(&mut self, facts: &BTreeMap<Uuid, TenantFacts>) {
        let sum = |f: fn(&TenantFacts) -> i64| facts.values().map(f).sum::<i64>();
        self.restored_in_flight = Some(json!({
            "issued_g1": sum(|f| f.issued_g1),
            "open_jobs": sum(|f| f.open_jobs),
            "reserved_calls": sum(|f| f.reserved_calls),
        }));
    }

    /// D-N (f): the two tenants with the most memories, each probed as role_gateway (memories, Evidence, registry)
    /// and role_retrieval_worker (vectors); every other-tenant row seen is a violation, and each tenant must see
    /// its own memories (non-vacuous).
    pub async fn check_isolation<G: DrillGatewayProbe, V: DrillVectorProbe<Error = G::Error>>(
        &mut self,
        gateway: &G,
        reader: &V,
        facts: &BTreeMap<Uuid, TenantFacts>,
    ) {
        let mut ranked: Vec<(Uuid, i64)> = facts
            .iter()
            .filter(|(_, f)| f.memories > 0)
            .map(|(t, f)| (*t, f.memories))
            .collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        ranked.truncate(2);
        if ranked.len() < 2 {
            self.fail("isolation_not_applicable: fewer than two tenants with memory records");
        }
        let mut violations = 0_i64;
        let mut pairs = 0;
        for (tenant, _) in &ranked {
            let gateway = gateway.gateway_isolation(*tenant).await;
            let vectors = reader.vector_isolation(*tenant).await;
            match (gateway, vectors) {
                (Ok((others, own)), Ok(vector_others)) => {
                    violations += others + vector_others;
                    pairs += 1;
                    if own == 0 {
                        self.fail(format!("isolation_vacuous:{tenant}"));
                    }
                }
                (Err(e), _) | (_, Err(e)) => {
                    self.fail(format!("probe_failed:isolation: {e}"));
                    return;
                }
            }
        }
        self.isolation_violations = Some(i32::try_from(violations).unwrap_or(i32::MAX));
        self.isolation_pairs = Some(pairs);
    }

    /// D-N (h): per tenant, the Evidence digest of the source at T against the restored cluster's (all rows).
    pub async fn check_digests<P: DrillEvidencePort, E: std::fmt::Display>(
        &mut self,
        source: &P,
        tenants: Result<Vec<Uuid>, E>,
        facts: &BTreeMap<Uuid, TenantFacts>,
        target: OffsetDateTime,
    ) where
        P::Error: std::fmt::Display,
    {
        let tenants = match tenants {
            Ok(t) => t,
            Err(e) => {
                self.fail(format!("probe_failed:digests: {e}"));
                return;
            }
        };
        let mut mismatches = 0;
        let mut seen: BTreeSet<Uuid> = BTreeSet::new();
        for tenant in tenants {
            seen.insert(tenant);
            match source.tenant_facts(tenant, Some(target)).await {
                Ok(s) => {
                    if facts.get(&tenant).map(|d| &d.evidence_digest) != Some(&s.evidence_digest) {
                        mismatches += 1;
                    }
                }
                Err(e) => {
                    self.fail(format!("probe_failed:digests: {e}"));
                    return;
                }
            }
        }
        mismatches += facts.keys().filter(|t| !seen.contains(t)).count();
        self.payload_digest_mismatches = Some(i32::try_from(mismatches).unwrap_or(i32::MAX));
    }

    /// Record both witnesses before refusing a pool that contains the post-target witness (D-N(b)).
    pub fn check_restored_witnesses(&mut self, kinds: &[String]) -> Result<(), String> {
        self.witness_a_present = Some(kinds.iter().any(|k| k == "A"));
        self.witness_b_absent = Some(!kinds.iter().any(|k| k == "B"));
        if kinds.iter().any(|k| k == "B") {
            return Err("drill_pool_is_not_the_restore".to_owned());
        }
        Ok(())
    }

    /// A drill claims success only when every check the table derives success from passed (D-O): any check that
    /// failed or was not reached becomes the named failure, so the receipt never claims what the CHECK refuses.
    pub fn derive_failure(&mut self) {
        let r = &*self;
        let checks = [
            ("manifest_matches", r.manifest_matches == Some(true)),
            ("witness_a_present", r.witness_a_present == Some(true)),
            ("witness_b_absent", r.witness_b_absent == Some(true)),
            (
                "server_version_matches",
                r.server_version_matches == Some(true),
            ),
            ("rebuild_equivalent", r.rebuild_equivalent == Some(true)),
            ("repo_intact", r.repo_intact == Some(true)),
            ("migrations_drift", r.migrations_drift == Some(0)),
            ("rls_unforced", r.rls_unforced == Some(0)),
            ("isolation_violations", r.isolation_violations == Some(0)),
            ("isolation_pairs", r.isolation_pairs == Some(2)),
            (
                "payload_digest_mismatches",
                r.payload_digest_mismatches == Some(0),
            ),
            ("provider_calls", r.provider_calls == Some(0)),
            (
                "drill_archiver_attempts",
                r.drill_archiver_attempts == Some(0),
            ),
            (
                "legacy_points_without_vector",
                r.legacy_points_without_vector == Some(0),
            ),
            ("residue", r.residue == Some(0)),
            ("rebuild_points", r.rebuild_points.is_some()),
        ];
        let failed: Vec<&str> = checks
            .iter()
            .filter(|(_, ok)| !ok)
            .map(|(name, _)| *name)
            .collect();
        if !failed.is_empty() {
            self.fail(format!("checks_failed:{}", failed.join(",")));
        }
    }
}

/// Source/restore evidence read under the maintenance role and the post-cleanup receipt write.
#[async_trait::async_trait(?Send)]
pub trait DrillEvidencePort {
    /// Includes database refusal of a success claim contradicted by the receipt.
    type Error;

    /// Select the latest eligible set.
    async fn newest_verified_set(&self) -> Result<Option<VerifiedSet>, Self::Error>;
    /// Read the tenant evidence in a scoped snapshot.
    async fn tenant_facts(
        &self,
        tenant: Uuid,
        at: Option<OffsetDateTime>,
    ) -> Result<TenantFacts, Self::Error>;
    /// Read server, RLS and archive facts.
    async fn cluster_facts(&self) -> Result<ClusterFacts, Self::Error>;
    /// Commit the witness before observing its WAL file.
    async fn write_witness(
        &self,
        drill_id: Uuid,
        kind: &str,
    ) -> Result<(OffsetDateTime, String), Self::Error>;
    /// Read the database clock between witnesses.
    async fn clock(&self) -> Result<OffsetDateTime, Self::Error>;
    /// Read witness kinds visible after restore.
    async fn witness_kinds(&self, drill_id: Uuid) -> Result<Vec<String>, Self::Error>;
    /// Append the receipt and return the database verdict.
    async fn insert_drill_receipt(&self, receipt: &DrillReceipt) -> Result<bool, Self::Error>;
}

/// Persist the final post-destroy receipt and obtain its database-derived verdict (ADR-0064 D-O).
pub async fn record_drill<P: DrillEvidencePort>(
    port: &P,
    receipt: &DrillReceipt,
) -> Result<bool, P::Error> {
    port.insert_drill_receipt(receipt).await
}

/// Reject either live address before the first restored pool connects (ADR-0064 D-N(g)).
pub fn check_drill_targets(
    source_addr: String,
    pg_addr: &str,
    configured_qdrant: Option<String>,
    qdrant_addr: String,
) -> Result<(), String> {
    let localhost =
        |a: &str| a.replace("localhost:", &format!("{}:", std::net::Ipv4Addr::LOCALHOST));
    if localhost(&source_addr) == pg_addr
        || configured_qdrant.as_deref().map(localhost) == Some(qdrant_addr)
    {
        return Err("drill_target_is_live".to_owned());
    }
    Ok(())
}

/// Require an empty Qdrant before initializing the closed projection worker (ADR-0064 D-N(g)).
pub fn check_drill_collections(collections: &[String]) -> Result<(), String> {
    if !collections.is_empty() {
        return Err("drill_qdrant_not_fresh".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod drill_target_tests {
    use super::{check_drill_collections, check_drill_targets};

    #[test]
    fn refuses_same_postgres() {
        assert_eq!(
            check_drill_targets(
                "localhost:5432".into(),
                "127.0.0.1:5432",
                None,
                "127.0.0.1:6333".into()
            ),
            Err("drill_target_is_live".into())
        );
    }

    #[test]
    fn postgres_loopback_spellings_have_the_same_refusal() {
        for source in ["localhost:5432", "127.0.0.1:5432"] {
            assert_eq!(
                check_drill_targets(
                    source.into(),
                    "127.0.0.1:5432",
                    None,
                    "127.0.0.1:6333".into()
                ),
                Err("drill_target_is_live".into())
            );
        }
    }

    #[test]
    fn refuses_same_qdrant() {
        assert_eq!(
            check_drill_targets(
                "localhost:5433".into(),
                "127.0.0.1:5432",
                Some("localhost:6333".into()),
                "127.0.0.1:6333".into()
            ),
            Err("drill_target_is_live".into())
        );
    }

    #[test]
    fn refuses_existing_collections() {
        assert_eq!(
            check_drill_collections(&["existing".into()]),
            Err("drill_qdrant_not_fresh".into())
        );
    }

    #[test]
    fn refuses_post_target_witness() {
        let mut receipt = super::DrillReceipt::default();
        assert_eq!(
            receipt.check_restored_witnesses(&["A".into(), "B".into()]),
            Err("drill_pool_is_not_the_restore".into())
        );
        assert_eq!(
            (receipt.witness_a_present, receipt.witness_b_absent),
            (Some(true), Some(false))
        );
    }

    #[test]
    fn permits_pre_target_witness() {
        let mut receipt = super::DrillReceipt::default();
        assert_eq!(receipt.check_restored_witnesses(&["A".into()]), Ok(()));
        assert_eq!(
            (receipt.witness_a_present, receipt.witness_b_absent),
            (Some(true), Some(true))
        );
    }

    #[test]
    fn permits_separate_empty_target() {
        assert_eq!(
            check_drill_targets(
                "localhost:5433".into(),
                "127.0.0.1:5432",
                Some("localhost:6334".into()),
                "127.0.0.1:6333".into()
            ),
            Ok(())
        );
        assert_eq!(check_drill_collections(&[]), Ok(()));
    }
}

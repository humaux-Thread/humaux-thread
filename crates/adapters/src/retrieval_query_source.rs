//! `adapters::retrieval_query_source` — Reads metadata for the authenticated query-source principal.
//! Depends-on: crates=[hex, humaux-domain, humaux-local-secret-scan, humaux-retrieval, sha2, sqlx]; services=[PostgreSQL(any) r=[private.retrieval_query_sources],
//!   PostgreSQL(role_retrieval_worker), subprocess(fake-gitleaks)]; env=[]; modules=[adapters::postgres, adapters::retrieval_query_reservation, domain::identity]
//! Called-by: [tests]
//! Invariants: [read visibility requires the source principal, user and an allowed workspace; query and wire bytes are never persisted]
//! Spec: none

use sqlx::Row;
use sqlx::types::Uuid;
use sqlx::types::time::OffsetDateTime;

use humaux_domain::identity::AuthorizationScope;

use crate::postgres::RetrievalWorkerDbPool;
use crate::retrieval_query_reservation::set_authorization_local;

pub use crate::retrieval_query_reservation::{
    RetrievalQueryCallContext, RetrievalQueryDisclosureReservation, RetrievalQuerySourceError,
    SerializedRetrievalQueryBatch, reserve_retrieval_query_batch, revoke_retrieval_query_source,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetrievalQuerySource {
    pub query_source_id: Uuid,
    pub tenant_id: Uuid,
    pub principal_id: Uuid,
    pub user_id: Uuid,
    pub workspace_id: Uuid,
    pub request_id: Uuid,
    pub logical_call_id: Uuid,
    pub attempt_no: i32,
    pub query_ordinal: i32,
    pub profile_fingerprint: String,
    pub classifier_revision: String,
    pub data_class: String,
    pub query_sha256: Vec<u8>,
    pub query_bytes: i64,
    pub wire_payload_sha256: Vec<u8>,
    pub wire_payload_bytes: i64,
    pub revoked_at: Option<OffsetDateTime>,
}

/// Reads a query-source metadata row only for the authenticated source principal/user and a
/// currently allowed workspace. It never returns query or provider wire bytes because none are
/// persisted.
pub async fn get_retrieval_query_source(
    pool: &RetrievalWorkerDbPool,
    authorization: &AuthorizationScope,
    query_source_id: Uuid,
) -> Result<Option<RetrievalQuerySource>, RetrievalQuerySourceError> {
    // dep: PostgreSQL(role_retrieval_worker) — transaction entry for `get_retrieval_query_source`
    let mut txn = pool.pool().begin().await?;
    let (tenant_id, user_id, principal_id) =
        set_authorization_local(&mut txn, authorization).await?;
    let rows = sqlx::query(
        "SELECT query_source_id, tenant_id, principal_id, user_id, workspace_id, request_id, \
                logical_call_id, attempt_no, query_ordinal, profile_fingerprint, classifier_revision, data_class, \
                query_sha256, query_bytes, wire_payload_sha256, wire_payload_bytes, revoked_at \
         FROM private.retrieval_query_sources \
         WHERE tenant_id=$1 AND query_source_id=$2 AND principal_id=$3 AND user_id=$4",
    )
    .bind(tenant_id)
    .bind(query_source_id)
    .bind(principal_id)
    .bind(user_id)
    .fetch_all(&mut *txn)
    .await?;
    let source = match rows.as_slice() {
        [] => None,
        [row]
            if authorization
                .allowed_workspace_ids()
                .iter()
                .any(|id| id.0 == row.get::<Uuid, _>("workspace_id")) =>
        {
            Some(RetrievalQuerySource {
                query_source_id: row.get("query_source_id"),
                tenant_id: row.get("tenant_id"),
                principal_id: row.get("principal_id"),
                user_id: row.get("user_id"),
                workspace_id: row.get("workspace_id"),
                request_id: row.get("request_id"),
                logical_call_id: row.get("logical_call_id"),
                attempt_no: row.get("attempt_no"),
                query_ordinal: row.get("query_ordinal"),
                profile_fingerprint: row.get("profile_fingerprint"),
                classifier_revision: row.get("classifier_revision"),
                data_class: row.get("data_class"),
                query_sha256: row.get("query_sha256"),
                query_bytes: row.get("query_bytes"),
                wire_payload_sha256: row.get("wire_payload_sha256"),
                wire_payload_bytes: row.get("wire_payload_bytes"),
                revoked_at: row.get("revoked_at"),
            })
        }
        [_] => None,
        _ => return Err(RetrievalQuerySourceError::InvalidMetadata),
    };
    txn.commit().await?;
    Ok(source)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use crate::retrieval_query_reservation::validate_call;
    use humaux_domain::dataclass::DataClass;
    use humaux_domain::egress::{self, PrivateDataPurpose, ProcessorId};
    use humaux_domain::identity::{BoundedSet, PrincipalId};
    use humaux_domain::ids::{TenantId, UserId, WorkspaceId};
    use humaux_local_secret_scan::{
        LocalSecretScanner, LocalSecretScannerConfig, SealedRetrievalQuery,
    };
    use humaux_retrieval::request::{RetrievalIntent, build_request};
    use sha2::{Digest, Sha256};

    struct FakeScanner(PathBuf);

    impl FakeScanner {
        /// One stable fake scanner per marker, kept beside the test binary under `target/` and
        /// reused across runs instead of written fresh into `temp_dir()` every time.
        ///
        /// A newly created executable pays a macOS Gatekeeper/XProtect provenance assessment on
        /// its first `exec`, inside `dyld` before `main` runs: sub-second on an idle box, and
        /// measured at 32m15s on a busy one (ADR-0047). `seal()` probes the binary under the
        /// production 2 s `LocalSecretScannerConfig.timeout`, so a per-test binary turned that
        /// assessment into a `DependencyUnavailable` flake (cards 8 / 13 / 17). The production
        /// timeout must not be widened (§79.2), so the fixture stops manufacturing the cost: the
        /// file is rewritten only when its content changes, and any assessment it still owes is
        /// paid by the unbounded warm `exec` below — never inside the timed probe.
        fn new(marker: &str) -> Self {
            let script = format!(
                "#!/bin/sh\nif [ \"$1\" = \"version\" ]; then printf 'same-version\\n'; exit 0; fi\ncat >/dev/null\nexit 0\n# {marker}\n"
            );
            let directory = std::env::current_exe()
                .ok()
                .and_then(|executable| executable.parent().map(Path::to_path_buf))
                .unwrap_or_else(std::env::temp_dir);
            let path = directory.join(format!("humaux-query-scanner-{marker}"));
            if fs::read(&path).is_ok_and(|current| current == script.as_bytes()) {
                // Byte-identical: reuse it, assessment included. Rewriting would forfeit both.
            } else {
                let staged =
                    directory.join(format!("humaux-query-scanner-{marker}-{}", Uuid::now_v7()));
                fs::write(&staged, &script).expect("write fake scanner");
                let mut permissions = fs::metadata(&staged)
                    .expect("fake scanner metadata")
                    .permissions();
                permissions.set_mode(0o700);
                fs::set_permissions(&staged, permissions).expect("make fake scanner executable");
                // Rename so a concurrent test process never execs a half-written script.
                fs::rename(&staged, &path).expect("publish fake scanner");
            }
            // dep: subprocess(fake-gitleaks) — spawns for `new`
            let _ = std::process::Command::new(&path)
                .arg("version")
                .env_clear()
                .output();
            Self(path)
        }

        fn seal(&self, text: &str) -> SealedRetrievalQuery {
            let binary = fs::read(&self.0).expect("read fake scanner");
            let scanner = LocalSecretScanner::new(LocalSecretScannerConfig {
                executable: self.0.clone(),
                expected_version: "same-version".to_owned(),
                expected_executable_sha256: hex::encode(Sha256::digest(binary)),
                timeout: Duration::from_secs(2),
                max_payload_bytes: 64 * 1024,
                finding_exit_code: 1,
            })
            .expect("valid fake scanner");
            let profile =
                humaux_retrieval::request::resolve_registered_retrieval_profile(&BTreeMap::new())
                    .expect("registered profile");
            let request = build_request(
                RetrievalIntent::new(text.to_owned(), vec![], BTreeSet::new(), BTreeSet::new())
                    .expect("retrieval intent"),
                &profile,
            )
            .expect("retrieval request");
            scanner
                .seal_query(&request.trusted_query().expect("trusted text query"))
                .expect("clean sealed query")
        }
    }

    // No `Drop` that removes the file: deleting it is what forced the next run to create — and
    // have macOS re-assess — a brand-new executable. It lives under `target/`, which `.gitignore`
    // already covers and `cargo clean` reclaims.

    #[test]
    fn mixed_scanner_attestations_are_rejected_before_reserve() {
        let first_scanner = FakeScanner::new("first-binary");
        let second_scanner = FakeScanner::new("second-binary");
        let queries = [
            first_scanner.seal("first clean query"),
            second_scanner.seal("second clean query"),
        ];
        assert_ne!(
            queries[0].classifier_revision(),
            queries[1].classifier_revision()
        );

        let tenant_id = TenantId::new();
        let workspace_id = WorkspaceId::new();
        let authorization = AuthorizationScope::new(
            tenant_id,
            PrincipalId(Uuid::now_v7()),
            Some(UserId::new()),
            BoundedSet::new([workspace_id]).expect("bounded workspace"),
        );
        let context = RetrievalQueryCallContext::new(
            &authorization,
            workspace_id,
            Uuid::now_v7(),
            Uuid::now_v7(),
            1,
        )
        .expect("query context");
        let wire = SerializedRetrievalQueryBatch::new("text-embedding-v4", 2, &queries)
            .expect("query wire");
        let permit = egress::authorize(
            tenant_id,
            ProcessorId(Uuid::now_v7()),
            PrivateDataPurpose::RetrievalEmbedding,
            DataClass::Private,
            wire.payload(),
            Duration::from_secs(30),
        )
        .expect("embedding permit");

        assert!(matches!(
            validate_call(&context, &wire, &permit),
            Err(RetrievalQuerySourceError::InvalidMetadata)
        ));
    }
}

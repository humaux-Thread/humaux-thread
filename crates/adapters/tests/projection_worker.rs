//! `adapters::tests::projection_worker` — `projection_worker::run_once` integration test (§17.4/§15.7) against a real
//!   Postgres and a real Qdrant.
//! Depends-on: crates=[async-trait, humaux-adapters, humaux-domain, humaux-infra-cell, humaux-local-secret-scan,
//!   humaux-projection, humaux-retrieval-provider, humaux-testkit, postgres, serde_json, sha2, sqlx, time, tokio];
//!   services=[PostgreSQL(any) r=[ops.commit_seq_seq, private.ingest_tickets] w=[control.memberships,
//!   control.private_reasoning_domains, control.tenants, control.users, control.workspace_memberships,
//!   control.workspaces, ops.jobs, ops.outbox, private.events, private.evidence_objects,
//!   private.identity_note_materializations, private.memory_affects, private.memory_evidence, private.memory_records,
//!   private.memory_subjects, private.subjects, projection.card_profile_policies, projection.memory_vectors,
//!   projection.private_memory_points, projection.stream_checkpoints, projection.stream_log,
//!   projection.tenant_placements]
//!   x=[private.memory_subject_visibility_ok, projection.note_chunk_count],
//!   PostgreSQL(role_batch_issuer), PostgreSQL(role_gateway) x=[projection.stream_point_ledger],
//!   PostgreSQL(role_retrieval_worker), Qdrant(*),
//!   subprocess(gitleaks)]; env=[HUMAUX_RETRIEVAL_WORKER_PG_DSN, HUMAUX_TEST_GITLEAKS_BIN, HUMAUX_TEST_PG_DSN,
//!   HUMAUX_TEST_QDRANT_URL]; modules=[adapters::memory_governance_repo, adapters::postgres,
//!   adapters::private_projection_registry, adapters::projection_worker, adapters::qdrant, adapters::remember,
//!   adapters::tests::support::governance_ops, adapters::tests::support::token_keys, domain::authority,
//!   domain::confirm, domain::dataclass, domain::egress, domain::error, domain::evidence, domain::identity, domain::ids,
//!   domain::memory, domain::subject, humaux-local-secret-scan, humaux-testkit, infra-cell::permit,
//!   infra-cell::resource, infra-cell::transport, projection::card, projection::note_chunks, projection::serving,
//!   retrieval-provider::adapters, retrieval-provider::contract]
//! Called-by: [cargo-test]
//! Invariants: [uses a throwaway tenant and Qdrant collection cleaned up on Drop; a ticket is marked done only after
//!   search-visible confirmation; no DSN, unreachable PG/Qdrant or no local gitleaks is a visible SKIP; the global
//!   card profile policy row is read or flipped only under one process-wide lock and restored on drop (ADR-0068 D-I)]
//! Spec: Baseline §17.4; §15.7; §79.2; ADR-0052; ADR-0055; ADR-0056; ADR-0057; ADR-0068; ADR-0083 D-B
//!
//! Same convention as `outbox_batch_remember.rs`/`stream_repo.rs`: throwaway
//! `control.tenants` row + throwaway Qdrant collection, cleaned up on `Drop`.
//!
//! Three-state skip (§79.2): no DSN, unreachable Postgres/Qdrant, or a missing local gitleaks
//! binary all print a visible SKIP and return — see [`discover_gitleaks`]'s doc for why the
//! last one is resolved dynamically rather than via fixed env vars.

use std::collections::{BTreeMap, BTreeSet};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use humaux_adapters::postgres::{RetrievalWorkerDbPool, RuntimeDbPool};
use humaux_adapters::private_projection_registry::{
    PrivateMemoryPointRegistration, ProjectionPointId, RegistrationOutcome,
    bind_embedding_fingerprint, register_private_memory_point, retire_private_memory_point,
    worker_fingerprint_inputs,
};
use humaux_adapters::projection_worker::{CardEmbedder, ProjectionWorkerDeps, run_once};
use humaux_adapters::qdrant::{
    DenseCandidate, DenseQuery, DenseQueryVersions, Distance, PlacementClass, PointId,
    PromotionState, QdrantOperation, RetrievalFamily, ShardingMethod, TenantPlacementRow,
    create_collection_body, delete_points, ha_profile_for, query_dense, subject_index_body,
    tenant_index_body,
};
use humaux_adapters::remember::{self, RememberCommand};
use humaux_domain::authority::MemoryId;
use humaux_domain::egress::ProcessorId;
use humaux_domain::error::ErrorCode;
use humaux_domain::evidence::{EvidenceOriginClass, payload_sha256};
use humaux_domain::identity::{AuthorizationScope, BoundedSet, PrincipalId};
use humaux_domain::ids::{TenantId, UserId};
use humaux_domain::subject::SubjectId;
use humaux_infra_cell::{
    CallerId, CellAccessPermit, CellId, HttpIntraCellTransport, IntraCellError,
    IntraCellHttpTransport, IntraCellMethod, IntraCellRequest, IntraCellResource,
    IntraCellResourceRegistry, IntraCellResponse, ResourceEntry, authorize_cell_access,
};
use humaux_local_secret_scan::{LocalSecretScanner, LocalSecretScannerConfig, SealedRetrievalCard};
use humaux_projection::serving::StreamFamily;
use humaux_retrieval_provider::adapters::TestDoubleProvider;
use humaux_retrieval_provider::contract::{
    CalibrationProfileId, EmbeddingModelDescriptor, EmbeddingProvider, ModelId,
    RerankModelDescriptor, RerankScoreSemantics,
};
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use sha2::{Digest, Sha256};
use sqlx::types::Uuid;

use humaux_adapters::memory_governance_repo::{ArchiveResult, RestoreResult};
use humaux_domain::confirm::DestructiveOp;

#[path = "support/governance_ops.rs"]
mod governance_ops;
use governance_ops::Governor;

/// Card 21 fix pass: this suite's fixed §7.4 worker identity. `advance_prefix` writes it into
/// `projection.stream_checkpoints.projection_processor_id` (migration 0171); the attribution
/// itself is asserted in `tests/stream_repo.rs`
/// (`a_checkpoint_carries_the_processor_id_of_the_worker_that_advanced_it`).
const TEST_PROCESSOR_ID: Uuid = Uuid::from_u128(0x0171_0001);

fn dsn_as_role(admin_dsn: &str, role: &str) -> String {
    let sep = if admin_dsn.contains('?') { '&' } else { '?' };
    format!("{admin_dsn}{sep}options=-c%20role%3D{role}")
}

/// Locates a real gitleaks binary and computes the exact `(version, sha256)` pair
/// [`LocalSecretScanner::new`] will independently re-derive and check — mirrors that
/// function's own `run_version`/`sha256_hex` (a copy is unavoidable: those are private to
/// `humaux-local-secret-scan`). Checks `HUMAUX_TEST_GITLEAKS_BIN` first (the convention
/// `bins/gateway/tests/mcp_gateway.rs` already uses), then a couple of locally-staged fallback
/// paths, so this test exercises the real scan path in an environment that has gitleaks
/// staged without requiring three more env vars to be exported by hand.
fn discover_gitleaks() -> Option<(std::path::PathBuf, String, String)> {
    let candidates: Vec<std::path::PathBuf> =
        if let Ok(bin) = std::env::var("HUMAUX_TEST_GITLEAKS_BIN") {
            vec![bin.into()]
        } else {
            vec![
                "/private/tmp/gitleaks-8.30.1/gitleaks".into(),
                "/private/tmp/gitleaks-linux/gitleaks".into(),
            ]
        };
    for path in candidates {
        if !path.is_absolute() || !path.is_file() {
            continue;
        }
        let bytes = std::fs::read(&path).ok()?;
        let sha256 = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        // dep: subprocess(gitleaks) — spawn a child process for this fixture
        let output = Command::new(&path)
            .arg("version")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        if !output.status.success() {
            continue;
        }
        let version = String::from_utf8(output.stdout).ok()?.trim().to_owned();
        if version.is_empty() {
            continue;
        }
        return Some((path, version, sha256));
    }
    None
}

fn qdrant_port() -> u16 {
    std::env::var("HUMAUX_TEST_QDRANT_URL")
        .ok()
        .and_then(|url| url.rsplit(':').next().map(str::to_owned))
        .and_then(|port| port.parse().ok())
        .unwrap_or(6333)
}

struct Handle {
    rt: tokio::runtime::Runtime,
    admin: Client,
    gateway: RuntimeDbPool,
    transport: Arc<HttpIntraCellTransport>,
    registry: IntraCellResourceRegistry,
    collection: String,
    tenant_id: Uuid,
    reasoning_domain_id: Uuid,
    scanner: Arc<LocalSecretScanner>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        Governor::cleanup(&mut self.admin, self.tenant_id);
        // Jobs go first, in one batch with the rows that produced them: the `ops.outbox` trigger
        // enqueues a DERIVED_DISTILL job per seeded Evidence, and a claimable job of a tenant with
        // no route binding is released NotReady forever, never DEAD (private-worker distill.rs) —
        // left behind, it is claimed ahead of every later tenant on the shared dev DB (card 31
        // rehearsal: 258 leaked jobs, memory_records=0). A failure is printed, not swallowed; gate
        // `no_leaked_distill_jobs` is the check.
        if let Err(error) = self.admin.batch_execute(&format!(
            "DELETE FROM ops.jobs WHERE tenant_id = '{0}'; \
             DELETE FROM projection.private_memory_points WHERE tenant_id = '{0}'; \
             DELETE FROM projection.memory_vectors WHERE tenant_id = '{0}'; \
             DELETE FROM projection.tenant_placements WHERE tenant_id = '{0}'; \
             DELETE FROM ops.outbox WHERE tenant_id = '{0}'; \
             DELETE FROM projection.stream_log WHERE tenant_id = '{0}'; \
             DELETE FROM projection.stream_checkpoints WHERE tenant_id = '{0}'; \
             DELETE FROM private.memory_evidence USING private.memory_records m \
               WHERE memory_evidence.memory_id = m.memory_id AND m.tenant_id = '{0}'; \
             DELETE FROM private.memory_records WHERE tenant_id = '{0}'; \
             DELETE FROM private.events USING private.evidence_objects eo \
               WHERE events.event_id = eo.evidence_id AND eo.tenant_id = '{0}'; \
             DELETE FROM private.evidence_objects WHERE tenant_id = '{0}'; \
             DELETE FROM control.private_reasoning_domains WHERE tenant_id = '{0}';",
            self.tenant_id
        )) {
            eprintln!(
                "projection_worker cleanup failed for tenant {}: {error}",
                self.tenant_id
            );
        }
        // Best effort and kept apart: `control.audit_events` is append-only and references the
        // tenant, so a fixture that ran a governance op cannot delete its tenant row. In the same
        // batch as the deletes above, this refusal rolled the whole cleanup back.
        let _ = self.admin.batch_execute(&format!(
            "DELETE FROM control.workspaces WHERE tenant_id = '{0}'; \
             DELETE FROM control.tenants WHERE tenant_id = '{0}';",
            self.tenant_id
        ));
        if let Ok(runtime) = tokio::runtime::Runtime::new() {
            let transport = self.transport.clone();
            let registry = self.registry.clone();
            let collection = self.collection.clone();
            runtime.block_on(async move {
                if let Ok(permit) = authorize_cell_access(
                    &registry,
                    IntraCellResource::QDRANT_REST,
                    Duration::from_secs(30),
                ) {
                    let _ = transport
                        .execute(
                            &permit,
                            // dep: Qdrant(*) — Qdrant wire call for this fixture
                            IntraCellRequest {
                                method: IntraCellMethod::Delete,
                                path: format!("/collections/{collection}"),
                                json_body: None,
                                headers: Vec::new(),
                            },
                        )
                        .await;
                }
            });
        }
    }
}

/// Builds a loopback Qdrant `IntraCellResource` registry/transport and creates one throwaway
/// collection (§17.1 tenant index included) — split out of [`Fixture::isolate`] purely to stay
/// under this repo's line-count lint.
async fn setup_qdrant_collection() -> Result<
    (
        IntraCellResourceRegistry,
        Arc<HttpIntraCellTransport>,
        String,
    ),
    DbFixtureSkipReason,
> {
    let cell_id = CellId(Uuid::new_v4());
    let caller = CallerId("projection_worker.rs test".to_owned());
    let mut entries = BTreeMap::new();
    entries.insert(
        IntraCellResource::QDRANT_REST,
        ResourceEntry::new(
            "127.0.0.1",
            qdrant_port(),
            cell_id,
            vec!["127.0.0.1/32".parse().expect("loopback CIDR")],
            BTreeSet::from([caller.clone()]),
            false,
        )
        .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(format!("{e:?}")))?,
    );
    let registry = IntraCellResourceRegistry::new(entries, cell_id, caller);
    let transport = Arc::new(
        HttpIntraCellTransport::new(
            registry.clone(),
            Duration::from_secs(10),
            humaux_infra_cell::DEFAULT_MAX_RESPONSE_BYTES,
        )
        .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(format!("{e:?}")))?,
    );
    let collection = format!("test_private_memory_v1_{}", Uuid::new_v4().simple());
    let permit = authorize_cell_access(
        &registry,
        IntraCellResource::QDRANT_REST,
        Duration::from_secs(30),
    )
    .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(format!("{e:?}")))?;
    for (path, body) in [
        (
            format!("/collections/{collection}"),
            create_collection_body(4, Distance::Cosine, 1, 1, 1, ShardingMethod::Auto),
        ),
        (
            format!("/collections/{collection}/index"),
            tenant_index_body(),
        ),
        (
            format!("/collections/{collection}/index"),
            subject_index_body(),
        ),
    ] {
        transport
            .execute(
                &permit,
                // dep: Qdrant(*) — Qdrant wire call for this fixture
                IntraCellRequest {
                    method: IntraCellMethod::Put,
                    path,
                    json_body: Some(body),
                    headers: Vec::new(),
                },
            )
            .await
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(format!("{e:?}")))?;
    }
    Ok((registry, transport, collection))
}

struct Fixture;

impl DbIntegrationFixture for Fixture {
    type Handle = Handle;

    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        governance_ops::token_keys::install();
        let dsn =
            std::env::var("HUMAUX_TEST_PG_DSN").map_err(|_| DbFixtureSkipReason::NoDatabaseUrl)?;
        // dep: PostgreSQL(any) — open a role-scoped PG connection/pool for this test
        let mut admin = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;

        let migrated: bool = admin
            .query_one(
                "SELECT to_regclass('private.ingest_tickets') IS NOT NULL \
                 AND to_regclass('projection.private_memory_points') IS NOT NULL",
                &[],
            )
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?
            .get(0);
        if !migrated {
            return Err(DbFixtureSkipReason::IsolationSetupFailed(
                "private.ingest_tickets / projection.private_memory_points missing — run \
                 `cargo xtask migrate` against HUMAUX_TEST_PG_DSN first"
                    .to_string(),
            ));
        }

        let Some((gitleaks_bin, gitleaks_version, gitleaks_sha256)) = discover_gitleaks() else {
            return Err(DbFixtureSkipReason::IsolationSetupFailed(
                "no local gitleaks binary found (HUMAUX_TEST_GITLEAKS_BIN unset and no staged \
                 fallback present)"
                    .to_string(),
            ));
        };
        let scanner = LocalSecretScanner::new(LocalSecretScannerConfig {
            executable: gitleaks_bin,
            expected_version: gitleaks_version,
            expected_executable_sha256: gitleaks_sha256,
            timeout: Duration::from_secs(5),
            max_payload_bytes: 64 * 1024,
            finding_exit_code: 1,
        })
        .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(format!("{e}")))?;

        let tenant_id: Uuid = admin
            .query_one(
                "INSERT INTO control.tenants (name) VALUES ($1) RETURNING tenant_id",
                &[&"projection_worker.rs throwaway tenant"],
            )
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?
            .get(0);
        let reasoning_domain_id: Uuid = admin
            .query_one(
                "INSERT INTO control.private_reasoning_domains (tenant_id, name) \
                 VALUES ($1, 'throwaway') RETURNING reasoning_domain_id",
                &[&tenant_id],
            )
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?
            .get(0);

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        let gateway = rt
            // dep: PostgreSQL(role_gateway) — open a role-scoped PG connection/pool for this test
            .block_on(RuntimeDbPool::connect(&dsn_as_role(&dsn, "role_gateway")))
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;

        let (registry, transport, collection) = rt.block_on(setup_qdrant_collection())?;

        Ok(Handle {
            rt,
            admin,
            gateway,
            transport,
            registry,
            collection,
            tenant_id,
            reasoning_domain_id,
            scanner: Arc::new(scanner),
        })
    }
}

/// Local `CardEmbedder` wrapper around [`TestDoubleProvider`] — see
/// `crates/adapters/src/projection_worker.rs`'s `CardEmbedder` doc for why this indirection
/// (not `impl CardEmbedder for TestDoubleProvider` directly) is required: neither type is
/// local to `humaux-adapters`, so only a crate that depends on both (this test crate, via a
/// dev-dependency, exactly like `bins/retrieval-worker`) can bridge them.
struct TestEmbedder(Arc<TestDoubleProvider>);

#[async_trait]
impl CardEmbedder for TestEmbedder {
    async fn embed_cards(
        &self,
        tenant_id: TenantId,
        dimension: u32,
        cards: &[SealedRetrievalCard],
        _memory_ids: &[Uuid],
    ) -> Result<Vec<Vec<f32>>, ErrorCode> {
        Ok(self
            .0
            .embed_cards(tenant_id, dimension, cards)
            .await?
            .vectors)
    }
}

fn embedding_model() -> EmbeddingModelDescriptor {
    EmbeddingModelDescriptor {
        model_id: ModelId("projection-worker-test-embedding".to_owned()),
        model_revision: "embed-v1".to_owned(),
        dimension_options: vec![4],
        max_input_tokens: 4_096,
        max_batch_items: std::num::NonZeroU32::new(10).expect("non-zero cap"),
        batch_supported: true,
        dense_supported: true,
        sparse_supported: false,
    }
}

fn unused_rerank_model() -> RerankModelDescriptor {
    RerankModelDescriptor {
        model_id: ModelId("projection-worker-unused-reranker".to_owned()),
        model_revision: "unused-v1".to_owned(),
        max_documents: 5,
        max_input_tokens: 4_096,
        score_semantics: RerankScoreSemantics::RawLogit,
        calibration_profile: CalibrationProfileId("unused-v1".to_owned()),
    }
}

/// Writes one Evidence+Event (via `remember::remember`, `domain = "private_memory"` — the
/// same convention `outbox_batch_remember.rs`'s own fixture already establishes for this
/// domain) plus a TENANT_SHARED `private.memory_records` row bound to it through
/// `private.memory_evidence`, and returns the `stream_log` row's `stream_seq`.
///
/// `content` carries `title`/`key_claim`/`evidence_excerpt` directly so [`build_card`] always
/// produces a `Complete` card — this fixture is about `run_once`'s own contract, not §18.4's
/// partial-card substitution.
/// A real `control.users` row — `private.memory_records.visibility_user_id` is FK-constrained
/// to it, so `USER_PRIVATE` fixtures can't use a bare `Uuid::new_v4()`.
fn seed_user(handle: &mut Handle) -> Uuid {
    handle
        .admin
        .query_one(
            "INSERT INTO control.users DEFAULT VALUES RETURNING user_id",
            &[],
        )
        .expect("seed throwaway user")
        .get(0)
}

/// A real `control.workspaces` row (this fixture's tenant) — `private.memory_records`'s
/// `visibility_workspace_id` is FK-constrained to it, so `WORKSPACE_SHARED` fixtures can't use a
/// A throwaway `control.users` row with an ACTIVE membership in this fixture's tenant AND an
/// ACTIVE `control.workspace_memberships` row for `workspace_id` — the acting member a
/// `WORKSPACE_SHARED` evidence write needs to satisfy `evidence_objects`' WITH CHECK (ADR-0035,
/// card 13: the WORKSPACE_SHARED arm now EXISTS-checks `control.workspace_memberships` for the
/// row's own workspace, not tenant `control.memberships`).
fn seed_member(handle: &mut Handle, workspace_id: Uuid) -> Uuid {
    let user_id = seed_user(handle);
    handle
        .admin
        .execute(
            "INSERT INTO control.memberships (tenant_id, user_id, role, state) \
             VALUES ($1, $2, 'MEMBER', 'ACTIVE')",
            &[&handle.tenant_id, &user_id],
        )
        .expect("seed ACTIVE membership");
    handle
        .admin
        .execute(
            "INSERT INTO control.workspace_memberships (tenant_id, workspace_id, user_id, role, state) \
             VALUES ($1, $2, $3, 'MEMBER', 'ACTIVE')",
            &[&handle.tenant_id, &workspace_id, &user_id],
        )
        .expect("seed ACTIVE workspace membership");
    user_id
}

/// bare `Uuid::new_v4()`.
fn seed_workspace(handle: &mut Handle) -> Uuid {
    handle
        .admin
        .query_one(
            "INSERT INTO control.workspaces (tenant_id, name) VALUES ($1, 'throwaway') \
             RETURNING workspace_id",
            &[&handle.tenant_id],
        )
        .expect("seed throwaway workspace")
        .get(0)
}

fn seed_memory(handle: &mut Handle, scope_id: Uuid, content: &str) -> i64 {
    seed_memory_with_visibility(handle, scope_id, content, "TENANT_SHARED", None, None).0
}

/// Same as [`seed_memory`] but lets the caller choose the `private.memory_records` row's own
/// `visibility_class`/`visibility_user_id`/`visibility_workspace_id`; the Evidence's own
/// visibility (the `RememberCommand` fields) stays `TENANT_SHARED` here (see
/// [`seed_memory_with_visibility_and_evidence`] for the non-shared case), mirroring
/// `remember::token_workspace_id`'s "stream-routing binding, not Evidence visibility"
/// distinction the module doc's `## Scope` section already draws: the memory row is what §6.1.2
/// gates, not the Evidence that backs it. Returns `(stream_seq, memory_id)` — the latter lets a
/// caller resolve the deterministic Qdrant point id from `projection.private_memory_points`.
fn seed_memory_with_visibility(
    handle: &mut Handle,
    scope_id: Uuid,
    content: &str,
    visibility_class: &str,
    visibility_user_id: Option<Uuid>,
    visibility_workspace_id: Option<Uuid>,
) -> (i64, Uuid) {
    seed_memory_with_visibility_and_evidence(
        handle,
        scope_id,
        content,
        visibility_class,
        visibility_user_id,
        visibility_workspace_id,
        "TENANT_SHARED",
        None,
        None,
    )
}

/// Like [`seed_memory_with_visibility`] but the backing Evidence row gets its own
/// `visibility_*` triple too. `resolve_memories` INNER JOINs `private.evidence_objects`, so a
/// memory whose PRIMARY evidence is `USER_PRIVATE`/`WORKSPACE_SHARED` is only resolvable
/// because migration 0140 widened *both* policies for `role_retrieval_worker` — the earlier
/// fixture always wrote `TENANT_SHARED` evidence and therefore never exercised that half of
/// the join (the production shape `remember.rs` writes verbatim from the request).
#[allow(clippy::too_many_arguments)]
fn seed_memory_with_visibility_and_evidence(
    handle: &mut Handle,
    scope_id: Uuid,
    content: &str,
    visibility_class: &str,
    visibility_user_id: Option<Uuid>,
    visibility_workspace_id: Option<Uuid>,
    evidence_visibility_class: &str,
    evidence_visibility_user_id: Option<Uuid>,
    evidence_visibility_workspace_id: Option<Uuid>,
) -> (i64, Uuid) {
    // §6.1.2 WITH CHECK: writing USER_PRIVATE/WORKSPACE_SHARED evidence needs the acting
    // member in `humaux.user_id` (remember.rs:450 sets it from `authorization_user_id`) — and
    // for WORKSPACE_SHARED that member must hold an ACTIVE membership. The production writer
    // is always a member, so the fixture mirrors that instead of bypassing RLS.
    let acting_user = evidence_visibility_user_id
        .or_else(|| evidence_visibility_workspace_id.map(|ws| seed_member(handle, ws)));
    let cmd = RememberCommand {
        tenant_id: handle.tenant_id,
        authorization_user_id: acting_user,
        scope_kind: "workspace".to_owned(),
        scope_id,
        domain: "private_memory".to_owned(),
        projection_kind: "PRIVATE_MEMORY".to_owned(),
        projection_version: "v1".to_owned(),
        consistency_token_expires_at: time::OffsetDateTime::now_utc()
            + std::time::Duration::from_secs(3600),
        batch_id: None,
        payload_sha256: payload_sha256(content.as_bytes()),
        data_class: "INTERNAL".to_owned(),
        origin_class: EvidenceOriginClass::DirectUserInput,
        origin_principal_id: None,
        origin_connector_id: None,
        visibility_class: evidence_visibility_class.to_owned(),
        visibility_user_id: evidence_visibility_user_id,
        visibility_workspace_id: evidence_visibility_workspace_id,
        reasoning_domain_id: handle.reasoning_domain_id,
        occurred_at: None,
        event_kind: "MANUAL_NOTE".to_owned(),
        event_payload: serde_json::json!({ "content": content }),
        subjects: humaux_domain::subject::SubjectDeclaration::default(),
        affects: Vec::new(),
        mood_half_life: None,
    };
    let accepted = handle
        .rt
        .block_on(remember::remember(&handle.gateway, cmd))
        .expect("remember writes evidence + private_memory stream_log ticket");

    let content_json = serde_json::json!({
        "title": format!("title: {content}"),
        "key_claim": format!("key claim: {content}"),
        "evidence_excerpt": content,
    });
    let mut txn = handle.admin.transaction().expect("admin transaction");
    let memory_id: Uuid = txn
        .query_one(
            "INSERT INTO private.memory_records \
               (tenant_id, memory_type, content, visibility_class, visibility_user_id, \
                visibility_workspace_id, authority_class, confidence, status, asserted_at) \
             VALUES ($1,'NOTE',$2,$3,$4,$5,'PrivateKnowledge',0.9,'active',now()) \
             RETURNING memory_id",
            &[
                &handle.tenant_id,
                &content_json,
                &visibility_class,
                &visibility_user_id,
                &visibility_workspace_id,
            ],
        )
        .expect("insert memory_records row")
        .get(0);
    // dep: PostgreSQL(any) — pool/txn query execution
    txn.execute(
        "INSERT INTO private.memory_evidence (memory_id, evidence_id, role, ordinal) \
         VALUES ($1, $2, 'PRIMARY', 0)",
        &[&memory_id, &accepted.evidence_id],
    )
    .expect("link memory to its evidence");
    txn.commit().expect("commit memory + evidence link");

    let stream_seq: i64 = handle
        .admin
        .query_one(
            "SELECT sl.stream_seq FROM projection.stream_log sl \
             JOIN ops.outbox ob ON ob.tenant_id = sl.tenant_id AND ob.commit_seq = sl.commit_seq \
             WHERE ob.evidence_id = $1",
            &[&accepted.evidence_id],
        )
        .expect("resolve the stream_log row remember() issued")
        .get(0);
    (stream_seq, memory_id)
}

/// Resolves the deterministic Qdrant point id `finish_row` registered for a given `memory_id`,
/// once `run_once` has processed it.
fn point_id_for_memory(handle: &mut Handle, memory_id: Uuid) -> Uuid {
    handle
        .admin
        .query_one(
            "SELECT point_id FROM projection.private_memory_points WHERE memory_id = $1",
            &[&memory_id],
        )
        .expect("registered point for this memory")
        .get(0)
}

/// Raw `POST /collections/{name}/points/scroll` with `with_payload: true` — the only way to
/// read a point's payload back out; [`humaux_adapters::qdrant::scroll_by_ids`] deliberately
/// hardcodes `with_payload: false` (it only proves presence, §17's read-your-write check), so
/// this test goes around the adapter layer to inspect the indexed payload directly, the same
/// way [`setup_qdrant_collection`] talks to the transport directly for collection setup.
fn scroll_payloads(
    handle: &Handle,
    permit: &CellAccessPermit,
    point_ids: &[Uuid],
) -> serde_json::Value {
    let body = serde_json::json!({
        "filter": { "must": [{ "has_id": point_ids.iter().map(ToString::to_string).collect::<Vec<_>>() }] },
        "limit": point_ids.len().max(1),
        "with_payload": true,
        "with_vector": false,
    });
    handle
        .rt
        .block_on(handle.transport.execute(
            permit,
            // dep: Qdrant(*) — Qdrant wire call for this fixture
            IntraCellRequest {
                method: IntraCellMethod::Post,
                path: format!("/collections/{}/points/scroll", handle.collection),
                json_body: Some(body),
                headers: Vec::new(),
            },
        ))
        .expect("scroll with payload succeeds")
        .json_body
        .expect("scroll response has a JSON body")
}

fn stream_log_state(
    handle: &mut Handle,
    key: &(Uuid, &str, Uuid, &str, &str, &str),
    stream_seq: i64,
) -> String {
    handle
        .admin
        .query_one(
            "SELECT state FROM projection.stream_log \
             WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND domain=$4 \
               AND projection_kind=$5 AND projection_version=$6 AND stream_seq=$7",
            &[&key.0, &key.1, &key.2, &key.3, &key.4, &key.5, &stream_seq],
        )
        .expect("stream_log row must exist")
        .get(0)
}

fn stream_log_error_class(
    handle: &mut Handle,
    key: &(Uuid, &str, Uuid, &str, &str, &str),
    stream_seq: i64,
) -> Option<String> {
    handle
        .admin
        .query_one(
            "SELECT error_class FROM projection.stream_log \
             WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND domain=$4 \
               AND projection_kind=$5 AND projection_version=$6 AND stream_seq=$7",
            &[&key.0, &key.1, &key.2, &key.3, &key.4, &key.5, &stream_seq],
        )
        .expect("stream_log row must exist")
        .get(0)
}

fn stream_log_attempts(
    handle: &mut Handle,
    key: &(Uuid, &str, Uuid, &str, &str, &str),
    stream_seq: i64,
) -> i32 {
    handle
        .admin
        .query_one(
            "SELECT attempts FROM projection.stream_log \
             WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND domain=$4 \
               AND projection_kind=$5 AND projection_version=$6 AND stream_seq=$7",
            &[&key.0, &key.1, &key.2, &key.3, &key.4, &key.5, &stream_seq],
        )
        .expect("stream_log row must exist")
        .get(0)
}

/// Exact point count of the fixture's throwaway collection.
fn collection_point_count(handle: &Handle) -> u64 {
    let permit = authorize_cell_access(
        &handle.registry,
        IntraCellResource::QDRANT_REST,
        Duration::from_secs(30),
    )
    .expect("count permit");
    handle
        .rt
        .block_on(handle.transport.execute(
            &permit,
            // dep: Qdrant(*) — Qdrant wire call for this fixture
            IntraCellRequest {
                method: IntraCellMethod::Post,
                path: format!("/collections/{}/points/count", handle.collection),
                json_body: Some(serde_json::json!({ "exact": true })),
                headers: Vec::new(),
            },
        ))
        .expect("count succeeds")
        .json_body
        .and_then(|body| body["result"]["count"].as_u64())
        .expect("count response carries result.count")
}

/// The tenant's §17.3 private-memory placement counters, `(point_count, bytes_estimate)`.
fn placement_counts(handle: &mut Handle) -> (i64, i64) {
    let row = handle
        .admin
        .query_one(
            "SELECT point_count, bytes_estimate FROM projection.tenant_placements \
             WHERE tenant_id = $1 AND projection_family = 'private_memory_v1'",
            &[&handle.tenant_id],
        )
        .expect("the fixture's placement row");
    (row.get(0), row.get(1))
}

/// The registry's own live-binding count — the §17.3 counter's PG-side ground truth.
fn live_binding_count(handle: &mut Handle) -> i64 {
    handle
        .admin
        .query_one(
            "SELECT count(*) FROM projection.private_memory_points \
             WHERE tenant_id = $1 AND projection_live",
            &[&handle.tenant_id],
        )
        .expect("registry count")
        .get(0)
}

fn projection_highwater(handle: &mut Handle, key: &(Uuid, &str, Uuid, &str, &str, &str)) -> i64 {
    handle
        .admin
        .query_one(
            "SELECT projection_highwater FROM projection.stream_checkpoints \
             WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND domain=$4 \
               AND projection_kind=$5 AND projection_version=$6",
            &[&key.0, &key.1, &key.2, &key.3, &key.4, &key.5],
        )
        .expect("checkpoint row must exist")
        .get(0)
}

async fn deps_for(
    handle: &Handle,
    scope_id: Uuid,
    provider: Arc<TestDoubleProvider>,
) -> ProjectionWorkerDeps {
    let retrieval_dsn = std::env::var("HUMAUX_RETRIEVAL_WORKER_PG_DSN")
        .expect("HUMAUX_RETRIEVAL_WORKER_PG_DSN must be set for this test");
    // dep: PostgreSQL(role_retrieval_worker) — open a role-scoped PG connection/pool for this test
    let pool = RetrievalWorkerDbPool::connect(&retrieval_dsn)
        .await
        .expect("role_retrieval_worker connects");
    let permit = authorize_cell_access(
        &handle.registry,
        IntraCellResource::QDRANT_REST,
        Duration::from_secs(30),
    )
    .expect("retrieval worker Qdrant permit");
    ProjectionWorkerDeps {
        pool,
        embedder: Arc::new(TestEmbedder(provider)),
        scanner: handle.scanner.clone(),
        transport: handle.transport.clone(),
        permit,
        placement: TenantPlacementRow {
            tenant_id: TenantId(handle.tenant_id),
            projection_family: RetrievalFamily::PrivateMemoryV1,
            collection_name: handle.collection.clone(),
            shard_key: None,
            placement_class: PlacementClass::SharedFallback,
            point_count: 0,
            bytes_estimate: 0,
            promotion_state: PromotionState::Stable,
        },
        family: StreamFamily::new(
            TenantId(handle.tenant_id),
            "workspace",
            scope_id,
            "private_memory",
            "PRIVATE_MEMORY",
        ),
        embedding_version: "embed-v1".to_owned(),
        projection_version: "v1".to_owned(),
        dimension: 4,
        processor_id: ProcessorId(TEST_PROCESSOR_ID),
    }
}

/// (1): one seeded memory settles `DONE`, lands in Qdrant, registers in
/// `projection.private_memory_points`, and the checkpoint's `projection_highwater` reaches
/// that seq.
#[test]
fn happy_path_indexes_and_advances_checkpoint() {
    run_db_fixture::<Fixture, _>(
        "happy_path_indexes_and_advances_checkpoint",
        |mut handle| {
            let scope_id = Uuid::new_v4();
            let stream_seq = seed_memory(&mut handle, scope_id, "first private memory");
            assert_eq!(stream_seq, 1, "first ticket on a fresh scope is seq 1");

            let provider = Arc::new(TestDoubleProvider::new(
                embedding_model(),
                unused_rerank_model(),
            ));
            let deps = handle.rt.block_on(deps_for(&handle, scope_id, provider));

            let outcome = handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("run_once succeeds");
            assert_eq!(outcome.done, 1);
            assert_eq!(outcome.failed, 0);
            assert_eq!(outcome.skipped_by_policy, 0);
            assert_eq!(outcome.projection_highwater, 1);

            let key = (
                handle.tenant_id,
                "workspace",
                scope_id,
                "private_memory",
                "PRIVATE_MEMORY",
                "v1",
            );
            assert_eq!(stream_log_state(&mut handle, &key, stream_seq), "DONE");
            assert_eq!(projection_highwater(&mut handle, &key), 1);

            let registered: i64 = handle
                .admin
                .query_one(
                    "SELECT count(*) FROM projection.private_memory_points \
                 WHERE tenant_id = $1 AND scope_id = $2",
                    &[&handle.tenant_id, &scope_id],
                )
                .expect("registry query")
                .get(0);
            assert_eq!(registered, 1, "exactly one point registered");
        },
    );
}

/// One raw `POST /collections/{fixture collection}/{tail}`; the reply must be 2xx.
fn qdrant_post(
    handle: &Handle,
    permit: &CellAccessPermit,
    tail: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    let response = handle
        .rt
        .block_on(handle.transport.execute(
            permit,
            // dep: Qdrant(*) — Qdrant wire call for this fixture
            IntraCellRequest {
                method: IntraCellMethod::Post,
                path: format!("/collections/{}/{tail}", handle.collection),
                json_body: Some(body),
                headers: Vec::new(),
            },
        ))
        .expect("Qdrant call succeeds");
    assert!(
        (200..300).contains(&response.status),
        "{tail}: {} {:?}",
        response.status,
        response.json_body
    );
    response.json_body.expect("Qdrant reply has a JSON body")
}

/// T-RET-6b G6b-2 (ADR-0083 D-B, D-A): a memory the worker projects holds a non-empty `bm25` sparse vector next to its
/// dense one, and a `qdrant/bm25` query with the shared `multilingual` options, for a token of its card, returns that
/// point. Real Qdrant v1.19.0 computes the sparse vector from the card text (nothing is sent to a provider for it).
/// Fault: the projector sends no `bm25` ⇒ the retrieved point has no sparse vector ⇒ red; its options differ from the
/// query's ⇒ the pin test `bm25_document_options_are_pinned_byte_for_byte` (qdrant.rs) is the red.
#[test]
fn a_projected_point_holds_a_bm25_vector_its_card_text_can_be_queried_by() {
    run_db_fixture::<Fixture, _>(
        "a_projected_point_holds_a_bm25_vector_its_card_text_can_be_queried_by",
        |mut handle| {
            let scope_id = Uuid::new_v4();
            let (_, memory_id) = seed_memory_with_visibility(
                &mut handle,
                scope_id,
                "zorblax lexical needle",
                "TENANT_SHARED",
                None,
                None,
            );
            let provider = Arc::new(TestDoubleProvider::new(
                embedding_model(),
                unused_rerank_model(),
            ));
            let deps = handle.rt.block_on(deps_for(&handle, scope_id, provider));
            let outcome = handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("run_once succeeds");
            assert_eq!(outcome.done, 1);
            let point = point_id_for_memory(&mut handle, memory_id);
            let permit = admin_permit(&handle);

            let retrieved = qdrant_post(
                &handle,
                &permit,
                "points",
                serde_json::json!({
                    "ids": [point.to_string()],
                    "with_payload": false,
                    "with_vector": ["bm25"],
                }),
            );
            let sparse = &retrieved["result"][0]["vector"]["bm25"];
            let indices = sparse["indices"].as_array().map(Vec::len).unwrap_or(0);
            assert!(
                indices > 0,
                "the point holds a non-empty bm25 vector: {retrieved}"
            );
            assert_eq!(
                sparse["values"].as_array().map(Vec::len),
                Some(indices),
                "{retrieved}"
            );

            let found = qdrant_post(
                &handle,
                &permit,
                "points/query",
                serde_json::json!({
                    "query": {
                        "text": "zorblax",
                        "model": "qdrant/bm25",
                        "options": { "tokenizer": "multilingual" },
                    },
                    "using": "bm25",
                    "limit": 5,
                    "with_payload": false,
                }),
            );
            let ids: Vec<&str> = found["result"]["points"]
                .as_array()
                .map(|points| points.iter().filter_map(|p| p["id"].as_str()).collect())
                .unwrap_or_default();
            assert!(
                ids.contains(&point.to_string().as_str()),
                "a token of the card finds the point by bm25: {found}"
            );
        },
    );
}

/// (2): a second `run_once` against the same key, after the first has already settled every
/// row `DONE`, is a no-op (idempotent — nothing left `ISSUED`, `advance_prefix` reports the
/// same highwater unchanged).
#[test]
fn second_run_once_is_idempotent() {
    run_db_fixture::<Fixture, _>("second_run_once_is_idempotent", |mut handle| {
        let scope_id = Uuid::new_v4();
        seed_memory(&mut handle, scope_id, "idempotency fixture memory");

        let provider = Arc::new(TestDoubleProvider::new(
            embedding_model(),
            unused_rerank_model(),
        ));
        let deps = handle.rt.block_on(deps_for(&handle, scope_id, provider));

        let first = handle
            .rt
            .block_on(run_once(&deps, 10))
            .expect("first run_once succeeds");
        assert_eq!(first.done, 1);
        assert_eq!(first.projection_highwater, 1);

        let second = handle
            .rt
            .block_on(run_once(&deps, 10))
            .expect("second run_once succeeds");
        assert_eq!(second.done, 0);
        assert_eq!(second.failed, 0);
        assert_eq!(second.skipped_by_policy, 0);
        assert_eq!(second.projection_highwater, 1);
    });
}

/// F3 fixture: a [`CardEmbedder`] that always returns a vector one element longer than whatever
/// `dimension` it is asked for, ignoring the request — unlike [`TestDoubleProvider`], which
/// always honors the requested dimension and so can never exercise `resolve_and_embed`'s
/// post-embed length check. Proves that check is load-bearing: without it, this vector would
/// reach `qdrant::upsert` unchecked (task card F3).
struct WrongDimEmbedder;

#[async_trait]
impl CardEmbedder for WrongDimEmbedder {
    async fn embed_cards(
        &self,
        _tenant_id: TenantId,
        dimension: u32,
        cards: &[SealedRetrievalCard],
        _memory_ids: &[Uuid],
    ) -> Result<Vec<Vec<f32>>, ErrorCode> {
        Ok(cards
            .iter()
            .map(|_| vec![0.0_f32; dimension as usize + 1])
            .collect())
    }
}

/// F1 fixture: wraps a real [`IntraCellHttpTransport`] and forces every `/points/scroll` call
/// (the wire shape [`humaux_adapters::qdrant::scroll_by_ids`]/`verify_visible_via_transport`
/// issues) to report zero observed points, while forwarding every other call (the upsert PUT
/// included) unchanged to the real transport. The point genuinely lands in the real Qdrant
/// collection; only the worker's own visibility read is stubbed to "not visible yet" — proving
/// `finish_row` actually branches on `verify_visible_via_transport`'s result instead of always
/// settling `Done` after a successful upsert (task card F1).
struct ScrollStubTransport {
    inner: Arc<HttpIntraCellTransport>,
}

#[async_trait]
impl IntraCellHttpTransport for ScrollStubTransport {
    async fn execute(
        &self,
        permit: &CellAccessPermit,
        request: IntraCellRequest,
    ) -> Result<IntraCellResponse, IntraCellError> {
        if request.path.ends_with("/points/scroll") {
            return Ok(IntraCellResponse {
                status: 200,
                json_body: Some(serde_json::json!({ "result": { "points": [] } })),
            });
        }
        self.inner.execute(permit, request).await
    }
}

/// (4): the embedder returns a vector whose length disagrees with `deps.dimension` — must settle
/// `FAILED` with `error_class = 'embedding_dimension_mismatch'` before ever reaching Qdrant (no
/// registry row, checkpoint held at 0). Regression test for F3.
#[test]
fn dimension_mismatch_fails_before_reaching_qdrant() {
    run_db_fixture::<Fixture, _>(
        "dimension_mismatch_fails_before_reaching_qdrant",
        |mut handle| {
            let scope_id = Uuid::new_v4();
            let stream_seq = seed_memory(&mut handle, scope_id, "wrong dimension vector");

            let retrieval_dsn = std::env::var("HUMAUX_RETRIEVAL_WORKER_PG_DSN")
                .expect("HUMAUX_RETRIEVAL_WORKER_PG_DSN must be set for this test");
            let pool = handle
                .rt
                // dep: PostgreSQL(role_retrieval_worker) — open a role-scoped PG connection/pool for this test
                .block_on(RetrievalWorkerDbPool::connect(&retrieval_dsn))
                .expect("role_retrieval_worker connects");
            let permit = authorize_cell_access(
                &handle.registry,
                IntraCellResource::QDRANT_REST,
                Duration::from_secs(30),
            )
            .expect("retrieval worker Qdrant permit");
            let deps = ProjectionWorkerDeps {
                pool,
                embedder: Arc::new(WrongDimEmbedder),
                scanner: handle.scanner.clone(),
                transport: handle.transport.clone(),
                permit,
                placement: TenantPlacementRow {
                    tenant_id: TenantId(handle.tenant_id),
                    projection_family: RetrievalFamily::PrivateMemoryV1,
                    collection_name: handle.collection.clone(),
                    shard_key: None,
                    placement_class: PlacementClass::SharedFallback,
                    point_count: 0,
                    bytes_estimate: 0,
                    promotion_state: PromotionState::Stable,
                },
                family: StreamFamily::new(
                    TenantId(handle.tenant_id),
                    "workspace",
                    scope_id,
                    "private_memory",
                    "PRIVATE_MEMORY",
                ),
                embedding_version: "embed-v1".to_owned(),
                projection_version: "v1".to_owned(),
                dimension: 4,
                processor_id: ProcessorId(TEST_PROCESSOR_ID),
            };

            let outcome = handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("run_once succeeds even with a per-row embedding failure");
            assert_eq!(outcome.failed, 1);
            assert_eq!(outcome.done, 0);
            assert_eq!(outcome.projection_highwater, 0);

            let key = (
                handle.tenant_id,
                "workspace",
                scope_id,
                "private_memory",
                "PRIVATE_MEMORY",
                "v1",
            );
            assert_eq!(stream_log_state(&mut handle, &key, stream_seq), "FAILED");
            assert_eq!(
                stream_log_error_class(&mut handle, &key, stream_seq),
                Some("embedding_dimension_mismatch".to_owned())
            );

            let registered: i64 = handle
                .admin
                .query_one(
                    "SELECT count(*) FROM projection.private_memory_points \
                 WHERE tenant_id = $1 AND scope_id = $2",
                    &[&handle.tenant_id, &scope_id],
                )
                .expect("registry query")
                .get(0);
            assert_eq!(
                registered, 0,
                "a wrong-dimension vector must never reach qdrant::upsert/registration"
            );

            // ADR-0049 D-C, the failed half: a MEMORY_LIFECYCLE ticket that settles FAILED
            // leaves its carrier outbox row FAILED, not DONE (card 24 review P1 — a failed
            // lifecycle projection must not read as drained work).
            let memory_id: Uuid = handle
                .admin
                .query_one(
                    "SELECT memory_id FROM private.memory_records WHERE tenant_id = $1",
                    &[&handle.tenant_id],
                )
                .expect("the one seeded memory")
                .get(0);
            let ticket = reissue_lifecycle_ticket(&mut handle, scope_id, memory_id);
            let outcome = handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("second run_once succeeds");
            assert_eq!(outcome.failed, 1, "{outcome:?}");
            assert_eq!(stream_log_state(&mut handle, &key, ticket), "FAILED");
            assert_eq!(
                outbox_status(&mut handle, ticket),
                "FAILED",
                "the carrier mirrors the ticket's terminal"
            );
        },
    );
}

/// (5): the visibility probe reports the point as not (yet) observed after a successful upsert —
/// ADR-0052 D-E: that is a retry, not a verdict. The row stays `ISSUED` with one attempt spent
/// and `error_class = 'visibility_not_confirmed'`, and the checkpoint does not cross it, proving
/// `finish_row` actually awaits/branches on `verify_visible_via_transport`'s result rather than
/// unconditionally marking `Done` once the upsert call itself succeeds (F1). Before card 27 this
/// settled `FAILED` for good (audit C4).
#[test]
fn unconfirmed_visibility_retries_row_and_blocks_checkpoint() {
    run_db_fixture::<Fixture, _>(
        "unconfirmed_visibility_retries_row_and_blocks_checkpoint",
        |mut handle| {
            let scope_id = Uuid::new_v4();
            let stream_seq = seed_memory(&mut handle, scope_id, "never visible memory");

            let provider = Arc::new(TestDoubleProvider::new(
                embedding_model(),
                unused_rerank_model(),
            ));
            let retrieval_dsn = std::env::var("HUMAUX_RETRIEVAL_WORKER_PG_DSN")
                .expect("HUMAUX_RETRIEVAL_WORKER_PG_DSN must be set for this test");
            let pool = handle
                .rt
                // dep: PostgreSQL(role_retrieval_worker) — open a role-scoped PG connection/pool for this test
                .block_on(RetrievalWorkerDbPool::connect(&retrieval_dsn))
                .expect("role_retrieval_worker connects");
            let permit = authorize_cell_access(
                &handle.registry,
                IntraCellResource::QDRANT_REST,
                Duration::from_secs(30),
            )
            .expect("retrieval worker Qdrant permit");
            let stub_transport = Arc::new(ScrollStubTransport {
                inner: handle.transport.clone(),
            });
            let deps = ProjectionWorkerDeps {
                pool,
                embedder: Arc::new(TestEmbedder(provider)),
                scanner: handle.scanner.clone(),
                transport: stub_transport,
                permit,
                placement: TenantPlacementRow {
                    tenant_id: TenantId(handle.tenant_id),
                    projection_family: RetrievalFamily::PrivateMemoryV1,
                    collection_name: handle.collection.clone(),
                    shard_key: None,
                    placement_class: PlacementClass::SharedFallback,
                    point_count: 0,
                    bytes_estimate: 0,
                    promotion_state: PromotionState::Stable,
                },
                family: StreamFamily::new(
                    TenantId(handle.tenant_id),
                    "workspace",
                    scope_id,
                    "private_memory",
                    "PRIVATE_MEMORY",
                ),
                embedding_version: "embed-v1".to_owned(),
                projection_version: "v1".to_owned(),
                dimension: 4,
                processor_id: ProcessorId(TEST_PROCESSOR_ID),
            };

            let outcome = handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("run_once succeeds even with an unconfirmed visibility probe");
            assert_eq!(outcome.retried, 1, "{outcome:?}");
            assert_eq!(outcome.failed, 0);
            assert_eq!(outcome.done, 0);
            assert_eq!(
                outcome.projection_highwater, 0,
                "an unconfirmed-visibility row must never let the checkpoint cross it"
            );

            let key = (
                handle.tenant_id,
                "workspace",
                scope_id,
                "private_memory",
                "PRIVATE_MEMORY",
                "v1",
            );
            assert_eq!(stream_log_state(&mut handle, &key, stream_seq), "ISSUED");
            assert_eq!(stream_log_attempts(&mut handle, &key, stream_seq), 1);
            assert_eq!(
                stream_log_error_class(&mut handle, &key, stream_seq),
                Some("visibility_not_confirmed".to_owned())
            );
        },
    );
}

/// ADR-0052 D-E fixture: an embedder whose vectors are exactly as wide as the worker asks for —
/// so the worker's own dimension check passes and the width reaches Qdrant, whose 4-d fixture
/// collection refuses an 8-d point with HTTP 400.
struct WideEmbedder;

#[async_trait]
impl CardEmbedder for WideEmbedder {
    async fn embed_cards(
        &self,
        _tenant_id: TenantId,
        dimension: u32,
        cards: &[SealedRetrievalCard],
        _memory_ids: &[Uuid],
    ) -> Result<Vec<Vec<f32>>, ErrorCode> {
        Ok(cards
            .iter()
            .map(|_| vec![0.25_f32; dimension as usize])
            .collect())
    }
}

/// ADR-0052 D-E: a permanent Qdrant refusal (HTTP 400, here a vector-width mismatch between the
/// worker's configured dimension and the collection's) settles the ticket `FAILED`
/// `qdrant_upsert_rejected` on the FIRST attempt — no retry budget spent on a request that can
/// never succeed — and leaves no point and no registry row. Fault injection: classify 400 as
/// transient in `QdrantTransportError::is_transient` ⇒ the row stays `ISSUED` and this is red.
#[test]
fn permanent_qdrant_400_fails_immediately_and_leaves_no_point() {
    run_db_fixture::<Fixture, _>(
        "permanent_qdrant_400_fails_immediately_and_leaves_no_point",
        |mut handle| {
            let scope_id = Uuid::new_v4();
            let stream_seq = seed_memory(&mut handle, scope_id, "eight wide vector");
            let provider = Arc::new(TestDoubleProvider::new(
                embedding_model(),
                unused_rerank_model(),
            ));
            let mut deps = handle.rt.block_on(deps_for(&handle, scope_id, provider));
            deps.embedder = Arc::new(WideEmbedder);
            deps.dimension = 8;

            let outcome = handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("run_once succeeds with a per-row Qdrant refusal");
            assert_eq!((outcome.failed, outcome.retried, outcome.done), (1, 0, 0));
            let key = (
                handle.tenant_id,
                "workspace",
                scope_id,
                "private_memory",
                "PRIVATE_MEMORY",
                "v1",
            );
            assert_eq!(stream_log_state(&mut handle, &key, stream_seq), "FAILED");
            assert_eq!(
                stream_log_error_class(&mut handle, &key, stream_seq),
                Some("qdrant_upsert_rejected".to_owned())
            );
            assert_eq!(stream_log_attempts(&mut handle, &key, stream_seq), 0);
            let registered: i64 = handle
                .admin
                .query_one(
                    "SELECT count(*) FROM projection.private_memory_points WHERE tenant_id = $1",
                    &[&handle.tenant_id],
                )
                .expect("registry query")
                .get(0);
            assert_eq!(registered, 0, "a refused upsert registers nothing");
            assert_eq!(collection_point_count(&handle), 0, "and leaves no point");
        },
    );
}

/// Card 30b (ADR-0056 D-A): memories whose card text carries a date, an e-mail address, a phone
/// number, a 12-digit order number and a random UUID are ordinary private cards on the §7.5 B
/// seal — all five project `DONE`, none settles `secret_scan_rejected`. Fault: the
/// contribution-privacy rules back on `seal_card` ⇒ five FAILED ⇒ red.
#[test]
fn cards_with_date_email_phone_number_and_uuid_project_done() {
    run_db_fixture::<Fixture, _>(
        "cards_with_date_email_phone_number_and_uuid_project_done",
        |mut handle| {
            let scope_id = Uuid::new_v4();
            let seqs: Vec<i64> = [
                "the billing cutover is on 2026-10-15",
                "write to a@example.test about the invoice",
                "call +1 (415) 555-0123 for the on-call rota",
                "order 123456789012 shipped late",
                "incident 3f0c9a4e-1b7d-4c55-9e21-79869668a78d is closed",
            ]
            .into_iter()
            .map(|content| seed_memory(&mut handle, scope_id, content))
            .collect();
            let provider = Arc::new(TestDoubleProvider::new(
                embedding_model(),
                unused_rerank_model(),
            ));
            let deps = handle.rt.block_on(deps_for(&handle, scope_id, provider));
            let outcome = handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("run_once succeeds");
            assert_eq!((outcome.done, outcome.failed, outcome.retried), (5, 0, 0));
            let key = (
                handle.tenant_id,
                "workspace",
                scope_id,
                "private_memory",
                "PRIVATE_MEMORY",
                "v1",
            );
            for seq in seqs {
                assert_eq!(stream_log_state(&mut handle, &key, seq), "DONE");
                assert_eq!(stream_log_error_class(&mut handle, &key, seq), None);
            }
            assert_eq!(collection_point_count(&handle), 5);
        },
    );
}

/// ADR-0052 D-E, unchanged by ADR-0056: a card carrying a real gitleaks finding (the fake
/// GitHub-shaped vector of `contribution_scan.rs`) is a verdict on the card — `FAILED
/// secret_scan_rejected`, no retry, no point. Fault: gitleaks removed from the seal path ⇒ DONE
/// ⇒ red.
#[test]
fn a_card_with_a_real_gitleaks_finding_settles_failed_secret_scan_rejected() {
    run_db_fixture::<Fixture, _>(
        "a_card_with_a_real_gitleaks_finding_settles_failed_secret_scan_rejected",
        |mut handle| {
            let scope_id = Uuid::new_v4();
            let seq = seed_memory(
                &mut handle,
                scope_id,
                "the CI bot uses ghp_RkqFzVpLwNyHtBvDgXsWuCePjMoTnAiSyEkl for releases",
            );
            let provider = Arc::new(TestDoubleProvider::new(
                embedding_model(),
                unused_rerank_model(),
            ));
            let deps = handle.rt.block_on(deps_for(&handle, scope_id, provider));
            let outcome = handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("run_once succeeds with a per-row refusal");
            assert_eq!((outcome.failed, outcome.retried, outcome.done), (1, 0, 0));
            let key = (
                handle.tenant_id,
                "workspace",
                scope_id,
                "private_memory",
                "PRIVATE_MEMORY",
                "v1",
            );
            assert_eq!(stream_log_state(&mut handle, &key, seq), "FAILED");
            assert_eq!(
                stream_log_error_class(&mut handle, &key, seq),
                Some("secret_scan_rejected".to_owned())
            );
            assert_eq!(collection_point_count(&handle), 0, "not projected");
        },
    );
}

/// ADR-0052 D-E (b) fixture: forwards everything to the real transport, and right after the
/// upsert PUT lands it moves the memory's `updated_at` — so the registration that follows sees
/// the source changed (`SourceChanged`, D-A's race in miniature) and refuses to bind the point
/// the upsert just wrote.
struct SourceChangesAfterUpsert {
    inner: Arc<HttpIntraCellTransport>,
    admin_dsn: String,
    memory_id: std::sync::Mutex<Option<Uuid>>,
}

#[async_trait]
impl IntraCellHttpTransport for SourceChangesAfterUpsert {
    async fn execute(
        &self,
        permit: &CellAccessPermit,
        request: IntraCellRequest,
    ) -> Result<IntraCellResponse, IntraCellError> {
        let is_upsert = matches!(request.method, IntraCellMethod::Put)
            && request.path.contains("/points")
            && !request.path.contains("/points/");
        let response = self.inner.execute(permit, request).await?;
        let memory_id = *self.memory_id.lock().expect("fixture mutex");
        if let (true, Some(memory_id)) = (is_upsert, memory_id) {
            // A fresh OS thread: the sync client runs its own runtime, which it may not do on
            // this async task's thread.
            let dsn = self.admin_dsn.clone();
            std::thread::spawn(move || {
                // dep: PostgreSQL(any) — the fixture's owner client moves the source mid-row
                let mut admin = Client::connect(&dsn, NoTls).expect("owner connects");
                admin
                    .execute(
                        "UPDATE private.memory_records \
                         SET updated_at = updated_at + interval '1 second' WHERE memory_id = $1",
                        &[&memory_id],
                    )
                    .expect("move the source");
            })
            .join()
            .expect("owner thread");
        }
        Ok(response)
    }
}

/// ADR-0052 D-E (b): when the upsert landed but the registry refused the binding, `finish_row`
/// deletes the point it just wrote — otherwise that point is live in Qdrant and bound to nothing,
/// so no later retirement could ever find it. The refusal here (`SourceChanged`) is transient, so
/// the ticket is retried (ISSUED, attempts 1, `registry_failed`). Fault injection: delete the
/// compensating `delete_points` call ⇒ the collection keeps one orphan point and this is red.
#[test]
fn upsert_then_registry_refusal_deletes_the_orphan_point() {
    run_db_fixture::<Fixture, _>(
        "upsert_then_registry_refusal_deletes_the_orphan_point",
        |mut handle| {
            let scope_id = Uuid::new_v4();
            let (stream_seq, memory_id) = seed_memory_with_visibility(
                &mut handle,
                scope_id,
                "source moves after upsert",
                "TENANT_SHARED",
                None,
                None,
            );
            let admin_dsn = std::env::var("HUMAUX_TEST_PG_DSN").expect("fixture DSN");
            let provider = Arc::new(TestDoubleProvider::new(
                embedding_model(),
                unused_rerank_model(),
            ));
            let mut deps = handle.rt.block_on(deps_for(&handle, scope_id, provider));
            deps.transport = Arc::new(SourceChangesAfterUpsert {
                inner: handle.transport.clone(),
                admin_dsn,
                memory_id: std::sync::Mutex::new(Some(memory_id)),
            });

            let outcome = handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("run_once succeeds with a refused registration");
            assert_eq!((outcome.retried, outcome.failed, outcome.done), (1, 0, 0));
            let key = (
                handle.tenant_id,
                "workspace",
                scope_id,
                "private_memory",
                "PRIVATE_MEMORY",
                "v1",
            );
            assert_eq!(stream_log_state(&mut handle, &key, stream_seq), "ISSUED");
            assert_eq!(stream_log_attempts(&mut handle, &key, stream_seq), 1);
            assert_eq!(
                stream_log_error_class(&mut handle, &key, stream_seq),
                Some("registry_failed".to_owned())
            );
            assert_eq!(
                collection_point_count(&handle),
                0,
                "the point the refused registration would have bound is deleted"
            );
        },
    );
}

/// (3): a batch of two rows (seq 1, seq 2) where the embedder is forced to fail on the first
/// call — since `run_once` processes ascending `stream_seq`, that is seq 1. §15.7: seq 1
/// settles `FAILED`, seq 2 may settle `DONE`, but `projection_highwater` must stay at 0 (the
/// prefix before the first gap), never cross the `FAILED` row. The forced error is a PERMANENT
/// one (`ProviderPermanent`): since ADR-0052 a transient provider error is a retry and the row
/// would stay `ISSUED` (which blocks the prefix just the same, but is not what this test pins).
#[test]
fn failed_row_blocks_checkpoint_past_it() {
    run_db_fixture::<Fixture, _>("failed_row_blocks_checkpoint_past_it", |mut handle| {
        let scope_id = Uuid::new_v4();
        let seq1 = seed_memory(&mut handle, scope_id, "row that will fail to embed");
        let seq2 = seed_memory(&mut handle, scope_id, "row after the failure");
        assert_eq!((seq1, seq2), (1, 2));

        let provider = Arc::new(TestDoubleProvider::new(
            embedding_model(),
            unused_rerank_model(),
        ));
        provider.force_next_error(ErrorCode::ProviderPermanent);
        let deps = handle.rt.block_on(deps_for(&handle, scope_id, provider));

        let outcome = handle
            .rt
            .block_on(run_once(&deps, 10))
            .expect("run_once succeeds even with a per-row embedding failure");
        assert_eq!(outcome.failed, 1);
        assert_eq!(outcome.done, 1);
        assert_eq!(
            outcome.projection_highwater, 0,
            "§15.7: FAILED seq 1 blocks the prefix"
        );

        let key = (
            handle.tenant_id,
            "workspace",
            scope_id,
            "private_memory",
            "PRIVATE_MEMORY",
            "v1",
        );
        assert_eq!(stream_log_state(&mut handle, &key, seq1), "FAILED");
        assert_eq!(
            stream_log_error_class(&mut handle, &key, seq1),
            Some("embedding_rejected".to_owned())
        );
        assert_eq!(stream_log_state(&mut handle, &key, seq2), "DONE");
        assert_eq!(
            projection_highwater(&mut handle, &key),
            0,
            "checkpoint must not have advanced past the FAILED row"
        );
    });
}

/// (T4): 0140's `role_retrieval_worker` RLS read bypass — before it existed, a
/// `USER_PRIVATE`/`WORKSPACE_SHARED` row's stream_log entry could never resolve under this
/// worker's tenant-only session and settled `FAILED` forever (module doc's old "RLS and
/// visibility" note). A batch mixing a `USER_PRIVATE` row (owned by user A) and a
/// `WORKSPACE_SHARED` row in the same stream both settle `DONE`, both land in Qdrant with their
/// real `visibility_user_id`/`visibility_workspace_id` payload fields populated (real
/// enforcement stays downstream at query time, §6.1.2 — see T5), and the checkpoint reaches the
/// batch's last seq.
#[test]
fn mixed_visibility_batch_indexes_both_and_populates_payload() {
    run_db_fixture::<Fixture, _>(
        "mixed_visibility_batch_indexes_both_and_populates_payload",
        |mut handle| {
            let scope_id = Uuid::new_v4();
            let user_a = seed_user(&mut handle);
            let workspace_w = seed_workspace(&mut handle);
            let (seq1, private_memory_id) = seed_memory_with_visibility(
                &mut handle,
                scope_id,
                "user A's private memory",
                "USER_PRIVATE",
                Some(user_a),
                None,
            );
            let (seq2, shared_memory_id) = seed_memory_with_visibility(
                &mut handle,
                scope_id,
                "workspace shared memory",
                "WORKSPACE_SHARED",
                None,
                Some(workspace_w),
            );
            assert_eq!((seq1, seq2), (1, 2));

            let provider = Arc::new(TestDoubleProvider::new(
                embedding_model(),
                unused_rerank_model(),
            ));
            let deps = handle.rt.block_on(deps_for(&handle, scope_id, provider));

            let outcome = handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("run_once succeeds");
            let key = (
                handle.tenant_id,
                "workspace",
                scope_id,
                "private_memory",
                "PRIVATE_MEMORY",
                "v1",
            );
            assert_eq!(outcome.done, 2);
            assert_eq!(outcome.failed, 0);
            assert_eq!(outcome.skipped_by_policy, 0);
            assert_eq!(outcome.projection_highwater, 2);

            assert_eq!(stream_log_state(&mut handle, &key, seq1), "DONE");
            assert_eq!(stream_log_state(&mut handle, &key, seq2), "DONE");

            let registered: i64 = handle
                .admin
                .query_one(
                    "SELECT count(*) FROM projection.private_memory_points \
                     WHERE tenant_id = $1 AND scope_id = $2",
                    &[&handle.tenant_id, &scope_id],
                )
                .expect("registry query")
                .get(0);
            assert_eq!(
                registered, 2,
                "both rows registered despite mixed visibility"
            );

            let private_point = point_id_for_memory(&mut handle, private_memory_id);
            let shared_point = point_id_for_memory(&mut handle, shared_memory_id);
            let permit = authorize_cell_access(
                &handle.registry,
                IntraCellResource::QDRANT_REST,
                Duration::from_secs(30),
            )
            .expect("admin Qdrant permit");
            let scrolled = scroll_payloads(&handle, &permit, &[private_point, shared_point]);
            assert_mixed_visibility_payloads(
                &scrolled,
                private_point,
                user_a,
                shared_point,
                workspace_w,
            );
        },
    );
}

/// Asserts T4's scroll result contains exactly the `USER_PRIVATE` point (with its
/// `visibility_user_id`) and the `WORKSPACE_SHARED` point (with its `visibility_workspace_id`)
/// — split out of the test body purely to stay under this repo's line-count lint.
fn assert_mixed_visibility_payloads(
    scrolled: &serde_json::Value,
    private_point: Uuid,
    user_a: Uuid,
    shared_point: Uuid,
    workspace_w: Uuid,
) {
    let points = scrolled
        .get("result")
        .and_then(|r| r.get("points"))
        .and_then(|p| p.as_array())
        .expect("scroll result.points");
    assert_eq!(points.len(), 2, "both points present in Qdrant");
    for point in points {
        let payload = point.get("payload").expect("point has a payload");
        let id = point.get("id").and_then(|v| v.as_str()).unwrap_or_default();
        if id == private_point.to_string() {
            assert_eq!(
                payload.get("visibility_class").and_then(|v| v.as_str()),
                Some("USER_PRIVATE")
            );
            assert_eq!(
                payload.get("visibility_user_id").and_then(|v| v.as_str()),
                Some(user_a.to_string()).as_deref()
            );
        } else if id == shared_point.to_string() {
            assert_eq!(
                payload.get("visibility_class").and_then(|v| v.as_str()),
                Some("WORKSPACE_SHARED")
            );
            assert_eq!(
                payload
                    .get("visibility_workspace_id")
                    .and_then(|v| v.as_str()),
                Some(workspace_w.to_string()).as_deref()
            );
        } else {
            panic!("unexpected point id {id} in scroll result");
        }
    }
}

/// Builds a limit-10, `ReadYourWriteStrict` `DenseQuery` scoped to `user_id` (no workspace
/// grants), against `v1`/`embed-v1`, with a fixed finite non-zero probe vector — the caller only
/// ever asserts result-set membership, never ranking/score, so the exact vector value is
/// unimportant as long as it is valid.
fn dense_query_for_user(
    handle: &Handle,
    placement: &TenantPlacementRow,
    user_id: Uuid,
) -> DenseQuery {
    let scope = AuthorizationScope::new(
        TenantId(handle.tenant_id),
        PrincipalId(Uuid::new_v4()),
        Some(UserId(user_id)),
        BoundedSet::new([]).expect("empty workspace set is always within MAX_LEN"),
    );
    DenseQuery::new(
        &scope,
        placement,
        DenseQueryVersions {
            projection: "v1",
            embedding: "embed-v1",
        },
        vec![1.0_f32, 0.0, 0.0, 0.0],
        10,
        Vec::new(),
        ha_profile_for(QdrantOperation::ReadYourWriteStrict),
    )
    .expect("valid dense query")
}

/// (T5): §6.1.2's real visibility boundary — enforced downstream at Qdrant query time via
/// `projection::dense::visibility_disjunction`, not by 0140's RLS read bypass (that bypass only
/// lets the worker *index* the row; it grants no reader anything). Reuses T4's indexed points:
/// a `DenseQuery` built for user B (a different user of the same tenant, no membership in
/// `workspace_w`) returns 0 hits for the `USER_PRIVATE` point owned by user A, while the same
/// query built for user A does return it — proving the RLS widening in 0140 did not leak
/// `USER_PRIVATE` visibility to an unrelated query-time reader.
#[test]
fn cross_user_dense_query_still_enforces_user_private_visibility() {
    run_db_fixture::<Fixture, _>(
        "cross_user_dense_query_still_enforces_user_private_visibility",
        |mut handle| {
            let scope_id = Uuid::new_v4();
            let user_a = seed_user(&mut handle);
            let user_b = seed_user(&mut handle);
            let (_, private_memory_id) = seed_memory_with_visibility(
                &mut handle,
                scope_id,
                "user A's private memory for cross-user check",
                "USER_PRIVATE",
                Some(user_a),
                None,
            );

            let provider = Arc::new(TestDoubleProvider::new(
                embedding_model(),
                unused_rerank_model(),
            ));
            let deps = handle.rt.block_on(deps_for(&handle, scope_id, provider));
            let outcome = handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("run_once succeeds");
            assert_eq!(outcome.done, 1);

            let private_point = point_id_for_memory(&mut handle, private_memory_id);
            let placement = TenantPlacementRow {
                tenant_id: TenantId(handle.tenant_id),
                projection_family: RetrievalFamily::PrivateMemoryV1,
                collection_name: handle.collection.clone(),
                shard_key: None,
                placement_class: PlacementClass::SharedFallback,
                point_count: 1,
                bytes_estimate: 0,
                promotion_state: PromotionState::Stable,
            };
            let permit = handle
                .rt
                .block_on(async {
                    authorize_cell_access(
                        &handle.registry,
                        IntraCellResource::QDRANT_REST,
                        Duration::from_secs(30),
                    )
                })
                .expect("query permit");
            let query_as_a = dense_query_for_user(&handle, &placement, user_a);
            let query_as_b = dense_query_for_user(&handle, &placement, user_b);

            // Real Qdrant upsert-then-search has read-after-write lag under Weak ordering, so
            // poll like `private_projection_registry.rs`'s own `query_private_qdrant_points`
            // does, rather than asserting on the very first attempt.
            let hits_as_a: Vec<DenseCandidate> = handle.rt.block_on(async {
                for _ in 0..20 {
                    let candidates = query_dense(handle.transport.as_ref(), &permit, &query_as_a)
                        .await
                        .expect("dense query as user A succeeds");
                    if !candidates.is_empty() {
                        return candidates;
                    }
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Vec::new()
            });
            assert_eq!(
                hits_as_a.len(),
                1,
                "user A's own USER_PRIVATE memory is visible to user A"
            );
            assert_eq!(hits_as_a[0].point_id, PointId::Uuid(private_point));

            let hits_as_b = handle
                .rt
                .block_on(query_dense(handle.transport.as_ref(), &permit, &query_as_b))
                .expect("dense query as user B succeeds");
            assert!(
                hits_as_b.is_empty(),
                "0140's RLS read bypass must not leak USER_PRIVATE visibility to user B's \
                 query-time dense read: got {hits_as_b:?}"
            );
        },
    );
}

/// 0140 must widen the evidence half of `resolve_memories`' INNER JOIN too: a memory whose
/// PRIMARY evidence is `USER_PRIVATE`/`WORKSPACE_SHARED` (the shape `remember.rs` writes when
/// the request says so) has to index and advance the checkpoint, not settle FAILED and freeze
/// the tenant under §15.7. Fault F-evidence: drop the role clause from
/// `evidence_objects_tenant_and_visibility` ⇒ this test goes red (rows FAILED, highwater 0).
#[test]
fn non_tenant_shared_evidence_still_resolves_and_advances_checkpoint() {
    run_db_fixture::<Fixture, _>(
        "non_tenant_shared_evidence_still_resolves_and_advances_checkpoint",
        |mut handle| {
            let scope_id = Uuid::new_v4();
            let user_a = seed_user(&mut handle);
            let workspace_w = seed_workspace(&mut handle);
            let (seq1, _) = seed_memory_with_visibility_and_evidence(
                &mut handle,
                scope_id,
                "private memory backed by private evidence",
                "USER_PRIVATE",
                Some(user_a),
                None,
                "USER_PRIVATE",
                Some(user_a),
                None,
            );
            let (seq2, _) = seed_memory_with_visibility_and_evidence(
                &mut handle,
                scope_id,
                "shared memory backed by workspace-shared evidence",
                "WORKSPACE_SHARED",
                None,
                Some(workspace_w),
                "WORKSPACE_SHARED",
                None,
                Some(workspace_w),
            );
            assert_eq!((seq1, seq2), (1, 2));
            let provider = Arc::new(TestDoubleProvider::new(
                embedding_model(),
                unused_rerank_model(),
            ));
            let deps = handle.rt.block_on(deps_for(&handle, scope_id, provider));
            let outcome = handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("run_once succeeds");
            let key = (
                handle.tenant_id,
                "workspace",
                scope_id,
                "private_memory",
                "PRIVATE_MEMORY",
                "v1",
            );
            assert_eq!(
                (outcome.done, outcome.failed, outcome.skipped_by_policy),
                (2, 0, 0),
                "non-TENANT_SHARED evidence must resolve under 0140, not settle FAILED"
            );
            assert_eq!(outcome.projection_highwater, 2);
            assert_eq!(stream_log_state(&mut handle, &key, seq1), "DONE");
            assert_eq!(stream_log_state(&mut handle, &key, seq2), "DONE");
            let registered: i64 = handle
                .admin
                .query_one(
                    "SELECT count(*) FROM projection.private_memory_points \
                     WHERE tenant_id = $1 AND scope_id = $2",
                    &[&handle.tenant_id, &scope_id],
                )
                .expect("registry query")
                .get(0);
            assert_eq!(registered, 2);
        },
    );
}

// ============================================================================
// §6.1.3 / ADR-0029 (card 9): subject-scoped projection payload, any-of dense prefilter, and the
// 0155 RESTRICTIVE subject-visibility policy's headless exemption.
// ============================================================================

fn seed_subject(handle: &mut Handle, name: &str) -> Uuid {
    handle
        .admin
        .query_one(
            "INSERT INTO private.subjects (tenant_id, kind, display_name) \
             VALUES ($1, 'PERSON', $2) RETURNING subject_id",
            &[&handle.tenant_id, &name],
        )
        .expect("owner seeds subject")
        .get(0)
}

fn link_subject(handle: &mut Handle, memory_id: Uuid, subject_id: Uuid) {
    handle
        .admin
        .execute(
            "INSERT INTO private.memory_subjects \
               (tenant_id, memory_id, subject_id, relation, source_kind, confidence_bp) \
             VALUES ($1, $2, $3, 'ABOUT', 'DECLARED', 10000)",
            &[&handle.tenant_id, &memory_id, &subject_id],
        )
        .expect("owner links memory to subject");
}

/// Payload `subject_ids` read back from Qdrant for one point (sorted, as the writer emits).
fn scrolled_subject_ids(scrolled: &serde_json::Value, point: Uuid) -> Vec<String> {
    scrolled["result"]["points"]
        .as_array()
        .expect("scroll result.points")
        .iter()
        .find(|p| p["id"].as_str() == Some(&point.to_string()))
        .unwrap_or_else(|| panic!("point {point} missing from scroll"))["payload"]["subject_ids"]
        .as_array()
        .expect("subject_ids payload array")
        .iter()
        .map(|v| v.as_str().expect("uuid string").to_owned())
        .collect()
}

fn sorted_ids(ids: &[Uuid]) -> Vec<String> {
    let mut v: Vec<String> = ids.iter().map(ToString::to_string).collect();
    v.sort();
    v
}

fn hit_points(hits: &[DenseCandidate]) -> BTreeSet<Uuid> {
    hits.iter()
        .map(|c| match c.point_id {
            PointId::Uuid(id) => id,
            PointId::Num(n) => panic!("unexpected numeric point id {n}"),
        })
        .collect()
}

/// Polls a dense query until it returns `expected` hits (real Qdrant read-after-write lag under
/// Weak ordering, same pattern as T5) and returns the final candidate list either way.
fn poll_dense(
    handle: &Handle,
    permit: &CellAccessPermit,
    query: &DenseQuery,
    expected: usize,
) -> Vec<DenseCandidate> {
    handle.rt.block_on(async {
        let mut last = Vec::new();
        for _ in 0..40 {
            last = query_dense(handle.transport.as_ref(), permit, query)
                .await
                .expect("dense query succeeds");
            if last.len() == expected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        last
    })
}

/// (S1, ADR-0029 D-C): two subjects A/B, four memories (A-only, B-only, A+B, and a USER_PRIVATE
/// A-only owned by user X) go through the real projection worker; the payload `subject_ids`
/// arrays are read back verbatim; `DenseQuery::with_subject_ids(&[A])` returns exactly the
/// A-linked points and never the B-only one (fault sentinel: stubbing
/// `DenseQueryFilter::about_any_of` to a no-op makes the B-only point appear here); the same
/// query as user Y (same tenant, not the owner) drops the USER_PRIVATE row — subject narrowing
/// is ANDed with §6.1.2 visibility, never a substitute for it.
#[test]
#[allow(clippy::too_many_lines)] // One causal chain: seed -> project -> payload -> filtered queries.
fn subject_scoped_dense_query_returns_only_memories_about_that_subject() {
    run_db_fixture::<Fixture, _>(
        "subject_scoped_dense_query_returns_only_memories_about_that_subject",
        |mut handle| {
            let scope_id = Uuid::new_v4();
            let user_x = seed_user(&mut handle);
            let user_y = seed_user(&mut handle);
            let subject_a = seed_subject(&mut handle, "Ada Customer");
            let subject_b = seed_subject(&mut handle, "Bob Customer");
            let (_, only_a) = seed_memory_with_visibility(
                &mut handle,
                scope_id,
                "about A only",
                "TENANT_SHARED",
                None,
                None,
            );
            let (_, only_b) = seed_memory_with_visibility(
                &mut handle,
                scope_id,
                "about B only",
                "TENANT_SHARED",
                None,
                None,
            );
            let (_, both) = seed_memory_with_visibility(
                &mut handle,
                scope_id,
                "about A and B",
                "TENANT_SHARED",
                None,
                None,
            );
            let (_, private_a) = seed_memory_with_visibility(
                &mut handle,
                scope_id,
                "user X private about A",
                "USER_PRIVATE",
                Some(user_x),
                None,
            );
            link_subject(&mut handle, only_a, subject_a);
            link_subject(&mut handle, only_b, subject_b);
            link_subject(&mut handle, both, subject_a);
            link_subject(&mut handle, both, subject_b);
            link_subject(&mut handle, private_a, subject_a);

            let provider = Arc::new(TestDoubleProvider::new(
                embedding_model(),
                unused_rerank_model(),
            ));
            let deps = handle.rt.block_on(deps_for(&handle, scope_id, provider));
            let outcome = handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("run_once succeeds");
            assert_eq!(
                (outcome.done, outcome.failed),
                (4, 0),
                "every subject-linked row projects"
            );

            let p_only_a = point_id_for_memory(&mut handle, only_a);
            let p_only_b = point_id_for_memory(&mut handle, only_b);
            let p_both = point_id_for_memory(&mut handle, both);
            let p_private_a = point_id_for_memory(&mut handle, private_a);
            let permit = authorize_cell_access(
                &handle.registry,
                IntraCellResource::QDRANT_REST,
                Duration::from_secs(30),
            )
            .expect("admin Qdrant permit");
            let scrolled =
                scroll_payloads(&handle, &permit, &[p_only_a, p_only_b, p_both, p_private_a]);
            assert_eq!(
                scrolled_subject_ids(&scrolled, p_only_a),
                sorted_ids(&[subject_a])
            );
            assert_eq!(
                scrolled_subject_ids(&scrolled, p_only_b),
                sorted_ids(&[subject_b])
            );
            assert_eq!(
                scrolled_subject_ids(&scrolled, p_both),
                sorted_ids(&[subject_a, subject_b])
            );
            assert_eq!(
                scrolled_subject_ids(&scrolled, p_private_a),
                sorted_ids(&[subject_a])
            );

            let placement = TenantPlacementRow {
                tenant_id: TenantId(handle.tenant_id),
                projection_family: RetrievalFamily::PrivateMemoryV1,
                collection_name: handle.collection.clone(),
                shard_key: None,
                placement_class: PlacementClass::SharedFallback,
                point_count: 4,
                bytes_estimate: 0,
                promotion_state: PromotionState::Stable,
            };
            let a = [SubjectId(subject_a)];
            let b = [SubjectId(subject_b)];
            let as_x_about_a =
                dense_query_for_user(&handle, &placement, user_x).with_subject_ids(&a);
            let hits = poll_dense(&handle, &permit, &as_x_about_a, 3);
            assert_eq!(
                hit_points(&hits),
                BTreeSet::from([p_only_a, p_both, p_private_a]),
                "subject A any-of: A-only + A+B + X's private A row; never the B-only point"
            );
            let as_y_about_a =
                dense_query_for_user(&handle, &placement, user_y).with_subject_ids(&a);
            let hits = poll_dense(&handle, &permit, &as_y_about_a, 2);
            assert_eq!(
                hit_points(&hits),
                BTreeSet::from([p_only_a, p_both]),
                "user Y is not authorized for X's USER_PRIVATE row: subject filter ANDs with visibility"
            );
            let as_x_about_b =
                dense_query_for_user(&handle, &placement, user_x).with_subject_ids(&b);
            let hits = poll_dense(&handle, &permit, &as_x_about_b, 2);
            assert_eq!(hit_points(&hits), BTreeSet::from([p_only_b, p_both]));
            let unscoped = dense_query_for_user(&handle, &placement, user_x);
            let hits = poll_dense(&handle, &permit, &unscoped, 4);
            assert_eq!(
                hits.len(),
                4,
                "no subject filter = the plain visibility read"
            );
        },
    );
}

/// Row count of one memory under `SET LOCAL ROLE {role}` with the tenant GUC set, inside a
/// rolled-back transaction on the superuser fixture connection.
fn count_as_role(handle: &mut Handle, role: &str, tenant: Uuid, memory_id: Uuid) -> i64 {
    let mut txn = handle.admin.transaction().expect("txn");
    // dep: PostgreSQL(any) — role switch before the scoped statements for `count_as_role`
    txn.batch_execute(&format!(
        "SET LOCAL ROLE {role}; SET LOCAL humaux.tenant_id = '{tenant}'; SET LOCAL humaux.user_id = '';"
    ))
    .expect("set role + GUCs");
    let n: i64 = txn
        .query_one(
            "SELECT count(*) FROM private.memory_records WHERE memory_id = $1",
            &[&memory_id],
        )
        .expect("count under role")
        .get(0);
    txn.rollback().expect("rollback");
    n
}

/// (S2, ADR-0029 D-B): migration 0155's RESTRICTIVE `memory_records_subject_visibility` policy.
/// A subject-linked TENANT_SHARED memory: `role_gateway` under the owning tenant reads it (1);
/// a gateway session under another tenant reads 0; with the predicate faulted to always-false
/// (inside a rolled-back transaction, so the fault never leaks) the gateway read goes to 0 —
/// proving the policy is wired through the function — while `role_retrieval_worker` still
/// reads the row in both states (the §15.7 watermark-freeze regression sentinel: the headless
/// role is exempt from the RESTRICTIVE policy, so a projection run never skips a row).
#[test]
fn subject_visibility_policy_gates_gateway_reads_but_never_the_retrieval_worker() {
    run_db_fixture::<Fixture, _>(
        "subject_visibility_policy_gates_gateway_reads_but_never_the_retrieval_worker",
        |mut handle| {
            let scope_id = Uuid::new_v4();
            let subject_a = seed_subject(&mut handle, "Gated Customer");
            let (_, memory_id) = seed_memory_with_visibility(
                &mut handle,
                scope_id,
                "gated by subject A",
                "TENANT_SHARED",
                None,
                None,
            );
            link_subject(&mut handle, memory_id, subject_a);
            let tenant = handle.tenant_id;

            assert_eq!(
                count_as_role(&mut handle, "role_gateway", tenant, memory_id),
                1
            );
            assert_eq!(
                count_as_role(&mut handle, "role_retrieval_worker", tenant, memory_id),
                1
            );
            assert_eq!(
                count_as_role(&mut handle, "role_gateway", Uuid::new_v4(), memory_id),
                0,
                "another tenant's gateway session is not authorized"
            );

            // Fault: the predicate answers false for every row. Superuser CREATE OR REPLACE
            // keeps the owner (role_migration_owner) and SECURITY DEFINER; rolled back below.
            let mut txn = handle.admin.transaction().expect("fault txn");
            txn.batch_execute(
                "CREATE OR REPLACE FUNCTION private.memory_subject_visibility_ok(p_tenant_id uuid, p_memory_id uuid) \
                 RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog \
                 AS $$ SELECT false $$;",
            )
            .expect("fault the predicate");
            let count_in = |txn: &mut postgres::Transaction<'_>, role: &str| -> i64 {
                let mut sp = txn.savepoint("role_probe").expect("savepoint");
                // dep: PostgreSQL(any) — role switch before the scoped statements for `subject_visibility_policy_gates_gateway_reads_but_never_the_retrieval_worker`
                sp.batch_execute(&format!(
                    "SET LOCAL ROLE {role}; SET LOCAL humaux.tenant_id = '{tenant}'; \
                     SET LOCAL humaux.user_id = '';"
                ))
                .expect("set role");
                let n: i64 = sp
                    .query_one(
                        "SELECT count(*) FROM private.memory_records WHERE memory_id = $1",
                        &[&memory_id],
                    )
                    .expect("count under role")
                    .get(0);
                sp.rollback().expect("rollback savepoint");
                n
            };
            assert_eq!(
                count_in(&mut txn, "role_gateway"),
                0,
                "faulted predicate hides the row from the gateway: the RESTRICTIVE policy is live"
            );
            assert_eq!(
                count_in(&mut txn, "role_retrieval_worker"),
                1,
                "role_retrieval_worker is exempt from the RESTRICTIVE policy (§15.7 sentinel)"
            );
            txn.rollback().expect("undo the fault");

            assert_eq!(
                count_as_role(&mut handle, "role_gateway", tenant, memory_id),
                1
            );

            // ACL (0155 A2): the definer predicate reads memory_subjects with the owner's
            // privileges, so only the two roles the policy names may call it. role_batch_issuer
            // has USAGE on schema private and no grant on the subject tables — a direct call
            // must be a permission error, never a boolean (the one-bit oracle the review found).
            let mut txn = handle.admin.transaction().expect("acl txn");
            // dep: PostgreSQL(role_batch_issuer) — role switch before the scoped statements for `subject_visibility_policy_gates_gateway_reads_but_never_the_retrieval_worker`
            txn.batch_execute(&format!(
                "SET LOCAL ROLE role_batch_issuer; SET LOCAL humaux.tenant_id = '{tenant}';"
            ))
            .expect("set role");
            let denied = txn
                .query_one(
                    "SELECT private.memory_subject_visibility_ok($1, $2)",
                    &[&tenant, &memory_id],
                )
                .expect_err("role_batch_issuer has no EXECUTE on the subject predicate");
            assert_eq!(
                denied.code().map(|c| c.code()),
                Some("42501"),
                "insufficient_privilege, not a boolean: {denied}"
            );
            txn.rollback().expect("rollback acl probe");
        },
    );
}

/// Adds a SECOND memory bound to the SAME Evidence as `sibling_of`, exactly the shape
/// `distill_repo::persist` writes when one pass extracts N memories from one Evidence
/// (`role='PRIMARY', ordinal 0` per memory, distill_repo.rs:457) — the multi-memory Evidence
/// every ticket issuer in the system can produce and that card 9 reported as unhandled.
fn attach_sibling_memory(handle: &mut Handle, sibling_of: Uuid, content: &str) -> Uuid {
    let evidence_id: Uuid = handle
        .admin
        .query_one(
            "SELECT evidence_id FROM private.memory_evidence WHERE memory_id = $1 \
             ORDER BY (role = 'PRIMARY') DESC, ordinal ASC LIMIT 1",
            &[&sibling_of],
        )
        .expect("the first memory's evidence")
        .get(0);
    let content_json = serde_json::json!({
        "title": format!("title: {content}"),
        "key_claim": format!("key claim: {content}"),
        "evidence_excerpt": content,
    });
    let mut txn = handle.admin.transaction().expect("sibling txn");
    let memory_id: Uuid = txn
        .query_one(
            "INSERT INTO private.memory_records \
               (tenant_id, memory_type, content, visibility_class, visibility_user_id, \
                visibility_workspace_id, authority_class, confidence, status, asserted_at) \
             VALUES ($1,'NOTE',$2,'TENANT_SHARED',NULL,NULL,'PrivateKnowledge',0.9,'active',now()) \
             RETURNING memory_id",
            &[&handle.tenant_id, &content_json],
        )
        .expect("insert sibling memory")
        .get(0);
    // dep: PostgreSQL(any) — pool/txn query execution
    txn.execute(
        "INSERT INTO private.memory_evidence (memory_id, evidence_id, role, ordinal) \
         VALUES ($1, $2, 'PRIMARY', 0)",
        &[&memory_id, &evidence_id],
    )
    .expect("link the sibling to the same evidence");
    txn.commit().expect("commit sibling");
    memory_id
}

/// Card 9's reported limit, closed by card 20 (ADR-0042): a ticket binds an EVIDENCE, and one
/// Evidence routinely carries N memories (`distill_repo` writes one `PRIMARY` row per extracted
/// memory against the single Evidence `remember` issued the ticket for). The worker used to
/// resolve `ORDER BY (role='PRIMARY') DESC, ordinal ASC LIMIT 1`, so memories 2..N of every
/// multi-output distill were never indexed, and a MEMORY_LIFECYCLE / 0155-backfill ticket aimed
/// at memory #2 silently re-projected memory #1 instead.
///
/// Both halves are asserted here on ONE causal chain: the remember-time ticket must index BOTH
/// memories, and the re-issued lifecycle ticket must re-project BOTH (not just the PRIMARY-first
/// one). Fault control: restore the `LIMIT 1` in `projection_worker::resolve_memories` and the
/// first `point_id_for_memory(sibling)` lookup panics — there is no registered point for it.
#[test]
fn one_ticket_projects_every_memory_its_evidence_carries() {
    run_db_fixture::<Fixture, _>(
        "one_ticket_projects_every_memory_its_evidence_carries",
        |mut handle| {
            let scope_id = Uuid::new_v4();
            let (_, memory_a) = seed_memory_with_visibility(
                &mut handle,
                scope_id,
                "first memory of a two-memory evidence",
                "TENANT_SHARED",
                None,
                None,
            );
            let memory_b =
                attach_sibling_memory(&mut handle, memory_a, "second memory of the same evidence");

            let provider = Arc::new(TestDoubleProvider::new(
                embedding_model(),
                unused_rerank_model(),
            ));
            let deps = handle.rt.block_on(deps_for(&handle, scope_id, provider));
            let outcome = handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("run_once succeeds");
            assert_eq!(
                (outcome.done, outcome.failed),
                (1, 0),
                "one ticket, one row settled DONE — N memories is not N rows"
            );

            let point_a = point_id_for_memory(&mut handle, memory_a);
            let point_b = point_id_for_memory(&mut handle, memory_b);
            assert_ne!(
                point_a, point_b,
                "each memory gets its own deterministic point id"
            );
            let permit = authorize_cell_access(
                &handle.registry,
                IntraCellResource::QDRANT_REST,
                Duration::from_secs(30),
            )
            .expect("admin Qdrant permit");
            let scrolled = scroll_payloads(&handle, &permit, &[point_a, point_b]);
            let indexed = scrolled["result"]["points"].as_array().map_or(0, Vec::len);
            assert_eq!(indexed, 2, "both memories are in the index: {scrolled}");

            // Second half: a lifecycle ticket aimed at the SIBLING re-projects it, rather than
            // resolving PRIMARY-first back to memory_a and dropping the sibling's change.
            let reissued = reissue_lifecycle_ticket(&mut handle, scope_id, memory_b);
            let outcome = handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("second run_once succeeds");
            assert_eq!((outcome.done, outcome.failed), (1, 0));
            let key = (
                handle.tenant_id,
                "workspace",
                scope_id,
                "private_memory",
                "PRIVATE_MEMORY",
                "v1",
            );
            assert_eq!(stream_log_state(&mut handle, &key, reissued), "DONE");
            assert_eq!(
                point_id_for_memory(&mut handle, memory_b),
                point_b,
                "same deterministic point id: the sibling's payload was rewritten in place"
            );
        },
    );
}

/// Re-issues one `MEMORY_LIFECYCLE` ticket for `memory_id` on the fixture's `v1` workspace
/// stream — the §60 `issue_stream_log_row` + `insert_outbox` sequence that migration 0155's
/// backfill block (C.) and `memory_governance_repo::issue_lifecycle_ticket` both perform, bound
/// to the memory's PRIMARY-first Evidence exactly as they bind it.
fn reissue_lifecycle_ticket(handle: &mut Handle, scope_id: Uuid, memory_id: Uuid) -> i64 {
    let mut txn = handle.admin.transaction().expect("ticket txn");
    let evidence_id: Uuid = txn
        .query_one(
            "SELECT evidence_id FROM private.memory_evidence WHERE memory_id = $1 \
             ORDER BY (role = 'PRIMARY') DESC, ordinal ASC LIMIT 1",
            &[&memory_id],
        )
        .expect("bound evidence")
        .get(0);
    let commit_seq: i64 = txn
        .query_one("SELECT nextval('ops.commit_seq_seq')", &[])
        .expect("commit seq")
        .get(0);
    let stream_seq: i64 = txn
        .query_one(
            "UPDATE projection.stream_checkpoints SET issued_highwater = issued_highwater + 1 \
             WHERE tenant_id = $1 AND scope_kind = 'workspace' AND scope_id = $2 \
               AND domain = 'private_memory' AND projection_kind = 'PRIVATE_MEMORY' \
               AND projection_version = 'v1' \
             RETURNING issued_highwater",
            &[&handle.tenant_id, &scope_id],
        )
        .expect("bump issued_highwater")
        .get(0);
    // dep: PostgreSQL(any) — pool/txn query execution
    txn.execute(
        "INSERT INTO projection.stream_log \
           (tenant_id, scope_kind, scope_id, domain, projection_kind, projection_version, \
            stream_seq, commit_seq) \
         VALUES ($1, 'workspace', $2, 'private_memory', 'PRIVATE_MEMORY', 'v1', $3, $4)",
        &[&handle.tenant_id, &scope_id, &stream_seq, &commit_seq],
    )
    .expect("stream_log row");
    // dep: PostgreSQL(any) — pool/txn query execution
    txn.execute(
        "INSERT INTO ops.outbox (tenant_id, commit_seq, stream_seq, event_type, evidence_id) \
         VALUES ($1, $2, $3, 'MEMORY_LIFECYCLE', $4)",
        &[&handle.tenant_id, &commit_seq, &stream_seq, &evidence_id],
    )
    .expect("outbox row");
    txn.commit().expect("commit ticket");
    stream_seq
}

/// (S3, ADR-0029 D-A backfill): a point projected BEFORE its memory carried any subject link
/// has `subject_ids: []` and the any-of prefilter never matches it — the shape every point
/// projected before 0155 is in (no field at all, same non-match). Migration 0155's block C.
/// re-issues one MEMORY_LIFECYCLE ticket per such linked memory; this is that mechanism end to
/// end: link A after the first projection, re-issue the ticket the way 0155 does, run the
/// worker again — the SAME point id (registration is keyed by `updated_at` + `body_sha256`,
/// which a link does not touch) now carries `[A]`, the ticket settles DONE, and the A-scoped
/// dense query hits the point it could not see before.
#[test]
#[allow(clippy::too_many_lines)] // One causal chain: project -> stale miss -> link -> re-ticket -> rewritten hit.
fn reissued_lifecycle_ticket_reprojects_the_same_point_with_current_subject_ids() {
    run_db_fixture::<Fixture, _>(
        "reissued_lifecycle_ticket_reprojects_the_same_point_with_current_subject_ids",
        |mut handle| {
            let scope_id = Uuid::new_v4();
            let user = seed_user(&mut handle);
            let subject_a = seed_subject(&mut handle, "Late-linked Customer");
            let (_, memory_id) = seed_memory_with_visibility(
                &mut handle,
                scope_id,
                "linked after projection",
                "TENANT_SHARED",
                None,
                None,
            );
            let provider = Arc::new(TestDoubleProvider::new(
                embedding_model(),
                unused_rerank_model(),
            ));
            let deps = handle.rt.block_on(deps_for(&handle, scope_id, provider));
            let outcome = handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("first run_once succeeds");
            assert_eq!((outcome.done, outcome.failed), (1, 0));
            let point = point_id_for_memory(&mut handle, memory_id);
            let permit = authorize_cell_access(
                &handle.registry,
                IntraCellResource::QDRANT_REST,
                Duration::from_secs(30),
            )
            .expect("admin Qdrant permit");
            let scrolled = scroll_payloads(&handle, &permit, &[point]);
            assert_eq!(
                scrolled_subject_ids(&scrolled, point),
                Vec::<String>::new(),
                "projected before any link: empty subject_ids"
            );
            let placement = TenantPlacementRow {
                tenant_id: TenantId(handle.tenant_id),
                projection_family: RetrievalFamily::PrivateMemoryV1,
                collection_name: handle.collection.clone(),
                shard_key: None,
                placement_class: PlacementClass::SharedFallback,
                point_count: 1,
                bytes_estimate: 0,
                promotion_state: PromotionState::Stable,
            };
            let a = [SubjectId(subject_a)];
            let about_a = dense_query_for_user(&handle, &placement, user).with_subject_ids(&a);
            // Presence first (read-after-write lag), then the scoped miss is a real miss.
            assert_eq!(
                poll_dense(
                    &handle,
                    &permit,
                    &dense_query_for_user(&handle, &placement, user),
                    1
                )
                .len(),
                1
            );
            let stale = handle
                .rt
                .block_on(query_dense(handle.transport.as_ref(), &permit, &about_a))
                .expect("dense query succeeds");
            assert!(
                stale.is_empty(),
                "the stale payload cannot be matched by the any-of prefilter"
            );

            link_subject(&mut handle, memory_id, subject_a);
            let reissued = reissue_lifecycle_ticket(&mut handle, scope_id, memory_id);
            let outcome = handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("second run_once succeeds");
            assert_eq!(
                (outcome.done, outcome.failed),
                (1, 0),
                "the re-issued ticket projects"
            );
            let key = (
                handle.tenant_id,
                "workspace",
                scope_id,
                "private_memory",
                "PRIVATE_MEMORY",
                "v1",
            );
            assert_eq!(stream_log_state(&mut handle, &key, reissued), "DONE");
            assert_eq!(
                point_id_for_memory(&mut handle, memory_id),
                point,
                "same deterministic point id: the payload was rewritten in place"
            );
            let scrolled = scroll_payloads(&handle, &permit, &[point]);
            assert_eq!(
                scrolled_subject_ids(&scrolled, point),
                sorted_ids(&[subject_a])
            );
            let hits = poll_dense(&handle, &permit, &about_a, 1);
            assert_eq!(
                hit_points(&hits),
                BTreeSet::from([point]),
                "after re-projection the A-scoped prefilter sees the point"
            );
        },
    );
}

/// ADR-0049 (card 24 rehearsal, 2026-09-26): the MEMORY_LIFECYCLE ticket a `memory.supersede`
/// issues used to fail `registry_failed` every time — the registry binds live sources only
/// (`current_source_matches`), and ADR-0018 §4's "re-upsert with status=superseded" predates
/// it — which wedged the §15.4 prefix behind the ticket and broke every token-carrying recall
/// on the stream. A dead memory's ticket now retires its binding, removes its point, and
/// settles `DONE`. ADR-0057 D-J: the supersede runs through the real
/// `memory_governance_repo::supersede_atomically`. Faults: remove that op's
/// `issue_lifecycle_ticket` call (no ticket ⇒ the point stays), or route the superseded memory
/// through `finish_row` again (`(0, 1)`, `registry_failed`).
#[test]
fn supersede_through_the_real_op_retires_its_point_and_settles_done() {
    run_db_fixture::<Fixture, _>(
        "supersede_through_the_real_op_retires_its_point_and_settles_done",
        |mut handle| {
            let (scope_id, deps, memories, gov) = governed_memories(&mut handle, 2);
            let (memory_a, memory_b) = (memories[0], memories[1]);
            let point_a = point_id_for_memory(&mut handle, memory_a);
            let point_b = point_id_for_memory(&mut handle, memory_b);
            let ticket = governance_ops::supersede(
                &handle.rt,
                &handle.gateway,
                &gov.scope(scope_id),
                &governance_ops::stream(handle.tenant_id, scope_id),
                memory_a,
                memory_b,
            )
            .expect("supersede through the real op")
            .stream_seq;
            let outcome = handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("second run_once succeeds");
            assert_eq!(
                (outcome.done, outcome.failed),
                (1, 0),
                "a dead memory's ticket settles DONE instead of wedging the prefix: {outcome:?}"
            );
            let key = (
                handle.tenant_id,
                "workspace",
                scope_id,
                "private_memory",
                "PRIVATE_MEMORY",
                "v1",
            );
            assert_eq!(stream_log_state(&mut handle, &key, ticket), "DONE");
            assert_eq!(stream_log_error_class(&mut handle, &key, ticket), None);
            assert_eq!(
                projection_highwater(&mut handle, &key),
                ticket,
                "the §15.4 prefix advances past the lifecycle ticket"
            );
            assert!(
                !point_live(&mut handle, point_a),
                "the superseded memory's binding is retired"
            );
            let permit = admin_permit(&handle);
            let scrolled = scroll_payloads(&handle, &permit, &[point_a, point_b]);
            let ids = scrolled["result"]["points"]
                .as_array()
                .map(|points| {
                    points
                        .iter()
                        .filter_map(|point| point["id"].as_str().map(str::to_owned))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            assert_eq!(
                ids,
                vec![point_b.to_string()],
                "the dead memory's point left the index, the live sibling stayed: {scrolled}"
            );
            assert_eq!(
                outbox_status(&mut handle, ticket),
                "DONE",
                "ADR-0049 D-C: the ticket's carrier outbox row is settled with the ticket"
            );
        },
    );
}

/// ADR-0020 restore through the real `restore_atomically` (ADR-0057 D-J): status back, same
/// `updated_at`, so the ticket brings the SAME point back (identity unchanged → the retired
/// binding is revived, ADR-0049) — the rehearsal's `restored_memory_is_servable_again = 0` shape
/// is this test failing. Fault: remove restore's `issue_lifecycle_ticket` call (no ticket ⇒ the
/// point stays retired).
#[test]
fn restore_through_the_real_op_revives_the_same_point() {
    run_db_fixture::<Fixture, _>(
        "restore_through_the_real_op_revives_the_same_point",
        |mut handle| {
            let (scope_id, deps, memories, gov) = governed_memories(&mut handle, 2);
            let (memory_a, memory_b) = (memories[0], memories[1]);
            let point_a = point_id_for_memory(&mut handle, memory_a);
            let (auth, key) = (
                gov.scope(scope_id),
                governance_ops::stream(handle.tenant_id, scope_id),
            );
            governance_ops::supersede(&handle.rt, &handle.gateway, &auth, &key, memory_a, memory_b)
                .expect("supersede");
            handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("retire pass");
            assert!(!point_live(&mut handle, point_a));
            let restored =
                governance_ops::restore(&handle.rt, &handle.gateway, &auth, &key, memory_a)
                    .expect("restore through the real op");
            let restore_ticket = match restored {
                RestoreResult::Restored(done) => done.stream_seq,
                RestoreResult::Refused(reason) => panic!("restore refused: {reason:?}"),
            };
            let outcome = handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("third run_once succeeds");
            assert_eq!((outcome.done, outcome.failed), (1, 0), "{outcome:?}");
            let stream_key = (
                handle.tenant_id,
                "workspace",
                scope_id,
                "private_memory",
                "PRIVATE_MEMORY",
                "v1",
            );
            assert_eq!(
                stream_log_state(&mut handle, &stream_key, restore_ticket),
                "DONE"
            );
            assert_eq!(outbox_status(&mut handle, restore_ticket), "DONE");
            assert_eq!(
                point_id_for_memory(&mut handle, memory_a),
                point_a,
                "same identity, same deterministic point id"
            );
            assert!(
                point_live(&mut handle, point_a),
                "the restored memory's binding is live again (revived)"
            );
            assert_eq!(
                lifecycle_flags(&handle, point_a),
                (Some(false), "active".to_owned())
            );
        },
    );
}

/// `ops.outbox.status` of the carrier row behind one ticket of the fixture's `v1` workspace
/// stream (ADR-0049 D-C).
fn outbox_status(handle: &mut Handle, stream_seq: i64) -> String {
    handle
        .admin
        .query_one(
            "SELECT status FROM ops.outbox WHERE tenant_id = $1 AND stream_seq = $2 \
               AND event_type = 'MEMORY_LIFECYCLE'",
            &[&handle.tenant_id, &stream_seq],
        )
        .expect("carrier outbox row")
        .get(0)
}

// ---- ADR-0055 D-B / ADR-0057 D-J: the `archived` payload flag follows the PG row on every
// ticket, each transition driven through the real `memory_governance_repo` op ----

/// The (`archived`, `status`) payload pair of one point, read back through a raw payload scroll.
/// `None` for `archived` = the point carries no flag (never the case after card 30).
fn lifecycle_flags(handle: &Handle, point: Uuid) -> (Option<bool>, String) {
    let permit = admin_permit(handle);
    let scrolled = scroll_payloads(handle, &permit, &[point]);
    let payload = &scrolled["result"]["points"][0]["payload"];
    assert!(
        payload.is_object(),
        "point {point} is in the index: {scrolled}"
    );
    (
        payload["archived"].as_bool(),
        payload["status"].as_str().unwrap_or_default().to_owned(),
    )
}

fn admin_permit(handle: &Handle) -> CellAccessPermit {
    authorize_cell_access(
        &handle.registry,
        IntraCellResource::QDRANT_REST,
        Duration::from_secs(30),
    )
    .expect("admin Qdrant permit")
}

fn point_live(handle: &mut Handle, point: Uuid) -> bool {
    handle
        .admin
        .query_one(
            "SELECT projection_live FROM projection.private_memory_points WHERE point_id = $1",
            &[&point],
        )
        .expect("binding row")
        .get(0)
}

fn point_present(handle: &Handle, point: Uuid) -> bool {
    let permit = admin_permit(handle);
    scroll_payloads(handle, &permit, &[point])["result"]["points"]
        .as_array()
        .is_some_and(|points| !points.is_empty())
}

/// Seeds `n` TENANT_SHARED memories in a fresh real workspace whose governor (ADR-0057 D-J) can
/// run the confirm-gated ops, projects them once, and returns the workspace, the worker deps,
/// the memory ids and the governor.
fn governed_memories(
    handle: &mut Handle,
    n: usize,
) -> (Uuid, ProjectionWorkerDeps, Vec<Uuid>, Governor) {
    let gov = Governor::seed(&mut handle.admin, handle.tenant_id);
    let scope_id = seed_workspace(handle);
    gov.join(&mut handle.admin, scope_id);
    let memories: Vec<Uuid> = (0..n)
        .map(|i| {
            seed_memory_with_visibility(
                handle,
                scope_id,
                &format!("governed lifecycle fixture memory {i}"),
                "TENANT_SHARED",
                None,
                None,
            )
            .1
        })
        .collect();
    let provider = Arc::new(TestDoubleProvider::new(
        embedding_model(),
        unused_rerank_model(),
    ));
    let deps = handle.rt.block_on(deps_for(handle, scope_id, provider));
    let outcome = handle
        .rt
        .block_on(run_once(&deps, 10))
        .expect("first run_once");
    assert_eq!(
        (outcome.done, outcome.failed),
        (u64::try_from(n).expect("n"), 0),
        "{outcome:?}"
    );
    (scope_id, deps, memories, gov)
}

/// One confirm-gated archive / unarchive through the real op, then one worker pass.
fn archive_step(
    handle: &mut Handle,
    deps: &ProjectionWorkerDeps,
    gov: &Governor,
    scope_id: Uuid,
    memory_id: Uuid,
    op: DestructiveOp,
) {
    let result = governance_ops::archive(
        &handle.rt,
        &handle.gateway,
        &gov.scope(scope_id),
        &governance_ops::stream(handle.tenant_id, scope_id),
        memory_id,
        op,
    )
    .expect("archive / unarchive through the real op");
    assert!(matches!(result, ArchiveResult::Done(_)), "{result:?}");
    let outcome = handle.rt.block_on(run_once(deps, 10)).expect("run_once");
    assert_eq!((outcome.done, outcome.failed), (1, 0), "{outcome:?}");
}

/// Fault: remove archive's `issue_lifecycle_ticket` call (no ticket ⇒ `archived` stays false).
#[test]
fn archive_through_the_real_op_reupserts_the_same_point_with_archived_true() {
    run_db_fixture::<Fixture, _>(
        "archive_through_the_real_op_reupserts_the_same_point_with_archived_true",
        |mut handle| {
            let (scope_id, deps, memories, gov) = governed_memories(&mut handle, 1);
            let point = point_id_for_memory(&mut handle, memories[0]);
            assert_eq!(
                lifecycle_flags(&handle, point),
                (Some(false), "active".to_owned())
            );
            archive_step(
                &mut handle,
                &deps,
                &gov,
                scope_id,
                memories[0],
                DestructiveOp::MemoryArchive,
            );
            assert_eq!(
                point_id_for_memory(&mut handle, memories[0]),
                point,
                "same point id"
            );
            assert_eq!(
                lifecycle_flags(&handle, point),
                (Some(true), "active".to_owned())
            );
        },
    );
}

/// Fault: remove the (shared) archive/unarchive `issue_lifecycle_ticket` call.
#[test]
fn unarchive_through_the_real_op_reupserts_the_same_point_with_archived_false() {
    run_db_fixture::<Fixture, _>(
        "unarchive_through_the_real_op_reupserts_the_same_point_with_archived_false",
        |mut handle| {
            let (scope_id, deps, memories, gov) = governed_memories(&mut handle, 1);
            let point = point_id_for_memory(&mut handle, memories[0]);
            archive_step(
                &mut handle,
                &deps,
                &gov,
                scope_id,
                memories[0],
                DestructiveOp::MemoryArchive,
            );
            assert_eq!(lifecycle_flags(&handle, point).0, Some(true));
            archive_step(
                &mut handle,
                &deps,
                &gov,
                scope_id,
                memories[0],
                DestructiveOp::MemoryUnarchive,
            );
            assert_eq!(
                point_id_for_memory(&mut handle, memories[0]),
                point,
                "same point id"
            );
            assert_eq!(
                lifecycle_flags(&handle, point),
                (Some(false), "active".to_owned())
            );
        },
    );
}

/// ADR-0055 lifecycle matrix: archive survives supersede → restore. The superseded memory's
/// point is retired (ADR-0049); the restore revives the SAME point and the flag is read from the
/// row again — still archived, because restore never touches `archived_at`.
#[test]
fn restore_of_an_archived_memory_revives_the_point_with_archived_true() {
    run_db_fixture::<Fixture, _>(
        "restore_of_an_archived_memory_revives_the_point_with_archived_true",
        |mut handle| {
            let (scope_id, deps, memories, gov) = governed_memories(&mut handle, 2);
            let (a, b) = (memories[0], memories[1]);
            let point = point_id_for_memory(&mut handle, a);
            archive_step(
                &mut handle,
                &deps,
                &gov,
                scope_id,
                a,
                DestructiveOp::MemoryArchive,
            );
            let (auth, key) = (
                gov.scope(scope_id),
                governance_ops::stream(handle.tenant_id, scope_id),
            );
            governance_ops::supersede(&handle.rt, &handle.gateway, &auth, &key, a, b)
                .expect("supersede a");
            handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("retire pass");
            assert!(!point_present(&handle, point), "superseded ⇒ retired point");
            governance_ops::restore(&handle.rt, &handle.gateway, &auth, &key, a)
                .expect("restore a");
            let outcome = handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("revive pass");
            assert_eq!(outcome.failed, 0, "{outcome:?}");
            assert_eq!(
                point_id_for_memory(&mut handle, a),
                point,
                "revived, same point id"
            );
            assert_eq!(
                lifecycle_flags(&handle, point),
                (Some(true), "active".to_owned())
            );
        },
    );
}

/// An unrelated re-projection (affect annotate re-issues MEMORY_LIFECYCLE — not a governance
/// transition, so its ticket stays the test-side reissue) must carry the archive flag from PG,
/// never reset it to the default.
#[test]
fn annotate_ticket_on_an_archived_memory_keeps_archived_true() {
    run_db_fixture::<Fixture, _>(
        "annotate_ticket_on_an_archived_memory_keeps_archived_true",
        |mut handle| {
            let (scope_id, deps, memories, gov) = governed_memories(&mut handle, 1);
            let point = point_id_for_memory(&mut handle, memories[0]);
            archive_step(
                &mut handle,
                &deps,
                &gov,
                scope_id,
                memories[0],
                DestructiveOp::MemoryArchive,
            );
            handle
                .admin
                .execute(
                    "INSERT INTO private.memory_affects \
                       (tenant_id, memory_id, affect_kind, label, valence_bp, arousal_bp, intensity_bp, \
                        confidence_bp, evidence_id, observed_at) \
                     SELECT m.tenant_id, m.memory_id, 'EMOTION', 'JOY', 5000, 2000, 6000, 10000, \
                            me.evidence_id, now() \
                     FROM private.memory_records m \
                     JOIN private.memory_evidence me ON me.memory_id = m.memory_id \
                     WHERE m.memory_id = $1 LIMIT 1",
                    &[&memories[0]],
                )
                .expect("annotate");
            reissue_lifecycle_ticket(&mut handle, scope_id, memories[0]);
            let outcome = handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("annotate pass");
            assert_eq!(outcome.failed, 0, "{outcome:?}");
            let permit = admin_permit(&handle);
            let scrolled = scroll_payloads(&handle, &permit, &[point]);
            assert_eq!(
                scrolled["result"]["points"][0]["payload"]["affect_kinds"],
                serde_json::json!(["EMOTION"]),
                "the annotate ticket really re-projected: {scrolled}"
            );
            assert_eq!(
                lifecycle_flags(&handle, point),
                (Some(true), "active".to_owned())
            );
        },
    );
}

/// `memory.correct` through the real op: M2's own ticket projects it live — `archived=false`,
/// `status="active"` whatever M1's flags were (the flag is per memory row, never inherited) — and
/// the second ticket on E1 retires M1's point (ADR-0057 D-B). Fault: remove correct's E1
/// `issue_lifecycle_ticket` call (M1's point stays).
#[test]
fn correct_through_the_real_op_projects_the_successor_and_retires_the_original() {
    run_db_fixture::<Fixture, _>(
        "correct_through_the_real_op_projects_the_successor_and_retires_the_original",
        |mut handle| {
            let (scope_id, deps, memories, gov) = governed_memories(&mut handle, 1);
            let m1 = memories[0];
            let m1_point = point_id_for_memory(&mut handle, m1);
            archive_step(
                &mut handle,
                &deps,
                &gov,
                scope_id,
                m1,
                DestructiveOp::MemoryArchive,
            );
            let done = governance_ops::correct(
                &handle.rt,
                &handle.gateway,
                &gov.scope(scope_id),
                &governance_ops::stream(handle.tenant_id, scope_id),
                m1,
                "corrected body",
            )
            .expect("correct through the real op");
            let outcome = handle
                .rt
                .block_on(run_once(&deps, 10))
                .expect("correct pass");
            assert_eq!((outcome.done, outcome.failed), (2, 0), "{outcome:?}");
            let point = point_id_for_memory(&mut handle, done.new_memory_id.0);
            assert_eq!(
                lifecycle_flags(&handle, point),
                (Some(false), "active".to_owned())
            );
            assert!(!point_present(&handle, m1_point), "M1's point is retired");
            assert!(!point_live(&mut handle, m1_point));
        },
    );
}

// ---- ADR-0057 D-I: the worker's Qdrant writes are fenced on `source_stream_seq` ----

/// The stored `source_stream_seq` of one point, read back through a raw payload scroll.
fn stored_seq(handle: &Handle, point: Uuid) -> Option<i64> {
    let permit = admin_permit(handle);
    scroll_payloads(handle, &permit, &[point])["result"]["points"][0]["payload"]
        ["source_stream_seq"]
        .as_i64()
}

/// The highest ticket seq on the fixture's workspace stream (the one an op just issued).
fn last_seq(handle: &mut Handle, scope_id: Uuid) -> i64 {
    handle
        .admin
        .query_one(
            "SELECT max(stream_seq) FROM projection.stream_log \
             WHERE tenant_id = $1 AND scope_kind = 'workspace' AND scope_id = $2",
            &[&handle.tenant_id, &scope_id],
        )
        .expect("stream has tickets")
        .get(0)
}

/// Holds (`park`) or releases one ISSUED ticket through its backoff column — the
/// `run_once` read skips a ticket whose `next_attempt_at` is in the future, exactly as it skips a
/// ticket another worker is backing off. Lets a lower seq be processed after a higher one.
fn set_backoff(handle: &mut Handle, scope_id: Uuid, stream_seq: i64, park: bool) {
    let at = if park {
        "now() + interval '1 hour'"
    } else {
        "now() - interval '1 second'"
    };
    // dep: PostgreSQL(any) — fixture backoff write on one ISSUED ticket
    let n = handle
        .admin
        .execute(
            &format!(
                "UPDATE projection.stream_log SET next_attempt_at = {at} \
                 WHERE tenant_id = $1 AND scope_kind = 'workspace' AND scope_id = $2 \
                   AND stream_seq = $3 AND state = 'ISSUED'"
            ),
            &[&handle.tenant_id, &scope_id, &stream_seq],
        )
        .expect("backoff write");
    assert_eq!(n, 1, "ticket {stream_seq} is ISSUED");
}

/// ADR-0057 D-I (debt 4): a ticket processed after a later ticket of the same memory — what a
/// stalled worker whose lease was reclaimed does when it resumes — must not overwrite the later
/// write. Archive (seq s1) is held back, unarchive (s2 > s1) projects first, then s1 runs through
/// the real worker. Qdrant answers `completed` either way, so the point is read back: its seq
/// stays s2. Fault: `finish_row` calls the unfenced `qdrant::upsert` (the stored seq becomes s1).
#[test]
fn stale_worker_upsert_is_refused_by_seq_fence() {
    run_db_fixture::<Fixture, _>(
        "stale_worker_upsert_is_refused_by_seq_fence",
        |mut handle| {
            let (scope_id, deps, memories, gov) = governed_memories(&mut handle, 1);
            let point = point_id_for_memory(&mut handle, memories[0]);
            let stream = governance_ops::stream(handle.tenant_id, scope_id);
            let archived = governance_ops::archive(
                &handle.rt,
                &handle.gateway,
                &gov.scope(scope_id),
                &stream,
                memories[0],
                DestructiveOp::MemoryArchive,
            )
            .expect("archive through the real op");
            assert!(matches!(archived, ArchiveResult::Done(_)), "{archived:?}");
            let s1 = last_seq(&mut handle, scope_id);
            set_backoff(&mut handle, scope_id, s1, true);
            let unarchived = governance_ops::archive(
                &handle.rt,
                &handle.gateway,
                &gov.scope(scope_id),
                &stream,
                memories[0],
                DestructiveOp::MemoryUnarchive,
            )
            .expect("unarchive through the real op");
            assert!(
                matches!(unarchived, ArchiveResult::Done(_)),
                "{unarchived:?}"
            );
            let s2 = last_seq(&mut handle, scope_id);
            assert!(s2 > s1, "s1={s1} s2={s2}");

            let later = handle.rt.block_on(run_once(&deps, 10)).expect("later pass");
            assert_eq!((later.done, later.failed), (1, 0), "{later:?}");
            assert_eq!(
                stored_seq(&handle, point),
                Some(s2),
                "the later ticket wrote"
            );

            set_backoff(&mut handle, scope_id, s1, false);
            let stale = handle.rt.block_on(run_once(&deps, 10)).expect("stale pass");
            assert_eq!((stale.done, stale.failed), (1, 0), "{stale:?}");
            eprintln!(
                "stale_worker_upsert: s1={s1} s2={s2} stored={:?}",
                stored_seq(&handle, point)
            );
            assert_eq!(
                stored_seq(&handle, point),
                Some(s2),
                "the stale ticket's write was refused (silently: it still settled DONE)"
            );
            assert_eq!(lifecycle_flags(&handle, point).0, Some(false));
        },
    );
}

/// ADR-0057 D-I: the delete mirror. A delete carrying a seq below the stored one (a stalled
/// worker's retire after a later revive) leaves the point; the stored seq itself deletes it.
/// Fault: drop the fence from `delete_points` (the first delete removes the point).
#[test]
fn stale_worker_delete_is_refused_by_seq_fence() {
    run_db_fixture::<Fixture, _>(
        "stale_worker_delete_is_refused_by_seq_fence",
        |mut handle| {
            let (_scope_id, _deps, memories, _gov) = governed_memories(&mut handle, 1);
            let point = point_id_for_memory(&mut handle, memories[0]);
            let seq = stored_seq(&handle, point).expect("projected point carries its seq");
            let permit = admin_permit(&handle);
            let delete = |fence_seq: i64| {
                // dep: Qdrant(*) — the adapter's fenced delete against the fixture collection
                handle
                    .rt
                    .block_on(delete_points(
                        handle.transport.as_ref(),
                        &permit,
                        &handle.collection,
                        &[PointId::Uuid(point)],
                        fence_seq,
                        ha_profile_for(QdrantOperation::CorrectionDeleteSupersede),
                    ))
                    .expect("delete answers completed");
            };
            delete(seq - 1);
            assert!(point_present(&handle, point), "a lower seq deletes nothing");
            delete(seq);
            assert!(!point_present(&handle, point), "the stored seq deletes it");
        },
    );
}

/// The G-M10-6 fixture (§17.3, card M10-5): a tenant with the placement row provisioning creates
/// (`projection.ensure_tenant_placement`, 0186 — the resident claim joins it), two TENANT_SHARED memories, and
/// worker deps under a label of this test's own bound as the worker binds it at boot, so every registration
/// carries its vector (ADR-0064 D-B) and the byte term has a dimension to state.
fn placement_gate_fixture(
    handle: &mut Handle,
) -> (Uuid, ProjectionWorkerDeps, Governor, Uuid, Uuid) {
    handle
        .admin
        .execute(
            "INSERT INTO projection.tenant_placements \
               (tenant_id, projection_family, collection_name, placement_class) \
             VALUES ($1, 'private_memory_v1', $2, 'SHARED_FALLBACK')",
            &[&handle.tenant_id, &handle.collection],
        )
        .expect("placement row");
    let gov = Governor::seed(&mut handle.admin, handle.tenant_id);
    let scope_id = seed_workspace(handle);
    gov.join(&mut handle.admin, scope_id);
    let memory_a = seed_memory_with_visibility(
        handle,
        scope_id,
        "placement counter memory a",
        "TENANT_SHARED",
        None,
        None,
    )
    .1;
    let memory_b = seed_memory_with_visibility(
        handle,
        scope_id,
        "placement counter memory b",
        "TENANT_SHARED",
        None,
        None,
    )
    .1;
    let provider = Arc::new(TestDoubleProvider::new(
        embedding_model(),
        unused_rerank_model(),
    ));
    let mut deps = handle.rt.block_on(deps_for(handle, scope_id, provider));
    deps.embedding_version = format!("m10-5-{}", Uuid::new_v4().simple());
    handle
        .rt
        .block_on(bind_embedding_fingerprint(
            &deps.pool,
            &deps.embedding_version,
            &worker_fingerprint_inputs("m10-5-test", &deps.embedding_version, "r1", 4, "v1"),
        ))
        .expect("label binding");
    (scope_id, deps, gov, memory_a, memory_b)
}

/// One exact §17.3 checkpoint: the placement counters, the registry's live bindings and Qdrant's own count must
/// agree on the same number, so the gate cannot pass on a counter that merely looks plausible.
fn assert_placement_state(handle: &mut Handle, counters: (i64, i64), points: u64, why: &str) {
    assert_eq!(placement_counts(handle), counters, "{why}");
    assert_eq!(collection_point_count(handle), points, "{why}: Qdrant");
    assert_eq!(
        live_binding_count(handle),
        i64::try_from(points).expect("a count is positive"),
        "{why}: registry"
    );
}

/// G-M10-6 (§17.3, card M10-5): the placement counters are written from the worker's own successful point writes,
/// in the binding transaction, with no Qdrant count scan. After a known sequence — two upserts, one re-upsert of
/// an already-bound point, one delete and one revive — `point_count` is exactly the live binding count and
/// `bytes_estimate` exactly those bindings' dense bytes (the fixture embeds 4 dimensions, so 16 B per point).
/// The Qdrant-side count is asserted as ground truth at every step, never "non-empty".
/// Fault: count a re-upsert as new (`AlreadyRegistered` also moving `+1`) → red on the second counter assertion.
#[test]
fn point_count_written() {
    run_db_fixture::<Fixture, _>("point_count_written", |mut handle| {
        let (scope_id, deps, gov, memory_a, memory_b) = placement_gate_fixture(&mut handle);

        // n = 2 upserts.
        let outcome = handle
            .rt
            .block_on(run_once(&deps, 10))
            .expect("indexing pass");
        assert_eq!((outcome.done, outcome.failed), (2, 0), "{outcome:?}");
        assert_placement_state(&mut handle, (2, 32), 2, "two 4-d f32 vectors");

        // One re-upsert of an already-bound point: archive issues a lifecycle ticket and the worker rewrites the
        // SAME deterministic point id (the source identity did not change), so nothing new is counted.
        let point_a = point_id_for_memory(&mut handle, memory_a);
        archive_step(
            &mut handle,
            &deps,
            &gov,
            scope_id,
            memory_a,
            DestructiveOp::MemoryArchive,
        );
        assert_eq!(
            point_id_for_memory(&mut handle, memory_a),
            point_a,
            "the archive pass re-upserted the same point"
        );
        assert_placement_state(
            &mut handle,
            (2, 32),
            2,
            "a re-upsert of an existing point must not count twice",
        );

        // m = 1 delete: the supersede makes the source non-live and the retire pass deletes its point.
        let (auth, key) = (
            gov.scope(scope_id),
            governance_ops::stream(handle.tenant_id, scope_id),
        );
        governance_ops::supersede(&handle.rt, &handle.gateway, &auth, &key, memory_a, memory_b)
            .expect("supersede a");
        let outcome = handle
            .rt
            .block_on(run_once(&deps, 10))
            .expect("retire pass");
        assert_eq!((outcome.done, outcome.failed), (1, 0), "{outcome:?}");
        assert_placement_state(
            &mut handle,
            (1, 16),
            1,
            "the delete takes exactly its own point",
        );
        assert!(
            !point_present(&handle, point_a),
            "the superseded memory's point is gone"
        );

        // One revive: the restore brings the same binding back, which is one live point again.
        governance_ops::restore(&handle.rt, &handle.gateway, &auth, &key, memory_a)
            .expect("restore a");
        let outcome = handle
            .rt
            .block_on(run_once(&deps, 10))
            .expect("revive pass");
        assert_eq!((outcome.done, outcome.failed), (1, 0), "{outcome:?}");
        assert_placement_state(
            &mut handle,
            (2, 32),
            2,
            "a revived binding is a live point again",
        );
    });
}

/// §17.3 / ADR-0068: the legacy registration uses the registry's exact live source fence.
fn registration_for(
    handle: &mut Handle,
    scope_id: Uuid,
    label: &str,
    memory_id: Uuid,
) -> PrivateMemoryPointRegistration {
    let row = handle
        .admin
        .query_one(
            "SELECT (extract(epoch FROM updated_at) * 1000000)::bigint, \
                    sha256(convert_to(content::text, 'UTF8')) \
               FROM private.memory_records WHERE memory_id = $1",
            &[&memory_id],
        )
        .expect("the Memory row");
    let micros: i64 = row.get(0);
    let updated_at = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros) * 1_000)
        .expect("a valid timestamp");
    PrivateMemoryPointRegistration::deterministic(
        StreamFamily::new(
            TenantId(handle.tenant_id),
            "workspace",
            scope_id,
            "private_memory",
            "PRIVATE_MEMORY",
        ),
        "v1".to_owned(),
        label.to_owned(),
        MemoryId(memory_id),
        updated_at,
        row.get(1),
    )
}

/// §17.3: the single-point API retires exactly one binding and its label's dense bytes; replay moves nothing.
#[test]
fn point_count_single_retire() {
    run_db_fixture::<Fixture, _>("point_count_single_retire", |mut handle| {
        let (scope_id, deps, gov, memory_a, _memory_b) = placement_gate_fixture(&mut handle);
        let outcome = handle
            .rt
            .block_on(run_once(&deps, 10))
            .expect("indexing pass");
        assert_eq!((outcome.done, outcome.failed), (2, 0), "{outcome:?}");
        assert_eq!(placement_counts(&mut handle), (2, 32));
        let point = ProjectionPointId::new(point_id_for_memory(&mut handle, memory_a));
        let auth = gov.scope(scope_id);
        let retired = handle.rt.block_on(retire_private_memory_point(
            &deps.pool,
            &auth,
            &deps.family,
            &deps.projection_version,
            &deps.embedding_version,
            point,
        ));
        assert_eq!(retired.map_err(|error| error.to_string()), Ok(true));
        assert_eq!(
            placement_counts(&mut handle),
            (1, 16),
            "one retire subtracts exactly one point and 16 bytes"
        );
        assert_eq!(live_binding_count(&mut handle), 1);
        let replay = handle.rt.block_on(retire_private_memory_point(
            &deps.pool,
            &auth,
            &deps.family,
            &deps.projection_version,
            &deps.embedding_version,
            point,
        ));
        assert_eq!(replay.map_err(|error| error.to_string()), Ok(false));
        assert_eq!(
            placement_counts(&mut handle),
            (1, 16),
            "replay subtracts nothing"
        );
    });
}

/// §17.3: a reset placement still permits retirement, clamping both bookkeeping columns at zero.
#[test]
fn point_count_retire_clamps_at_zero() {
    run_db_fixture::<Fixture, _>("point_count_retire_clamps_at_zero", |mut handle| {
        let (scope_id, deps, gov, memory_a, _memory_b) = placement_gate_fixture(&mut handle);
        let outcome = handle
            .rt
            .block_on(run_once(&deps, 10))
            .expect("indexing pass");
        assert_eq!((outcome.done, outcome.failed), (2, 0), "{outcome:?}");
        assert_eq!(placement_counts(&mut handle), (2, 32));
        // §17.3: a promoted/re-onboarded placement can have reset bookkeeping while a binding remains live.
        assert_eq!(
            handle
                .admin
                .execute(
                    "UPDATE projection.tenant_placements SET point_count = 0, bytes_estimate = 0 \
                     WHERE tenant_id = $1 AND projection_family = 'private_memory_v1'",
                    &[&handle.tenant_id],
                )
                .expect("reset placement counters"),
            1
        );
        assert_eq!(placement_counts(&mut handle), (0, 0));
        let point = ProjectionPointId::new(point_id_for_memory(&mut handle, memory_a));
        let retired = handle.rt.block_on(retire_private_memory_point(
            &deps.pool,
            &gov.scope(scope_id),
            &deps.family,
            &deps.projection_version,
            &deps.embedding_version,
            point,
        ));
        assert_eq!(
            retired.map_err(|error| error.to_string()),
            Ok(true),
            "zero-clamped retirement must commit, not fail a nonnegative CHECK"
        );
        assert_eq!(
            placement_counts(&mut handle),
            (0, 0),
            "neither counter can become negative"
        );
        assert_eq!(
            live_binding_count(&mut handle),
            1,
            "the retirement committed"
        );
    });
}

/// §17.3: independent worker connections racing on one tenant must preserve both registration deltas.
#[test]
fn point_count_two_workers_one_tenant() {
    run_db_fixture::<Fixture, _>("point_count_two_workers_one_tenant", |mut handle| {
        let (scope_id, deps, gov, memory_a, memory_b) = placement_gate_fixture(&mut handle);
        let registration_a =
            registration_for(&mut handle, scope_id, &deps.embedding_version, memory_a);
        let registration_b =
            registration_for(&mut handle, scope_id, &deps.embedding_version, memory_b);
        assert_eq!(placement_counts(&mut handle), (0, 0));
        let auth = gov.scope(scope_id);
        let retrieval_dsn = std::env::var("HUMAUX_RETRIEVAL_WORKER_PG_DSN")
            .expect("HUMAUX_RETRIEVAL_WORKER_PG_DSN must be set for this test");
        let results = handle.rt.block_on(async {
            // dep: PostgreSQL(role_retrieval_worker) — a second independent pool, not a clone of worker one's pool.
            let second_pool = RetrievalWorkerDbPool::connect(&retrieval_dsn)
                .await
                .expect("second worker connects");
            let barrier = tokio::sync::Barrier::new(2);
            let (first, second) = tokio::time::timeout(Duration::from_secs(30), async {
                tokio::join!(
                    async {
                        barrier.wait().await;
                        register_private_memory_point(&deps.pool, &auth, &registration_a).await
                    },
                    async {
                        barrier.wait().await;
                        register_private_memory_point(&second_pool, &auth, &registration_b).await
                    },
                )
            })
            .await
            .expect("both concurrent registrations finish");
            [
                first.map_err(|error| error.to_string()),
                second.map_err(|error| error.to_string()),
            ]
        });
        assert_eq!(
            results,
            [
                Ok(RegistrationOutcome::Inserted),
                Ok(RegistrationOutcome::Inserted)
            ]
        );
        assert_eq!(
            placement_counts(&mut handle),
            (2, 32),
            "both vectorless registrations use the bound 4-d label width"
        );
        assert_eq!(live_binding_count(&mut handle), 2);
    });
}

/// ADR-0068 card 40d-1b-ii: the worker's note chunk path, asserted on real registry rows, real Qdrant points and the
/// inputs a provider spy actually received.
mod note_chunk_projection {
    use std::collections::HashMap;
    use std::sync::{Mutex, MutexGuard, PoisonError};

    use humaux_adapters::private_projection_registry::{
        PrivateMemoryPointRegistration, bind_embedding_fingerprint, worker_fingerprint_inputs,
    };
    use humaux_domain::authority::MemoryId;
    use humaux_domain::dataclass::DataClass;
    use humaux_domain::memory::MemoryType;
    use humaux_projection::card::{CardBuildOutcome, CardInput, EgressDisposition};
    use humaux_projection::note_chunks::{
        LEGACY_CARD_PROFILE_HASH, NOTE_CHUNKS_V1_PROFILE_HASH, NoteChunk, NoteChunkPolicy,
        PlanInput, ProjectionPlan, build_projection_plan, chunk_card,
    };

    use super::*;

    /// Synthetic GitHub-shaped fixture (`contribution_scan.rs`), not a credential.
    const FAKE_GITHUB_TOKEN: &str = "ghp_RkqFzVpLwNyHtBvDgXsWuCePjMoTnAiSyEkl";
    /// Synthetic PEM block, not a key: 191 scalars, longer than the 64-scalar window overlap, so placed across a
    /// window boundary it is whole in no chunk.
    const FAKE_PRIVATE_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
        MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn7ygWyF8PbnGy0AHB7MaB2EVgxMUA0nCnD\n\
        7gH1qGx3pQ8qkIq9vZ8wVNw4tFz2dG5bYvM1Kk3nE4cRpUe8lJ0sQ2yX9aTbW6fD\n\
        -----END RSA PRIVATE KEY-----";

    /// ADR-0068 D-I: the serving projection's policy row is global (no tenant column), so every test here holds this
    /// lock for its whole body; [`PolicyGuard`] puts back the hash it found when it drops, panics included.
    static POLICY_ROW: Mutex<()> = Mutex::new(());

    const POLICY_KEY: (&str, &str, &str) = ("private_memory", "PRIVATE_MEMORY", "v1");

    struct PolicyGuard {
        owner: Client,
        found: Option<String>,
        _lock: MutexGuard<'static, ()>,
    }

    impl PolicyGuard {
        fn hold() -> Self {
            let lock = POLICY_ROW.lock().unwrap_or_else(PoisonError::into_inner);
            let dsn = std::env::var("HUMAUX_TEST_PG_DSN").expect("the fixture is running");
            // dep: PostgreSQL(any) — the owner client that reads and flips the global policy row
            let mut owner = Client::connect(&dsn, NoTls).expect("owner connects");
            let found = owner
                .query_one(
                    "SELECT note_chunk_profile_hash FROM projection.card_profile_policies \
                     WHERE domain = $1 AND projection_kind = $2 AND projection_version = $3",
                    &[&POLICY_KEY.0, &POLICY_KEY.1, &POLICY_KEY.2],
                )
                .expect("migration 0238 seeds the serving projection's row")
                .get(0);
            Self {
                owner,
                found,
                _lock: lock,
            }
        }

        fn set(&mut self, hash: Option<&str>) -> Result<u64, postgres::Error> {
            self.owner.execute(
                "UPDATE projection.card_profile_policies SET note_chunk_profile_hash = $4 \
                 WHERE domain = $1 AND projection_kind = $2 AND projection_version = $3",
                &[&POLICY_KEY.0, &POLICY_KEY.1, &POLICY_KEY.2, &hash],
            )
        }

        fn enable(&mut self) {
            assert_eq!(
                self.set(Some(NOTE_CHUNKS_V1_PROFILE_HASH)).expect("enable"),
                1
            );
        }
    }

    impl Drop for PolicyGuard {
        fn drop(&mut self) {
            let found = self.found.clone();
            if let Err(error) = self.set(found.as_deref()) {
                eprintln!("note_chunk_projection: the policy row was not restored: {error}");
            }
        }
    }

    /// The provider spy: every input the worker sends, with the Memory it serves, before the real test double.
    struct Spy {
        inner: TestEmbedder,
        seen: Mutex<Vec<(Uuid, String)>>,
    }

    impl Spy {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: TestEmbedder(Arc::new(TestDoubleProvider::new(
                    embedding_model(),
                    unused_rerank_model(),
                ))),
                seen: Mutex::new(Vec::new()),
            })
        }

        fn seen(&self) -> Vec<(Uuid, String)> {
            self.seen.lock().expect("spy").clone()
        }
    }

    #[async_trait]
    impl CardEmbedder for Spy {
        async fn embed_cards(
            &self,
            tenant_id: TenantId,
            dimension: u32,
            cards: &[SealedRetrievalCard],
            memory_ids: &[Uuid],
        ) -> Result<Vec<Vec<f32>>, ErrorCode> {
            self.seen.lock().expect("spy").extend(
                memory_ids
                    .iter()
                    .copied()
                    .zip(cards.iter().map(|card| card.as_str().to_owned())),
            );
            self.inner
                .embed_cards(tenant_id, dimension, cards, memory_ids)
                .await
        }
    }

    /// Forwards to the real transport, except that the upsert carrying `fail_upsert` answers 503 (a transient Qdrant
    /// failure of exactly that slot) and a visibility probe never reports `hide` (that slot is not yet visible).
    struct SlotFault {
        inner: Arc<HttpIntraCellTransport>,
        fail_upsert: Option<Uuid>,
        hide: Option<Uuid>,
    }

    #[async_trait]
    impl IntraCellHttpTransport for SlotFault {
        async fn execute(
            &self,
            permit: &CellAccessPermit,
            request: IntraCellRequest,
        ) -> Result<IntraCellResponse, IntraCellError> {
            let is_upsert = matches!(request.method, IntraCellMethod::Put)
                && request.path.contains("/points")
                && !request.path.contains("/points/");
            let carries = |id: Uuid| {
                request
                    .json_body
                    .as_ref()
                    .and_then(|body| body["points"].as_array())
                    .is_some_and(|points| {
                        points
                            .iter()
                            .any(|point| point["id"] == serde_json::json!(id.to_string()))
                    })
            };
            if is_upsert && self.fail_upsert.is_some_and(carries) {
                return Ok(IntraCellResponse {
                    status: 503,
                    json_body: None,
                });
            }
            let is_scroll = request.path.ends_with("/points/scroll");
            let mut response = self.inner.execute(permit, request).await?;
            if let (true, Some(hide), Some(body)) =
                (is_scroll, self.hide, response.json_body.as_mut())
                && let Some(points) = body["result"]["points"].as_array_mut()
            {
                points.retain(|point| point["id"] != serde_json::json!(hide.to_string()));
            }
            Ok(response)
        }
    }

    /// `len` ASCII scalars of distinct, secret-free words (`w0 w1 w2 …`), so no two windows share text.
    fn prose(len: usize) -> String {
        let mut text = String::new();
        let mut word = 0_usize;
        while text.len() < len {
            text.push_str(&format!("w{word} "));
            word += 1;
        }
        text.truncate(len);
        text
    }

    /// One identity note in `scope_id`: the fixture's Evidence + Memory, its content made a note's (`title`,
    /// `key_claim` = the body, ADR-0067 D-E) and the identity contract naming the Memory as the Evidence's output.
    fn seed_note(handle: &mut Handle, scope_id: Uuid, title: &str, body: &str) -> (i64, Uuid) {
        let (seq, memory_id) = seed_memory_with_visibility(
            handle,
            scope_id,
            &format!("note evidence {}", Uuid::new_v4()),
            "TENANT_SHARED",
            None,
            None,
        );
        let body_sha256 = Sha256::digest(body.as_bytes()).to_vec();
        let mut txn = handle.admin.transaction().expect("owner transaction");
        txn.execute(
            "UPDATE private.memory_records SET content = $2 WHERE memory_id = $1",
            &[
                &memory_id,
                &serde_json::json!({ "title": title, "key_claim": body }),
            ],
        )
        .expect("make the Memory a note");
        txn.execute(
            "INSERT INTO private.identity_note_materializations \
               (tenant_id, evidence_id, strategy, output_memory_id, body_sha256, policy_version) \
             SELECT m.tenant_id, me.evidence_id, 'identity_note_v1', m.memory_id, $2, 'origin_ceiling_v1' \
               FROM private.memory_records m JOIN private.memory_evidence me ON me.memory_id = m.memory_id \
              WHERE m.memory_id = $1",
            &[&memory_id, &body_sha256],
        )
        .expect("bind the identity contract");
        txn.commit().expect("commit the note");
        (seq, memory_id)
    }

    /// The `CardInput` fields the worker's `card_input` reads for a note (`title`, `key_claim`, no excerpt, INTERNAL
    /// evidence); `card_text` depends on nothing else.
    fn note_input(memory_id: Uuid, title: &str, body: &str) -> CardInput {
        CardInput {
            memory_id: MemoryId(memory_id),
            memory_type: MemoryType::Note,
            data_class: DataClass::Internal,
            egress_disposition: EgressDisposition::Allowed,
            workspace_id: None,
            topic: None,
            effective_from: std::time::SystemTime::UNIX_EPOCH,
            title: title.to_owned(),
            key_claim: Some(body.to_owned()),
            entities: Vec::new(),
            evidence_excerpt: None,
        }
    }

    /// The legacy card text of `card` under the legacy-only policy.
    fn legacy_text(card: CardInput, is_identity_note: bool) -> String {
        match build_projection_plan(PlanInput {
            card,
            is_identity_note,
            policy: NoteChunkPolicy::LegacyOnly,
        }) {
            ProjectionPlan::LegacyCardV1(CardBuildOutcome::Card(card)) => card.card_text,
            other => panic!("a legacy-only policy builds the legacy card: {other:?}"),
        }
    }

    /// The note's chunks under the `NoteChunksV1` policy.
    fn chunks(card: CardInput) -> Vec<NoteChunk> {
        match build_projection_plan(PlanInput {
            card,
            is_identity_note: true,
            policy: NoteChunkPolicy::NoteChunksV1,
        }) {
            ProjectionPlan::NoteChunksV1(chunks) => chunks,
            other => panic!("a long note under NoteChunksV1 is chunked: {other:?}"),
        }
    }

    /// `projection.note_chunk_count` — the SQL count the ledger uses (migration 0237).
    fn sql_chunk_count(handle: &mut Handle, title: &str, body: &str) -> u32 {
        let count: i32 = handle
            .admin
            .query_one(
                "SELECT projection.note_chunk_count($1, $2)",
                &[&title, &body],
            )
            .expect("the 0237 count")
            .get(0);
        u32::try_from(count).expect("a count is positive")
    }

    /// The worker's deps under a label of this test's own, bound as the retrieval worker binds its label at boot, so
    /// every vector is stored (ADR-0064 D-B) and the derived point ids are this test's alone. Returns the
    /// fingerprint.
    fn labeled_deps(
        handle: &Handle,
        scope_id: Uuid,
        spy: &Arc<Spy>,
    ) -> (ProjectionWorkerDeps, [u8; 32]) {
        let provider = Arc::new(TestDoubleProvider::new(
            embedding_model(),
            unused_rerank_model(),
        ));
        let mut deps = handle.rt.block_on(deps_for(handle, scope_id, provider));
        deps.embedding_version = format!("c40d-{}", Uuid::new_v4().simple());
        let fingerprint = handle
            .rt
            .block_on(bind_embedding_fingerprint(
                &deps.pool,
                &deps.embedding_version,
                &worker_fingerprint_inputs("c40d-test", &deps.embedding_version, "r1", 4, "v1"),
            ))
            .expect("label binding")
            .0;
        deps.embedder = spy.clone();
        (deps, fingerprint)
    }

    /// The v2 ids of a note's `count` chunk slots.
    fn chunk_ids(legacy: &PrivateMemoryPointRegistration, count: u32) -> Vec<Uuid> {
        (0..count)
            .map(|ordinal| {
                legacy
                    .clone()
                    .for_chunk(NOTE_CHUNKS_V1_PROFILE_HASH, ordinal)
                    .point_id
                    .as_uuid()
            })
            .collect()
    }

    /// One registry row: `(point_id, card_profile_hash, chunk_ordinal, input_sha256, fingerprint_sha256, live)`.
    type SlotRow = (Uuid, String, i32, Option<Vec<u8>>, Option<Vec<u8>>, bool);

    fn slot_rows(handle: &mut Handle, memory_id: Uuid) -> Vec<SlotRow> {
        handle
            .admin
            .query(
                "SELECT point_id, card_profile_hash, chunk_ordinal, input_sha256, fingerprint_sha256, \
                        projection_live \
                   FROM projection.private_memory_points WHERE memory_id = $1 \
                  ORDER BY card_profile_hash, chunk_ordinal",
                &[&memory_id],
            )
            .expect("registry rows")
            .iter()
            .map(|row| {
                (
                    row.get(0),
                    row.get(1),
                    row.get(2),
                    row.get(3),
                    row.get(4),
                    row.get(5),
                )
            })
            .collect()
    }

    /// `(chunk_ordinal, card_profile_hash)` of every point among `ids` present in the collection.
    fn indexed(handle: &Handle, ids: &[Uuid]) -> HashMap<Uuid, (Option<i64>, Option<String>)> {
        let scrolled = scroll_payloads(handle, &admin_permit(handle), ids);
        scrolled["result"]["points"]
            .as_array()
            .expect("scroll points")
            .iter()
            .map(|point| {
                let id = point["id"]
                    .as_str()
                    .and_then(|id| id.parse().ok())
                    .expect("a uuid point id");
                let payload = &point["payload"];
                (
                    id,
                    (
                        payload["chunk_ordinal"].as_i64(),
                        payload["card_profile_hash"].as_str().map(str::to_owned),
                    ),
                )
            })
            .collect()
    }

    /// The `memory_id` payload of every point among `ids` present in the collection.
    fn payload_memory_ids(handle: &Handle, ids: &[Uuid]) -> HashMap<Uuid, Option<String>> {
        let scrolled = scroll_payloads(handle, &admin_permit(handle), ids);
        scrolled["result"]["points"]
            .as_array()
            .expect("scroll points")
            .iter()
            .map(|point| {
                let id = point["id"]
                    .as_str()
                    .and_then(|id| id.parse().ok())
                    .expect("a uuid point id");
                (
                    id,
                    point["payload"]["memory_id"].as_str().map(str::to_owned),
                )
            })
            .collect()
    }

    fn key(
        handle: &Handle,
        scope_id: Uuid,
    ) -> (
        Uuid,
        &'static str,
        Uuid,
        &'static str,
        &'static str,
        &'static str,
    ) {
        (
            handle.tenant_id,
            "workspace",
            scope_id,
            "private_memory",
            "PRIVATE_MEMORY",
            "v1",
        )
    }

    fn run(handle: &Handle, deps: &ProjectionWorkerDeps) -> (u64, u64, u64) {
        let outcome = handle.rt.block_on(run_once(deps, 10)).expect("run_once");
        (outcome.done, outcome.failed, outcome.retried)
    }

    /// ADR-0068 gate `legacy_cards_are_byte_identical_end_to_end`: with the seeded policy (NULL = legacy only), a long
    /// note and an ordinary memory each register exactly one point — the v1 id `deterministic` derives, the legacy
    /// card's `input_sha256`, the label's fingerprint, a payload with no chunk field — and the provider spy sees
    /// exactly the two legacy card texts. Fault: plan under `NoteChunksV1` regardless of the row (or drop the policy
    /// term from `build_projection_plan`) ⇒ the note gets chunk rows and chunk inputs ⇒ red.
    #[test]
    fn legacy_cards_are_byte_identical_end_to_end() {
        run_db_fixture::<Fixture, _>(
            "legacy_cards_are_byte_identical_end_to_end",
            |mut handle| {
                let guard = PolicyGuard::hold();
                assert_eq!(
                    guard.found, None,
                    "migration 0238 seeds the row legacy only"
                );
                let scope_id = Uuid::new_v4();
                let title = "a long verbatim note";
                let body = prose(2_000);
                let (_, note) = seed_note(&mut handle, scope_id, title, &body);
                let fact_text = "an ordinary memory beside the note";
                let (_, fact) = seed_memory_with_visibility(
                    &mut handle,
                    scope_id,
                    fact_text,
                    "TENANT_SHARED",
                    None,
                    None,
                );
                let spy = Spy::new();
                let (deps, fingerprint) = labeled_deps(&handle, scope_id, &spy);
                assert_eq!(run(&handle, &deps), (2, 0, 0));

                let fact_card = CardInput {
                    title: format!("title: {fact_text}"),
                    key_claim: Some(format!("key claim: {fact_text}")),
                    evidence_excerpt: Some(fact_text.to_owned()),
                    ..note_input(fact, "", "")
                };
                let mut expected_inputs = vec![
                    (note, legacy_text(note_input(note, title, &body), true)),
                    (fact, legacy_text(fact_card, false)),
                ];
                for (memory_id, text) in &expected_inputs {
                    let legacy = registration_for(
                        &mut handle,
                        scope_id,
                        &deps.embedding_version,
                        *memory_id,
                    );
                    let id = legacy.point_id.as_uuid();
                    assert_eq!(
                        slot_rows(&mut handle, *memory_id),
                        vec![(
                            id,
                            LEGACY_CARD_PROFILE_HASH.to_owned(),
                            0,
                            Some(Sha256::digest(text.as_bytes()).to_vec()),
                            Some(fingerprint.to_vec()),
                            true,
                        )],
                        "{memory_id}: one legacy slot, v1 id, legacy input, the label's fingerprint"
                    );
                    assert_eq!(
                        indexed(&handle, &[id]).get(&id),
                        Some(&(None, None)),
                        "{memory_id}: a legacy payload carries no chunk field"
                    );
                }
                let mut seen = spy.seen();
                seen.sort();
                expected_inputs.sort();
                assert_eq!(
                    seen, expected_inputs,
                    "the provider saw exactly the legacy inputs"
                );
                assert_eq!(collection_point_count(&handle), 2);
            },
        );
    }

    /// ADR-0068 gate `long_note_is_projected_as_chunks`: under `NoteChunksV1` a long note registers C slots (C from
    /// the SQL count the ledger uses), ordinals 0..C-1 with the v2 ids `for_chunk` derives, each slot's input the
    /// plan's chunk text, one Qdrant point per slot carrying its ordinal and profile, and the ticket is DONE. Faults:
    /// register every slot under the v1 id (no `for_chunk`) ⇒ the registry refuses the second slot ⇒ not DONE ⇒ red;
    /// drop `with_chunk` ⇒ red on the payload.
    #[test]
    fn long_note_is_projected_as_chunks() {
        run_db_fixture::<Fixture, _>("long_note_is_projected_as_chunks", |mut handle| {
            let mut guard = PolicyGuard::hold();
            guard.enable();
            let scope_id = Uuid::new_v4();
            let title = "a long verbatim note";
            let body = prose(2_000);
            let (seq, note) = seed_note(&mut handle, scope_id, title, &body);
            let count = sql_chunk_count(&mut handle, title, &body);
            assert!(count > 1, "the fixture note is long");
            let spy = Spy::new();
            let (deps, fingerprint) = labeled_deps(&handle, scope_id, &spy);
            assert_eq!(run(&handle, &deps), (1, 0, 0));
            let key = key(&handle, scope_id);
            assert_eq!(stream_log_state(&mut handle, &key, seq), "DONE");

            let legacy = registration_for(&mut handle, scope_id, &deps.embedding_version, note);
            let ids = chunk_ids(&legacy, count);
            assert!(
                !ids.contains(&legacy.point_id.as_uuid()),
                "no chunk takes the v1 id"
            );
            let plan = chunks(note_input(note, title, &body));
            assert_eq!(plan.len(), count as usize, "Rust and SQL agree on C");
            let rows = slot_rows(&mut handle, note);
            assert_eq!(rows.len(), count as usize, "{rows:?}");
            let indexed = indexed(&handle, &ids);
            for (ordinal, (row, chunk)) in rows.iter().zip(&plan).enumerate() {
                assert_eq!(
                    row,
                    &(
                        ids[ordinal],
                        NOTE_CHUNKS_V1_PROFILE_HASH.to_owned(),
                        i32::try_from(ordinal).expect("ordinal"),
                        Some(Sha256::digest(chunk.text.as_bytes()).to_vec()),
                        Some(fingerprint.to_vec()),
                        true,
                    ),
                    "slot {ordinal}"
                );
                assert_eq!(
                    indexed.get(&ids[ordinal]),
                    Some(&(
                        Some(i64::try_from(ordinal).expect("ordinal")),
                        Some(NOTE_CHUNKS_V1_PROFILE_HASH.to_owned())
                    )),
                    "point {ordinal}"
                );
            }
            assert_eq!(collection_point_count(&handle), u64::from(count));
            let mut seen: Vec<String> = spy.seen().into_iter().map(|(_, text)| text).collect();
            let mut expected: Vec<String> = plan.into_iter().map(|chunk| chunk.text).collect();
            seen.sort();
            expected.sort();
            assert_eq!(seen, expected, "the provider saw each chunk text once");
        });
    }

    /// ADR-0068 gate `repeated_chunk_text_embeds_once`: a body of `W + 3 × stride` identical scalars has four slots
    /// with one card text, so the provider gets one input, the four slots share one stored vector row (vector key =
    /// memory, fingerprint, input) and remain four points. Fault: embed per slot instead of per distinct key ⇒ four
    /// provider inputs ⇒ red.
    #[test]
    fn repeated_chunk_text_embeds_once() {
        run_db_fixture::<Fixture, _>("repeated_chunk_text_embeds_once", |mut handle| {
            let mut guard = PolicyGuard::hold();
            guard.enable();
            let scope_id = Uuid::new_v4();
            let title = "a repetitive note";
            let body = "z".repeat(480 + 3 * 416);
            let (_, note) = seed_note(&mut handle, scope_id, title, &body);
            let count = sql_chunk_count(&mut handle, title, &body);
            assert_eq!(count, 4);
            let spy = Spy::new();
            let (deps, _) = labeled_deps(&handle, scope_id, &spy);
            assert_eq!(run(&handle, &deps), (1, 0, 0));

            let seen = spy.seen();
            assert_eq!(
                seen.len(),
                1,
                "one provider input for four identical windows"
            );
            assert!(seen.len() < count as usize);
            let rows = slot_rows(&mut handle, note);
            assert_eq!(rows.len(), count as usize, "{rows:?}");
            let inputs: BTreeSet<_> = rows.iter().map(|row| row.3.clone()).collect();
            assert_eq!(inputs.len(), 1, "every slot keys the same input");
            let points: BTreeSet<Uuid> = rows.iter().map(|row| row.0).collect();
            assert_eq!(points.len(), count as usize, "distinct points");
            let vectors: i64 = handle
                .admin
                .query_one(
                    "SELECT count(*) FROM projection.memory_vectors \
                      WHERE memory_id = $1 AND vector IS NOT NULL",
                    &[&note],
                )
                .expect("vector rows")
                .get(0);
            assert_eq!(vectors, 1, "duplicate slots share one vector row");
            assert_eq!(collection_point_count(&handle), u64::from(count));
        });
    }

    /// ADR-0068 gate `source_seal_blocks_a_secret_anywhere` (D-G). Three tickets: a long note whose token sits only
    /// in its last window, a long note whose PEM block straddles a window boundary so that no chunk holds it whole
    /// (precondition, with the real scanner: every chunk card seals clean and the whole source does not), and an
    /// ordinary memory with the token (the legacy path). All three end `FAILED secret_scan_rejected` with no
    /// registry row, no point and zero provider inputs. Faults: skip `seal_source` ⇒ the straddling note's chunks
    /// seal clean and are embedded ⇒ DONE ⇒ red.
    #[test]
    fn source_seal_blocks_a_secret_anywhere() {
        run_db_fixture::<Fixture, _>("source_seal_blocks_a_secret_anywhere", |mut handle| {
            let mut guard = PolicyGuard::hold();
            guard.enable();
            let scope_id = Uuid::new_v4();
            let title = "a long note with a secret";
            let tail_body = format!("{}{FAKE_GITHUB_TOKEN}", prose(480 + 3 * 416 + 200 - 40));
            let straddle_body = format!("{}{FAKE_PRIVATE_KEY} {}", prose(415), prose(700));
            let (tail_seq, tail) = seed_note(&mut handle, scope_id, title, &tail_body);
            let (straddle_seq, straddle) = seed_note(&mut handle, scope_id, title, &straddle_body);
            let (legacy_seq, legacy) = seed_memory_with_visibility(
                &mut handle,
                scope_id,
                &format!("the CI bot uses {FAKE_GITHUB_TOKEN} for releases"),
                "TENANT_SHARED",
                None,
                None,
            );

            let tail_chunks = chunks(note_input(tail, title, &tail_body));
            let holding: Vec<usize> = tail_chunks
                .iter()
                .filter(|chunk| chunk.text.contains(FAKE_GITHUB_TOKEN))
                .map(|chunk| chunk.chunk_ordinal)
                .collect();
            assert_eq!(
                holding,
                vec![tail_chunks.len() - 1],
                "the token is in the last window only"
            );
            let straddle_input = note_input(straddle, title, &straddle_body);
            for chunk in chunks(straddle_input.clone()) {
                assert!(
                    !chunk.text.contains(FAKE_PRIVATE_KEY),
                    "chunk {} holds the block",
                    chunk.chunk_ordinal
                );
                assert!(
                    handle
                        .scanner
                        .seal_card(&chunk_card(&straddle_input, &chunk))
                        .is_ok(),
                    "precondition: chunk {} seals clean on its own",
                    chunk.chunk_ordinal
                );
            }
            assert_eq!(
                handle
                    .scanner
                    .seal_source(straddle, DataClass::Internal, title, &straddle_body)
                    .map(|_| ()),
                Err(ErrorCode::Forbidden),
                "precondition: the whole source holds the block"
            );

            let spy = Spy::new();
            let (deps, _) = labeled_deps(&handle, scope_id, &spy);
            assert_eq!(run(&handle, &deps), (0, 3, 0));
            let key = key(&handle, scope_id);
            for (seq, memory_id) in [
                (tail_seq, tail),
                (straddle_seq, straddle),
                (legacy_seq, legacy),
            ] {
                assert_eq!(
                    (
                        stream_log_state(&mut handle, &key, seq),
                        stream_log_error_class(&mut handle, &key, seq)
                    ),
                    ("FAILED".to_owned(), Some("secret_scan_rejected".to_owned())),
                    "{memory_id}: the legacy secret disposition"
                );
                assert!(
                    slot_rows(&mut handle, memory_id).is_empty(),
                    "{memory_id}: no slot"
                );
            }
            assert!(spy.seen().is_empty(), "no provider input at all");
            assert_eq!(collection_point_count(&handle), 0);
        });
    }

    /// ADR-0068 gate `legacy_point_retired_only_with_last_chunk` (D-I): a long note projected legacy-only keeps its
    /// legacy point through a chunk re-projection whose last slot fails, and loses it in the pass that settles every
    /// slot. Two midway arms: the last slot's upsert fails, then every slot is written but the last one is not yet
    /// visible. Faults: retire the legacy point before the slots are written ⇒ red on the first midway arm; retire it
    /// before the visibility check (or drop that check) ⇒ red on the hidden arm; skip the retirement ⇒ red on the
    /// final arm.
    #[test]
    fn legacy_point_retired_only_with_last_chunk() {
        run_db_fixture::<Fixture, _>("legacy_point_retired_only_with_last_chunk", |mut handle| {
            let mut guard = PolicyGuard::hold();
            let gov = Governor::seed(&mut handle.admin, handle.tenant_id);
            let scope_id = seed_workspace(&mut handle);
            gov.join(&mut handle.admin, scope_id);
            let title = "a note projected before chunking";
            let body = prose(1_500);
            let (_, note) = seed_note(&mut handle, scope_id, title, &body);
            let spy = Spy::new();
            let (mut deps, _) = labeled_deps(&handle, scope_id, &spy);
            assert_eq!(run(&handle, &deps), (1, 0, 0), "legacy-only projection");
            let legacy_id = registration_for(&mut handle, scope_id, &deps.embedding_version, note)
                .point_id
                .as_uuid();
            assert!(point_live(&mut handle, legacy_id) && point_present(&handle, legacy_id));

            guard.enable();
            let archived = governance_ops::archive(
                &handle.rt,
                &handle.gateway,
                &gov.scope(scope_id),
                &governance_ops::stream(handle.tenant_id, scope_id),
                note,
                DestructiveOp::MemoryArchive,
            )
            .expect("a lifecycle ticket through the real op");
            assert!(matches!(archived, ArchiveResult::Done(_)), "{archived:?}");
            let count = sql_chunk_count(&mut handle, title, &body);
            let legacy = registration_for(&mut handle, scope_id, &deps.embedding_version, note);
            assert_eq!(
                legacy.point_id.as_uuid(),
                legacy_id,
                "archive keeps the source fence"
            );
            let ids = chunk_ids(&legacy, count);
            let last = *ids.last().expect("C >= 1");

            deps.transport = Arc::new(SlotFault {
                inner: handle.transport.clone(),
                fail_upsert: Some(last),
                hide: None,
            });
            assert_eq!(run(&handle, &deps), (0, 0, 1), "the last slot failed");
            assert!(
                point_live(&mut handle, legacy_id),
                "midway: the legacy binding is live"
            );
            assert!(
                point_present(&handle, legacy_id),
                "midway: the legacy point answers recall"
            );
            let midway = slot_rows(&mut handle, note);
            assert_eq!(
                midway
                    .iter()
                    .filter(|row| row.1 == NOTE_CHUNKS_V1_PROFILE_HASH)
                    .count(),
                count as usize - 1,
                "every slot but the last: {midway:?}"
            );

            deps.transport = Arc::new(SlotFault {
                inner: handle.transport.clone(),
                fail_upsert: None,
                hide: Some(last),
            });
            assert_eq!(
                run(&handle, &deps),
                (0, 0, 1),
                "every slot written, the last not yet visible"
            );
            assert!(
                point_live(&mut handle, legacy_id),
                "hidden: the legacy binding is live"
            );
            assert!(
                point_present(&handle, legacy_id),
                "hidden: the legacy point answers recall"
            );

            deps.transport = handle.transport.clone();
            assert_eq!(
                run(&handle, &deps),
                (1, 0, 0),
                "the retry settles every slot"
            );
            assert!(
                !point_live(&mut handle, legacy_id),
                "the legacy binding retired"
            );
            assert!(
                !point_present(&handle, legacy_id),
                "the legacy point left the index"
            );
            let settled = slot_rows(&mut handle, note);
            let live_chunks: Vec<Uuid> = settled
                .iter()
                .filter(|row| row.1 == NOTE_CHUNKS_V1_PROFILE_HASH && row.5)
                .map(|row| row.0)
                .collect();
            assert_eq!(live_chunks, ids, "every chunk slot is live");
            assert!(ids.iter().all(|id| point_present(&handle, *id)));
        });
    }

    /// ADR-0068 gate `partial_chunks_are_not_done` (D-F): one slot's upsert failing, or one slot's point never seen
    /// by the visibility probe, leaves the ticket ISSUED (retry), never DONE; the same ticket with every slot written
    /// and visible is DONE. Faults: verify only the first slot's point ⇒ red on the hidden arm; count a
    /// memory DONE after its first slot ⇒ red on the upsert arm.
    #[test]
    fn partial_chunks_are_not_done() {
        run_db_fixture::<Fixture, _>("partial_chunks_are_not_done", |mut handle| {
            let mut guard = PolicyGuard::hold();
            guard.enable();
            let scope_id = Uuid::new_v4();
            let title = "a long note";
            let body = prose(1_500);
            let (seq, note) = seed_note(&mut handle, scope_id, title, &body);
            let count = sql_chunk_count(&mut handle, title, &body);
            let spy = Spy::new();
            let (mut deps, _) = labeled_deps(&handle, scope_id, &spy);
            let ids = chunk_ids(
                &registration_for(&mut handle, scope_id, &deps.embedding_version, note),
                count,
            );
            let key = key(&handle, scope_id);
            for (fail_upsert, hide, class, registered) in [
                (Some(ids[1]), None, "qdrant_upsert_failed", 1),
                (
                    None,
                    Some(ids[2]),
                    "visibility_not_confirmed",
                    count as usize,
                ),
            ] {
                deps.transport = Arc::new(SlotFault {
                    inner: handle.transport.clone(),
                    fail_upsert,
                    hide,
                });
                assert_eq!(run(&handle, &deps), (0, 0, 1), "{class}");
                assert_eq!(
                    (
                        stream_log_state(&mut handle, &key, seq),
                        stream_log_error_class(&mut handle, &key, seq)
                    ),
                    ("ISSUED".to_owned(), Some(class.to_owned()))
                );
                assert!(slot_rows(&mut handle, note).len() >= registered, "{class}");
            }
            deps.transport = handle.transport.clone();
            assert_eq!(
                run(&handle, &deps),
                (1, 0, 0),
                "control: every slot written and visible"
            );
            assert_eq!(stream_log_state(&mut handle, &key, seq), "DONE");
        });
    }

    /// The five `projection.stream_point_ledger` readings (expected, settled, in flight, unsettled, retiring) of the
    /// test family, read as role_gateway the way `stream_repo::close_ledger_in_txn` reads them (tenant GUC, a reader
    /// whose §6.1 visibility admits the TENANT_SHARED memories seeded here).
    fn ledger_slots(handle: &mut Handle, scope_id: Uuid) -> (i64, i64, i64, i64, i64) {
        let (tenant_id, scope_kind, scope_id, domain, kind, version) = key(handle, scope_id);
        let mut txn = handle.admin.transaction().expect("ledger read txn");
        // dep: PostgreSQL(role_gateway) — role switch for the definer call (the visible_index_count pattern)
        txn.batch_execute(&format!(
            "SET LOCAL ROLE role_gateway; SET LOCAL humaux.tenant_id = '{tenant_id}'; \
             SET LOCAL humaux.user_id = '{}';",
            Uuid::new_v4()
        ))
        .expect("act as role_gateway");
        let row = txn
            .query_one(
                "SELECT points_expected, points_settled, points_in_flight, points_unsettled, points_retiring \
                 FROM projection.stream_point_ledger($1, $2, $3, $4, $5, $6, 'SECRET_MATERIAL', $7)",
                &[
                    &tenant_id,
                    &scope_kind,
                    &scope_id,
                    &domain,
                    &kind,
                    &version,
                    &vec![scope_id],
                ],
            )
            .expect("point ledger");
        txn.rollback().expect("read only");
        (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4))
    }

    /// ADR-0068 gate `ledger_counts_unbuilt_chunk_slots` (D-D, D-I). A long note and an ordinary memory projected
    /// legacy-only read v2's numbers. Enabling the policy, with nothing re-projected, makes the note C expected slots
    /// with 0 built: the gap is unsettled (never settled) and its live legacy point is retiring. The re-projection
    /// that settles every chunk retires the legacy point and settles 1 + C. Faults: count a Memory as one slot ⇒ red
    /// on the enabled arm; settle a chunked Memory by its DONE ticket instead of its built slots ⇒ red there too; drop
    /// the gap from unsettled, or the retiring term ⇒ red there too.
    #[test]
    fn ledger_counts_unbuilt_chunk_slots() {
        run_db_fixture::<Fixture, _>("ledger_counts_unbuilt_chunk_slots", |mut handle| {
            let mut guard = PolicyGuard::hold();
            let gov = Governor::seed(&mut handle.admin, handle.tenant_id);
            let scope_id = seed_workspace(&mut handle);
            gov.join(&mut handle.admin, scope_id);
            let title = "a note projected before chunking";
            let body = prose(1_500);
            let (_, note) = seed_note(&mut handle, scope_id, title, &body);
            seed_memory_with_visibility(
                &mut handle,
                scope_id,
                "an ordinary memory beside the note",
                "TENANT_SHARED",
                None,
                None,
            );
            let spy = Spy::new();
            let (deps, _) = labeled_deps(&handle, scope_id, &spy);
            assert_eq!(run(&handle, &deps), (2, 0, 0), "legacy-only projection");
            assert_eq!(
                ledger_slots(&mut handle, scope_id),
                (2, 2, 0, 0, 0),
                "legacy only: one slot per memory, v2's numbers"
            );

            guard.enable();
            let count = i64::from(sql_chunk_count(&mut handle, title, &body));
            assert!(count > 1, "the note is over the legacy capacity");
            assert_eq!(
                ledger_slots(&mut handle, scope_id),
                (1 + count, 1, 0, count, 1),
                "enabled, nothing re-projected: C expected, 0 built, the gap unsettled, the legacy point retiring"
            );

            let archived = governance_ops::archive(
                &handle.rt,
                &handle.gateway,
                &gov.scope(scope_id),
                &governance_ops::stream(handle.tenant_id, scope_id),
                note,
                DestructiveOp::MemoryArchive,
            )
            .expect("a lifecycle ticket through the real op");
            assert!(matches!(archived, ArchiveResult::Done(_)), "{archived:?}");
            assert_eq!(run(&handle, &deps), (1, 0, 0), "the chunk re-projection");
            assert_eq!(
                ledger_slots(&mut handle, scope_id),
                (1 + count, 1 + count, 0, 0, 0),
                "every chunk slot built and settled, the legacy point retired"
            );
        });
    }

    /// ADR-0068 gate `partial_projection_does_not_settle_memory` (D-D): under `NoteChunksV1` a note whose last slot's
    /// upsert fails, or whose last slot is written but not yet visible, has C - 1 slots registered and settles none of
    /// them: its C slots are in flight until the ticket is DONE, then all C settle. Faults: settle a chunked Memory by
    /// its registered slots whatever its latest ticket ⇒ C - 1 settled on both midway arms ⇒ red; count it as one
    /// slot ⇒ red on every arm.
    #[test]
    fn partial_projection_does_not_settle_memory() {
        run_db_fixture::<Fixture, _>("partial_projection_does_not_settle_memory", |mut handle| {
            let mut guard = PolicyGuard::hold();
            guard.enable();
            let scope_id = Uuid::new_v4();
            let title = "a long note";
            let body = prose(1_500);
            let (_, note) = seed_note(&mut handle, scope_id, title, &body);
            let count = sql_chunk_count(&mut handle, title, &body);
            let spy = Spy::new();
            let (mut deps, _) = labeled_deps(&handle, scope_id, &spy);
            let ids = chunk_ids(
                &registration_for(&mut handle, scope_id, &deps.embedding_version, note),
                count,
            );
            let last = *ids.last().expect("C >= 1");
            let slots = i64::from(count);
            for (fail_upsert, hide, arm) in [
                (Some(last), None, "the last upsert failed"),
                (None, Some(last), "the last slot is not yet visible"),
            ] {
                deps.transport = Arc::new(SlotFault {
                    inner: handle.transport.clone(),
                    fail_upsert,
                    hide,
                });
                assert_eq!(run(&handle, &deps), (0, 0, 1), "{arm}");
                assert!(
                    slot_rows(&mut handle, note).len() >= count as usize - 1,
                    "{arm}: C - 1 slots registered at least"
                );
                assert_eq!(
                    ledger_slots(&mut handle, scope_id),
                    (slots, 0, slots, 0, 0),
                    "{arm}: every slot in flight, none settled"
                );
            }
            deps.transport = handle.transport.clone();
            assert_eq!(run(&handle, &deps), (1, 0, 0), "control");
            assert_eq!(
                ledger_slots(&mut handle, scope_id),
                (slots, slots, 0, 0, 0),
                "every slot settled once the ticket is DONE"
            );
        });
    }

    /// ADR-0068 gate `retry_reuses_committed_batch_vectors` (D-F): a chunked note whose last slot's upsert fails has
    /// C - 1 slots registered with their vectors; the retry embeds only the last chunk's input and settles DONE.
    /// Fault: stored-first all-or-nothing per ticket ⇒ the retry re-embeds all C inputs ⇒ red.
    #[test]
    fn retry_reuses_committed_batch_vectors() {
        run_db_fixture::<Fixture, _>("retry_reuses_committed_batch_vectors", |mut handle| {
            let mut guard = PolicyGuard::hold();
            guard.enable();
            let scope_id = Uuid::new_v4();
            let title = "a long note";
            let body = prose(1_500);
            let (_, note) = seed_note(&mut handle, scope_id, title, &body);
            let count = sql_chunk_count(&mut handle, title, &body) as usize;
            let spy = Spy::new();
            let (mut deps, _) = labeled_deps(&handle, scope_id, &spy);
            let ids = chunk_ids(
                &registration_for(&mut handle, scope_id, &deps.embedding_version, note),
                count as u32,
            );
            deps.transport = Arc::new(SlotFault {
                inner: handle.transport.clone(),
                fail_upsert: ids.last().copied(),
                hide: None,
            });
            assert_eq!(run(&handle, &deps), (0, 0, 1), "the last upsert failed");
            assert_eq!(
                spy.seen().len(),
                count,
                "the first attempt embeds every chunk"
            );

            deps.transport = handle.transport.clone();
            assert_eq!(run(&handle, &deps), (1, 0, 0), "the retry settles");
            let last = chunks(note_input(note, title, &body))
                .pop()
                .expect("C >= 1")
                .text;
            let retried: Vec<(Uuid, String)> = spy.seen().split_off(count);
            assert_eq!(
                retried.len(),
                1,
                "only the slot that never committed: {retried:?}"
            );
            assert_eq!(retried[0].0, note);
            assert!(
                retried[0].1.contains(&last),
                "the retried input is the last chunk's card"
            );
        });
    }

    /// ADR-0068 gate `chunk_backfill_embeds_only_note_chunk_inputs` (zero re-embed): a long note, a short note and a
    /// long ordinary memory are projected legacy-only; the policy is enabled and all three are re-projected by
    /// lifecycle tickets. The provider sees exactly the long note's C chunk inputs and no input of the other two
    /// (their legacy cards are unchanged and their stored vectors are reused). Faults: drop the legacy-capacity term
    /// or the identity-note term from `build_projection_plan` ⇒ the short note or the ordinary memory is chunked and
    /// embedded ⇒ red.
    #[test]
    fn chunk_backfill_embeds_only_note_chunk_inputs() {
        run_db_fixture::<Fixture, _>(
            "chunk_backfill_embeds_only_note_chunk_inputs",
            |mut handle| {
                let mut guard = PolicyGuard::hold();
                let gov = Governor::seed(&mut handle.admin, handle.tenant_id);
                let scope_id = seed_workspace(&mut handle);
                gov.join(&mut handle.admin, scope_id);
                let title = "a long note";
                let body = prose(1_500);
                let (_, long_note) = seed_note(&mut handle, scope_id, title, &body);
                let (_, short_note) = seed_note(&mut handle, scope_id, "a short note", &prose(200));
                let (_, ordinary) = seed_memory_with_visibility(
                    &mut handle,
                    scope_id,
                    &prose(1_500),
                    "TENANT_SHARED",
                    None,
                    None,
                );
                let spy = Spy::new();
                let (deps, _) = labeled_deps(&handle, scope_id, &spy);
                assert_eq!(run(&handle, &deps), (3, 0, 0), "legacy-only projection");
                let before = spy.seen().len();

                guard.enable();
                for memory in [long_note, short_note, ordinary] {
                    let archived = governance_ops::archive(
                        &handle.rt,
                        &handle.gateway,
                        &gov.scope(scope_id),
                        &governance_ops::stream(handle.tenant_id, scope_id),
                        memory,
                        DestructiveOp::MemoryArchive,
                    )
                    .expect("a lifecycle ticket through the real op");
                    assert!(matches!(archived, ArchiveResult::Done(_)), "{archived:?}");
                }
                assert_eq!(run(&handle, &deps), (3, 0, 0), "the backfill pass");
                let backfill: Vec<(Uuid, String)> = spy.seen().split_off(before);
                let count = sql_chunk_count(&mut handle, title, &body) as usize;
                assert!(
                    backfill.iter().all(|(memory, _)| *memory == long_note),
                    "an input that is not the long note's: {backfill:?}"
                );
                let mut expected: Vec<String> = chunks(note_input(long_note, title, &body))
                    .into_iter()
                    .map(|chunk| chunk.text)
                    .collect();
                assert_eq!(backfill.len(), count, "{backfill:?}");
                for (_, input) in &backfill {
                    let at = expected
                        .iter()
                        .position(|text| input.contains(text.as_str()))
                        .unwrap_or_else(|| panic!("not a chunk of the long note: {input}"));
                    expected.remove(at);
                }
            },
        );
    }

    /// ADR-0068 gate `written_memory_id_matches_the_registry` (D-E): every point the worker writes — each chunk of a
    /// long note and the legacy point of an ordinary memory — carries as `memory_id` the Memory its registry row
    /// resolves to. Fault: fill the payload's `memory_id` from anything but the resolved Memory ⇒ red.
    #[test]
    fn written_memory_id_matches_the_registry() {
        run_db_fixture::<Fixture, _>("written_memory_id_matches_the_registry", |mut handle| {
            let mut guard = PolicyGuard::hold();
            guard.enable();
            let scope_id = Uuid::new_v4();
            let title = "a long note";
            let body = prose(1_500);
            let (_, note) = seed_note(&mut handle, scope_id, title, &body);
            let (_, ordinary) = seed_memory_with_visibility(
                &mut handle,
                scope_id,
                "an ordinary memory",
                "TENANT_SHARED",
                None,
                None,
            );
            let spy = Spy::new();
            let (deps, _) = labeled_deps(&handle, scope_id, &spy);
            assert_eq!(run(&handle, &deps), (2, 0, 0));
            let count = sql_chunk_count(&mut handle, title, &body);
            let mut expected: Vec<(Uuid, Uuid)> = chunk_ids(
                &registration_for(&mut handle, scope_id, &deps.embedding_version, note),
                count,
            )
            .into_iter()
            .map(|id| (id, note))
            .collect();
            let legacy = registration_for(&mut handle, scope_id, &deps.embedding_version, ordinary);
            expected.push((legacy.point_id.as_uuid(), ordinary));
            let ids: Vec<Uuid> = expected.iter().map(|(id, _)| *id).collect();
            let written = payload_memory_ids(&handle, &ids);
            assert_eq!(written.len(), expected.len(), "{written:?}");
            for (id, memory) in expected {
                assert_eq!(
                    written.get(&id).cloned().flatten(),
                    Some(memory.to_string()),
                    "point {id}"
                );
            }
        });
    }
}

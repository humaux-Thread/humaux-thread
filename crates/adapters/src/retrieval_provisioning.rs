//! `adapters::retrieval_provisioning` — Qdrant collection setup and the VerifiedEmpty first activation (ADR-0053 D-D).
//! Depends-on: crates=[async-trait, hex, humaux-application, humaux-domain, humaux-infra-cell, humaux-projection, serde_json, sha2, sqlx, uuid];
//!   services=[PostgreSQL(role_maintenance) r=[control.workspaces, projection.tenant_placements] x=[projection.activate_empty_family], Qdrant(*)]; env=[];
//!   modules=[adapters::membership_repo, adapters::postgres, adapters::provisioning, adapters::qdrant, adapters::retrieve, application::operator_provisioning,
//!   domain::ids, domain::ticket_family, infra-cell::permit, infra-cell::resource, infra-cell::transport, projection::serving]
//! Called-by: [adapters::rebuild, maintenance::bootstrap, tests, xtask::e2e_seed]
//! Invariants: [the Qdrant empty probe precedes the activation transaction; the PG definer, switch verdict,
//!   success audit and generation recheck share one transaction; refusal rolls it back before writing a DENIED audit]
//! Spec: Baseline §16.3; §17.1; §77; ADR-0053 D-D; ADR-0057 D-C; ADR-0083 D-B; ADR-0130 D7

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use humaux_application::operator_provisioning::{
    self as operator, ActivationReceipt, CollectionProvisioningPort, CollectionReceipt,
    WorkspaceActivation, WorkspaceActivationPort,
};
use humaux_domain::ids::{TenantId, WorkspaceId};
use humaux_domain::ticket_family::TicketFamily;
use humaux_infra_cell::{
    CallerId, CellAccessPermit, CellId, DEFAULT_MAX_RESPONSE_BYTES, HttpIntraCellTransport,
    IntraCellHttpTransport, IntraCellMethod, IntraCellRequest, IntraCellResource,
    IntraCellResourceRegistry, ResourceEntry, authorize_cell_access,
};
use humaux_projection::serving::{
    ActivationEvidence, ContinuationVerdict, GenerationId, SwitchCriteria, VerifiedEmpty,
    evaluate_switch,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::types::time::OffsetDateTime;
use uuid::Uuid;

use crate::membership_repo::AdminAction;
use crate::postgres::MaintenanceDbPool;
use crate::provisioning::{
    AUDIT_RESULT_SUCCESS, AUDIT_RISK_TAG, ProvisioningError, audit, audit_denied, require_admin,
    set_tenant,
};
use crate::qdrant::{
    BM25_MODIFIER, BM25_VECTOR_NAME, CollectionSpec, bm25_vector_body,
    default_collection_create_body, memory_id_index_body, subject_index_body, tenant_index_body,
};
use crate::retrieve::{IndexFace, stream_count_of_version};

type Result<T> = std::result::Result<T, ProvisioningError>;

/// Qdrant caller identity of this module's own ReadWrite registry (it creates collections, so
/// it can never share the gateway's read-only one, ADR-0014).
const QDRANT_CALLER: &str = "humaux-maintenance";
const QDRANT_PERMIT_TTL: Duration = Duration::from_secs(60);
const QDRANT_TIMEOUT: Duration = Duration::from_secs(10);

// ============================================================================
// Qdrant steps
// ============================================================================

/// A ReadWrite `QDRANT_REST` face of this operator process (ADR-0014's read-only rule binds the
/// gateway's runtime registry, not the tool that creates collections).
// ponytail: plaintext (tls = false), like the seed it replaces; add a TLS flag when a production
// Qdrant needs it.
pub struct QdrantFace {
    registry: IntraCellResourceRegistry,
    transport: HttpIntraCellTransport,
}

impl QdrantFace {
    /// `host`/`port` of the same-Cell Qdrant and the private CIDR its address must resolve into
    /// (§83.4 判据3).
    pub fn new(host: &str, port: u16, cidr: &str) -> Result<Self> {
        let cell = CellId(Uuid::now_v7());
        let caller = CallerId(QDRANT_CALLER.to_owned());
        let cidr = cidr
            .parse()
            .map_err(|_| ProvisioningError::InvalidInput(format!("qdrant cidr {cidr}")))?;
        let mut entries = BTreeMap::new();
        entries.insert(
            IntraCellResource::QDRANT_REST,
            ResourceEntry::new(
                host,
                port,
                cell,
                vec![cidr],
                BTreeSet::from([caller.clone()]),
                false,
            )
            .map_err(|e| ProvisioningError::InvalidInput(format!("qdrant resource entry: {e}")))?,
        );
        let registry = IntraCellResourceRegistry::new(entries, cell, caller);
        let transport = HttpIntraCellTransport::new(
            registry.clone(),
            QDRANT_TIMEOUT,
            DEFAULT_MAX_RESPONSE_BYTES,
        )
        .map_err(|e| ProvisioningError::Qdrant(format!("transport: {e}")))?;
        Ok(Self {
            registry,
            transport,
        })
    }

    fn permit(&self) -> Result<CellAccessPermit> {
        authorize_cell_access(
            &self.registry,
            IntraCellResource::QDRANT_REST,
            QDRANT_PERMIT_TTL,
        )
        .map_err(|e| ProvisioningError::Qdrant(format!("permit: {e:?}")))
    }

    /// This face's transport and a fresh permit, for the rebuild verifier's scroll / count / delete
    /// (ADR-0064 D-F), so the operator CLI holds one Qdrant face, not two.
    pub fn wire(&self) -> Result<(&HttpIntraCellTransport, CellAccessPermit)> {
        Ok((&self.transport, self.permit()?))
    }

    /// One raw REST call: `(status, body)` — the caller decides what a status means.
    async fn request(
        &self,
        method: IntraCellMethod,
        path: String,
        json_body: Option<Value>,
    ) -> Result<(u16, Option<Value>)> {
        let permit = self.permit()?;
        let response = self
            .transport
            .execute(
                &permit,
                // dep: Qdrant(*) — collection create/index/config/delete for onboarding
                IntraCellRequest {
                    method,
                    path,
                    json_body,
                    headers: Vec::new(),
                },
            )
            .await
            .map_err(|e| ProvisioningError::Qdrant(format!("{e:?}")))?;
        Ok((response.status, response.json_body))
    }

    /// `DELETE /collections/{c}` (e2e teardown only; never called by onboarding).
    pub async fn delete_collection(&self, collection: &str) -> Result<()> {
        let (status, _) = self
            .request(
                IntraCellMethod::Delete,
                format!("/collections/{collection}"),
                None,
            )
            .await?;
        if (200..300).contains(&status) || status == 404 {
            Ok(())
        } else {
            Err(ProvisioningError::Qdrant(format!(
                "DELETE collection returned {status}"
            )))
        }
    }
}

/// The exact `PUT` sequence that brings one collection into existence: the collection itself,
/// then the payload indexes §17.1 / §6.1.3 / ADR-0068 require (card 9 P2: the `subject_ids` uuid index was
/// once simply never PUT and nothing could see it missing — the sentinel test below pins them), then ADR-0083 D-B's
/// `bm25` sparse vector. The collection body already declares `bm25`, so on a fresh collection the last PUT is Qdrant's
/// idempotent no-op; on a collection created before ADR-0083 it is what adds the vector (`PATCH /collections/{c}` cannot,
/// ADR-0083 V1; `PUT /collections/{c}/vectors/{name}` can, V1b).
pub fn collection_setup_puts(collection: &str, dimension: u32) -> Vec<(String, Value)> {
    setup_puts(collection, default_collection_create_body(dimension))
}

/// [`collection_setup_puts`] for one [`CollectionSpec`]: the same sequence, named and shaped by the spec (ADR-0086).
pub fn collection_setup_puts_for(spec: &CollectionSpec) -> Vec<(String, Value)> {
    setup_puts(&spec.collection_name(), spec.create_body())
}

/// The sequence behind both entry points. Order is the contract (§17.1, ADR-0086 D-C): the collection, then the
/// tenant index (`is_tenant`) and the other payload indexes, the sparse vector last, and never a point write: no
/// point exists before every index does.
fn setup_puts(collection: &str, create_body: Value) -> Vec<(String, Value)> {
    vec![
        (format!("/collections/{collection}"), create_body),
        (
            format!("/collections/{collection}/index"),
            tenant_index_body(),
        ),
        (
            format!("/collections/{collection}/index"),
            subject_index_body(),
        ),
        (
            format!("/collections/{collection}/index"),
            memory_id_index_body(),
        ),
        (
            format!("/collections/{collection}/vectors/{BM25_VECTOR_NAME}"),
            bm25_vector_body(),
        ),
    ]
}

/// The payload index names `collection_setup_puts` creates, in order.
fn payload_index_names(collection: &str) -> Vec<String> {
    collection_setup_puts(collection, 1)
        .iter()
        .filter(|(path, _)| path.ends_with("/index"))
        .filter_map(|(_, body)| body["field_name"].as_str().map(str::to_owned))
        .collect()
}

/// ADR-0053: the collection's generation from `GET /collections/{c}` — its name plus the sha256
/// of the canonical config subset (vector size + distance, the `bm25` sparse vector's modifier (ADR-0083 D-B), and
/// each required payload index's type and params; never the live `points` counts). A missing collection is
/// `collection_missing`; a dimension, `bm25` or index mismatch is `collection_misconfigured`.
pub async fn collection_generation(
    face: &QdrantFace,
    collection: &str,
    dimension: u32,
) -> Result<GenerationId> {
    let (status, body) = face
        .request(
            IntraCellMethod::Get,
            format!("/collections/{collection}"),
            None,
        )
        .await?;
    if status == 404 {
        return Err(ProvisioningError::Refused("collection_missing".to_owned()));
    }
    if !(200..300).contains(&status) {
        return Err(ProvisioningError::Qdrant(format!(
            "GET collection returned {status}"
        )));
    }
    let body = body.unwrap_or(Value::Null);
    let result = &body["result"];
    let vectors = &result["config"]["params"]["vectors"];
    let mut canonical = format!(
        "size={};distance={}",
        vectors["size"],
        vectors["distance"].as_str().unwrap_or("")
    );
    if vectors["size"].as_u64() != Some(u64::from(dimension)) {
        return Err(ProvisioningError::Refused(
            "collection_misconfigured".to_owned(),
        ));
    }
    // ADR-0083 D-B: a collection created before the sparse vector existed reads misconfigured until
    // `collection ensure` adds it, the path ADR-0068 used for the `memory_id` index.
    let sparse = &result["config"]["params"]["sparse_vectors"][BM25_VECTOR_NAME];
    let modifier = sparse["modifier"].as_str().unwrap_or("");
    if modifier != BM25_MODIFIER {
        return Err(ProvisioningError::Refused(
            "collection_misconfigured".to_owned(),
        ));
    }
    canonical.push_str(&format!(";{BM25_VECTOR_NAME}_modifier={modifier}"));
    for index in payload_index_names(collection) {
        let schema = &result["payload_schema"][&index];
        if schema.is_null() {
            return Err(ProvisioningError::Refused(
                "collection_misconfigured".to_owned(),
            ));
        }
        canonical.push_str(&format!(
            ";{index}={}:{}",
            schema["data_type"], schema["params"]
        ));
    }
    let digest = hex::encode(Sha256::digest(canonical.as_bytes()));
    Ok(GenerationId(format!("{collection}@{digest}")))
}

/// `collection ensure`: creates the collection and every payload index unless present, and adds the `bm25` sparse
/// vector to a collection that predates it (ADR-0083 D-B). A
/// non-2xx create is re-read and accepted when the collection now exists (a concurrent
/// onboarding created it); the index and vector PUTs are idempotent and wait for completion so the
/// generation read right after sees them.
pub async fn ensure_collection(
    face: &QdrantFace,
    collection: &str,
    dimension: u32,
) -> Result<CollectionReceipt> {
    ensure_with_puts(
        face,
        collection,
        dimension,
        collection_setup_puts(collection, dimension),
    )
    .await
}

/// [`ensure_collection`] for one [`CollectionSpec`] (ADR-0086): the generation's own name and create body; an existing
/// collection of that name is left as it is, whatever its datatype or HNSW (a knob change is a new generation).
pub async fn ensure_collection_for(
    face: &QdrantFace,
    spec: &CollectionSpec,
) -> Result<CollectionReceipt> {
    ensure_with_puts(
        face,
        &spec.collection_name(),
        spec.dimension(),
        collection_setup_puts_for(spec),
    )
    .await
}

async fn ensure_with_puts(
    face: &QdrantFace,
    collection: &str,
    dimension: u32,
    puts: Vec<(String, Value)>,
) -> Result<CollectionReceipt> {
    let (status, _) = face
        .request(
            IntraCellMethod::Get,
            format!("/collections/{collection}"),
            None,
        )
        .await?;
    let existed = (200..300).contains(&status);
    let mut puts = puts.into_iter();
    let (create_path, create_body) = puts
        .next()
        .ok_or_else(|| ProvisioningError::Qdrant("empty setup sequence".to_owned()))?;
    let mut created = false;
    if !existed {
        let (status, _) = face
            .request(IntraCellMethod::Put, create_path.clone(), Some(create_body))
            .await?;
        if (200..300).contains(&status) {
            created = true;
        } else {
            // A concurrent onboarding holds the name (409) and may still be creating it: accept
            // the collection once it reads back.
            // ponytail: bounded blocking re-read (10 × 100 ms) in a one-shot CLI; an async timer
            // needs a tokio dependency this crate does not carry outside tests.
            let mut exists = false;
            for _ in 0..10 {
                let (again, _) = face
                    .request(IntraCellMethod::Get, create_path.clone(), None)
                    .await?;
                if (200..300).contains(&again) {
                    exists = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            if !exists {
                return Err(ProvisioningError::Qdrant(format!(
                    "PUT collection returned {status}"
                )));
            }
        }
    }
    for (path, body) in puts {
        let (status, _) = face
            .request(
                IntraCellMethod::Put,
                format!("{path}?wait=true"),
                Some(body),
            )
            .await?;
        if !(200..300).contains(&status) {
            return Err(ProvisioningError::Qdrant(format!(
                "PUT {path} returned {status}"
            )));
        }
    }
    let generation = collection_generation(face, collection, dimension).await?;
    Ok(CollectionReceipt {
        name: collection.to_owned(),
        created,
        dimension,
        payload_indexes: payload_index_names(collection),
        generation: generation.0,
    })
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// `activate`: the ADR-0053 D-D VerifiedEmpty first activation of every family of one workspace
/// (or only `only`). A refused family is reported with its named reason, audited `DENIED`, and
/// wrote nothing; the caller maps any refusal to exit 3.
pub async fn activate_workspace(
    pool: &MaintenanceDbPool,
    face: &QdrantFace,
    tenant_id: Uuid,
    workspace_id: Uuid,
    dimension: u32,
    only: Option<TicketFamily>,
    admin: &AdminAction<'_>,
) -> Result<WorkspaceActivation> {
    require_admin(admin)?;
    let mut activations = Vec::new();
    for family in TicketFamily::ALL
        .into_iter()
        .filter(|f| only.is_none_or(|o| o == *f))
    {
        let receipt = activate_family(
            pool,
            face,
            tenant_id,
            workspace_id,
            dimension,
            family,
            admin,
        )
        .await?;
        activations.push(receipt);
    }
    // dep: PostgreSQL(role_maintenance) — read the workspace lifecycle after activation
    let mut txn = pool.pool().begin().await?;
    set_tenant(&mut txn, tenant_id).await?;
    let lifecycle: Option<String> = sqlx::query_scalar(
        "SELECT lifecycle FROM control.workspaces WHERE tenant_id = $1 AND workspace_id = $2",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .fetch_optional(&mut *txn)
    .await?;
    txn.commit().await?;
    Ok(WorkspaceActivation {
        tenant_id,
        workspace_id,
        activations,
        lifecycle: lifecycle.unwrap_or_else(|| "NOT_FOUND".to_owned()),
    })
}

fn family_receipt(family: TicketFamily) -> ActivationReceipt {
    ActivationReceipt {
        domain: family.domain(),
        projection_kind: family.projection_kind(),
        projection_version: family.projection_version(),
        outcome: "refused",
        reason: None,
        evidence: "VerifiedEmpty",
        collection: None,
        generation: None,
        probe_id: None,
        probe_visible: None,
        probe_latency_ms: None,
        activation_txn_ms: None,
        audit_event_id: None,
    }
}

async fn refuse(
    pool: &MaintenanceDbPool,
    tenant_id: Uuid,
    workspace_id: Uuid,
    mut receipt: ActivationReceipt,
    reason: String,
    admin: &AdminAction<'_>,
) -> Result<ActivationReceipt> {
    receipt.audit_event_id = Some(
        audit_denied(
            pool,
            tenant_id,
            ("FAMILY_ACTIVATE", AUDIT_RISK_TAG),
            ("workspace", &workspace_id.to_string()),
            &reason,
            admin,
        )
        .await?,
    );
    receipt.outcome = "refused";
    receipt.reason = Some(reason);
    Ok(receipt)
}

#[allow(clippy::too_many_lines)] // one linear D-D sequence; splitting it hides the txn boundary
async fn activate_family(
    pool: &MaintenanceDbPool,
    face: &QdrantFace,
    tenant_id: Uuid,
    workspace_id: Uuid,
    dimension: u32,
    family: TicketFamily,
    admin: &AdminAction<'_>,
) -> Result<ActivationReceipt> {
    let mut receipt = family_receipt(family);

    // Step 1, outside any transaction: placement, generation g1, the probe.
    // dep: PostgreSQL(role_maintenance) — placement read before the probe
    let mut txn = pool.pool().begin().await?;
    set_tenant(&mut txn, tenant_id).await?;
    let collection: Option<String> = sqlx::query_scalar(
        "SELECT collection_name FROM projection.tenant_placements \
          WHERE tenant_id = $1 AND projection_family = $2",
    )
    .bind(tenant_id)
    .bind(family.collection_name())
    .fetch_optional(&mut *txn)
    .await?;
    txn.commit().await?;
    let Some(collection) = collection else {
        return refuse(
            pool,
            tenant_id,
            workspace_id,
            receipt,
            "placement_missing".to_owned(),
            admin,
        )
        .await;
    };
    receipt.collection = Some(collection.clone());

    let probe_started = Instant::now();
    let g1 = match collection_generation(face, &collection, dimension).await {
        Ok(generation) => generation,
        Err(ProvisioningError::Refused(reason)) => {
            return refuse(pool, tenant_id, workspace_id, receipt, reason, admin).await;
        }
        Err(other) => return Err(other),
    };
    let probe_id = Uuid::now_v7();
    if family.projection_version().is_empty() {
        return Err(ProvisioningError::InvalidInput(
            "projection_version".to_owned(),
        ));
    }
    let permit = face.permit()?;
    // ADR-0057 D-C: the ops stream count — every point of the family whatever its visibility
    // class (the previous user-less probe scope could not see USER_PRIVATE points).
    let probe_visible = stream_count_of_version(
        &IndexFace {
            transport: &face.transport,
            permit: &permit,
            collection: &collection,
        },
        TenantId(tenant_id),
        WorkspaceId(workspace_id),
        family.projection_version(),
        &[],
    )
    .await
    .ok_or_else(|| ProvisioningError::Qdrant("probe count unavailable".to_owned()))?;
    let probed_at = OffsetDateTime::now_utc();
    receipt.probe_latency_ms = Some(millis(probe_started.elapsed()));
    receipt.generation = Some(g1.0.clone());
    receipt.probe_id = Some(probe_id);
    receipt.probe_visible = Some(probe_visible);

    // Step 2-3: the short re-verifying transaction.
    let txn_started = Instant::now();
    // dep: PostgreSQL(role_maintenance) — the short activation transaction (definer + audit)
    let mut txn = pool.pool().begin().await?;
    set_tenant(&mut txn, tenant_id).await?;
    let row = sqlx::query(
        "SELECT outcome, reason, initialized_head, open_gaps, first_activation, workspace_ready \
           FROM projection.activate_empty_family($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(family.domain())
    .bind(family.projection_kind())
    .bind(family.projection_version())
    .bind(&collection)
    .bind(&g1.0)
    .bind(probe_id)
    .bind(i64::try_from(probe_visible).unwrap_or(i64::MAX))
    .bind(probed_at)
    .fetch_one(&mut *txn)
    .await?;
    let outcome: String = row.try_get("outcome")?;
    match outcome.as_str() {
        "EXISTING" => {
            txn.commit().await?;
            receipt.outcome = "existing";
            receipt.activation_txn_ms = Some(millis(txn_started.elapsed()));
            return Ok(receipt);
        }
        "REFUSED" => {
            drop(txn);
            let reason: Option<String> = row.try_get("reason")?;
            return refuse(
                pool,
                tenant_id,
                workspace_id,
                receipt,
                reason.unwrap_or_else(|| "refused".to_owned()),
                admin,
            )
            .await;
        }
        "ACTIVATED" => {}
        other => {
            return Err(ProvisioningError::Qdrant(format!(
                "unexpected activation outcome {other}"
            )));
        }
    }

    // §16.3's single judgement point, on the facts the DB returned (never on caller claims).
    let initialized_head: Option<i64> = row.try_get("initialized_head")?;
    let open_gaps: Option<i64> = row.try_get("open_gaps")?;
    let first_activation: Option<bool> = row.try_get("first_activation")?;
    let criteria = SwitchCriteria {
        shadow: ActivationEvidence::VerifiedEmpty(VerifiedEmpty {
            initialized_head: initialized_head
                .and_then(|h| u64::try_from(h).ok())
                .unwrap_or(u64::MAX),
            target_generation: g1.clone(),
            probe_id,
            probe_visible,
        }),
        visible_serving: None,
        first_activation: first_activation.unwrap_or(false),
        shadow_open_gaps: open_gaps
            .and_then(|g| u64::try_from(g).ok())
            .unwrap_or(u64::MAX),
        // No baseline exists for a first activation (ADR-0017); only a proven Fail refuses.
        continuation: ContinuationVerdict::CannotEstablish,
    };
    if let Err(rejections) = evaluate_switch(&criteria) {
        drop(txn);
        return refuse(
            pool,
            tenant_id,
            workspace_id,
            receipt,
            format!("evaluator_veto {rejections:?}"),
            admin,
        )
        .await;
    }
    let audit_event_id = audit(
        &mut txn,
        tenant_id,
        "FAMILY_ACTIVATE",
        "workspace",
        &workspace_id.to_string(),
        AUDIT_RESULT_SUCCESS,
        admin,
        json!({
            "evidence": "VerifiedEmpty",
            "domain": family.domain(),
            "projection_kind": family.projection_kind(),
            "projection_version": family.projection_version(),
            "collection": collection,
            "generation": g1.0,
            "probe_id": probe_id.to_string(),
            "probe_visible": probe_visible,
        }),
    )
    .await?;
    let g2 = collection_generation(face, &collection, dimension).await;
    if g2.as_ref().ok() != Some(&g1) {
        drop(txn);
        return refuse(
            pool,
            tenant_id,
            workspace_id,
            receipt,
            "generation_changed".to_owned(),
            admin,
        )
        .await;
    }
    txn.commit().await?;
    receipt.outcome = "activated";
    receipt.audit_event_id = Some(audit_event_id);
    receipt.activation_txn_ms = Some(millis(txn_started.elapsed()));
    Ok(receipt)
}

#[async_trait::async_trait]
impl CollectionProvisioningPort for QdrantFace {
    async fn ensure_collection(
        &self,
        collection: &str,
        dimension: u32,
    ) -> std::result::Result<CollectionReceipt, operator::ProvisioningError> {
        ensure_collection(self, collection, dimension)
            .await
            .map_err(Into::into)
    }
}

/// Existing workspace activation operation with its PG and Qdrant dependencies.
pub struct WorkspaceActivationAdapter<'a> {
    pool: &'a MaintenanceDbPool,
    face: &'a QdrantFace,
}

impl<'a> WorkspaceActivationAdapter<'a> {
    /// Binds the dependencies without accessing either service.
    pub fn new(pool: &'a MaintenanceDbPool, face: &'a QdrantFace) -> Self {
        Self { pool, face }
    }
}

#[async_trait::async_trait]
impl WorkspaceActivationPort for WorkspaceActivationAdapter<'_> {
    async fn activate_workspace(
        &self,
        tenant_id: Uuid,
        workspace_id: Uuid,
        dimension: u32,
        only: Option<TicketFamily>,
        admin: &AdminAction<'_>,
    ) -> std::result::Result<WorkspaceActivation, operator::ProvisioningError> {
        activate_workspace(
            self.pool,
            self.face,
            tenant_id,
            workspace_id,
            dimension,
            only,
            admin,
        )
        .await
        .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::{collection_setup_puts, payload_index_names};

    /// Card 9 P2 / card 24 (moved from `xtask::e2e_seed` with the function). FAULT SENTINEL:
    /// goes red the moment a seeded collection stops getting the `subject_ids` uuid payload
    /// index, the state this repo shipped in while `docs/ops/runbook.md` already told operators
    /// both indexes were created; and, since ADR-0068 D-E, the `memory_id` keyword index recall groups by.
    /// Fault: drop any of the three index PUTs ⇒ red.
    #[test]
    fn a_seeded_collection_gets_every_payload_index() {
        let puts = collection_setup_puts("c", 1024);
        assert_eq!(
            puts.len(),
            5,
            "collection + tenant index + subject index + memory_id index + bm25 vector"
        );
        assert_eq!(puts[0].0, "/collections/c");
        let fields: Vec<&str> = puts[1..4]
            .iter()
            .map(|(path, body)| {
                assert_eq!(path, "/collections/c/index");
                body["field_name"].as_str().expect("field_name")
            })
            .collect();
        assert_eq!(fields, vec!["tenant_id", "subject_ids", "memory_id"]);
        assert_eq!(puts[1].1["field_schema"]["is_tenant"], true);
        assert_eq!(puts[2].1["field_schema"]["type"], "uuid");
        assert_eq!(puts[3].1["field_schema"]["type"], "keyword");
        assert_eq!(
            payload_index_names("c"),
            vec!["tenant_id", "subject_ids", "memory_id"]
        );
    }

    /// ADR-0083 D-B / G6b-1 (T-RET-6b): a fresh collection is created WITH the `bm25` sparse vector
    /// (`modifier: idf`), and the setup sequence ends with the `PUT /collections/c/vectors/bm25` that adds it to a
    /// collection created before ADR-0083 (`PATCH` cannot, V1). The live arm — an old collection gains the vector
    /// through `ensure_collection` and a second call changes nothing — is `rebuild.rs`'s
    /// `ensure_adds_bm25_to_an_old_collection_once`.
    /// Fault: drop the vector PUT from `collection_setup_puts` ⇒ red; drop `sparse_vectors` from the body ⇒ red.
    #[test]
    fn a_seeded_collection_gets_the_bm25_sparse_vector() {
        let puts = collection_setup_puts("c", 1024);
        assert_eq!(
            puts[0].1["sparse_vectors"],
            serde_json::json!({ "bm25": { "modifier": "idf" } }),
            "a fresh collection is created with bm25"
        );
        let last = puts.last().expect("a non-empty sequence");
        assert_eq!(last.0, "/collections/c/vectors/bm25");
        assert_eq!(
            last.1,
            serde_json::json!({ "sparse": { "modifier": "idf" } })
        );
    }
}

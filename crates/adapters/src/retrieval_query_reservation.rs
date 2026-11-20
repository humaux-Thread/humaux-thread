//! `adapters::retrieval_query_reservation` — Owner commands for private retrieval-query provenance.
//! Depends-on: crates=[humaux-domain, humaux-local-secret-scan, serde_json, sqlx];
//!   services=[PostgreSQL(any) w=[private.retrieval_query_sources], PostgreSQL(role_maintenance),
//!   PostgreSQL(role_retrieval_worker)]; env=[]; modules=[adapters::disclosure,
//!   adapters::postgres, domain::dataclass, domain::egress, domain::identity, domain::ids, humaux-local-secret-scan]
//! Called-by: [adapters::retrieval_query_source, retrieval-provider::adapters, tests]
//! Invariants: [sealed queries bind the exact serialized wire payload; trusted authorization supplies the principal;
//!   source insertion and disclosure attachment share one PostgreSQL transaction; revocation is one-way]
//! Spec: none

use sqlx::Row;
use sqlx::types::Uuid;

use humaux_domain::dataclass::DataClass;
use humaux_domain::egress::{AuthorizedEgressPayload, EgressPermit, PrivateDataPurpose};
use humaux_domain::identity::AuthorizationScope;
use humaux_domain::ids::WorkspaceId;
use humaux_local_secret_scan::SealedRetrievalQuery;

use crate::disclosure::{self, DisclosureError, DisclosureScope};
use crate::postgres::{MaintenanceDbPool, RetrievalWorkerDbPool};

#[derive(Debug)]
pub enum RetrievalQuerySourceError {
    Db(sqlx::Error),
    Disclosure(DisclosureError),
    UnauthorizedScope,
    WrongPermit,
    InvalidMetadata,
}

impl From<sqlx::Error> for RetrievalQuerySourceError {
    fn from(error: sqlx::Error) -> Self {
        Self::Db(error)
    }
}

impl From<DisclosureError> for RetrievalQuerySourceError {
    fn from(error: DisclosureError) -> Self {
        Self::Disclosure(error)
    }
}

impl std::fmt::Display for RetrievalQuerySourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Db(error) => write!(f, "retrieval query source DB error: {error}"),
            Self::Disclosure(error) => error.fmt(f),
            Self::UnauthorizedScope => {
                write!(f, "query source is outside the trusted authorization scope")
            }
            Self::WrongPermit => write!(
                f,
                "query source requires a matching retrieval-embedding permit"
            ),
            Self::InvalidMetadata => write!(f, "query source metadata is invalid"),
        }
    }
}

impl std::error::Error for RetrievalQuerySourceError {}

const RETRIEVAL_QUERY_SOURCE_TTL_SECONDS: i32 = 300;

/// Exact provider embedding wire bytes bound to the sealed query slice that produced them.
/// The canonical embedding request shape is provider-neutral at this provenance boundary;
/// callers can inspect the authorized payload but cannot replace either side of the binding.
pub struct SerializedRetrievalQueryBatch<'a> {
    queries: &'a [SealedRetrievalQuery],
    payload: AuthorizedEgressPayload,
}

impl<'a> SerializedRetrievalQueryBatch<'a> {
    /// Performs the sole serialization used by the real provider query path. Keeping the query
    /// references and serialized bytes in one value makes `sealed A + payload B` unrepresentable
    /// at the reserve boundary without importing or naming a provider client in this crate.
    pub fn new(
        model_id: &str,
        dimension: u32,
        queries: &'a [SealedRetrievalQuery],
    ) -> Result<Self, RetrievalQuerySourceError> {
        if model_id.trim().is_empty() || dimension == 0 || queries.is_empty() {
            return Err(RetrievalQuerySourceError::InvalidMetadata);
        }
        let input: Vec<&str> = queries.iter().map(SealedRetrievalQuery::as_str).collect();
        let bytes = serde_json::to_vec(&serde_json::json!({
            "model": model_id,
            "input": input,
            "dimensions": dimension,
            "encoding_format": "float",
        }))
        .map_err(|_| RetrievalQuerySourceError::InvalidMetadata)?;
        Ok(Self {
            queries,
            payload: AuthorizedEgressPayload::new(bytes),
        })
    }

    pub fn payload(&self) -> &AuthorizedEgressPayload {
        &self.payload
    }

    /// Consumes the binding after provenance reservation so the exact same bytes can cross the
    /// transport boundary; no second serialization is possible on that path.
    pub fn into_payload(self) -> AuthorizedEgressPayload {
        self.payload
    }
}

/// Trusted per-call identity for query embedding. Query/profile/classifier metadata and source
/// expiry are deliberately absent: the reserve path derives them from each sealed query and a
/// server-owned TTL. Tenant, principal, and user come only from `authorization`.
pub struct RetrievalQueryCallContext<'a> {
    authorization: &'a AuthorizationScope,
    workspace_id: WorkspaceId,
    request_id: Uuid,
    logical_call_id: Uuid,
    attempt_no: i32,
}

impl<'a> RetrievalQueryCallContext<'a> {
    pub fn new(
        authorization: &'a AuthorizationScope,
        workspace_id: WorkspaceId,
        request_id: Uuid,
        logical_call_id: Uuid,
        attempt_no: i32,
    ) -> Result<Self, RetrievalQuerySourceError> {
        if authorization.user_id().is_none()
            || !authorization
                .allowed_workspace_ids()
                .contains(&workspace_id)
        {
            return Err(RetrievalQuerySourceError::UnauthorizedScope);
        }
        if workspace_id.0.is_nil()
            || request_id.is_nil()
            || logical_call_id.is_nil()
            || attempt_no <= 0
        {
            return Err(RetrievalQuerySourceError::InvalidMetadata);
        }
        Ok(Self {
            authorization,
            workspace_id,
            request_id,
            logical_call_id,
            attempt_no,
        })
    }

    pub fn authorization(&self) -> &AuthorizationScope {
        self.authorization
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }

    pub const fn logical_call_id(&self) -> Uuid {
        self.logical_call_id
    }

    pub const fn attempt_no(&self) -> i32 {
        self.attempt_no
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetrievalQueryDisclosureReservation {
    pub query_source_ids: Vec<Uuid>,
    pub disclosure_id: Uuid,
}

pub(crate) async fn set_authorization_local(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    authorization: &AuthorizationScope,
) -> Result<(Uuid, Uuid, Uuid), RetrievalQuerySourceError> {
    let Some(user_id) = authorization.user_id() else {
        return Err(RetrievalQuerySourceError::UnauthorizedScope);
    };
    let tenant_id = authorization.tenant_id().0;
    let principal_id = authorization.principal().0;
    sqlx::query(
        "SELECT set_config('humaux.tenant_id', $1, true), \
                set_config('humaux.user_id', $2, true), \
                set_config('humaux.principal_id', $3, true)",
    )
    .bind(tenant_id.to_string())
    .bind(user_id.0.to_string())
    .bind(principal_id.to_string())
    .execute(&mut **txn)
    .await?;
    Ok((tenant_id, user_id.0, principal_id))
}

pub(super) fn validate_call(
    context: &RetrievalQueryCallContext<'_>,
    wire: &SerializedRetrievalQueryBatch<'_>,
    permit: &EgressPermit,
) -> Result<(), RetrievalQuerySourceError> {
    let queries = wire.queries;
    let payload = wire.payload();
    let Some(first) = queries.first() else {
        return Err(RetrievalQuerySourceError::InvalidMetadata);
    };
    if context.authorization.tenant_id() != permit.tenant_id()
        || permit.purpose() != PrivateDataPurpose::RetrievalEmbedding
        || permit.data_class() != DataClass::Private
        || permit.payload_sha256() != payload.sha256()
        || payload.bytes().is_empty()
        || queries.len() > i32::MAX as usize
    {
        return Err(RetrievalQuerySourceError::WrongPermit);
    }
    if queries.iter().any(|query| {
        query.data_class() != DataClass::Private
            || query.payload_bytes() == 0
            || query.profile_fingerprint_identity() != first.profile_fingerprint_identity()
            || query.classifier_revision() != first.classifier_revision()
            || query.profile_fingerprint_identity().as_str().is_empty()
            || query.profile_fingerprint_identity().as_str().len() > 128
            || query.classifier_revision().is_empty()
            || query.classifier_revision().len() > 128
    }) {
        return Err(RetrievalQuerySourceError::InvalidMetadata);
    }
    Ok(())
}

/// Creates one metadata-only source per sealed query and one matching disclosure in a single
/// transaction. Stable zero-based ordinals preserve batch cardinality; no query can be silently
/// dropped. The payload is the exact serialized provider wire form and is independently bound
/// to every query source by digest and byte length.
pub async fn reserve_retrieval_query_batch(
    pool: &RetrievalWorkerDbPool,
    context: &RetrievalQueryCallContext<'_>,
    wire: &SerializedRetrievalQueryBatch<'_>,
    permit: &EgressPermit,
    region: &str,
) -> Result<RetrievalQueryDisclosureReservation, RetrievalQuerySourceError> {
    validate_call(context, wire, permit)?;
    let queries = wire.queries;
    let payload = wire.payload();
    // dep: PostgreSQL(role_retrieval_worker) — transaction entry for `reserve_retrieval_query_batch`
    let mut txn = pool.pool().begin().await?;
    let (tenant_id, user_id, principal_id) =
        set_authorization_local(&mut txn, context.authorization).await?;
    let workspace_id = context.workspace_id.0;
    let mut query_source_ids = Vec::with_capacity(queries.len());
    for (ordinal, query) in queries.iter().enumerate() {
        let row = sqlx::query(
            "INSERT INTO private.retrieval_query_sources \
               (tenant_id, principal_id, user_id, workspace_id, request_id, logical_call_id, \
                attempt_no, query_ordinal, profile_fingerprint, classifier_revision, data_class, \
                purpose, query_sha256, query_bytes, wire_payload_sha256, wire_payload_bytes, \
                expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, \
                     'RETRIEVAL_EMBEDDING', $12, $13, $14, $15, \
                     clock_timestamp() + make_interval(secs => $16)) \
             RETURNING query_source_id",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .bind(user_id)
        .bind(workspace_id)
        .bind(context.request_id)
        .bind(context.logical_call_id)
        .bind(context.attempt_no)
        .bind(ordinal as i32)
        .bind(query.profile_fingerprint_identity().as_str())
        .bind(query.classifier_revision())
        .bind(permit.data_class().as_str())
        .bind(query.payload_sha256_bytes().to_vec())
        .bind(query.payload_bytes() as i64)
        .bind(payload.sha256().to_vec())
        .bind(payload.bytes().len() as i64)
        .bind(RETRIEVAL_QUERY_SOURCE_TTL_SECONDS)
        .fetch_one(&mut *txn)
        .await?;
        query_source_ids.push(row.try_get("query_source_id")?);
    }
    let disclosure_id = disclosure::reserve_retrieval_queries_in_txn(
        &mut txn,
        permit,
        region,
        payload,
        DisclosureScope {
            scope_kind: "workspace",
            scope_id: workspace_id,
        },
        &query_source_ids,
    )
    .await?;
    txn.commit().await?;
    Ok(RetrievalQueryDisclosureReservation {
        query_source_ids,
        disclosure_id,
    })
}

/// Maintenance's only permitted mutation: one-way source revocation. Retention never deletes
/// this metadata because the disclosure relation remains the §7.4 deletion/revocation trace.
pub async fn revoke_retrieval_query_source(
    pool: &MaintenanceDbPool,
    tenant_id: Uuid,
    query_source_id: Uuid,
    reason: &str,
) -> Result<bool, RetrievalQuerySourceError> {
    if reason.trim().is_empty() {
        return Err(RetrievalQuerySourceError::InvalidMetadata);
    }
    // dep: PostgreSQL(role_maintenance) — transaction entry for `revoke_retrieval_query_source`
    let mut txn = pool.pool().begin().await?;
    sqlx::query("SELECT set_config('humaux.tenant_id', $1, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *txn)
        .await?;
    let result = sqlx::query(
        "UPDATE private.retrieval_query_sources \
         SET revoked_at=clock_timestamp(), revocation_reason=$3 \
         WHERE tenant_id=$1 AND query_source_id=$2 AND revoked_at IS NULL",
    )
    .bind(tenant_id)
    .bind(query_source_id)
    .bind(reason)
    .execute(&mut *txn)
    .await?;
    txn.commit().await?;
    Ok(result.rows_affected() == 1)
}

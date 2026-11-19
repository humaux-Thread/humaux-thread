//! `adapters::provisioning` — the single home of production onboarding writes (ADR-0053) and of the operator
//!   re-drive of DEAD distill jobs (ADR-0058 R4), plus the daemon and retention audit guard (ADR-0062/0063).
//! Depends-on: crates=[async-trait, humaux-application, humaux-domain, serde_json, sqlx, uuid]; services=[PostgreSQL(role_maintenance) r=[control.api_keys, control.memberships,
//!   control.retrieval_provider_admission_limits, control.tenants, control.workspaces, projection.family_activations,
//!   projection.stream_checkpoints, projection.tenant_placements] x=[control.audit_event_insert,
//!   control.ensure_admission_tier, control.ensure_user, control.issue_api_key, control.onboard_tenant,
//!   control.onboard_workspace, control.revoke_api_key, control.set_workspace_membership, ops.requeue_dead_distill,
//!   projection.ensure_tenant_placement], PostgreSQL(owner) x=[control.audit_event_insert]]; env=[];
//!   modules=[adapters::entitlement_repo, adapters::membership_repo, adapters::postgres,
//!   application::auth, application::operator_provisioning, domain::audit, domain::identity, domain::ids,
//!   domain::ticket_family]
//! Called-by: [adapters::cost_repo, adapters::reasoning_route_onboarding, adapters::rebuild, adapters::retrieval_provisioning, adapters::role_hygiene, maintenance::bootstrap,
//!   tests, xtask::e2e_seed]
//! Invariants: [every write goes through a 0186 / 0197 owner definer as role_maintenance, no table INSERT here; one transaction
//!   per tenant (onboard_tenant installs the tenant GUC for the caller's transaction);
//!   the maintenance guard borrows the caller transaction and never commits it; no receipt carries a wire key or the pepper]
//! Spec: Baseline §4.2; §6.2.2; §16.2; §16.3; §17.3; §17.6; §17.7; §77; ADR-0017; ADR-0053; ADR-0057; ADR-0058; ADR-0083 D-B;
//!   ADR-0086
//!
//! Every onboarding write runs as `role_maintenance` ([`MaintenanceDbPool`]) through the eight
//! owner SECURITY DEFINER doors of migration 0186 — this module holds no table INSERT of its own.
//! `humaux-maintenance` (the operator CLI) and `xtask e2e-seed` (a thin, 127.0.0.1-only wrapper)
//! both call it, so there is exactly one copy of each onboarding step (ADR-0053 D-A/D-G).
//!
//! Transactions (ADR-0053 D-D / D-F):
//! - [`onboard_tenant`] is ONE transaction: `ensure_user` → `onboard_tenant` (→
//!   `onboard_workspace`) → `ensure_tenant_placement` → `issue_api_key` (only when the tenant was
//!   created) → the §77 audit row. `control.onboard_tenant` installs `humaux.tenant_id` with
//!   `set_config(…, true)`, which lasts until this transaction ends — one transaction per tenant.
//!
//! Secrets: the API key is minted by the caller (the §73.5 hash lives in `humaux-protocol`, which
//! this crate does not depend on) and only its prefix, hash and log fingerprint reach this module;
//! no receipt carries a wire key or the pepper.

use std::collections::BTreeMap;

use humaux_application::auth::canonicalize_email;
use humaux_domain::audit::SYSTEM_TENANT_ID;
use humaux_domain::identity::{MembershipConflict, MembershipMutation, MembershipRole};
use humaux_domain::ids::{TenantId, UserId};
use humaux_domain::ticket_family::TicketFamily;
use serde_json::{Value, json};
use sqlx::Row;
use sqlx::types::time::OffsetDateTime;
use uuid::Uuid;

use crate::entitlement_repo::{self, RecomputeOutcome};
use crate::membership_repo::{self, AdminAction, MembershipRepoError, MembershipRequest};
use humaux_application::operator_provisioning::{self as operator, ProvisioningPort};
pub use humaux_application::operator_provisioning::{
    ActivationReceipt, ApiKeyReceipt, CollectionReceipt, DeployInitReceipt, NewApiKey,
    PlacementReceipt, RequeueReceipt, RequeueSkipReason, RequeueTarget, RequeuedJob, RevokeReceipt,
    SkippedJob, TenantReceipt, TenantRequest, TierReceipt, UserReceipt, WorkspaceActivation,
    WorkspaceReceipt, api_key_prefix,
};

use crate::postgres::MaintenanceDbPool;
type Txn<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

/// §77 `AuditEvent` spellings for this path, defined once next to their only writer (§78.2).
const AUDIT_ACTOR_TYPE: &str = "ADMIN";
pub(crate) const AUDIT_RESULT_SUCCESS: &str = "SUCCESS";
const AUDIT_RESULT_DENIED: &str = "DENIED";
/// §77 onboarding tag shared by the activation adapter.
pub(crate) const AUDIT_RISK_TAG: &str = "onboarding";
const AUDIT_ABSENT: &str = "";

/// Why a provisioning step did not complete. `Refused` is a named, definite refusal that wrote
/// nothing (CLI exit 3); `InvalidInput` a malformed request (exit 2); `Db` / `Qdrant` an
/// infrastructure failure (exit 1). None of them ever carries secret material.
#[derive(Debug)]
pub enum ProvisioningError {
    Refused(String),
    InvalidInput(String),
    Db(sqlx::Error),
    Qdrant(String),
}

impl ProvisioningError {
    /// The `humaux-maintenance` exit code for this failure (ADR-0053 D-F).
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Refused(_) => 3,
            Self::InvalidInput(_) => 2,
            Self::Db(_) | Self::Qdrant(_) => 1,
        }
    }
}

impl std::fmt::Display for ProvisioningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(reason) => write!(f, "refused: {reason}"),
            Self::InvalidInput(reason) => write!(f, "invalid input: {reason}"),
            Self::Db(error) => write!(f, "db: {error}"),
            Self::Qdrant(reason) => write!(f, "qdrant: {reason}"),
        }
    }
}

impl std::error::Error for ProvisioningError {}

impl From<sqlx::Error> for ProvisioningError {
    /// 0186's doors refuse with SQLSTATE 55000 and the reason as the message, and reject a
    /// malformed request with 22023.
    fn from(error: sqlx::Error) -> Self {
        if let sqlx::Error::Database(database) = &error {
            match database.code().as_deref() {
                Some("55000") => return Self::Refused(database.message().to_owned()),
                Some("22023") => return Self::InvalidInput(database.message().to_owned()),
                _ => {}
            }
        }
        Self::Db(error)
    }
}

type Result<T> = std::result::Result<T, ProvisioningError>;

/// The flat `(domain, projection_kind, projection_version)` triples 0186 takes, from the one
/// closed set that owns them (§78.2 — SQL never spells a family).
fn family_triples() -> Vec<String> {
    TicketFamily::ALL
        .iter()
        .flat_map(|f| {
            [
                f.domain().to_owned(),
                f.projection_kind().to_owned(),
                f.projection_version().to_owned(),
            ]
        })
        .collect()
}

pub(crate) fn require_admin(admin: &AdminAction<'_>) -> Result<()> {
    let complete = [
        admin.actor,
        admin.reason,
        admin.ticket,
        admin.trace_id,
        admin.step_up_auth_context,
    ]
    .iter()
    .all(|field| !field.trim().is_empty());
    if complete {
        Ok(())
    } else {
        Err(ProvisioningError::InvalidInput(
            "actor, reason, ticket, trace_id and step_up_auth_context must all be non-empty \
             (§77 Sensitive Admin Action)"
                .to_owned(),
        ))
    }
}

pub(crate) async fn set_tenant(txn: &mut Txn<'_>, tenant_id: Uuid) -> Result<()> {
    sqlx::query("SELECT set_config('humaux.tenant_id', $1, true)")
        .bind(tenant_id.to_string())
        .execute(&mut **txn)
        .await?;
    Ok(())
}

/// One onboarding §77 row (risk tag [`AUDIT_RISK_TAG`]); see [`audit_tagged`].
#[allow(clippy::too_many_arguments)] // one audit row = these facts, in one place
pub(crate) async fn audit(
    txn: &mut Txn<'_>,
    tenant_id: Uuid,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    result: &str,
    admin: &AdminAction<'_>,
    metadata: Value,
) -> Result<Uuid> {
    audit_tagged(
        txn,
        tenant_id,
        (action, AUDIT_RISK_TAG),
        resource_type,
        resource_id,
        result,
        admin,
        metadata,
    )
    .await
}

/// One §77 row through `control.audit_event_insert` (the only audit writer, 0161) — same shape
/// as `membership_repo`'s rows; `(action, risk_tag)`. The tenant GUC must already be installed.
#[allow(clippy::too_many_arguments)] // one audit row = these facts, in one place
pub(crate) async fn audit_tagged(
    txn: &mut Txn<'_>,
    tenant_id: Uuid,
    (action, risk_tag): (&str, &str),
    resource_type: &str,
    resource_id: &str,
    result: &str,
    admin: &AdminAction<'_>,
    mut metadata: Value,
) -> Result<Uuid> {
    if let Value::Object(map) = &mut metadata {
        map.insert("reason".into(), json!(admin.reason));
        map.insert("ticket".into(), json!(admin.ticket));
        map.insert(
            "step_up_auth_context".into(),
            json!(admin.step_up_auth_context),
        );
    }
    let event_id: Uuid = sqlx::query_scalar(
        "SELECT control.audit_event_insert( \
           $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NULL::inet, $12, $13, NULL, NULL, $14)",
    )
    .bind(Uuid::now_v7())
    .bind(OffsetDateTime::now_utc())
    .bind(tenant_id)
    .bind(AUDIT_ACTOR_TYPE)
    .bind(admin.actor)
    .bind(action)
    .bind(resource_type)
    .bind(resource_id)
    .bind(result)
    .bind(admin.ticket)
    .bind(admin.trace_id)
    .bind(AUDIT_ABSENT)
    .bind(vec![risk_tag.to_owned()])
    .bind(metadata)
    .fetch_one(&mut **txn)
    .await?;
    Ok(event_id)
}

/// Install tenant scope on the caller's maintenance transaction.
pub async fn install_maintenance_tenant(txn: &mut Txn<'_>, tenant: Uuid) -> Result<()> {
    set_tenant(txn, tenant).await
}

/// Validate the administrator fields before a retention operation.
pub fn require_retention_admin(admin: &AdminAction<'_>) -> Result<()> {
    require_admin(admin)
}

/// Record the result of a nonempty automatic re-drive in its transaction.
pub async fn audit_maintenance_redrive(
    txn: &mut Txn<'_>,
    tenant: Uuid,
    resource_id: &str,
    admin: &AdminAction<'_>,
    metadata: Value,
) -> Result<Uuid> {
    audit_tagged(
        txn,
        tenant,
        ("DISTILL_AUTO_REDRIVE", REDRIVE_RISK_TAG),
        REDRIVE_RESOURCE,
        resource_id,
        AUDIT_RESULT_SUCCESS,
        admin,
        metadata,
    )
    .await
}

/// Record a retention effect under the system tenant in the transaction that made the change.
pub async fn audit_retention_effect(
    txn: &mut Txn<'_>,
    action: &str,
    (resource_type, resource_id): (&str, &str),
    admin: &AdminAction<'_>,
    metadata: Value,
) -> Result<Uuid> {
    set_tenant(txn, SYSTEM_TENANT_ID.0).await?;
    audit_tagged(
        txn,
        SYSTEM_TENANT_ID.0,
        (action, "retention"),
        resource_type,
        resource_id,
        AUDIT_RESULT_SUCCESS,
        admin,
        metadata,
    )
    .await
}

/// A refusal decided after its transaction rolled back still gets its `DENIED` row (§77 "全部
/// 审计"), in a transaction of its own.
pub(crate) async fn audit_denied(
    pool: &MaintenanceDbPool,
    tenant_id: Uuid,
    (action, risk_tag): (&str, &str),
    (resource_type, resource_id): (&str, &str),
    reason: &str,
    admin: &AdminAction<'_>,
) -> Result<Uuid> {
    // dep: PostgreSQL(role_maintenance) — the DENIED audit row of a rolled-back refusal
    let mut txn = pool.pool().begin().await?;
    set_tenant(&mut txn, tenant_id).await?;
    let id = audit_tagged(
        &mut txn,
        tenant_id,
        (action, risk_tag),
        resource_type,
        resource_id,
        AUDIT_RESULT_DENIED,
        admin,
        json!({ "refusal": reason }),
    )
    .await?;
    txn.commit().await?;
    Ok(id)
}

/// The active 0117 rows that admit `provider_id` for `tenant_id` (GLOBAL, REGION, TENANT,
/// PURPOSE), read under the installed tenant GUC.
async fn read_tiers(
    txn: &mut Txn<'_>,
    provider_id: &str,
    region: &str,
    tenant_id: Option<Uuid>,
) -> Result<Vec<TierReceipt>> {
    let rows = sqlx::query(
        "SELECT tenant_id, region, purpose, tpm_limit, rpm_limit \
           FROM control.retrieval_provider_admission_limits \
          WHERE provider_id = $1 AND effective_to IS NULL \
            AND ((tenant_id IS NULL AND purpose IS NULL AND (region IS NULL OR region = $2)) \
                 OR tenant_id = $3) \
          ORDER BY tenant_id NULLS FIRST, region NULLS FIRST, purpose NULLS FIRST",
    )
    .bind(provider_id)
    .bind(region)
    .bind(tenant_id)
    .fetch_all(&mut **txn)
    .await?;
    rows.iter()
        .map(|row| {
            let tenant: Option<Uuid> = row.try_get("tenant_id")?;
            let region: Option<String> = row.try_get("region")?;
            let purpose: Option<String> = row.try_get("purpose")?;
            let tier = match (tenant.is_some(), region.is_some(), purpose.is_some()) {
                (false, false, _) => "GLOBAL",
                (false, true, _) => "REGION",
                (true, _, false) => "TENANT",
                (true, _, true) => "PURPOSE",
            };
            Ok(TierReceipt {
                tier,
                provider_id: provider_id.to_owned(),
                region,
                purpose,
                tpm_limit: row.try_get("tpm_limit")?,
                rpm_limit: row.try_get("rpm_limit")?,
                created: None,
            })
        })
        .collect()
}

// ============================================================================
// PostgreSQL steps
// ============================================================================

/// `deploy-init`: the deployment-level GLOBAL and REGION 0117 tiers of one provider. Never
/// overwrites an active row. Audited under the §77 system tenant (the rows belong to no tenant).
pub async fn deploy_init(
    pool: &MaintenanceDbPool,
    provider_id: &str,
    region: &str,
    tpm: i64,
    rpm: i64,
    admin: &AdminAction<'_>,
) -> Result<DeployInitReceipt> {
    require_admin(admin)?;
    // dep: PostgreSQL(role_maintenance) — deploy-init transaction (two tier rows + audit)
    let mut txn = pool.pool().begin().await?;
    set_tenant(&mut txn, SYSTEM_TENANT_ID.0).await?;
    let mut created = BTreeMap::new();
    for (tier, tier_region) in [("GLOBAL", None), ("REGION", Some(region))] {
        let inserted: bool =
            sqlx::query_scalar("SELECT control.ensure_admission_tier($1, $2, NULL, NULL, $3, $4)")
                .bind(provider_id)
                .bind(tier_region)
                .bind(tpm)
                .bind(rpm)
                .fetch_one(&mut *txn)
                .await?;
        created.insert(tier, inserted);
    }
    let mut tiers = read_tiers(&mut txn, provider_id, region, None).await?;
    for tier in &mut tiers {
        tier.created = created.get(tier.tier).copied();
    }
    let any_created = created.values().any(|c| *c);
    let audit_event_id = if any_created {
        Some(
            audit(
                &mut txn,
                SYSTEM_TENANT_ID.0,
                "ONBOARD_DEPLOY_INIT",
                "admission_limits",
                provider_id,
                AUDIT_RESULT_SUCCESS,
                admin,
                json!({ "provider_id": provider_id, "region": region, "created": created }),
            )
            .await?,
        )
    } else {
        None
    };
    txn.commit().await?;
    Ok(DeployInitReceipt {
        outcome: if any_created { "created" } else { "existing" },
        tiers,
        audit_event_id,
    })
}

/// `onboard tenant`, transaction T1 (module doc). `mint` is called at most once, with the new
/// tenant's id, and only when the tenant was created — a re-run writes nothing and answers
/// `existing` (a lost key is revoked and reissued under a new key name, never recovered).
#[allow(clippy::too_many_lines)] // T1 is one transaction; splitting it hides its boundary
pub async fn onboard_tenant(
    pool: &MaintenanceDbPool,
    request: &TenantRequest<'_>,
    mint: &mut (dyn FnMut(Uuid) -> NewApiKey + Send),
    admin: &AdminAction<'_>,
) -> Result<TenantReceipt> {
    require_admin(admin)?;
    let (email_original, email_canonical) = canonicalize_email(request.owner_email)
        .map_err(|_| ProvisioningError::InvalidInput("owner email".to_owned()))?;
    if request.scopes.is_empty() {
        return Err(ProvisioningError::InvalidInput("scopes".to_owned()));
    }
    // dep: PostgreSQL(role_maintenance) — onboard tenant T1 (one transaction per tenant)
    let mut txn = pool.pool().begin().await?;
    let user = sqlx::query("SELECT user_id, created FROM control.ensure_user($1, $2)")
        .bind(&email_original)
        .bind(&email_canonical)
        .fetch_one(&mut *txn)
        .await?;
    let owner_user_id: Uuid = user.try_get("user_id")?;
    let owner_user_created: bool = user.try_get("created")?;

    let tenant = sqlx::query(
        "SELECT tenant_id, workspace_id, reasoning_domain_id, created \
           FROM control.onboard_tenant($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
    )
    .bind(request.name)
    .bind(owner_user_id)
    .bind(request.workspace_name)
    .bind(request.reasoning_domain_name)
    .bind(request.plan_key)
    .bind(request.plan_version)
    .bind(request.period_start)
    .bind(request.period_end)
    .bind(request.provider_id)
    .bind(request.region)
    .bind(request.tenant_tpm)
    .bind(request.tenant_rpm)
    .bind(family_triples())
    .fetch_one(&mut *txn)
    .await?;
    let tenant_id: Uuid = tenant.try_get("tenant_id")?;
    let workspace_id: Uuid = tenant.try_get("workspace_id")?;
    let reasoning_domain_id: Uuid = tenant.try_get("reasoning_domain_id")?;
    let created: bool = tenant.try_get("created")?;
    // Already installed by the definer; restated so every later statement's scope is explicit.
    set_tenant(&mut txn, tenant_id).await?;
    if created {
        // §76: onboarding writes the PLAN grants; the snapshot is the projector's, in this same transaction.
        let outcome = entitlement_repo::recompute_in_txn(&mut txn, TenantId(tenant_id))
            .await
            .map_err(|code| {
                ProvisioningError::Refused(format!("entitlement recompute: {code:?}"))
            })?;
        if outcome != RecomputeOutcome::Written {
            return Err(ProvisioningError::Refused(format!(
                "entitlement recompute wrote no snapshot: {outcome:?}"
            )));
        }
    }

    let mut placements = Vec::new();
    for family in TicketFamily::ALL {
        let projection_family = family.collection_name();
        let placed: bool =
            sqlx::query_scalar("SELECT projection.ensure_tenant_placement($1, $2, $3)")
                .bind(tenant_id)
                .bind(&projection_family)
                .bind(request.collection)
                .fetch_one(&mut *txn)
                .await?;
        placements.push(PlacementReceipt {
            projection_family,
            collection_name: request.collection.to_owned(),
            created: placed,
        });
    }

    let api_key = if created {
        let key = mint(tenant_id);
        let api_key_id: Uuid = sqlx::query_scalar(
            "SELECT api_key_id FROM control.issue_api_key($1, $2, $3, $4, $5, $6)",
        )
        .bind(tenant_id)
        .bind(owner_user_id)
        .bind(workspace_id)
        .bind(&key.prefix)
        .bind(&key.key_hash)
        .bind(request.scopes)
        .fetch_one(&mut *txn)
        .await?;
        Some(ApiKeyReceipt {
            api_key_id,
            prefix: key.prefix,
            fingerprint: key.fingerprint,
            created: true,
        })
    } else {
        None
    };

    let admission_tiers = read_tiers(
        &mut txn,
        request.provider_id,
        request.region,
        Some(tenant_id),
    )
    .await?;
    let audit_event_id = if created || placements.iter().any(|p| p.created) {
        Some(
            audit(
                &mut txn,
                tenant_id,
                "ONBOARD_TENANT",
                "tenant",
                &tenant_id.to_string(),
                AUDIT_RESULT_SUCCESS,
                admin,
                json!({
                    "tenant_created": created,
                    "workspace_id": workspace_id.to_string(),
                    "owner_user_id": owner_user_id.to_string(),
                    "api_key_prefix": api_key.as_ref().map(|k| k.prefix.clone()),
                }),
            )
            .await?,
        )
    } else {
        None
    };
    txn.commit().await?;
    Ok(TenantReceipt {
        outcome: if created { "created" } else { "existing" },
        tenant_id,
        tenant_name: request.name.to_owned(),
        owner_user_id,
        owner_user_created,
        workspace_id,
        workspace_name: request.workspace_name.to_owned(),
        reasoning_domain_id,
        api_key,
        admission_tiers,
        placements,
        audit_event_id,
    })
}

/// `onboard workspace`: a PROVISIONING workspace of an existing tenant, its OWNER workspace
/// membership and its zeroed checkpoint rows. Idempotent on (tenant, name).
pub async fn onboard_workspace(
    pool: &MaintenanceDbPool,
    tenant_id: Uuid,
    name: &str,
    owner_user_id: Uuid,
    admin: &AdminAction<'_>,
) -> Result<WorkspaceReceipt> {
    require_admin(admin)?;
    // dep: PostgreSQL(role_maintenance) — onboard workspace transaction
    let mut txn = pool.pool().begin().await?;
    set_tenant(&mut txn, tenant_id).await?;
    let row =
        sqlx::query("SELECT workspace_id, created FROM control.onboard_workspace($1, $2, $3, $4)")
            .bind(tenant_id)
            .bind(name)
            .bind(owner_user_id)
            .bind(family_triples())
            .fetch_one(&mut *txn)
            .await?;
    let workspace_id: Uuid = row.try_get("workspace_id")?;
    let created: bool = row.try_get("created")?;
    let audit_event_id = if created {
        Some(
            audit(
                &mut txn,
                tenant_id,
                "ONBOARD_WORKSPACE",
                "workspace",
                &workspace_id.to_string(),
                AUDIT_RESULT_SUCCESS,
                admin,
                json!({ "name": name, "owner_user_id": owner_user_id.to_string() }),
            )
            .await?,
        )
    } else {
        None
    };
    txn.commit().await?;
    Ok(WorkspaceReceipt {
        outcome: if created { "created" } else { "existing" },
        tenant_id,
        workspace_id,
        workspace_name: name.to_owned(),
        audit_event_id,
    })
}

/// `apikey issue`: one ACTIVE workspace-bound key for (tenant, user, workspace). `existing`
/// when the same prefix is already bound to the same triple.
pub async fn issue_api_key(
    pool: &MaintenanceDbPool,
    tenant_id: Uuid,
    user_id: Uuid,
    workspace_id: Uuid,
    key: &NewApiKey,
    scopes: &[String],
    admin: &AdminAction<'_>,
) -> Result<ApiKeyReceipt> {
    require_admin(admin)?;
    // dep: PostgreSQL(role_maintenance) — apikey issue transaction
    let mut txn = pool.pool().begin().await?;
    set_tenant(&mut txn, tenant_id).await?;
    let row = sqlx::query(
        "SELECT api_key_id, created FROM control.issue_api_key($1, $2, $3, $4, $5, $6)",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(workspace_id)
    .bind(&key.prefix)
    .bind(&key.key_hash)
    .bind(scopes)
    .fetch_one(&mut *txn)
    .await?;
    let api_key_id: Uuid = row.try_get("api_key_id")?;
    let created: bool = row.try_get("created")?;
    if created {
        audit(
            &mut txn,
            tenant_id,
            "APIKEY_ISSUE",
            "api_key",
            &api_key_id.to_string(),
            AUDIT_RESULT_SUCCESS,
            admin,
            json!({ "prefix": key.prefix, "workspace_id": workspace_id.to_string() }),
        )
        .await?;
    }
    txn.commit().await?;
    Ok(ApiKeyReceipt {
        api_key_id,
        prefix: key.prefix.clone(),
        fingerprint: key.fingerprint.clone(),
        created,
    })
}

/// `apikey revoke`: idempotent (`changed = false` on an already revoked key).
pub async fn revoke_api_key(
    pool: &MaintenanceDbPool,
    tenant_id: Uuid,
    prefix: &str,
    admin: &AdminAction<'_>,
) -> Result<RevokeReceipt> {
    require_admin(admin)?;
    // dep: PostgreSQL(role_maintenance) — apikey revoke transaction
    let mut txn = pool.pool().begin().await?;
    set_tenant(&mut txn, tenant_id).await?;
    let row = sqlx::query("SELECT api_key_id, changed FROM control.revoke_api_key($1, $2)")
        .bind(tenant_id)
        .bind(prefix)
        .fetch_one(&mut *txn)
        .await?;
    let api_key_id: Uuid = row.try_get("api_key_id")?;
    let changed: bool = row.try_get("changed")?;
    let audit_event_id = if changed {
        Some(
            audit(
                &mut txn,
                tenant_id,
                "APIKEY_REVOKE",
                "api_key",
                &api_key_id.to_string(),
                AUDIT_RESULT_SUCCESS,
                admin,
                json!({ "prefix": prefix }),
            )
            .await?,
        )
    } else {
        None
    };
    txn.commit().await?;
    Ok(RevokeReceipt {
        outcome: if changed { "created" } else { "existing" },
        api_key_id,
        prefix: prefix.to_owned(),
        changed,
        audit_event_id,
    })
}

/// `placement ensure`: the tenant's §17.3 placement row for every ticket family.
pub async fn ensure_placement(
    pool: &MaintenanceDbPool,
    tenant_id: Uuid,
    collection: &str,
    admin: &AdminAction<'_>,
) -> Result<Vec<PlacementReceipt>> {
    require_admin(admin)?;
    // dep: PostgreSQL(role_maintenance) — placement ensure transaction
    let mut txn = pool.pool().begin().await?;
    set_tenant(&mut txn, tenant_id).await?;
    let mut placements = Vec::new();
    for family in TicketFamily::ALL {
        let projection_family = family.collection_name();
        let created: bool =
            sqlx::query_scalar("SELECT projection.ensure_tenant_placement($1, $2, $3)")
                .bind(tenant_id)
                .bind(&projection_family)
                .bind(collection)
                .fetch_one(&mut *txn)
                .await?;
        placements.push(PlacementReceipt {
            projection_family,
            collection_name: collection.to_owned(),
            created,
        });
    }
    if placements.iter().any(|p| p.created) {
        audit(
            &mut txn,
            tenant_id,
            "PLACEMENT_ENSURE",
            "tenant_placement",
            collection,
            AUDIT_RESULT_SUCCESS,
            admin,
            json!({ "collection": collection }),
        )
        .await?;
    }
    txn.commit().await?;
    Ok(placements)
}

/// `onboard user`: the user (by canonical email), an ACTIVE tenant membership through the §6.3
/// admin path (`membership_repo::apply`, invite then activate — both audited there), and, when
/// `workspace_id` is given, an ACTIVE workspace membership through 0162's definer.
pub async fn onboard_user(
    pool: &MaintenanceDbPool,
    tenant_id: Uuid,
    email: &str,
    role: MembershipRole,
    workspace_id: Option<Uuid>,
    admin: &AdminAction<'_>,
) -> Result<UserReceipt> {
    require_admin(admin)?;
    let (email_original, email_canonical) = canonicalize_email(email)
        .map_err(|_| ProvisioningError::InvalidInput("email".to_owned()))?;
    // dep: PostgreSQL(role_maintenance) — ensure_user transaction
    let mut txn = pool.pool().begin().await?;
    let row = sqlx::query("SELECT user_id, created FROM control.ensure_user($1, $2)")
        .bind(&email_original)
        .bind(&email_canonical)
        .fetch_one(&mut *txn)
        .await?;
    txn.commit().await?;
    let user_id: Uuid = row.try_get("user_id")?;
    let user_created: bool = row.try_get("created")?;

    let mut changed = user_created;
    for request in [
        MembershipRequest::Invite(role),
        MembershipRequest::Mutate(MembershipMutation::Activate),
    ] {
        match membership_repo::apply(pool, TenantId(tenant_id), UserId(user_id), request, *admin)
            .await
        {
            Ok(_) => changed = true,
            Err(MembershipRepoError::Conflict(MembershipConflict::AlreadyInState)) => {}
            Err(MembershipRepoError::Db(error)) => return Err(ProvisioningError::Db(error)),
            Err(other) => return Err(ProvisioningError::Refused(other.to_string())),
        }
    }

    if let Some(workspace_id) = workspace_id {
        let workspace_role = if role == MembershipRole::Owner {
            "OWNER"
        } else {
            "MEMBER"
        };
        // dep: PostgreSQL(role_maintenance) — workspace membership transaction
        let mut txn = pool.pool().begin().await?;
        set_tenant(&mut txn, tenant_id).await?;
        // 0162's upsert must pass workspace_memberships' RESTRICTIVE self-read policy.
        sqlx::query("SELECT set_config('humaux.user_id', $1, true)")
            .bind(user_id.to_string())
            .execute(&mut *txn)
            .await?;
        sqlx::query("SELECT control.set_workspace_membership($1, $2, $3, $4, 'ACTIVE')")
            .bind(tenant_id)
            .bind(workspace_id)
            .bind(user_id)
            .bind(workspace_role)
            .execute(&mut *txn)
            .await?;
        audit(
            &mut txn,
            tenant_id,
            "ONBOARD_WORKSPACE_MEMBERSHIP",
            "workspace_membership",
            &workspace_id.to_string(),
            AUDIT_RESULT_SUCCESS,
            admin,
            json!({ "user_id": user_id.to_string(), "role": workspace_role }),
        )
        .await?;
        txn.commit().await?;
    }

    // dep: PostgreSQL(role_maintenance) — read back the membership the admin path left
    let mut txn = pool.pool().begin().await?;
    set_tenant(&mut txn, tenant_id).await?;
    let membership = sqlx::query(
        "SELECT state, role FROM control.memberships WHERE tenant_id = $1 AND user_id = $2",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_one(&mut *txn)
    .await?;
    txn.commit().await?;
    Ok(UserReceipt {
        outcome: if changed { "created" } else { "existing" },
        tenant_id,
        user_id,
        user_created,
        membership_state: membership.try_get("state")?,
        membership_role: membership.try_get("role")?,
        workspace_id,
    })
}

// ============================================================================
// Operator re-drive of DEAD distill jobs (ADR-0058 R4, migration 0197)
// ============================================================================

/// §77 risk tag of the distill re-drive rows (not an onboarding step); also the daemon's automatic re-drive rows
/// (ADR-0062 D-P, `maintenance_repo::auto_redrive_schema_failed`).
pub(crate) const REDRIVE_RISK_TAG: &str = "distill_redrive";
const REDRIVE_ACTION: &str = "DISTILL_REQUEUE_DEAD";
/// The §77 resource type of a re-drive row (operator or daemon).
pub(crate) const REDRIVE_RESOURCE: &str = "distill_job";

/// The definer's `skipped` value (0200).
fn requeue_skip_reason(value: &str) -> Option<RequeueSkipReason> {
    match value {
        "evidence_gone" => Some(RequeueSkipReason::EvidenceGone),
        "outbox_settled" => Some(RequeueSkipReason::OutboxSettled),
        _ => None,
    }
}

/// `jobs requeue-dead` (ADR-0058 R4): one transaction re-arms the selected DEAD jobs and their
/// FAILED outbox rows through `ops.requeue_dead_distill` (PENDING, attempt 0, class kept,
/// scheduler row admitted) and appends the §77 row; in class mode the receipt and that row also
/// name every matching DEAD job it skipped, with the reason (0200). A refusal (`job_not_found`,
/// `job_not_dead`, `evidence_gone` / `outbox_settled` in job mode, `no_dead_job`) writes nothing
/// but its DENIED row.
pub async fn requeue_dead_distill(
    pool: &MaintenanceDbPool,
    tenant_id: Uuid,
    target: RequeueTarget<'_>,
    admin: &AdminAction<'_>,
) -> Result<RequeueReceipt> {
    require_admin(admin)?;
    let (job_id, error_class, resource_id) = match target {
        RequeueTarget::Job(job_id) => (Some(job_id), None, job_id.to_string()),
        RequeueTarget::ErrorClass(class) => (None, Some(class), format!("error_class:{class}")),
    };
    // dep: PostgreSQL(role_maintenance) — requeue-dead transaction (definer + audit row)
    let mut txn = pool.pool().begin().await?;
    set_tenant(&mut txn, tenant_id).await?;
    let rows = sqlx::query(
        "SELECT job_id, evidence_id, last_error_class, attempt_spent, skipped \
         FROM ops.requeue_dead_distill($1, $2, $3)",
    )
    .bind(tenant_id)
    .bind(job_id)
    .bind(error_class)
    .fetch_all(&mut *txn)
    .await;
    let rows = match rows.map_err(ProvisioningError::from) {
        Ok(rows) => rows,
        Err(ProvisioningError::Refused(reason)) => {
            txn.rollback().await?;
            audit_denied(
                pool,
                tenant_id,
                (REDRIVE_ACTION, REDRIVE_RISK_TAG),
                (REDRIVE_RESOURCE, &resource_id),
                &reason,
                admin,
            )
            .await?;
            return Err(ProvisioningError::Refused(reason));
        }
        Err(error) => return Err(error),
    };
    let (mut requeued, mut skipped) = (Vec::new(), Vec::new());
    for row in &rows {
        let job_id = row.try_get("job_id")?;
        let last_error_class = row.try_get("last_error_class")?;
        let attempt_spent = row.try_get("attempt_spent")?;
        match row.try_get::<Option<String>, _>("skipped")? {
            None => requeued.push(RequeuedJob {
                job_id,
                evidence_id: row.try_get("evidence_id")?,
                last_error_class,
                attempt_spent,
            }),
            Some(reason) => skipped.push(SkippedJob {
                job_id,
                evidence_id: row.try_get("evidence_id")?,
                last_error_class,
                attempt_spent,
                reason: requeue_skip_reason(&reason).ok_or_else(|| {
                    sqlx::Error::Decode(format!("unknown requeue skip reason {reason}").into())
                })?,
            }),
        }
    }
    let audit_event_id = audit_tagged(
        &mut txn,
        tenant_id,
        (REDRIVE_ACTION, REDRIVE_RISK_TAG),
        REDRIVE_RESOURCE,
        &resource_id,
        AUDIT_RESULT_SUCCESS,
        admin,
        json!({ "requeued": requeued, "skipped": skipped }),
    )
    .await?;
    txn.commit().await?;
    Ok(RequeueReceipt {
        outcome: if requeued.is_empty() {
            "nothing_requeued"
        } else {
            "requeued"
        },
        tenant_id,
        requeued,
        skipped,
        audit_event_id,
    })
}

/// `status --tenant`: read-only facts of one tenant (maintenance SELECTs under its tenant GUC).
#[allow(clippy::too_many_lines)] // one read-only snapshot, one row mapper per table
pub async fn status(pool: &MaintenanceDbPool, tenant_id: Uuid) -> Result<Value> {
    // dep: PostgreSQL(role_maintenance) — read-only status snapshot
    let mut txn = pool.pool().begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *txn)
        .await?;
    set_tenant(&mut txn, tenant_id).await?;
    let tenant = sqlx::query(
        "SELECT name, state, onboarding_name FROM control.tenants WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *txn)
    .await?
    .ok_or_else(|| ProvisioningError::Refused("tenant_not_found".to_owned()))?;
    let workspaces = sqlx::query(
        "SELECT workspace_id, name, lifecycle FROM control.workspaces \
          WHERE tenant_id = $1 ORDER BY created_at",
    )
    .bind(tenant_id)
    .fetch_all(&mut *txn)
    .await?
    .iter()
    .map(|r| {
        Ok(json!({
            "workspace_id": r.try_get::<Uuid, _>("workspace_id")?,
            "name": r.try_get::<String, _>("name")?,
            "lifecycle": r.try_get::<String, _>("lifecycle")?,
        }))
    })
    .collect::<Result<Vec<_>>>()?;
    let families = sqlx::query(
        "SELECT scope_id, domain, projection_kind, projection_version, serving, \
                issued_highwater, projection_highwater \
           FROM projection.stream_checkpoints WHERE tenant_id = $1 \
          ORDER BY scope_id, domain, projection_kind, projection_version",
    )
    .bind(tenant_id)
    .fetch_all(&mut *txn)
    .await?
    .iter()
    .map(|r| {
        Ok(json!({
            "workspace_id": r.try_get::<Uuid, _>("scope_id")?,
            "domain": r.try_get::<String, _>("domain")?,
            "projection_kind": r.try_get::<String, _>("projection_kind")?,
            "projection_version": r.try_get::<String, _>("projection_version")?,
            "serving": r.try_get::<bool, _>("serving")?,
            "issued_highwater": r.try_get::<i64, _>("issued_highwater")?,
            "projection_highwater": r.try_get::<i64, _>("projection_highwater")?,
        }))
    })
    .collect::<Result<Vec<_>>>()?;
    let activations = sqlx::query(
        "SELECT scope_id, domain, projection_version, evidence_kind, collection_generation, \
                probe_id, activated_at::text AS activated_at \
           FROM projection.family_activations WHERE tenant_id = $1 ORDER BY activated_at",
    )
    .bind(tenant_id)
    .fetch_all(&mut *txn)
    .await?
    .iter()
    .map(|r| {
        Ok(json!({
            "workspace_id": r.try_get::<Uuid, _>("scope_id")?,
            "domain": r.try_get::<String, _>("domain")?,
            "projection_version": r.try_get::<String, _>("projection_version")?,
            "evidence_kind": r.try_get::<String, _>("evidence_kind")?,
            "generation": r.try_get::<String, _>("collection_generation")?,
            "probe_id": r.try_get::<Uuid, _>("probe_id")?,
            "activated_at": r.try_get::<String, _>("activated_at")?,
        }))
    })
    .collect::<Result<Vec<_>>>()?;
    let placements = sqlx::query(
        "SELECT projection_family, collection_name FROM projection.tenant_placements \
          WHERE tenant_id = $1 ORDER BY projection_family",
    )
    .bind(tenant_id)
    .fetch_all(&mut *txn)
    .await?
    .iter()
    .map(|r| {
        Ok(json!({
            "projection_family": r.try_get::<String, _>("projection_family")?,
            "collection_name": r.try_get::<String, _>("collection_name")?,
        }))
    })
    .collect::<Result<Vec<_>>>()?;
    let api_keys = sqlx::query(
        "SELECT prefix, status, workspace_id FROM control.api_keys \
          WHERE tenant_id = $1 ORDER BY created_at",
    )
    .bind(tenant_id)
    .fetch_all(&mut *txn)
    .await?
    .iter()
    .map(|r| {
        Ok(json!({
            "prefix": r.try_get::<String, _>("prefix")?,
            "status": r.try_get::<String, _>("status")?,
            "workspace_id": r.try_get::<Option<Uuid>, _>("workspace_id")?,
        }))
    })
    .collect::<Result<Vec<_>>>()?;
    let tiers = sqlx::query(
        "SELECT provider_id, region, purpose, tpm_limit, rpm_limit \
           FROM control.retrieval_provider_admission_limits \
          WHERE tenant_id = $1 AND effective_to IS NULL ORDER BY provider_id, purpose NULLS FIRST",
    )
    .bind(tenant_id)
    .fetch_all(&mut *txn)
    .await?
    .iter()
    .map(|r| {
        Ok(json!({
            "provider_id": r.try_get::<String, _>("provider_id")?,
            "purpose": r.try_get::<Option<String>, _>("purpose")?,
            "tpm_limit": r.try_get::<i64, _>("tpm_limit")?,
            "rpm_limit": r.try_get::<i64, _>("rpm_limit")?,
        }))
    })
    .collect::<Result<Vec<_>>>()?;
    txn.commit().await?;
    Ok(json!({
        "outcome": "existing",
        "tenant_id": tenant_id,
        "tenant_name": tenant.try_get::<String, _>("name")?,
        "tenant_state": tenant.try_get::<String, _>("state")?,
        "onboarding_name": tenant.try_get::<Option<String>, _>("onboarding_name")?,
        "workspaces": workspaces,
        "families": families,
        "activations": activations,
        "placements": placements,
        "api_keys": api_keys,
        "tenant_tiers": tiers,
    }))
}

impl From<ProvisioningError> for operator::ProvisioningError {
    fn from(error: ProvisioningError) -> Self {
        match error {
            ProvisioningError::Refused(reason) => Self::Refused(reason),
            ProvisioningError::InvalidInput(reason) => Self::InvalidInput(reason),
            ProvisioningError::Db(error) => Self::Infrastructure(format!("db: {error}")),
            ProvisioningError::Qdrant(reason) => Self::Infrastructure(format!("qdrant: {reason}")),
        }
    }
}

#[async_trait::async_trait]
impl ProvisioningPort for MaintenanceDbPool {
    async fn deploy_init(
        &self,
        provider_id: &str,
        region: &str,
        tpm: i64,
        rpm: i64,
        admin: &AdminAction<'_>,
    ) -> std::result::Result<DeployInitReceipt, operator::ProvisioningError> {
        deploy_init(self, provider_id, region, tpm, rpm, admin)
            .await
            .map_err(Into::into)
    }

    async fn onboard_tenant(
        &self,
        request: &TenantRequest<'_>,
        mint: &mut (dyn FnMut(Uuid) -> NewApiKey + Send),
        admin: &AdminAction<'_>,
    ) -> std::result::Result<TenantReceipt, operator::ProvisioningError> {
        onboard_tenant(self, request, mint, admin)
            .await
            .map_err(Into::into)
    }

    async fn onboard_workspace(
        &self,
        tenant_id: Uuid,
        name: &str,
        owner_user_id: Uuid,
        admin: &AdminAction<'_>,
    ) -> std::result::Result<WorkspaceReceipt, operator::ProvisioningError> {
        onboard_workspace(self, tenant_id, name, owner_user_id, admin)
            .await
            .map_err(Into::into)
    }

    async fn issue_api_key(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        workspace_id: Uuid,
        key: &NewApiKey,
        scopes: &[String],
        admin: &AdminAction<'_>,
    ) -> std::result::Result<ApiKeyReceipt, operator::ProvisioningError> {
        issue_api_key(self, tenant_id, user_id, workspace_id, key, scopes, admin)
            .await
            .map_err(Into::into)
    }

    async fn revoke_api_key(
        &self,
        tenant_id: Uuid,
        prefix: &str,
        admin: &AdminAction<'_>,
    ) -> std::result::Result<RevokeReceipt, operator::ProvisioningError> {
        revoke_api_key(self, tenant_id, prefix, admin)
            .await
            .map_err(Into::into)
    }

    async fn ensure_placement(
        &self,
        tenant_id: Uuid,
        collection: &str,
        admin: &AdminAction<'_>,
    ) -> std::result::Result<Vec<PlacementReceipt>, operator::ProvisioningError> {
        ensure_placement(self, tenant_id, collection, admin)
            .await
            .map_err(Into::into)
    }

    async fn onboard_user(
        &self,
        tenant_id: Uuid,
        email: &str,
        role: MembershipRole,
        workspace_id: Option<Uuid>,
        admin: &AdminAction<'_>,
    ) -> std::result::Result<UserReceipt, operator::ProvisioningError> {
        onboard_user(self, tenant_id, email, role, workspace_id, admin)
            .await
            .map_err(Into::into)
    }

    async fn requeue_dead_distill(
        &self,
        tenant_id: Uuid,
        target: RequeueTarget<'_>,
        admin: &AdminAction<'_>,
    ) -> std::result::Result<RequeueReceipt, operator::ProvisioningError> {
        requeue_dead_distill(self, tenant_id, target, admin)
            .await
            .map_err(Into::into)
    }

    async fn status(
        &self,
        tenant_id: Uuid,
    ) -> std::result::Result<Value, operator::ProvisioningError> {
        status(self, tenant_id).await.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::api_key_prefix;
    use uuid::Uuid;

    /// The prefix is deterministic per (tenant, key name) — a re-run finds the same key — and
    /// differs across tenants and key names; it satisfies 0186's `^[a-z0-9]{4,64}$`.
    #[test]
    fn api_key_prefix_is_deterministic_and_well_formed() {
        let t = Uuid::now_v7();
        let p = api_key_prefix(t, "k1");
        assert_eq!(p, api_key_prefix(t, "k1"));
        assert_ne!(p, api_key_prefix(t, "k2"));
        assert_ne!(p, api_key_prefix(Uuid::now_v7(), "k1"));
        assert_eq!(p.len(), 14);
        assert!(
            p.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        );
    }
}

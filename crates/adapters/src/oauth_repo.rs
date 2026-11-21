//! `adapters::oauth_repo` — OAuth 2.1 Authorization Server persistence over the `control.oauth_*` doors (migrations 0268/0308/0311):
//!   client registry, one-time authorization codes, grants and single-use refresh rotation. Writes only through definers; no
//!   runtime role holds any privilege on the four tables, so every read goes through a door too.
//!   The chooser settings door (0312) checks live tenant-admin authority and returns a committed row version.
//!   The chooser read door (0313) returns the policy/group subset and holds shared locks through this transaction.
//! Depends-on: crates=[async-trait, humaux-application, humaux-domain, serde_json, sqlx, time]; services=[PostgreSQL(any) r=[control.memberships, control.tenants, control.users] x=[control.oauth_client_lookup, control.oauth_client_register, control.oauth_code_consume, control.oauth_code_issue, control.oauth_consent_tenants, control.oauth_dcr_register, control.oauth_grant_issue, control.oauth_grant_lookup, control.oauth_grant_revoke, control.oauth_chooser_identity_targets, control.oauth_chooser_lock_memberships, control.oauth_refresh_family_revoke, control.oauth_refresh_grant, control.oauth_refresh_rotate, control.read_mcp_chooser_decisions, control.write_mcp_chooser_settings]]; env=[]; modules=[adapters::postgres, adapters::request_guard_repo, adapters::session_repo, application::oauth, application::oauth_exchange, application::session, domain::error, domain::identity, domain::ids]
//! Called-by: [gateway::auth, gateway::bootstrap, tests]
//! Invariants: [a raw code or refresh token never reaches this module: callers pass a SecretHash, whose Debug is redacted;
//!   consume and rotate are single conditional statements inside the doors, so of two concurrent exchanges of one secret
//!   at most one succeeds; a reused refresh token revokes its family and grant and the transaction still commits; a
//!   database failure is DependencyUnavailable, a TTL that does not fit the door is Internal]
//! Spec: ADR-0137; §6.2.1; §73.5; §52; §78.1; §78.2
//!
//! This module executes; the verdicts (PKCE, redirect, resource, epoch compare, lifetime) belong to the pure state machine
//! (M02-9). TTLs and the grant ceiling are the caller's §78.1 policy values. Every step of one exchange runs on one
//! [`OAuthTxn`] so a failure after consume rolls the consume back.

use std::time::Duration;

use humaux_application::oauth::{
    self, AllowedSubset, ConsentSubject, ConsentTarget, OAuthPolicy, ValidatedAuthorize,
    ValidatedClientId,
};
use humaux_application::session::{SessionPolicy, VerifiedSession};
use humaux_domain::error::ErrorCode;
use humaux_domain::identity::{AuthorizationScope, BoundedSet, McpPolicyEffect, PrincipalId};
use humaux_domain::ids::{TenantId, UserId, WorkspaceId};
use serde_json::json;
use sqlx::Row;
use sqlx::types::Uuid;
use time::OffsetDateTime;

use crate::{postgres::RuntimeDbPool, request_guard_repo, session_repo};

// Compatibility exports for existing persistence callers; vocabulary belongs to identity's application port.
pub use humaux_application::oauth_exchange::{
    ClientKind, ClientRecord, CodeIssue, ConsumedCode, GrantIssue, GrantRecord, GrantStatus,
    IssuedGrant, RefreshTokenStatus, RevokeReason, RotateOutcome, SecretHash,
};

/// SQLSTATE of a CHECK violation: the caller sent a value the closed columns or the metadata bound refuse.
const CHECK_VIOLATION: &str = "23514";

fn db_failure(error: sqlx::Error) -> ErrorCode {
    match error.as_database_error().and_then(|db| db.code()) {
        Some(code) if code == CHECK_VIOLATION => ErrorCode::InvalidInput,
        _ => ErrorCode::DependencyUnavailable,
    }
}

fn ttl_seconds(ttl: Duration) -> Result<i32, ErrorCode> {
    i32::try_from(ttl.as_secs())
        .ok()
        .filter(|secs| *secs > 0)
        .ok_or(ErrorCode::Internal)
}

type ConsentCheck = fn(request_guard_repo::EffectiveEntitlementFacts) -> Result<(), ErrorCode>;

#[derive(Clone, Copy)]
struct LockedSelection {
    session: VerifiedSession,
    session_policy: SessionPolicy,
    target: ConsentTarget,
}

/// One open transaction of an OAuth exchange. Dropping it without [`OAuthTxn::commit`] rolls everything back.
pub struct OAuthTxn {
    txn: sqlx::Transaction<'static, sqlx::Postgres>,
    consent: Option<(AuthorizationScope, ConsentCheck)>,
    chooser: Option<LockedSelection>,
}

/// Opens an [`OAuthTxn`] on the gateway pool.
pub async fn begin(pool: &RuntimeDbPool) -> Result<OAuthTxn, ErrorCode> {
    // dep: PostgreSQL(any) — opens a PostgreSQL transaction
    let txn = pool.pool().begin().await.map_err(db_failure)?;
    Ok(OAuthTxn {
        txn,
        consent: None,
        chooser: None,
    })
}

/// Persist the trusted selected target. Browser selection verification belongs to the caller.
pub async fn persist_chooser_consent_code(
    pool: &RuntimeDbPool,
    session: VerifiedSession,
    session_policy: &SessionPolicy,
    target: ConsentTarget,
    validated: &ValidatedAuthorize,
    oauth_policy: &OAuthPolicy<'_>,
    check: ConsentCheck,
) -> Result<String, ErrorCode> {
    let mut txn = begin(pool).await?;
    let allowed = txn
        .allowed_mcp_targets(session.user_id, validated.validated_client_id(), &[target])
        .await?;
    if !allowed.contains(&target) {
        return Err(ErrorCode::Forbidden);
    }
    let (tenant, workspace) = target;
    // dep: PostgreSQL(any) — exact tenant/workspace grants stay locked until the code commits.
    let members_live =
        sqlx::query_scalar::<_, bool>("SELECT control.oauth_chooser_lock_memberships($1, $2, $3)")
            .bind(session.user_id.0)
            .bind(tenant.0)
            .bind(workspace.map(|id| id.0))
            .fetch_one(&mut *txn.txn)
            .await
            .map_err(db_failure)?;
    if !members_live {
        return Err(ErrorCode::Forbidden);
    }
    if !session_repo::chooser_session_live(&mut txn.txn, session, session_policy, true).await? {
        return Err(ErrorCode::Forbidden);
    }
    let scope = AuthorizationScope::new(
        tenant,
        PrincipalId(session.user_id.0),
        Some(session.user_id),
        BoundedSet::new(workspace)?,
    );
    txn.admit_consent(&scope, check).await?;
    txn.chooser = Some(LockedSelection {
        session,
        session_policy: *session_policy,
        target,
    });

    let terms = oauth::issue_code(
        validated,
        &ConsentSubject {
            user_id: session.user_id,
            tenant_id: tenant,
            workspace_id: workspace,
        },
        oauth_policy,
    )?;
    humaux_application::oauth_exchange::persist_consent_code(Box::new(txn), &terms)
        .await?
        .ok_or(ErrorCode::Forbidden)
}

/// Atomically insert a dynamic client if there is unused-client capacity.
pub async fn register_dcr(
    pool: &RuntimeDbPool,
    client_id: &str,
    redirect_uris: &[String],
    metadata: &serde_json::Value,
    source_tags: &[Vec<u8>],
    budget: humaux_application::oauth::RegistrationBudget,
) -> Result<bool, ErrorCode> {
    sqlx::query_scalar("SELECT control.oauth_dcr_register($1, $2, $3, $4, $5, $6, $7)")
        .bind(client_id)
        .bind(redirect_uris)
        .bind(metadata)
        .bind(source_tags)
        .bind(budget.max_unused)
        .bind(budget.max_unused_per_ip)
        .bind(budget.unused_ttl_seconds)
        // dep: PostgreSQL(any) — one guarded, autocommitted registration door
        .fetch_one(pool.pool())
        .await
        .map_err(db_failure)
}

impl OAuthTxn {
    /// Derive this console session's live identity targets and apply the chooser's settings.
    pub async fn chooser_identity_candidates(
        &mut self,
        session: VerifiedSession,
        session_policy: &SessionPolicy,
        client: ValidatedClientId<'_>,
    ) -> Result<AllowedSubset, ErrorCode> {
        if !session_repo::chooser_session_live(&mut self.txn, session, session_policy, false)
            .await?
        {
            return Err(ErrorCode::Forbidden);
        }
        // dep: PostgreSQL(any) — authority derives targets from this session; 257 rows is the overflow sentinel.
        let rows = sqlx::query_as::<_, (Uuid, Option<Uuid>)>(
            "SELECT out_tenant_id, out_workspace_id FROM control.oauth_chooser_identity_targets($1) \
             ORDER BY out_tenant_id, out_workspace_id NULLS FIRST",
        )
        .bind(session.session_id.0)
        .fetch_all(&mut *self.txn)
        .await
        .map_err(db_failure)?;
        let candidates: Vec<_> = rows
            .into_iter()
            .map(|(tenant, workspace)| (TenantId(tenant), workspace.map(WorkspaceId)))
            .collect();
        self.allowed_mcp_targets(session.user_id, client, &candidates)
            .await
    }

    /// Apply policy and allowed groups to authenticated, server-derived candidates (ADR-0137).
    ///
    /// The shared decision locks stay held until this transaction ends, including when no
    /// configuration exists. Use the same transaction for a subsequent protected write.
    pub async fn allowed_mcp_targets(
        &mut self,
        user: UserId,
        client: ValidatedClientId<'_>,
        candidates: &[ConsentTarget],
    ) -> Result<AllowedSubset, ErrorCode> {
        if candidates.len() > BoundedSet::<ConsentTarget>::MAX_LEN {
            return Err(ErrorCode::InvalidInput);
        }
        let (tenants, workspaces): (Vec<_>, Vec<_>) = candidates
            .iter()
            .map(|(tenant, workspace)| (tenant.0, workspace.map(|id| id.0)))
            .unzip();

        // dep: PostgreSQL(any) — chooser decision and shared locks on the current exchange.
        let decisions = sqlx::query_as::<_, (i64, bool)>(
            "SELECT candidate_no, allowed FROM control.read_mcp_chooser_decisions($1, $2, $3, $4)
             ORDER BY candidate_no",
        )
        .bind(user.0)
        .bind(client.as_str())
        .bind(tenants)
        .bind(workspaces)
        .fetch_all(&mut *self.txn)
        .await
        .map_err(|error| {
            if matches!(error, sqlx::Error::ColumnDecode { .. }) {
                return ErrorCode::Internal;
            }
            match error
                .as_database_error()
                .and_then(|db| db.code())
                .as_deref()
            {
                Some("22023") => ErrorCode::InvalidInput,
                Some("25000") => ErrorCode::Internal,
                Some("40001" | "40P01") => ErrorCode::Conflict,
                _ => ErrorCode::DependencyUnavailable,
            }
        })?;

        if decisions.len() != candidates.len()
            || (1_i64..)
                .zip(&decisions)
                .any(|(expected, (ordinal, _))| expected != *ordinal)
        {
            return Err(ErrorCode::Internal);
        }

        BoundedSet::new(
            candidates
                .iter()
                .copied()
                .zip(decisions)
                .filter_map(|(target, (_, allowed))| allowed.then_some(target)),
        )
    }

    /// Lock and validate consent entitlement, retaining the same policy for the post-insert check.
    pub async fn admit_consent(
        &mut self,
        scope: &AuthorizationScope,
        check: ConsentCheck,
    ) -> Result<(), ErrorCode> {
        let facts =
            request_guard_repo::read_effective_entitlements_in_txn(&mut self.txn, scope, true)
                .await?;
        check(facts)?;
        self.consent = Some((scope.clone(), check));
        Ok(())
    }

    /// Commits every door call made on this transaction.
    pub async fn commit(self) -> Result<(), ErrorCode> {
        // dep: PostgreSQL(any) — commits the exchange
        self.txn.commit().await.map_err(db_failure)
    }

    /// Registers or refreshes a client. `false` when the client exists with another kind or is disabled.
    pub async fn register_client(
        &mut self,
        client_id: &str,
        kind: ClientKind,
        redirect_uris: &[String],
        metadata: &serde_json::Value,
        cimd_fetched_at: Option<OffsetDateTime>,
    ) -> Result<bool, ErrorCode> {
        sqlx::query_scalar::<_, bool>("SELECT control.oauth_client_register($1, $2, $3, $4, $5)")
            .bind(client_id)
            .bind(kind.as_db_str())
            .bind(redirect_uris)
            .bind(metadata)
            .bind(cimd_fetched_at)
            // dep: PostgreSQL(any) — calls the oauth_client_register door
            .fetch_one(&mut *self.txn)
            .await
            .map_err(db_failure)
    }

    /// The registered client, if any.
    pub async fn lookup_client(
        &mut self,
        client_id: &str,
    ) -> Result<Option<ClientRecord>, ErrorCode> {
        let row = sqlx::query(
            "SELECT out_kind, out_redirect_uris, out_metadata, out_cimd_fetched_at, out_disabled_at \
             FROM control.oauth_client_lookup($1)",
        )
        .bind(client_id)
        // dep: PostgreSQL(any) — calls the oauth_client_lookup door
        .fetch_optional(&mut *self.txn)
        .await
        .map_err(db_failure)?;
        row.map(|row| -> Result<ClientRecord, sqlx::Error> {
            let kind: String = row.try_get("out_kind")?;
            Ok(ClientRecord {
                kind: ClientKind::from_db_str(&kind),
                redirect_uris: row.try_get("out_redirect_uris")?,
                metadata: row.try_get("out_metadata")?,
                cimd_fetched_at: row.try_get("out_cimd_fetched_at")?,
                disabled_at: row.try_get("out_disabled_at")?,
            })
        })
        .transpose()
        .map_err(db_failure)
    }

    /// Stores an authorization code; its expiry, or `None` when the client is unknown, disabled or the redirect URI is
    /// not registered for it.
    pub async fn issue_code(
        &mut self,
        request: &CodeIssue<'_>,
        ttl: Duration,
    ) -> Result<Option<OffsetDateTime>, ErrorCode> {
        let ttl = ttl_seconds(ttl)?;
        sqlx::query_scalar::<_, Option<OffsetDateTime>>(
            "SELECT control.oauth_code_issue($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(request.code_hash.as_bytes().as_slice())
        .bind(request.client_id)
        .bind(request.redirect_uri)
        .bind(request.pkce_challenge)
        .bind(request.resource)
        .bind(request.user_id.0)
        .bind(request.tenant_id.0)
        .bind(request.workspace_id.map(|w| w.0))
        .bind(request.scopes)
        .bind(ttl)
        // dep: PostgreSQL(any) — calls the oauth_code_issue door
        .fetch_one(&mut *self.txn)
        .await
        .map_err(db_failure)
    }

    /// Consumes a code through the one conditional UPDATE: `Some` only for the single caller that found it unused and
    /// unexpired. The caller compares PKCE, client, redirect and resource; a failed comparison does not give the code back.
    pub async fn consume_code(
        &mut self,
        code_hash: &SecretHash,
    ) -> Result<Option<ConsumedCode>, ErrorCode> {
        let row = sqlx::query(
            "SELECT out_client_id, out_redirect_uri, out_pkce_challenge, out_resource, out_user_id, out_tenant_id, \
                    out_workspace_id, out_scopes \
             FROM control.oauth_code_consume($1)",
        )
        .bind(code_hash.as_bytes().as_slice())
        // dep: PostgreSQL(any) — calls the oauth_code_consume door
        .fetch_optional(&mut *self.txn)
        .await
        .map_err(db_failure)?;
        row.map(|row| -> Result<ConsumedCode, sqlx::Error> {
            Ok(ConsumedCode {
                client_id: row.try_get("out_client_id")?,
                redirect_uri: row.try_get("out_redirect_uri")?,
                pkce_challenge: row.try_get("out_pkce_challenge")?,
                resource: row.try_get("out_resource")?,
                user_id: UserId(row.try_get("out_user_id")?),
                tenant_id: TenantId(row.try_get("out_tenant_id")?),
                workspace_id: row
                    .try_get::<Option<Uuid>, _>("out_workspace_id")?
                    .map(WorkspaceId),
                scopes: row.try_get("out_scopes")?,
            })
        })
        .transpose()
        .map_err(db_failure)
    }

    /// Creates a grant and its first refresh token. `None` when the client is unknown or disabled or the user or tenant
    /// is not ACTIVE. The epoch snapshots are read by the door from the live rows.
    pub async fn issue_grant(
        &mut self,
        request: &GrantIssue<'_>,
    ) -> Result<Option<IssuedGrant>, ErrorCode> {
        let refresh_ttl = ttl_seconds(request.refresh_ttl)?;
        let grant_max_ttl = ttl_seconds(request.grant_max_ttl)?;
        let row = sqlx::query(
            "SELECT out_grant_id, out_family_id, out_refresh_expires_at, out_grant_max_expires_at \
             FROM control.oauth_grant_issue($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(request.user_id.0)
        .bind(request.tenant_id.0)
        .bind(request.workspace_id.map(|w| w.0))
        .bind(request.client_id)
        .bind(request.resource)
        .bind(request.scopes)
        .bind(request.refresh_hash.as_bytes().as_slice())
        .bind(refresh_ttl)
        .bind(grant_max_ttl)
        // dep: PostgreSQL(any) — calls the oauth_grant_issue door
        .fetch_optional(&mut *self.txn)
        .await
        .map_err(db_failure)?;
        row.map(|row| -> Result<IssuedGrant, sqlx::Error> {
            Ok(IssuedGrant {
                grant_id: row.try_get("out_grant_id")?,
                family_id: row.try_get("out_family_id")?,
                refresh_expires_at: row.try_get("out_refresh_expires_at")?,
                grant_max_expires_at: row.try_get("out_grant_max_expires_at")?,
            })
        })
        .transpose()
        .map_err(db_failure)
    }

    /// The grant and the live epochs, or `None` for an unknown grant.
    pub async fn lookup_grant(&mut self, grant_id: Uuid) -> Result<Option<GrantRecord>, ErrorCode> {
        let row = sqlx::query(
            "SELECT out_user_id, out_tenant_id, out_workspace_id, out_client_id, out_resource, out_scopes, out_status, \
                    out_issued_at, out_grant_max_expires_at, out_revoked_at, out_user_epoch_snapshot, \
                    out_tenant_epoch_snapshot, out_live_user_epoch, out_live_tenant_epoch \
             FROM control.oauth_grant_lookup($1)",
        )
        .bind(grant_id)
        // dep: PostgreSQL(any) — calls the oauth_grant_lookup door
        .fetch_optional(&mut *self.txn)
        .await
        .map_err(db_failure)?;
        row.map(|row| -> Result<GrantRecord, sqlx::Error> {
            let status: String = row.try_get("out_status")?;
            Ok(GrantRecord {
                user_id: UserId(row.try_get("out_user_id")?),
                tenant_id: TenantId(row.try_get("out_tenant_id")?),
                workspace_id: row
                    .try_get::<Option<Uuid>, _>("out_workspace_id")?
                    .map(WorkspaceId),
                client_id: row.try_get("out_client_id")?,
                resource: row.try_get("out_resource")?,
                scopes: row.try_get("out_scopes")?,
                status: GrantStatus::from_db_str(&status),
                issued_at: row.try_get("out_issued_at")?,
                grant_max_expires_at: row.try_get("out_grant_max_expires_at")?,
                revoked_at: row.try_get("out_revoked_at")?,
                user_epoch_snapshot: row.try_get("out_user_epoch_snapshot")?,
                tenant_epoch_snapshot: row.try_get("out_tenant_epoch_snapshot")?,
                live_user_epoch: row.try_get("out_live_user_epoch")?,
                live_tenant_epoch: row.try_get("out_live_tenant_epoch")?,
            })
        })
        .transpose()
        .map_err(db_failure)
    }

    /// Resolve the grant's live tenant and account membership under role_gateway's tenant scope.
    pub async fn subject_is_active(&mut self, grant: &GrantRecord) -> Result<bool, ErrorCode> {
        request_guard_repo::set_authorized_ids_local(
            &mut self.txn,
            grant.tenant_id,
            Some(grant.user_id),
        )
        .await?;
        sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM control.memberships m \
             JOIN control.users u USING(user_id) JOIN control.tenants t USING(tenant_id) \
             WHERE m.tenant_id=$1 AND m.user_id=$2 AND m.state='ACTIVE' \
               AND u.state='ACTIVE' AND t.state='ACTIVE')",
        )
        .bind(grant.tenant_id.0)
        .bind(grant.user_id.0)
        // dep: PostgreSQL(any) — read the live, tenant-scoped grant subject
        .fetch_one(&mut *self.txn)
        .await
        .map_err(db_failure)
    }

    /// Revokes a grant and every ACTIVE refresh token of it; `true` only for the call that closed an ACTIVE grant.
    pub async fn revoke_grant(
        &mut self,
        grant_id: Uuid,
        reason: RevokeReason,
    ) -> Result<bool, ErrorCode> {
        sqlx::query_scalar::<_, bool>("SELECT control.oauth_grant_revoke($1, $2)")
            .bind(grant_id)
            .bind(reason.as_db_str())
            // dep: PostgreSQL(any) — calls the oauth_grant_revoke door
            .fetch_one(&mut *self.txn)
            .await
            .map_err(db_failure)
    }

    /// Revokes the grant that owns a refresh-token family, with all its ACTIVE tokens; `false` for an unknown family or one
    /// whose grant was already closed.
    pub async fn revoke_family(
        &mut self,
        family_id: Uuid,
        reason: RevokeReason,
    ) -> Result<bool, ErrorCode> {
        sqlx::query_scalar::<_, bool>("SELECT control.oauth_refresh_family_revoke($1, $2)")
            .bind(family_id)
            .bind(reason.as_db_str())
            // dep: PostgreSQL(any) — calls the oauth_refresh_family_revoke door
            .fetch_one(&mut *self.txn)
            .await
            .map_err(db_failure)
    }

    /// Rotates a refresh token: the presented token becomes ROTATED and `successor` is stored in its family, or reuse
    /// revokes the family and grant. Commit the transaction whatever the outcome, or a reuse revocation is lost.
    pub async fn rotate_refresh(
        &mut self,
        presented: &SecretHash,
        successor: &SecretHash,
        ttl: Duration,
    ) -> Result<RotateOutcome, ErrorCode> {
        let ttl = ttl_seconds(ttl)?;
        let row = sqlx::query(
            "SELECT out_outcome, out_grant_id, out_family_id, out_expires_at \
             FROM control.oauth_refresh_rotate($1, $2, $3)",
        )
        .bind(presented.as_bytes().as_slice())
        .bind(successor.as_bytes().as_slice())
        .bind(ttl)
        // dep: PostgreSQL(any) — calls the oauth_refresh_rotate door
        .fetch_one(&mut *self.txn)
        .await
        .map_err(db_failure)?;
        let outcome: String = row.try_get("out_outcome").map_err(db_failure)?;
        let grant_id: Option<Uuid> = row.try_get("out_grant_id").map_err(db_failure)?;
        let family_id: Option<Uuid> = row.try_get("out_family_id").map_err(db_failure)?;
        let expires_at: Option<OffsetDateTime> =
            row.try_get("out_expires_at").map_err(db_failure)?;
        match (outcome.as_str(), grant_id, family_id, expires_at) {
            ("ROTATED", Some(grant_id), Some(family_id), Some(expires_at)) => {
                Ok(RotateOutcome::Rotated {
                    grant_id,
                    family_id,
                    expires_at,
                })
            }
            ("REUSE_DETECTED", Some(grant_id), Some(family_id), None) => {
                Ok(RotateOutcome::ReuseDetected {
                    grant_id,
                    family_id,
                })
            }
            ("REJECTED", None, None, None) => Ok(RotateOutcome::Rejected),
            _ => Err(ErrorCode::Internal),
        }
    }
}

#[async_trait::async_trait]
impl humaux_application::oauth_exchange::ExchangeStore for RuntimeDbPool {
    async fn begin_exchange(
        &self,
    ) -> Result<Box<dyn humaux_application::oauth_exchange::ExchangeTransaction>, ErrorCode> {
        Ok(Box::new(begin(self).await?))
    }
}

#[async_trait::async_trait]
impl humaux_application::oauth_exchange::ExchangeTransaction for OAuthTxn {
    async fn lookup_client(&mut self, client_id: &str) -> Result<Option<ClientRecord>, ErrorCode> {
        OAuthTxn::lookup_client(self, client_id).await
    }

    async fn consent_tenants(&mut self, user: UserId) -> Result<Vec<TenantId>, ErrorCode> {
        sqlx::query_scalar::<_, Uuid>("SELECT control.oauth_consent_tenants($1)")
            .bind(user.0)
            // dep: PostgreSQL(any) — resolve the live browser subject's tenant.
            .fetch_all(&mut *self.txn)
            .await
            .map(|ids| ids.into_iter().map(TenantId).collect())
            .map_err(db_failure)
    }

    async fn issue_consent_code(
        &mut self,
        request: &CodeIssue<'_>,
        ttl: Duration,
    ) -> Result<bool, ErrorCode> {
        let (scope, _) = self.consent.as_ref().ok_or(ErrorCode::Internal)?;
        if scope.tenant_id() != request.tenant_id || scope.user_id() != Some(request.user_id) {
            return Err(ErrorCode::Forbidden);
        }
        let issued = if let Some(chooser) = self.chooser {
            if chooser.target != (request.tenant_id, request.workspace_id) {
                return Err(ErrorCode::Forbidden);
            }
            self.issue_code(request, ttl).await?.is_some()
        } else {
            sqlx::query_scalar::<_, bool>(
            "SELECT CASE WHEN ARRAY(SELECT control.oauth_consent_tenants($6)) = ARRAY[$7::uuid] \
             THEN control.oauth_code_issue($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) IS NOT NULL ELSE false END",
        )
        .bind(request.code_hash.as_bytes().as_slice())
        .bind(request.client_id)
        .bind(request.redirect_uri)
        .bind(request.pkce_challenge)
        .bind(request.resource)
        .bind(request.user_id.0)
        .bind(request.tenant_id.0)
        .bind(request.workspace_id.map(|id| id.0))
        .bind(request.scopes)
        .bind(ttl_seconds(ttl)?)
        // dep: PostgreSQL(any) — recheck membership and persist in one statement.
        .fetch_one(&mut *self.txn)
        .await
        .map_err(db_failure)?
        };
        if issued {
            let (scope, check) = self.consent.as_ref().ok_or(ErrorCode::Internal)?;
            // The row is still locked, but the clock may have advanced during the insert.
            let facts =
                request_guard_repo::read_effective_entitlements_in_txn(&mut self.txn, scope, false)
                    .await?;
            check(facts)?;
            // The insert may have waited while the subject's memberships changed.
            let live = if let Some(chooser) = self.chooser {
                session_repo::chooser_session_live(
                    &mut self.txn,
                    chooser.session,
                    &chooser.session_policy,
                    false,
                )
                .await?
            } else {
                self.consent_tenants(request.user_id).await?.as_slice() == [request.tenant_id]
            };
            if !live {
                return Err(ErrorCode::Forbidden);
            }
        }
        Ok(issued)
    }

    async fn refresh_grant(
        &mut self,
        hash: &SecretHash,
        client: &str,
    ) -> Result<Option<Uuid>, ErrorCode> {
        sqlx::query_scalar::<_, Option<Uuid>>("SELECT control.oauth_refresh_grant($1, $2)")
            .bind(hash.as_bytes().as_slice())
            .bind(client)
            // dep: PostgreSQL(any) — token digest and client must match.
            .fetch_one(&mut *self.txn)
            .await
            .map_err(db_failure)
    }

    async fn consume_code(&mut self, hash: &SecretHash) -> Result<Option<ConsumedCode>, ErrorCode> {
        OAuthTxn::consume_code(self, hash).await
    }
    async fn issue_grant(
        &mut self,
        issue: &GrantIssue<'_>,
    ) -> Result<Option<IssuedGrant>, ErrorCode> {
        OAuthTxn::issue_grant(self, issue).await
    }
    async fn lookup_grant(&mut self, id: Uuid) -> Result<Option<GrantRecord>, ErrorCode> {
        OAuthTxn::lookup_grant(self, id).await
    }
    async fn rotate_refresh(
        &mut self,
        presented: &SecretHash,
        successor: &SecretHash,
        ttl: Duration,
    ) -> Result<RotateOutcome, ErrorCode> {
        OAuthTxn::rotate_refresh(self, presented, successor, ttl).await
    }
    async fn revoke_family(&mut self, id: Uuid, reason: RevokeReason) -> Result<bool, ErrorCode> {
        OAuthTxn::revoke_family(self, id, reason).await
    }
    async fn revoke_grant(&mut self, id: Uuid, reason: RevokeReason) -> Result<bool, ErrorCode> {
        OAuthTxn::revoke_grant(self, id, reason).await
    }
    async fn commit(self: Box<Self>) -> Result<(), ErrorCode> {
        OAuthTxn::commit(*self).await
    }
}

/// One change through the tenant-admin write door.
pub enum McpChooserChange<'a> {
    /// Enable the policy and configure whether the allowed-group condition applies.
    Configure {
        policy_enabled: bool,
        groups_restricted: bool,
    },
    /// Activate or withdraw one rule effect. `None` matches every value for that dimension.
    Rule {
        workspace_id: Option<WorkspaceId>,
        client_id: Option<&'a str>,
        effect: McpPolicyEffect,
        active: bool,
    },
    /// Create a tenant-local group or set whether it is an allowed group.
    Group { group_id: Uuid, allowed: bool },
    /// Add or revoke a tenant member's group membership.
    Member {
        group_id: Uuid,
        user_id: UserId,
        active: bool,
    },
}

/// Apply a change by a direct human administrator and return the row's new version.
pub async fn write_settings(
    pool: &RuntimeDbPool,
    actor: &AuthorizationScope,
    tenant_id: TenantId,
    change: McpChooserChange<'_>,
) -> Result<i64, ErrorCode> {
    let principal = actor.principal();
    // Human sessions use the user's own principal. Delegated credentials carry a separate principal.
    if actor.user_id() != Some(UserId(principal.0)) {
        return Err(ErrorCode::Forbidden);
    }
    let (action, values) = match change {
        McpChooserChange::Configure {
            policy_enabled,
            groups_restricted,
        } => (
            "configure",
            json!({ "policy_enabled": policy_enabled, "groups_restricted": groups_restricted }),
        ),
        McpChooserChange::Rule {
            workspace_id,
            client_id,
            effect,
            active,
        } => (
            "rule",
            json!({
                "workspace_id": workspace_id.map(|id| id.0),
                "client_id": client_id,
                "effect": effect.as_db_str(),
                "active": active,
            }),
        ),
        McpChooserChange::Group { group_id, allowed } => {
            ("group", json!({ "group_id": group_id, "allowed": allowed }))
        }
        McpChooserChange::Member {
            group_id,
            user_id,
            active,
        } => (
            "member",
            json!({ "group_id": group_id, "user_id": user_id.0, "active": active }),
        ),
    };

    // dep: PostgreSQL(any) — calls the chooser write door (gateway role only).
    sqlx::query_scalar::<_, Option<i64>>(
        "SELECT control.write_mcp_chooser_settings($1, $2, $3, $4, $5)",
    )
    .bind(actor.tenant_id().0)
    .bind(principal.0)
    .bind(tenant_id.0)
    .bind(action)
    .bind(values)
    .fetch_one(pool.pool())
    .await
    .map_err(|error| {
        match error
            .as_database_error()
            .and_then(|db| db.code())
            .as_deref()
        {
            Some("22023" | "22P02" | "23502" | "23503" | "23514") => ErrorCode::InvalidInput,
            Some("40001" | "40P01") => ErrorCode::Conflict,
            _ => ErrorCode::DependencyUnavailable,
        }
    })?
    .ok_or(ErrorCode::Forbidden)
}

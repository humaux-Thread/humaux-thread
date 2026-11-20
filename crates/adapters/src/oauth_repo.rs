//! `adapters::oauth_repo` — OAuth 2.1 Authorization Server persistence over the `control.oauth_*` doors (migrations 0268/0308/0311):
//!   client registry, one-time authorization codes, grants and single-use refresh rotation. Writes only through definers; no
//!   runtime role holds any privilege on the four tables, so every read goes through a door too.
//! Depends-on: crates=[async-trait, humaux-application, humaux-domain, serde_json, sqlx, time]; services=[PostgreSQL(any) x=[control.oauth_client_lookup, control.oauth_client_register, control.oauth_code_consume, control.oauth_code_issue, control.oauth_consent_tenants, control.oauth_dcr_register, control.oauth_grant_issue, control.oauth_grant_lookup, control.oauth_grant_revoke, control.oauth_refresh_family_revoke, control.oauth_refresh_grant, control.oauth_refresh_rotate]]; env=[]; modules=[adapters::postgres, adapters::request_guard_repo, application::oauth_exchange, domain::error, domain::identity, domain::ids]
//! Called-by: [gateway::bootstrap, tests]
//! Invariants: [a raw code or refresh token never reaches this module: callers pass a SecretHash, whose Debug is redacted;
//!   consume and rotate are single conditional statements inside the doors, so of two concurrent exchanges of one secret
//!   at most one succeeds; a reused refresh token revokes its family and grant and the transaction still commits; a
//!   database failure is DependencyUnavailable, a TTL that does not fit the door is Internal]
//! Spec: §6.2.1; §73.5; §52; §78.1; §78.2
//!
//! This module executes; the verdicts (PKCE, redirect, resource, epoch compare, lifetime) belong to the pure state machine
//! (M02-9). TTLs and the grant ceiling are the caller's §78.1 policy values. Every step of one exchange runs on one
//! [`OAuthTxn`] so a failure after consume rolls the consume back.

use std::time::Duration;

use humaux_domain::error::ErrorCode;
use humaux_domain::identity::AuthorizationScope;
use humaux_domain::ids::{TenantId, UserId, WorkspaceId};
use sqlx::Row;
use sqlx::types::Uuid;
use time::OffsetDateTime;

use crate::{postgres::RuntimeDbPool, request_guard_repo};

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

/// One open transaction of an OAuth exchange. Dropping it without [`OAuthTxn::commit`] rolls everything back.
pub struct OAuthTxn {
    txn: sqlx::Transaction<'static, sqlx::Postgres>,
    consent: Option<(AuthorizationScope, ConsentCheck)>,
}

/// Opens an [`OAuthTxn`] on the gateway pool.
pub async fn begin(pool: &RuntimeDbPool) -> Result<OAuthTxn, ErrorCode> {
    // dep: PostgreSQL(any) — opens a PostgreSQL transaction
    let txn = pool.pool().begin().await.map_err(db_failure)?;
    Ok(OAuthTxn { txn, consent: None })
}

/// Atomically insert a dynamic client if there is unused-client capacity.
pub async fn register_dcr(
    pool: &RuntimeDbPool,
    client_id: &str,
    redirect_uris: &[String],
    metadata: &serde_json::Value,
    max_unused: i64,
) -> Result<bool, ErrorCode> {
    sqlx::query_scalar("SELECT control.oauth_dcr_register($1, $2, $3, $4)")
        .bind(client_id)
        .bind(redirect_uris)
        .bind(metadata)
        .bind(max_unused)
        // dep: PostgreSQL(any) — one guarded, autocommitted registration door
        .fetch_one(pool.pool())
        .await
        .map_err(db_failure)
}

impl OAuthTxn {
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
        let (scope, check) = self.consent.as_ref().ok_or(ErrorCode::Internal)?;
        if scope.tenant_id() != request.tenant_id || scope.user_id() != Some(request.user_id) {
            return Err(ErrorCode::Forbidden);
        }
        let issued = sqlx::query_scalar::<_, bool>(
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
        .map_err(db_failure)?;
        if issued {
            // The row is still locked, but the clock may have advanced during the insert.
            let facts =
                request_guard_repo::read_effective_entitlements_in_txn(&mut self.txn, scope, false)
                    .await?;
            check(facts)?;
            // The insert may have waited while the subject's memberships changed.
            if self.consent_tenants(request.user_id).await?.as_slice() != [request.tenant_id] {
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

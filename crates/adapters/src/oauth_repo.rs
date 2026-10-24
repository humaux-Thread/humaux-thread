//! `adapters::oauth_repo` — OAuth 2.1 Authorization Server persistence over the nine `control.oauth_*` doors (migration 0268):
//!   client registry, one-time authorization codes, grants and single-use refresh rotation. Writes only through definers; no
//!   runtime role holds any privilege on the four tables, so every read goes through a door too.
//! Depends-on: crates=[humaux-domain, serde_json, sha2, sqlx, time]; services=[PostgreSQL(any) x=[control.oauth_client_lookup, control.oauth_client_register, control.oauth_code_consume, control.oauth_code_issue, control.oauth_grant_issue, control.oauth_grant_lookup, control.oauth_grant_revoke, control.oauth_refresh_family_revoke, control.oauth_refresh_rotate]]; env=[]; modules=[adapters::postgres, domain::error, domain::ids]
//! Called-by: [tests]
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
use humaux_domain::ids::{TenantId, UserId, WorkspaceId};
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::types::Uuid;
use time::OffsetDateTime;

use crate::postgres::RuntimeDbPool;

macro_rules! db_enum {
    (
        $(#[$meta:meta])*
        $name:ident { $($(#[$vmeta:meta])* $variant:ident => $wire:literal),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vmeta])* $variant,)+
        }

        impl $name {
            /// Every variant, in CHECK order.
            pub const ALL: [$name; { [$(stringify!($variant)),+].len() }] = [$($name::$variant,)+];

            /// SQL CHECK spelling, verbatim.
            pub const fn as_db_str(self) -> &'static str {
                match self {
                    $($name::$variant => $wire,)+
                }
            }

            /// Inverse of [`Self::as_db_str`]; `None` for any other spelling.
            pub fn from_db_str(spelling: &str) -> Option<Self> {
                match spelling {
                    $($wire => Some($name::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

db_enum! {
    /// `control.oauth_client_registrations.kind` — mirrors the CHECK list of migration 0268, both directions (§78.2).
    ClientKind {
        /// Operator-provisioned client.
        Static => "STATIC",
        /// Dynamic client registration (compatibility, M02 D5).
        Dcr => "DCR",
        /// Client ID Metadata Document, fetched by URL (M02 D5).
        Cimd => "CIMD",
        /// Imported from the legacy authorization server for the migration window (M02 D9).
        Legacy => "LEGACY",
    }
}

db_enum! {
    /// `control.oauth_grants.status` — mirrors the CHECK list of migration 0268, both directions (§78.2).
    GrantStatus {
        /// The grant authorizes bearer calls, subject to its expiry and epoch snapshots.
        Active => "ACTIVE",
        /// Closed; stays closed.
        Revoked => "REVOKED",
    }
}

db_enum! {
    /// `control.oauth_grants.revoke_reason` — mirrors the CHECK list of migration 0268, both directions (§78.2).
    RevokeReason {
        /// The user or the client asked for revocation.
        UserRequest => "USER_REQUEST",
        /// A rotated refresh token was presented again (M02 D4).
        RefreshReuse => "REFRESH_REUSE",
        /// The user or tenant security epoch moved past the grant's snapshot.
        SecurityEpoch => "SECURITY_EPOCH",
        /// An operator closed the grant.
        Operator => "OPERATOR",
    }
}

db_enum! {
    /// `control.oauth_refresh_tokens.status` — mirrors the CHECK list of migration 0268, both directions (§78.2).
    RefreshTokenStatus {
        /// The one token of its family that may still be rotated.
        Active => "ACTIVE",
        /// Replaced by its successor; presenting it again is reuse.
        Rotated => "ROTATED",
        /// Closed with its grant.
        Revoked => "REVOKED",
    }
}

/// SHA-256 digest of a high-entropy secret (authorization code, refresh token): the only form in which one is stored or
/// passed to a door. No pepper: the inputs are 256-bit random, so a keyed hash adds nothing the lookup could use.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretHash([u8; 32]);

impl SecretHash {
    /// Hashes `secret`. The caller keeps the plaintext only long enough to hand it to the client.
    pub fn of_secret(secret: &str) -> Self {
        Self(Sha256::digest(secret.as_bytes()).into())
    }

    /// Wraps a digest already computed elsewhere.
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// The 32 digest bytes, as stored in the `bytea` columns.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SecretHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretHash(<redacted>)")
    }
}

/// A registered client as the door returns it.
#[derive(Debug, Clone, PartialEq)]
pub struct ClientRecord {
    /// How the client got registered, or `None` for a spelling this build does not know (never silently mapped).
    pub kind: Option<ClientKind>,
    /// Exact-match redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Registration metadata document.
    pub metadata: serde_json::Value,
    /// When the CIMD document was last fetched.
    pub cimd_fetched_at: Option<OffsetDateTime>,
    /// Set once the client is disabled.
    pub disabled_at: Option<OffsetDateTime>,
}

/// What `issue_code` stores. Every field except the hash is an authorization-request fact the exchange compares later.
#[derive(Debug, Clone)]
pub struct CodeIssue<'a> {
    /// Digest of the code handed to the client.
    pub code_hash: &'a SecretHash,
    /// Client the code is bound to.
    pub client_id: &'a str,
    /// Redirect URI of the authorization request; must be registered for the client.
    pub redirect_uri: &'a str,
    /// PKCE challenge of the request.
    pub pkce_challenge: &'a str,
    /// Resource (audience) the grant will be bound to.
    pub resource: &'a str,
    /// Consenting user.
    pub user_id: UserId,
    /// Tenant the grant will act in.
    pub tenant_id: TenantId,
    /// Workspace narrowing, if any.
    pub workspace_id: Option<WorkspaceId>,
    /// Granted scopes.
    pub scopes: &'a [String],
}

/// The facts a consumed code was issued with.
#[derive(Debug, Clone, PartialEq)]
pub struct ConsumedCode {
    /// Client the code was bound to.
    pub client_id: String,
    /// Redirect URI of the authorization request.
    pub redirect_uri: String,
    /// PKCE challenge to compare the verifier against.
    pub pkce_challenge: String,
    /// Resource the code was bound to.
    pub resource: String,
    /// Consenting user.
    pub user_id: UserId,
    /// Tenant the code was issued in.
    pub tenant_id: TenantId,
    /// Workspace narrowing, if any.
    pub workspace_id: Option<WorkspaceId>,
    /// Granted scopes.
    pub scopes: Vec<String>,
}

/// What `issue_grant` stores besides the first refresh token's digest.
#[derive(Debug, Clone)]
pub struct GrantIssue<'a> {
    /// Consenting user; must be ACTIVE.
    pub user_id: UserId,
    /// Tenant; must be ACTIVE.
    pub tenant_id: TenantId,
    /// Workspace narrowing, if any.
    pub workspace_id: Option<WorkspaceId>,
    /// Client; must be registered and enabled.
    pub client_id: &'a str,
    /// Resource (audience) the grant is bound to.
    pub resource: &'a str,
    /// Granted scopes.
    pub scopes: &'a [String],
    /// Digest of the first refresh token.
    pub refresh_hash: &'a SecretHash,
    /// Refresh token lifetime (§78.1); capped by the grant ceiling.
    pub refresh_ttl: Duration,
    /// Lifetime of the grant itself (§78.1), after which a browser sign-in is required.
    pub grant_max_ttl: Duration,
}

/// A grant and its first refresh token as `issue_grant` created them.
#[derive(Debug, Clone, PartialEq)]
pub struct IssuedGrant {
    /// The new grant.
    pub grant_id: Uuid,
    /// Family of the first refresh token.
    pub family_id: Uuid,
    /// Expiry of the first refresh token.
    pub refresh_expires_at: OffsetDateTime,
    /// Ceiling of the grant.
    pub grant_max_expires_at: OffsetDateTime,
}

/// A grant plus the live epochs, the inputs of the bearer verdict (M02 D3).
#[derive(Debug, Clone, PartialEq)]
pub struct GrantRecord {
    /// Consenting user.
    pub user_id: UserId,
    /// Tenant the grant acts in.
    pub tenant_id: TenantId,
    /// Workspace narrowing, if any.
    pub workspace_id: Option<WorkspaceId>,
    /// Client the grant was issued to.
    pub client_id: String,
    /// Resource the grant is bound to.
    pub resource: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// `None` for a spelling this build does not know (never silently mapped).
    pub status: Option<GrantStatus>,
    /// When the grant was created.
    pub issued_at: OffsetDateTime,
    /// Ceiling after which the grant is dead whatever its refresh tokens say.
    pub grant_max_expires_at: OffsetDateTime,
    /// Set once revoked.
    pub revoked_at: Option<OffsetDateTime>,
    /// User epoch at issuance.
    pub user_epoch_snapshot: i64,
    /// Tenant epoch at issuance.
    pub tenant_epoch_snapshot: i64,
    /// User epoch now.
    pub live_user_epoch: i64,
    /// Tenant epoch now.
    pub live_tenant_epoch: i64,
}

/// Verdict of one refresh rotation. Every variant is committed by the caller.
#[derive(Debug, Clone, PartialEq)]
pub enum RotateOutcome {
    /// The presented token was rotated and its successor stored.
    Rotated {
        /// Grant the family belongs to.
        grant_id: Uuid,
        /// Family of both tokens.
        family_id: Uuid,
        /// Expiry of the successor, capped by the grant ceiling.
        expires_at: OffsetDateTime,
    },
    /// The presented token had already been rotated: its family and grant are now revoked.
    ReuseDetected {
        /// Grant that was revoked.
        grant_id: Uuid,
        /// Family that was revoked.
        family_id: Uuid,
    },
    /// Unknown, expired or revoked token, or a grant that is closed or past its ceiling.
    Rejected,
}

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

/// One open transaction of an OAuth exchange. Dropping it without [`OAuthTxn::commit`] rolls everything back.
pub struct OAuthTxn {
    txn: sqlx::Transaction<'static, sqlx::Postgres>,
}

/// Opens an [`OAuthTxn`] on the gateway pool.
pub async fn begin(pool: &RuntimeDbPool) -> Result<OAuthTxn, ErrorCode> {
    // dep: PostgreSQL(any) — opens a PostgreSQL transaction
    let txn = pool.pool().begin().await.map_err(db_failure)?;
    Ok(OAuthTxn { txn })
}

impl OAuthTxn {
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
        .bind(request.code_hash.0.as_slice())
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
        .bind(code_hash.0.as_slice())
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
        .bind(request.refresh_hash.0.as_slice())
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
        .bind(presented.0.as_slice())
        .bind(successor.0.as_slice())
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

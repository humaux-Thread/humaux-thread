//! `application::oauth_exchange` — M02 token exchange use cases and transactional credential store port.
//! Depends-on: crates=[async-trait, hex, humaux-domain, rand, serde_json, sha2, time, uuid]; services=[]; env=[]; modules=[application::oauth, domain::error, domain::ids]
//! Called-by: [adapters::oauth_repo, application::api_key, application::bearer, gateway::bootstrap, gateway::oauth_http, tests]
//! Invariants: [precheck before consume; spent codes and revoking refusals commit; other refusals roll back]
//! Spec: ADR-0130; §73.5; §78.1; M02 D3/D4.

use crate::oauth::{
    self, AccessTerms, CodeExchangeRequest, CodeTerms, ConsumedCodeView, GrantView, OAuthPolicy,
    OAuthReason, OAuthRefusal, RefreshDecision, RefreshRequest, RevokeCause, RotationFact,
};
use humaux_domain::{
    error::ErrorCode,
    ids::{TenantId, UserId, WorkspaceId},
};
use rand::{TryRngCore as _, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

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

/// The existing PG exchange transaction. Dropping without commit rolls back every door call.
#[async_trait::async_trait]
pub trait ExchangeTransaction: Send {
    /// Read the registered client before establishing a trusted redirect.
    async fn lookup_client(&mut self, client_id: &str) -> Result<Option<ClientRecord>, ErrorCode>;
    /// Return at most two live targets for the current console user.
    async fn consent_tenants(&mut self, user: UserId) -> Result<Vec<TenantId>, ErrorCode>;
    /// Persist the code only if its consenting tenant is still the sole live target.
    async fn issue_consent_code(
        &mut self,
        issue: &CodeIssue<'_>,
        ttl: Duration,
    ) -> Result<bool, ErrorCode>;
    /// Resolve a refresh token only for the presenting client.
    async fn refresh_grant(
        &mut self,
        hash: &SecretHash,
        client: &str,
    ) -> Result<Option<Uuid>, ErrorCode>;

    /// Consume a code once within this exchange.
    async fn consume_code(&mut self, hash: &SecretHash) -> Result<Option<ConsumedCode>, ErrorCode>;
    /// Issue the grant and initial refresh family atomically with consumption.
    async fn issue_grant(
        &mut self,
        issue: &GrantIssue<'_>,
    ) -> Result<Option<IssuedGrant>, ErrorCode>;
    /// Read the grant and live security epochs in this exchange.
    async fn lookup_grant(&mut self, id: Uuid) -> Result<Option<GrantRecord>, ErrorCode>;
    /// Rotate once; reuse closes the family in the same transaction.
    async fn rotate_refresh(
        &mut self,
        presented: &SecretHash,
        successor: &SecretHash,
        ttl: Duration,
    ) -> Result<RotateOutcome, ErrorCode>;
    /// Close a refresh family.
    async fn revoke_family(&mut self, id: Uuid, reason: RevokeReason) -> Result<bool, ErrorCode>;
    /// Close a grant.
    async fn revoke_grant(&mut self, id: Uuid, reason: RevokeReason) -> Result<bool, ErrorCode>;
    /// Commit all exchange effects together.
    async fn commit(self: Box<Self>) -> Result<(), ErrorCode>;
}

/// Persistence boundary used by the two token endpoint use cases.
#[async_trait::async_trait]
pub trait ExchangeStore: Sync {
    /// Open one exchange, with no connection or SQL transaction exposed to the use case.
    async fn begin_exchange(&self) -> Result<Box<dyn ExchangeTransaction>, ErrorCode>;
}

/// Protocol-neutral successful token exchange.
pub struct TokenExchange {
    /// Claims to sign using the issuer keys at the HTTP boundary.
    pub access: AccessTerms,
    /// Successor refresh secret, returned only to the caller.
    pub refresh: String,
    /// The same clock observation used to compute the access lifetime.
    pub observed_at: OffsetDateTime,
}

fn secret() -> Result<String, ErrorCode> {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| ErrorCode::Internal)?;
    Ok(hex::encode(bytes))
}

/// Issue and commit an opaque authorization code, rolling back the consent transaction on refusal.
pub async fn persist_consent_code(
    mut txn: Box<dyn ExchangeTransaction>,
    terms: &CodeTerms,
) -> Result<Option<String>, ErrorCode> {
    let code = secret()?;
    let issued = txn
        .issue_consent_code(
            &CodeIssue {
                code_hash: &SecretHash::of_secret(&code),
                client_id: &terms.client_id,
                redirect_uri: &terms.redirect_uri,
                pkce_challenge: &terms.pkce_challenge,
                resource: &terms.resource,
                user_id: terms.user_id,
                tenant_id: terms.tenant_id,
                workspace_id: terms.workspace_id,
                scopes: &terms.scopes,
            },
            terms.ttl,
        )
        .await?;
    if !issued {
        return Ok(None);
    }
    txn.commit().await?;
    Ok(Some(code))
}

/// Revoke a refresh token and its grant, with no observable difference for an unknown token.
pub async fn revoke_refresh(
    store: &impl ExchangeStore,
    client: &str,
    token: &str,
) -> Result<(), ErrorCode> {
    let mut txn = store.begin_exchange().await?;
    if let Some(grant) = txn
        .refresh_grant(&SecretHash::of_secret(token), client)
        .await?
    {
        txn.revoke_grant(grant, RevokeReason::UserRequest).await?;
    }
    txn.commit().await
}

async fn spent(
    txn: Box<dyn ExchangeTransaction>,
    reason: OAuthReason,
) -> Result<Result<TokenExchange, OAuthReason>, ErrorCode> {
    txn.commit().await?;
    Ok(Err(reason))
}

/// Exchange one authorization code, preserving consumption and refusal ordering.
pub async fn exchange_code(
    store: &impl ExchangeStore,
    policy: &OAuthPolicy<'_>,
    request: CodeExchangeRequest<'_>,
    presented: Option<&str>,
) -> Result<Result<TokenExchange, OAuthReason>, ErrorCode> {
    if let Err(error) = oauth::precheck_code_exchange(&request) {
        return Ok(Err(error.reason));
    }
    let Some(presented) = presented else {
        return Ok(Err(OAuthReason::CODE_INVALID));
    };
    let mut txn = store.begin_exchange().await?;
    let Some(consumed) = txn.consume_code(&SecretHash::of_secret(presented)).await? else {
        return Ok(Err(OAuthReason::CODE_INVALID));
    };
    // ponytail: tokens issued from a replayed code are not revoked (no code→grant link in 0268); add the link + revoke in a migration card (RFC 6749 §4.1.2 SHOULD)
    let view = ConsumedCodeView {
        client_id: &consumed.client_id,
        redirect_uri: &consumed.redirect_uri,
        pkce_challenge: &consumed.pkce_challenge,
        resource: &consumed.resource,
        user_id: consumed.user_id,
        tenant_id: consumed.tenant_id,
        workspace_id: consumed.workspace_id,
        scopes: &consumed.scopes,
    };
    let terms = match oauth::exchange_code(&request, &view, policy) {
        Ok(terms) => terms,
        Err(error) => return spent(txn, error.reason).await,
    };
    let refresh = secret()?;
    let hash = SecretHash::of_secret(&refresh);
    let issued = txn
        .issue_grant(&GrantIssue {
            user_id: terms.user_id,
            tenant_id: terms.tenant_id,
            workspace_id: terms.workspace_id,
            client_id: &terms.client_id,
            resource: &terms.resource,
            scopes: &terms.scopes,
            refresh_hash: &hash,
            refresh_ttl: terms.refresh_ttl,
            grant_max_ttl: terms.grant_max_ttl,
        })
        .await?;
    let Some(issued) = issued else {
        return spent(txn, OAuthReason::GRANT_CLOSED).await;
    };
    let grant = txn
        .lookup_grant(issued.grant_id)
        .await?
        .ok_or(ErrorCode::Internal)?;
    let now = OffsetDateTime::now_utc();
    let access = oauth::access_terms(issued.grant_id, &grant.view(), now, policy);
    let response = Ok(TokenExchange {
        access,
        refresh,
        observed_at: now,
    });
    txn.commit().await?;
    Ok(response)
}

impl GrantRecord {
    pub(crate) fn view(&self) -> GrantView<'_> {
        GrantView {
            client_id: &self.client_id,
            resource: &self.resource,
            scopes: &self.scopes,
            active: self.status == Some(GrantStatus::Active),
            revoked_at: self.revoked_at,
            grant_max_expires_at: self.grant_max_expires_at,
            user_epoch_snapshot: self.user_epoch_snapshot,
            tenant_epoch_snapshot: self.tenant_epoch_snapshot,
            live_user_epoch: self.live_user_epoch,
            live_tenant_epoch: self.live_tenant_epoch,
        }
    }
}

fn rotation_fact(outcome: RotateOutcome) -> RotationFact {
    match outcome {
        RotateOutcome::Rotated {
            grant_id,
            family_id,
            expires_at,
        } => RotationFact::Rotated {
            grant_id,
            family_id,
            expires_at,
        },
        RotateOutcome::ReuseDetected {
            grant_id,
            family_id,
        } => RotationFact::ReuseDetected {
            grant_id,
            family_id,
        },
        RotateOutcome::Rejected => RotationFact::Rejected,
    }
}

/// Rotate a refresh token; non-revoking refusals leave the presented token usable.
pub async fn refresh_token(
    store: &impl ExchangeStore,
    policy: &OAuthPolicy<'_>,
    request: RefreshRequest<'_>,
    presented: Option<&str>,
) -> Result<Result<TokenExchange, OAuthReason>, ErrorCode> {
    let Some(presented) = presented else {
        return Ok(Err(OAuthReason::REFRESH_REJECTED));
    };
    let successor = secret()?;
    let mut txn = store.begin_exchange().await?;
    let fact = rotation_fact(
        txn.rotate_refresh(
            &SecretHash::of_secret(presented),
            &SecretHash::of_secret(&successor),
            policy.refresh_ttl,
        )
        .await?,
    );
    let grant = match fact {
        RotationFact::Rotated { grant_id, .. } => txn.lookup_grant(grant_id).await?,
        _ => None,
    };
    let view = grant.as_ref().map(GrantRecord::view);
    let now = OffsetDateTime::now_utc();
    // RFC 6749 §6 / OPEN-5: requested scope is ignored; only the stored grant's scopes are returned.
    match oauth::decide_refresh(fact, view.as_ref(), &request, now, policy) {
        RefreshDecision::Issue { access, .. } => {
            let response = Ok(TokenExchange {
                access,
                refresh: successor,
                observed_at: now,
            });
            txn.commit().await?;
            Ok(response)
        }
        RefreshDecision::Deny {
            refusal: OAuthRefusal { reason, .. },
            revoke,
        } => {
            if let Some(revoke) = revoke {
                let cause = match revoke.cause {
                    RevokeCause::RefreshReuse => RevokeReason::RefreshReuse,
                    RevokeCause::SecurityEpoch => RevokeReason::SecurityEpoch,
                    RevokeCause::ResourceDisabled => RevokeReason::Operator,
                };
                if let Some(family) = revoke.family_id {
                    txn.revoke_family(family, cause).await?;
                } else {
                    txn.revoke_grant(revoke.grant_id, cause).await?;
                }
                return spent(txn, reason).await;
            }
            Ok(Err(reason))
        }
    }
}

//! `application::api_key` — API credential validation policy (§73.5; ADR-0059 D-H).
//! Depends-on: crates=[hmac, humaux-domain, sha2, async-trait]; services=[]; env=[]; modules=[application::oauth, application::oauth_exchange, domain::network, domain::error, domain::identity, domain::ids]
//! Called-by: [tests, application::bearer, adapters::credential_repo, gateway::auth, gateway::bootstrap, gateway::route_cache]
//! Invariants: [caller-supplied clock and peppers; current pepper precedes previous]
//! Spec: §73.5; ADR-0130

use hmac::{Hmac, KeyInit, Mac};
use humaux_domain::error::ErrorCode;
use humaux_domain::identity::{AuthorizationScope, BoundedSet, PrincipalId};
use humaux_domain::ids::{TenantId, UserId, WorkspaceId};
use humaux_domain::network::Cidr;
use sha2::Sha256;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::SystemTime;

type HmacSha256 = Hmac<Sha256>;

/// §73.5 lifecycle: `CREATE -> ACTIVE -> ROTATING -> REVOKED/EXPIRED`. Wire form matches the
/// `control.api_keys.status` CHECK constraint (migration 0035) — [`ApiKeyStatus::as_db_str`]
/// / [`ApiKeyStatus::from_db_str`] are the only conversion points, kept next to the enum so
/// the two never drift independently. [`ApiKeyStatus::ALL`] + `contract_tests` below hold
/// this against the migration's literal CHECK list (§78.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyStatus {
    Create,
    Active,
    Rotating,
    Revoked,
    Expired,
}

impl ApiKeyStatus {
    /// Every variant, in the same order as `control.api_keys.status`'s CHECK list —
    /// order matters, `protocol::edge::contract_tests` diffs this positionally against the migration.
    pub const ALL: [ApiKeyStatus; 5] = [
        ApiKeyStatus::Create,
        ApiKeyStatus::Active,
        ApiKeyStatus::Rotating,
        ApiKeyStatus::Revoked,
        ApiKeyStatus::Expired,
    ];

    pub const fn as_db_str(self) -> &'static str {
        match self {
            ApiKeyStatus::Create => "CREATE",
            ApiKeyStatus::Active => "ACTIVE",
            ApiKeyStatus::Rotating => "ROTATING",
            ApiKeyStatus::Revoked => "REVOKED",
            ApiKeyStatus::Expired => "EXPIRED",
        }
    }

    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "CREATE" => Some(ApiKeyStatus::Create),
            "ACTIVE" => Some(ApiKeyStatus::Active),
            "ROTATING" => Some(ApiKeyStatus::Rotating),
            "REVOKED" => Some(ApiKeyStatus::Revoked),
            "EXPIRED" => Some(ApiKeyStatus::Expired),
            _ => None,
        }
    }
}

/// §73.5 lifecycle edges. `Active` may skip `Rotating` straight to `Revoked`/`Expired`
/// (rotation is optional); `Rotating` only ever concludes the *old* key via `Revoked`/`Expired`
/// once its overlap window ends — it never goes back to `Active`.
pub fn is_legal_api_key_transition(from: ApiKeyStatus, to: ApiKeyStatus) -> bool {
    use ApiKeyStatus::*;
    matches!(
        (from, to),
        (Create, Active)
            | (Active, Rotating)
            | (Active, Revoked)
            | (Active, Expired)
            | (Rotating, Revoked)
            | (Rotating, Expired)
    )
}

/// §73.5 keyed hash: `HMAC-SHA256(pepper, raw_key)`. A random-entropy API key (unlike a
/// user-chosen password, §74.3) does not need Argon2's deliberately-slow KDF — a fast keyed
/// hash keyed by a server-side pepper is the standard shape for this credential class, and
/// `hmac::Mac::verify_slice` gives constant-time comparison for free (no hand-rolled
/// timing-safe compare here — that would be reinventing a primitive the crate already owns).
pub fn compute_api_key_hash(pepper: &[u8], raw_key: &str) -> Vec<u8> {
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(pepper).expect("HMAC accepts any key length");
    mac.update(raw_key.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn verify_api_key_hash(pepper: &[u8], raw_key: &str, stored_hash: &[u8]) -> bool {
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(pepper).expect("HMAC accepts any key length");
    mac.update(raw_key.as_bytes());
    mac.verify_slice(stored_hash).is_ok()
}

/// One `control.api_keys` row's fields relevant to validation — not the full DB row shape,
/// just what [`validate_api_key`] needs.
pub struct ApiKeyRecord {
    pub key_hash: Vec<u8>,
    pub status: ApiKeyStatus,
    pub allowed_cidrs: Vec<Cidr>,
    pub expires_at: Option<SystemTime>,
    pub revoked_at: Option<SystemTime>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyRejection {
    /// Presented key does not verify against the stored keyed hash.
    HashMismatch,
    Revoked,
    Expired,
    /// `status` is not `Active`/`Rotating` (e.g. still `Create`, never activated).
    InactiveStatus,
    /// `allowed_cidrs` is non-empty and the request IP is not in it (§73.5 credential CIDR
    /// binding).
    CidrNotAllowed,
}

/// Which pepper verified the presented key (ADR-0059 D-H). A result, not an error: `Previous`
/// tells the caller to rehash the stored verifier under the current pepper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PepperMatch {
    Current,
    Previous,
}

/// §73.5 validation: keyed-hash compare, then lifecycle status, then `expires_at`/`revoked_at`
/// timestamps (belt-and-suspenders with `status` — a row can be `Active` in the DB with a
/// stale `expires_at` between the row's actual expiry and the next sweep), then CIDR binding.
/// `now` is caller-supplied (§78.1: no clock read baked into a pure function).
///
/// ADR-0059 D-H: `previous` is the rotation window's old pepper (`None` = window closed); it is
/// tried only after `current` fails.
pub fn validate_api_key(
    record: &ApiKeyRecord,
    presented_key: &str,
    current: &[u8],
    previous: Option<&[u8]>,
    request_ip: IpAddr,
    now: SystemTime,
) -> Result<PepperMatch, ApiKeyRejection> {
    let matched = if verify_api_key_hash(current, presented_key, &record.key_hash) {
        PepperMatch::Current
    } else if previous.is_some_and(|p| verify_api_key_hash(p, presented_key, &record.key_hash)) {
        PepperMatch::Previous
    } else {
        return Err(ApiKeyRejection::HashMismatch);
    };
    match record.status {
        ApiKeyStatus::Revoked => return Err(ApiKeyRejection::Revoked),
        ApiKeyStatus::Expired => return Err(ApiKeyRejection::Expired),
        ApiKeyStatus::Create => return Err(ApiKeyRejection::InactiveStatus),
        ApiKeyStatus::Active | ApiKeyStatus::Rotating => {}
    }
    if record.revoked_at.is_some_and(|at| at <= now) {
        return Err(ApiKeyRejection::Revoked);
    }
    if record.expires_at.is_some_and(|at| at <= now) {
        return Err(ApiKeyRejection::Expired);
    }
    if !record.allowed_cidrs.is_empty() {
        let ip = request_ip.to_canonical();
        if !record.allowed_cidrs.iter().any(|c| c.contains(ip)) {
            return Err(ApiKeyRejection::CidrNotAllowed);
        }
    }
    Ok(matched)
}

/// §73.5 lookup snapshot, including the verifier. Never serialize or log these facts.
pub struct CredentialFacts {
    /// Service principal on the key row.
    pub principal: PrincipalId,
    /// Tenant bound to the key.
    pub tenant_id: TenantId,
    /// Verification inputs for the existing §73.5 policy.
    pub key: ApiKeyRecord,
    /// Stored permission vocabulary, parsed after authentication.
    pub scopes: Vec<String>,
    /// Legacy rows have no recognized binding version.
    pub authorization_version: Option<i16>,
    /// PAT owner, absent for machine credentials.
    pub user_id: Option<UserId>,
    /// Optional ceiling on workspace routing.
    pub workspace_id: Option<WorkspaceId>,
    /// Tenant epoch captured on issue.
    pub tenant_security_epoch: Option<i64>,
    /// User epoch captured on issue.
    pub user_security_epoch: Option<i64>,
    /// Current tenant state.
    pub tenant_state: String,
    /// Current tenant epoch.
    pub live_tenant_security_epoch: i64,
    /// Current user state.
    pub user_state: Option<String>,
    /// Current user epoch.
    pub live_user_security_epoch: Option<i64>,
    /// Current membership in the tenant.
    pub membership_state: Option<String>,
    /// Tenant routing generation from the live credential snapshot (ADR-0133).
    pub routing_revoke_epoch: i64,
}

/// §73.5 service-credential persistence boundary.
#[async_trait::async_trait]
pub trait CredentialStore: Sync {
    /// One inexpensive snapshot before any membership read.
    async fn lookup(&self, prefix: &str) -> Result<Option<CredentialFacts>, ErrorCode>;
    /// Read the PAT owner's live workspace ceiling.
    async fn live_workspaces(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<WorkspaceId>, ErrorCode>;
    /// Compare-and-set under the open rotation epoch, atomically auditing the rewrite.
    async fn rehash(
        &self,
        principal: PrincipalId,
        old: &[u8],
        new: &[u8],
    ) -> Result<Option<bool>, ErrorCode>;
    /// Stamp a validated credential when the caller's throttle allows it.
    async fn mark_used(&self, principal: PrincipalId) -> Result<(), ErrorCode>;
}
/// The closed service-credential scope vocabulary from §33.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CredentialScope {
    /// Read context and recall visible memories.
    ContextRead,
    /// Write memories and evidence through the guarded application path.
    MemoryWrite,
    /// Manage artifacts.
    ArtifactManage,
    /// Manage code knowledge.
    CodeManage,
    /// Manage agent coordination.
    CoordinationManage,
}

impl CredentialScope {
    /// Parses an explicit stored grant; unknown values never imply a permission.
    pub fn parse(value: &str) -> Result<Self, ErrorCode> {
        match value {
            "context:read" => Ok(Self::ContextRead),
            "memory:write" => Ok(Self::MemoryWrite),
            "artifact:manage" => Ok(Self::ArtifactManage),
            "code:manage" => Ok(Self::CodeManage),
            "coordination:manage" => Ok(Self::CoordinationManage),
            _ => Err(ErrorCode::Unauthorized),
        }
    }
}

/// A candidate routing tuple. Only authorization derived from live credential facts can be used by a guard.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CredentialRouteHint {
    /// Candidate account that owns the credential.
    pub tenant_id: TenantId,
    /// Candidate credential identity.
    pub principal: PrincipalId,
    /// Routing generation observed with the binding.
    pub routing_revoke_epoch: i64,
}

/// An authenticated request, not a reusable session or a deserializable tool input.
///
/// This contains no credential secret or verifier. Call the authenticator for each
/// request so revocations, account state, membership, and epochs are re-read.
pub struct VerifiedCredential {
    authorization: AuthorizationScope,
    routing_revoke_epoch: i64,
    scopes: BTreeSet<CredentialScope>,
    workspace_id: Option<WorkspaceId>,
    /// The live §6.1.1 workspace ceiling for this request (ADR-0035): for a PAT the user's ACTIVE
    /// WorkspaceMembership set, for a machine credential its bound singleton or empty. `authorize`
    /// intersects it with the bound + requested workspace on every operation — the SSOT the
    /// stored `authorization.allowed_workspace_ids` was itself derived from. A small de-duped
    /// list (`BoundedSet`-capped upstream), never Ord-sorted — `WorkspaceId` is not `Ord`.
    live_workspace_ids: Vec<WorkspaceId>,
}

impl VerifiedCredential {
    pub(crate) fn from_oauth(
        access: crate::oauth::AccessTerms,
        grant: crate::oauth_exchange::GrantRecord,
        live_workspace_ids: Vec<WorkspaceId>,
    ) -> Result<Self, ErrorCode> {
        let allowed = derive_workspace_scope(&live_workspace_ids, grant.workspace_id, None)?;
        Ok(Self {
            authorization: AuthorizationScope::new(
                grant.tenant_id,
                PrincipalId(access.grant_id),
                Some(grant.user_id),
                allowed,
            ),
            routing_revoke_epoch: 0,
            scopes: access
                .scopes
                .iter()
                .map(|scope| CredentialScope::parse(scope))
                .collect::<Result<_, _>>()?,
            workspace_id: grant.workspace_id,
            live_workspace_ids,
        })
    }

    /// Routing facts from this request's successful live check (ADR-0133).
    pub fn route_hint(&self) -> CredentialRouteHint {
        CredentialRouteHint {
            tenant_id: self.authorization.tenant_id(),
            principal: self.authorization.principal(),
            routing_revoke_epoch: self.routing_revoke_epoch,
        }
    }

    /// RequestGuard may inspect the current authenticated identity for non-business
    /// protocol traffic. Business operations must still call `authorize` for a scope.
    pub fn identity(&self) -> &AuthorizationScope {
        &self.authorization
    }

    /// The server-stored resource-routing bound. A missing tool workspace defaults
    /// to this value; routing must not widen a workspace-bound key to its tenant.
    pub fn bound_workspace_id(&self) -> Option<WorkspaceId> {
        self.workspace_id
    }

    /// Authorizes one operation and only narrows the database-derived scope.
    ///
    /// The RequestGuard must also bind its resource route to
    /// [`Self::bound_workspace_id`]; a visibility predicate alone is not a route.
    pub fn authorize(
        &self,
        required_scope: CredentialScope,
        requested_workspace: Option<WorkspaceId>,
    ) -> Result<AuthorizationScope, ErrorCode> {
        self.authorize_reporting_scope(required_scope, requested_workspace, || {})
    }

    /// Like `authorize`, with a signal reserved for a verified credential missing the required scope.
    pub fn authorize_reporting_scope(
        &self,
        required_scope: CredentialScope,
        requested_workspace: Option<WorkspaceId>,
        mark_insufficient_scope: impl FnOnce(),
    ) -> Result<AuthorizationScope, ErrorCode> {
        if false && !self.scopes.contains(&required_scope) {
            mark_insufficient_scope();
            return Err(ErrorCode::Forbidden);
        }
        // ADR-0035 D-D: the workspace set is `live ∩ {bound} ∩ {requested}`, computed here from the
        // live membership ceiling — never from the credential's baked column, never a union.
        let allowed = derive_workspace_scope(
            &self.live_workspace_ids,
            self.workspace_id,
            requested_workspace,
        )?;
        Ok(AuthorizationScope::new(
            self.authorization.tenant_id(),
            self.authorization.principal(),
            self.authorization.user_id(),
            allowed,
        ))
    }
}

/// ADR-0035 D-D: the per-request workspace authorization set. `live` is the on-behalf-of user's
/// ACTIVE WorkspaceMembership ceiling (the credential's bound singleton / empty for a machine
/// credential); `credential_ws` is the credential's optional bound workspace (a default route and
/// a restriction, never a widening); `requested_ws` is the tool argument, defaulting to the bound
/// route. Each present constraint must be a member of what the live set leaves — otherwise the
/// caller asked for a workspace its live membership does not grant (a non-member workspace, or a
/// stale binding whose membership was revoked): `Forbidden`, before any object lookup. With no
/// constraint the whole live set survives (a machine credential's empty set = TENANT_SHARED only;
/// an unbound PAT's full member set, so one credential reads every member workspace in one
/// session). Replacing either intersection with a union lets a credential reach a non-member
/// workspace — the fault the acceptance tests turn red.
fn derive_workspace_scope(
    live: &[WorkspaceId],
    credential_ws: Option<WorkspaceId>,
    requested_ws: Option<WorkspaceId>,
) -> Result<BoundedSet<WorkspaceId>, ErrorCode> {
    // Start from the live ceiling, then apply the binding and the request as successive
    // narrowings — both restrictions, never widenings. A credential bound to W1 cannot reach a
    // second member workspace W2 even when the request names it (the binding was already applied),
    // and a request for a non-member workspace never survives. Each present constraint must lie in
    // what the previous step left, or the caller is reaching outside its authorization: Forbidden.
    let mut set: Vec<WorkspaceId> = live.to_vec();
    for narrow in [credential_ws, requested_ws].into_iter().flatten() {
        if false && !set.contains(&narrow) {
            return Err(ErrorCode::Forbidden);
        }
        set = vec![narrow];
    }
    BoundedSet::new(set)
}

/// Validate the key before reading live membership, and rehash only a fully authorized binding.
pub async fn authenticate_key(
    store: &impl CredentialStore,
    prefix: &str,
    raw_key: &str,
    pepper: &[u8],
    pepper_previous: Option<&[u8]>,
    request_ip: IpAddr,
    now: SystemTime,
) -> Result<VerifiedCredential, ErrorCode> {
    if pepper.is_empty() {
        return Err(ErrorCode::Internal);
    }
    let record = store.lookup(prefix).await?.ok_or(ErrorCode::Unauthorized)?;
    let pepper_match = validate_api_key(
        &record.key,
        raw_key,
        pepper,
        pepper_previous,
        request_ip,
        now,
    )
    .map_err(|_| ErrorCode::Unauthorized)?;
    // §6.1.1 / ADR-0035 D-D: derive the live workspace ceiling ONLY after a valid key, and only
    // for a user-bound credential (a machine credential's ceiling is its bound singleton / empty,
    // no membership read). A bad key or an unknown prefix never reaches this DB round trip.
    let live: Vec<WorkspaceId> = match record.user_id {
        Some(user) => store.live_workspaces(record.tenant_id, user).await?,
        None => record.workspace_id.into_iter().collect(),
    };
    let authenticated = authenticated_binding(&record, live)?;
    if pepper_match == PepperMatch::Previous {
        rehash_to_current(store, &record, pepper, raw_key).await;
    }
    Ok(authenticated)
}

/// §73.5 / ADR-0059 D-H: moves a previous-pepper verifier to the current pepper. Runs only after
/// the request fully validated and is never fatal to it: a lost compare-and-set, a closed epoch or
/// a DB error is logged by class only (never a key, hash or prefix) and the request proceeds.
async fn rehash_to_current(
    store: &impl CredentialStore,
    record: &CredentialFacts,
    pepper: &[u8],
    raw_key: &str,
) {
    let new_hash = compute_api_key_hash(pepper, raw_key);
    let class = match store
        .rehash(record.principal, &record.key.key_hash, &new_hash)
        .await
    {
        Ok(Some(true)) => return,
        Ok(Some(false) | None) => "pepper_rehash_skipped",
        Err(_) => "pepper_rehash_failed",
    };
    eprintln!("humaux-gateway: auth credential {class}");
}

fn authenticated_binding(
    record: &CredentialFacts,
    live_workspace_ids: Vec<WorkspaceId>,
) -> Result<VerifiedCredential, ErrorCode> {
    if record.authorization_version != Some(1)
        || record.principal.0.is_nil()
        || record.tenant_id.0.is_nil()
        || record.tenant_state != "ACTIVE"
        || record.routing_revoke_epoch < 0
        || record.live_tenant_security_epoch < 0
        || record.tenant_security_epoch != Some(record.live_tenant_security_epoch)
        || record.workspace_id.is_some_and(|id| id.0.is_nil())
    {
        return Err(ErrorCode::Unauthorized);
    }
    if let Some(user_id) = record.user_id {
        if user_id.0.is_nil()
            || record.user_state.as_deref() != Some("ACTIVE")
            || record.membership_state.as_deref() != Some("ACTIVE")
            || record
                .live_user_security_epoch
                .is_none_or(|epoch| epoch < 0)
            || record.user_security_epoch != record.live_user_security_epoch
        {
            return Err(ErrorCode::Unauthorized);
        }
    } else if record.user_security_epoch.is_some() {
        return Err(ErrorCode::Unauthorized);
    }
    let scopes = record
        .scopes
        .iter()
        .map(|scope| CredentialScope::parse(scope))
        .collect::<Result<_, _>>()?;
    let workspace_id = record.workspace_id;
    // The stored scope's set is the live ceiling narrowed by the binding (no request yet): a bound
    // PAT/machine credential -> its bound workspace (Forbidden if the binding is no longer live —
    // a stale capability is gone), an unbound PAT -> its whole live member set (so recall reads
    // every member workspace in one session). `authorize` re-derives per operation with the
    // request's workspace through the same [`derive_workspace_scope`].
    let allowed = derive_workspace_scope(&live_workspace_ids, workspace_id, None)?;
    let authorization =
        AuthorizationScope::new(record.tenant_id, record.principal, record.user_id, allowed);
    Ok(VerifiedCredential {
        authorization,
        routing_revoke_epoch: record.routing_revoke_epoch,
        scopes,
        workspace_id,
        live_workspace_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    /// §6.1.1: a missing grant wins even when the workspace input also fails the bound.
    #[test]
    fn grant_denial_precedes_invalid_workspace_ceiling() {
        let credential = VerifiedCredential {
            routing_revoke_epoch: 0,
            authorization: AuthorizationScope::new(
                TenantId::new(),
                PrincipalId::new(),
                None,
                BoundedSet::new([]).unwrap(),
            ),
            scopes: BTreeSet::from([CredentialScope::ContextRead]),
            workspace_id: None,
            live_workspace_ids: (0..=BoundedSet::<WorkspaceId>::MAX_LEN)
                .map(|_| WorkspaceId::new())
                .collect(),
        };
        assert_eq!(
            credential.authorize(CredentialScope::ContextRead, None),
            Err(ErrorCode::InvalidInput)
        );
        assert_eq!(
            credential.authorize(CredentialScope::MemoryWrite, None),
            Err(ErrorCode::Forbidden)
        );
    }

    /// ADR-0035 D-D: `derive_workspace_scope` is the SSOT for `live ∩ {bound} ∩ {requested}`, and
    /// every narrowing is a restriction — a union anywhere lets a credential reach a non-member
    /// workspace (the acceptance faults).
    #[test]
    fn derive_workspace_scope_is_intersection_never_union() {
        let (a, b, c) = (WorkspaceId::new(), WorkspaceId::new(), WorkspaceId::new());
        let live = vec![a, b];
        let members = |set: &BoundedSet<WorkspaceId>| {
            let mut v: Vec<_> = set.iter().copied().collect();
            v.sort_by_key(|w| w.0);
            v
        };
        // Unbound, no request: the whole live member set (recall reads every member workspace).
        let mut both = [a, b];
        both.sort_by_key(|w| w.0);
        assert_eq!(
            members(&derive_workspace_scope(&live, None, None).unwrap()),
            both.to_vec()
        );
        // Unbound, request a member: narrowed to it; a non-member is Forbidden (union would admit).
        assert_eq!(
            derive_workspace_scope(&live, None, Some(a))
                .unwrap()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![a]
        );
        assert_eq!(
            derive_workspace_scope(&live, None, Some(c)),
            Err(ErrorCode::Forbidden)
        );
        // Bound to A: default route A; a request for a second member B is a widening → Forbidden.
        assert_eq!(
            derive_workspace_scope(&live, Some(a), None)
                .unwrap()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![a]
        );
        assert_eq!(
            derive_workspace_scope(&live, Some(a), Some(b)),
            Err(ErrorCode::Forbidden)
        );
        // Stale binding (bound to C, no longer a live member) → Forbidden, not a tenant-wide read.
        assert_eq!(
            derive_workspace_scope(&live, Some(c), None),
            Err(ErrorCode::Forbidden)
        );
        // Machine credential: empty live, no constraint → empty (TENANT_SHARED only); a request
        // for any workspace is Forbidden.
        assert!(derive_workspace_scope(&[], None, None).unwrap().is_empty());
        assert_eq!(
            derive_workspace_scope(&[], None, Some(a)),
            Err(ErrorCode::Forbidden)
        );
    }

    #[test]
    fn scopes_and_workspace_arguments_can_only_narrow() {
        let workspace = WorkspaceId::new();
        let other = WorkspaceId::new();
        let credential = VerifiedCredential {
            routing_revoke_epoch: 0,
            authorization: AuthorizationScope::new(
                TenantId::new(),
                PrincipalId::new(),
                None,
                BoundedSet::new([workspace]).unwrap(),
            ),
            scopes: BTreeSet::from([CredentialScope::ContextRead]),
            workspace_id: Some(workspace),
            live_workspace_ids: vec![workspace],
        };
        assert_eq!(credential.bound_workspace_id(), Some(workspace));
        assert!(
            credential
                .authorize(CredentialScope::ContextRead, None)
                .is_ok()
        );
        assert!(
            credential
                .authorize(CredentialScope::ContextRead, Some(workspace))
                .is_ok()
        );
        assert_eq!(
            credential.authorize(CredentialScope::ContextRead, Some(other)),
            Err(ErrorCode::Forbidden)
        );
        assert_eq!(
            credential.authorize(CredentialScope::MemoryWrite, None),
            Err(ErrorCode::Forbidden)
        );
        let unbound = VerifiedCredential {
            routing_revoke_epoch: 0,
            authorization: AuthorizationScope::new(
                TenantId::new(),
                PrincipalId::new(),
                None,
                BoundedSet::new([]).unwrap(),
            ),
            scopes: BTreeSet::from([CredentialScope::ContextRead]),
            workspace_id: None,
            live_workspace_ids: Vec::new(),
        };
        assert!(
            unbound
                .authorize(CredentialScope::ContextRead, None)
                .unwrap()
                .allowed_workspace_ids()
                .is_empty()
        );
        assert_eq!(
            unbound.authorize(CredentialScope::ContextRead, Some(workspace)),
            Err(ErrorCode::Forbidden)
        );
        for unknown in [
            "*",
            "context:*",
            "memory:read",
            "CONTEXT:READ",
            "context:read ",
            "",
        ] {
            assert_eq!(
                CredentialScope::parse(unknown),
                Err(ErrorCode::Unauthorized)
            );
        }
    }
}

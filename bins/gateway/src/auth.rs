//! `gateway::auth` — §73.5.1 headless authentication.
//! Depends-on: crates=[humaux-adapters, humaux-domain,
//!   humaux-protocol]; services=[]; env=[]; modules=[adapters::credential_repo, adapters::postgres, domain::error,
//!   domain::identity, domain::ids, protocol::edge]
//! Called-by: [gateway::guard, tests]
//! Invariants: [a PAT's allowed_workspace_ids is always an intersection of the live ACTIVE membership set with the credential's bound workspace; a stale binding whose membership was revoked yields Forbidden, never a silent tenant-wide downgrade; a key verified only by the previous pepper is rehashed after validation and the rehash is never fatal to the request (ADR-0059 D-H); the touch throttle gates only the last_used_at write, so lookup and validation run on every request and a revoked or expired key is refused on the very next request whatever the throttle window holds (M02 D8)]
//! Spec: Baseline §73.5.1; §6.1.1; §33; §78.1; ADR-0035; ADR-0059
//!
//! Credentials and live grants come from the
//! database; tool arguments never supply a principal, user, or workspace grant.
//!
//! §6.1.1 / ADR-0035 (card 13): a PAT's `allowed_workspace_ids` is derived per request from the
//! on-behalf-of user's *live* ACTIVE WorkspaceMembership set (`control.workspace_memberships`,
//! read by [`credential_repo::load_live_workspace_ids`] AFTER `validate_api_key` succeeds and
//! only when the credential carries a user) intersected with the credential's optional bound
//! workspace and any tool-requested workspace — [`derive_workspace_scope`]. The bound workspace
//! is a default route and a narrowing, never an authority; the result is always an intersection,
//! so a credential cannot admit a workspace the live membership does not — and a stale binding
//! whose membership was revoked yields `Forbidden`, not a silent downgrade to tenant-wide reads.
//! Machine credentials (no user) keep the §73.5.1 shape: their live set is their bound singleton
//! or empty, so the same derivation reproduces the 0111 behaviour without a membership read.
//!
//! M02 D8 / §78.1: `last_used_at` is an activity projection, never an authorization input. [`TouchThrottle`] limits
//! how often one credential's stamp is written; it sits after every validity decision in
//! [`authenticate_service_credential`], so the credential row, its epochs and the live memberships are read and
//! checked on every request and no allow decision is ever cached.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use humaux_adapters::credential_repo::{self, CredentialRecord};
use humaux_adapters::postgres::RuntimeDbPool;
use humaux_domain::error::ErrorCode;
use humaux_domain::identity::{AuthorizationScope, BoundedSet, PrincipalId};
use humaux_domain::ids::{TenantId, UserId, WorkspaceId};
use humaux_protocol::edge::{
    ApiKeyRecord, ApiKeyStatus, PepperMatch, compute_api_key_hash, validate_api_key,
};

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

/// An authenticated request, not a reusable session or a deserializable tool input.
///
/// This contains no credential secret or verifier. Call the authenticator for each
/// request so revocations, account state, membership, and epochs are re-read.
pub struct AuthenticatedServiceCredential {
    authorization: AuthorizationScope,
    scopes: BTreeSet<CredentialScope>,
    workspace_id: Option<WorkspaceId>,
    /// The live §6.1.1 workspace ceiling for this request (ADR-0035): for a PAT the user's ACTIVE
    /// WorkspaceMembership set, for a machine credential its bound singleton or empty. `authorize`
    /// intersects it with the bound + requested workspace on every operation — the SSOT the
    /// stored `authorization.allowed_workspace_ids` was itself derived from. A small de-duped
    /// list (`BoundedSet`-capped upstream), never Ord-sorted — `WorkspaceId` is not `Ord`.
    live_workspace_ids: Vec<WorkspaceId>,
}

impl AuthenticatedServiceCredential {
    /// RequestGuard may inspect the current authenticated identity for non-business
    /// protocol traffic. Business operations must still call `authorize` for a scope.
    pub(crate) fn identity(&self) -> &AuthorizationScope {
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
        if !self.scopes.contains(&required_scope) {
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
        if !set.contains(&narrow) {
            return Err(ErrorCode::Forbidden);
        }
        set = vec![narrow];
    }
    BoundedSet::new(set)
}

/// Most credentials [`TouchThrottle`] remembers at once. A memory bound, not business config: past it the oldest entry
/// is dropped, which costs that credential one extra `last_used_at` write and nothing else.
// ponytail: dropping the oldest entry is a linear scan, paid only at the cap; an LRU map if one node ever keeps more
// credentials than this active inside a single interval.
const TOUCH_MAP_CAP: usize = 10_000;

/// M02 D8 / §78.1: the in-process memory that keeps `last_used_at` from being written on every request.
///
/// It answers one question, "write the stamp now?", and holds no credential state: it cannot admit or refuse a
/// request, and [`authenticate_service_credential`] has read and validated the credential before it asks.
/// `interval` is `HUMAUX_GATEWAY_CREDENTIAL_TOUCH_INTERVAL_SECONDS`; zero writes on every request.
pub struct TouchThrottle {
    interval: Duration,
    last_touch: Mutex<HashMap<PrincipalId, SystemTime>>,
}

impl TouchThrottle {
    /// A throttle that lets one write per credential through every `interval`.
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            last_touch: Mutex::new(HashMap::new()),
        }
    }

    /// True when the caller must write the stamp now. The credential is marked as touched at `now` in the same
    /// critical section, so concurrent requests inside one window produce one writer. `now` is the request clock; if
    /// it steps backwards past the mark the credential is due again rather than silent for the difference.
    fn claim(&self, credential: PrincipalId, now: SystemTime) -> bool {
        if self.interval.is_zero() {
            return true;
        }
        // The guarded map is a hint about past writes, valid after any panic, so a poisoned lock stays usable.
        let mut touched = self
            .last_touch
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let inside_window = touched.get(&credential).is_some_and(|previous| {
            now.duration_since(*previous)
                .is_ok_and(|elapsed| elapsed < self.interval)
        });
        if inside_window {
            return false;
        }
        if touched.len() >= TOUCH_MAP_CAP && !touched.contains_key(&credential) {
            let oldest = touched.iter().min_by_key(|(_, at)| **at).map(|(id, _)| *id);
            if let Some(oldest) = oldest {
                touched.remove(&oldest);
            }
        }
        touched.insert(credential, now);
        true
    }

    /// Gives back a claim whose write failed, so the next request retries instead of waiting out the window.
    fn release(&self, credential: PrincipalId) {
        self.last_touch
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&credential);
    }
}

/// Authenticates an HTTP Bearer service credential against current database facts.
///
/// `request_ip` must be the trusted edge-derived client address (§73.1), not a
/// forwarded header or an MCP argument. `pepper` is supplied by bootstrap, never
/// loaded from a request. Errors intentionally contain no credential material.
///
/// Every request reads the credential row and validates it (M02 D8); `touch` only decides whether this request also
/// writes `last_used_at`, and a rejected credential never reaches it.
pub async fn authenticate_service_credential(
    pool: &RuntimeDbPool,
    authorization_header: &str,
    pepper: &[u8],
    pepper_previous: Option<&[u8]>,
    request_ip: IpAddr,
    now: SystemTime,
    touch: &TouchThrottle,
) -> Result<AuthenticatedServiceCredential, ErrorCode> {
    if pepper.is_empty() {
        return Err(ErrorCode::Internal);
    }
    let (prefix, raw_key) = parse_bearer_credential(authorization_header)?;
    let record = credential_repo::lookup(pool, prefix)
        .await?
        .ok_or(ErrorCode::Unauthorized)?;
    let key = ApiKeyRecord {
        key_hash: record.key_hash().to_vec(),
        status: ApiKeyStatus::from_db_str(record.status()).ok_or(ErrorCode::Unauthorized)?,
        allowed_cidrs: record
            .allowed_cidrs()
            .iter()
            .map(|cidr| cidr.parse().map_err(|_| ErrorCode::Unauthorized))
            .collect::<Result<_, _>>()?,
        expires_at: record.expires_at().map(SystemTime::from),
        revoked_at: record.revoked_at().map(SystemTime::from),
    };
    let pepper_match = validate_api_key(&key, raw_key, pepper, pepper_previous, request_ip, now)
        .map_err(|_| ErrorCode::Unauthorized)?;
    // §6.1.1 / ADR-0035 D-D: derive the live workspace ceiling ONLY after a valid key, and only
    // for a user-bound credential (a machine credential's ceiling is its bound singleton / empty,
    // no membership read). A bad key or an unknown prefix never reaches this DB round trip.
    let live: Vec<WorkspaceId> = match record.user_id() {
        Some(user) => credential_repo::load_live_workspace_ids(pool, record.tenant_id(), user)
            .await?
            .into_iter()
            .map(WorkspaceId)
            .collect(),
        None => record.workspace_id().map(WorkspaceId).into_iter().collect(),
    };
    let authenticated = authenticated_binding(&record, live)?;
    if pepper_match == PepperMatch::Previous {
        rehash_to_current(pool, &record, pepper, raw_key).await;
    }
    // Reuse the gateway-only definer; rejected credentials never get a usage write, and the throttle skips only this
    // write: everything above ran on this request whatever the window holds. A failed write fails the request as it
    // always did and hands the claim back, so the next request retries.
    let principal = PrincipalId(record.api_key_id());
    if touch.claim(principal, now)
        && let Err(code) = credential_repo::mark_used(pool, record.api_key_id()).await
    {
        touch.release(principal);
        return Err(code);
    }
    Ok(authenticated)
}

/// §73.5 / ADR-0059 D-H: moves a previous-pepper verifier to the current pepper. Runs only after
/// the request fully validated and is never fatal to it: a lost compare-and-set, a closed epoch or
/// a DB error is logged by class only (never a key, hash or prefix) and the request proceeds.
async fn rehash_to_current(
    pool: &RuntimeDbPool,
    record: &CredentialRecord,
    pepper: &[u8],
    raw_key: &str,
) {
    let new_hash = compute_api_key_hash(pepper, raw_key);
    let class = match credential_repo::rehash(
        pool,
        record.api_key_id(),
        record.key_hash(),
        &new_hash,
    )
    .await
    {
        Ok(Some(true)) => return,
        Ok(Some(false) | None) => "pepper_rehash_skipped",
        Err(_) => "pepper_rehash_failed",
    };
    eprintln!("humaux-gateway: auth credential {class}");
}

fn authenticated_binding(
    record: &CredentialRecord,
    live_workspace_ids: Vec<WorkspaceId>,
) -> Result<AuthenticatedServiceCredential, ErrorCode> {
    if record.authorization_version() != Some(1)
        || record.api_key_id().is_nil()
        || record.tenant_id().is_nil()
        || record.tenant_state() != "ACTIVE"
        || record.live_tenant_security_epoch() < 0
        || record.tenant_security_epoch() != Some(record.live_tenant_security_epoch())
        || record.workspace_id().is_some_and(|id| id.is_nil())
    {
        return Err(ErrorCode::Unauthorized);
    }
    if let Some(user_id) = record.user_id() {
        if user_id.is_nil()
            || record.user_state() != Some("ACTIVE")
            || record.membership_state() != Some("ACTIVE")
            || record
                .live_user_security_epoch()
                .is_none_or(|epoch| epoch < 0)
            || record.user_security_epoch() != record.live_user_security_epoch()
        {
            return Err(ErrorCode::Unauthorized);
        }
    } else if record.user_security_epoch().is_some() {
        return Err(ErrorCode::Unauthorized);
    }
    let scopes = record
        .scopes()
        .iter()
        .map(|scope| CredentialScope::parse(scope))
        .collect::<Result<_, _>>()?;
    let workspace_id = record.workspace_id().map(WorkspaceId);
    // The stored scope's set is the live ceiling narrowed by the binding (no request yet): a bound
    // PAT/machine credential -> its bound workspace (Forbidden if the binding is no longer live —
    // a stale capability is gone), an unbound PAT -> its whole live member set (so recall reads
    // every member workspace in one session). `authorize` re-derives per operation with the
    // request's workspace through the same [`derive_workspace_scope`].
    let allowed = derive_workspace_scope(&live_workspace_ids, workspace_id, None)?;
    let authorization = AuthorizationScope::new(
        TenantId(record.tenant_id()),
        PrincipalId(record.api_key_id()),
        record.user_id().map(UserId),
        allowed,
    );
    Ok(AuthenticatedServiceCredential {
        authorization,
        scopes,
        workspace_id,
        live_workspace_ids,
    })
}

fn parse_bearer_credential(header: &str) -> Result<(&str, &str), ErrorCode> {
    let (scheme, raw_key) = header.split_once(' ').ok_or(ErrorCode::Unauthorized)?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Err(ErrorCode::Unauthorized);
    }
    let (prefix, secret) = raw_key.split_once('.').ok_or(ErrorCode::Unauthorized)?;
    let valid_part = |part: &str, min, max| {
        (min..=max).contains(&part.len())
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    };
    if !valid_part(prefix, 1, 64) || !valid_part(secret, 32, 256) {
        return Err(ErrorCode::Unauthorized);
    }
    Ok((prefix, raw_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// G-M02-2 (M02 D8): one stamp write per credential per interval — the first request claims, every request inside
    /// the window is told to skip, the request one interval later claims again, and a second credential has its own
    /// window. Fault: a throttle that always claims, or one shared by all credentials, turns an assertion red.
    #[test]
    fn touch_throttle_claims_once_per_interval_per_credential() {
        let throttle = TouchThrottle::new(secs(60));
        let (a, b) = (PrincipalId::new(), PrincipalId::new());
        let t0 = SystemTime::UNIX_EPOCH + secs(1_000_000);
        assert!(throttle.claim(a, t0), "first request writes");
        for offset in [0, 1, 30, 59] {
            assert!(!throttle.claim(a, t0 + secs(offset)), "offset {offset}s");
        }
        assert!(throttle.claim(b, t0 + secs(1)), "b has its own window");
        assert!(throttle.claim(a, t0 + secs(60)), "window elapsed");
        assert!(
            !throttle.claim(a, t0 + secs(119)),
            "the window restarts at the claim"
        );
        assert!(throttle.claim(a, t0 + secs(120)));
        assert_eq!(throttle.last_touch.lock().unwrap().len(), 2);
    }

    /// A zero interval writes on every request and remembers nothing; a clock that steps backwards makes the
    /// credential due again; a released claim lets the very next request retry the failed write.
    #[test]
    fn touch_throttle_zero_interval_clock_step_and_release() {
        let zero = TouchThrottle::new(Duration::ZERO);
        let a = PrincipalId::new();
        let t0 = SystemTime::UNIX_EPOCH + secs(1_000_000);
        assert!(zero.claim(a, t0) && zero.claim(a, t0) && zero.claim(a, t0));
        assert!(zero.last_touch.lock().unwrap().is_empty());

        let throttle = TouchThrottle::new(secs(60));
        assert!(throttle.claim(a, t0));
        assert!(!throttle.claim(a, t0 + secs(1)));
        assert!(
            throttle.claim(a, t0 - secs(10)),
            "a request clock behind the mark is due again"
        );
        throttle.release(a);
        assert!(throttle.last_touch.lock().unwrap().is_empty());
        assert!(
            throttle.claim(a, t0),
            "a released claim is claimable at once"
        );
    }

    /// The map never holds more than `TOUCH_MAP_CAP` credentials: the next new credential evicts the oldest mark,
    /// which then writes once more; every other credential keeps its window.
    #[test]
    fn touch_throttle_is_bounded_and_evicts_the_oldest() {
        let throttle = TouchThrottle::new(secs(60));
        let t0 = SystemTime::UNIX_EPOCH + secs(1_000_000);
        let oldest = PrincipalId::new();
        assert!(throttle.claim(oldest, t0));
        for _ in 1..TOUCH_MAP_CAP {
            assert!(throttle.claim(PrincipalId::new(), t0 + secs(1)));
        }
        assert_eq!(throttle.last_touch.lock().unwrap().len(), TOUCH_MAP_CAP);
        let newest = PrincipalId::new();
        assert!(throttle.claim(newest, t0 + secs(2)));
        assert_eq!(throttle.last_touch.lock().unwrap().len(), TOUCH_MAP_CAP);
        assert!(
            !throttle.last_touch.lock().unwrap().contains_key(&oldest),
            "the oldest mark was dropped"
        );
        assert!(
            !throttle.claim(newest, t0 + secs(3)),
            "newest keeps its window"
        );
        assert!(
            throttle.claim(oldest, t0 + secs(3)),
            "the evicted one writes again"
        );
        assert_eq!(throttle.last_touch.lock().unwrap().len(), TOUCH_MAP_CAP);
    }

    #[test]
    fn bearer_wire_is_bounded_and_never_accepts_extra_fields() {
        let secret = "a".repeat(32);
        let raw_key = format!("prefix_1.{secret}");
        let header = format!("bEaReR {raw_key}");
        assert_eq!(
            parse_bearer_credential(&header),
            Ok(("prefix_1", raw_key.as_str()))
        );
        for invalid in [
            raw_key.clone(),
            format!("Basic {raw_key}"),
            format!("Bearer  {raw_key}"),
            format!("Bearer {raw_key} "),
            format!("Bearer {raw_key}.extra"),
            format!("Bearer .{secret}"),
            format!("Bearer {}.{secret}", "p".repeat(65)),
            format!("Bearer prefix.{}", "a".repeat(31)),
            format!("Bearer prefix.{}", "a".repeat(257)),
            format!("Bearer prefix.{secret}\r\n"),
            format!("Bearer 前缀.{secret}"),
        ] {
            assert_eq!(
                parse_bearer_credential(&invalid),
                Err(ErrorCode::Unauthorized)
            );
        }
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
        let credential = AuthenticatedServiceCredential {
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
        let unbound = AuthenticatedServiceCredential {
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

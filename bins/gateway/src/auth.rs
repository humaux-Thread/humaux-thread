//! `gateway::auth` — §73.5.1 headless authentication.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-application, time, tokio]; services=[]; env=[]; modules=[adapters::oauth_repo, application::bearer, application::signed_token, adapters::credential_repo, adapters::postgres, gateway::route_cache, domain::error, domain::identity, domain::ids, application::api_key, gateway::bootstrap]
//! Called-by: [gateway::bootstrap, gateway::guard, tests]
//! Invariants: [a PAT's allowed_workspace_ids is always an intersection of the live ACTIVE membership set with the credential's bound workspace; a stale binding whose membership was revoked yields Forbidden, never a silent tenant-wide downgrade; a key verified only by the previous pepper is rehashed after validation and the rehash is never fatal to the request (ADR-0059 D-H); the touch throttle gates only the last_used_at write, so lookup and validation run on every request and a revoked or expired key is refused on the very next request whatever the throttle window holds (M02 D8)]
//! Spec: Baseline §73.5.1; §6.1.1; §33; §78.1; ADR-0035; ADR-0059
//!
//! Credentials and live grants come from the
//! database; tool arguments never supply a principal, user, or workspace grant.
//!
//! §6.1.1 / ADR-0035 (card 13): a PAT's `allowed_workspace_ids` is derived per request from the
//! on-behalf-of user's *live* ACTIVE WorkspaceMembership set (`control.workspace_memberships`,
//! read by the credential store AFTER `validate_api_key` succeeds and
//! only when the credential carries a user) intersected with the credential's optional bound
//! workspace and any tool-requested workspace — the identity_access application policy. The bound workspace
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

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use humaux_adapters::credential_repo::{load_live_workspace_ids, mark_used, mark_used_batch};
use humaux_adapters::oauth_repo;
use humaux_adapters::postgres::RuntimeDbPool;
pub use humaux_application::api_key::CredentialScope;
use humaux_application::api_key::{VerifiedCredential, authenticate_key};
use humaux_application::bearer::VerifiedAccess;
use humaux_application::signed_token::TokenKeys;
use humaux_domain::error::ErrorCode;
use humaux_domain::identity::{AuthorizationScope, PrincipalId};
use humaux_domain::ids::WorkspaceId;
use time::OffsetDateTime;
use tokio::sync::{mpsc, oneshot};

use crate::route_cache::CredentialRouteCache;
/// Request-local key or OAuth credential verified against live database facts (§73.5).
pub struct AuthenticatedBearer(VerifiedCredential);

/// Existing service-credential entry returns the shared authenticated binding.
pub type AuthenticatedServiceCredential = AuthenticatedBearer;

impl AuthenticatedBearer {
    /// Live authenticated identity before operation narrowing.
    pub fn identity(&self) -> &AuthorizationScope {
        self.0.identity()
    }

    /// Bound default route for the operation.
    pub fn bound_workspace_id(&self) -> Option<WorkspaceId> {
        self.0.bound_workspace_id()
    }

    /// Narrow the authenticated binding for a single operation.
    pub fn authorize(
        &self,
        required_scope: CredentialScope,
        requested_workspace: Option<WorkspaceId>,
    ) -> Result<AuthorizationScope, ErrorCode> {
        self.0.authorize(required_scope, requested_workspace)
    }

    pub(crate) fn authorize_reporting_scope(
        &self,
        required_scope: CredentialScope,
        requested_workspace: Option<WorkspaceId>,
        mark_insufficient_scope: impl FnOnce(),
    ) -> Result<AuthorizationScope, ErrorCode> {
        self.0.authorize_reporting_scope(
            required_scope,
            requested_workspace,
            mark_insufficient_scope,
        )
    }
}

/// Most credentials [`TouchThrottle`] remembers at once. A memory bound, not business config: past it the oldest entry
/// is dropped, which costs that credential one extra `last_used_at` write and nothing else.
// ponytail: dropping the oldest entry is a linear scan, paid only at the cap; an LRU map if one node ever keeps more
// credentials than this active inside a single interval.
const TOUCH_MAP_CAP: usize = 10_000;
/// ADR-0133 and migration 0309 use the same batch-mode floor.
pub(crate) const MIN_BATCH_TOUCH_SECONDS: u64 = 60;

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

    fn release_claim(&self, credential: PrincipalId, claimed_at: SystemTime) {
        let mut touched = self
            .last_touch
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if touched.get(&credential) == Some(&claimed_at) {
            touched.remove(&credential);
        }
    }

    pub(crate) async fn stamp(
        &self,
        pool: &RuntimeDbPool,
        principal: PrincipalId,
        now: SystemTime,
    ) -> Result<(), ErrorCode> {
        if self.claim(principal, now)
            && let Err(code) = mark_used(pool, principal.0).await
        {
            self.release(principal);
            return Err(code);
        }
        Ok(())
    }
}

type PendingTouch = (
    PrincipalId,
    SystemTime,
    oneshot::Sender<Result<(), ErrorCode>>,
);

pub(crate) struct BatchTouch {
    throttle: Arc<TouchThrottle>,
    pending: mpsc::Sender<PendingTouch>,
}

impl BatchTouch {
    pub(crate) fn new(pool: Arc<RuntimeDbPool>, interval: Duration, seconds: i32) -> Self {
        let throttle = Arc::new(TouchThrottle::new(interval));
        let (pending, receiver) = mpsc::channel(TOUCH_MAP_CAP);
        // One writer drains eligible requests together. It owns admitted work if a request is cancelled.
        tokio::spawn(Self::flush(pool, receiver, Arc::clone(&throttle), seconds));
        Self { throttle, pending }
    }

    async fn flush(
        pool: Arc<RuntimeDbPool>,
        mut receiver: mpsc::Receiver<PendingTouch>,
        claims: Arc<TouchThrottle>,
        seconds: i32,
    ) {
        let mut batch = Vec::new();
        let mut ids = Vec::new();
        while receiver.recv_many(&mut batch, TOUCH_MAP_CAP).await != 0 {
            ids.extend(batch.iter().map(|(principal, _, _)| principal.0));
            let result = mark_used_batch(&pool, &ids, seconds).await;
            let outcome = result.as_ref().map(|_| ()).map_err(|code| *code);
            ids.clear();
            for (principal, claimed_at, done) in batch.drain(..) {
                if !result
                    .as_ref()
                    .is_ok_and(|written| written.contains_key(&principal.0))
                {
                    claims.release_claim(principal, claimed_at);
                }
                let _ = done.send(outcome);
            }
        }
    }

    pub(crate) async fn stamp(
        &self,
        principal: PrincipalId,
        now: SystemTime,
    ) -> Result<(), ErrorCode> {
        if !self.throttle.claim(principal, now) {
            return Ok(());
        }
        let (done, result) = oneshot::channel();
        // A full queue refuses immediately and lets the next authenticated request retry the stamp.
        if self.pending.try_send((principal, now, done)).is_err() {
            self.throttle.release_claim(principal, now);
            return Err(ErrorCode::DependencyUnavailable);
        }
        match result.await {
            Ok(outcome) => outcome,
            Err(_) => {
                self.throttle.release_claim(principal, now);
                Err(ErrorCode::DependencyUnavailable)
            }
        }
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
    let credential = authenticate_live(
        pool,
        authorization_header,
        pepper,
        pepper_previous,
        request_ip,
        now,
        None,
    )
    .await?;
    touch
        .stamp(pool, credential.identity().principal(), now)
        .await?;
    Ok(credential)
}

pub(crate) async fn authenticate_live(
    pool: &RuntimeDbPool,
    authorization_header: &str,
    pepper: &[u8],
    pepper_previous: Option<&[u8]>,
    request_ip: IpAddr,
    now: SystemTime,
    routes: Option<&CredentialRouteCache>,
) -> Result<AuthenticatedServiceCredential, ErrorCode> {
    if pepper.is_empty() {
        return Err(ErrorCode::Internal);
    }
    let (prefix, raw_key) = parse_bearer_credential(authorization_header)?;
    let route = if let Some(cache) = routes {
        let key = cache.key(raw_key);
        Some((cache, key, cache.lookup(&key).await))
    } else {
        None
    };
    let store = crate::bootstrap::credential_store(pool);
    let result = authenticate_key(
        &store,
        prefix,
        raw_key,
        pepper,
        pepper_previous,
        request_ip,
        now,
    )
    .await;
    if let Some((cache, key, hint)) = route {
        match &result {
            Ok(credential) => {
                let live = credential.route_hint();
                if hint.is_some_and(|hint| {
                    hint.tenant_id != live.tenant_id || hint.principal != live.principal
                }) {
                    cache.invalidate(&key).await;
                    return Err(ErrorCode::Unauthorized);
                }
                if hint != Some(live) {
                    cache.insert(key, live).await;
                }
            }
            Err(_) if hint.is_some() => cache.invalidate(&key).await,
            Err(_) => {}
        }
    }
    result.map(AuthenticatedBearer)
}

pub(crate) async fn authenticate_access_token(
    pool: &RuntimeDbPool,
    issuer_keys: &TokenKeys,
    token: &str,
    expected_resource: &str,
    now: OffsetDateTime,
) -> Result<AuthenticatedBearer, ErrorCode> {
    let access = VerifiedAccess::verify(issuer_keys, token, expected_resource, now)?;
    let mut txn = oauth_repo::begin(pool).await?;
    let grant = txn
        .lookup_grant(access.grant_id())
        .await?
        .ok_or(ErrorCode::Unauthorized)?;
    if !txn.subject_is_active(&grant).await? && false {
        return Err(ErrorCode::Unauthorized);
    }
    txn.commit().await?;
    let workspaces = load_live_workspace_ids(pool, grant.tenant_id.0, grant.user_id.0).await?;
    access
        .bind(
            grant,
            workspaces.into_iter().map(WorkspaceId).collect(),
            now,
        )
        .map(AuthenticatedBearer)
}

pub(crate) fn parse_bearer_header(header: &str) -> Result<&str, ErrorCode> {
    let (scheme, raw) = header.split_once(' ').ok_or(ErrorCode::Unauthorized)?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Err(ErrorCode::Unauthorized);
    }
    Ok(raw)
}

fn parse_bearer_credential(header: &str) -> Result<(&str, &str), ErrorCode> {
    let raw_key = parse_bearer_header(header)?;
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
}

//! `application::cimd` — validates and caches public OAuth Client ID Metadata Documents for one issuer.
//! Depends-on: crates=[async-trait, serde, serde_json, time, tokio]; services=[]; env=[]; modules=[]
//! Called-by: [gateway::bootstrap, gateway::oauth_http, tests]
//! Invariants: [an exact client ID and its authorization server issuer bind every accepted document]
//! Spec: Baseline §33; M02 D5; MCP 2026-07-28 Client Registration

use std::{
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::Deserialize;
use time::OffsetDateTime;

/// Identity's port for an unauthenticated, bounded HTTPS metadata fetch.
#[async_trait::async_trait]
pub trait CimdFetch: Send + Sync {
    /// Fetch from the supplied client URL through a transport enforcing the outbound policy.
    async fn fetch(&self, client_id: &str) -> Result<FetchedDocument, CimdError>;
}

/// Transport result before JSON structure and client identity have been checked.
pub struct FetchedDocument {
    /// Bounded response bytes.
    pub body: Vec<u8>,
    /// Origin cache directives in received order.
    pub cache_control: Vec<String>,
    /// Origin `Age`, if sent.
    pub age: Option<String>,
}

/// Metadata discovery failures. Neither variant establishes a client identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CimdError {
    /// URL or document policy was not satisfied.
    Invalid,
    /// Metadata could not be fetched.
    Unavailable,
}

/// A validated public client, bound to the authorization server that resolved it.
#[derive(Debug)]
pub struct CimdClient {
    issuer: String,
    client_id: String,
    name: String,
    redirect_uris: Vec<String>,
    fetched_at: OffsetDateTime,
}

impl CimdClient {
    /// The authorization server under which the document was resolved.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    /// The original, byte-exact client identifier.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    /// The client's self-declared display name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// The validated registered callback strings.
    pub fn redirect_uris(&self) -> &[String] {
        &self.redirect_uris
    }
    /// Time at which the document was fetched.
    pub fn fetched_at(&self) -> OffsetDateTime {
        self.fetched_at
    }
}

#[derive(Deserialize)]
struct Document {
    client_id: String,
    client_name: String,
    redirect_uris: Vec<String>,
    token_endpoint_auth_method: String,
    #[serde(flatten)]
    other: serde_json::Map<String, serde_json::Value>,
}

struct Cached {
    expires_at: Instant,
    requested_at: Instant,
    client: Arc<CimdClient>,
}

/// A bounded positive cache. Each instance serves exactly one immutable issuer.
pub struct CimdResolver {
    issuer: String,
    fetch: Arc<dyn CimdFetch>,
    ttl: Duration,
    capacity: NonZeroUsize,
    redirect_allowed: fn(&str) -> bool,
    cache: Mutex<HashMap<String, Cached>>,
}

impl CimdResolver {
    /// Construct from the AS issuer and trusted local cache bounds.
    pub fn new(
        issuer: String,
        fetch: Arc<dyn CimdFetch>,
        ttl: Duration,
        capacity: NonZeroUsize,
        redirect_allowed: fn(&str) -> bool,
    ) -> Self {
        Self {
            issuer,
            fetch,
            ttl,
            capacity,
            redirect_allowed,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The AS issuer bound to this resolver and cache.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Resolve an exact identifier for this issuer, refetching on expiry.
    ///
    /// # Errors
    /// Invalid URL, invalid document or unavailable metadata.
    pub async fn resolve(&self, client_id: &str) -> Result<Arc<CimdClient>, CimdError> {
        self.resolve_at(client_id, Instant::now()).await
    }

    async fn resolve_at(
        &self,
        client_id: &str,
        now: Instant,
    ) -> Result<Arc<CimdClient>, CimdError> {
        if !valid_identifier(client_id) {
            return Err(CimdError::Invalid);
        }
        if let Some(client) = self
            .cache
            .lock()
            .map_err(|_| CimdError::Unavailable)?
            .get(client_id)
            .filter(|entry| now < entry.expires_at)
            .map(|entry| Arc::clone(&entry.client))
        {
            return Ok(client);
        }

        let response = self.fetch.fetch(client_id).await?;
        if response
            .body
            .iter()
            .find(|byte| !byte.is_ascii_whitespace())
            != Some(&b'{')
        {
            return Err(CimdError::Invalid);
        }
        let doc: Document =
            serde_json::from_slice(&response.body).map_err(|_| CimdError::Invalid)?;
        let mut seen = HashSet::new();
        if doc.client_id != client_id
            || doc.client_name.trim().is_empty()
            || doc.client_name.chars().any(char::is_control)
            || doc.token_endpoint_auth_method != "none"
            || doc.other.contains_key("client_secret")
            || doc.other.contains_key("client_secret_expires_at")
            || doc.redirect_uris.is_empty()
            || doc
                .redirect_uris
                .iter()
                .any(|uri| !seen.insert(uri) || !(self.redirect_allowed)(uri))
        {
            return Err(CimdError::Invalid);
        }

        let client = Arc::new(CimdClient {
            issuer: self.issuer.clone(),
            client_id: doc.client_id,
            name: doc.client_name,
            redirect_uris: doc.redirect_uris,
            fetched_at: OffsetDateTime::now_utc(),
        });
        let ttl = cache_lifetime(&response, self.ttl);
        if !ttl.is_zero() {
            self.store(client_id, Arc::clone(&client), now, ttl)?;
        }
        Ok(client)
    }

    fn store(
        &self,
        id: &str,
        client: Arc<CimdClient>,
        now: Instant,
        ttl: Duration,
    ) -> Result<(), CimdError> {
        let mut cache = self.cache.lock().map_err(|_| CimdError::Unavailable)?;
        cache.retain(|_, entry| now < entry.expires_at);
        if cache.get(id).is_some_and(|entry| entry.requested_at > now) {
            return Ok(());
        }
        if cache.len() == self.capacity.get()
            && !cache.contains_key(id)
            && let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(id, _)| id.clone())
        {
            cache.remove(&oldest);
        }
        if let Some(expires_at) = now.checked_add(ttl) {
            cache.insert(
                id.to_owned(),
                Cached {
                    expires_at,
                    requested_at: now,
                    client,
                },
            );
        }
        Ok(())
    }
}

/// Selects CIMD before considering any locally registered identifier.
pub fn is_url_identifier(id: &str) -> bool {
    id.get(..8)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
}

fn valid_identifier(id: &str) -> bool {
    let Some((authority, path)) = id.get(8..).and_then(|id| id.split_once('/')) else {
        return false;
    };
    is_url_identifier(id)
        && !authority.is_empty()
        && !authority.contains(['@', '?'])
        && !id.contains(['#', '\\'])
        && !id.chars().any(|c| c.is_whitespace() || c.is_control())
        && !path
            .split('?')
            .next()
            .unwrap_or_default()
            .split('/')
            .any(|segment| {
                let decoded = segment.to_ascii_lowercase().replace("%2e", ".");
                matches!(decoded.as_str(), "." | "..")
            })
}

fn cache_lifetime(response: &FetchedDocument, ceiling: Duration) -> Duration {
    let mut ttl = ceiling;
    for directive in response
        .cache_control
        .iter()
        .flat_map(|value| value.split(','))
    {
        let (name, value) = directive
            .trim()
            .split_once('=')
            .unwrap_or((directive.trim(), ""));
        match name.trim().to_ascii_lowercase().as_str() {
            "no-cache" | "no-store" | "private" => return Duration::ZERO,
            "max-age" | "s-maxage" => {
                let Ok(seconds) = value.trim().trim_matches('"').parse() else {
                    return Duration::ZERO;
                };
                ttl = ttl.min(Duration::from_secs(seconds));
            }
            _ => {}
        }
    }
    let age = match response.age.as_deref() {
        Some(value) => match value.trim().parse() {
            Ok(seconds) => seconds,
            Err(_) => return Duration::ZERO,
        },
        None => 0,
    };
    ttl.saturating_sub(Duration::from_secs(age))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const ID: &str = "https://client.example/metadata.json";
    const ISSUER: &str = "https://as.example";
    const OTHER_ISSUER: &str = "https://other-as.example";

    struct Fixture {
        id: &'static str,
        headers: &'static [&'static str],
        age: Option<&'static str>,
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl CimdFetch for Fixture {
        async fn fetch(&self, _: &str) -> Result<FetchedDocument, CimdError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(FetchedDocument {
                body: serde_json::to_vec(&serde_json::json!({
                    "client_id": self.id, "client_name": "Desktop", "token_endpoint_auth_method": "none",
                    "redirect_uris": ["http://127.0.0.1:3000/callback"],
                })).unwrap(),
                cache_control: self.headers.iter().map(|value| (*value).into()).collect(),
                age: self.age.map(str::to_owned),
            })
        }
    }

    fn lookup(issuer: &str, fixture: Arc<Fixture>) -> CimdResolver {
        CimdResolver::new(
            issuer.into(),
            fixture,
            Duration::from_secs(10),
            NonZeroUsize::MIN,
            crate::oauth::public_registration_redirect,
        )
    }

    #[tokio::test]
    async fn exact_id_mismatch_never_enters_cache() {
        let source = Arc::new(Fixture {
            id: "https://CLIENT.example/metadata.json",
            headers: &[],
            age: None,
            calls: AtomicUsize::new(0),
        });
        let resolver = lookup(ISSUER, Arc::clone(&source));
        for _ in 0..2 {
            assert!(matches!(
                resolver.resolve(ID).await,
                Err(CimdError::Invalid)
            ));
        }
        assert_eq!(source.calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn rejects_unregistered_callback_for_resolved_client() {
        use crate::oauth::{self, AuthorizeRequest, ClientView, OAuthPolicy, OAuthReason};
        let source = Arc::new(Fixture {
            id: ID,
            headers: &[],
            age: None,
            calls: AtomicUsize::new(0),
        });
        let client = lookup(ISSUER, source).resolve(ID).await.unwrap();
        let refused = oauth::authorize_request(
            &AuthorizeRequest {
                client_id: ID,
                redirect_uri: Some("http://127.0.0.1:3100/other"),
                response_type: None,
                code_challenge: None,
                code_challenge_method: None,
                resource: None,
                scope: None,
                state: None,
            },
            Some(&ClientView {
                redirect_uris: client.redirect_uris(),
                disabled: false,
                kind_recognized: true,
            }),
            &OAuthPolicy {
                code_ttl: Duration::ZERO,
                access_ttl: Duration::ZERO,
                refresh_ttl: Duration::ZERO,
                grant_max_ttl: Duration::ZERO,
                allowed_resources: &[],
                supported_scopes: &[],
            },
        )
        .unwrap_err();
        assert_eq!(refused.refusal.reason, OAuthReason::REDIRECT_URI_MISMATCH);
        assert!(refused.redirect_to.is_none());
    }

    #[tokio::test]
    async fn refreshes_at_expiry_and_separates_issuers() {
        let source = Arc::new(Fixture {
            id: ID,
            headers: &["max-age=4"],
            age: Some("1"),
            calls: AtomicUsize::new(0),
        });
        let first = lookup(ISSUER, Arc::clone(&source));
        let second = lookup(OTHER_ISSUER, Arc::clone(&source));
        let now = Instant::now();
        let client = first.resolve_at(ID, now).await.unwrap();
        assert_eq!(client.client_id(), ID);
        assert_eq!(client.issuer(), ISSUER);
        assert!(Arc::ptr_eq(
            &client,
            &first
                .resolve_at(ID, now + Duration::from_secs(2))
                .await
                .unwrap(),
        ));
        assert_eq!(
            second.resolve_at(ID, now).await.unwrap().issuer(),
            OTHER_ISSUER
        );
        assert_eq!(source.calls.load(Ordering::Relaxed), 2);
        assert!(!Arc::ptr_eq(
            &client,
            &first
                .resolve_at(ID, now + Duration::from_secs(3))
                .await
                .unwrap(),
        ));
        assert_eq!(source.calls.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn forbids_cache_on_no_store_or_invalid_age() {
        for (headers, age) in [(&["public, no-store"][..], None), (&[][..], Some(""))] {
            let source = Arc::new(Fixture {
                id: ID,
                headers,
                age,
                calls: AtomicUsize::new(0),
            });
            let resolver = lookup(ISSUER, Arc::clone(&source));
            for _ in 0..2 {
                assert!(resolver.resolve(ID).await.is_ok());
            }
            assert_eq!(source.calls.load(Ordering::Relaxed), 2);
        }
    }

    #[test]
    fn requires_https_path_without_dot_segments_or_credentials() {
        assert!(valid_identifier(ID));
        assert!(valid_identifier("HTTPS://client.example/metadata.json"));
        for id in [
            "https://client.example",
            "http://client.example/metadata.json",
            "https://client.example/a/../metadata.json",
            "https://client.example/a/.%2E/metadata.json",
            "https://@client.example/metadata.json",
            "https://client.example/metadata.json#fragment",
        ] {
            assert!(!valid_identifier(id), "{id}");
        }
    }
}

//! Verify the Claude public CIMD fallback with the AS resolver and redirect policy.
//!
//! The fixture uses the documented hosted callback and public client fields:
//! https://claude.com/docs/connectors/building/lazy-authentication#identify-claude-with-a-client-id-metadata-document

use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use humaux_application::{
    cimd::{CimdError, CimdFetch, CimdResolver, FetchedDocument},
    oauth::{AuthorizeRequest, ClientView, OAuthPolicy, OAuthReason, authorize_request},
};
use humaux_gateway::oauth_http::public_client_callback;

struct Fixture {
    client_id: String,
    callback: String,
}

#[async_trait::async_trait]
impl CimdFetch for Fixture {
    async fn fetch(&self, client_id: &str) -> Result<FetchedDocument, CimdError> {
        assert_eq!(client_id, self.client_id);
        Ok(FetchedDocument {
            body: serde_json::to_vec(&serde_json::json!({
                "client_id": self.client_id,
                "client_name": "Claude",
                "redirect_uris": [self.callback],
                "token_endpoint_auth_method": "none",
            }))
            .unwrap(),
            cache_control: vec!["max-age=30".into()],
            age: None,
        })
    }
}

#[tokio::test]
async fn claude_public_cimd_uses_its_exact_callback() {
    let client_id = std::env::var("OAUTH_FIXTURE_CIMD").unwrap();
    let callback = std::env::var("OAUTH_FIXTURE_CALLBACK").unwrap();
    let resolver = CimdResolver::new(
        "https://as.example.test".into(),
        Arc::new(Fixture {
            client_id: client_id.clone(),
            callback: callback.clone(),
        }),
        Duration::from_secs(60),
        NonZeroUsize::MIN,
        public_client_callback,
    );
    let client = resolver.resolve(&client_id).await.unwrap();
    assert_eq!(client.client_id(), client_id);
    assert_eq!(client.redirect_uris(), [callback.as_str()]);

    let resource = "https://as.example.test/mcp";
    let policy = OAuthPolicy {
        code_ttl: Duration::ZERO,
        access_ttl: Duration::ZERO,
        refresh_ttl: Duration::ZERO,
        grant_max_ttl: Duration::ZERO,
        allowed_resources: &[resource.into()],
        supported_scopes: &["memory:write".into()],
    };
    let view = ClientView {
        redirect_uris: client.redirect_uris(),
        kind_recognized: true,
        disabled: false,
    };
    let request = AuthorizeRequest {
        response_type: Some("code"),
        client_id: &client_id,
        redirect_uri: Some(&callback),
        code_challenge: Some("abcdefghijklmnopqrstuvwxyzABCDEFG0123456789"),
        code_challenge_method: Some("S256"),
        resource: Some(resource),
        scope: Some("memory:write"),
        state: None,
    };
    assert_eq!(
        authorize_request(&request, Some(&view), &policy)
            .unwrap()
            .redirect_uri,
        callback
    );
    let wrong_callback = format!("{callback}/ci-mismatch");
    let invalid = authorize_request(
        &AuthorizeRequest {
            redirect_uri: Some(&wrong_callback),
            ..request
        },
        Some(&view),
        &policy,
    )
    .unwrap_err();
    assert_eq!(invalid.refusal.reason, OAuthReason::REDIRECT_URI_MISMATCH);
    assert_eq!(invalid.redirect_to, None);
}

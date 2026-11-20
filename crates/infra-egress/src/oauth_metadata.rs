//! `infra-egress::oauth_metadata` — Layer 1A's credential-free OAUTH_METADATA GET capability.
//! Depends-on: crates=[humaux-infra-network, tokio]; services=[HTTP(provider), HTTP(loopback)]; env=[];
//!   modules=[humaux-infra-network, infra-egress::resolver, infra-network::http]
//! Called-by: [gateway::bootstrap]
//! Invariants: [only validated public addresses reach the connector; no ambient proxy, credentials, or redirects]
//! Spec: Baseline §33; §83.4; ADR-0039

use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use humaux_infra_network::http::ClientConfig;
use humaux_infra_network::reqwest::{self, StatusCode, Url, header};

use crate::resolver::{
    CheckedDnsResolve, SystemCheckedResolve, build_pinned_client, refusal_in_error_chain,
};

/// The OAUTH_METADATA network capability. Its only operation is a bounded HTTPS GET
/// to a public destination and carries no application credentials or request body.
pub struct OAuthMetadataGet {
    client: reqwest::Client,
    max_bytes: NonZeroUsize,
    mime: header::HeaderValue,
}

/// The successful document and origin cache directives, which the consumer may cap.
#[derive(Debug)]
pub struct OAuthMetadataDocument {
    pub body: Vec<u8>,
    pub cache_control: Vec<String>,
    pub age: Option<String>,
}

/// A request failed a destination, transport, or response precondition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthMetadataError {
    Configuration,
    InvalidUrl,
    AddressDenied,
    Timeout,
    Transport,
    Status(u16),
    Mime,
    TooLarge,
}

impl OAuthMetadataGet {
    /// Builds the capability from trusted settings. `mime` is one media type without parameters.
    ///
    /// # Errors
    /// Invalid settings or failure to initialize the underlying TLS client.
    pub fn new(
        timeout: Duration,
        max_bytes: NonZeroUsize,
        mime: &str,
    ) -> Result<Self, OAuthMetadataError> {
        if timeout.is_zero()
            || !mime.split_once('/').is_some_and(|(kind, subtype)| {
                [kind, subtype].into_iter().all(|part| {
                    !part.is_empty()
                        && part.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || b"!#$&^_.+-".contains(&byte)
                        })
                })
            })
        {
            return Err(OAuthMetadataError::Configuration);
        }
        let mime =
            header::HeaderValue::from_str(mime).map_err(|_| OAuthMetadataError::Configuration)?;
        let client = metadata_client(timeout, Arc::new(PublicDns(SystemCheckedResolve)))?;
        Ok(Self {
            client,
            max_bytes,
            mime,
        })
    }

    /// Fetches one document with TLS verification against the original URL hostname.
    ///
    /// # Errors
    /// A destination, response or transport precondition failed.
    pub async fn fetch(&self, url: &str) -> Result<OAuthMetadataDocument, OAuthMetadataError> {
        self.fetch_checked(checked_https_url(url)?).await
    }

    async fn fetch_checked(&self, url: Url) -> Result<OAuthMetadataDocument, OAuthMetadataError> {
        let request = self.client.get(url).header(header::ACCEPT, &self.mime);
        // dep: HTTP(provider) — unauthenticated OAUTH_METADATA GET
        let mut response = request.send().await.map_err(transport_error)?;
        if response.status() != StatusCode::OK {
            return Err(OAuthMetadataError::Status(response.status().as_u16()));
        }
        let types = response.headers().get_all(header::CONTENT_TYPE);
        let mut types = types.iter();
        let mime_matches = types
            .next()
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .as_bytes()
                    .eq_ignore_ascii_case(self.mime.as_bytes())
            });
        if !mime_matches || types.next().is_some() {
            return Err(OAuthMetadataError::Mime);
        }
        let cache_control = response
            .headers()
            .get_all(header::CACHE_CONTROL)
            .iter()
            .map(|value| value.to_str().unwrap_or("no-store").to_owned())
            .collect();
        let mut ages = response.headers().get_all(header::AGE).iter();
        let age = ages.next().map(|value| {
            // Invalid or repeated Age must not be interpreted as a fresh response.
            match (value.to_str(), ages.next()) {
                (Ok(value), None) => value.to_owned(),
                _ => String::new(),
            }
        });

        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(transport_error)? {
            if chunk.len() > self.max_bytes.get() - body.len() {
                return Err(OAuthMetadataError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(OAuthMetadataDocument {
            body,
            cache_control,
            age,
        })
    }
}

fn metadata_client(
    request_timeout: Duration,
    resolver: Arc<dyn CheckedDnsResolve>,
) -> Result<reqwest::Client, OAuthMetadataError> {
    build_pinned_client(
        ClientConfig {
            request_timeout,
            trust_env_proxy: false,
        },
        resolver,
        Duration::ZERO,
    )
    .map_err(|_| OAuthMetadataError::Configuration)
}

fn checked_https_url(raw: &str) -> Result<Url, OAuthMetadataError> {
    let url = Url::parse(raw).map_err(|_| OAuthMetadataError::InvalidUrl)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(OAuthMetadataError::InvalidUrl);
    }
    let host = url.host_str().ok_or(OAuthMetadataError::InvalidUrl)?;
    // The connector skips DNS for numeric hosts, so apply the same policy here.
    if host
        .trim_matches(['[', ']'])
        .parse()
        .is_ok_and(|ip| !is_public(ip))
    {
        return Err(OAuthMetadataError::AddressDenied);
    }
    Ok(url)
}

struct PublicDns<R>(R);

impl<R: CheckedDnsResolve> CheckedDnsResolve for PublicDns<R> {
    fn resolve_checked(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        let addresses = self.0.resolve_checked(host)?;
        if addresses.iter().any(|&ip| !is_public(ip)) {
            return Err("DNS returned a non-public address".into());
        }
        Ok(addresses)
    }
}

fn is_public(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => !matches!(
            ip.octets(),
            [0 | 10 | 127 | 224..=255, ..]
                | [100, 64..=127, ..]
                | [169, 254, ..]
                | [172, 16..=31, ..]
                | [192, 0, 0 | 2, _]
                | [192, 88, 99, _]
                | [192, 168, ..]
                | [198, 18 | 19, ..]
                | [198, 51, 100, _]
                | [203, 0, 113, _]
        ),
        // Only currently allocated global unicast space, excluding special-use subnets.
        IpAddr::V6(ip) => {
            matches!(ip.segments()[0], 0x2000..=0x3fff)
                && !matches!(
                    ip.segments(),
                    [0x2001, 0..=0x1ff | 0xdb8, ..] | [0x2002, ..] | [0x3fff, 0..=0x0fff, ..]
                )
        }
    }
}

fn transport_error(error: reqwest::Error) -> OAuthMetadataError {
    if refusal_in_error_chain(&error).is_some() {
        OAuthMetadataError::AddressDenied
    } else if error.is_timeout() {
        OAuthMetadataError::Timeout
    } else {
        OAuthMetadataError::Transport
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const TIMEOUT: Duration = Duration::from_secs(2);
    const JSON: &str = "application/json";

    fn transport(timeout: Duration) -> OAuthMetadataGet {
        OAuthMetadataGet::new(timeout, NonZeroUsize::new(2).unwrap(), JSON).unwrap()
    }

    #[test]
    fn rejects_insecure_scheme_and_non_public_literals() {
        for url in [
            "http://metadata.example/doc",
            "https://user:secret@metadata.example/doc",
            "https://metadata.example/doc#fragment",
        ] {
            assert_eq!(checked_https_url(url), Err(OAuthMetadataError::InvalidUrl));
        }
        for authority in [
            "10.0.0.1",
            "127.1",
            "169.254.169.254",
            "192.0.2.1",
            "[::1]",
            "[fc00::1]",
            "[fe80::1]",
            "[::ffff:10.0.0.1]",
            "[2001:db8::1]",
        ] {
            assert_eq!(
                checked_https_url(&format!("https://{authority}/doc")),
                Err(OAuthMetadataError::AddressDenied),
                "{authority}"
            );
        }
        assert!(checked_https_url("https://metadata.example/doc").is_ok());
        assert!(checked_https_url("https://[2606:4700::1]/doc").is_ok());
    }

    struct ChangingDns(AtomicUsize);

    impl CheckedDnsResolve for ChangingDns {
        fn resolve_checked(&self, _: &str) -> Result<Vec<IpAddr>, String> {
            let mut answers = vec!["1.1.1.1".parse().unwrap()];
            if self.0.fetch_add(1, Ordering::Relaxed) != 0 {
                answers.push(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
            }
            Ok(answers)
        }
    }

    struct FixtureDns(AtomicUsize);

    impl CheckedDnsResolve for FixtureDns {
        fn resolve_checked(&self, _: &str) -> Result<Vec<IpAddr>, String> {
            if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
                Ok(vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)])
            } else {
                Err("changed DNS answer was denied".into())
            }
        }
    }

    #[tokio::test]
    async fn rechecks_dns_and_rejects_mixed_answers_before_dialing() {
        use reqwest::dns::Resolve;
        let dns = Arc::new(PublicDns(ChangingDns(AtomicUsize::new(0))));
        let pinned = crate::resolver::PinnedResolver::new(dns, Duration::ZERO);
        let name = || "metadata.example".parse::<reqwest::dns::Name>().unwrap();
        let addresses: Vec<_> = pinned.resolve(name()).await.unwrap().collect();
        assert_eq!(addresses, ["1.1.1.1:0".parse().unwrap()]);
        assert!(pinned.resolve(name()).await.is_err());
    }

    #[tokio::test]
    async fn denied_dns_surfaces_through_the_https_connector() {
        struct LocalDns;
        impl CheckedDnsResolve for LocalDns {
            fn resolve_checked(&self, _: &str) -> Result<Vec<IpAddr>, String> {
                Ok(vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)])
            }
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = transport(TIMEOUT);
        client.client = metadata_client(TIMEOUT, Arc::new(PublicDns(LocalDns))).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_eq!(
            client
                .fetch(&format!("https://metadata.example:{port}/doc"))
                .await
                .unwrap_err(),
            OAuthMetadataError::AddressDenied
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }

    async fn serve(response: String, keep_open: bool) -> (Url, tokio::task::JoinHandle<()>) {
        // dep: HTTP(loopback) — controlled response fixture
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}/doc", listener.local_addr().unwrap())).unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(socket.read_u8().await.unwrap());
            }
            let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
            assert!(request.starts_with("get /doc http/1.1\r\n"));
            assert!(request.contains("\r\naccept: application/json\r\n"));
            assert!(!request.contains("\r\nauthorization:"));
            socket.write_all(response.as_bytes()).await.unwrap();
            if keep_open {
                std::future::pending::<()>().await;
            }
        });
        (url, task)
    }

    #[tokio::test]
    async fn accepts_bounded_json_and_preserves_cache_headers() {
        let (url, server) = serve(
            concat!(
                "HTTP/1.1 200 OK\r\nContent-Type: Application/JSON; charset=utf-8\r\n",
                "Cache-Control: public, max-age=30\r\nAge: 10\r\nContent-Length: 2\r\n\r\n{}",
            )
            .into(),
            false,
        )
        .await;
        // The response path is exercised over a local fixture independent of the public HTTPS policy.
        let doc = transport(TIMEOUT).fetch_checked(url).await.unwrap();
        assert_eq!(doc.body, b"{}");
        assert_eq!(doc.cache_control, ["public, max-age=30"]);
        assert_eq!(doc.age.as_deref(), Some("10"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn new_connections_use_fresh_dns_answers() {
        let mut client = transport(TIMEOUT);
        client.client =
            metadata_client(TIMEOUT, Arc::new(FixtureDns(AtomicUsize::new(0)))).unwrap();
        let (mut url, server) = serve(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".into(),
            false,
        ).await;
        url.set_host(Some("metadata.example")).unwrap();
        assert_eq!(client.fetch_checked(url.clone()).await.unwrap().body, b"{}");
        server.await.unwrap();
        assert_eq!(
            client.fetch_checked(url).await.unwrap_err(),
            OAuthMetadataError::AddressDenied
        );
    }

    #[tokio::test]
    async fn rejects_wrong_mime_and_oversized_chunked_body() {
        for (response, error) in [
            (
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\n{}",
                OAuthMetadataError::Mime,
            ),
            (
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n1\r\n \r\n0\r\n\r\n",
                OAuthMetadataError::TooLarge,
            ),
        ] {
            let (url, server) = serve(response.into(), false).await;
            assert_eq!(
                transport(TIMEOUT).fetch_checked(url).await.unwrap_err(),
                error
            );
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn does_not_follow_redirects() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (url, server) = serve(
            format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{}/doc\r\nContent-Length: 0\r\n\r\n",
                target.local_addr().unwrap()
            ),
            false,
        )
        .await;
        assert_eq!(
            transport(TIMEOUT).fetch_checked(url).await.unwrap_err(),
            OAuthMetadataError::Status(302)
        );
        server.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), target.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn wall_clock_limit_covers_the_body() {
        let (url, server) = serve(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{"
                .into(),
            true,
        )
        .await;
        let client = transport(Duration::from_millis(200));
        let result = tokio::time::timeout(TIMEOUT, client.fetch_checked(url))
            .await
            .expect("transport must apply its own configured deadline");
        assert_eq!(result.unwrap_err(), OAuthMetadataError::Timeout);
        server.abort();
    }
}

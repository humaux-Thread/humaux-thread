//! `protocol::edge` — H1: §73 Edge/Trusted-Proxy/IP Policy/ClientNetworkIdentity/API key/session/CSRF 中间件类型 （Phase 2
//!   wave 实现；判据出处见 spec 家章）。
//! Depends-on: crates=[humaux-application, humaux-domain]; services=[]; env=[CARGO_MANIFEST_DIR]; modules=[]
//! Called-by: [gateway::auth_pages, gateway::bootstrap, gateway::guard, maintenance::main, tests, xtask::e2e_seed]
//! Invariants: [no runtime env or service read; CARGO_MANIFEST_DIR is build-time (`env!`) in the unit tests only, to embed migration 0037 for the contract checks]
//! Spec: §73; §73.2
//!
//! Every item here is a pure function or a plain value type: no HTTP framework, no DB, no
//! clock/RNG access baked in. Callers (the not-yet-wired `bins/gateway`) supply the raw
//! ingredients — TCP peer address, a raw header string, "now", freshly generated random
//! bytes — and get back a constructed value or a decision. Keeping I/O out of this module is
//! what makes the fault-injection tests below possible without a live socket or a clock mock.

use std::net::IpAddr;
#[cfg(test)]
use std::time::SystemTime;

// ============================================================================
// §73.2 Trusted Proxy / Real IP — Cidr + ClientNetworkIdentity construction
// ============================================================================

// ponytail: keep edge callers compatible; remove CIDR aliases in the network caller migration card.
pub use humaux_domain::network::{Cidr, CidrParseError};

/// §73.2 `trusted_proxy_cidrs[]` / `max_forwarded_hops` — supplied by the caller's resolved
/// config (§78.1: no business threshold hardcoded in this module). Which header to read
/// (`X-Forwarded-For` vs `Forwarded`) is the caller's own extraction concern — nothing in
/// this crate is wired to a live header collection yet (`bins/gateway` is not built), so a
/// `trusted_ip_header` field here would be decorative; add it back when the gateway wiring
/// needs to pick the header itself rather than being handed an already-extracted value.
#[derive(Debug, Clone)]
pub struct TrustedProxyConfig {
    pub trusted_proxy_cidrs: Vec<Cidr>,
    pub max_forwarded_hops: usize,
}

/// §73.2 `ClientNetworkIdentity { peer_ip, client_ip, proxy_chain, asn?, country?, risk_tags[] }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientNetworkIdentity {
    pub peer_ip: IpAddr,
    pub client_ip: IpAddr,
    pub proxy_chain: Vec<IpAddr>,
    pub asn: Option<u32>,
    pub country: Option<String>,
    pub risk_tags: Vec<String>,
}

/// A forwarded-header value arrived from a TCP peer outside `trusted_proxy_cidrs` — §73.2's
/// forgery case. The header is discarded entirely, not partially trusted.
pub const RISK_TAG_FORWARDED_HEADER_IGNORED_UNTRUSTED_PEER: &str =
    "FORWARDED_HEADER_IGNORED_UNTRUSTED_PEER";
/// Forwarded-header hop count exceeded `max_forwarded_hops` — treated as suspect, chain
/// discarded, falls back to the peer address.
pub const RISK_TAG_FORWARDED_HOP_LIMIT_EXCEEDED: &str = "FORWARDED_HOP_LIMIT_EXCEEDED";
/// At least one comma-separated entry in the forwarded header did not parse as an IP address.
pub const RISK_TAG_FORWARDED_HEADER_UNPARSEABLE: &str = "FORWARDED_HEADER_UNPARSEABLE";

/// §73.2: "只有请求 TCP peer 属于可信代理 CIDR 时才解析 forwarded header" — this is the sole
/// constructor for [`ClientNetworkIdentity`]. `asn`/`country` are accepted as already-resolved
/// inputs (a GeoIP/ASN lookup is I/O, out of scope for a pure function) — pass `None` if the
/// caller has no such enrichment.
pub fn build_client_network_identity(
    peer_ip: IpAddr,
    forwarded_header_value: Option<&str>,
    config: &TrustedProxyConfig,
    asn: Option<u32>,
    country: Option<String>,
) -> ClientNetworkIdentity {
    let peer_ip = peer_ip.to_canonical();
    let peer_is_trusted = config
        .trusted_proxy_cidrs
        .iter()
        .any(|c| c.contains(peer_ip));

    let peer_only = |risk_tags: Vec<String>| ClientNetworkIdentity {
        peer_ip,
        client_ip: peer_ip,
        proxy_chain: Vec::new(),
        asn,
        country: country.clone(),
        risk_tags,
    };

    let Some(raw) = forwarded_header_value.filter(|s| !s.trim().is_empty()) else {
        return peer_only(Vec::new());
    };

    if !peer_is_trusted {
        return peer_only(vec![
            RISK_TAG_FORWARDED_HEADER_IGNORED_UNTRUSTED_PEER.to_string(),
        ]);
    }

    let mut risk_tags = Vec::new();
    let mut hops: Vec<IpAddr> = Vec::new();
    let mut saw_unparseable = false;
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.parse::<IpAddr>() {
            Ok(ip) => hops.push(ip.to_canonical()),
            Err(_) => saw_unparseable = true,
        }
    }
    if saw_unparseable {
        risk_tags.push(RISK_TAG_FORWARDED_HEADER_UNPARSEABLE.to_string());
    }
    if hops.len() > config.max_forwarded_hops {
        // §73.3: tagged as suspect, but NOT discarded wholesale — a client can pad the
        // chain to force this branch on demand, and if the whole chain were dropped in
        // favor of `peer_ip` here, that client would be attributing every request to the
        // trusted proxy's own address (bypassing IP-policy denylists and collapsing every
        // such client onto one shared rate-limit key). The walk below still finds the real
        // client from the padded data.
        risk_tags.push(RISK_TAG_FORWARDED_HOP_LIMIT_EXCEEDED.to_string());
    }
    if hops.is_empty() {
        return peer_only(risk_tags);
    }
    // §73.2/§73.3: a real proxy APPENDS the address it received the request from — it does
    // not remove what the client sent. So the leftmost entry is exactly the part of the
    // chain the client itself controls. Walk right-to-left, skipping entries that are
    // themselves trusted-proxy addresses (chained trusted hops); the first non-trusted
    // entry from the right is the one no trusted proxy could have fabricated — that is
    // `client_ip`. Everything to its right is the (trusted) proxy chain.
    let split_at = hops
        .iter()
        .rposition(|ip| !config.trusted_proxy_cidrs.iter().any(|c| c.contains(*ip)));
    let Some(idx) = split_at else {
        // Every hop is itself a trusted-proxy address — none of them can be the real
        // client. Fall back to the TCP peer, which genuinely is a trusted proxy here.
        return peer_only(risk_tags);
    };
    ClientNetworkIdentity {
        peer_ip,
        client_ip: hops[idx],
        proxy_chain: hops[idx + 1..].to_vec(),
        asn,
        country,
        risk_tags,
    }
}

// ============================================================================
// §73.3 IP Policy — fixed priority chain
// ============================================================================

/// Which tier of the §73.3 chain produced a deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpPolicyDenyReason {
    GlobalDenylist,
    TenantExplicitDeny,
    TenantAllowlistRequired,
    CredentialCidrBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpPolicyDecision {
    Deny(IpPolicyDenyReason),
    /// §73.3: "IP 只能是风险/访问控制信号之一，不能替代用户身份认证" — an allow always
    /// carries risk tags rather than the risk tier itself ever denying.
    Allow {
        risk_tags: Vec<String>,
    },
}

/// One evaluation's inputs. Empty allowlist slices mean "no allowlist requirement configured"
/// (§73.3's "Tenant allowlist requirement" tier only fires when the tenant actually has one).
pub struct IpPolicyInput<'a> {
    pub ip: IpAddr,
    pub global_denylist: &'a [Cidr],
    pub global_emergency_allowlist: &'a [Cidr],
    pub tenant_denylist: &'a [Cidr],
    pub tenant_allowlist: &'a [Cidr],
    pub credential_allowed_cidrs: &'a [Cidr],
    /// Pre-computed by the caller (region/ASN lookup is I/O); tagged onto an `Allow`, never
    /// used to deny.
    pub region_asn_risk_tags: &'a [String],
}

/// §73.3 priority chain, spec verbatim: "Emergency deny > Administrative network policy >
/// Tenant explicit deny > Tenant allowlist requirement > Risk policy > allow". `global_denylist`
/// IS the "Emergency deny" tier; `global_emergency_allowlist` is "Administrative network
/// policy" — an ops override that beats a tenant's OWN policy below it but never beats the
/// global denylist above it (an IP on both lists stays denied). Admin API allowlist (§73.4) is
/// a separate hostname/route-scoped policy, evaluated by the Admin Plane's own layer, not
/// folded into this per-request chain.
pub fn evaluate_ip_policy(input: &IpPolicyInput<'_>) -> IpPolicyDecision {
    let ip = input.ip.to_canonical();
    let in_list = |list: &[Cidr]| list.iter().any(|c| c.contains(ip));

    if in_list(input.global_denylist) {
        return IpPolicyDecision::Deny(IpPolicyDenyReason::GlobalDenylist);
    }
    if in_list(input.global_emergency_allowlist) {
        return IpPolicyDecision::Allow {
            risk_tags: Vec::new(),
        };
    }
    if in_list(input.tenant_denylist) {
        return IpPolicyDecision::Deny(IpPolicyDenyReason::TenantExplicitDeny);
    }
    if !input.tenant_allowlist.is_empty() && !in_list(input.tenant_allowlist) {
        return IpPolicyDecision::Deny(IpPolicyDenyReason::TenantAllowlistRequired);
    }
    if !input.credential_allowed_cidrs.is_empty() && !in_list(input.credential_allowed_cidrs) {
        return IpPolicyDecision::Deny(IpPolicyDenyReason::CredentialCidrBinding);
    }
    IpPolicyDecision::Allow {
        risk_tags: input.region_asn_risk_tags.to_vec(),
    }
}

// ============================================================================
// §73.5 API Key / MCP Credential
// ============================================================================

// ponytail: keep edge callers compatible; remove API key aliases in the credential caller migration card.
pub use humaux_application::api_key::{
    ApiKeyRecord, ApiKeyRejection, ApiKeyStatus, PepperMatch, compute_api_key_hash,
    is_legal_api_key_transition, validate_api_key,
};

/// §73.5 "日志只记录 fingerprint/prefix，不记录 secret". A short, deterministic,
/// non-reversible string safe for logs/audit metadata — never the raw key, never the full
/// keyed hash (itself a secret verifier). Four bytes of the hash is enough to disambiguate
/// two keys sharing a prefix without materially narrowing a brute-force search for the raw
/// key (a 4-byte HMAC prefix is not a usable oracle against the full 32-byte verifier).
pub fn api_key_log_fingerprint(prefix: &str, key_hash: &[u8]) -> String {
    let fp: String = key_hash
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{prefix}.{fp}")
}

// ============================================================================
// §73.6 Web Console Session + CSRF
// ============================================================================

/// §73.6 cookie name. The `__Host-` prefix is part of the name itself, not a separate flag —
/// browsers refuse to set a `__Host-`-prefixed cookie unless `Secure`, `Path=/`, and no
/// `Domain` attribute are all present, so the name alone constrains the attributes below.
pub const SESSION_COOKIE_NAME: &str = "__Host-humaux_session";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSitePolicy {
    Lax,
    Strict,
}

impl SameSitePolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            SameSitePolicy::Lax => "Lax",
            SameSitePolicy::Strict => "Strict",
        }
    }
}

/// §73.6 fixed session-cookie attribute string: `Secure`/`HttpOnly`/`Path=/` are frozen;
/// `SameSite` is the one attribute the spec leaves to caller judgement ("according to UX"), so
/// it is a parameter rather than baked into the constant.
pub fn session_cookie_attributes(same_site: SameSitePolicy) -> String {
    format!("Secure; HttpOnly; SameSite={}; Path=/", same_site.as_str())
}

/// §73.6 / M02 D6: request header carrying the session-bound CSRF token. It is a header only, never a cookie: the
/// value is `application::session::csrf_token` of the caller's own session, so a token cannot be replayed onto
/// another session.
pub const CSRF_HEADER_NAME: &str = "x-humaux-csrf-token";

/// `Sec-Fetch-Site` request header (Fetch Metadata), set by the browser and not forgeable from page script.
pub const FETCH_SITE_HEADER_NAME: &str = "sec-fetch-site";

/// The `Sec-Fetch-Site` value of one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchSite {
    /// `same-origin`.
    SameOrigin,
    /// `same-site`: another origin of the same registrable domain (a sibling subdomain).
    SameSite,
    /// `cross-site`.
    CrossSite,
    /// `none`: user-initiated navigation (typed URL, bookmark).
    None,
    /// The header is absent: not a Fetch-Metadata browser.
    Absent,
    /// A value outside the spec'd set.
    Unrecognised,
}

impl FetchSite {
    /// Parses the raw header value; `None` is an absent header.
    pub fn from_header(raw: Option<&str>) -> Self {
        match raw.map(str::trim) {
            None => Self::Absent,
            Some("same-origin") => Self::SameOrigin,
            Some("same-site") => Self::SameSite,
            Some("cross-site") => Self::CrossSite,
            Some("none") => Self::None,
            Some(_) => Self::Unrecognised,
        }
    }
}

/// RFC 9110 §9.2.1 safe methods are never CSRF-checked; every other method (and any unknown one) is state-changing.
pub fn method_is_state_changing(method: &str) -> bool {
    !["GET", "HEAD", "OPTIONS", "TRACE"]
        .iter()
        .any(|safe| method.eq_ignore_ascii_case(safe))
}

/// §73.6 / M02 D6 CSRF decision for one request. A state-changing method passes only when BOTH hold:
/// (a) `Sec-Fetch-Site` is `same-origin` or `none` (an absent header fails closed, `same-site` is refused: a sibling
/// subdomain is not this origin), and (b) `header_value` equals `expected`, the token minted for THIS session
/// (`application::session::csrf_token`), compared without an early exit. A safe method always passes.
pub fn verify_csrf(
    method: &str,
    site: FetchSite,
    header_value: Option<&str>,
    expected: &str,
) -> bool {
    if !method_is_state_changing(method) {
        return true;
    }
    if !matches!(site, FetchSite::SameOrigin | FetchSite::None) {
        return false;
    }
    let Some(presented) = header_value else {
        return false;
    };
    if expected.is_empty() || presented.len() != expected.len() {
        return false;
    }
    // Length is public (fixed-size HMAC hex); the bytes never short-circuit.
    let mut diff = 0u8;
    for (a, b) in presented.bytes().zip(expected.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// §78.2 "DB enum 与 Rust enum 走 contract test 对账": [`ApiKeyStatus::ALL`] must list
/// exactly `control.api_keys.status`'s CHECK constraint in `migrations/0037_edge_security.sql`,
/// both directions. Runs against the real migration file text (`include_str!`), not a live-DB
/// fixture, so it always executes and fails loud the moment either side drifts — same shape
/// as `crates/adapters/src/email/outbox.rs`'s `contract_tests`.
#[cfg(test)]
mod contract_tests {
    use super::*;

    const MIGRATION_SQL: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../migrations/0037_edge_security.sql"
    ));

    fn check_values(column: &str) -> Vec<String> {
        let needle = format!("CHECK ({column} IN (");
        let start = MIGRATION_SQL
            .find(&needle)
            .unwrap_or_else(|| panic!("migration SQL has no `CHECK ({column} IN (...))` clause"))
            + needle.len();
        let end = MIGRATION_SQL[start..]
            .find(')')
            .expect("unterminated CHECK IN (...) clause")
            + start;
        MIGRATION_SQL[start..end]
            .split(',')
            .map(|s| s.trim().trim_matches('\'').to_string())
            .collect()
    }

    #[test]
    fn api_key_status_matches_check_constraint() {
        let db: Vec<String> = check_values("status");
        let rust: Vec<String> = ApiKeyStatus::ALL
            .iter()
            .map(|s| s.as_db_str().to_string())
            .collect();
        assert_eq!(
            db, rust,
            "ApiKeyStatus::ALL must list every status in DB order"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(s: &str) -> Cidr {
        s.parse().unwrap()
    }

    // ---- §73.2 Cidr ----

    #[test]
    fn cidr_v4_contains() {
        let c = cidr("10.0.0.0/8");
        assert!(c.contains("10.1.2.3".parse().unwrap()));
        assert!(!c.contains("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn cidr_v6_contains() {
        let c = cidr("2001:db8::/32");
        assert!(c.contains("2001:db8::1".parse().unwrap()));
        assert!(!c.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn cidr_canonicalizes_ipv4_mapped_ipv6() {
        // §73.2: IPv4/IPv6 must canonicalize before CIDR comparison.
        let c = cidr("10.0.0.0/8");
        let mapped: IpAddr = "::ffff:10.1.2.3".parse().unwrap();
        assert!(c.contains(mapped));
    }

    #[test]
    fn cidr_zero_prefix_matches_everything() {
        assert!(cidr("0.0.0.0/0").contains("203.0.113.9".parse().unwrap()));
        assert!(cidr("::/0").contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn cidr_rejects_malformed_literal() {
        assert!("not-a-cidr".parse::<Cidr>().is_err());
        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
    }

    // ---- §73.2 ClientNetworkIdentity — the required red→green case ----

    fn trusted_proxy_config() -> TrustedProxyConfig {
        TrustedProxyConfig {
            trusted_proxy_cidrs: vec![cidr("10.0.0.0/8")],
            max_forwarded_hops: 3,
        }
    }

    /// 注错红转绿: a forged `X-Forwarded-For` arriving from a peer OUTSIDE
    /// `trusted_proxy_cidrs` must be ignored — `client_ip` falls back to the raw peer, not the
    /// attacker-supplied header.
    #[test]
    fn forged_xff_from_untrusted_peer_is_ignored() {
        let peer: IpAddr = "203.0.113.9".parse().unwrap(); // not in 10.0.0.0/8
        let id = build_client_network_identity(
            peer,
            Some("198.51.100.1"), // forged "real" client IP
            &trusted_proxy_config(),
            None,
            None,
        );
        assert_eq!(
            id.client_ip, peer,
            "forged header must not override peer_ip"
        );
        assert!(id.proxy_chain.is_empty());
        assert!(
            id.risk_tags
                .contains(&RISK_TAG_FORWARDED_HEADER_IGNORED_UNTRUSTED_PEER.to_string())
        );
    }

    #[test]
    fn xff_from_trusted_peer_is_honored() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let id = build_client_network_identity(
            peer,
            Some(" 198.51.100.1 , 10.0.0.5 "),
            &trusted_proxy_config(),
            None,
            None,
        );
        assert_eq!(id.client_ip, "198.51.100.1".parse::<IpAddr>().unwrap());
        assert_eq!(id.proxy_chain, vec!["10.0.0.5".parse::<IpAddr>().unwrap()]);
        assert!(id.risk_tags.is_empty());
    }

    /// 注错红转绿 (§73.2/§73.3 blocker): the leftmost XFF entry is exactly the part of the
    /// chain the CLIENT controls — a real proxy appends what it received, it never removes
    /// what the client sent. An attacker behind the trusted CDN sends `X-Forwarded-For:
    /// 1.2.3.4`; the CDN appends the attacker's real address `203.0.113.66`. `client_ip`
    /// must resolve to the rightmost non-trusted hop (the CDN's own addition), never the
    /// leftmost attacker-supplied one — otherwise every §73.3 IP-policy consumer (denylist,
    /// allowlist, credential CIDR binding) and the rate-limit key evaluate a forged address.
    #[test]
    fn leftmost_forged_xff_entry_is_not_trusted_as_client_ip() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let id = build_client_network_identity(
            peer,
            Some("1.2.3.4, 203.0.113.66"),
            &trusted_proxy_config(),
            None,
            None,
        );
        assert_eq!(
            id.client_ip,
            "203.0.113.66".parse::<IpAddr>().unwrap(),
            "client_ip must be the rightmost (proxy-appended) hop, not the attacker-supplied leftmost one"
        );
        assert!(id.proxy_chain.is_empty());
    }

    /// 注错红转绿 (§73.2/§73.3 major): hop-limit-exceeded must not collapse the request onto
    /// the trusted proxy's own address — that is a client-triggerable IP-policy bypass (pad
    /// the chain, get attributed to the CDN, dodge a denylisted real IP) and a shared
    /// rate-limit key for every client who does it. The chain is still walked for the real
    /// client even while the hop-limit risk tag is raised.
    #[test]
    fn xff_hop_limit_exceeded_still_resolves_real_client_not_peer() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let id = build_client_network_identity(
            peer,
            Some("1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4"), // 4 hops > max_forwarded_hops=3
            &trusted_proxy_config(),
            None,
            None,
        );
        assert_eq!(
            id.client_ip,
            "4.4.4.4".parse::<IpAddr>().unwrap(),
            "must not fall back to peer_ip — that lets a client hide behind the trusted proxy"
        );
        assert!(
            id.risk_tags
                .contains(&RISK_TAG_FORWARDED_HOP_LIMIT_EXCEEDED.to_string())
        );
    }

    #[test]
    fn xff_all_hops_trusted_falls_back_to_peer() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let id = build_client_network_identity(
            peer,
            Some("10.0.0.2, 10.0.0.3"), // every hop is itself a trusted-proxy address
            &trusted_proxy_config(),
            None,
            None,
        );
        assert_eq!(id.client_ip, peer);
    }

    // ---- §73.3 IP Policy — the required priority test ----

    /// 注错红转绿: emergency deny (global denylist) must override a tenant allowlist that
    /// would otherwise admit the same IP.
    #[test]
    fn global_denylist_overrides_tenant_allowlist() {
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let denylist = vec![cidr("203.0.113.0/24")];
        let allowlist = vec![cidr("203.0.113.0/24")]; // same block, would otherwise allow
        let decision = evaluate_ip_policy(&IpPolicyInput {
            ip,
            global_denylist: &denylist,
            global_emergency_allowlist: &[],
            tenant_denylist: &[],
            tenant_allowlist: &allowlist,
            credential_allowed_cidrs: &[],
            region_asn_risk_tags: &[],
        });
        assert_eq!(
            decision,
            IpPolicyDecision::Deny(IpPolicyDenyReason::GlobalDenylist)
        );
    }

    #[test]
    fn emergency_allowlist_overrides_tenant_denylist_but_not_global_denylist() {
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let emergency = vec![cidr("203.0.113.0/24")];
        let tenant_deny = vec![cidr("203.0.113.0/24")];
        let decision = evaluate_ip_policy(&IpPolicyInput {
            ip,
            global_denylist: &[],
            global_emergency_allowlist: &emergency,
            tenant_denylist: &tenant_deny,
            tenant_allowlist: &[],
            credential_allowed_cidrs: &[],
            region_asn_risk_tags: &[],
        });
        assert_eq!(decision, IpPolicyDecision::Allow { risk_tags: vec![] });

        // Same IP, but now also globally denylisted: emergency allow no longer wins.
        let decision2 = evaluate_ip_policy(&IpPolicyInput {
            ip,
            global_denylist: &emergency, // reuse same block as an explicit global deny
            global_emergency_allowlist: &emergency,
            tenant_denylist: &tenant_deny,
            tenant_allowlist: &[],
            credential_allowed_cidrs: &[],
            region_asn_risk_tags: &[],
        });
        assert_eq!(
            decision2,
            IpPolicyDecision::Deny(IpPolicyDenyReason::GlobalDenylist)
        );
    }

    #[test]
    fn risk_policy_never_denies_only_tags() {
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let tags = vec!["HIGH_RISK_ASN".to_string()];
        let decision = evaluate_ip_policy(&IpPolicyInput {
            ip,
            global_denylist: &[],
            global_emergency_allowlist: &[],
            tenant_denylist: &[],
            tenant_allowlist: &[],
            credential_allowed_cidrs: &[],
            region_asn_risk_tags: &tags,
        });
        assert_eq!(decision, IpPolicyDecision::Allow { risk_tags: tags });
    }

    // ---- §73.5 API key ----

    fn active_record(hash: Vec<u8>) -> ApiKeyRecord {
        ApiKeyRecord {
            key_hash: hash,
            status: ApiKeyStatus::Active,
            allowed_cidrs: vec![],
            expires_at: None,
            revoked_at: None,
        }
    }

    #[test]
    fn valid_key_passes() {
        let pepper = b"server-side-pepper";
        let hash = compute_api_key_hash(pepper, "raw-key-value");
        let record = active_record(hash);
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(
            validate_api_key(
                &record,
                "raw-key-value",
                pepper,
                None,
                ip,
                SystemTime::now()
            ),
            Ok(PepperMatch::Current)
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let pepper = b"server-side-pepper";
        let hash = compute_api_key_hash(pepper, "raw-key-value");
        let record = active_record(hash);
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(
            validate_api_key(&record, "wrong-key", pepper, None, ip, SystemTime::now()),
            Err(ApiKeyRejection::HashMismatch)
        );
    }

    /// 注错红转绿: REVOKED key must always be rejected, even with the right key material.
    #[test]
    fn revoked_key_is_rejected() {
        let pepper = b"server-side-pepper";
        let hash = compute_api_key_hash(pepper, "raw-key-value");
        let mut record = active_record(hash);
        record.status = ApiKeyStatus::Revoked;
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(
            validate_api_key(
                &record,
                "raw-key-value",
                pepper,
                None,
                ip,
                SystemTime::now()
            ),
            Err(ApiKeyRejection::Revoked)
        );
    }

    #[test]
    fn expired_by_timestamp_is_rejected_even_if_status_stale() {
        let pepper = b"server-side-pepper";
        let hash = compute_api_key_hash(pepper, "raw-key-value");
        let mut record = active_record(hash);
        record.expires_at = Some(SystemTime::UNIX_EPOCH);
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(
            validate_api_key(
                &record,
                "raw-key-value",
                pepper,
                None,
                ip,
                SystemTime::now()
            ),
            Err(ApiKeyRejection::Expired)
        );
    }

    #[test]
    fn cidr_binding_rejects_out_of_band_ip() {
        let pepper = b"server-side-pepper";
        let hash = compute_api_key_hash(pepper, "raw-key-value");
        let mut record = active_record(hash);
        record.allowed_cidrs = vec![cidr("10.0.0.0/8")];
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(
            validate_api_key(
                &record,
                "raw-key-value",
                pepper,
                None,
                ip,
                SystemTime::now()
            ),
            Err(ApiKeyRejection::CidrNotAllowed)
        );
        let bound_ip: IpAddr = "10.1.1.1".parse().unwrap();
        assert_eq!(
            validate_api_key(
                &record,
                "raw-key-value",
                pepper,
                None,
                bound_ip,
                SystemTime::now()
            ),
            Ok(PepperMatch::Current)
        );
    }

    /// ADR-0059 D-H (card 33 acceptance): a key hashed under the previous pepper verifies while
    /// the window is open and reports `Previous`, so the gateway rehashes it.
    #[test]
    fn pepper_window_verifies_previous_and_reports_it() {
        let (old, new) = (
            b"pepper-before-rotation".as_slice(),
            b"pepper-after-rotation".as_slice(),
        );
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let old_hashed = active_record(compute_api_key_hash(old, "raw-key-value"));
        assert_eq!(
            validate_api_key(
                &old_hashed,
                "raw-key-value",
                new,
                Some(old),
                ip,
                SystemTime::now()
            ),
            Ok(PepperMatch::Previous)
        );
        let new_hashed = active_record(compute_api_key_hash(new, "raw-key-value"));
        assert_eq!(
            validate_api_key(
                &new_hashed,
                "raw-key-value",
                new,
                Some(old),
                ip,
                SystemTime::now()
            ),
            Ok(PepperMatch::Current)
        );
        assert_eq!(
            validate_api_key(
                &old_hashed,
                "wrong-key",
                new,
                Some(old),
                ip,
                SystemTime::now()
            ),
            Err(ApiKeyRejection::HashMismatch)
        );
    }

    /// ADR-0059 D-H: once the window closes (`previous = None`) the old-pepper key is refused.
    #[test]
    fn pepper_outside_window_refuses_old_key() {
        let (old, new) = (
            b"pepper-before-rotation".as_slice(),
            b"pepper-after-rotation".as_slice(),
        );
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let old_hashed = active_record(compute_api_key_hash(old, "raw-key-value"));
        assert_eq!(
            validate_api_key(
                &old_hashed,
                "raw-key-value",
                new,
                None,
                ip,
                SystemTime::now()
            ),
            Err(ApiKeyRejection::HashMismatch)
        );
    }

    #[test]
    fn lifecycle_transitions() {
        use ApiKeyStatus::*;
        assert!(is_legal_api_key_transition(Create, Active));
        assert!(is_legal_api_key_transition(Active, Rotating));
        assert!(is_legal_api_key_transition(Rotating, Revoked));
        assert!(!is_legal_api_key_transition(Create, Revoked));
        assert!(!is_legal_api_key_transition(Revoked, Active));
        assert!(!is_legal_api_key_transition(Rotating, Active));
    }

    #[test]
    fn status_db_str_round_trips() {
        for s in [
            ApiKeyStatus::Create,
            ApiKeyStatus::Active,
            ApiKeyStatus::Rotating,
            ApiKeyStatus::Revoked,
            ApiKeyStatus::Expired,
        ] {
            assert_eq!(ApiKeyStatus::from_db_str(s.as_db_str()), Some(s));
        }
        assert_eq!(ApiKeyStatus::from_db_str("BOGUS"), None);
    }

    /// 注错红转绿: the log fingerprint helper must never leak the raw key or the full keyed
    /// hash — this is what a `grep` over log output is meant to catch (§73.5).
    #[test]
    fn log_fingerprint_never_contains_secret_material() {
        let pepper = b"server-side-pepper";
        let raw_key = "sk_live_super_secret_value_do_not_log";
        let hash = compute_api_key_hash(pepper, raw_key);
        let full_hash_hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();

        let fingerprint = api_key_log_fingerprint("sk_live_ab12", &hash);

        assert!(fingerprint.starts_with("sk_live_ab12."));
        assert!(!fingerprint.contains(raw_key));
        assert!(!fingerprint.contains(&full_hash_hex));
        // Fingerprint's hash segment is exactly 8 hex chars (4 bytes) — far shorter than the
        // 64-char full SHA-256 hex digest, so it cannot literally embed it.
        let hash_segment = fingerprint.rsplit('.').next().unwrap();
        assert_eq!(hash_segment.len(), 8);
    }

    // ---- §73.6 session cookie + CSRF ----

    #[test]
    fn session_cookie_name_has_host_prefix() {
        assert!(SESSION_COOKIE_NAME.starts_with("__Host-"));
    }

    #[test]
    fn session_cookie_attributes_are_fixed_plus_samesite() {
        let attrs = session_cookie_attributes(SameSitePolicy::Strict);
        assert!(attrs.contains("Secure"));
        assert!(attrs.contains("HttpOnly"));
        assert!(attrs.contains("Path=/"));
        assert!(attrs.contains("SameSite=Strict"));
    }

    const EXPECTED: &str = "a1b2c3";

    #[test]
    fn csrf_header_must_equal_the_expected_token_on_a_state_changing_method() {
        let site = FetchSite::SameOrigin;
        assert!(verify_csrf("POST", site, Some(EXPECTED), EXPECTED));
        assert!(!verify_csrf("POST", site, Some("a1b2c4"), EXPECTED));
        assert!(!verify_csrf("POST", site, Some("a1b2"), EXPECTED));
        assert!(!verify_csrf("POST", site, None, EXPECTED));
        assert!(!verify_csrf("POST", site, Some(""), ""));
    }

    /// 注错红转绿 (§73.6): the site gate is independent of the token; a correct token on a cross-site, same-site,
    /// header-less or unrecognised request is still refused, `none` (user navigation) passes.
    #[test]
    fn fetch_site_gates_state_changing_methods() {
        for site in [
            FetchSite::CrossSite,
            FetchSite::SameSite,
            FetchSite::Absent,
            FetchSite::Unrecognised,
        ] {
            assert!(
                !verify_csrf("DELETE", site, Some(EXPECTED), EXPECTED),
                "{site:?}"
            );
        }
        assert!(verify_csrf(
            "PUT",
            FetchSite::None,
            Some(EXPECTED),
            EXPECTED
        ));
    }

    #[test]
    fn safe_methods_skip_the_csrf_check() {
        for method in ["GET", "head", "OPTIONS", "TRACE"] {
            assert!(!method_is_state_changing(method), "{method}");
            assert!(verify_csrf(method, FetchSite::CrossSite, None, EXPECTED));
        }
        for method in ["POST", "PUT", "PATCH", "DELETE", "BREW"] {
            assert!(method_is_state_changing(method), "{method}");
        }
    }

    #[test]
    fn fetch_site_header_parses_the_spec_set_exactly() {
        let parsed: Vec<FetchSite> = [
            Some("same-origin"),
            Some("same-site"),
            Some("cross-site"),
            Some("none"),
            None,
            Some("Same-Origin"),
        ]
        .into_iter()
        .map(FetchSite::from_header)
        .collect();
        assert_eq!(
            parsed,
            vec![
                FetchSite::SameOrigin,
                FetchSite::SameSite,
                FetchSite::CrossSite,
                FetchSite::None,
                FetchSite::Absent,
                FetchSite::Unrecognised,
            ]
        );
    }
}

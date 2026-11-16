//! `domain::network` — Pure network values shared by credentials and proxy/IP policy (§73.2; ADR-0130).
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: [application::api_key]
//! Invariants: [canonical IPv4-mapped IPv6; no I/O]
//! Spec: §73.2; §73.5

use std::net::IpAddr;
use std::str::FromStr;

/// One CIDR block, either address family (§73.2 `trusted_proxy_cidrs[]` / IP policy lists /
/// API credential `allowed_cidrs`— one shape serves all three, spec draws no distinction).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix_len: u8,
}

/// [`Cidr::from_str`] failure — malformed literal, not a runtime condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrParseError(pub String);

impl std::fmt::Display for CidrParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid CIDR literal: {}", self.0)
    }
}
impl std::error::Error for CidrParseError {}

impl FromStr for Cidr {
    type Err = CidrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_s, len_s) = s
            .split_once('/')
            .ok_or_else(|| CidrParseError(s.to_string()))?;
        // §73.2: canonicalize before it becomes a CIDR/rate-limit key — an IPv4-mapped IPv6
        // literal in config ("::ffff:10.0.0.0/104") collapses to the plain IPv4 form so it
        // compares correctly against a canonicalized peer address in `contains`.
        let network: IpAddr = addr_s
            .parse::<IpAddr>()
            .map_err(|_| CidrParseError(s.to_string()))?
            .to_canonical();
        let max_len: u8 = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix_len: u8 = len_s.parse().map_err(|_| CidrParseError(s.to_string()))?;
        if prefix_len > max_len {
            return Err(CidrParseError(s.to_string()));
        }
        Ok(Cidr {
            network,
            prefix_len,
        })
    }
}

impl Cidr {
    /// Whether `ip` (canonicalized first, §73.2) falls inside this block. Cross-family
    /// comparisons (an IPv6-only address against a v4 block) never match — canonicalization
    /// already folded every IPv4-mapped v6 address into its v4 form, so a real mismatch here
    /// means the families are genuinely different.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = mask_u32(self.prefix_len);
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = mask_u128(self.prefix_len);
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

/// `u32::MAX << n` panics at `n == 32`; the `/0` block ("match everything") is the one case
/// that needs the all-zero mask directly.
const fn mask_u32(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

const fn mask_u128(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_cidr_parse_and_contains() {
        for (literal, inside, outside) in [
            ("10.0.0.0/8", "10.1.2.3", "11.0.0.1"),
            ("2001:db8::/32", "2001:db8::1", "2001:db9::1"),
            ("::ffff:10.0.0.0/8", "::ffff:10.1.2.3", "11.0.0.1"),
            ("0.0.0.0/0", "203.0.113.9", "2001:db8::1"),
        ] {
            let block: Cidr = literal.parse().unwrap();
            assert!(block.contains(inside.parse().unwrap()), "{literal}");
            assert!(!block.contains(outside.parse().unwrap()), "{literal}");
        }
        for invalid in [
            "::ffff:10.0.0.0/104",
            "bad/8",
            "10.0.0.0/33",
            "2001:db8::/129",
            "10.0.0.0",
            "10.0.0.0/x",
        ] {
            assert!(invalid.parse::<Cidr>().is_err(), "{invalid}");
        }
    }
}

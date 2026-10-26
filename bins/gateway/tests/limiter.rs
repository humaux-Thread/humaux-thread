//! `gateway::tests::limiter` — Exact hierarchical rate gates (§72.3; ADR-0100).
//! Depends-on: crates=[humaux-domain, tokio, uuid]; services=[]; env=[]; modules=[domain::error, gateway::limiter]
//! Called-by: [cargo-test]
//! Invariants: [G-M03-1 calls the production limiter with 80 distinct credentials; frozen time excludes scheduling noise]
//! Spec: Baseline §72.3; §79; §80.1; ADR-0100

use humaux_domain::error::ErrorCode;
use humaux_gateway::limiter::{Limiter, RatePolicy, Subject};
use std::{collections::BTreeSet, time::Duration};
use uuid::Uuid;

fn policy(burst: i64, refill: i64) -> RatePolicy {
    RatePolicy::new(burst, refill).expect("fixture policy")
}

#[tokio::test(start_paused = true)]
async fn g_m03_1_eighty_keys_share_exact_account_burst() {
    let mut policies = [policy(1000, 1000); 5];
    policies[3] = policy(128, 20);
    let limiter = Limiter::new(policies, [1000; 5]).expect("limiter");
    // ADR-0100 D1: settle the conservative restart credit before measuring a full burst.
    let account = Uuid::now_v7();
    limiter.check(&[Subject::Account(account)]).expect("seed");
    tokio::time::advance(Duration::from_secs(7)).await;
    let mut passed = BTreeSet::new();
    let mut denied = BTreeSet::new();
    for i in 0..160_u128 {
        let subjects = [
            Subject::Credential(account, Uuid::from_u128(i % 80 + 1)),
            Subject::Account(account),
        ];
        match limiter.check(&subjects) {
            Ok(()) => {
                passed.insert(i);
            }
            Err(e) => {
                assert_eq!((e.code, e.scope), (ErrorCode::RateLimited, "tenant"));
                denied.insert(i);
            }
        }
    }
    assert_eq!(passed.len(), 128, "G-M03-1 account burst");
    assert_eq!(passed, (0..128).collect());
    assert_eq!(denied, (128..160).collect());
}

#[tokio::test(start_paused = true)]
async fn restart_refill_and_all_five_tiers_are_atomic() {
    let account = Uuid::now_v7();
    let subjects = [
        Subject::ip("2001:db8::1".parse().unwrap(), 64).unwrap(),
        Subject::Credential(account, Uuid::from_u128(1)),
        Subject::User(account, Uuid::from_u128(2)),
        Subject::Account(account),
        Subject::Operation(account, Uuid::from_u128(1), "protocol".into()),
    ];
    assert_eq!(
        subjects.iter().map(Subject::scope).collect::<BTreeSet<_>>(),
        ["ip", "credential", "user", "tenant", "operation"]
            .into_iter()
            .collect()
    );
    for tier in 0..5 {
        let mut policies = [policy(1000, 1000); 5];
        policies[tier] = policy(128, 1);
        let limiter = Limiter::new(policies, [100; 5]).unwrap();
        assert_eq!(limiter.check(&subjects), Ok(()));
        assert_eq!(
            limiter.check(&subjects).unwrap_err().scope,
            subjects[tier].scope()
        );
        let other: Vec<_> = subjects
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != tier)
            .map(|(_, s)| s.clone())
            .collect();
        for _ in 0..999 {
            assert_eq!(limiter.check(&other), Ok(()));
        }
        assert_eq!(
            limiter.check(&other).unwrap_err().code,
            ErrorCode::RateLimited
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(limiter.check(&subjects), Ok(()));
    }
    assert_eq!(
        Subject::ip("2001:db8::ffff".parse().unwrap(), 64).unwrap(),
        subjects[0]
    );
}

#[tokio::test(start_paused = true)]
async fn memory_cap_never_evicts_an_active_bucket_and_duplicates_charge_once() {
    let limiter = Limiter::new([policy(2, 1); 5], [1; 5]).unwrap();
    let a = Subject::Account(Uuid::from_u128(1));
    let b = Subject::Account(Uuid::from_u128(2));
    assert_eq!(limiter.check(&[a.clone(), a.clone()]), Ok(()));
    assert_eq!(
        limiter.check(std::slice::from_ref(&a)).unwrap_err().code,
        ErrorCode::RateLimited
    );
    assert_eq!(
        limiter.check(std::slice::from_ref(&b)).unwrap_err().code,
        ErrorCode::DependencyUnavailable
    );
    assert_eq!(
        limiter.check(std::slice::from_ref(&a)).unwrap_err().code,
        ErrorCode::RateLimited
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(limiter.check(&[b]), Ok(()));
}

#[test]
fn adr_0065_w10_ip_identity_table() {
    let cases = [
        ("fe80::1", "fe80::1"),
        ("fe80::2", "fe80::2"),
        ("2001:db8::1", "2001:db8::"),
        ("2001:db8::2", "2001:db8::"),
        ("::1", "::1"),
        ("203.0.113.9", "203.0.113.9"),
        ("::ffff:203.0.113.9", "203.0.113.9"),
    ];
    let actual: Vec<_> = cases
        .iter()
        .map(|(ip, _)| Subject::ip(ip.parse().unwrap(), 64).unwrap())
        .collect();
    let expected: Vec<_> = cases
        .iter()
        .map(|(_, ip)| Subject::Ip(ip.parse().unwrap()))
        .collect();
    assert_eq!(actual.len(), 7);
    assert_eq!(actual, expected, "ADR-0065 W-10 /128 local IPv6 identities");
}

#[tokio::test(start_paused = true)]
async fn ip_capacity_isolated_from_authenticated_tiers() {
    let limiter = Limiter::new([policy(2, 1); 5], [1; 5]).unwrap();
    let ip = Subject::ip("203.0.113.1".parse().unwrap(), 64).unwrap();
    assert_eq!(limiter.check(&[ip]), Ok(()));
    let ip = Subject::ip("203.0.113.2".parse().unwrap(), 64).unwrap();
    assert_eq!(
        limiter.check(&[ip]).unwrap_err().code,
        ErrorCode::DependencyUnavailable
    );
    let tenant = Uuid::from_u128(1);
    let credential = Uuid::from_u128(2);
    let authenticated = [
        Subject::Credential(tenant, credential),
        Subject::User(tenant, Uuid::from_u128(3)),
        Subject::Account(tenant),
        Subject::Operation(tenant, credential, "protocol".into()),
    ];
    assert_eq!(authenticated.len(), 4);
    assert_eq!(limiter.check(&authenticated), Ok(()));
}

#[tokio::test(start_paused = true)]
async fn pressure_eviction_probes_at_most_thirty_two_entries() {
    let mut policies = [policy(2, 1); 5];
    policies[3] = policy(2, 2);
    let limiter = Limiter::new(policies, [33; 5]).unwrap();
    // §67.2: oldest 32 remain active; the 33rd alone will refill in one second.
    for i in 1..=33 {
        assert_eq!(
            limiter.check(&[Subject::Account(Uuid::from_u128(i))]),
            Ok(())
        );
    }
    tokio::time::advance(Duration::from_secs(1)).await;
    for i in 1..=32 {
        assert_eq!(
            limiter.check(&[Subject::Account(Uuid::from_u128(i))]),
            Ok(())
        );
    }
    let new = Subject::Account(Uuid::from_u128(34));
    assert_eq!(
        limiter.check(std::slice::from_ref(&new)).unwrap_err().code,
        ErrorCode::DependencyUnavailable,
        "pressure must stop before probe 33"
    );
    assert_eq!(
        limiter.check(&[new]),
        Ok(()),
        "next pressure resumes at the idle entry"
    );
}

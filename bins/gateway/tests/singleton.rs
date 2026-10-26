//! Dedicated session and real gateway boot gates (§67.2; ADR-0100).
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-gateway, postgres, tokio, uuid];
//!   services=[PostgreSQL(owner), PostgreSQL(role_gateway), HTTP(loopback), subprocess(humaux-gateway)];
//!   env=[HUMAUX_GATEWAY_PG_DSN, HUMAUX_TEST_PG_DSN, CARGO_BIN_EXE_humaux-gateway]; modules=[gateway::bootstrap]
//! Called-by: [cargo-test]
//! Invariants: [missing CI inputs fail; admin termination targets only the fixture-owned lock backend]
//! Spec: Baseline §67.2; §79; §80.1; ADR-0100

#[path = "support/singleton_env.rs"]
mod support;
use humaux_adapters::postgres::RuntimeDbPool;
use humaux_domain::error::ErrorCode;
use humaux_gateway::bootstrap::acquire_gateway_lock;
use postgres::{Client, NoTls};
use std::{
    collections::BTreeMap,
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use uuid::Uuid;

fn input(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("fail: missing object {key}"))
}
fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

struct Process(Child);
impl Process {
    fn spawn(env: &BTreeMap<String, String>) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_humaux-gateway"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("HUMAUX_GATEWAY_") {
                command.env_remove(key);
            }
        }
        Self(
            command
                .envs(env)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn gateway"),
        )
    }
    fn started(&mut self, addr: SocketAddr) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            assert_eq!(
                self.0.try_wait().unwrap(),
                None,
                "gateway refused unexpectedly"
            );
            if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
                return;
            }
            assert!(Instant::now() < deadline, "boot timed out");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    fn exit_code(&mut self) -> Option<i32> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status.code();
            }
            assert!(
                Instant::now() < deadline,
                "G-M03-3 second gateway booted or lease loss did not exit"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn g_m03_3_second_gateway_refuses_same_deployment_but_other_deployment_boots() {
    let dsn = input("HUMAUX_GATEWAY_PG_DSN");
    let deployment = Uuid::now_v7().to_string();
    let first_addr = free_addr();
    let mut env = support::base_env(&dsn, first_addr, free_addr());
    env.insert("HUMAUX_GATEWAY_DEPLOYMENT".into(), deployment.clone());
    let mut first = Process::spawn(&env);
    first.started(first_addr);
    let second_addr = free_addr();
    let mut second_env = support::base_env(&dsn, second_addr, free_addr());
    second_env.insert("HUMAUX_GATEWAY_DEPLOYMENT".into(), deployment);
    let mut second = Process::spawn(&second_env);
    assert_eq!(
        second.exit_code(),
        Some(1),
        "G-M03-3 second gateway must refuse"
    );
    let third_addr = free_addr();
    let mut third = Process::spawn(&support::base_env(&dsn, third_addr, free_addr()));
    third.started(third_addr);
    assert_eq!(first.0.try_wait().unwrap(), None);
    assert_eq!(third.0.try_wait().unwrap(), None);
}

fn terminate_lock(admin: &mut Client, key: i64) {
    let high = i64::from(
        u32::try_from((u64::from_ne_bytes(key.to_ne_bytes()) >> 32) & 0xffff_ffff).unwrap(),
    );
    let low =
        i64::from(u32::try_from(u64::from_ne_bytes(key.to_ne_bytes()) & 0xffff_ffff).unwrap());
    let rows = admin.query("SELECT pg_terminate_backend(pid, 5000) FROM pg_locks WHERE locktype = 'advisory' AND classid::bigint = $1 AND objid::bigint = $2 AND objsubid = 1 AND granted", &[&high, &low]).unwrap();
    assert_eq!(rows.len(), 1, "terminate exactly the owned session");
    assert!(rows[0].get::<_, bool>(0));
}

#[tokio::test]
async fn lease_drop_unlocks_and_dead_original_session_returns_exact_error() {
    let pool = RuntimeDbPool::connect(&input("HUMAUX_GATEWAY_PG_DSN"))
        .await
        .unwrap();
    let deployment = Uuid::now_v7().to_string();
    let lease = acquire_gateway_lock(&pool, &deployment).await.unwrap();
    assert_eq!(
        acquire_gateway_lock(&pool, &deployment).await.err(),
        Some(ErrorCode::Conflict)
    );
    drop(lease);
    let key = i64::from_be_bytes(Uuid::now_v7().as_bytes()[..8].try_into().unwrap());
    let mut lease = pool.try_session_lock(key).await.unwrap().unwrap();
    assert_eq!(lease.check().await, Ok(()));
    tokio::task::spawn_blocking(move || {
        let mut admin = Client::connect(&input("HUMAUX_TEST_PG_DSN"), NoTls).unwrap();
        terminate_lock(&mut admin, key);
    })
    .await
    .unwrap();
    assert_eq!(lease.check().await, Err(ErrorCode::DependencyUnavailable));
    assert_eq!(
        lease.check().await,
        Err(ErrorCode::DependencyUnavailable),
        "no reconnect"
    );
    assert!(pool.try_session_lock(key).await.unwrap().is_some());
    let mut replacement = acquire_gateway_lock(&pool, &deployment).await.unwrap();
    assert_eq!(replacement.check().await, Ok(()));
}

#[test]
fn gateway_exits_nonzero_when_the_lock_session_is_terminated() {
    use sha2::{Digest, Sha256};
    let dsn = input("HUMAUX_GATEWAY_PG_DSN");
    let addr = free_addr();
    let mut env = support::base_env(&dsn, addr, free_addr());
    env.insert(
        "HUMAUX_GATEWAY_SESSION_LOCK_CHECK_SECONDS".into(),
        "1".into(),
    );
    let deployment = &env["HUMAUX_GATEWAY_DEPLOYMENT"];
    let digest = Sha256::digest(
        [
            b"humaux-gateway-singleton\0".as_slice(),
            deployment.as_bytes(),
        ]
        .concat(),
    );
    let key = i64::from_be_bytes(digest[..8].try_into().unwrap());
    let mut gateway = Process::spawn(&env);
    gateway.started(addr);
    let mut admin = Client::connect(&input("HUMAUX_TEST_PG_DSN"), NoTls).unwrap();
    terminate_lock(&mut admin, key);
    assert_eq!(gateway.exit_code(), Some(1));
}

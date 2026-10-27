//! `humaux-application` — Humaux Thread workspace crate（布局见 §58）。
//! Depends-on: crates=[]; services=[];
//!   env=[]; modules=[]
//! Called-by: [crate(humaux-adapters), crate(humaux-consolidation-worker), crate(humaux-gateway), crate(humaux-private-worker), crate(humaux-protocol), crate(humaux-public-pool)]
//! Invariants: []
//! Spec: §58; §3; §78.3
//!
//! 本 crate 的职责边界与依赖规则以 docs/architecture/Baseline_2.9.md 为唯一规范真源；
//! Domain 永不 import HTTP / SQLx / Qdrant / Provider SDK / ENV（§3 / §78.3）。

pub mod affect;
pub mod archive;
pub mod auth;
/// C3 (M04 D7): the `BillingProvider` port of §71.2; no provider type, no implementation.
pub mod billing;
pub mod confirm;
pub mod consolidate;
pub mod continuity;
pub mod contribute;
pub mod contribution_execution;
pub mod correct;
pub mod distill;
pub mod entitlement;
pub mod forget;
pub mod ingest;
pub mod login;
pub mod notify;
pub mod oauth;
pub mod pin;
pub mod referral;
pub mod remember;
pub mod retrieval_embedding_port;
pub mod retrieve;
pub mod scheduler;
pub mod session;
pub mod signed_token;
pub mod supersede;

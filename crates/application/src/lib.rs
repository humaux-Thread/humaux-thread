//! `humaux-application` — Humaux Thread workspace crate（布局见 §58）。
//! Depends-on: crates=[]; services=[];
//!   env=[]; modules=[]
//! Called-by: [crate(humaux-adapters), crate(humaux-billing-worker), crate(humaux-consolidation-worker), crate(humaux-gateway), crate(humaux-maintenance), crate(humaux-private-worker), crate(humaux-protocol), crate(humaux-public-pool), crate(humaux-public-worker), crate(humaux-retrieval-worker)]
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
/// ADR-0110 D-E: per-account processing status (§15.6).
pub mod processing_status;
pub mod referral;
pub mod remember;
pub mod retrieval_embedding_port;
pub mod retrieve;
pub mod scheduler;
pub mod session;
pub mod signed_token;
pub mod supersede;

/// Recall hydration use case and complete snapshot read port (ADR-0130).
pub mod recall_read;

/// Task lease acquisition (§30.2).
pub mod coordination;

/// Bounded public dispatch use cases (§13/§14).
pub mod public_dispatch;

/// Registered query embedding execution (ADR-0012).
pub mod query_embedding_execution;

/// Private inference RPC lifecycle.
pub mod private_inference;

/// Operational health sampling (ADR-0061 D-D; ADR-0130 D2).
pub mod health;

/// Pure §73 credential/network vocabulary.
pub mod api_key;

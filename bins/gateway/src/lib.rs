//! `humaux-gateway` — Trusted gateway entry points shared by HTTP and MCP transports.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: [crate(humaux-private-worker)]
//! Invariants: []
//! Spec: none

pub mod admission;
pub mod auth;
pub mod auth_pages;
pub mod bootstrap;
pub mod cached_embedding;
pub mod context;
pub mod continuity;
pub mod guard;
pub mod limiter;
pub mod mcp_application;
mod memory;
pub mod recall;
pub mod remember;
pub mod rerank_client;
pub mod retrieval_embedding_client;
pub mod status;

//! `adapters::batch` — Compatibility entry point for standalone batch issuance (§34.2 / §60 transaction A).
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: [tests]
//! Invariants: [the issuer uses a separate pool and commits independently of Remember]
//! Spec: Baseline §34.2; §60.1

pub use crate::ingest_ticket_repo::{BatchError, BatchIssued, BeginBatchCommand, begin_batch};

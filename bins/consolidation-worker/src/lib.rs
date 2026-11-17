//! `humaux-consolidation-worker` — Process-facing consolidation API and UDS inference adapter.
//! Depends-on: crates=[humaux-application]; services=[]; env=[]; modules=[]
//! Called-by: []
//! Invariants: [§11.8 inference is bound by the caller to the recorded run]
//! Spec: §11.8; ADR-0130

pub mod dsn;
pub mod inference_client;

pub use humaux_application::consolidation_execution::{
    DispatchConfig, DispatchError, DispatchReport, RollupParts, RunOnceError, dispatch_pass,
    run_once, run_once_bound,
};

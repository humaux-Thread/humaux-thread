//! `consolidation-worker::main` — Start the consolidation worker on its Tokio runtime.
//! Depends-on: crates=[tokio]; services=[]; env=[]; modules=[consolidation-worker::bootstrap]
//! Called-by: [process(humaux-consolidation-worker)]
//! Invariants: [all mode dispatch and exit codes come from the composition root]
//! Spec: ADR-0130 D2

mod bootstrap;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    bootstrap::run().await
}

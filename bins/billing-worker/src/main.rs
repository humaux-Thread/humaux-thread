//! `billing-worker::main` — non-live startup probe (§71.2).
//! Depends-on: crates=[]; services=[]; env=[]; modules=[billing-worker::mode]
//! Called-by: [process(humaux-billing-worker)]
//! Invariants: [gate precedes startup output; no processing loop]
//! Spec: Baseline §71.2

fn main() {
    match humaux_billing_worker::mode::BillingMode::from_env() {
        Ok(mode) => println!("{}", mode.name()),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

//! `public-pool::admission` — Admission rule modules; today only the A3 de-identification rule (ADR-0090 D-C).
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: []
//! Invariants: [rules here are pure and deterministic with no I/O and no model call; an unchecked input is NOT_RUN and never pass]
//! Spec: Baseline §12.6; §57.1; ADR-0090 D-C
//!
//! Persistence of receipts and the model-bound A5 leg belong to later cards (M20-10, M20-11); the other rules land beside `deid`.

pub mod deid;

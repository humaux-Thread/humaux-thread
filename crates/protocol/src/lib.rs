//! `humaux-protocol` — Humaux Thread workspace crate（布局见 §58）。
//! Depends-on: crates=[]; services=[];
//!   env=[]; modules=[]
//! Called-by: [crate(humaux-gateway), crate(humaux-maintenance), crate(humaux-private-worker), crate(xtask)]
//! Invariants: [`page` is the one pager and `page@1` cursor codec of this crate (M26 D7); list-type tool results are
//!   sized and cursored there and nowhere else in protocol]
//! Spec: §58; §3; §78.3; §33.5
//!
//! 本 crate 的职责边界与依赖规则以 docs/architecture/Baseline_2.9.md 为唯一规范真源；
//! Domain 永不 import HTTP / SQLx / Qdrant / Provider SDK / ENV（§3 / §78.3）。

pub mod edge;
pub mod error_map;
pub mod mcp;
pub mod mcp_catalog;
pub mod page;
pub mod rest;

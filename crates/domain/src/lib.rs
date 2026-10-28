//! `humaux-domain` — Humaux Thread workspace crate（布局见 §58）。
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: [crate(humaux-adapters), crate(humaux-admin), crate(humaux-application), crate(humaux-billing-worker), crate(humaux-cache), crate(humaux-consolidation-worker), crate(humaux-gateway), crate(humaux-infra-cell), crate(humaux-infra-egress), crate(humaux-local-secret-scan), crate(humaux-maintenance), crate(humaux-private-worker), crate(humaux-projection), crate(humaux-protocol), crate(humaux-public-pool), crate(humaux-public-worker), crate(humaux-retrieval), crate(humaux-retrieval-provider), crate(humaux-retrieval-worker), crate(humaux-telemetry), crate(humaux-testkit), crate(xtask)]
//! Invariants: [§78.2 closed-set enums, ALL and wire labels share one macro declaration]
//! Spec: Baseline §3; §58; §78.3
//!
//! 本 crate 的职责边界与依赖规则以 docs/architecture/Baseline_2.9.md 为唯一规范真源；
//! Domain 永不 import HTTP / SQLx / Qdrant / Provider SDK / ENV（§3 / §78.3）。

/// One closed set from one list: the enum, its `ALL` and its wire labels, so `ALL` and the labels cannot drift from the
/// variants (a variant added here is in `ALL`, so G-N09-1 and the §78.2 contract test see it).
macro_rules! closed_set {
    (@all slice, $name:ident, $($variant:ident),+) => {
        /// Every variant, in declaration order: the §78.2 contract-test surface.
        pub const ALL: &[Self] = &[$(Self::$variant,)+];
    };
    (@all array, $name:ident, $($variant:ident),+) => {
        /// Every variant, in declaration order: the §78.2 contract-test surface.
        pub const ALL: [Self; [$(stringify!($variant)),+].len()] = [$(Self::$variant,)+];
    };
    ($wire_fn:ident, $parse_fn:ident, $shape:ident;
     $(#[$meta:meta])* $name:ident { $($(#[$vmeta:meta])* $variant:ident => $wire:literal,)+ }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $($(#[$vmeta])* $variant,)+
        }
        impl $name {
            closed_set!(@all $shape, $name, $($variant),+);

            /// Stable DB CHECK label (§78.2).
            pub const fn $wire_fn(self) -> &'static str {
                match self { $(Self::$variant => $wire,)+ }
            }

            /// A DB value outside the closed set is never a default (§78.2).
            pub fn $parse_fn(value: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|item| item.$wire_fn() == value)
            }
        }
    };
}

pub mod affect;
/// ADR-0096: closed applicability vocabulary, independent of visibility (§78.2).
pub mod applicability;
pub mod attribution;
pub mod audit;
pub mod authority;
/// M04 D7: billing vocabularies (§71.2, §71.3) and the pure subscription-state projection.
pub mod billing;
pub mod boundary;
pub mod code;
pub mod confirm;
pub mod consolidate;
pub mod context;
pub mod continuity;
pub mod coordination;
pub mod dataclass;
pub mod egress;
pub mod error;
pub mod evidence;
pub mod grounding;
pub mod identity;
pub mod ids;
pub mod knowledge;
pub mod ledger;
pub mod lifecycle;
pub mod memory;
pub mod note;
pub mod plan;
pub mod policy;
/// ADR-0101: hierarchy and facet closed sets (§78.2).
pub mod project_tree;
pub mod public;
pub mod relation;
pub mod selection;
pub mod source;
pub mod subject;
pub mod temporal;
pub mod ticket_family;

//! `domain::attribution` — the §6.1.4 work-attribution closed sets: the ground of a formal memory → project link and
//!   the registered rule that wrote it (ADR-0078 D-D, M29 T06a).
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: [adapters::attribution_repo, adapters::remember, tests]
//! Invariants: [SourceKind has no model-derived variant (N09 R2, gate G-N09-1); each ALL is generated from the same
//!   list as its enum, so it cannot omit a variant; the wire labels are migration 0252's CHECK literals (§78.2,
//!   G-M29-1)]
//! Spec: Baseline §6.1.4; §78.2; ADR-0078
//!
//! | Rust | DB (migration `0252_work_attribution.sql`) |
//! |---|---|
//! | [`SourceKind`] | `evidence_projects_source_kind_check`, `memory_projects_source_kind_check` |
//! | [`RuleId`] | `memory_projects_rule_id_ver_check` |

/// One closed set from one list: the enum, its `ALL` and its wire labels, so `ALL` and the labels cannot drift from the
/// variants (a variant added here is in `ALL`, so G-N09-1 and the §78.2 contract test see it).
macro_rules! closed_set {
    ($(#[$meta:meta])* $name:ident { $($(#[$vmeta:meta])* $variant:ident => $wire:literal,)+ }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $($(#[$vmeta])* $variant,)+
        }

        impl $name {
            /// Every variant, in declaration order: the §78.2 contract-test surface.
            pub const ALL: &[$name] = &[$($name::$variant,)+];

            /// The migration 0252 CHECK literal.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $wire,)+
                }
            }
        }
    };
}

closed_set! {
    /// `source_kind` of `memory_projects` / `evidence_projects`: the deterministic ground of a formal attribution
    /// (ADR-0078 D-D ladder, N09 R1). Frozen with no model-derived variant (N09 R2, G-N09-1).
    SourceKind {
        /// A1: a `project_id` declared on the write and validated by the server (N09 R1 ①).
        Declared => "DECLARED",
        /// A2 (deferred): a trusted external key that matches one project (N09 R1 ②).
        ExternalKey => "EXTERNAL_KEY",
        /// A3 / A3': inherited from an already-formal relation under a registered rule (N09 R1 ③).
        Inherited => "INHERITED",
    }
}

closed_set! {
    /// `memory_projects.rule_id_ver`: the registered `rule_id@version` every automatic formal row carries, so a
    /// falsified rule's rows can be revoked in bulk (N09 R6).
    RuleId {
        /// A1, with [`SourceKind::Declared`].
        Declared1 => "declared@1",
        /// A3, with [`SourceKind::Inherited`].
        TaskRun1 => "task_run@1",
        /// A3', with [`SourceKind::Inherited`]; written by the M29 supersede trigger (T06b).
        Correction1 => "correction@1",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// G-N09-1: the source set is the three deterministic grounds and nothing else; a `ModelExtracted` variant is red.
    #[test]
    fn g_n09_1_source_kind_is_frozen() {
        let wire: Vec<&str> = SourceKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(wire, ["DECLARED", "EXTERNAL_KEY", "INHERITED"]);
    }
}

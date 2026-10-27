//! `domain::code` — closed code-graph vocabularies: snapshot kind, snapshot state and repository provider key.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: [tests]
//! Invariants: [the crate-root closed_set macro generates each enum, ALL and DB labels; each set equals its CHECK list in
//!   private.code_snapshots / control.repositories item by item; a DB value outside the set parses to None, never a default]
//! Spec: Baseline §27; §78.2; ADR-0114 D-B, D-J

closed_set! { as_db_str, from_db_str, array;
    /// ADR-0114 D-B: what a snapshot freezes.
    SnapshotKind {
        /// A committed tree.
        Commit => "COMMIT",
        /// An uncommitted working-tree overlay (D-H).
        Worktree => "WORKTREE",
    }
}

closed_set! { as_db_str, from_db_str, array;
    /// ADR-0114 D-B/D-D: only READY is readable by query ops.
    SnapshotState {
        /// Pushed, not yet verified and published.
        Building => "BUILDING",
        /// Verified and published.
        Ready => "READY",
        /// Verification or publish failed, with a reason.
        Failed => "FAILED",
        /// Aged out of its view.
        Expired => "EXPIRED",
    }
}

closed_set! { as_db_str, from_db_str, array;
    /// ADR-0114 D-J: the namespace of `control.repositories.external_id`.
    RepositoryProvider {
        /// A UUID the client minted and persists.
        Client => "CLIENT",
        /// The old system's `project_id`, for the M25 facade.
        LegacyProject => "LEGACY_PROJECT",
    }
}

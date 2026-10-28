//! `domain::code` — closed code-graph vocabularies: snapshot kind, snapshot state, repository provider key, symbol kind, edge
//!   kind and evidence level.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: [tests]
//! Invariants: [the crate-root closed_set macro generates each enum, ALL and DB labels; each set equals its CHECK list in
//!   private.code_snapshots / code_symbols / code_edges and control.repositories item by item; a DB value outside the set
//!   parses to None, never a default]
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

// ponytail: kinds = v1 grammars' tags captures at 2026-10-27; M16-5 pins grammar versions and extends enum + CHECK + contract test if a pinned grammar adds one (ADR-0114 "an edge-kind or level change touches enum + CHECK + contract test + this ADR")
closed_set! { as_db_str, from_db_str, array;
    /// ADR-0114 D-B: what a symbol defines. The set is the union of the `@definition.<kind>` captures in the `queries/tags.scm`
    /// of the v1 grammars (tree-sitter-rust, -python, -javascript, -typescript, -go; default branches read 2026-10-27); the
    /// tree-sitter code-navigation page (tree-sitter.github.io/tree-sitter/4-code-navigation.html) documents class, function,
    /// interface, method and module, and the grammars add constant, macro and type.
    SymbolKind {
        /// A class-like definition.
        Class => "CLASS",
        /// A constant.
        Constant => "CONSTANT",
        /// A function.
        Function => "FUNCTION",
        /// An interface-like definition.
        Interface => "INTERFACE",
        /// A macro definition.
        Macro => "MACRO",
        /// A method.
        Method => "METHOD",
        /// A module; every parsed file also has one file-scope MODULE symbol, the from end of its top-level edges.
        Module => "MODULE",
        /// A type definition.
        Type => "TYPE",
    }
}

closed_set! { as_db_str, from_db_str, array;
    /// ADR-0114 D-B: the relation between two symbols; Baseline §27 "Edge", verbatim and in that order.
    EdgeKind {
        /// The from symbol contains the definition of the to symbol.
        Defines => "DEFINES",
        /// The from symbol mentions the target by name.
        References => "REFERENCES",
        /// The from symbol calls the target.
        Calls => "CALLS",
        /// The from symbol imports the target.
        Imports => "IMPORTS",
        /// The from symbol implements the target interface or trait.
        Implements => "IMPLEMENTS",
        /// The from symbol inherits from the target.
        Inherits => "INHERITS",
    }
}

closed_set! { as_db_str, from_db_str, array;
    /// ADR-0114 D-B/D-E: how an edge was established. v1 extraction emits only `syntax_candidate`.
    EvidenceLevel {
        /// Name match on the syntax tree; may be wrong.
        SyntaxCandidate => "syntax_candidate",
        /// Resolved by a semantic index (client SCIP upload).
        SemanticResolved => "semantic_resolved",
        /// Observed at run time (trace upload).
        RuntimeObserved => "runtime_observed",
    }
}

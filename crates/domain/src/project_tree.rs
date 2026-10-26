//! `domain::project_tree` — M18 hierarchy and attribute vocabulary, without IO.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: [adapters::coord_tree_repo, tests]
//! Invariants: [§78.2 each closed set equals its 0281 CHECK; facets never create another parent]
//! Spec: Baseline §30; §78.2; ADR-0101 D-A; ADR-0101 D-C

closed_set! { as_db_str, from_db_str, array;
    /// ADR-0101 D-A: the registry hierarchy kinds.
    ProjectKind {
        /// A business line root or sub-project.
        BusinessLine => "BUSINESS_LINE",
        /// A project with its own lifecycle.
        Project => "PROJECT",
        /// A module within a project.
        Module => "MODULE",
    }
}

closed_set! { as_db_str, from_db_str, array;
    /// ADR-0101 D-C: orthogonal attributes, never parents.
    ProjectFacetKind {
        /// M14's existing channel assignment.
        Channel => "CHANNEL",
        /// A platform attribute.
        Platform => "PLATFORM",
    }
}

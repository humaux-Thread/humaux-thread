//! `domain::applicability` — closed applicability vocabulary; no visibility authority.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: [adapters::applicability_repo, tests]
//! Invariants: [the crate-root closed_set macro generates each enum, ALL and wire labels; DB CHECK lists equal these closed sets; absence of a row means project-local]
//! Spec: Baseline §6.1.1; §78.2; ADR-0096 D-A/D-B.1

closed_set! { wire, parse_wire, array;
    /// ADR-0096 D-A: where a memory may apply, independently of who may read it.
    ApplicabilityScope {
        /// One product or brand.
        ProductSpecific => "PRODUCT_SPECIFIC",
        /// Any project on the named channel.
        ChannelGeneric => "CHANNEL_GENERIC",
        /// Any project subject to qualifiers.
        Universal => "UNIVERSAL",
    }
}

closed_set! { wire, parse_wire, array;
    /// ADR-0096 D-B: only a decision door can leave the proposed state.
    ApplicabilityStatus {
        /// Candidate only; grants no reuse eligibility.
        Proposed => "PROPOSED",
        /// Explicitly approved with decision Evidence.
        Approved => "APPROVED",
        /// Explicitly rejected with decision Evidence.
        Rejected => "REJECTED",
    }
}

closed_set! { wire, parse_wire, array;
    /// ADR-0096 D-B.1: recorded provenance, never a caller authentication claim.
    AssignmentMethod {
        /// Reserved for M14-5b; refused until trusted console binding exists.
        OwnerConsole => "OWNER_CONSOLE",
        /// Relayed owner instruction, labelled 由聊天授权.
        AgentOnOwnerChat => "AGENT_ON_OWNER_CHAT",
    }
}

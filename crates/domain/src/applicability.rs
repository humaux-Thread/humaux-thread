//! `domain::applicability` — closed applicability vocabulary; no visibility authority.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: [adapters::applicability_repo, tests]
//! Invariants: [DB CHECK lists equal these closed sets; absence of a row means project-local]
//! Spec: Baseline §6.1.1; §78.2; ADR-0096 D-A/D-B.1

/// §78.2: enum, complete set and wire labels share one declaration (attribution closed-set pattern).
macro_rules! closed_set {
    ($(#[$meta:meta])* $name:ident { $($(#[$vmeta:meta])* $variant:ident => $wire:literal,)+ }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $($(#[$vmeta])* $variant,)+
        }
        impl $name {
            /// Every variant in declaration order (§78.2).
            pub const ALL: [Self; [$(stringify!($variant)),+].len()] = [$(Self::$variant,)+];

            /// Stable DB CHECK label (§78.2).
            #[must_use]
            pub const fn wire(self) -> &'static str {
                match self { $(Self::$variant => $wire,)+ }
            }

            /// Unknown values never widen applicability (§78.2).
            #[must_use]
            pub fn parse_wire(value: &str) -> Option<Self> {
                Self::ALL.into_iter().find(|item| item.wire() == value)
            }
        }
    };
}

closed_set! {
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

closed_set! {
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

closed_set! {
    /// ADR-0096 D-B.1: recorded provenance, never a caller authentication claim.
    AssignmentMethod {
        /// Reserved for M14-5b; refused until trusted console binding exists.
        OwnerConsole => "OWNER_CONSOLE",
        /// Relayed owner instruction, labelled 由聊天授权.
        AgentOnOwnerChat => "AGENT_ON_OWNER_CHAT",
    }
}

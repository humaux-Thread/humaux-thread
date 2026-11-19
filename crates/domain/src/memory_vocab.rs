//! `domain::memory_vocab` — shared memory, authority, and note classifications and note byte limits.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: []
//! Invariants: [§78.2 closed sets preserve their database and wire labels]
//! Spec: Baseline §8.5; §10; §59; §78.2; ADR-0067; ADR-0124; ADR-0130

/// Memory's fixed classification, a closed set of exactly 12 variants (§8.5, Rust shape §59).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    /// A stated fact (§8.5).
    Fact,
    /// A stated preference (§8.5).
    Preference,
    /// A recorded decision (§8.5).
    Decision,
    /// A rejected option or approach (§8.5).
    Rejection,
    /// Current state of something (§8.5).
    State,
    /// A known issue (§8.5).
    Issue,
    /// A lesson learned (§8.5).
    Lesson,
    /// A constraint that must hold (§8.5).
    Constraint,
    /// Retrievable procedural knowledge; does not guarantee the Agent auto-executes it (§8.5).
    Procedure,
    /// Action -> Result -> Validation; high-value knowledge for coding/agent continuity (§8.5).
    Outcome,
    /// A reference pointer to external material (§8.5).
    Reference,
    /// A free-form note (§8.5).
    Note,
}

impl MemoryType {
    /// Every variant, in §8.5's declaration order. Closed set of 12.
    pub const ALL: [Self; 12] = [
        Self::Fact,
        Self::Preference,
        Self::Decision,
        Self::Rejection,
        Self::State,
        Self::Issue,
        Self::Lesson,
        Self::Constraint,
        Self::Procedure,
        Self::Outcome,
        Self::Reference,
        Self::Note,
    ];

    /// The DB wire label (`private.memory_records.memory_type`, migration 0004's CHECK set).
    ///
    // ponytail: three adapter-side copies of this mapping predate it
    // (`adapters::qdrant`, `adapters::distill_repo`, `adapters::projection_worker`); they are
    // outside card 22b's allowed files. Collapse them onto this one when a card owns them —
    // the §78.2 contract test below now pins THIS list against the live CHECK, so a drift in
    // the domain copy is a red gate rather than a silent disagreement.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Fact => "FACT",
            Self::Preference => "PREFERENCE",
            Self::Decision => "DECISION",
            Self::Rejection => "REJECTION",
            Self::State => "STATE",
            Self::Issue => "ISSUE",
            Self::Lesson => "LESSON",
            Self::Constraint => "CONSTRAINT",
            Self::Procedure => "PROCEDURE",
            Self::Outcome => "OUTCOME",
            Self::Reference => "REFERENCE",
            Self::Note => "NOTE",
        }
    }

    /// Inverse of [`MemoryType::wire`]; `None` for a label outside the closed set.
    #[must_use]
    pub fn parse_wire(wire: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.wire() == wire)
    }
}

/// Typed expression of §10's priority chain, a closed set of 7 variants (§59).
///
/// The discriminant *is* the priority — larger outranks smaller, mapping item-for-item onto
/// §10's priority chain (§59.1 I1, first tier of the adjudication total order). No
/// `#[non_exhaustive]`, no `Other`/`Unknown`/`Custom(String)` (§59 frozen).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthorityClass {
    /// General public knowledge, no personal or project context (§10, lowest priority).
    PublicKnowledge = 0,
    /// Private knowledge specific to this tenant/user (§10).
    PrivateKnowledge = 1,
    /// A stated user preference (§10).
    UserPreference = 2,
    /// A recorded project decision (§10).
    ProjectDecision = 3,
    /// The user explicitly correcting prior output (§10).
    UserCorrection = 4,
    /// A project-level constraint that must hold (§10).
    ProjectConstraint = 5,
    /// Context explicitly supplied for the current task (§10, highest priority).
    ExplicitTaskContext = 6,
}

/// Authority lifecycle state, a closed set of 4 variants (§59).
///
/// A non-`Active` row does not participate in adjudication (§59.1 I3), but still counts
/// toward §23's `visible` and `done` as usual — completeness measures "what you cannot see",
/// not "which row won adjudication"; the two must never be conflated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityStatus {
    /// Currently in force and eligible for adjudication (§59).
    Active,
    /// Replaced by a newer Authority row; kept for history (§59).
    Superseded,
    /// Explicitly withdrawn (§59).
    Revoked,
    /// Past its validity window (§59).
    Expired,
}

/// ADR-0067 D-E: the decoded body limit, counted in UTF-8 bytes (the wire schema counts code points, which is weaker).
pub const MAX_BODY_BYTES: usize = 65_536;
/// ADR-0067 D-E: the explicit title limit, in UTF-8 bytes.
pub const MAX_TITLE_BYTES: usize = 1024;

/// ADR-0067 D-D, amended by ADR-0124: the author's classification of a note, a closed set of twelve. It certifies no
/// truth and decides no authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteKind {
    /// A rejected option (`REJECTION`).
    Rejected,
    /// A decision (`DECISION`).
    Decision,
    /// The record of an implemented fix, its result (`OUTCOME`).
    Fix,
    /// A known problem (`ISSUE`).
    Problem,
    /// A lesson (`LESSON`).
    Lesson,
    /// A research finding (`NOTE`; counted apart from `Note` by `note_kind`).
    Research,
    /// A preference (`PREFERENCE`).
    Preference,
    /// A state record (`STATE`).
    State,
    /// A free-form note (`NOTE`).
    Note,
    /// A fact about something that happened, such as an email, a chat message or a calendar entry (`NOTE`; ADR-0124 D-A).
    Event,
    /// A commitment (`NOTE`; ADR-0124 D-A). Reminders are not this kind's job (M14/M22).
    Plan,
    /// One attempt at something and how it went (`NOTE`; ADR-0124 D-A). Its tables land with M07-8.
    Episode,
}

impl NoteKind {
    /// Every kind: ADR-0067 D-D table order, then the three ADR-0124 kinds.
    pub const ALL: [Self; 12] = [
        Self::Rejected,
        Self::Decision,
        Self::Fix,
        Self::Problem,
        Self::Lesson,
        Self::Research,
        Self::Preference,
        Self::State,
        Self::Note,
        Self::Event,
        Self::Plan,
        Self::Episode,
    ];

    /// Wire and DB label (`private.memory_records.note_kind`, migration 0283's CHECK set).
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Rejected => "rejected",
            Self::Decision => "decision",
            Self::Fix => "fix",
            Self::Problem => "problem",
            Self::Lesson => "lesson",
            Self::Research => "research",
            Self::Preference => "preference",
            Self::State => "state",
            Self::Note => "note",
            Self::Event => "event",
            Self::Plan => "plan",
            Self::Episode => "episode",
        }
    }

    /// Inverse of [`NoteKind::wire`]; `None` outside the closed set.
    #[must_use]
    pub fn parse_wire(wire: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.wire() == wire)
    }

    /// The `memory_type` this kind is stored under (ADR-0067 D-D table, ADR-0124 D-A; the DB CHECK binds the same pairs).
    #[must_use]
    pub const fn memory_type(self) -> MemoryType {
        match self {
            Self::Rejected => MemoryType::Rejection,
            Self::Decision => MemoryType::Decision,
            Self::Fix => MemoryType::Outcome,
            Self::Problem => MemoryType::Issue,
            Self::Lesson => MemoryType::Lesson,
            Self::Research | Self::Note | Self::Event | Self::Plan | Self::Episode => {
                MemoryType::Note
            }
            Self::Preference => MemoryType::Preference,
            Self::State => MemoryType::State,
        }
    }
}

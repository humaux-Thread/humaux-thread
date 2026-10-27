//! `domain::note` — the verbatim note lane's pure rules: `NoteKind`, the verbatim body and its digest, the title,
//!   and the authority decision of `memory.note_put` (ADR-0067 D-C/D-D/D-E).
//! Depends-on: crates=[sha2, uuid]; services=[]; env=[]; modules=[domain::authority, domain::error, domain::evidence, domain::memory, domain::policy]
//! Called-by: [adapters::memory_repo, adapters::note_repo, adapters::operation_receipt, adapters::read_gate, adapters::read_materialize, gateway::mcp_application, humaux-local-secret-scan, tests]
//! Invariants: [NoteKind is a closed 12-value set whose memory_type mapping is the DB CHECK of migration 0283 (nine kinds
//!   of 0235 plus event, plan, episode; ADR-0124); the body is never trimmed, normalised or re-encoded; authority is
//!   decided by the existing ceiling table and never inferred from note_kind, title or body]
//! Spec: Baseline §8.5; §9; §10.1; ADR-0067; ADR-0124
//!
//! Pure data and decisions only: the one SQL statement lives in `adapters::memory_repo::insert_memory_in_txn`, the one
//! transaction in `adapters::operation_receipt`. A reconciliation test in `adapters` pins [`NoteKind`] against the
//! live `memory_records_note_kind_*` CHECKs and the generated `facet` (§78.2, ADR-0067 G09).

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::authority::{AuthorityClass, CandidateRejection, NonEmptyVec};
use crate::error::ErrorCode;
use crate::evidence::EvidenceOriginClass;
use crate::memory::MemoryType;
use crate::policy::StoredAuthority;

/// ADR-0067 D-E: the decoded body limit, counted in UTF-8 bytes (the wire schema counts code points, which is weaker).
pub const MAX_BODY_BYTES: usize = 65_536;
/// ADR-0067 D-E: the explicit title limit, in UTF-8 bytes.
pub const MAX_TITLE_BYTES: usize = 1024;
/// ADR-0067 D-E: a derived title is cut to this many Unicode scalars.
pub const DERIVED_TITLE_SCALARS: usize = 80;
/// ADR-0067 D-E: the title of an all-blank body.
pub const DEFAULT_TITLE: &str = "Untitled note";
/// ADR-0067 D-F: `content.representation` of an identity note. Set only by `memory.note_put`, never by a caller.
pub const REPRESENTATION: &str = "verbatim_assertion";
/// ADR-0067 D-B: the only identity-contract strategy.
pub const STRATEGY_IDENTITY_NOTE_V1: &str = "identity_note_v1";
/// ADR-0067 D-B: `policy_version` of the contract row — the authority rule that granted the stored class (the §10.1
/// origin-ceiling table, read by [`authorize_note`]).
pub const POLICY_VERSION: &str = "origin_ceiling_v1";

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

/// `memory.note_put.requested_authority` wire forms, in `AuthorityClass` order. Verbatim `AuthorityClass` variant names,
/// the same spelling as `private.memory_records.authority_class`.
const AUTHORITY_WIRE: [(&str, AuthorityClass); 7] = [
    ("PublicKnowledge", AuthorityClass::PublicKnowledge),
    ("PrivateKnowledge", AuthorityClass::PrivateKnowledge),
    ("UserPreference", AuthorityClass::UserPreference),
    ("ProjectDecision", AuthorityClass::ProjectDecision),
    ("UserCorrection", AuthorityClass::UserCorrection),
    ("ProjectConstraint", AuthorityClass::ProjectConstraint),
    ("ExplicitTaskContext", AuthorityClass::ExplicitTaskContext),
];

/// Every `requested_authority` wire form with its class (ADR-0067 D-C: a closed enum).
#[must_use]
pub const fn requested_authority_wire() -> &'static [(&'static str, AuthorityClass); 7] {
    &AUTHORITY_WIRE
}

/// Parses a `requested_authority` wire form; `None` outside the closed set.
#[must_use]
pub fn parse_requested_authority(wire: &str) -> Option<AuthorityClass> {
    AUTHORITY_WIRE
        .iter()
        .find(|(name, _)| *name == wire)
        .map(|(_, class)| *class)
}

/// ADR-0067 D-C: the class `memory.note_put` stores when `requested_authority` is absent.
pub const DEFAULT_AUTHORITY: AuthorityClass = AuthorityClass::PrivateKnowledge;

/// ADR-0067 D-C: grants exactly `requested` for the server-fixed origin `AuthenticatedAgent`, or refuses. No clamp, no
/// inference from the kind, title or body; the kind only selects the `memory_type` the §10.1 ceiling table is read at.
///
/// # Errors
/// The refusal [`StoredAuthority::authorize`] returns when `requested` exceeds the origin's ceiling (or is
/// `ExplicitTaskContext`).
pub fn authorize_note(
    kind: NoteKind,
    requested: AuthorityClass,
) -> Result<AuthorityClass, CandidateRejection> {
    let basis = NonEmptyVec::new(vec![EvidenceOriginClass::AuthenticatedAgent])
        .expect("one-element basis is non-empty");
    StoredAuthority::authorize(requested, kind.memory_type(), basis).map(|granted| granted.0)
}

/// ADR-0067 D-E: a validated verbatim body and its digest, `SHA-256(UTF-8 bytes of the decoded body)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteBody {
    text: String,
    sha256: [u8; 32],
}

impl NoteBody {
    /// Validates at the input edge: `U+0000` (which jsonb refuses) and more than [`MAX_BODY_BYTES`] bytes are refused,
    /// never repaired. The text is kept exactly as given: no trim, no newline or Unicode normalisation.
    ///
    /// # Errors
    /// [`ErrorCode::InvalidInput`] for an empty, NUL-carrying or oversize body.
    pub fn new(text: &str) -> Result<Self, ErrorCode> {
        if text.is_empty() || text.len() > MAX_BODY_BYTES || text.contains('\0') {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self {
            text: text.to_owned(),
            sha256: Sha256::digest(text.as_bytes()).into(),
        })
    }

    /// The body, byte for byte as the caller sent it.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// `SHA-256` of [`NoteBody::text`]'s UTF-8 bytes.
    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

/// ADR-0067 D-J: the domain separator of the replacement intent digest [`replace_intent_sha256`].
pub const REPLACE_INTENT_DOMAIN: &[u8] = b"memory.note_put.replace/v1";

/// ADR-0067 D-J: `H`, the digest one replacement's confirm token (`control.confirm_tokens.request_sha256`) and its
/// commit receipt (`request_fingerprint` = hex `H`) both bind. SHA-256 over the domain separator and then note_id,
/// supersedes, note_kind, title, the body digest, requested_authority and idempotency_key, in that fixed order, each
/// as a big-endian `u64` byte length followed by the bytes — so no two field splits share an encoding, and a 40a create
/// fingerprint (SHA-256 of raw argument bytes) never equals it.
#[must_use]
pub fn replace_intent_sha256(
    note_id: Uuid,
    supersedes: Uuid,
    kind: NoteKind,
    title: &str,
    body: &NoteBody,
    requested: AuthorityClass,
    idempotency_key: &str,
) -> [u8; 32] {
    let authority = AUTHORITY_WIRE
        .iter()
        .find(|(_, class)| *class == requested)
        .map_or("", |(wire, _)| *wire);
    let fields: [&[u8]; 8] = [
        REPLACE_INTENT_DOMAIN,
        note_id.as_bytes(),
        supersedes.as_bytes(),
        kind.wire().as_bytes(),
        title.as_bytes(),
        body.sha256(),
        authority.as_bytes(),
        idempotency_key.as_bytes(),
    ];
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

/// ADR-0067 D-E: the stored title. An explicit title is kept verbatim (at most [`MAX_TITLE_BYTES`], no NUL); otherwise
/// the first non-blank line, trimmed and cut to [`DERIVED_TITLE_SCALARS`] scalars; an all-blank body gets
/// [`DEFAULT_TITLE`]. The title never edits the body.
///
/// # Errors
/// [`ErrorCode::InvalidInput`] for an empty, oversize or NUL-carrying explicit title.
pub fn note_title(explicit: Option<&str>, body: &NoteBody) -> Result<String, ErrorCode> {
    if let Some(title) = explicit {
        if title.is_empty() || title.len() > MAX_TITLE_BYTES || title.contains('\0') {
            return Err(ErrorCode::InvalidInput);
        }
        return Ok(title.to_owned());
    }
    Ok(body
        .text()
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map_or_else(
            || DEFAULT_TITLE.to_owned(),
            |line| line.chars().take(DERIVED_TITLE_SCALARS).collect(),
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// How many variants `pub enum NoteKind` declares, counted from this file's own source, so a variant added to the enum
    /// but not to `NoteKind::ALL` changes the count and fails the test that uses it.
    fn declared_note_kinds() -> usize {
        let head = "pub enum NoteKind {\n";
        let src = include_str!("note.rs");
        let body = &src[src.find(head).expect("enum declaration") + head.len()..];
        body[..body.find("\n}").expect("end of enum")]
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with("//") && line.ends_with(','))
            .count()
    }

    #[test]
    fn note_kind_all_lists_every_variant_once() {
        assert_eq!(NoteKind::ALL.len(), 12);
        assert_eq!(
            NoteKind::ALL.len(),
            declared_note_kinds(),
            "a declared variant is missing from NoteKind::ALL"
        );
        let wires: std::collections::BTreeSet<&str> =
            NoteKind::ALL.into_iter().map(NoteKind::wire).collect();
        assert_eq!(wires.len(), NoteKind::ALL.len(), "a kind is listed twice");
    }

    #[test]
    fn note_kind_wire_round_trips_and_the_set_is_twelve() {
        assert_eq!(NoteKind::ALL.len(), 12);
        for kind in NoteKind::ALL {
            assert_eq!(NoteKind::parse_wire(kind.wire()), Some(kind));
        }
        assert_eq!(NoteKind::parse_wire("claim"), None);
        assert_eq!(NoteKind::parse_wire("Fix"), None);
    }

    #[test]
    fn research_and_note_share_a_memory_type_but_not_a_kind() {
        assert_eq!(NoteKind::Research.memory_type(), MemoryType::Note);
        assert_eq!(NoteKind::Note.memory_type(), MemoryType::Note);
        assert_ne!(NoteKind::Research.wire(), NoteKind::Note.wire());
    }

    #[test]
    fn the_adr_0124_kinds_are_notes_with_their_own_labels() {
        for (kind, wire) in [
            (NoteKind::Event, "event"),
            (NoteKind::Plan, "plan"),
            (NoteKind::Episode, "episode"),
        ] {
            assert_eq!(kind.wire(), wire);
            assert_eq!(kind.memory_type(), MemoryType::Note);
            assert_eq!(NoteKind::parse_wire(wire), Some(kind));
        }
    }

    #[test]
    fn authority_is_exact_or_refused_never_clamped() {
        for kind in NoteKind::ALL {
            assert_eq!(
                authorize_note(kind, AuthorityClass::PrivateKnowledge),
                Ok(AuthorityClass::PrivateKnowledge)
            );
            assert_eq!(
                authorize_note(kind, AuthorityClass::PublicKnowledge),
                Ok(AuthorityClass::PublicKnowledge)
            );
            for above in [
                AuthorityClass::UserPreference,
                AuthorityClass::ProjectDecision,
                AuthorityClass::UserCorrection,
                AuthorityClass::ProjectConstraint,
                AuthorityClass::ExplicitTaskContext,
            ] {
                assert_eq!(
                    authorize_note(kind, above),
                    Err(CandidateRejection::OriginAuthorityCeiling)
                );
            }
        }
    }

    #[test]
    fn requested_authority_wire_covers_every_class() {
        assert_eq!(AUTHORITY_WIRE.len(), 7);
        for (wire, class) in AUTHORITY_WIRE {
            assert_eq!(parse_requested_authority(wire), Some(class));
        }
        assert_eq!(parse_requested_authority("privateknowledge"), None);
    }

    #[test]
    fn body_is_verbatim_and_refuses_nul_empty_and_oversize() {
        let raw = "  a\r\n\u{65}\u{301} \u{1F600} \"q\" \\ \n";
        let body = NoteBody::new(raw).unwrap();
        assert_eq!(body.text(), raw);
        assert_eq!(
            body.sha256().as_slice(),
            Sha256::digest(raw.as_bytes()).as_slice()
        );
        assert_eq!(NoteBody::new("a\0b"), Err(ErrorCode::InvalidInput));
        assert_eq!(NoteBody::new(""), Err(ErrorCode::InvalidInput));
        assert!(NoteBody::new(&"a".repeat(MAX_BODY_BYTES)).is_ok());
        assert_eq!(
            NoteBody::new(&"a".repeat(MAX_BODY_BYTES + 1)),
            Err(ErrorCode::InvalidInput)
        );
        // The limit counts UTF-8 bytes, not scalars.
        assert_eq!(
            NoteBody::new(&"\u{4e2d}".repeat(MAX_BODY_BYTES / 3 + 1)),
            Err(ErrorCode::InvalidInput)
        );
    }

    #[test]
    fn precomposed_and_decomposed_forms_digest_differently() {
        let composed = NoteBody::new("\u{e9}").unwrap();
        let decomposed = NoteBody::new("e\u{301}").unwrap();
        assert_ne!(composed.sha256(), decomposed.sha256());
        assert_eq!(composed.sha256(), NoteBody::new("\u{e9}").unwrap().sha256());
    }

    /// ADR-0067 D-J: `H` is a pure function of the seven intent fields, each of which moves it, and it is not the
    /// body digest. Mutation: drop any field from `fields` and the matching `assert_ne!` goes red.
    #[test]
    fn replace_intent_is_deterministic_and_binds_every_field() {
        let body = NoteBody::new("the body").unwrap();
        let edited = NoteBody::new("the body!").unwrap();
        let (note, head) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let other = Uuid::from_u128(3);
        let pk = AuthorityClass::PrivateKnowledge;
        let base = replace_intent_sha256(note, head, NoteKind::Decision, "t", &body, pk, "k");
        assert_eq!(
            base,
            replace_intent_sha256(note, head, NoteKind::Decision, "t", &body, pk, "k")
        );
        let changed = [
            replace_intent_sha256(other, head, NoteKind::Decision, "t", &body, pk, "k"),
            replace_intent_sha256(note, other, NoteKind::Decision, "t", &body, pk, "k"),
            replace_intent_sha256(head, note, NoteKind::Decision, "t", &body, pk, "k"),
            replace_intent_sha256(note, head, NoteKind::Lesson, "t", &body, pk, "k"),
            replace_intent_sha256(note, head, NoteKind::Decision, "u", &body, pk, "k"),
            replace_intent_sha256(note, head, NoteKind::Decision, "t", &edited, pk, "k"),
            replace_intent_sha256(
                note,
                head,
                NoteKind::Decision,
                "t",
                &body,
                AuthorityClass::PublicKnowledge,
                "k",
            ),
            replace_intent_sha256(note, head, NoteKind::Decision, "t", &body, pk, "k2"),
        ];
        for (n, digest) in changed.iter().enumerate() {
            assert_ne!(*digest, base, "field change {n} must move H");
        }
        // Known answer (computed independently from the documented encoding: each field as a big-endian u64 length + its
        // bytes, in this order). Dropping a length prefix, reordering fields or changing the separator turns this red.
        assert_eq!(
            base.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "ce91372c9216faaf95b6575e5e13fd72a2065fc667c73c7ded163fa44d211006"
        );
        assert_ne!(&base, body.sha256(), "H is not the plain body digest");
        let mut plain = Sha256::new();
        plain.update(REPLACE_INTENT_DOMAIN);
        assert_ne!(
            base.as_slice(),
            plain.finalize().as_slice(),
            "H is length-prefixed, not the bare separator"
        );
    }

    #[test]
    fn title_is_explicit_or_first_non_blank_line_or_default() {
        let body = NoteBody::new("\n  \n  First line  \nsecond").unwrap();
        assert_eq!(note_title(None, &body).unwrap(), "First line");
        assert_eq!(note_title(Some("Given"), &body).unwrap(), "Given");
        assert_eq!(note_title(Some(""), &body), Err(ErrorCode::InvalidInput));
        assert_eq!(
            note_title(Some(&"t".repeat(MAX_TITLE_BYTES + 1)), &body),
            Err(ErrorCode::InvalidInput)
        );
        let long = NoteBody::new(&"\u{4e2d}".repeat(200)).unwrap();
        assert_eq!(
            note_title(None, &long).unwrap().chars().count(),
            DERIVED_TITLE_SCALARS
        );
        let blank = NoteBody::new(" \n\t ").unwrap();
        assert_eq!(note_title(None, &blank).unwrap(), DEFAULT_TITLE);
    }
}

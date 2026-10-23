//! `projection::note_chunks` — ADR-0068 D-A/D-B/D-I: the frozen `NoteChunksV1` profile (fixed Unicode-scalar windows
//!   over a long note's body), the projection's [`NoteChunkPolicy`], and [`build_projection_plan`], the one entry that
//!   picks a chunk profile or the unchanged legacy card.
//! Depends-on: crates=[humaux-domain, sha2]; services=[]; env=[]; modules=[domain::dataclass, projection::card]
//! Called-by: [adapters::private_projection_registry, adapters::projection_worker, adapters::rebuild, adapters::retrieve, gateway::recall, tests]
//! Invariants: [pure and IO-free (§3/§78.3); chunk card text is constructed only here, SQL recomputes only the count
//!   and the legacy predicate (ADR-0068 D-B); ranges are half-open over Unicode scalars and a slice never splits a
//!   UTF-8 sequence; only an identity note that is not SECRET_MATERIAL, whose projection policy is NoteChunksV1 and
//!   whose non-empty body the legacy card cannot hold losslessly is chunked, every other input yields exactly
//!   build_card's outcome (ADR-0068 D-A); a policy hash this build does not know is refused, never read as legacy
//!   (ADR-0068 D-I); the document a reranker scores for a point is built here from the point's registry slot, as
//!   the card text that was embedded (ADR-0084 D-C 3)]
//! Spec: Baseline §18.2; §3; §78.3; ADR-0068; ADR-0084 D-C
//!
//! The projection worker builds through [`build_projection_plan`]; rebuild's verifier still calls `build_card` (40d-1b-iii).
//! The window parameters are a frozen,
//! versioned profile (ADR-0068 D-B), not runtime config (§78.1): changing any of them is a new profile with a new
//! [`NOTE_CHUNKS_V1_PROFILE_HASH`]. Its SQL twins are `projection.note_chunk_count` (migration 0237) and
//! `projection.note_legacy_capacity_holds` (migration 0238), pinned to [`chunk_count`] / [`legacy_capacity_holds`]
//! by `adapters::tests::note_chunk_count_parity`. A slot is legacy iff [`legacy_capacity_holds`] holds (or the Memory
//! is not a note, or the policy is legacy only), never because its count is 1: a note whose body fits one window but
//! not the legacy card is one `NoteChunksV1` slot.

use std::ops::Range;

use humaux_domain::dataclass::DataClass;

use crate::card::{
    CARD_BUILDER_VERSION, CARD_TEMPLATE_HASH, CardBudget, CardBuildOutcome, CardInput, CardStatus,
    RetrievalCard, build_card,
};

/// ADR-0068 D-B: window W, in body scalars.
pub const NOTE_CHUNKS_V1_WINDOW: usize = 480;
/// ADR-0068 D-B: scalars shared by adjacent windows.
pub const NOTE_CHUNKS_V1_OVERLAP: usize = 64;
/// ADR-0068 D-B: start-to-start distance, W − overlap.
pub const NOTE_CHUNKS_V1_STRIDE: usize = NOTE_CHUNKS_V1_WINDOW - NOTE_CHUNKS_V1_OVERLAP;
/// ADR-0068 D-B: scalars of the title carried by each chunk card; prefix + separator + W = the 600-scalar legacy
/// budget, so a chunk card is never longer than a legacy card.
pub const NOTE_CHUNKS_V1_TITLE_PREFIX: usize = 119;
/// ADR-0068 D-B: between the title prefix and the body window.
pub const NOTE_CHUNKS_V1_SEPARATOR: &str = "\n";
/// ADR-0068 D-A: separators the legacy template emits for a note — `assemble` writes all three `\n` even with no
/// entities, and `fit_budget` drops the evidence placeholder whole before it cuts the body, so a note's body survives
/// the legacy card exactly when title + 3 + body fits the budget.
pub const LEGACY_NOTE_SEPARATORS: usize = 3;

/// ADR-0068 D-C: `card_profile_hash` of a legacy card — the registry column's default and its v1 point-id marker
/// (migration 0238). Not a SHA-256: no profile hash can equal it.
pub const LEGACY_CARD_PROFILE_HASH: &str = "LegacyCardV1";

/// `card_profile_hash` of `NoteChunksV1`: `NoteChunksV1-` + SHA-256 hex over the parameter tuple and the
/// length-prefixed chunk texts of a fixed golden note. Recomputed by `tests::profile_hash_is_pinned`; a changed
/// parameter, separator or prefix rule turns that test red until a new profile is minted. Not named like the legacy
/// template constants on purpose: `xtask card-version` pairs those by name (§18.4).
pub const NOTE_CHUNKS_V1_PROFILE_HASH: &str =
    "NoteChunksV1-6cef9eb0e1cc9219c9739a76a12880fd8e4efe004639e51688922c5f596a334c";

/// ADR-0068 D-A: true iff the legacy card loses none of the note's body: the body is empty (nothing to lose;
/// `build_card` marks a bodiless note unbuildable), or `title + LEGACY_NOTE_SEPARATORS + body <=
/// CardBudget::default().max_chars`, counted in Unicode scalars. SQL twin: `projection.note_legacy_capacity_holds`,
/// which is STRICT — a NULL body yields NULL there, so a SQL caller coalesces it to true: a Memory with no body takes
/// the legacy branch here too (`build_projection_plan` with `key_claim: None`).
pub fn legacy_capacity_holds(title: &str, body: &str) -> bool {
    body.is_empty()
        || title.chars().count() + LEGACY_NOTE_SEPARATORS + body.chars().count()
            <= CardBudget::default().max_chars
}

/// ADR-0068 D-B: `C(L) = 1 + ceil(max(0, L − W) / stride)` for a body of `body_chars` scalars.
pub fn chunk_count(body_chars: usize) -> usize {
    1 + body_chars
        .saturating_sub(NOTE_CHUNKS_V1_WINDOW)
        .div_ceil(NOTE_CHUNKS_V1_STRIDE)
}

/// ADR-0068 D-B: the half-open scalar ranges of `body`'s chunks, ordinal = index. An empty body has one empty range.
pub fn chunk_ranges(body: &str) -> Vec<Range<usize>> {
    ranges(body.chars().count())
}

fn ranges(len: usize) -> Vec<Range<usize>> {
    (0..chunk_count(len))
        .map(|ordinal| {
            let start = ordinal * NOTE_CHUNKS_V1_STRIDE;
            start..len.min(start + NOTE_CHUNKS_V1_WINDOW)
        })
        .collect()
}

/// `s[range]` with `range` in Unicode scalars; `None` when the range is reversed or past the end. Slices only at
/// scalar boundaries, so it never splits a UTF-8 sequence.
pub fn scalar_slice(s: &str, range: Range<usize>) -> Option<&str> {
    slice_at(s, &scalar_boundaries(s), range)
}

/// Byte offset of every scalar boundary of `s`: `[0, …, s.len()]`.
fn scalar_boundaries(s: &str) -> Vec<usize> {
    s.char_indices()
        .map(|(byte, _)| byte)
        .chain(std::iter::once(s.len()))
        .collect()
}

/// `str::get` refuses a reversed range, so a reversed scalar range is `None` too.
fn slice_at<'a>(s: &'a str, boundaries: &[usize], range: Range<usize>) -> Option<&'a str> {
    s.get(*boundaries.get(range.start)?..*boundaries.get(range.end)?)
}

fn title_prefix(title: &str) -> &str {
    title
        .char_indices()
        .nth(NOTE_CHUNKS_V1_TITLE_PREFIX)
        .map_or(title, |(cut, _)| &title[..cut])
}

fn card_text(title: &str, window: &str) -> String {
    format!("{}{NOTE_CHUNKS_V1_SEPARATOR}{window}", title_prefix(title))
}

/// ADR-0068 D-B: the card text of chunk `ordinal` — title prefix + separator + `body[range]`, no trim, no
/// normalisation. `None` past the last chunk.
pub fn chunk_card_text(title: &str, body: &str, ordinal: usize) -> Option<String> {
    let range = chunk_ranges(body).into_iter().nth(ordinal)?;
    Some(card_text(title, scalar_slice(body, range)?))
}

/// ADR-0084 D-C 3: the card slot a registered point stands for, read from its registry row
/// (`projection.private_memory_points.card_profile_hash`, `chunk_ordinal`, ADR-0068 D-C). The registry is the identity;
/// a Qdrant payload is never read for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardSlot {
    /// [`LEGACY_CARD_PROFILE_HASH`]: the Memory's one point; the whole body is its text.
    Legacy,
    /// [`NOTE_CHUNKS_V1_PROFILE_HASH`] slot `ordinal` (0-based, [`chunk_ranges`] order).
    Chunk {
        /// The slot within the profile.
        ordinal: u32,
    },
}

impl CardSlot {
    /// Reads a registry row. `None` for a profile this build does not know and for an ordinal outside the profile's
    /// range (a legacy row is ordinal 0 only, 0238 CHECK): an unknown profile is refused, never read as legacy
    /// (ADR-0068 D-I).
    pub fn from_registry(card_profile_hash: &str, chunk_ordinal: i32) -> Option<Self> {
        match (card_profile_hash, u32::try_from(chunk_ordinal).ok()?) {
            (LEGACY_CARD_PROFILE_HASH, 0) => Some(Self::Legacy),
            (NOTE_CHUNKS_V1_PROFILE_HASH, ordinal) => Some(Self::Chunk { ordinal }),
            _ => None,
        }
    }
}

/// ADR-0084 D-C 3: the rerank document of a Memory whose best leg hit was the point of `slot`: title prefix +
/// separator + the text that point stands for. A chunk slot is [`chunk_card_text`] itself, so the document is
/// byte-for-byte the card text that was embedded; a legacy slot is the title prefix, the separator and the whole body
/// (the legacy card holds the body whole, [`legacy_capacity_holds`]). `None` when the slot lies past the body's last
/// chunk.
pub fn rerank_document(title: &str, body: &str, slot: CardSlot) -> Option<String> {
    match slot {
        CardSlot::Legacy => Some(card_text(title, body)),
        CardSlot::Chunk { ordinal } => chunk_card_text(title, body, usize::try_from(ordinal).ok()?),
    }
}

/// ADR-0068 D-I: which note chunk profile a projection builds, parsed once from
/// `projection.card_profile_policies.note_chunk_profile_hash` for the ticket family (a missing row reads as NULL).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteChunkPolicy {
    /// NULL: every Memory takes `LegacyCardV1` (today's behaviour).
    LegacyOnly,
    /// [`NOTE_CHUNKS_V1_PROFILE_HASH`]: identity notes over the legacy capacity are chunked.
    NoteChunksV1,
}

/// ADR-0068 D-I: a policy hash this build has no profile for. The worker refuses to boot on it: a silent legacy
/// fallback would build slots the ledger, which reads the same row, does not expect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownNoteChunkProfile(pub String);

impl NoteChunkPolicy {
    /// ADR-0068 D-I: `None` is legacy only; [`NOTE_CHUNKS_V1_PROFILE_HASH`] is `NoteChunksV1`; anything else is
    /// refused.
    pub fn from_profile_hash(hash: Option<&str>) -> Result<Self, UnknownNoteChunkProfile> {
        match hash {
            None => Ok(Self::LegacyOnly),
            Some(NOTE_CHUNKS_V1_PROFILE_HASH) => Ok(Self::NoteChunksV1),
            Some(other) => Err(UnknownNoteChunkProfile(other.to_owned())),
        }
    }
}

/// What [`build_projection_plan`] reads: the worker's `card_input`, whether the Memory has an identity contract
/// (`private.identity_note_materializations`) and the projection's policy. A note's body is `card.key_claim`
/// (ADR-0067 D-E).
#[derive(Debug, Clone)]
pub struct PlanInput {
    /// The legacy card input, unchanged.
    pub card: CardInput,
    /// ADR-0068 D-A: chunking is keyed on the identity contract, never on `memory_type`.
    pub is_identity_note: bool,
    /// ADR-0068 D-I: the projection's policy; [`NoteChunkPolicy::LegacyOnly`] keeps every Memory on the legacy card.
    pub policy: NoteChunkPolicy,
}

/// One `NoteChunksV1` point slot (ADR-0068 D-C identity: `card_profile_hash`, `chunk_ordinal`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteChunk {
    /// Always [`NOTE_CHUNKS_V1_PROFILE_HASH`].
    pub card_profile_hash: &'static str,
    /// From 0, in body order.
    pub chunk_ordinal: usize,
    /// Half-open, in body scalars.
    pub range: Range<usize>,
    /// The text to seal and embed.
    pub text: String,
}

/// ADR-0068 D-A: how one Memory is projected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionPlan {
    /// Profile `LegacyCardV1`: exactly `build_card`'s outcome; a card is the Memory's one slot, ordinal 0.
    LegacyCardV1(CardBuildOutcome),
    /// Profile `NoteChunksV1`: one entry per chunk, `chunk_count(body)` of them.
    NoteChunksV1(Vec<NoteChunk>),
}

/// ADR-0068 D-A: the single construction entry. `NoteChunksV1` only under a `NoteChunksV1` policy, for an identity
/// note that is not SECRET_MATERIAL (§18.2 excludes it before any chunking) and whose body the legacy card cannot hold
/// ([`legacy_capacity_holds`], so never an empty body); everything else is the unchanged `build_card` at the default
/// budget.
pub fn build_projection_plan(input: PlanInput) -> ProjectionPlan {
    let PlanInput {
        card,
        is_identity_note,
        policy,
    } = input;
    let chunked = policy == NoteChunkPolicy::NoteChunksV1
        && is_identity_note
        && card.data_class != DataClass::SecretMaterial
        && card
            .key_claim
            .as_deref()
            .is_some_and(|body| !legacy_capacity_holds(&card.title, body));
    if !chunked {
        return ProjectionPlan::LegacyCardV1(build_card(card, CardBudget::default()));
    }
    let body = card.key_claim.as_deref().unwrap_or_default();
    let boundaries = scalar_boundaries(body);
    let chunks = ranges(boundaries.len() - 1)
        .into_iter()
        .enumerate()
        .map(|(chunk_ordinal, range)| {
            let window = slice_at(body, &boundaries, range.clone()).expect(
                "ADR-0068 D-B: ranges() of the body's own scalar count stay inside its boundaries",
            );
            NoteChunk {
                card_profile_hash: NOTE_CHUNKS_V1_PROFILE_HASH,
                chunk_ordinal,
                text: card_text(&card.title, window),
                range,
            }
        })
        .collect();
    ProjectionPlan::NoteChunksV1(chunks)
}

/// ADR-0068 D-G: chunk `chunk` of the note `input` as the [`RetrievalCard`] the seal and the vector key read.
/// `card_text` is the chunk text (what is sealed, hashed into `input_sha256` and embedded); `memory_id`, `data_class`,
/// `egress_disposition` and the other §18.2 fields are the note's, so `seal_chunk_card` checks the same Memory and data
/// class; `title` is the full title (§18.3 never cuts the field; the card text carries the bounded prefix);
/// `key_claim` is the body window. `card_builder_version` / `card_template_hash` stay the legacy pair (§18.4 allows
/// one hash per builder version, and the fingerprint is per projection, ADR-0068 D-B): the profile is named by the
/// registry identity (`card_profile_hash`, `chunk_ordinal`), never by these fields.
pub fn chunk_card(input: &CardInput, chunk: &NoteChunk) -> RetrievalCard {
    let window = input
        .key_claim
        .as_deref()
        .and_then(|body| scalar_slice(body, chunk.range.clone()))
        .unwrap_or_default();
    RetrievalCard {
        schema_version: RetrievalCard::SCHEMA_VERSION,
        card_builder_version: CARD_BUILDER_VERSION,
        card_template_hash: CARD_TEMPLATE_HASH,
        memory_id: input.memory_id,
        memory_type: input.memory_type,
        data_class: input.data_class,
        egress_disposition: input.egress_disposition,
        workspace_id: input.workspace_id,
        topic: input.topic.clone(),
        effective_from: input.effective_from,
        title: input.title.clone(),
        key_claim: window.to_owned(),
        entities: Vec::new(),
        evidence_excerpt: String::new(),
        card_status: CardStatus::Complete,
        card_text: chunk.text.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use humaux_domain::authority::MemoryId;
    use humaux_domain::memory::MemoryType;

    use super::*;
    use crate::card::{self, EgressDisposition, template_fingerprint};

    fn note(title: &str, body: &str) -> PlanInput {
        PlanInput {
            card: CardInput {
                memory_id: MemoryId::new(),
                memory_type: MemoryType::Note,
                data_class: DataClass::Private,
                egress_disposition: EgressDisposition::Allowed,
                workspace_id: None,
                topic: None,
                effective_from: SystemTime::UNIX_EPOCH,
                title: title.to_owned(),
                key_claim: Some(body.to_owned()),
                entities: Vec::new(),
                evidence_excerpt: None,
            },
            is_identity_note: true,
            policy: NoteChunkPolicy::NoteChunksV1,
        }
    }

    fn chunks_of(input: PlanInput) -> Vec<NoteChunk> {
        match build_projection_plan(input) {
            ProjectionPlan::NoteChunksV1(chunks) => chunks,
            other => panic!("expected NoteChunksV1, got {other:?}"),
        }
    }

    /// ADR-0068 gate `chunk_ranges_cover_entire_body`. Fault: stride 417 (gap) or `start + W + 1` (overlap 65, a
    /// window past W) ⇒ red on the overlap / width assertion; `chunk_count` off by one ⇒ red on the end assertion.
    #[test]
    fn chunk_ranges_cover_entire_body() {
        for len in [0, 1, 479, 480, 481, 896, 897, 65_536] {
            let body = "a".repeat(len);
            let ranges = chunk_ranges(&body);
            assert_eq!(ranges.first().map(|r| r.start), Some(0), "L={len}");
            assert_eq!(ranges.last().map(|r| r.end), Some(len), "L={len}: tail");
            for r in &ranges {
                assert!(
                    (r.start..=len).contains(&r.end),
                    "L={len}: {r:?} out of bounds"
                );
                assert!(
                    r.end - r.start <= NOTE_CHUNKS_V1_WINDOW,
                    "L={len}: {r:?} wider than W"
                );
            }
            for pair in ranges.windows(2) {
                assert_eq!(
                    pair[0].end - pair[0].start,
                    NOTE_CHUNKS_V1_WINDOW,
                    "L={len}: short non-last {pair:?}"
                );
                assert_eq!(
                    pair[0].end - pair[1].start,
                    NOTE_CHUNKS_V1_OVERLAP,
                    "L={len}: overlap {pair:?}"
                );
            }
            let covered: usize = ranges.iter().map(|r| r.end - r.start).sum::<usize>()
                - NOTE_CHUNKS_V1_OVERLAP * (ranges.len() - 1);
            assert_eq!(covered, len, "L={len}: union");
        }
        assert_eq!(
            chunk_ranges(&"a".repeat(65_536)).len(),
            158,
            "ADR-0068 D-B: 64 KiB ASCII"
        );
    }

    /// Closed form vs the smallest n whose windows reach L. Fault: `div_ceil` → plain `/` ⇒ red at L = 481.
    #[test]
    fn chunk_count_matches_ranges() {
        for len in (0..=3_000).chain([65_535, 65_536]) {
            let smallest = (1_usize..)
                .find(|&n| (n - 1) * NOTE_CHUNKS_V1_STRIDE + NOTE_CHUNKS_V1_WINDOW >= len)
                .expect("some n reaches L");
            assert_eq!(chunk_count(len), smallest, "L={len}");
            assert_eq!(
                chunk_ranges(&"x".repeat(len)).len(),
                chunk_count(len),
                "L={len}"
            );
        }
    }

    /// ADR-0068 gate `note_budget_boundary_is_exact`, against the real legacy card, with a CJK title so bytes ≠
    /// scalars. Fault: `LEGACY_NOTE_SEPARATORS = 2`, or `<` for `<=`, or counting `len()` bytes ⇒ red.
    #[test]
    fn note_budget_boundary_is_exact() {
        let title = "題".repeat(20);
        let at = CardBudget::default().max_chars - LEGACY_NOTE_SEPARATORS - 20;
        for (body_len, holds) in [(at - 1, true), (at, true), (at + 1, false)] {
            let body = "長".repeat(body_len);
            assert_eq!(
                legacy_capacity_holds(&title, &body),
                holds,
                "body {body_len}"
            );
            let mut legacy = note(&title, &body);
            legacy.is_identity_note = false;
            let ProjectionPlan::LegacyCardV1(CardBuildOutcome::Card(card)) =
                build_projection_plan(legacy)
            else {
                panic!("a non-note always builds a legacy card");
            };
            assert_eq!(
                card.key_claim == body,
                holds,
                "body {body_len}: legacy card lossless iff capacity holds"
            );
            match build_projection_plan(note(&title, &body)) {
                ProjectionPlan::LegacyCardV1(_) => {
                    assert!(holds, "body {body_len}: long note left on the legacy card")
                }
                ProjectionPlan::NoteChunksV1(chunks) => {
                    assert!(!holds, "body {body_len}: a note that fits was chunked");
                    assert_eq!(chunks.len(), chunk_count(body_len));
                }
            }
        }
    }

    /// ADR-0068 gate `legacy_cards_are_byte_identical`: non-notes (short, over budget), a long SECRET_MATERIAL note, a
    /// bodiless note and a short note get exactly `build_card`'s outcome, and the legacy template hash is the one every
    /// stored fingerprint was minted under. Fault: drop the `is_identity_note` or SECRET_MATERIAL term from `build_projection_plan` ⇒ red.
    #[test]
    fn legacy_cards_are_byte_identical() {
        let long = "x".repeat(5_000);
        let mut fact = note("title", "a short fact");
        fact.is_identity_note = false;
        fact.card.memory_type = MemoryType::Fact;
        fact.card.entities = vec!["b".into(), "a".into()];
        fact.card.evidence_excerpt = Some("excerpt".into());
        let mut long_fact = note("title", &long);
        long_fact.is_identity_note = false;
        let mut secret_note = note("title", &long);
        secret_note.card.data_class = DataClass::SecretMaterial;
        let mut bodiless = note(&long, "");
        bodiless.card.key_claim = None;
        for input in [
            fact,
            long_fact,
            secret_note,
            bodiless,
            note("short note", "fits the legacy card"),
        ] {
            let expected = build_card(input.card.clone(), CardBudget::default());
            assert_eq!(
                build_projection_plan(input),
                ProjectionPlan::LegacyCardV1(expected)
            );
        }
        assert_eq!(
            card::CARD_TEMPLATE_HASH,
            "v1-ea55e89d6b9673b7113957816c36d347c4c071766189854609e8731f24dac52b"
        );
        assert_eq!(card::CARD_TEMPLATE_HASH, template_fingerprint());
    }

    /// ADR-0068 D-I: the policy, not the note alone, decides the profile. A long note stays on the legacy card under
    /// `LegacyOnly` and is chunked under `NoteChunksV1`; an empty body with a long title is never a title-only chunk;
    /// a hash this build does not know is refused. Faults: drop the policy term ⇒ red on the `LegacyOnly` arm; drop
    /// `body.is_empty()` from `legacy_capacity_holds` ⇒ red on the empty-body arm; map an unknown hash to `LegacyOnly`
    /// ⇒ red on the refusal arm.
    #[test]
    fn plan_follows_the_projection_policy() {
        let long_title = "t".repeat(700);
        let long_body = "b".repeat(2_000);
        let mut legacy_only = note("title", &long_body);
        legacy_only.policy = NoteChunkPolicy::LegacyOnly;
        let expected = build_card(legacy_only.card.clone(), CardBudget::default());
        assert_eq!(
            build_projection_plan(legacy_only),
            ProjectionPlan::LegacyCardV1(expected)
        );
        assert_eq!(
            chunks_of(note("title", &long_body)).len(),
            chunk_count(2_000)
        );
        let empty_body = note(&long_title, "");
        let expected = build_card(empty_body.card.clone(), CardBudget::default());
        assert_eq!(expected, CardBuildOutcome::Unbuildable);
        assert_eq!(
            build_projection_plan(empty_body),
            ProjectionPlan::LegacyCardV1(expected)
        );
        assert_eq!(
            NoteChunkPolicy::from_profile_hash(None),
            Ok(NoteChunkPolicy::LegacyOnly)
        );
        assert_eq!(
            NoteChunkPolicy::from_profile_hash(Some(NOTE_CHUNKS_V1_PROFILE_HASH)),
            Ok(NoteChunkPolicy::NoteChunksV1)
        );
        let unknown = format!("{NOTE_CHUNKS_V1_PROFILE_HASH}0");
        let refused = NoteChunkPolicy::from_profile_hash(Some(&unknown));
        assert_eq!(refused, Err(UnknownNoteChunkProfile(unknown)));
        assert_eq!(
            NoteChunkPolicy::from_profile_hash(Some(LEGACY_CARD_PROFILE_HASH)),
            Err(UnknownNoteChunkProfile(LEGACY_CARD_PROFILE_HASH.to_owned())),
            "the legacy marker is not a note chunk profile"
        );
    }

    /// ADR-0068 gate `secret_material_note_is_never_chunked`: a long identity note classified SECRET_MATERIAL under
    /// the `NoteChunksV1` policy is excluded by `build_card` (§18.2), never split into chunk slots. Fault: drop the
    /// SECRET_MATERIAL term from `build_projection_plan` ⇒ `NoteChunksV1` ⇒ red.
    #[test]
    fn secret_material_note_is_never_chunked() {
        let mut secret = note("title", &"s".repeat(2_000));
        secret.card.data_class = DataClass::SecretMaterial;
        assert_eq!(
            build_projection_plan(secret),
            ProjectionPlan::LegacyCardV1(CardBuildOutcome::ExcludedSecret)
        );
    }

    /// ADR-0068 D-G: a chunk card seals and hashes exactly the chunk text and carries the note's identity and data
    /// class. Faults: `card_text` from the window alone, or the title prefix dropped ⇒ red on `card_text`; a fixed data
    /// class ⇒ red on `data_class`.
    #[test]
    fn chunk_card_carries_the_chunk_text_and_the_note_identity() {
        let mut input = note(&"t".repeat(200), &"長".repeat(1_000));
        input.card.data_class = DataClass::Sensitive;
        let card_input = input.card.clone();
        for chunk in chunks_of(input) {
            let card = chunk_card(&card_input, &chunk);
            assert_eq!(card.card_text, chunk.text);
            assert_eq!(
                card.title, card_input.title,
                "the field keeps the whole title"
            );
            assert_eq!(
                (card.memory_id, card.data_class),
                (card_input.memory_id, DataClass::Sensitive)
            );
            assert_eq!(
                Some(card.key_claim.as_str()),
                scalar_slice(
                    card_input.key_claim.as_deref().unwrap_or_default(),
                    chunk.range
                )
            );
        }
    }

    /// ADR-0068 D-B: recomputes [`NOTE_CHUNKS_V1_PROFILE_HASH`] from the parameter tuple and the real chunk texts of
    /// a golden note (138-scalar title, 1 047-scalar body with CJK, emoji, a combining mark and CRLF: three chunks,
    /// the last one short). Fault: any parameter, the separator or the prefix rule ⇒ red.
    #[test]
    fn profile_hash_is_pinned() {
        use sha2::{Digest, Sha256};
        let title = format!("GOLDEN_NOTE_TITLE_{}", "標".repeat(120));
        let body = format!(
            "NOTE_CHUNKS_V1_GOLDEN_BODY|{}",
            "0123456789 長😀e\u{301}\r\n".repeat(60)
        );
        let chunks = chunks_of(note(&title, &body));
        assert_eq!(chunks.len(), 3);
        let parameters = format!(
            "NoteChunksV1;unit=scalar;window={NOTE_CHUNKS_V1_WINDOW};overlap={NOTE_CHUNKS_V1_OVERLAP};\
             stride={NOTE_CHUNKS_V1_STRIDE};title_prefix={NOTE_CHUNKS_V1_TITLE_PREFIX};\
             legacy_separators={LEGACY_NOTE_SEPARATORS};legacy_budget={}",
            CardBudget::default().max_chars
        );
        let mut hasher = Sha256::new();
        hasher.update(parameters.as_bytes());
        for chunk in &chunks {
            assert_eq!(chunk.card_profile_hash, NOTE_CHUNKS_V1_PROFILE_HASH);
            hasher.update((chunk.text.len() as u64).to_be_bytes());
            hasher.update(chunk.text.as_bytes());
        }
        let hex: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(NOTE_CHUNKS_V1_PROFILE_HASH, format!("NoteChunksV1-{hex}"));
        assert_eq!(
            NOTE_CHUNKS_V1_TITLE_PREFIX
                + NOTE_CHUNKS_V1_SEPARATOR.chars().count()
                + NOTE_CHUNKS_V1_WINDOW,
            CardBudget::default().max_chars,
            "a full chunk card is exactly a legacy-budget card"
        );
    }

    /// Multi-byte bodies: every chunk is `title_prefix + "\n" + body[range]` on scalar boundaries, its window has
    /// exactly `range.len()` scalars, and dropping each later window's 64-scalar overlap rebuilds the body byte for
    /// byte. Fault: byte offsets instead of scalar boundaries ⇒ a slice panics or the rebuild differs.
    #[test]
    fn multibyte_bodies_round_trip_without_splitting_a_scalar() {
        let title = "標題😀".repeat(50);
        let prefix: String = title.chars().take(NOTE_CHUNKS_V1_TITLE_PREFIX).collect();
        for unit in [
            "長文本",
            "😀🧪🫠",
            "e\u{301}a\u{308}\u{323}",
            "line\r\n",
            "a長😀e\u{301}\r\n",
        ] {
            let body = unit.repeat(700);
            let chunks = chunks_of(note(&title, &body));
            assert_eq!(chunks.len(), chunk_count(body.chars().count()), "{unit:?}");
            let mut rebuilt = String::new();
            for chunk in &chunks {
                let window = chunk
                    .text
                    .strip_prefix(&format!("{prefix}{NOTE_CHUNKS_V1_SEPARATOR}"))
                    .expect("title prefix + separator");
                assert_eq!(window.chars().count(), chunk.range.end - chunk.range.start);
                assert_eq!(scalar_slice(&body, chunk.range.clone()), Some(window));
                assert_eq!(
                    chunk_card_text(&title, &body, chunk.chunk_ordinal).as_deref(),
                    Some(chunk.text.as_str())
                );
                let skip = if chunk.chunk_ordinal == 0 {
                    0
                } else {
                    NOTE_CHUNKS_V1_OVERLAP
                };
                rebuilt.extend(window.chars().skip(skip));
            }
            assert_eq!(rebuilt, body, "{unit:?}");
            assert_eq!(chunk_card_text(&title, &body, chunks.len()), None);
        }
        assert_eq!(scalar_slice("長😀", 1..3), None);
        let reversed_end = 1;
        assert_eq!(scalar_slice("長😀", 2..reversed_end), None);
        assert_eq!(scalar_slice("長😀", 1..2), Some("😀"));
    }

    /// ADR-0084 D-C 3: a registry row reads as the slot its point stands for; a profile this build does not know, a
    /// legacy row off ordinal 0 and a negative ordinal read as no slot. Fault: read an unknown profile as legacy ⇒ red.
    #[test]
    fn registry_rows_read_as_card_slots() {
        assert_eq!(
            CardSlot::from_registry(LEGACY_CARD_PROFILE_HASH, 0),
            Some(CardSlot::Legacy)
        );
        assert_eq!(
            CardSlot::from_registry(NOTE_CHUNKS_V1_PROFILE_HASH, 0),
            Some(CardSlot::Chunk { ordinal: 0 })
        );
        assert_eq!(
            CardSlot::from_registry(NOTE_CHUNKS_V1_PROFILE_HASH, 2),
            Some(CardSlot::Chunk { ordinal: 2 })
        );
        assert_eq!(CardSlot::from_registry("NoteChunksV2-unknown", 0), None);
        assert_eq!(CardSlot::from_registry(LEGACY_CARD_PROFILE_HASH, 1), None);
        assert_eq!(
            CardSlot::from_registry(NOTE_CHUNKS_V1_PROFILE_HASH, -1),
            None
        );
    }

    /// ADR-0084 D-C 3: the rerank document of a chunk slot is the embedded card text of that chunk, for every slot of
    /// a three-chunk body, distinct per slot; past the last chunk there is none.
    /// A legacy slot is title prefix + separator + the whole body. Fault: build the document from slot 0 whatever the
    /// ordinal ⇒ red on the per-slot equality.
    #[test]
    fn rerank_document_is_the_card_text_of_the_slot() {
        let title = "t".repeat(NOTE_CHUNKS_V1_TITLE_PREFIX + 10);
        let prefix = "t".repeat(NOTE_CHUNKS_V1_TITLE_PREFIX);
        // 1,000 distinct scalars: no two chunk windows are equal, so a wrong slot cannot pass.
        let body: String = (0x4e00_u32..0x4e00 + 1_000)
            .filter_map(char::from_u32)
            .collect();
        let count = chunk_count(body.chars().count());
        assert_eq!(count, 3);
        let documents: Vec<String> = (0..count)
            .map(|ordinal| {
                let slot = CardSlot::Chunk {
                    ordinal: u32::try_from(ordinal).expect("small"),
                };
                let document =
                    rerank_document(&title, &body, slot).expect("a slot inside the body");
                assert_eq!(
                    Some(document.as_str()),
                    chunk_card_text(&title, &body, ordinal).as_deref()
                );
                document
            })
            .collect();
        assert_ne!(documents[0], documents[1]);
        assert_ne!(documents[1], documents[2]);
        assert_eq!(
            rerank_document(&title, &body, CardSlot::Chunk { ordinal: 3 }),
            None
        );
        assert_eq!(
            rerank_document("short", "the whole body", CardSlot::Legacy),
            Some(format!("short{NOTE_CHUNKS_V1_SEPARATOR}the whole body"))
        );
        assert_eq!(
            rerank_document(&title, "b", CardSlot::Legacy),
            Some(format!("{prefix}{NOTE_CHUNKS_V1_SEPARATOR}b"))
        );
    }
}

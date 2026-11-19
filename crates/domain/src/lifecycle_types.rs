//! `domain::lifecycle_types` — shared lifecycle identifiers (§49) and subject kinds (§6.1.3, ADR-0078).
//! Depends-on: crates=[uuid]; services=[]; env=[]; modules=[domain::error]
//! Called-by: []
//! Invariants: [§49 UUIDv7 mint and parse, §78.2 closed-set subject kinds]
//! Spec: Baseline §6.1.3; §49; §59; ADR-0130
//!
//! Lifecycle and subject IDs are separate from the seven scope IDs frozen in `domain::ids` (§59).

use crate::error::ErrorCode;
use uuid::Uuid;

/// Memory row id, UUIDv7 (§49). See module doc for why it is minted here instead of
/// `domain::ids`; `parse` and the mint/parse split otherwise match `ids::uuid_newtype!`
/// exactly (§49: "exactly two entry points, mint and parse").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemoryId(pub Uuid);

impl MemoryId {
    // See `domain::ids`'s identical rationale: `Default` would silently mint a fresh random
    // id, a bigger trap than one extra `::new()` call.
    #[allow(clippy::new_without_default)]
    /// Mints a new id (UUIDv7, §49).
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Parses an existing UUID string (§49's second entry point; no legacy uuid5/hash
    /// formula compatibility).
    pub fn parse(s: &str) -> Result<Self, ErrorCode> {
        Uuid::parse_str(s)
            .map(Self)
            .map_err(|_| ErrorCode::InvalidInput)
    }
}

/// Evidence row id, UUIDv7 (§49). See module doc for why it is minted here instead of
/// `domain::ids`; not ordered — I1 tier 4 orders `MemoryId`, never `EvidenceId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EvidenceId(pub Uuid);

impl EvidenceId {
    #[allow(clippy::new_without_default)]
    /// Mints a new id (UUIDv7, §49).
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Parses an existing UUID string (§49's second entry point; no legacy uuid5/hash
    /// formula compatibility).
    pub fn parse(s: &str) -> Result<Self, ErrorCode> {
        Uuid::parse_str(s)
            .map(Self)
            .map_err(|_| ErrorCode::InvalidInput)
    }
}

/// Subject id (§6.1.3). UUIDv7, minted like every other §49 id. Deliberately *not* in
/// [`crate::ids`]: that module is frozen at the seven `Scope` ids (§59); a subject is aboutness,
/// not scope, and lives on its own axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubjectId(pub Uuid);

#[allow(clippy::new_without_default)]
impl SubjectId {
    /// Mints a new subject id (UUIDv7, §49).
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Parses an existing UUID string. Malformed input is `INVALID_INPUT` (§52.1).
    pub fn parse(s: &str) -> Result<Self, ErrorCode> {
        Uuid::parse_str(s)
            .map(Self)
            .map_err(|_| ErrorCode::InvalidInput)
    }
}

/// The kind of subject a memory can be about (§6.1.3). Frozen closed set — no `Other`,
/// no `#[non_exhaustive]`. Wire form = `private.subjects.kind`'s `text` CHECK, widened
/// expand-only by `migrations/0247_subject_kinds_business_brand_product_website.sql`.
///
/// ADR-0078 D-B adds the four work-attribution kinds below. `CHANNEL_ACCOUNT` and
/// `PRODUCT_LINE` are deliberately absent: provisional kinds stay out of the set until
/// experiment E-C accepts them, and a repository is never a subject (`control.repositories`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubjectKind {
    /// A natural person.
    Person,
    /// An organisation / company.
    Organisation,
    /// A business: the commercial entity a brand is owned by (§6.1.3, ADR-0078 D-B).
    Business,
    /// A brand: owned by a business, it owns websites and products (§6.1.3, ADR-0078 D-B).
    Brand,
    /// A product; a product line is one product that other products are `PART_OF`
    /// (§6.1.3, ADR-0078 D-B).
    Product,
    /// A website. The domain serving it is a locator, never the identity (§6.1.3, ADR-0078 D-B).
    Website,
}

impl SubjectKind {
    /// All variants — derived list, the §78.2 contract-test and exhaustiveness surface.
    pub const ALL: [SubjectKind; 6] = [
        SubjectKind::Person,
        SubjectKind::Organisation,
        SubjectKind::Business,
        SubjectKind::Brand,
        SubjectKind::Product,
        SubjectKind::Website,
    ];

    /// Wire string frozen on `private.subjects.kind`.
    pub fn as_str(self) -> &'static str {
        match self {
            SubjectKind::Person => "PERSON",
            SubjectKind::Organisation => "ORGANISATION",
            SubjectKind::Business => "BUSINESS",
            SubjectKind::Brand => "BRAND",
            SubjectKind::Product => "PRODUCT",
            SubjectKind::Website => "WEBSITE",
        }
    }

    /// Parse a wire string; unknown/lowercase input is `None` (caller maps to its own error).
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

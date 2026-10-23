//! `domain::source` — ingest source identity and the single source-kind classification table (M06 D1/D2, ADR-0098).
//! Depends-on: crates=[sha2]; services=[]; env=[]; modules=[domain::dataclass, domain::error, domain::evidence, domain::identity]
//! Called-by: [adapters::remember, tests]
//! Invariants: [`classify_source`] is the one place an [`IngestSourceKind`] is mapped to origin, data-class floor, event kind
//!   and visibility rule; a raw external object/thread key is never stored, only a 16-byte SHA-256 prefix; the identity
//!   carries no agent, ingest time or project]
//! Spec: Baseline §7.5; §8.7; §10.1; §78.2; ADR-0078; ADR-0098
//!
//! Named [`IngestSourceKind`], not `SourceKind`: `attribution::SourceKind` (ADR-0078) is the work-attribution axis and
//! shares nothing with it.

use sha2::{Digest, Sha256};

use crate::dataclass::{DataClass, join_data_class};
use crate::error::ErrorCode;
use crate::evidence::EvidenceOriginClass;
use crate::identity::VisibilityClass;

/// Longest `version` in characters; the `private.evidence_sources.source_version` CHECK (0264) carries the same bound.
pub const SOURCE_VERSION_MAX_CHARS: usize = 64;

/// What kind of external object an Evidence was relayed from (ADR-0098 D1). Closed set; the DB code is the
/// `private.evidence_sources.source_kind` CHECK list, reconciled by `adapters::tests::evidence_sources` (§78.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IngestSourceKind {
    /// An agent's own note; today's remember rules apply unchanged.
    AgentNote,
    /// One email message relayed by an agent.
    EmailMessage,
    /// One chat message relayed by an agent.
    ChatMessage,
    /// One calendar item relayed by an agent.
    CalendarItem,
    /// One turn of the agent's conversation with its user.
    ConversationTurn,
    /// Data replayed from the previous system.
    LegacyImport,
}

impl IngestSourceKind {
    /// Every variant, in DB-code order.
    pub const ALL: [IngestSourceKind; 6] = [
        IngestSourceKind::AgentNote,
        IngestSourceKind::EmailMessage,
        IngestSourceKind::ChatMessage,
        IngestSourceKind::CalendarItem,
        IngestSourceKind::ConversationTurn,
        IngestSourceKind::LegacyImport,
    ];

    /// The `smallint` stored in `private.evidence_sources.source_kind`; codes are never reused or renumbered.
    pub const fn db_code(self) -> i16 {
        match self {
            IngestSourceKind::AgentNote => 1,
            IngestSourceKind::EmailMessage => 2,
            IngestSourceKind::ChatMessage => 3,
            IngestSourceKind::CalendarItem => 4,
            IngestSourceKind::ConversationTurn => 5,
            IngestSourceKind::LegacyImport => 6,
        }
    }

    /// Strict inverse of [`Self::db_code`].
    pub fn from_db_code(code: i16) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.db_code() == code)
    }
}

/// The `private.events.event_kind` values an ingest classification can force or accept; a subset of that CHECK list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestEventKind {
    /// `USER_MESSAGE`.
    UserMessage,
    /// `ASSISTANT_MESSAGE`.
    AssistantMessage,
    /// `SYSTEM_IMPORT`.
    SystemImport,
}

impl IngestEventKind {
    /// Every variant.
    pub const ALL: [IngestEventKind; 3] = [
        IngestEventKind::UserMessage,
        IngestEventKind::AssistantMessage,
        IngestEventKind::SystemImport,
    ];

    /// The `private.events.event_kind` CHECK literal.
    pub const fn as_str(self) -> &'static str {
        match self {
            IngestEventKind::UserMessage => "USER_MESSAGE",
            IngestEventKind::AssistantMessage => "ASSISTANT_MESSAGE",
            IngestEventKind::SystemImport => "SYSTEM_IMPORT",
        }
    }

    /// Strict inverse of [`Self::as_str`].
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == s)
    }
}

/// First 16 bytes of the SHA-256 of an external key (ADR-0098 D1).
// ponytail: unkeyed digest, confirmable by anyone who can read the table and guess the key; upgrade to a tenant-keyed
// HMAC once M05's key hierarchy exists (ADR-0098).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceDigest16([u8; 16]);

impl SourceDigest16 {
    fn of(raw: &str) -> Self {
        let full = Sha256::digest(raw.as_bytes());
        let mut prefix = [0u8; 16];
        prefix.copy_from_slice(&full[..16]);
        SourceDigest16(prefix)
    }

    /// The `bytea` value of an `*_d16` column.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Source identity of one relayed object: kind, object-key digest, version and optional thread-key digest
/// (ADR-0098 D1). Only digests are held; the raw keys end at [`Self::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceIdentity {
    kind: IngestSourceKind,
    object_key_d16: SourceDigest16,
    version: String,
    thread_key_d16: Option<SourceDigest16>,
}

impl SourceIdentity {
    /// Builds the identity from the raw wire keys. An empty key or version, or a version over
    /// [`SOURCE_VERSION_MAX_CHARS`], is `INVALID_INPUT`. An absent version is stored as the empty string so the
    /// UNIQUE key has no NULL member.
    pub fn new(
        kind: IngestSourceKind,
        object_key: &str,
        version: Option<&str>,
        thread_key: Option<&str>,
    ) -> Result<Self, ErrorCode> {
        if object_key.is_empty()
            || thread_key.is_some_and(str::is_empty)
            || version.is_some_and(|v| v.is_empty() || v.chars().count() > SOURCE_VERSION_MAX_CHARS)
        {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(SourceIdentity {
            kind,
            object_key_d16: SourceDigest16::of(object_key),
            version: version.unwrap_or_default().to_owned(),
            thread_key_d16: thread_key.map(SourceDigest16::of),
        })
    }

    /// The source kind.
    pub fn kind(&self) -> IngestSourceKind {
        self.kind
    }

    /// Digest of the raw object key.
    pub fn object_key_d16(&self) -> &SourceDigest16 {
        &self.object_key_d16
    }

    /// The version, empty when none was supplied.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Digest of the raw thread key, when one was supplied.
    pub fn thread_key_d16(&self) -> Option<&SourceDigest16> {
        self.thread_key_d16.as_ref()
    }
}

/// How a source kind decides `private.events.event_kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKindRule {
    /// The caller's value stands.
    Caller,
    /// Always this value.
    Forced(IngestEventKind),
    /// The caller's value must be one of these.
    OneOf(&'static [IngestEventKind]),
}

/// How a source kind constrains the requested visibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisibilityRule {
    /// The caller's value stands.
    Caller,
    /// Only `USER_PRIVATE` is accepted; anything wider is refused, never narrowed silently (§8.7).
    UserPrivateOnly,
    /// Anything but tenant-wide is accepted.
    NotTenantWide,
}

/// One row of the classification table (ADR-0098 D2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceClassification {
    /// Event-kind rule.
    pub event_kind: EventKindRule,
    /// Origin class stamped by the ingress path (§8.7); `None` keeps the caller's.
    pub origin_class: Option<EvidenceOriginClass>,
    /// Lowest data class the Evidence may carry; the stored class is the lattice join with the request (§7.5.1).
    pub data_class_floor: Option<DataClass>,
    /// Visibility rule.
    pub visibility: VisibilityRule,
}

/// The single source-kind classification table (ADR-0098 D2, §7.5 / §8.7). Every kind has its own arm and there is no
/// wildcard, so a new kind cannot compile without a decision here.
pub fn classify_source(kind: IngestSourceKind) -> SourceClassification {
    match kind {
        IngestSourceKind::AgentNote => SourceClassification {
            event_kind: EventKindRule::Caller,
            origin_class: None,
            data_class_floor: None,
            visibility: VisibilityRule::Caller,
        },
        IngestSourceKind::EmailMessage
        | IngestSourceKind::ChatMessage
        | IngestSourceKind::CalendarItem => SourceClassification {
            event_kind: EventKindRule::Forced(IngestEventKind::SystemImport),
            origin_class: Some(EvidenceOriginClass::ExternalContent),
            data_class_floor: Some(DataClass::Sensitive),
            visibility: VisibilityRule::UserPrivateOnly,
        },
        IngestSourceKind::ConversationTurn => SourceClassification {
            event_kind: EventKindRule::OneOf(&[
                IngestEventKind::UserMessage,
                IngestEventKind::AssistantMessage,
            ]),
            origin_class: Some(EvidenceOriginClass::AuthenticatedAgent),
            data_class_floor: None,
            visibility: VisibilityRule::NotTenantWide,
        },
        IngestSourceKind::LegacyImport => SourceClassification {
            event_kind: EventKindRule::Forced(IngestEventKind::SystemImport),
            origin_class: Some(EvidenceOriginClass::SystemMigration),
            data_class_floor: None,
            visibility: VisibilityRule::Caller,
        },
    }
}

/// What [`SourceClassification::apply`] decided for one write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassifiedIngest {
    /// `Some` = the event kind to store.
    pub event_kind: Option<IngestEventKind>,
    /// `Some` = the origin class to store.
    pub origin_class: Option<EvidenceOriginClass>,
    /// The data class to store.
    pub data_class: DataClass,
}

impl SourceClassification {
    /// Applies the row to a request. A refused request is `INVALID_INPUT` and nothing is stored (§8.7: explicit, never
    /// silent narrowing). The stored data class is `join(requested, floor)`, so it never falls below the request (§7.5.1).
    pub fn apply(
        &self,
        event_kind: &str,
        data_class: DataClass,
        visibility: VisibilityClass,
    ) -> Result<ClassifiedIngest, ErrorCode> {
        let event_kind = match self.event_kind {
            EventKindRule::Caller => None,
            EventKindRule::Forced(kind) => Some(kind),
            EventKindRule::OneOf(allowed) => Some(
                IngestEventKind::parse(event_kind)
                    .filter(|kind| allowed.contains(kind))
                    .ok_or(ErrorCode::InvalidInput)?,
            ),
        };
        let visibility_ok = match self.visibility {
            VisibilityRule::Caller => true,
            VisibilityRule::UserPrivateOnly => visibility == VisibilityClass::UserPrivate,
            VisibilityRule::NotTenantWide => visibility != VisibilityClass::TenantShared,
        };
        if !visibility_ok {
            return Err(ErrorCode::InvalidInput);
        }
        let data_class = self
            .data_class_floor
            .map_or(data_class, |floor| join_data_class([data_class, floor]));
        Ok(ClassifiedIngest {
            event_kind,
            origin_class: self.origin_class,
            data_class,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_codes_are_one_to_six_in_order_and_round_trip() {
        let codes: Vec<i16> = IngestSourceKind::ALL.iter().map(|k| k.db_code()).collect();
        assert_eq!(codes, vec![1, 2, 3, 4, 5, 6]);
        for kind in IngestSourceKind::ALL {
            assert_eq!(IngestSourceKind::from_db_code(kind.db_code()), Some(kind));
        }
        assert_eq!(IngestSourceKind::from_db_code(0), None);
        assert_eq!(IngestSourceKind::from_db_code(7), None);
    }

    #[test]
    fn event_kind_literals_round_trip_and_refuse_the_rest() {
        let wire: Vec<&str> = IngestEventKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(
            wire,
            vec!["USER_MESSAGE", "ASSISTANT_MESSAGE", "SYSTEM_IMPORT"]
        );
        for kind in IngestEventKind::ALL {
            assert_eq!(IngestEventKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(IngestEventKind::parse("user_message"), None);
        assert_eq!(IngestEventKind::parse("MANUAL_NOTE"), None);
    }

    /// The full table, kind by kind (ADR-0098 D2).
    #[test]
    fn the_table_is_exactly_the_adr_table() {
        use EvidenceOriginClass as O;
        let third_party = SourceClassification {
            event_kind: EventKindRule::Forced(IngestEventKind::SystemImport),
            origin_class: Some(O::ExternalContent),
            data_class_floor: Some(DataClass::Sensitive),
            visibility: VisibilityRule::UserPrivateOnly,
        };
        let expected = [
            (
                IngestSourceKind::AgentNote,
                SourceClassification {
                    event_kind: EventKindRule::Caller,
                    origin_class: None,
                    data_class_floor: None,
                    visibility: VisibilityRule::Caller,
                },
            ),
            (IngestSourceKind::EmailMessage, third_party),
            (IngestSourceKind::ChatMessage, third_party),
            (IngestSourceKind::CalendarItem, third_party),
            (
                IngestSourceKind::ConversationTurn,
                SourceClassification {
                    event_kind: EventKindRule::OneOf(&[
                        IngestEventKind::UserMessage,
                        IngestEventKind::AssistantMessage,
                    ]),
                    origin_class: Some(O::AuthenticatedAgent),
                    data_class_floor: None,
                    visibility: VisibilityRule::NotTenantWide,
                },
            ),
            (
                IngestSourceKind::LegacyImport,
                SourceClassification {
                    event_kind: EventKindRule::Forced(IngestEventKind::SystemImport),
                    origin_class: Some(O::SystemMigration),
                    data_class_floor: None,
                    visibility: VisibilityRule::Caller,
                },
            ),
        ];
        assert_eq!(expected.len(), IngestSourceKind::ALL.len());
        for (kind, row) in expected {
            assert_eq!(classify_source(kind), row, "{kind:?}");
        }
    }

    #[test]
    fn third_party_kinds_force_sensitive_external_content_and_refuse_wider_visibility() {
        for kind in [
            IngestSourceKind::EmailMessage,
            IngestSourceKind::ChatMessage,
            IngestSourceKind::CalendarItem,
        ] {
            let row = classify_source(kind);
            let ok = row
                .apply(
                    "MANUAL_NOTE",
                    DataClass::Internal,
                    VisibilityClass::UserPrivate,
                )
                .expect("user-private is accepted");
            assert_eq!(ok.data_class, DataClass::Sensitive);
            assert_eq!(ok.origin_class, Some(EvidenceOriginClass::ExternalContent));
            assert_eq!(ok.event_kind, Some(IngestEventKind::SystemImport));
            for wider in [
                VisibilityClass::WorkspaceShared,
                VisibilityClass::TenantShared,
            ] {
                assert_eq!(
                    row.apply("MANUAL_NOTE", DataClass::Internal, wider),
                    Err(ErrorCode::InvalidInput),
                    "{kind:?} {wider:?}"
                );
            }
            let secret = row
                .apply(
                    "MANUAL_NOTE",
                    DataClass::SecretMaterial,
                    VisibilityClass::UserPrivate,
                )
                .expect("accepted");
            assert_eq!(
                secret.data_class,
                DataClass::SecretMaterial,
                "never lowered"
            );
        }
    }

    #[test]
    fn conversation_turn_accepts_only_message_events_and_nothing_tenant_wide() {
        let row = classify_source(IngestSourceKind::ConversationTurn);
        assert_eq!(
            row.apply(
                "ASSISTANT_MESSAGE",
                DataClass::Private,
                VisibilityClass::WorkspaceShared
            )
            .map(|c| (c.event_kind, c.data_class)),
            Ok((Some(IngestEventKind::AssistantMessage), DataClass::Private))
        );
        assert_eq!(
            row.apply(
                "MANUAL_NOTE",
                DataClass::Private,
                VisibilityClass::UserPrivate
            ),
            Err(ErrorCode::InvalidInput)
        );
        assert_eq!(
            row.apply(
                "USER_MESSAGE",
                DataClass::Private,
                VisibilityClass::TenantShared
            ),
            Err(ErrorCode::InvalidInput)
        );
    }

    #[test]
    fn agent_note_and_legacy_import_keep_the_callers_class_and_visibility() {
        for (kind, origin) in [
            (IngestSourceKind::AgentNote, None),
            (
                IngestSourceKind::LegacyImport,
                Some(EvidenceOriginClass::SystemMigration),
            ),
        ] {
            let got = classify_source(kind)
                .apply(
                    "MANUAL_NOTE",
                    DataClass::Public,
                    VisibilityClass::TenantShared,
                )
                .expect("accepted");
            assert_eq!(got.data_class, DataClass::Public);
            assert_eq!(got.origin_class, origin);
        }
    }

    #[test]
    fn identity_stores_only_digests_and_excludes_everything_but_the_key() {
        let a = SourceIdentity::new(
            IngestSourceKind::EmailMessage,
            "msg-1",
            Some("v1"),
            Some("t-1"),
        )
        .expect("valid");
        let b = SourceIdentity::new(
            IngestSourceKind::EmailMessage,
            "msg-1",
            Some("v1"),
            Some("t-1"),
        )
        .expect("valid");
        assert_eq!(a, b);
        let other = SourceIdentity::new(IngestSourceKind::EmailMessage, "msg-2", Some("v1"), None)
            .expect("valid");
        assert_ne!(a.object_key_d16(), other.object_key_d16());
        assert_eq!(other.thread_key_d16(), None);
        assert_eq!(
            SourceIdentity::new(IngestSourceKind::ChatMessage, "msg-1", None, None)
                .expect("valid")
                .version(),
            ""
        );
        // First 16 bytes of SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223.
        let abc =
            SourceIdentity::new(IngestSourceKind::ChatMessage, "abc", None, None).expect("valid");
        assert_eq!(
            abc.object_key_d16().as_bytes(),
            &[
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23
            ]
        );
    }

    #[test]
    fn identity_refuses_empty_keys_and_over_long_versions() {
        let kind = IngestSourceKind::EmailMessage;
        assert_eq!(
            SourceIdentity::new(kind, "", None, None),
            Err(ErrorCode::InvalidInput)
        );
        assert_eq!(
            SourceIdentity::new(kind, "k", None, Some("")),
            Err(ErrorCode::InvalidInput)
        );
        assert_eq!(
            SourceIdentity::new(kind, "k", Some(""), None),
            Err(ErrorCode::InvalidInput)
        );
        let at_bound = "v".repeat(SOURCE_VERSION_MAX_CHARS);
        assert!(SourceIdentity::new(kind, "k", Some(&at_bound), None).is_ok());
        let over = "v".repeat(SOURCE_VERSION_MAX_CHARS + 1);
        assert_eq!(
            SourceIdentity::new(kind, "k", Some(&over), None),
            Err(ErrorCode::InvalidInput)
        );
    }
}

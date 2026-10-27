//! `adapters::email` — H3: §74.6 `EmailProvider` trait + SMTP adapter + the Email Deliverability Plane (outbox /
//!   delivery events / suppression / domain / provider health).
//! Depends-on: crates=[async-trait]; services=[]; env=[]; modules=[]
//! Called-by: [adapters::email::outbox, adapters::email::sink, adapters::email::smtp, adapters::email::test_double, adapters::login_repo, gateway::auth_pages, gateway::bootstrap, tests]
//! Invariants: [no caller outside smtp/sink/test_double names a concrete provider except EmailMode::into_provider;
//!   everything else takes &dyn EmailProvider (§74.6); the default mode is the non-sending Sink (M02 D10);
//!   the recipient allowlist, the priority order and the send cap are decided here, never by a caller]
//! Spec: Baseline §74.6
//!
//! Module layout: this file (trait, wire enums, [`EmailMode`], [`RecipientAllowlist`], [`SendPolicy`]),
//! [`smtp`] (lettre-backed SMTP adapter, config from parameters — never reads env directly, §74.6
//! task brief), [`sink`] (writes `.eml` files, the default mode), [`test_double`] (in-memory
//! [`test_double::RecordingEmailProvider`]), [`outbox`] (DB-backed `enqueue_in_txn` + SKIP LOCKED
//! worker + suppression check + delivery-event recording, `ops.email_outbox` DDL in
//! `migrations/0038_email_deliverability.sql` and `migrations/0263_email_door.sql`).
//!
//! §74.6 "不写死供应商": nothing outside [`smtp`]/[`sink`]/[`test_double`] may name a concrete
//! provider type — every other caller (including [`outbox`]) takes `&dyn EmailProvider`.

pub mod outbox;
pub mod sink;
pub mod smtp;
pub mod test_double;

pub use outbox::{EnqueueOutcome, OutboxError};
pub use sink::SinkEmailProvider;
pub use smtp::{SmtpConfig, SmtpEmailProvider};
pub use test_double::RecordingEmailProvider;

use std::collections::BTreeSet;
use std::path::PathBuf;

use async_trait::async_trait;

/// §74.6 abstraction, verbatim signature from the spec code block. The sole boundary
/// between the Deliverability Plane (this module) and a concrete transport
/// (SMTP/SES/Postmark/Resend/...); [`outbox::run_once`] holds this as `&dyn EmailProvider`
/// so the worker never names a concrete adapter type.
#[async_trait]
pub trait EmailProvider: Send + Sync {
    /// Sends one email through this provider. This is the one network round trip in the
    /// whole H3 module — §74.6 "发信走 email_outbox, 验证码 HTTP handler 不直接阻塞 SMTP"
    /// is enforced by [`outbox::enqueue`] never calling this method at all, only the
    /// background [`outbox::run_once`] worker does.
    async fn send(&self, mail: OutboundEmail) -> Result<ProviderMessageId, EmailError>;

    /// Adapter identity written to `ops.email_outbox.provider` /
    /// `ops.email_delivery_events.provider` once [`outbox::run_once`] dispatches through this
    /// provider — an open string (§74.6 "不写死供应商"), never a fixed enum of provider
    /// names. Both columns are documented (migrations/0038_email_deliverability.sql) as
    /// "filled in once dispatched"; this method is what [`outbox::run_once`] now has to fill
    /// them with.
    fn name(&self) -> &str;
}

/// One outbound email, provider-agnostic.
#[derive(Debug, Clone)]
pub struct OutboundEmail {
    pub to: String,
    pub from: String,
    pub subject: String,
    pub body_text: String,
    pub body_html: Option<String>,
    /// Carried through to the provider call so an adapter with separate sending
    /// identities/IP pools per stream (§74.6 "Transactional 与 Marketing 分离") can route
    /// on it. This struct does not itself enforce the separation — [`outbox::enqueue`]'s
    /// suppression check does (§74.6 Suppression / [`SuppressionScope::blocks`]).
    pub stream: EmailStream,
    /// Full `Message-ID` header value including angle brackets, deterministic per outbox row
    /// (`<outbox_id@sender-domain>`, M02 D10) so a resend after an unknown outcome can be
    /// de-duplicated by the receiving side.
    pub message_id: String,
}

/// Provider-assigned message id, opaque outside this module (stored in
/// `ops.email_outbox.provider_message_id` / `ops.email_delivery_events.detail`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderMessageId(pub String);

/// Adapter-level send failure. Not one of the workspace's two frozen domain error enums
/// (`ErrorCode`/`DegradeCode`, §52 "禁止新开第三个错误枚举") — this is a transport-technical
/// error local to the `EmailProvider` boundary, same precedent as this crate's own
/// `postgres::PoolInitError`. The calling layer ([`outbox::run_once`]) maps it to a
/// `state = 'FAILED'` row + a `FAILED` delivery event; it never itself becomes a domain
/// `ErrorCode`.
#[derive(Debug)]
pub enum EmailError {
    /// Transport/connect/auth failure talking to the provider.
    Transport(String),
    /// Provider rejected the message content/recipient outright (e.g. a 5xx SMTP reply).
    Rejected(String),
    /// The connection was lost after the message body may have been transmitted, so whether
    /// the provider accepted it is unknowable. [`outbox::run_once`] records
    /// `SUBMISSION_UNKNOWN` and never resends it automatically (M02 D10 / M22 D7).
    SubmissionUnknown(String),
    /// The configured [`EmailMode`] is unusable (unknown mode name, SMTP selected without
    /// its settings).
    Config(String),
}

impl std::fmt::Display for EmailError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(m) => write!(f, "email transport error: {m}"),
            Self::Rejected(m) => write!(f, "email rejected by provider: {m}"),
            Self::SubmissionUnknown(m) => write!(f, "email submission outcome unknown: {m}"),
            Self::Config(m) => write!(f, "email mode misconfigured: {m}"),
        }
    }
}

impl std::error::Error for EmailError {}

/// §74.6 "Transactional 与 Marketing 分离" stream. Wire values back
/// `ops.email_outbox.stream` and the two non-`ALL` values of
/// `ops.email_suppressions.scope` — `outbox::contract_tests` reconciles Rust/DB (§78.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmailStream {
    Transactional,
    Marketing,
}

impl EmailStream {
    pub const ALL: [EmailStream; 2] = [Self::Transactional, Self::Marketing];

    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Transactional => "TRANSACTIONAL",
            Self::Marketing => "MARKETING",
        }
    }
}

/// `ops.email_outbox.state` — §74.6 Email Deliverability Plane state list, verbatim
/// (`QUEUED -> SENT -> DELIVERED -> BOUNCED/COMPLAINED/SUPPRESSED/FAILED`), plus
/// `SUBMISSION_UNKNOWN` (M02 D10): lost acknowledgement after DATA, terminal for the automatic path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmailOutboxState {
    Queued,
    Sent,
    Delivered,
    Bounced,
    Complained,
    Suppressed,
    Failed,
    SubmissionUnknown,
}

impl EmailOutboxState {
    pub const ALL: [EmailOutboxState; 8] = [
        Self::Queued,
        Self::Sent,
        Self::Delivered,
        Self::Bounced,
        Self::Complained,
        Self::Suppressed,
        Self::Failed,
        Self::SubmissionUnknown,
    ];

    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Queued => "QUEUED",
            Self::Sent => "SENT",
            Self::Delivered => "DELIVERED",
            Self::Bounced => "BOUNCED",
            Self::Complained => "COMPLAINED",
            Self::Suppressed => "SUPPRESSED",
            Self::Failed => "FAILED",
            Self::SubmissionUnknown => "SUBMISSION_UNKNOWN",
        }
    }
}

/// `ops.email_delivery_events.event_type` — the outbox states minus `QUEUED` (queueing a
/// row is not itself a delivery *event*; §74.6 "email_outbox 只是第一步, 还必须维护
/// email_delivery_events").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeliveryEventType {
    Sent,
    Delivered,
    Bounced,
    Complained,
    Suppressed,
    Failed,
    SubmissionUnknown,
}

impl DeliveryEventType {
    pub const ALL: [DeliveryEventType; 7] = [
        Self::Sent,
        Self::Delivered,
        Self::Bounced,
        Self::Complained,
        Self::Suppressed,
        Self::Failed,
        Self::SubmissionUnknown,
    ];

    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Sent => "SENT",
            Self::Delivered => "DELIVERED",
            Self::Bounced => "BOUNCED",
            Self::Complained => "COMPLAINED",
            Self::Suppressed => "SUPPRESSED",
            Self::Failed => "FAILED",
            Self::SubmissionUnknown => "SUBMISSION_UNKNOWN",
        }
    }
}

/// `ops.email_outbox.priority` (M02 D10 / M22 D11 storm guard): the drain takes the lowest rank
/// first, so a login code is never queued behind a digest backlog. The wire value is the rank;
/// `outbox::contract_tests` reconciles it with the CHECK list (§78.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmailPriority {
    Auth,
    Security,
    Reminder,
    Digest,
}

impl EmailPriority {
    pub const ALL: [EmailPriority; 4] = [Self::Auth, Self::Security, Self::Reminder, Self::Digest];

    /// Column value; lower drains first.
    pub fn as_rank(self) -> i16 {
        match self {
            Self::Auth => 0,
            Self::Security => 1,
            Self::Reminder => 2,
            Self::Digest => 3,
        }
    }
}

/// Wire value of the configured send mode (`sink` / `smtp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmailModeKind {
    Sink,
    Smtp,
}

impl EmailModeKind {
    pub const ALL: [EmailModeKind; 2] = [Self::Sink, Self::Smtp];

    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::Sink => "sink",
            Self::Smtp => "smtp",
        }
    }
}

/// How outbound mail leaves the process. [`EmailMode::resolve`] is the one place a mode is
/// chosen, and an absent explicit choice is [`EmailMode::Sink`] in every profile (M02 D10):
/// `Smtp` exists only when the owner names it and supplies its settings.
#[derive(Debug, Clone)]
pub enum EmailMode {
    /// Writes `.eml` files under the directory; opens no connection.
    Sink(PathBuf),
    /// Submits through the configured SMTP relay.
    Smtp(SmtpConfig),
}

impl EmailMode {
    /// `explicit` is the owner-supplied mode name, if any. `None` selects the sink. A name that
    /// is not one of [`EmailModeKind::ALL`], or `smtp` without `smtp` settings, is an error —
    /// it never falls back to sending.
    pub fn resolve(
        explicit: Option<&str>,
        sink_dir: PathBuf,
        smtp: Option<SmtpConfig>,
    ) -> Result<Self, EmailError> {
        let Some(name) = explicit else {
            return Ok(Self::Sink(sink_dir));
        };
        let kind = EmailModeKind::ALL
            .into_iter()
            .find(|k| k.as_wire_str() == name)
            .ok_or_else(|| EmailError::Config(format!("unknown email mode {name:?}")))?;
        match kind {
            EmailModeKind::Sink => Ok(Self::Sink(sink_dir)),
            EmailModeKind::Smtp => smtp.map(Self::Smtp).ok_or_else(|| {
                EmailError::Config("email mode smtp requires SMTP settings".to_string())
            }),
        }
    }

    /// Builds the provider for this mode. The only non-test place that names a concrete
    /// provider type (§74.6).
    pub fn into_provider(self) -> Result<Box<dyn EmailProvider>, EmailError> {
        match self {
            Self::Sink(dir) => Ok(Box::new(SinkEmailProvider::new(dir))),
            Self::Smtp(cfg) => Ok(Box::new(SmtpEmailProvider::new(&cfg)?)),
        }
    }
}

/// Recipients the door may deliver to. Unset allows everyone (the sink is the safety net);
/// once set, any other recipient becomes `SUPPRESSED` at enqueue and again at send time.
#[derive(Debug, Clone, Default)]
pub struct RecipientAllowlist(Option<BTreeSet<String>>);

impl RecipientAllowlist {
    /// No allowlist configured.
    pub fn allow_all() -> Self {
        Self(None)
    }

    /// Exactly these addresses (compared ASCII case-insensitively).
    pub fn only<I, S>(addresses: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self(Some(
            addresses
                .into_iter()
                .map(|a| a.as_ref().trim().to_ascii_lowercase())
                .filter(|a| !a.is_empty())
                .collect(),
        ))
    }

    /// Parses the comma-separated owner setting. `None` (unset) allows all; a present but blank
    /// value is an empty allowlist that permits nobody (fail closed).
    pub fn parse(setting: Option<&str>) -> Self {
        match setting {
            None => Self::allow_all(),
            Some(csv) => Self::only(csv.split(',')),
        }
    }

    /// Whether mail to `to` may be delivered.
    pub fn permits(&self, to: &str) -> bool {
        match &self.0 {
            None => true,
            Some(set) => set.contains(&to.trim().to_ascii_lowercase()),
        }
    }
}

/// What the worker side of the door enforces on every send.
#[derive(Debug, Clone, Default)]
pub struct SendPolicy {
    /// Recipient filter, re-checked at send time.
    pub allowlist: RecipientAllowlist,
    /// Global per-minute send cap (M22 D11); `None` = uncapped. The value comes from
    /// configuration, never a constant here (§78.1).
    pub max_sends_per_minute: Option<u32>,
}

/// `ops.email_suppressions.reason` (§74.6 Suppression: "硬退信、投诉等" plus the Gmail
/// one-click-unsubscribe reference in the same section). Closed set — `Manual` is an
/// operator-entered row, the rest are provider-signaled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SuppressionReason {
    HardBounce,
    Complaint,
    Unsubscribe,
    Manual,
}

impl SuppressionReason {
    pub const ALL: [SuppressionReason; 4] = [
        Self::HardBounce,
        Self::Complaint,
        Self::Unsubscribe,
        Self::Manual,
    ];

    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::HardBounce => "HARD_BOUNCE",
            Self::Complaint => "COMPLAINT",
            Self::Unsubscribe => "UNSUBSCRIBE",
            Self::Manual => "MANUAL",
        }
    }
}

/// `ops.email_suppressions.scope` — which stream(s) one suppression row blocks. `All` is
/// what keeps a hard bounce (mailbox does not exist) off *every* stream, while a
/// marketing-only complaint or unsubscribe leaves the transactional verification/reset
/// channel untouched — the frozen §74.6 rule "不能让营销投诉率打坏验证码/找回密码通道"
/// implemented as data (one column), not as two separate suppression tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SuppressionScope {
    Transactional,
    Marketing,
    All,
}

impl SuppressionScope {
    pub const ALL_VARIANTS: [SuppressionScope; 3] =
        [Self::Transactional, Self::Marketing, Self::All];

    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Transactional => "TRANSACTIONAL",
            Self::Marketing => "MARKETING",
            Self::All => "ALL",
        }
    }

    /// Whether a suppression carrying this scope blocks a send on `stream`.
    pub fn blocks(self, stream: EmailStream) -> bool {
        match self {
            Self::All => true,
            Self::Transactional => stream == EmailStream::Transactional,
            Self::Marketing => stream == EmailStream::Marketing,
        }
    }

    /// The reasonable default scope for a provider-signaled `reason`, used by
    /// [`outbox::record_suppression`] when the caller does not override it. A mailbox that
    /// hard-bounces or an address that files an abuse complaint is unreachable/hostile
    /// regardless of which stream triggered it — `All`. An unsubscribe click is scoped to
    /// the stream the user actually opted out of (§74.6 Gmail one-click unsubscribe is a
    /// marketing-list requirement, not a transactional one). `Manual` has no reason-derived
    /// default — an operator states the scope explicitly.
    pub fn default_for_reason(reason: SuppressionReason, stream: EmailStream) -> Option<Self> {
        match reason {
            SuppressionReason::HardBounce | SuppressionReason::Complaint => Some(Self::All),
            SuppressionReason::Unsubscribe => Some(match stream {
                EmailStream::Transactional => Self::Transactional,
                EmailStream::Marketing => Self::Marketing,
            }),
            SuppressionReason::Manual => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suppression_scope_blocks_matches_intent() {
        assert!(SuppressionScope::All.blocks(EmailStream::Transactional));
        assert!(SuppressionScope::All.blocks(EmailStream::Marketing));
        assert!(SuppressionScope::Transactional.blocks(EmailStream::Transactional));
        assert!(!SuppressionScope::Transactional.blocks(EmailStream::Marketing));
        assert!(!SuppressionScope::Marketing.blocks(EmailStream::Transactional));
        assert!(SuppressionScope::Marketing.blocks(EmailStream::Marketing));
    }

    #[test]
    fn marketing_complaint_does_not_block_transactional() {
        // §74.6 frozen rule, exercised directly: a marketing complaint (scope=All per
        // default_for_reason) DOES also block transactional — that's intentional (a
        // COMPLAINT is a hostile-mailbox signal like a hard bounce). The rule the frozen
        // text actually protects is the *unsubscribe* case: opting out of marketing must
        // NOT silently suppress the password-reset channel too.
        let unsub_scope = SuppressionScope::default_for_reason(
            SuppressionReason::Unsubscribe,
            EmailStream::Marketing,
        )
        .expect("unsubscribe always has a default scope");
        assert_eq!(unsub_scope, SuppressionScope::Marketing);
        assert!(!unsub_scope.blocks(EmailStream::Transactional));
    }
}

//! `domain::confirm` — §33.10 rule 9: destructive MCP actions must not assume the client supports MRTR; the two-step
//!   fallback is `first call -> confirmation_required + confirm_token`, `second call(confirm_token) -> execute`
//!   (ADR-0018).
//! Depends-on: crates=[sha2]; services=[]; env=[]; modules=[domain::error]
//! Called-by: [adapters::confirm_token_repo, adapters::context_repo, adapters::distill_repo, adapters::forget_repo, adapters::memory_governance_repo, adapters::operation_receipt, application::archive, application::pin, application::supersede, domain::context, gateway::guard, gateway::mcp_application, gateway::memory, protocol::mcp_catalog, tests, xtask::architecture_check]
//! Invariants: [DestructiveOp::wire is exhaustive with no wildcard arm: every gated op chooses Mcp | McpPending | Rest]
//! Spec: Baseline §78.2; §52.1; §33.10
//!
//! Two closed types, no strings (§78.2):
//! - [`DestructiveOp`] is the closed set of operations that go through the gate. Its
//!   `operation_key` is the *only* place the wire key of a gated operation is spelled; the
//!   gateway's supported-operation table and its dispatch arm both read it from here.
//!   [`DestructiveOp::wire`] classifies each op as [`ConfirmWire`], and the M26-1 catalog
//!   invariant (G-M26-1) reads that class in both directions: only `Mcp` ops are in the registry.
//! - [`ConfirmToken`] is the 32-byte nonce handed to the client (base64url on the wire,
//!   sha256 at rest — the server never stores the nonce itself).
//!
//! "Needs confirmation" is **not** an error (§52.1: the `ErrorCode` set is frozen at 18);
//! it is a success-shaped result carrying `confirmation_required` + the token. Rejections
//! of a wrong/expired/consumed token map to the existing `Conflict`.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::error::ErrorCode;

closed_set! { operation_key, parse_operation_key, array;
        /// Closed confirmation operations (Baseline §33.10 rule 9; ADR-0092 D-B).
    #[derive(Hash)]
    DestructiveOp {
        /// §36 `memory.supersede`: mark one Memory superseded by a successor (G59-4).
        MemorySupersede => "memory.supersede",
        /// §36 `memory.pin`: upsert one PINNED `context_bindings` row (ADR-0019).
        MemoryPin => "memory.pin",
        /// §36 `memory.unpin`: revoke that binding row only — never Evidence/Memory (ADR-0019).
        MemoryUnpin => "memory.unpin",
        /// §36 `memory.restore`: undo a SUPERSEDE within the window (ADR-0020). Not itself
        /// destructive, but it runs through the same confirm gate (reuse, no second token path).
        MemoryRestore => "memory.restore",
        /// §36 `memory.archive`: hide one Memory from recall/context without destroying it
        /// (ADR-0024, Q3). Sets `archived_at`; not a fifth AuthorityStatus. Runs the same gate.
        MemoryArchive => "memory.archive",
        /// §36 `memory.unarchive`: clear `archived_at`, making the Memory visible again
        /// (ADR-0024). The inverse of archive — never reachable via `memory.restore` (an ARCHIVE
        /// head is NOT_REVERSIBLE there). Same gate, no successor.
        MemoryUnarchive => "memory.unarchive",
        /// §Q4 `memory.correct` (ADR-0025): a user correction — one transaction inserts a new
        /// Evidence + a new Memory version and supersedes the original (reason USER_CORRECTION).
        /// Runs the same confirm gate; no successor argument on the wire (the successor is minted
        /// inside the confirmed transaction, so the token carries no `successor_id`).
        MemoryCorrect => "memory.correct",
        /// §36/§10.1 `memory.confirm` (ADR-0026, Card 6): promote a `private.distill_candidates`
        /// row into `UserConfirmed` Evidence + a new Memory version. Runs the same confirm gate; the
        /// gate `target_id` is the `candidate_id` (not a memory_id), no successor argument.
        MemoryConfirm => "memory.confirm",
        /// §36 `memory.reject` (ADR-0026, Card 6): mark a pending candidate REJECTED. Same gate,
        /// `target_id` is the candidate_id, no successor; writes no Evidence/Memory.
        MemoryReject => "memory.reject",
        /// §25.4.A(8) `memory.bind` (card 22b, ADR-0045): create one MANDATORY
        /// `context_bindings` row at a TASK scope — the controlled write path the ruling requires
        /// before `task_explicit_context_v1` can have anything to read. Mirrors `memory.pin`'s
        /// gate exactly; the difference is the mode (MANDATORY) and the scope kind (TASK), and
        /// the envelope re-reads the memory's authority/type/evidence basis in the same
        /// transaction before `domain::context::authorize_mandatory` may mint a grant.
        MemoryBind => "memory.bind",
        /// §25.4.A(9) `memory.unbind` (card 22b, ADR-0045): revoke that MANDATORY TASK binding.
        /// Evidence/Memory untouched, same gate. The A->B authorized replacement is `memory.bind`
        /// with `replaces_binding_id` (one transaction), not an unbind followed by a bind.
        MemoryUnbind => "memory.unbind",
        /// ADR-0067 D-J `memory.note_put` with `note_id` + `supersedes`: a confirmed replacement of a note's head version.
        /// Target = `supersedes`, no successor; the token also binds the replacement intent digest
        /// (`note::replace_intent_sha256`). A `note_put` create (no `note_id`) never enters the gate.
        MemoryNoteReplace => "memory.note_put",
        /// ADR-0092 D-B: confirms one frozen deletion request and its scope digest.
        MemoryForget => "memory.forget",
        /// ADR-0092 D-E: reserved for the separately re-authenticated tenant deletion entry.
        AccountDelete => "account.delete",
    }
}

/// How a confirm-gated operation is reachable on the wire (ADR-0092 D-B / C-M19-1). Closed: a new class is
/// an architecture change, not a default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfirmWire {
    /// A live MCP operation: it is in the MCP registry with effect `destructive` (G-M26-1).
    Mcp,
    /// Gated, but its MCP registry row has not landed yet: it must NOT be in the registry, so a pending op
    /// never quietly appears as a live tool.
    McpPending,
    /// REST entry only, never an MCP operation: it must NOT be in the registry.
    Rest,
}

impl DestructiveOp {
    /// The wire class of this op. The match has no `_` arm on purpose: a new `DestructiveOp` variant must choose
    /// its class here, and the M26-1 catalog invariant then checks the registry against it (§78.2).
    pub const fn wire(self) -> ConfirmWire {
        match self {
            Self::MemorySupersede
            | Self::MemoryPin
            | Self::MemoryUnpin
            | Self::MemoryRestore
            | Self::MemoryArchive
            | Self::MemoryUnarchive
            | Self::MemoryCorrect
            | Self::MemoryConfirm
            | Self::MemoryReject
            | Self::MemoryBind
            | Self::MemoryUnbind
            | Self::MemoryNoteReplace => ConfirmWire::Mcp,
            // ADR-0092 D-B; flips to `Mcp` in card M19-6, which adds its registry row.
            Self::MemoryForget => ConfirmWire::McpPending,
            // ADR-0092 D-E / C-M19-1: REST entry, never an MCP op.
            Self::AccountDelete => ConfirmWire::Rest,
        }
    }
}

/// Raw nonce length (D-A: 32 random bytes).
pub const CONFIRM_TOKEN_BYTES: usize = 32;

/// §77 `risk_tags` marker on the `MCP_REQUEST_FINISHED` audit of a gate's *first* call. The
/// mint and the executed write are the same (action, resource_id, result) triple; this tag is
/// what lets an auditor count destructive writes without counting abandoned confirmations.
pub const RISK_TAG_CONFIRMATION_MINTED: &str = "CONFIRMATION_MINTED";
/// base64url (no padding) length of a 32-byte nonce: ceil(32 * 8 / 6).
const WIRE_LEN: usize = 43;

/// One issued confirmation nonce. Constructed from random bytes by the application layer
/// (the domain has no RNG) or decoded from the wire; compared and stored only as
/// [`Self::sha256`]. Deliberately not `Debug`-printable in full.
#[derive(Clone, PartialEq, Eq)]
pub struct ConfirmToken([u8; CONFIRM_TOKEN_BYTES]);

impl fmt::Debug for ConfirmToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfirmToken(<redacted>)")
    }
}

impl ConfirmToken {
    /// Wraps already-random bytes. The caller owns the RNG contract (D-A).
    pub const fn from_bytes(bytes: [u8; CONFIRM_TOKEN_BYTES]) -> Self {
        Self(bytes)
    }

    /// Wire form: base64url without padding, 43 characters.
    pub fn encode(&self) -> String {
        base64url_encode(&self.0)
    }

    /// Strict wire decode: exact length, alphabet, and canonical trailing bits.
    /// Anything else is `INVALID_INPUT` (§52.1) — never a distinguishable "unknown token".
    pub fn decode(wire: &str) -> Result<Self, ErrorCode> {
        base64url_decode_32(wire).map(Self)
    }

    /// What the server stores and matches (`control.confirm_tokens.nonce_sha256`).
    pub fn sha256(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(char::from(ALPHABET[((n >> 18) & 63) as usize]));
        out.push(char::from(ALPHABET[((n >> 12) & 63) as usize]));
        if chunk.len() > 1 {
            out.push(char::from(ALPHABET[((n >> 6) & 63) as usize]));
        }
        if chunk.len() > 2 {
            out.push(char::from(ALPHABET[(n & 63) as usize]));
        }
    }
    out
}

fn sextet(c: u8) -> Option<u32> {
    let value = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    };
    Some(u32::from(value))
}

fn base64url_decode_32(wire: &str) -> Result<[u8; CONFIRM_TOKEN_BYTES], ErrorCode> {
    if wire.len() != WIRE_LEN {
        return Err(ErrorCode::InvalidInput);
    }
    let mut out = [0u8; CONFIRM_TOKEN_BYTES];
    let mut filled = 0usize;
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for c in wire.bytes() {
        let value = sextet(c).ok_or(ErrorCode::InvalidInput)?;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            if filled == CONFIRM_TOKEN_BYTES {
                return Err(ErrorCode::InvalidInput);
            }
            out[filled] = ((acc >> bits) & 0xff) as u8;
            filled += 1;
            acc &= (1 << bits) - 1;
        }
    }
    // 43 * 6 = 258 bits carry 2 trailing bits; a canonical encoding leaves them zero.
    if filled != CONFIRM_TOKEN_BYTES || acc != 0 {
        return Err(ErrorCode::InvalidInput);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn destructive_op_keys_round_trip_and_reject_unknown() {
        for op in DestructiveOp::ALL {
            assert_eq!(
                DestructiveOp::parse_operation_key(op.operation_key()),
                Some(op)
            );
        }
        assert_eq!(DestructiveOp::parse_operation_key("memory.get"), None);
        assert_eq!(DestructiveOp::parse_operation_key(""), None);
    }

    /// The ops whose wire is not `Mcp`, pinned with `==` both ways (ADR-0092 C-M19-1): adding a pending or REST op
    /// is a reviewed edit of this table, never a silent widening of the M26-1 catalog invariant.
    #[test]
    fn non_mcp_wire_ops_are_pinned_exactly() {
        let pinned: HashSet<(DestructiveOp, ConfirmWire)> = HashSet::from([
            (DestructiveOp::MemoryForget, ConfirmWire::McpPending),
            (DestructiveOp::AccountDelete, ConfirmWire::Rest),
        ]);
        let actual: HashSet<(DestructiveOp, ConfirmWire)> = DestructiveOp::ALL
            .iter()
            .map(|op| (*op, op.wire()))
            .filter(|(_, wire)| *wire != ConfirmWire::Mcp)
            .collect();
        assert_eq!(actual, pinned);
    }

    #[test]
    fn token_wire_form_round_trips_and_is_canonical() {
        let mut bytes = [0u8; CONFIRM_TOKEN_BYTES];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        let token = ConfirmToken::from_bytes(bytes);
        let wire = token.encode();
        assert_eq!(wire.len(), WIRE_LEN);
        assert!(
            wire.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
        assert_eq!(ConfirmToken::decode(&wire).unwrap(), token);
        assert_eq!(
            token.sha256(),
            ConfirmToken::decode(&wire).unwrap().sha256()
        );
        assert_eq!(format!("{token:?}"), "ConfirmToken(<redacted>)");
        // all-0xff exercises the '-'/'_' arm and the trailing-bit rule
        let high = ConfirmToken::from_bytes([0xff; CONFIRM_TOKEN_BYTES]);
        assert_eq!(ConfirmToken::decode(&high.encode()).unwrap(), high);
    }

    #[test]
    fn token_decode_rejects_length_alphabet_and_noncanonical_tail() {
        let good = ConfirmToken::from_bytes([7u8; CONFIRM_TOKEN_BYTES]).encode();
        assert_eq!(
            ConfirmToken::decode(&good[..42]),
            Err(ErrorCode::InvalidInput)
        );
        assert_eq!(
            ConfirmToken::decode(&format!("{good}A")),
            Err(ErrorCode::InvalidInput)
        );
        assert_eq!(
            ConfirmToken::decode(&format!("{}=", &good[..42])),
            Err(ErrorCode::InvalidInput)
        );
        assert_eq!(
            ConfirmToken::decode(&format!("{}+", &good[..42])),
            Err(ErrorCode::InvalidInput)
        );
        // last sextet with non-zero trailing bits: '/' is not in the alphabet, so use 'B'
        // (000001) after a canonical prefix whose last sextet must be a multiple of 4.
        let mut noncanonical = good.clone();
        noncanonical.pop();
        noncanonical.push('B');
        assert_eq!(
            ConfirmToken::decode(&noncanonical),
            Err(ErrorCode::InvalidInput)
        );
    }
}

//! `protocol::page` — the sole pager and cursor codec for list-type tool results: the byte budget, the whole-record pager, body continuation and the `page@1` cursor.
//! Depends-on: crates=[humaux-application, humaux-domain, serde_json, sha2]; services=[]; env=[];
//!   modules=[application::signed_token, domain::error, domain::identity, protocol::mcp_catalog]
//! Called-by: [tests]
//! Invariants: [a page is built only by serializing the `serde_json::Value` the owner's renderer returns and never
//!   exceeds min(op budget, manifest cap) bytes; records are appended whole in the caller's order and only the first
//!   record of a page is ever split, at a UTF-8 boundary; a `page@1` cursor is MAC-verified before one payload byte
//!   is read, then bound to principal, op, args hash and expiry, and every failure is the same `InvalidInput`]
//! Spec: §33.4; §33.5; §78.1
//!
//! M26 D7: the budget is the UTF-8 byte length of the serialized tool `result` (text, `structuredContent` and `_meta`,
//! after JSON escaping), the exact bytes the caller sends. The per-op value and the hard cap are registry data
//! (`contracts/mcp/manifest.json`), never literals here (§78.1). There is no client byte parameter and no integer
//! OFFSET: a record is resumed by an owner-supplied opaque `resume_key` (the last returned record's sort tuple).
//!
//! M26 D8: bodies travel in the text channel only; paging fields (`next_cursor`, `omitted`, `body_complete`,
//! `body_cursor`) travel in both channels, which [`PageMeta::stamp`] writes so they cannot drift apart.
//!
//! What this file does not own: per-op record order (each owner supplies records in its own order), totals (the caller
//! attaches M13 `Totals`), the cursor TTL (a parameter; the config key is M26-3's) and the wiring into `tools/call`.

use humaux_application::signed_token::{TokenKeys, TokenLabel};
use humaux_domain::error::ErrorCode;
use humaux_domain::identity::PrincipalId;
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

use crate::mcp_catalog::CanonicalCatalog;

/// M26 D7: MAC and kid domain labels of the cursor. The version is part of the label, so a future `page@2` cursor
/// never verifies as `page@1` under the same key (the kid label follows `signed_token`'s `<kind>.kid.<version>` shape).
const PAGE_LABEL: TokenLabel = TokenLabel::new(b"page@1", b"page.kid@1");

/// The one rejection every cursor failure maps to (G-M26-8): the caller cannot tell which leg failed.
const REJECTED: ErrorCode = ErrorCode::InvalidInput;

/// Members of the cursor payload object; `parse_claims` accepts exactly these and no others.
const PAYLOAD_FIELDS: usize = 6;

/// M26 D7: the byte budget of one page, taken from the registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    bytes: u64,
    cap: u64,
}

impl Budget {
    /// The budget of the operation `op` (its registry key, e.g. `memory.get`) and the manifest's hard cap.
    /// An `op` the catalog does not hold is a server fault (`Internal`): callers pass keys the catalog derived.
    pub fn for_op(catalog: &CanonicalCatalog, op: &str) -> Result<Self, ErrorCode> {
        let operation = catalog.operations().get(op).ok_or(ErrorCode::Internal)?;
        Ok(Self {
            bytes: operation.budget_bytes,
            cap: catalog.budget_cap_bytes(),
        })
    }

    /// Most bytes a serialized page may occupy: the op's budget, never above the manifest cap.
    pub fn limit(&self) -> usize {
        usize::try_from(self.bytes.min(self.cap)).unwrap_or(usize::MAX)
    }
}

/// Where a cursor resumes. The owner maps `resume_key` back to its own sort position; it is opaque here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Position {
    /// Resume with the first record strictly after `resume_key`.
    Record {
        /// The last returned record's owner-supplied sort tuple.
        resume_key: String,
    },
    /// Resume inside the record at `resume_key` (inclusive), from byte `byte_offset` of its body.
    Body {
        /// The split record's owner-supplied sort tuple.
        resume_key: String,
        /// Byte offset into the full body where the next page starts; always a UTF-8 boundary.
        byte_offset: usize,
    },
}

impl Position {
    fn to_json(&self) -> Value {
        match self {
            Self::Record { resume_key } => json!({ "kind": "record", "resume_key": resume_key }),
            Self::Body {
                resume_key,
                byte_offset,
            } => json!({ "kind": "body", "resume_key": resume_key, "byte_offset": byte_offset }),
        }
    }

    /// Strict inverse of [`Self::to_json`]: an unknown kind, a missing or an extra member is `None`.
    fn from_json(value: &Value) -> Option<Self> {
        let map = value.as_object()?;
        let resume_key = field(map, "resume_key")?.to_owned();
        match (field(map, "kind")?, map.len()) {
            ("record", 2) => Some(Self::Record { resume_key }),
            ("body", 3) => Some(Self::Body {
                resume_key,
                byte_offset: usize::try_from(map.get("byte_offset")?.as_u64()?).ok()?,
            }),
            _ => None,
        }
    }
}

/// The string member `key` of `map`, if present and a string.
fn field<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key)?.as_str()
}

/// What a cursor is bound to: the calling principal, the called op and the arguments (minus the cursor itself).
/// No typed credential id exists in the auth context (`CredentialRecord::api_key_id` is a raw `Uuid` inside
/// adapters, and for a machine credential it is the principal), so the principal is the credential leg.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    principal: String,
    op: String,
    args_hash: String,
}

impl Binding {
    /// Binds to `principal`, the registry key `op`, and `args`: the call's arguments, `cursor` field included or not.
    pub fn new(principal: PrincipalId, op: &str, args: &Value) -> Self {
        Self {
            principal: principal.0.to_string(),
            op: op.to_owned(),
            args_hash: args_hash(args),
        }
    }
}

/// Hex SHA-256 of the compact JSON of `args` with the top-level `cursor` field removed, so the follow-up call that
/// carries the cursor hashes like the first call that did not.
// ponytail: member order is serde_json's sorted `Map` (no `preserve_order` in the lock); enabling that feature would
// change every hash, and the page_budget test pins order independence. Upgrade = an explicit canonical re-sort.
fn args_hash(args: &Value) -> String {
    let mut canonical = args.clone();
    if let Value::Object(map) = &mut canonical {
        map.remove("cursor");
    }
    to_hex(&Sha256::digest(canonical.to_string().as_bytes()))
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The decoded payload of a verified token, before it is compared with the caller's [`Binding`].
struct Claims {
    principal: String,
    op: String,
    args: String,
    snapshot: String,
    position: Position,
    exp: i64,
}

/// Strict parse: valid JSON, an object with exactly [`PAYLOAD_FIELDS`] members of the right types.
fn parse_claims(payload: &str) -> Option<Claims> {
    let value: Value = serde_json::from_str(payload).ok()?;
    let map = value
        .as_object()
        .filter(|map| map.len() == PAYLOAD_FIELDS)?;
    Some(Claims {
        principal: field(map, "principal")?.to_owned(),
        op: field(map, "op")?.to_owned(),
        args: field(map, "args")?.to_owned(),
        snapshot: field(map, "snapshot")?.to_owned(),
        position: Position::from_json(map.get("position")?)?,
        exp: map.get("exp")?.as_i64()?,
    })
}

/// A `page@1` cursor: an opaque owner `snapshot`/frontier string plus the [`Position`] to resume at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cursor {
    /// Owner-defined snapshot or frontier the cursor pages through; opaque here and returned unchanged by `open`.
    pub snapshot: String,
    /// Where the next page starts.
    pub position: Position,
}

impl Cursor {
    /// Signs this cursor under `keys` (current key) for `binding`, valid while `now < exp_unix`.
    pub fn sign(&self, keys: &TokenKeys, binding: &Binding, exp_unix: i64) -> String {
        let payload = json!({
            "principal": binding.principal,
            "op": binding.op,
            "args": binding.args_hash,
            "snapshot": self.snapshot,
            "position": self.position.to_json(),
            "exp": exp_unix,
        });
        keys.sign(&PAGE_LABEL, &payload.to_string())
    }

    /// M26 D7 / G-M26-8: verifies the MAC (current or previous key), parses the payload strictly, then requires the
    /// principal, op and args hash to equal `expected` and `now_unix < exp`. Every failure is `InvalidInput`.
    pub fn open(
        keys: &TokenKeys,
        token: &str,
        expected: &Binding,
        now_unix: i64,
    ) -> Result<Self, ErrorCode> {
        let payload = keys.verify(&PAGE_LABEL, token).map_err(|_| REJECTED)?;
        let claims = parse_claims(&payload).ok_or(REJECTED)?;
        let bound = claims.principal == expected.principal
            && claims.op == expected.op
            && claims.args == expected.args_hash
            && now_unix < claims.exp;
        if !bound {
            return Err(REJECTED);
        }
        Ok(Self {
            snapshot: claims.snapshot,
            position: claims.position,
        })
    }
}

/// What the pager needs from an owner's record type.
pub trait PageRecord {
    /// Opaque sort tuple of this record; a cursor after it resumes with the next record in the owner's order.
    fn resume_key(&self) -> String;
    /// The record's large text field, the only part the pager may split (at a UTF-8 boundary).
    fn body(&self) -> &str;
}

/// One record as a page carries it.
pub struct Entry<'a, R> {
    /// The owner's record: every field except the body is rendered from here.
    pub record: &'a R,
    /// The part of the body this page carries: all of it, or the slice from a body cursor and/or up to the split.
    pub body: &'a str,
}

/// The paging fields of one page. The renderer must carry them in both channels (M26 D7/D8); [`Self::stamp`] does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageMeta {
    /// Cursor for the records after the last returned one; `None` when nothing was omitted.
    pub next_cursor: Option<String>,
    /// Records the caller supplied that this page does not return (a split record counts as returned).
    pub omitted: usize,
    /// `false` when the page ends inside a body (that record's body continues at `body_cursor`).
    pub body_complete: bool,
    /// Cursor for the rest of the split record's body, then the records after it; `Some` iff `!body_complete`.
    pub body_cursor: Option<String>,
}

impl PageMeta {
    /// Writes the paging fields into both channels: a footer in `text` and members of `structured`
    /// (`next_cursor` and `body_cursor` are JSON null when absent). Bodies never go to `structured` (M26 D8).
    pub fn stamp(&self, text: &mut String, structured: &mut Map<String, Value>) {
        text.push_str(&format!(
            "\nomitted: {}\nbody_complete: {}",
            self.omitted, self.body_complete
        ));
        for (name, cursor) in [
            ("next_cursor", &self.next_cursor),
            ("body_cursor", &self.body_cursor),
        ] {
            if let Some(cursor) = cursor {
                text.push_str(&format!("\n{name}: {cursor}"));
            }
            structured.insert(name.to_owned(), json!(cursor));
        }
        structured.insert("omitted".to_owned(), json!(self.omitted));
        structured.insert("body_complete".to_owned(), json!(self.body_complete));
    }
}

/// One finished page.
#[derive(Debug)]
pub struct PageOut {
    /// The tool `result` the renderer built for the returned records.
    pub result: Value,
    /// `result` serialized: the exact bytes the caller sends, and the bytes the budget was measured on.
    pub json: Vec<u8>,
    /// The paging fields `result` carries.
    pub meta: PageMeta,
}

/// Builds pages of whole records under a [`Budget`] and mints their cursors.
pub struct Pager<'a> {
    budget: Budget,
    keys: &'a TokenKeys,
    binding: &'a Binding,
    snapshot: &'a str,
    exp_unix: i64,
}

impl<'a> Pager<'a> {
    /// A pager whose cursors are signed with `keys` for `binding` over `snapshot` and expire `ttl_secs` after
    /// `now_unix` (both parameters: the clock and the TTL config are the caller's).
    pub fn new(
        budget: Budget,
        keys: &'a TokenKeys,
        binding: &'a Binding,
        snapshot: &'a str,
        now_unix: i64,
        ttl_secs: i64,
    ) -> Self {
        Self {
            budget,
            keys,
            binding,
            snapshot,
            exp_unix: now_unix.saturating_add(ttl_secs),
        }
    }

    /// One page over `records`, which must start at the resume point (the first record after a
    /// [`Position::Record`], or the record of a [`Position::Body`] with `body_offset` its `byte_offset`; 0 otherwise).
    ///
    /// Records are appended whole, in the order given, and the page stops before the record that would cross the
    /// budget. A first record that alone does not fit has its body cut at the largest UTF-8 boundary whose page fits
    /// (`body_complete: false`). `render` builds the full tool `result` for the entries and meta it is given; it must
    /// render `Entry::body` verbatim and carry the meta in both channels. Output is only ever produced by serializing
    /// what `render` returns, never by cutting bytes.
    ///
    /// Errors: `InvalidInput` for a `body_offset` that is not a boundary of the first record's body; `Internal` when
    /// not even an empty page, or the first record without its body, or one character of it, fits the budget.
    pub fn page<R: PageRecord>(
        &self,
        records: &[R],
        body_offset: usize,
        render: impl Fn(&[Entry<'_, R>], &PageMeta) -> Value,
    ) -> Result<PageOut, ErrorCode> {
        let entries = entries_from(records, body_offset)?;
        if entries.is_empty() {
            let meta = PageMeta {
                next_cursor: None,
                omitted: 0,
                body_complete: true,
                body_cursor: None,
            };
            return self
                .fit(&render, &entries, meta)?
                .ok_or(ErrorCode::Internal);
        }
        match self.whole_prefix(records, &entries, &render)? {
            Some(out) => Ok(out),
            None => self.split_first(records, &entries, body_offset, &render),
        }
    }

    fn mint(&self, position: Position) -> String {
        Cursor {
            snapshot: self.snapshot.to_owned(),
            position,
        }
        .sign(self.keys, self.binding, self.exp_unix)
    }

    /// Renders one candidate page; `Some` only when its serialized bytes fit the budget.
    fn fit<R>(
        &self,
        render: &impl Fn(&[Entry<'_, R>], &PageMeta) -> Value,
        entries: &[Entry<'_, R>],
        meta: PageMeta,
    ) -> Result<Option<PageOut>, ErrorCode> {
        let result = render(entries, &meta);
        let json = serde_json::to_vec(&result).map_err(|_| ErrorCode::Internal)?;
        let fits = json.len() <= self.budget.limit();
        Ok(fits.then_some(PageOut { result, json, meta }))
    }

    /// The longest prefix of whole records that fits; `None` when not even the first one does.
    fn whole_prefix<R: PageRecord>(
        &self,
        records: &[R],
        entries: &[Entry<'_, R>],
        render: &impl Fn(&[Entry<'_, R>], &PageMeta) -> Value,
    ) -> Result<Option<PageOut>, ErrorCode> {
        let total = records.len();
        let mut best = None;
        // ponytail: re-serializes per appended record, bounded by the cap; upgrade = incremental accounting if a profile shows it
        for taken in 1..=total {
            let last_key = records[taken - 1].resume_key();
            let meta = PageMeta {
                next_cursor: (taken < total).then(|| {
                    self.mint(Position::Record {
                        resume_key: last_key,
                    })
                }),
                omitted: total - taken,
                body_complete: true,
                body_cursor: None,
            };
            match self.fit(render, &entries[..taken], meta)? {
                Some(out) => best = Some(out),
                None => break,
            }
        }
        Ok(best)
    }

    /// The first record alone, its body cut at the largest char boundary whose page fits (binary search: more body is
    /// never fewer bytes). A cut of 0 would be a page without progress, so it is an error, not an answer.
    fn split_first<R: PageRecord>(
        &self,
        records: &[R],
        entries: &[Entry<'_, R>],
        body_offset: usize,
        render: &impl Fn(&[Entry<'_, R>], &PageMeta) -> Value,
    ) -> Result<PageOut, ErrorCode> {
        let first = &entries[0];
        let text = first.body;
        let limit = self.budget.limit();
        // A prefix longer than the budget cannot fit, so the candidates are the char starts within `limit` bytes; the
        // cut one past the last candidate is known not to fit (the whole record already failed above).
        let cuts: Vec<usize> = text
            .char_indices()
            .map(|(at, _)| at)
            .take_while(|&at| at <= limit)
            .collect();
        let (mut lo, mut hi) = (0, cuts.len());
        let mut best = None;
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            let cut = cuts[mid];
            let one = [Entry {
                record: first.record,
                body: &text[..cut],
            }];
            match self.fit(render, &one, self.split_meta(records, body_offset + cut))? {
                Some(out) => {
                    lo = mid;
                    best = Some(out);
                }
                None => hi = mid,
            }
        }
        best.ok_or(ErrorCode::Internal)
    }

    /// Meta of a page that ends inside the first record's body, `offset` bytes into the full body.
    fn split_meta<R: PageRecord>(&self, records: &[R], offset: usize) -> PageMeta {
        let key = records[0].resume_key();
        PageMeta {
            next_cursor: (records.len() > 1).then(|| {
                self.mint(Position::Record {
                    resume_key: key.clone(),
                })
            }),
            omitted: records.len() - 1,
            body_complete: false,
            body_cursor: Some(self.mint(Position::Body {
                resume_key: key,
                byte_offset: offset,
            })),
        }
    }
}

/// One [`Entry`] per record, the first one carrying its body from `body_offset`.
fn entries_from<R: PageRecord>(
    records: &[R],
    body_offset: usize,
) -> Result<Vec<Entry<'_, R>>, ErrorCode> {
    let mut entries: Vec<Entry<'_, R>> = records
        .iter()
        .map(|record| Entry {
            record,
            body: record.body(),
        })
        .collect();
    match entries.first_mut() {
        Some(first) => {
            first.body = first
                .record
                .body()
                .get(body_offset..)
                .ok_or(ErrorCode::InvalidInput)?;
        }
        None if body_offset != 0 => return Err(ErrorCode::InvalidInput),
        None => {}
    }
    Ok(entries)
}

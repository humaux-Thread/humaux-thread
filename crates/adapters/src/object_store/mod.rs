//! `adapters::object_store` — C-M17-2: the `ObjectStore` port, its typed keys and prefixes, and the session temp-prefix
//!   constructor.
//! Depends-on: crates=[uuid]; services=[]; env=[]; modules=[]
//! Called-by: [adapters::audit_sink, adapters::object_store::fs, tests]
//! Invariants: [a key is `/`-separated segments of 1-128 chars from [A-Za-z0-9._-], each starting alphanumeric, at most
//!   1024 bytes in all, so `.`, `..`, dot-files, empty segments, backslash and NUL cannot be built; a prefix is the same
//!   grammar plus a mandatory trailing `/` and matches whole segments only; `temp_prefix` is the one constructor of
//!   `tmp/<tenant>/<session>/`; a malformed key or prefix is an InvalidInput io error before any store is touched]
//! Spec: Baseline §29; §78.2; ADR-0115
//!
//! ADR-0115 D-A keeps the original and every derived item of an upload session under one temp prefix of the fs
//! implementation ([`fs::FsObjectStore`], D12); `delete_prefix` is how that prefix is purged. Keys and prefixes are
//! parsed types, never raw strings (§78.2), so a path-escaping or ambiguous name cannot reach an implementation.
//! Parse failures are `std::io::Error` of kind `InvalidInput`: this port has no `ErrorCode` return (the fs impl's error
//! is `io::Error`), and §52 forbids a third error enum. Write-once is not a property of this port; it is the future
//! WORM adapter's job (`adapters::audit_sink`).

use std::io;

use uuid::Uuid;

pub mod fs;

/// Longest key in bytes, the S3 key limit, so a later S3 impl never rejects a key this module accepted.
const MAX_KEY_BYTES: usize = 1024;
/// Longest single segment in bytes.
const MAX_SEGMENT_BYTES: usize = 128;

/// A validated object key: `/`-separated segments, each 1-128 chars of `[A-Za-z0-9._-]` starting alphanumeric, at most
/// 1024 bytes in all (§78.2). `.`, `..`, dot-files, empty segments, a leading or trailing `/`, backslash and NUL are
/// unrepresentable. Ordering is byte order of the key text, the order `list_prefix` returns.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObjectKey(String);

impl ObjectKey {
    /// Parses `raw`; `InvalidInput` when it breaks the key grammar.
    pub fn parse(raw: &str) -> io::Result<Self> {
        if is_path(raw) {
            Ok(Self(raw.to_owned()))
        } else {
            Err(malformed("object key"))
        }
    }

    /// The key text, as recorded in `AuditBatch::exported_object` and in locators.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated key prefix: the key grammar plus a mandatory trailing `/`. It matches whole segments only, so
/// `tmp/t/s1/` never matches `tmp/t/s10/x`. There is no empty prefix: no operation can address a whole store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectPrefix(String);

impl ObjectPrefix {
    /// Parses `raw`; `InvalidInput` when it breaks the key grammar or lacks the trailing `/`.
    pub fn parse(raw: &str) -> io::Result<Self> {
        match raw.strip_suffix('/') {
            Some(body) if is_path(body) => Ok(Self(raw.to_owned())),
            _ => Err(malformed("object prefix")),
        }
    }

    /// The prefix text, always ending in `/`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What `head` reports about an object. Length only: anything more is a later card's contract change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectMeta {
    /// Object size in bytes.
    pub len: u64,
}

/// The temp prefix `tmp/<tenant>/<session>/` that holds an upload session's original and every derived item
/// (ADR-0115 D-A, module note D1). The one constructor of this shape; uuids are hyphenated lower-case.
pub fn temp_prefix(tenant_id: Uuid, session_id: Uuid) -> ObjectPrefix {
    ObjectPrefix(format!(
        "tmp/{}/{}/",
        tenant_id.hyphenated(),
        session_id.hyphenated()
    ))
}

/// Byte-store port (C-M17-2): the fs impl serves the single-node temp store, an S3 impl is deferred (D12).
///
/// Contract every implementation meets (`crates/adapters/tests/object_store_contract.rs`, G-M17-8): `put` creates or
/// replaces and is atomic to readers; `get` and `head` of a missing key are `Ok(None)`; `delete` of a missing key is
/// `Ok(())`; `delete_prefix` removes every object at any depth and returns the count, a missing prefix being `Ok(0)`;
/// `list_prefix` returns every key at any depth, sorted, matching whole segments.
// ponytail: sync std::fs port; async callers use spawn_blocking; upgrade = async port when the S3 impl lands (D12)
pub trait ObjectStore {
    /// Adapter-defined failure (the fs impl uses `std::io::Error`).
    type Error: std::error::Error;

    /// Creates or replaces the object at `key`; a concurrent reader sees the old bytes or the new, never a mix.
    fn put(&self, key: &ObjectKey, bytes: &[u8]) -> Result<(), Self::Error>;

    /// The bytes at `key`, `None` when there is no such object.
    fn get(&self, key: &ObjectKey) -> Result<Option<Vec<u8>>, Self::Error>;

    /// The size of the object at `key`, `None` when there is no such object.
    fn head(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>, Self::Error>;

    /// Removes the object at `key`; a missing key is `Ok(())`.
    fn delete(&self, key: &ObjectKey) -> Result<(), Self::Error>;

    /// Removes every object at any depth under `prefix` and returns how many; a missing prefix is `Ok(0)`.
    fn delete_prefix(&self, prefix: &ObjectPrefix) -> Result<u64, Self::Error>;

    /// Every key at any depth under `prefix`, sorted; empty for a missing prefix.
    fn list_prefix(&self, prefix: &ObjectPrefix) -> Result<Vec<ObjectKey>, Self::Error>;
}

fn is_segment(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    bytes.len() <= MAX_SEGMENT_BYTES
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn is_path(text: &str) -> bool {
    text.len() <= MAX_KEY_BYTES && text.split('/').all(is_segment)
}

fn malformed(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "malformed {what}: segments are 1-128 chars of [A-Za-z0-9._-] starting alphanumeric, joined by '/', at most 1024 bytes (a prefix also ends in '/')"
        ),
    )
}

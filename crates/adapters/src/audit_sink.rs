//! `adapters::audit_sink` — §77 Immutable Audit Sink export path.
//! Depends-on: crates=[humaux-domain, uuid]; services=[]; env=[]; modules=[adapters::object_store, domain::audit]
//! Called-by: []
//! Invariants: [no WORM object-store client ships here yet: the export call site writes through the object_store port
//!   only, and the one implementation, the fs temp store, is not a WORM sink and must not be wired to audit export, so no
//!   audit bytes are placed anywhere until a real WORM adapter implements the port]
//! Spec: Baseline §3; §78.3; ADR-0115
//!
//! The hash-chain itself (`AuditBatch`, `batch_hash`, `verify_chain`) is pure logic and
//! lives in `humaux_domain::audit` — Domain never touches an object store (§3/§78.3). This
//! module is the one place that will eventually call a real WORM/immutable object store to
//! place exported batch bytes; **no such adapter ships in this task** (tracked for Phase 13
//! — `crates/adapters/src/s3.rs` is the existing sibling placeholder for that client). What
//! exists here now is the export call site, written against the shared port
//! [`ObjectStore`] of `adapters::object_store` (C-M17-2, ADR-0115). Write-once semantics is
//! the future WORM adapter's job — the port does not enforce it, and the filesystem
//! implementation is a temp store, NOT a WORM sink.

use crate::object_store::{ObjectKey, ObjectStore};
use humaux_domain::audit::{self, AuditBatch};

/// Builds the next batch in a lineage and writes its payload through `store` at `object_key`
/// (§77 Audit Batch export path); `object_key.as_str()` is recorded as
/// [`AuditBatch::exported_object`]. `previous` is `None` only for the very first batch in a
/// lineage (chains from [`humaux_domain::audit::GENESIS_BATCH_HASH`]).
pub fn export_batch<S: ObjectStore>(
    store: &S,
    previous: Option<&AuditBatch>,
    seq_start: i64,
    seq_end: i64,
    payload: &[u8],
    object_key: &ObjectKey,
    created_at: std::time::SystemTime,
) -> Result<AuditBatch, S::Error> {
    let previous_batch_hash = previous
        .map(audit::batch_hash)
        .unwrap_or(audit::GENESIS_BATCH_HASH);
    store.put(object_key, payload)?;
    Ok(AuditBatch {
        seq_start,
        seq_end,
        previous_batch_hash,
        payload_hash: audit::payload_hash(payload),
        exported_object: object_key.as_str().to_owned(),
        created_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_store::fs::FsObjectStore;

    /// A unique temp directory that is removed on drop, so a failed assertion cannot leak it.
    struct Scratch(std::path::PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `FsObjectStore` as a test double for the port; it is not a WORM sink and is never wired to audit export.
    fn scratch_store() -> (Scratch, FsObjectStore) {
        let dir = std::env::temp_dir().join(format!("humaux-audit-sink-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir(&dir).unwrap();
        let store = FsObjectStore::new(dir.clone()).unwrap();
        (Scratch(dir), store)
    }

    #[test]
    fn export_batch_chains_from_genesis_when_no_previous() {
        let (_scratch, store) = scratch_store();
        let key = ObjectKey::parse("audit/batch-1").unwrap();
        let batch = export_batch(
            &store,
            None,
            1,
            100,
            b"payload-1",
            &key,
            std::time::SystemTime::UNIX_EPOCH,
        )
        .expect("fs store write succeeds");
        assert_eq!(batch.previous_batch_hash, audit::GENESIS_BATCH_HASH);
        assert_eq!(batch.exported_object, "audit/batch-1");
        assert_eq!(batch.payload_hash, audit::payload_hash(b"payload-1"));
        assert_eq!(store.get(&key).unwrap(), Some(b"payload-1".to_vec()));
    }

    #[test]
    fn export_batch_chains_from_previous_batch_hash() {
        let (_scratch, store) = scratch_store();
        let first = export_batch(
            &store,
            None,
            1,
            100,
            b"payload-1",
            &ObjectKey::parse("audit/batch-1").unwrap(),
            std::time::SystemTime::UNIX_EPOCH,
        )
        .unwrap();
        let second = export_batch(
            &store,
            Some(&first),
            101,
            200,
            b"payload-2",
            &ObjectKey::parse("audit/batch-2").unwrap(),
            std::time::SystemTime::UNIX_EPOCH,
        )
        .unwrap();
        assert_eq!(second.previous_batch_hash, audit::batch_hash(&first));
        assert!(audit::verify_chain(&[first, second]).is_ok());
    }
}

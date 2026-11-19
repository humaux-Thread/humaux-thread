//! `adapters::audit_sink` — §77 Immutable Audit Sink export path.
//! Depends-on: crates=[humaux-domain, uuid]; services=[]; env=[]; modules=[domain::audit]
//! Called-by: []
//! Invariants: [only a WORM object-store adapter may be wired in production; no WORM adapter ships here]
//! Spec: Baseline §3; §77; §78.3; ADR-0115

use humaux_domain::audit::{self, AuditBatch};

/// A validated, bound destination in the immutable audit store (§77).
pub trait AuditBlobSinkPort {
    /// Error reported by the underlying sink.
    type Error;

    /// Stable key of the object that `put` writes.
    fn object_key(&self) -> &str;

    /// Writes one batch payload at the bound key. Production adapters enforce write-once storage.
    fn put(&self, payload: &[u8]) -> Result<(), Self::Error>;
}

/// Builds the next batch in a lineage and writes its payload to the bound destination.
/// `previous` is `None` only for the first batch, which chains from
/// [`humaux_domain::audit::GENESIS_BATCH_HASH`].
pub fn export_batch<S: AuditBlobSinkPort>(
    sink: &S,
    previous: Option<&AuditBatch>,
    seq_start: i64,
    seq_end: i64,
    payload: &[u8],
    created_at: std::time::SystemTime,
) -> Result<AuditBatch, S::Error> {
    let previous_batch_hash = previous
        .map(audit::batch_hash)
        .unwrap_or(audit::GENESIS_BATCH_HASH);
    sink.put(payload)?;
    Ok(AuditBatch {
        seq_start,
        seq_end,
        previous_batch_hash,
        payload_hash: audit::payload_hash(payload),
        exported_object: sink.object_key().to_owned(),
        created_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_store::{ObjectKey, ObjectStore, fs::FsObjectStore};

    struct FsAuditBlob<'a> {
        store: &'a FsObjectStore,
        key: &'a ObjectKey,
    }

    impl AuditBlobSinkPort for FsAuditBlob<'_> {
        type Error = std::io::Error;

        fn object_key(&self) -> &str {
            self.key.as_str()
        }

        fn put(&self, payload: &[u8]) -> Result<(), Self::Error> {
            self.store.put(self.key, payload)
        }
    }

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
            &FsAuditBlob {
                store: &store,
                key: &key,
            },
            None,
            1,
            100,
            b"payload-1",
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
            &FsAuditBlob {
                store: &store,
                key: &ObjectKey::parse("audit/batch-1").unwrap(),
            },
            None,
            1,
            100,
            b"payload-1",
            std::time::SystemTime::UNIX_EPOCH,
        )
        .unwrap();
        let second = export_batch(
            &FsAuditBlob {
                store: &store,
                key: &ObjectKey::parse("audit/batch-2").unwrap(),
            },
            Some(&first),
            101,
            200,
            b"payload-2",
            std::time::SystemTime::UNIX_EPOCH,
        )
        .unwrap();
        assert_eq!(second.previous_batch_hash, audit::batch_hash(&first));
        assert!(audit::verify_chain(&[first, second]).is_ok());
    }
}

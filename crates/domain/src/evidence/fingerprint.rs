//! `domain::evidence::fingerprint` — the retrieval contract for the Evidence axis of §16.1.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: [domain::evidence, projection::fingerprint]
//! Invariants: [Only the owner supplies canonical Evidence digest hex]
//! Spec: Baseline §16.1; ADR-0130; ADR-0131

// Keep the seal visible only inside the evidence module, even within this crate.
pub(super) mod sealed {
    pub trait Sealed {}
}

/// Read-only access to the canonical Evidence digest for a processing fingerprint.
pub trait EvidenceFingerprintDigest: sealed::Sealed {
    /// The owner's fixed-width, lowercase hexadecimal encoding of the existing digest.
    fn fingerprint_hex(&self) -> String;
}

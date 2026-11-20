//! `domain::affect_read` — retrieval views of the owner's §8.5.1 affect data.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: [adapters::projection_worker, adapters::qdrant, adapters::read_materialize, adapters::retrieve, application::recall_read, domain::affect, projection::dense]
//! Invariants: [AffectReadFilter is issued by the owner; index fields are prefilter inputs only]
//! Spec: Baseline §8.5.1; ADR-0030; ADR-0130; ADR-0131

/// The owner's immutable recall query, shared by the index and exact-match reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffectReadFilter(Option<AffectPrefilter>);

impl AffectReadFilter {
    pub(crate) fn new(bounds: Option<AffectPrefilter>) -> Self {
        Self(bounds)
    }

    /// The candidate predicate bounds, or `None` for an unscoped filter.
    pub fn prefilter(&self) -> Option<&AffectPrefilter> {
        self.0.as_ref()
    }
}

/// Flat candidate prefilter inputs. Only the exact reader can decide whether an annotation matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffectPrefilter {
    /// Accepted kind wire values.
    pub kinds: Vec<&'static str>,
    /// Accepted label wire values.
    pub labels_any: Vec<&'static str>,
    /// Inclusive raw valence bounds.
    pub valence: Option<(i16, i16)>,
    /// Inclusive raw arousal bounds.
    pub arousal: Option<(i16, i16)>,
    /// Inclusive raw dominance bounds.
    pub dominance: Option<(i16, i16)>,
    /// Inclusive raw intensity bounds, a superset of the effective-intensity test.
    pub intensity: Option<(i16, i16)>,
}

/// The six §8.5.1 columns used to prefilter index candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AffectIndexRow(AffectIndexColumns);

impl AffectIndexRow {
    pub(crate) fn new(columns: AffectIndexColumns) -> Self {
        Self(columns)
    }

    /// Borrows the owner's raw values in their candidate-index representation.
    pub fn columns(&self) -> &AffectIndexColumns {
        &self.0
    }
}

/// Raw payload values published by the annotation owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AffectIndexColumns {
    /// Annotation kind wire value.
    pub kind: &'static str,
    /// Annotation label wire value.
    pub label: Option<&'static str>,
    /// Raw valence.
    pub valence: Option<i16>,
    /// Raw arousal.
    pub arousal: Option<i16>,
    /// Raw dominance.
    pub dominance: Option<i16>,
    /// Raw intensity before read-time decay.
    pub intensity: i16,
}

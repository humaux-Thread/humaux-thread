//! Controlled vocabulary validation shared with the offline gate (§12.3, ADR-0089 D-E).
//! Depends-on: crates=[toml]; services=[]; env=[]; modules=[]
//! Called-by: [public-pool::vocab, xtask::vocab_check]
//! Invariants: [stable ids; BROADER is an intra-facet DAG; replacements are active]
//! Spec: Baseline §12.3; §78.2; ADR-0089 D-E

use std::collections::{BTreeMap, BTreeSet};
use toml::Value;

// §78.2: public-plane types stay outside domain; one declaration generates ALL and wire labels.
macro_rules! closed_set {
    ($(#[$meta:meta])* $name:ident { $($(#[$vmeta:meta])* $variant:ident => $wire:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum $name { $($(#[$vmeta])* $variant),+ }
        impl $name {
            /// Complete contract-test set (§78.2).
            pub const ALL: &[Self] = &[$(Self::$variant),+];
            /// Stable CHECK label (§78.2).
            pub const fn as_str(self) -> &'static str { match self { $(Self::$variant => $wire),+ } }
            /// Reject unknown wire labels (§78.2).
            pub fn parse(value: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|v| v.as_str() == value)
            }
        }
    };
}
closed_set! {
    /// Vocabulary facets (ADR-0089 D-E).
    Facet {
        /// Curated domain.
        Domain => "domain",
        /// Curated task.
        Task => "task",
        /// Curated project type.
        ProjectType => "project_type",
        /// Curated industry.
        Industry => "industry",
        /// Phase-1 unit type.
        KnowledgeType => "knowledge_type",
        /// Content language.
        ContentLanguage => "content_language",
    }
}
closed_set! {
    /// Concept lifecycle (ADR-0089 D-E).
    Status {
        /// Current vocabulary.
        Active => "ACTIVE",
        /// Known wrong; requires an active successor.
        Deprecated => "DEPRECATED",
    }
}
closed_set! {
    /// Localised label role (ADR-0089 D-E).
    LabelKind {
        /// One preferred label per concept and language.
        Pref => "PREF",
        /// Alternative label.
        Alt => "ALT",
    }
}
closed_set! {
    /// Non-transitive public relations (ADR-0089 D-E).
    RelationKind {
        /// Intra-facet broader concept.
        Broader => "BROADER",
        /// Related concept.
        Related => "RELATED",
        /// Close external match.
        CloseMatch => "CLOSE_MATCH",
        /// Exact external match.
        ExactMatch => "EXACT_MATCH",
    }
}

/// One validated concept and its localised labels (§12.3).
#[derive(Debug)]
pub struct Concept {
    /// Immutable stable slug.
    pub id: String,
    /// Closed facet.
    pub facet: Facet,
    /// Closed lifecycle.
    pub status: Status,
    /// Active successor for known-wrong entries only.
    pub replaced_by: Option<String>,
    /// Source-backed meaning.
    pub definition: String,
    /// Complete labels, including one PREF for each represented language.
    pub labels: Vec<Label>,
}
/// One language-specific label (§12.3).
#[derive(Debug)]
pub struct Label {
    /// Language code.
    pub lang: String,
    /// Closed label role.
    pub kind: LabelKind,
    /// Display text.
    pub label: String,
}
/// A directed relation (§12.3).
#[derive(Debug)]
pub struct Relation {
    /// Source concept.
    pub from: String,
    /// Destination concept.
    pub to: String,
    /// Closed relation kind.
    pub kind: RelationKind,
}
/// Validated source of truth, shared by loader and G-M20-16 (§12.3).
#[derive(Debug)]
pub struct Vocabulary {
    /// Complete concept set.
    pub concepts: Vec<Concept>,
    /// Complete edge set.
    pub relations: Vec<Relation>,
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| format!("missing or empty {key}: {value}"))
}
fn slug(id: &str) -> bool {
    id.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && id.split(['-', '_']).all(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}
fn concept(value: &Value) -> Result<Concept, String> {
    let id = field(value, "concept_id")?.to_owned();
    if !slug(&id) {
        return Err(format!("{id}: invalid stable slug"));
    }
    let facet =
        Facet::parse(field(value, "facet")?).ok_or_else(|| format!("{id}: invalid facet"))?;
    let status =
        Status::parse(field(value, "status")?).ok_or_else(|| format!("{id}: invalid status"))?;
    let replaced_by = value
        .get("replaced_by")
        .map(|_| field(value, "replaced_by").map(str::to_owned))
        .transpose()?;
    let labels = value
        .get("labels")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{id}: missing labels"))?
        .iter()
        .map(|v| {
            Ok(Label {
                lang: field(v, "lang")?.to_owned(),
                kind: LabelKind::parse(field(v, "kind")?)
                    .ok_or_else(|| format!("{id}: invalid label kind"))?,
                label: field(v, "label")?.to_owned(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(Concept {
        id,
        facet,
        status,
        replaced_by,
        definition: field(value, "definition")?.to_owned(),
        labels,
    })
}
fn relation(value: &Value) -> Result<Relation, String> {
    Ok(Relation {
        from: field(value, "from_id")?.to_owned(),
        to: field(value, "to_id")?.to_owned(),
        kind: RelationKind::parse(field(value, "kind")?)
            .ok_or_else(|| format!("invalid relation: {value}"))?,
    })
}

impl Vocabulary {
    /// Parse and validate the entire document and append-only id lock (G-M20-16).
    pub fn parse(source: &str, lock: &str) -> Result<Self, Vec<String>> {
        let value: Value = source
            .parse()
            .map_err(|e| vec![format!("vocab_v1.toml: {e}")])?;
        let concepts = value
            .get("concepts")
            .and_then(Value::as_array)
            .ok_or_else(|| vec!["vocab_v1.toml: missing concepts".into()])?
            .iter()
            .map(concept)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| vec![e])?;
        let relations = value
            .get("relations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(relation)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| vec![e])?;
        let vocab = Self {
            concepts,
            relations,
        };
        let errors = vocab.validate(lock);
        if errors.is_empty() {
            Ok(vocab)
        } else {
            Err(errors)
        }
    }

    fn validate(&self, lock: &str) -> Vec<String> {
        let mut errors = Vec::new();
        let ids: BTreeMap<_, _> = self.concepts.iter().map(|c| (c.id.as_str(), c)).collect();
        let locked: Vec<_> = lock.lines().filter(|s| !s.is_empty()).collect();
        let locked_set: BTreeSet<_> = locked.iter().copied().collect();
        if locked.len() != locked_set.len() {
            errors.push("vocab_ids.lock: duplicate id".into());
        }
        for id in &locked_set {
            if !ids.contains_key(id) {
                errors.push(format!("{id}: removed or renamed locked id"));
            }
        }
        let mut seen = BTreeSet::new();
        let mut labels = BTreeSet::new();
        for c in &self.concepts {
            if !seen.insert(&c.id) {
                errors.push(format!("{}: duplicate concept id", c.id));
            }
            if !locked_set.contains(c.id.as_str()) {
                errors.push(format!("{}: id absent from vocab_ids.lock", c.id));
            }
            validate_replacement(c, &ids, &mut errors);
            validate_labels(c, &mut labels, &mut errors);
        }
        let mut edges: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        let mut unique = BTreeSet::new();
        for r in &self.relations {
            if !unique.insert((&r.from, &r.to, r.kind.as_str())) {
                errors.push(format!("{} -> {}: duplicate relation", r.from, r.to));
            }
            match (ids.get(r.from.as_str()), ids.get(r.to.as_str())) {
                (Some(a), Some(b)) if a.id != b.id => {
                    if r.kind == RelationKind::Broader {
                        if a.facet != b.facet {
                            errors.push(format!("{} -> {}: BROADER crosses facets", r.from, r.to));
                        }
                        edges.entry(&r.from).or_default().push(&r.to);
                    }
                }
                _ => errors.push(format!(
                    "{} -> {}: missing endpoint or self relation",
                    r.from, r.to
                )),
            }
        }
        for id in ids.keys() {
            if cycle(id, &edges, &mut BTreeSet::new(), &mut BTreeSet::new()) {
                errors.push(format!("{id}: BROADER cycle"));
            }
        }
        errors
    }
}
fn validate_replacement(c: &Concept, ids: &BTreeMap<&str, &Concept>, errors: &mut Vec<String>) {
    let valid = match (c.status, c.replaced_by.as_deref()) {
        (Status::Active, None) => true,
        (Status::Deprecated, Some(id)) if id != c.id => {
            ids.get(id).is_some_and(|v| v.status == Status::Active)
        }
        _ => false,
    };
    if !valid {
        errors.push(format!("{}: DEPRECATED needs replaced_by pointing to an ACTIVE concept; ACTIVE must not have replaced_by", c.id));
    }
}
fn validate_labels(
    c: &Concept,
    seen: &mut BTreeSet<(String, String, String)>,
    errors: &mut Vec<String>,
) {
    let mut prefs: BTreeMap<&str, usize> = BTreeMap::new();
    for l in &c.labels {
        *prefs.entry(&l.lang).or_default() += usize::from(l.kind == LabelKind::Pref);
        if !seen.insert((
            c.facet.as_str().into(),
            l.lang.clone(),
            l.label.to_lowercase(),
        )) {
            errors.push(format!(
                "{}: duplicate label ({}, {}, {})",
                c.id,
                c.facet.as_str(),
                l.lang,
                l.label
            ));
        }
    }
    if prefs.is_empty() || prefs.values().any(|n| *n != 1) {
        errors.push(format!("{}: exactly one PREF required per language", c.id));
    }
}
fn cycle<'a>(
    id: &'a str,
    edges: &BTreeMap<&'a str, Vec<&'a str>>,
    visiting: &mut BTreeSet<&'a str>,
    done: &mut BTreeSet<&'a str>,
) -> bool {
    if visiting.contains(id) {
        return true;
    }
    if done.contains(id) {
        return false;
    }
    visiting.insert(id);
    if edges
        .get(id)
        .is_some_and(|next| next.iter().any(|n| cycle(n, edges, visiting, done)))
    {
        return true;
    }
    visiting.remove(id);
    done.insert(id);
    false
}

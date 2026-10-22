//! `retrieval::rerank` — the pure half of the local rerank lane (ADR-0084): the pinned model identity and the one
//!   constructor of `provenance.rerank_model_id`, the order-only step, the settlement of an executor's answer, and the
//!   one place its degradations are emitted.
//! Depends-on: crates=[humaux-telemetry]; services=[]; env=[]; modules=[retrieval::envelope, telemetry::degrade]
//! Called-by: [gateway::bootstrap, gateway::recall, gateway::rerank_client, tests]
//! Invariants: [the rendered `provenance.rerank_model_id` is built by exactly one constructor, `RerankModelId::render`,
//!   and differs whenever any part of the D-A identity differs (the source scan `rerank_provenance_constructor` counts
//!   `== 1`); `order_by_score` only reorders: the output id set equals the input set, ties follow fused rank, and a
//!   reply that does not fit the request is `None`, never applied (G-RET-15); `settle` falls back to the fused order
//!   on every failure and never returns scores of a model other than the pinned one (ADR-0084 D-D); `degradations`
//!   holds the only two exits of `RERANK_PROVIDER_TIMEOUT` and `RERANK_MODEL_MISMATCH`, each through `abstain()`
//!   (§53.1)]
//! Spec: Baseline §23.1③; §23.3; §53.1; §53.4; ADR-0084 D-A; ADR-0084 D-C; ADR-0084 D-D
//!
//! No IO and no model: the gateway sends the texts and hands the answer to [`settle`]. The ordering step takes ids, not
//! documents, so G-RET-15 needs no model. `Id` is whatever identifies a visible candidate (a Memory id).

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use humaux_telemetry::degrade::{DegradeCode, abstain};

use crate::envelope::ProvenanceValue;

/// ADR-0084 D-A: the model identity `(repo, revision, recipe version, onnx sha256, tokenizer sha256)`. The pin the
/// gateway holds and the identity the worker reports are the same type, so "the model that answered is the pinned one"
/// is plain equality.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelIdentity {
    repo: String,
    revision: String,
    recipe: String,
    onnx_sha256: String,
    tokenizer_sha256: String,
}

impl ModelIdentity {
    /// The identity of the given parts, or `None` when a part cannot be told apart in the rendered id: `repo`,
    /// `revision` and `recipe` must be non-empty with no whitespace, control character or `#` (the separator of
    /// [`RerankModelId`]), and both hashes 64 lowercase hex characters. That makes the rendering injective.
    #[must_use]
    pub fn new(
        repo: &str,
        revision: &str,
        recipe: &str,
        onnx_sha256: &str,
        tokenizer_sha256: &str,
    ) -> Option<Self> {
        let word = |part: &str| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| !c.is_whitespace() && !c.is_control() && c != '#')
        };
        let hash = |part: &str| {
            part.len() == 64
                && part
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        (word(repo)
            && word(revision)
            && word(recipe)
            && hash(onnx_sha256)
            && hash(tokenizer_sha256))
        .then(|| Self {
            repo: repo.to_owned(),
            revision: revision.to_owned(),
            recipe: recipe.to_owned(),
            onnx_sha256: onnx_sha256.to_owned(),
            tokenizer_sha256: tokenizer_sha256.to_owned(),
        })
    }

    /// The rendered `provenance.rerank_model_id` of this identity (the only way to get one).
    #[must_use]
    pub fn model_id(&self) -> RerankModelId {
        RerankModelId::render(self)
    }
}

/// The rendered `provenance.rerank_model_id` (ADR-0084 D-C): one string that differs whenever any part of the identity
/// differs. The field is private and [`RerankModelId::render`] is the only constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RerankModelId(String);

impl RerankModelId {
    fn render(identity: &ModelIdentity) -> Self {
        RerankModelId(format!(
            "{}#{}#{}#{}#{}",
            identity.repo,
            identity.revision,
            identity.recipe,
            identity.onnx_sha256,
            identity.tokenizer_sha256
        ))
    }

    /// The id as it is written into the envelope.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// ADR-0084 D-C 5: `sent` ordered by score, highest first, ties by fused rank (the position in `visible`), followed by
/// every visible id that was not sent, in fused order. `scores` holds one raw logit per sent id, in `sent` order.
///
/// Order only: the result is a permutation of `visible`. `None` when the reply cannot be applied: a score count other
/// than `sent`'s, a non-finite score, a sent id that is not visible or sent twice, or a duplicate in `visible`.
#[must_use]
pub fn order_by_score<Id: Copy + Eq + Hash>(
    visible: &[Id],
    sent: &[Id],
    scores: &[f32],
) -> Option<Vec<Id>> {
    if scores.len() != sent.len() || scores.iter().any(|score| !score.is_finite()) {
        return None;
    }
    let mut fused_rank: HashMap<Id, usize> = HashMap::with_capacity(visible.len());
    for (position, id) in visible.iter().enumerate() {
        if fused_rank.insert(*id, position).is_some() {
            return None;
        }
    }
    let mut seen: HashSet<Id> = HashSet::with_capacity(sent.len());
    let mut scored: Vec<(Id, f32, usize)> = Vec::with_capacity(sent.len());
    for (id, score) in sent.iter().zip(scores) {
        let position = *fused_rank.get(id)?;
        if !seen.insert(*id) {
            return None;
        }
        // -0.0 and 0.0 are one score: a tie, ordered by fused rank.
        let score = if *score == 0.0 { 0.0 } else { *score };
        scored.push((*id, score, position));
    }
    scored.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.2.cmp(&b.2)));
    let mut order: Vec<Id> = scored.iter().map(|entry| entry.0).collect();
    order.extend(visible.iter().filter(|id| !seen.contains(*id)).copied());
    Some(order)
}

/// What the executor of one rerank call answered, as the gateway maps its transport onto it.
#[derive(Debug, Clone, Copy)]
pub enum Executor<'a> {
    /// Scores arrived within the timeout: one raw logit per sent document, in request order, and the identity the
    /// worker reported.
    Scored {
        /// One raw logit per sent document.
        scores: &'a [f32],
        /// The model identity the worker reported.
        model: &'a ModelIdentity,
    },
    /// No scores: a timeout, a transport error, a non-success or malformed reply, a count that differs from the
    /// request, a session error.
    Unavailable,
}

/// Why a selected rerank branch fell back to the fused order (ADR-0084 D-D rows 3 and 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RerankFailure {
    /// Timeout or any failure, or a reply that cannot be applied: `RERANK_PROVIDER_TIMEOUT`.
    Unavailable,
    /// The worker's identity differs from the pin; its scores were discarded: `RERANK_MODEL_MISMATCH`.
    ModelMismatch,
}

/// The outcome of one rerank stage for the visible Memories.
#[derive(Debug, Clone, PartialEq)]
pub struct Settlement<Id> {
    /// Every visible id, in the final order (a permutation of the input).
    pub order: Vec<Id>,
    /// Memories actually scored: the number sent on success, 0 on any fallback (ADR-0084 D-D).
    pub reranked_count: u32,
    /// `provenance.rerank_model_id`: `used` on success, `cannot_establish` on a failure, `not_applicable` when the
    /// branch did not run (§23.1③).
    pub model: ProvenanceValue,
    /// Set on a fallback; [`degradations`] turns it into the codes.
    pub failure: Option<RerankFailure>,
}

fn fallback<Id: Copy>(visible: &[Id], failure: RerankFailure) -> Settlement<Id> {
    Settlement {
        order: visible.to_vec(),
        reranked_count: 0,
        model: ProvenanceValue::CannotEstablish {},
        failure: Some(failure),
    }
}

/// A selected branch that could not call an executor at all (no lane is wired for a profile that turned it on): the
/// same fallback as an executor that answered nothing, so it is never silent (§23.1③).
#[must_use]
pub fn unavailable<Id: Copy>(visible: &[Id]) -> Settlement<Id> {
    fallback(visible, RerankFailure::Unavailable)
}

/// The stage that did not run (ADR-0084 D-D row 1: the lane is off or the tenant's policy skips it, or there was
/// nothing to score): the fused order, nothing reranked, `not_applicable`, no degradation.
#[must_use]
pub fn not_run<Id: Copy>(visible: &[Id]) -> Settlement<Id> {
    Settlement {
        order: visible.to_vec(),
        reranked_count: 0,
        model: ProvenanceValue::NotApplicable {},
        failure: None,
    }
}

/// ADR-0084 D-D rows 2 to 4 for a selected branch. `sent` are the ids whose texts were sent, in request order.
///
/// - Scores of the pinned model that fit the request: the rerank order, `reranked_count = sent.len()`, `used`.
/// - No scores, or a reply that cannot be applied: the fused order, 0, `cannot_establish`, [`RerankFailure::Unavailable`].
/// - A reply from another model: its scores are discarded, the fused order, 0, `cannot_establish`,
///   [`RerankFailure::ModelMismatch`]. Never a switch to another model.
#[must_use]
pub fn settle<Id: Copy + Eq + Hash>(
    visible: &[Id],
    sent: &[Id],
    pinned: &ModelIdentity,
    answer: Executor<'_>,
) -> Settlement<Id> {
    match answer {
        Executor::Unavailable => fallback(visible, RerankFailure::Unavailable),
        Executor::Scored { model, .. } if model != pinned => {
            fallback(visible, RerankFailure::ModelMismatch)
        }
        Executor::Scored { scores, .. } => match order_by_score(visible, sent, scores) {
            Some(order) => Settlement {
                order,
                reranked_count: u32::try_from(sent.len()).unwrap_or(u32::MAX),
                model: ProvenanceValue::Used {
                    id: pinned.model_id().0,
                },
                failure: None,
            },
            None => fallback(visible, RerankFailure::Unavailable),
        },
    }
}

/// ADR-0084 D-D / §53.1: the one place the rerank degradations fire, through `abstain()`. Call it once per answered
/// recall, when the envelope is assembled and never before the hydrate gate, so a later error leaves no counted
/// degrade without a finished retrieval. The result is still returned, so by §52.3 Q1 these are `DegradeCode`s and no
/// `ErrorCode`.
#[must_use]
pub fn degradations(failure: Option<RerankFailure>) -> Vec<DegradeCode> {
    match failure {
        None => Vec::new(),
        Some(RerankFailure::Unavailable) => abstain(DegradeCode::RerankProviderTimeout, ())
            .degradations
            .into_vec(),
        Some(RerankFailure::ModelMismatch) => abstain(DegradeCode::RerankModelMismatch, ())
            .degradations
            .into_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HEX_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn pin() -> ModelIdentity {
        ModelIdentity::new("org/model", "rev1", "recipe-v1", HEX_A, HEX_B)
            .expect("a valid identity")
    }

    /// G-RET-15 (ADR-0084 D-C 5): the result is a permutation of the visible ids: sent ids by score, ties by fused rank,
    /// then the ids that were not sent in fused order. `sent` is given in an order other than the fused one, so a tie
    /// broken by arrival order is a different list.
    /// Fault: break ties by `sent` order, or drop a low-score id ⇒ red.
    #[test]
    fn order_by_score_is_order_only_and_ties_follow_fused_rank() {
        let visible = [10_u32, 20, 30, 40, 50];
        // Sent: 40, 20, 30 (arrival order); 10 and 50 are not sent. 20 and 30 tie, and 20 is fused-earlier.
        let order = order_by_score(&visible, &[40, 30, 20], &[0.5, 0.9, 0.9]).expect("fits");
        assert_eq!(order, [20, 30, 40, 10, 50]);
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, visible, "the id set is unchanged");
        // A higher score always wins; negative logits are scores too.
        let order = order_by_score(&visible, &[10, 20, 30], &[-3.0, 2.0, -1.0]).expect("fits");
        assert_eq!(order, [20, 30, 10, 40, 50]);
        // Equal scores (0.0 and -0.0 included) fall back to fused rank entirely.
        let order = order_by_score(&visible, &[30, 10, 20], &[0.0, -0.0, 0.0]).expect("fits");
        assert_eq!(order, [10, 20, 30, 40, 50]);
        // Nothing sent: the fused order.
        assert_eq!(order_by_score(&visible, &[], &[]).expect("fits"), visible);
    }

    /// G-RET-15: a reply that does not fit the request is `None`, never applied: a wrong score count, a non-finite
    /// score, an id that is not visible, an id sent twice, a duplicate in the visible list.
    #[test]
    fn order_by_score_refuses_a_reply_that_does_not_fit_the_request() {
        let visible = [1_u32, 2, 3];
        assert_eq!(order_by_score(&visible, &[1, 2], &[1.0]), None, "short");
        assert_eq!(order_by_score(&visible, &[1], &[1.0, 2.0]), None, "long");
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            assert_eq!(order_by_score(&visible, &[1, 2], &[1.0, bad]), None);
        }
        assert_eq!(order_by_score(&visible, &[9], &[1.0]), None, "not visible");
        assert_eq!(
            order_by_score(&visible, &[2, 2], &[1.0, 2.0]),
            None,
            "twice"
        );
        assert_eq!(order_by_score(&[1_u32, 1], &[1], &[1.0]), None, "duplicate");
    }

    /// ADR-0084 D-D rows 2 to 4, in the pure step. The scored reply of the pinned model reorders and counts the
    /// sent ids; every other answer is the fused order with a zero count and `cannot_establish`.
    /// Fault: apply the scores of a model other than the pinned one ⇒ the mismatch row goes red.
    #[test]
    fn settle_follows_the_degradation_table() {
        let visible = [1_u32, 2, 3];
        let ok = settle(
            &visible,
            &[1, 2, 3],
            &pin(),
            Executor::Scored {
                scores: &[0.1, 0.9, 0.5],
                model: &pin(),
            },
        );
        assert_eq!(ok.order, [2, 3, 1]);
        assert_eq!(ok.reranked_count, 3);
        assert_eq!(
            ok.model,
            ProvenanceValue::Used {
                id: pin().model_id().as_str().to_owned()
            }
        );
        assert_eq!(ok.failure, None);

        let unavailable = settle(&visible, &[1, 2, 3], &pin(), Executor::Unavailable);
        let torn = settle(
            &visible,
            &[1, 2, 3],
            &pin(),
            Executor::Scored {
                scores: &[0.1],
                model: &pin(),
            },
        );
        for fallback in [unavailable, torn] {
            assert_eq!(fallback.order, visible, "the fused order");
            assert_eq!(fallback.reranked_count, 0);
            assert_eq!(fallback.model, ProvenanceValue::CannotEstablish {});
            assert_eq!(fallback.failure, Some(RerankFailure::Unavailable));
        }

        let other =
            ModelIdentity::new("org/model", "rev2", "recipe-v1", HEX_A, HEX_B).expect("valid");
        let mismatch = settle(
            &visible,
            &[1, 2, 3],
            &pin(),
            Executor::Scored {
                scores: &[0.1, 0.9, 0.5],
                model: &other,
            },
        );
        assert_eq!(mismatch.order, visible, "the scores are discarded");
        assert_eq!(mismatch.reranked_count, 0);
        assert_eq!(mismatch.model, ProvenanceValue::CannotEstablish {});
        assert_eq!(mismatch.failure, Some(RerankFailure::ModelMismatch));

        let idle = not_run(&visible);
        assert_eq!(idle.order, visible);
        assert_eq!(idle.model, ProvenanceValue::NotApplicable {});
        assert_eq!(idle.failure, None);
    }

    /// ADR-0084 D-C: the rendered id differs whenever any one part of the identity differs, and an identity whose parts
    /// could blur into one another is refused. Fault: leave one part out of the rendering ⇒ its row goes red.
    #[test]
    fn the_rendered_model_id_differs_with_every_part_of_the_identity() {
        let base = pin();
        let variants = [
            ModelIdentity::new("org/other", "rev1", "recipe-v1", HEX_A, HEX_B),
            ModelIdentity::new("org/model", "rev2", "recipe-v1", HEX_A, HEX_B),
            ModelIdentity::new("org/model", "rev1", "recipe-v2", HEX_A, HEX_B),
            ModelIdentity::new("org/model", "rev1", "recipe-v1", HEX_B, HEX_B),
            ModelIdentity::new("org/model", "rev1", "recipe-v1", HEX_A, HEX_A),
        ];
        for variant in variants {
            let variant = variant.expect("a valid variant");
            assert_ne!(variant, base);
            assert_ne!(variant.model_id(), base.model_id());
        }
        assert_eq!(
            base.model_id(),
            pin().model_id(),
            "the same identity, the same id"
        );
        assert!(ModelIdentity::new("", "r", "c", HEX_A, HEX_B).is_none());
        assert!(
            ModelIdentity::new("a#b", "r", "c", HEX_A, HEX_B).is_none(),
            "separator"
        );
        assert!(
            ModelIdentity::new("a b", "r", "c", HEX_A, HEX_B).is_none(),
            "whitespace"
        );
        assert!(
            ModelIdentity::new("a", "r", "c", "abc", HEX_B).is_none(),
            "short hash"
        );
        assert!(
            ModelIdentity::new("a", "r", "c", &HEX_A.to_uppercase(), HEX_B).is_none(),
            "upper-case hash"
        );
    }
}

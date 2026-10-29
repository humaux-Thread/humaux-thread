//! `adapters::projection_worker` — T-projection-worker: makes `humaux-retrieval-worker` actually index private
//!   memories per §17.4's contract, restated verbatim in the task card: "upsert -> await/verify search-visible
//!   according to adapter policy -> commit stream checkpoint".
//! Depends-on: crates=[async-trait, humaux-domain, humaux-infra-cell, humaux-local-secret-scan, humaux-projection,
//!   serde_json, sha2, sqlx]; services=[PostgreSQL(any) r=[private.evidence_objects,
//!   private.identity_note_materializations, private.memory_evidence, private.memory_records, private.memory_subjects,
//!   projection.card_profile_policies, projection.embedding_fingerprints, projection.memory_vectors,
//!   projection.private_memory_points, projection.rebuild_tickets]
//!   w=[ops.outbox, projection.stream_log],
//!   PostgreSQL(role_retrieval_worker)]; env=[]; modules=[adapters::affect_repo, adapters::postgres,
//!   adapters::private_projection_registry, adapters::qdrant, adapters::remember, adapters::stream_repo,
//!   domain::affect, domain::authority, domain::dataclass, domain::egress, domain::error, domain::identity,
//!   domain::ids, domain::memory, domain::subject, humaux-local-secret-scan, infra-cell::permit,
//!   infra-cell::transport, projection::card, projection::note_chunks, projection::serving, projection::stream]
//! Called-by: [adapters::rebuild, gateway::recall, maintenance::drill, retrieval-worker::main, tests]
//! Invariants: [run_claimed_pass claims across tenants by lease and processes one family's tickets sequentially in one
//!   worker; every family a pass holds is lease-renewed while any of them is worked; per row: resolve bound memories,
//!   upsert, verify search-visible, then settle; a transient failure returns the ticket to ISSUED with backoff
//!   (bounded by max attempts, then FAILED transient_exhausted), except that a dependency-outage failure while the
//!   dependency is already known down spends no attempt; a permanent one settles FAILED at once; every settle/retry/release is fenced on (lease_owner, attempts); a DONE is never written
//!   before search-visible confirmation; every point upsert and delete is fenced on the ticket's source_stream_seq, so a
//!   reclaimed worker's late write cannot overwrite or remove a point a later ticket wrote; the fence has no
//!   tombstone, so a stale upsert that lands after a retire delete re-inserts the point (ADR-0057 D-I, known limit 9;
//!   the rebuild verifier's id-set check deletes it as an orphan, ADR-0064 D-F E3); a card whose vector is stored
//!   under the worker label's fingerprint and the same input bytes is never sealed or embedded again, and every
//!   vector that is embedded is stored in the registry transaction (ADR-0064 D-B); run_claimed_pass_for_run claims
//!   only the generation tickets of one rebuild run (ADR-0064 D-N(g)); expected_points is the rebuild verifier's
//!   Project(PG) with the same card and payload builders, read in a READ ONLY projector transaction (ADR-0064 D-F);
//!   every Memory is planned by build_projection_plan under the projection's policy, read once per pass (ADR-0068
//!   D-A/D-I); a chunked note's whole source is sealed before any of its chunk cards and before any provider call
//!   (ADR-0068 D-G), on its own thread, so a slow scanner cannot keep the lease heartbeat from being polled (#79);
//!   one distinct vector key is embedded once and mapped to its slots by key (ADR-0068 D-F); a Memory
//!   counts toward DONE only when every one of its slots is registered and confirmed visible, and a chunked note's
//!   legacy point retires only in that same completion step (ADR-0068 D-F/D-I); every slot's point write carries
//!   its card text as the bm25 Document exactly when in_cell_text_processing_allowed(tenant), the one decision the
//!   rebuild verifier and the recall path share (ADR-0083 D-B)]
//! Spec: Baseline §4.2; §15.1; §17.4; §17.6; §18.2; §15.7; §6.1.2; ADR-0052; ADR-0057; ADR-0064 D-B; ADR-0064 D-F;
//!   ADR-0064 D-N; ADR-0068; ADR-0083 D-B
//!
//! §4.2 (line 818): there is no separate `projection-worker` process — this is
//! `humaux-retrieval-worker`'s own consumer loop, owned by `role_retrieval_worker`.
//!
//! ## What one [`run_once`] call processes
//!
//! Exactly one §15.1 stream identity (a [`StreamFamily`] + `projection_version`, i.e. one
//! [`StreamKey`]) — never "every ISSUED row across every tenant/stream in one call". A caller
//! (the `humaux-retrieval-worker` binary) instantiates one [`ProjectionWorkerDeps`] per stream
//! it is responsible for and calls [`run_once`] on a timer/loop, same shape
//! `humaux_public_pool::public_repo::run_once` already uses for the public plane.
//!
//! ## Per-row order (§17.4, verbatim in the task card)
//!
//! (a) read the next ISSUED `stream_log` rows for this key: (b) resolve the bound Memories —
//! ALL `private.memory_records` rows the ticket's Evidence carries, through
//! `ops.outbox`/`private.memory_evidence` (see `resolve_memories`: one Evidence routinely
//! carries N memories, and card 9 reported that only the first one used to be projected) (c)
//! the stored vectors of the cards (ADR-0064 D-B, stored-first: when every card has one, (c') is skipped) (c')
//! seal + `embed_cards` (one batched call for the whole Evidence, one input per distinct vector key; a chunked note's
//! whole source is sealed first, ADR-0068 D-G) (d) reject a short batch or a
//! dimension mismatch (e) build a `QdrantPointPayload` per memory, one point per expected slot (f)
//! [`crate::qdrant::upsert_fenced`] (g)
//! [`crate::private_projection_registry::register_private_memory_point_with_vector`] (the vector and the binding
//! in one transaction)
//! (h) [`crate::qdrant::verify_visible_via_transport`] (i) only then mark the row `DONE` (j)
//! [`crate::stream_repo::advance_prefix`] once for the whole batch.
//!
//! A failure at (b)-(h) is classified (ADR-0052 D-E, card 27 — before it, every failure was a
//! permanent `FAILED`, audit C4). A **permanent** one (a 4xx schema/payload refusal, a dimension
//! mismatch, an unbuildable card, a registry conflict, a terminally failed distill) settles the
//! row `FAILED` with its `error_class`; a **transient** one (PG connection/serialization/lock,
//! Qdrant transport/5xx/timeout, a provider 429/5xx, a lost registry race, an unconfirmed
//! visibility probe) returns it to the pool still `ISSUED` ([`stream_repo::release_for_retry`]),
//! with backoff, until `max_attempts` turns it into `FAILED` `transient_exhausted` — never an
//! unbounded retry (ADR-0048). `SKIPPED_BY_POLICY` stays the §18.2 policy exclusion. Either way
//! the next row runs *without* the checkpoint crossing this one — §15.7: one not-yet-DONE seq
//! blocks every later seq, so a batch that fails row N and settles row N+1 still leaves
//! `projection_highwater` at `N-1` after [`stream_repo::advance_prefix`].
//! `migrations/0011_roles_and_grants.sql`'s `projection.stream_log_guard_state_transition`
//! trigger only allows `role_retrieval_worker` to move `ISSUED -> {DONE,SKIPPED_BY_POLICY,FAILED}`;
//! the lease, the attempt counter and the backoff (migration 0176) are column writes with
//! `OLD.state = NEW.state`, which the guard admits, so a leased or backing-off ticket is still
//! `ISSUED` and there is still no in-between state for this role.
//!
//! ## The resident path: [`run_claimed_pass`] (ADR-0052)
//!
//! `humaux-retrieval-worker --serve` / `--run-once` call [`run_claimed_pass`]: the unplaced count
//! ([`stream_repo::unplaced_issued`], one `placement_missing` line), one cross-tenant claim
//! ([`stream_repo::claim_issued`], which also returns each ticket's placement; a ticket whose
//! placement does not parse is parked, never processed), then per family —
//! one worker holds a family at a time (D-A) and runs its tickets in `stream_seq` order — per
//! ticket: the exhaustion check, the family heartbeat ([`stream_repo::renew_family_leases`]; a
//! ticket not renewed was lost and is not settled), a freshly minted Qdrant permit, the same
//! [`process_row`] as below, and a fenced settle / retry / release; then one
//! [`stream_repo::advance_prefix`] per family. For the whole pass a background heartbeat renews
//! every claimed family each `lease_secs / 3`, so a family waiting behind a slow one keeps its
//! lease. A dependency-outage failure (Qdrant, provider incl. quota/budget, scanner, PG
//! connection) while [`SharedProjectionDeps::dependency_down`] is already set is released
//! without spending an attempt; the flag clears on the next `DONE`. [`run_once`] (one key, no lease) stays for the
//! adapter tests and keeps its signature.
//!
//! ## RLS and visibility
//!
//! `private.memory_records`' RLS policy (`migrations/0012_row_level_security.sql`, amended by
//! `migrations/0140_memory_records_rls_retrieval_worker_read.sql`) carves out a read-only
//! bypass for `role_retrieval_worker`, mirroring the `role_migration_owner` clause already in
//! the policy: inside the tenant-equality branch, `current_user = 'role_retrieval_worker'`
//! short-circuits the `USER_PRIVATE`/`WORKSPACE_SHARED` visibility disjunction, so this
//! tenant-scoped, headless worker can read every row of its own tenant regardless of
//! `visibility_class`/`visibility_user_id`/membership — real per-query visibility is enforced
//! downstream at Qdrant read time (§6.1.2) via the payload fields this module writes
//! (`visibility_class`/`visibility_user_id`/`visibility_workspace_id`) plus
//! `humaux_projection::dense::visibility_disjunction`, not by restricting what this worker can
//! index. The `WITH CHECK` clause is untouched — this worker never writes
//! `private.memory_records`. [`set_worker_rls_context`] still pins `humaux.user_id` to the nil
//! sentinel on every transaction (not to gate this policy — `current_user` does that — but to
//! keep a pooled connection's copy of that GUC always cast-safe for `private.evidence_objects`'
//! own, un-bypassed policy; see that function's doc for the plan-time crash this avoids).
//!
//! ## Scope
//!
//! This module only supports `scope_kind == "workspace"` streams: [`crate::qdrant::QdrantPointPayload`]'s
//! `workspace_id` field is mandatory (not `Option`), and the only stream-routing workspace this
//! module has to offer it is the family's own `scope_id` (mirrors `remember::token_workspace_id`'s
//! "stream-routing binding, not Evidence visibility" reasoning). A `"tenant"`-scoped family is
//! rejected with [`ErrorCode::InvalidInput`] before any row is touched.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::task::{Poll, Waker};
use std::time::Duration;

use humaux_domain::affect::AffectAnnotation;
use humaux_domain::authority::{AuthorityClass, AuthorityStatus, MemoryId};
use humaux_domain::dataclass::DataClass;
use humaux_domain::egress::ProcessorId;
use humaux_domain::error::ErrorCode;
use humaux_domain::identity::{AuthorizationScope, BoundedSet, PrincipalId};
use humaux_domain::ids::{TenantId, UserId, WorkspaceId};
use humaux_domain::memory::MemoryType;
use humaux_domain::subject::SubjectId;
use humaux_infra_cell::{CellAccessPermit, IntraCellHttpTransport};
use humaux_local_secret_scan::{LocalSecretScanner, SealedRetrievalCard, SealedSource};
use humaux_projection::card::{CardBuildOutcome, CardInput, EgressDisposition, RetrievalCard};
use humaux_projection::note_chunks::{
    LEGACY_CARD_PROFILE_HASH, NoteChunkPolicy, PlanInput, ProjectionPlan, UnknownNoteChunkProfile,
    build_projection_plan, chunk_card,
};
use humaux_projection::serving::StreamFamily;
use humaux_projection::stream::StreamKey;
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::types::Uuid;
use sqlx::types::time::OffsetDateTime;

use crate::postgres::RetrievalWorkerDbPool;
use crate::private_projection_registry::{
    self, PrivateMemoryPointRegistration, PrivateProjectionRegistryError, RegistrationOutcome,
    StoredVector, retire_legacy_point_for_memory, retire_points_for_memory,
};
use crate::qdrant::{
    self, IndexablePayload, PointId, QdrantOperation, QdrantPointPayload, TenantPlacementRow,
    delete_points, ha_profile_for, verify_visible_via_transport,
};
use crate::remember;
use crate::stream_repo::{self, Backoff, ClaimFamily, ClaimedTicket, OnlyRun, TicketFence};

/// The dense-write embedding call this worker needs, shaped like
/// `humaux_retrieval_provider::contract::EmbeddingProvider::embed_cards` but declared locally
/// rather than importing that trait.
///
/// `humaux-retrieval-provider`'s own `Cargo.toml` already depends on `humaux-adapters` (for
/// `RetrievalWorkerDbPool`/`disclosure::reserve_retrieval`/`finalize_retrieval` — see that
/// crate's manifest comment), so `humaux-adapters` cannot add a real (non-dev) dependency back
/// on `humaux-retrieval-provider` without a circular package graph; `EmbeddingProvider` itself
/// is therefore reachable from this crate's `tests/` (a dev-dependency) but never from `src/`.
/// This trait is the seam that keeps `run_once` generic over "something that embeds
/// `SealedRetrievalCard`s" without naming the crate on the wrong side of that edge — a caller
/// in `bins/retrieval-worker` (which depends on both crates with no cycle) or in this crate's
/// own `tests/` implements it by delegating one call to a real `EmbeddingProvider`.
#[async_trait::async_trait]
pub trait CardEmbedder: Send + Sync {
    /// Returns exactly one embedding vector per input card, in order. The caller
    /// ([`process_row`]) checks the returned vector length against the configured dimension
    /// itself — this trait carries no `EmbeddingBatch`-shaped metadata, only the vectors,
    /// precisely to avoid needing that type's crate.
    async fn embed_cards(
        &self,
        tenant_id: TenantId,
        dimension: u32,
        cards: &[SealedRetrievalCard],
        // §7.4: the memories the cards belong to (one per card) — the disclosure sources.
        memory_ids: &[Uuid],
    ) -> Result<Vec<Vec<f32>>, ErrorCode>;
}

/// Everything one [`run_once`] call needs. One instance == one `StreamKey` (`family` +
/// `projection_version`) — see module doc.
pub struct ProjectionWorkerDeps {
    /// `role_retrieval_worker`'s pool — the sole legal writer of this stream's `stream_log`/
    /// `stream_checkpoints` terminal edges (§6.2.2).
    pub pool: RetrievalWorkerDbPool,
    /// The dense-write embedding call — see [`CardEmbedder`]'s doc for why this is a local
    /// trait rather than `humaux_retrieval_provider::contract::EmbeddingProvider` directly.
    pub embedder: Arc<dyn CardEmbedder>,
    /// §1.2.3's sole constructor path for a card `embed_cards` may accept
    /// ([`humaux_local_secret_scan::SealedRetrievalCard`]) — every real caller of
    /// [`CardEmbedder::embed_cards`], this worker included, must scan first.
    pub scanner: Arc<LocalSecretScanner>,
    /// ADR-0003/§83.4 Layer 1B: the injected Qdrant transport (never `reqwest` directly).
    pub transport: Arc<dyn IntraCellHttpTransport>,
    /// The Qdrant `IntraCellResource` access token this deps instance authorizes with.
    pub permit: CellAccessPermit,
    /// §17.3 placement (collection name / shard key) for this tenant's `private_memory_v1`
    /// projection family.
    pub placement: TenantPlacementRow,
    /// The one §15.1 stream identity this deps instance processes — see module doc.
    pub family: StreamFamily,
    /// §17's `embedding_version` payload field — distinct from `projection_version` (module
    /// doc's own frozen warning, `qdrant::QdrantPointPayload`'s doc restates it).
    pub embedding_version: String,
    /// The `stream_log`/`stream_checkpoints` `projection_version` this deps instance settles.
    pub projection_version: String,
    /// The embedding vector width every card this deps instance embeds must produce.
    pub dimension: u32,
    /// §7.4 identity of the process running this loop — the same [`ProcessorId`] its embedding
    /// provider discloses under, taken from the deployment's own identity and never
    /// `Uuid::nil()` (card 21). [`stream_repo::advance_prefix`] writes it into
    /// `projection.stream_checkpoints.projection_processor_id`, so a checkpoint names the
    /// worker that advanced it.
    pub processor_id: ProcessorId,
}

/// [`run_once`]'s per-batch result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RunOnceOutcome {
    /// Rows this call settled `DONE`.
    pub done: u64,
    /// Rows this call settled `SKIPPED_BY_POLICY` (§18.2 `SecretMaterial`/`ExcludedSecret`).
    pub skipped_by_policy: u64,
    /// Rows this call settled `FAILED`.
    pub failed: u64,
    /// Rows returned to `ISSUED` after a transient failure, one attempt spent (ADR-0052 D-E).
    pub retried: u64,
    /// Rows left `ISSUED` because their Evidence is not distilled yet (ADR-0016 D6).
    pub pending: u64,
    /// `projection_highwater` after this call's [`stream_repo::advance_prefix`] — unchanged
    /// from before the call if nothing in this batch was contiguous-done-eligible (§15.7).
    pub projection_highwater: u64,
}

/// Everything [`run_claimed_pass`] shares across tenants (ADR-0052 D-F). No tenant, no placement,
/// no family and no permit: the claim supplies the first three per ticket, and a permit is
/// minted per ticket by `mint_permit` (a resident process outlives any single permit's TTL).
pub struct SharedProjectionDeps {
    /// `role_retrieval_worker`'s pool — claim, heartbeat, settle and every per-row read.
    pub pool: RetrievalWorkerDbPool,
    /// The dense-write embedding call (see [`CardEmbedder`]).
    pub embedder: Arc<dyn CardEmbedder>,
    /// §1.2.3: every card is sealed by the local scanner before it is embedded.
    pub scanner: Arc<LocalSecretScanner>,
    /// ADR-0003/§83.4 Layer 1B: the injected Qdrant transport.
    pub transport: Arc<dyn IntraCellHttpTransport>,
    /// Mints a fresh Qdrant permit (the bin closes over its cell registry and TTL); `None` = the
    /// registry refused, which the pass treats as a transient failure of that ticket.
    pub mint_permit: Arc<dyn Fn() -> Option<CellAccessPermit> + Send + Sync>,
    /// §17 `embedding_version` payload field.
    pub embedding_version: String,
    /// The embedding width every card must produce.
    pub dimension: u32,
    /// §7.4 identity of this process; written into `projection_processor_id` by `advance_prefix`.
    pub processor_id: ProcessorId,
    /// The async timer the pass's background lease heartbeat waits on (the bin's
    /// `tokio::time::sleep`). Injected like `mint_permit` because this crate has no async-runtime
    /// dependency (the `byok.rs` precedent).
    pub sleep: Arc<dyn Fn(Duration) -> Sleep + Send + Sync>,
    /// Review 2026-09-29 P1 (dependency-level breaker): `true` once a ticket failed on a
    /// dependency outage (Qdrant, embedding provider incl. quota/budget, scanner process, PG
    /// connection) and no ticket has reached `DONE` since. While it is `true`, further outage
    /// failures do not spend attempts. Starts `false`; the process owns it across passes.
    pub dependency_down: AtomicBool,
}

/// What [`SharedProjectionDeps::sleep`] returns.
pub type Sleep = Pin<Box<dyn Future<Output = ()> + Send>>;

/// One pass's knobs (ADR-0052 D-F). Every value comes from a required
/// `HUMAUX_RETRIEVAL_WORKER_*` key (§78); nothing here has a default.
#[derive(Debug, Clone)]
pub struct PassConfig {
    /// The §15.1 triple claimed and the §17.3 placement family its tenants must have
    /// ([`ClaimFamily::of`] of the one family the process projects).
    pub claim: ClaimFamily,
    /// `humaux-retrieval-worker/<uuid v7>`, one per process — the fence of every write.
    pub lease_owner: String,
    /// Lease length. A background heartbeat renews every family the pass holds each
    /// `lease_secs / 3`, and each ticket's family once more right before it is processed.
    pub lease_secs: f64,
    /// Tickets per claim (`HUMAUX_RETRIEVAL_WORKER_BATCH`).
    pub batch: i64,
    /// Tickets per tenant per claim (fairness).
    pub per_tenant_cap: i64,
    /// A transient failure at `attempts >= max_attempts` settles `FAILED` `transient_exhausted`.
    pub max_attempts: i32,
    /// Transient-failure backoff.
    pub backoff: Backoff,
}

/// [`run_claimed_pass`]'s counters — one log line per pass (ADR-0052 D-F).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PassOutcome {
    /// §39: original terminal class of the latest failure in this pass.
    pub last_error: Option<ErrorCode>,
    /// Tickets the claim leased.
    pub claimed: u64,
    /// Settled `DONE`.
    pub done: u64,
    /// Settled `SKIPPED_BY_POLICY`.
    pub skipped: u64,
    /// Settled `FAILED` (permanent, or `transient_exhausted`).
    pub failed: u64,
    /// Returned to `ISSUED` with backoff after a transient failure (charged or not).
    pub retried: u64,
    /// Of `retried`: outage failures while the dependency was already down — no attempt spent.
    pub refunded: u64,
    /// Released because the Evidence is still being distilled (attempt given back).
    pub pending: u64,
    /// Tickets not settled because the heartbeat or a fenced write found the lease gone.
    pub lost_lease: u64,
    /// ISSUED tickets whose tenant has no placement row (never claimed).
    pub placement_missing: u64,
    /// Claimed tickets whose placement row this build could not parse — parked with backoff,
    /// attempt given back, never processed.
    pub placement_invalid: u64,
    /// Wall time of the claim call alone.
    pub claim_ms: u64,
}

/// The borrowed view every per-row step reads. [`run_once`] builds it from one
/// [`ProjectionWorkerDeps`]; [`run_claimed_pass`] builds one per family from
/// [`SharedProjectionDeps`] plus the claimed ticket's key and placement.
struct RowCtx<'a> {
    last_error: Mutex<Option<ErrorCode>>,
    pool: &'a RetrievalWorkerDbPool,
    embedder: &'a dyn CardEmbedder,
    scanner: &'a Arc<LocalSecretScanner>,
    transport: &'a dyn IntraCellHttpTransport,
    permit: &'a CellAccessPermit,
    placement: &'a TenantPlacementRow,
    family: &'a StreamFamily,
    embedding_version: &'a str,
    projection_version: &'a str,
    dimension: u32,
    /// ADR-0068 D-I: the projection's note chunk policy, read once per pass ([`pass_policy`]).
    policy: NoteChunkPolicy,
    /// ADR-0083 D-B: this pass's answers to "does the collection already hold `bm25`" ([`Bm25Probes`]).
    bm25: &'a Bm25Probes,
}

impl<'a> RowCtx<'a> {
    fn record_error(&self, code: ErrorCode) {
        *self
            .last_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(code);
    }

    fn of(deps: &'a ProjectionWorkerDeps, policy: NoteChunkPolicy, bm25: &'a Bm25Probes) -> Self {
        Self {
            last_error: Mutex::new(None),
            pool: &deps.pool,
            embedder: deps.embedder.as_ref(),
            scanner: &deps.scanner,
            transport: deps.transport.as_ref(),
            permit: &deps.permit,
            placement: &deps.placement,
            family: &deps.family,
            embedding_version: &deps.embedding_version,
            projection_version: &deps.projection_version,
            dimension: deps.dimension,
            policy,
            bm25,
        }
    }
}

/// ADR-0083 D-B: one pass's answers to "does this collection already hold the `bm25` sparse vector", one
/// `GET /collections/{c}` per collection per pass, asked only when a row reaches its first Qdrant write (a row that
/// fails or skips earlier never touches Qdrant). `--serve` starts before anyone can run `collection ensure`, and a
/// point that names a vector the collection lacks is a permanent Qdrant 400 (`qdrant_upsert_rejected`); so a
/// collection without `bm25` is written dense-only until `ensure` and a rebuild catch it up. An unreadable answer is
/// remembered for the pass as `None` and its rows retry like any Qdrant outage: nothing is written on a guess.
#[derive(Default)]
struct Bm25Probes(Mutex<HashMap<String, Option<bool>>>);

impl Bm25Probes {
    /// `Some(true)`: write the `bm25` Document; `Some(false)`: write dense-only (one named operator line per pass);
    /// `None`: the probe failed.
    async fn holds(&self, ctx: &RowCtx<'_>) -> Option<bool> {
        let collection = &ctx.placement.collection_name;
        let known = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(collection)
            .copied();
        if let Some(known) = known {
            return known;
        }
        let probed = qdrant::collection_has_vector(
            ctx.transport,
            ctx.permit,
            collection,
            qdrant::BM25_VECTOR_NAME,
        )
        .await
        .ok();
        if probed == Some(false) {
            eprintln!(
                "projection_worker: collection lacks bm25 collection={collection} (run collection ensure; a rebuild \
                 backfills); writing dense-only"
            );
        }
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(collection.clone(), probed);
        probed
    }
}

/// ADR-0068 D-I: the projection's `note_chunk_profile_hash` row — `None` = no row, `Some(None)` = NULL (legacy only).
pub async fn card_profile_policy_row(
    pool: &RetrievalWorkerDbPool,
    domain: &str,
    projection_kind: &str,
    projection_version: &str,
) -> Result<Option<Option<String>>, sqlx::Error> {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT note_chunk_profile_hash FROM projection.card_profile_policies \
          WHERE domain = $1 AND projection_kind = $2 AND projection_version = $3",
    )
    .bind(domain)
    .bind(projection_kind)
    .bind(projection_version)
    // dep: PostgreSQL(role_retrieval_worker) — the projection's note chunk policy row (ADR-0068 D-I)
    .fetch_optional(pool.pool())
    .await
}

/// ADR-0068 D-I, the boot check of the binary's own projection: `None` when the row exists and its hash (NULL
/// included) names a profile this build knows; otherwise the refusal line (exit 2, an operator must change
/// something). A missing row is refused here, never read as legacy: migration 0238 seeds the serving projection's
/// row, so its absence is a broken deployment, and a worker that guessed would build slots the ledger does not count.
pub fn note_chunk_policy_refusal(row: Option<Option<&str>>) -> Option<String> {
    match row {
        None => Some(
            "boot refused: card_profile_policy_missing: the projection has no card profile policy row \
             (ADR-0068 D-I)"
                .to_owned(),
        ),
        Some(hash) => NoteChunkPolicy::from_profile_hash(hash).err().map(
            |UnknownNoteChunkProfile(hash)| {
                format!(
                    "boot refused: card_profile_policy_unknown: note chunk profile {hash:?} is not \
                     a profile this build knows (ADR-0068 D-I)"
                )
            },
        ),
    }
}

/// ADR-0083 D-A/D-E, U4: whether `tenant` allows text processing INSIDE the Data Cell (§17.6), i.e. whether a point of
/// this tenant carries a `bm25` sparse vector and the sparse leg may run for it. `false` is the §17.6 "extreme policy"
/// that makes the sparse lane `SKIPPED_BY_POLICY` (never a fallback to an external provider). It is the ONE decision:
/// the write path (`finish_row`, so an upsert and a rebuild alike), the rebuild verifier's `bm25` expectation and
/// T-RET-6c's query path all call this function and no other, so they cannot disagree about a tenant. Pure and
/// synchronous on purpose: when a policy source lands it is read here, and the callers do not change.
// ponytail: no tenant policy field exists (Baseline §17.6 prose only; TenantDataPolicy has none), so in-cell text processing is always allowed; upgrade = a TenantDataPolicy / control.egress_policies field read here when a tenant first needs it
pub fn in_cell_text_processing_allowed(_tenant: TenantId) -> bool {
    true
}

/// ADR-0068 D-I: the policy one pass plans under, read before anything is claimed. A missing row reads as NULL, as
/// the ledger reads the same row (the binary refuses a missing row of its own projection at boot); a hash this build
/// does not know refuses the pass (`InvalidInput`) before any ticket is touched.
async fn pass_policy(
    pool: &RetrievalWorkerDbPool,
    domain: &str,
    projection_kind: &str,
    projection_version: &str,
) -> Result<NoteChunkPolicy, ErrorCode> {
    let row = card_profile_policy_row(pool, domain, projection_kind, projection_version)
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    NoteChunkPolicy::from_profile_hash(row.flatten().as_deref()).map_err(
        |UnknownNoteChunkProfile(hash)| {
            eprintln!("projection_worker: card_profile_policy_unknown hash={hash:?}");
            ErrorCode::InvalidInput
        },
    )
}

/// Sets `humaux.tenant_id` for the remainder of `txn` — same technique as
/// `stream_repo::set_tenant_local`. `humaux.user_id` is pinned to the nil sentinel on every
/// call, not to gate `private.memory_records` (0140's `current_user = 'role_retrieval_worker'`
/// clause does that regardless of this value — this worker never impersonates a principal, per
/// the module doc's RLS note) but to keep a *pooled* connection's `humaux.user_id` GUC always a
/// syntactically valid uuid. Leaving it unset on a connection this worker's own
/// `private_projection_registry::register_private_memory_point` call has previously `SET
/// LOCAL`-ed (even to this same nil value) is not safe: PostgreSQL reverts a custom GUC to an
/// empty-string placeholder, not to NULL, once a transaction that `SET LOCAL`-ed it commits
/// (0031's documented tenant_id hazard, never patched for user_id) — and `private.evidence_objects`'
/// own RLS policy (no role bypass, out of 0140's scope) casts
/// `current_setting('humaux.user_id', true)::uuid` unconditionally in its `USER_PRIVATE`
/// branch. PostgreSQL's planner constant-folds that stable-function cast at *plan time*
/// (verified: even a bare `EXPLAIN`, no `ANALYZE`, throws 22P02 on a leaked `''`) — before the
/// executor's branch-level short-circuiting would ever get a chance to skip it — so re-pinning
/// a valid value here every transaction is the only way to keep this worker's `resolve_memories`
/// join from crashing on a `TENANT_SHARED`-evidence row it has every right to read.
async fn set_worker_rls_context(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "SELECT set_config('humaux.tenant_id', $1, true), set_config('humaux.user_id', $2, true)",
    )
    .bind(tenant_id.to_string())
    .bind(Uuid::nil().to_string())
    .execute(&mut **txn)
    .await?;
    Ok(())
}

fn parse_memory_type(wire: &str) -> Option<MemoryType> {
    Some(match wire {
        "FACT" => MemoryType::Fact,
        "PREFERENCE" => MemoryType::Preference,
        "DECISION" => MemoryType::Decision,
        "REJECTION" => MemoryType::Rejection,
        "STATE" => MemoryType::State,
        "ISSUE" => MemoryType::Issue,
        "LESSON" => MemoryType::Lesson,
        "CONSTRAINT" => MemoryType::Constraint,
        "PROCEDURE" => MemoryType::Procedure,
        "OUTCOME" => MemoryType::Outcome,
        "REFERENCE" => MemoryType::Reference,
        "NOTE" => MemoryType::Note,
        _ => return None,
    })
}

fn parse_authority_status(wire: &str) -> Option<AuthorityStatus> {
    Some(match wire {
        "active" => AuthorityStatus::Active,
        "superseded" => AuthorityStatus::Superseded,
        "revoked" => AuthorityStatus::Revoked,
        "expired" => AuthorityStatus::Expired,
        _ => return None,
    })
}

fn parse_authority_class(wire: &str) -> Option<AuthorityClass> {
    Some(match wire {
        "PublicKnowledge" => AuthorityClass::PublicKnowledge,
        "PrivateKnowledge" => AuthorityClass::PrivateKnowledge,
        "UserPreference" => AuthorityClass::UserPreference,
        "ProjectDecision" => AuthorityClass::ProjectDecision,
        "UserCorrection" => AuthorityClass::UserCorrection,
        "ProjectConstraint" => AuthorityClass::ProjectConstraint,
        "ExplicitTaskContext" => AuthorityClass::ExplicitTaskContext,
        _ => return None,
    })
}

fn parse_visibility_class(wire: &str) -> Option<humaux_domain::identity::VisibilityClass> {
    use humaux_domain::identity::VisibilityClass;
    Some(match wire {
        "USER_PRIVATE" => VisibilityClass::UserPrivate,
        "WORKSPACE_SHARED" => VisibilityClass::WorkspaceShared,
        "TENANT_SHARED" => VisibilityClass::TenantShared,
        _ => return None,
    })
}

/// §7.5.1-adjacent, first-pass mapping (no §18.4 policy registry exists yet, same "later task's
/// deliverable" situation `retrieval-provider::contract`'s module doc names for the pricing/
/// calibration registries): `Sensitive` content needs a policy check before egress,
/// `SecretMaterial` never reaches this function (excluded at
/// [`build_card`](humaux_projection::card::build_card) already), anything else is unconditionally allowed.
// ponytail: a real `§18.4` per-tenant policy gate is a separate deliverable; this is the
// smallest disposition that is not simply always-`Allowed` (tracked in coord task 7e6da2f9).
fn egress_disposition_for(data_class: DataClass) -> EgressDisposition {
    match data_class {
        DataClass::Sensitive => EgressDisposition::PolicyGated,
        _ => EgressDisposition::Allowed,
    }
}

fn to_system_time(t: OffsetDateTime) -> std::time::SystemTime {
    std::time::UNIX_EPOCH + std::time::Duration::from_secs(t.unix_timestamp().max(0) as u64)
}

/// One row read out of the [`ResolvedMemory`] join described in the module doc.
pub(crate) struct ResolvedMemory {
    memory_id: MemoryId,
    content: serde_json::Value,
    visibility: humaux_domain::identity::VisibilityDescriptor,
    memory_type: MemoryType,
    status: AuthorityStatus,
    authority: AuthorityClass,
    data_class: DataClass,
    occurred_at: Option<OffsetDateTime>,
    effective_from: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    body_sha256: Vec<u8>,
    /// §6.1.3 / ADR-0029 D-A: the memory's `private.memory_subjects` links, read in the same
    /// transaction as the row (role_retrieval_worker's own SELECT; the 0155 RESTRICTIVE subject
    /// policy exempts this role precisely so a subject-gated row still projects — §15.7).
    subject_ids: Vec<SubjectId>,
    /// §8.5.1 / ADR-0030 D-D: the memory's `private.memory_affects` rows, read in the same
    /// transaction (role_retrieval_worker's own SELECT) through the ONE set-based read
    /// (`affect_repo::affects_for_memories_in_txn`), flattened into the payload by `finish_row`.
    affects: Vec<AffectAnnotation>,
    /// ADR-0055 D-B: `archived_at IS NOT NULL`, read here so every ticket that re-projects the
    /// memory writes the current flag (no transition-specific ticket exists or is needed).
    archived: bool,
    /// ADR-0068 D-A: the Memory is the output of an identity contract
    /// (`identity_note_materializations.output_memory_id`), read in the same statement as the row.
    is_identity_note: bool,
}

/// (b): resolves the Memories one `stream_log` row's bound Evidence carries, through
/// `ops.outbox` -> `private.memory_evidence` -> `private.memory_records`/
/// `private.evidence_objects` — see module doc for why rows this worker cannot see under RLS
/// resolve to an empty `Vec`, not an error.
///
/// **ALL of them, not the PRIMARY one** (card 9's reported limit, closed by card 20 / ADR-0042).
/// A ticket binds an EVIDENCE, and one Evidence routinely carries N Memories: `distill` writes
/// every memory it extracted against the single Evidence the `remember` ticket was issued for,
/// `memory_governance_repo::issue_lifecycle_ticket` binds the target memory's PRIMARY Evidence,
/// and 0155's backfill does the same. With `ORDER BY (role='PRIMARY') DESC, ordinal ASC LIMIT 1`
/// every one of those three issuers could only ever get the FIRST memory indexed — a
/// lifecycle change to memory #2 of an Evidence re-projected memory #1 and silently dropped
/// itself, and a multi-output distill indexed one card out of N. Generalising the resolution
/// here (rather than at each of the three issuers, or by adding a memory-bound ticket shape)
/// is the single point every ticket already routes through.
///
/// The `ORDER BY` is kept: it makes the projection order deterministic (PRIMARY first), which
/// is what the partial-failure retry in [`process_row`] leans on.
pub(crate) async fn resolve_memories(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    commit_seq: i64,
) -> Result<Vec<ResolvedMemory>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT m.memory_id, m.content, m.visibility_class, m.visibility_user_id, \
                m.visibility_workspace_id, m.memory_type, m.status, m.authority_class, \
                m.occurred_at, m.effective_from, m.created_at, m.updated_at, eo.data_class, \
                m.archived_at IS NOT NULL AS archived, \
                sha256(convert_to(m.content::text, 'UTF8')) AS body_sha256, \
                EXISTS (SELECT 1 FROM private.identity_note_materializations c \
                         WHERE c.tenant_id = m.tenant_id AND c.output_memory_id = m.memory_id) \
                  AS is_identity_note \
         FROM ops.outbox ob \
         JOIN private.memory_evidence me ON me.evidence_id = ob.evidence_id \
         JOIN private.memory_records m ON m.memory_id = me.memory_id \
         JOIN private.evidence_objects eo ON eo.evidence_id = ob.evidence_id \
         WHERE ob.tenant_id = $1 AND ob.commit_seq = $2 \
         ORDER BY (me.role = 'PRIMARY') DESC, me.ordinal ASC",
    )
    .bind(tenant_id)
    .bind(commit_seq)
    .fetch_all(&mut **txn)
    .await?;
    let mut resolved = Vec::with_capacity(rows.len());
    for row in rows {
        if let Some(memory) = parse_resolved_memory(txn, tenant_id, row).await? {
            resolved.push(memory);
        }
    }
    Ok(resolved)
}

/// One `resolve_memories` row -> [`ResolvedMemory`]; `Ok(None)` for a row whose closed-enum
/// wire values this build does not know (same fail-soft the single-row version had).
async fn parse_resolved_memory(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    row: sqlx::postgres::PgRow,
) -> Result<Option<ResolvedMemory>, sqlx::Error> {
    let visibility_class: String = row.try_get("visibility_class")?;
    let Some(class) = parse_visibility_class(&visibility_class) else {
        return Ok(None);
    };
    let visibility = humaux_domain::identity::VisibilityDescriptor {
        class,
        user_id: row
            .try_get::<Option<Uuid>, _>("visibility_user_id")?
            .map(UserId),
        workspace_id: row
            .try_get::<Option<Uuid>, _>("visibility_workspace_id")?
            .map(WorkspaceId),
    };
    let memory_type_wire: String = row.try_get("memory_type")?;
    let status_wire: String = row.try_get("status")?;
    let authority_wire: String = row.try_get("authority_class")?;
    let data_class_wire: String = row.try_get("data_class")?;
    let (Some(memory_type), Some(status), Some(authority)) = (
        parse_memory_type(&memory_type_wire),
        parse_authority_status(&status_wire),
        parse_authority_class(&authority_wire),
    ) else {
        return Ok(None);
    };
    let memory_id: Uuid = row.try_get("memory_id")?;
    let subject_ids = sqlx::query_scalar::<_, Uuid>(
        "SELECT subject_id FROM private.memory_subjects \
         WHERE tenant_id = $1 AND memory_id = $2 ORDER BY subject_id",
    )
    .bind(tenant_id)
    .bind(memory_id)
    .fetch_all(&mut **txn)
    .await?
    .into_iter()
    .map(SubjectId)
    .collect();
    let affects = crate::affect_repo::affects_for_memories_in_txn(txn, tenant_id, &[memory_id])
        .await?
        .into_iter()
        .map(|row| row.annotation)
        .collect();

    Ok(Some(ResolvedMemory {
        memory_id: MemoryId(memory_id),
        content: row.try_get("content")?,
        visibility,
        memory_type,
        status,
        authority,
        data_class: DataClass::parse_or_secret(&data_class_wire),
        occurred_at: row.try_get("occurred_at")?,
        effective_from: row.try_get("effective_from")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        body_sha256: row.try_get("body_sha256")?,
        subject_ids,
        affects,
        archived: row.try_get("archived")?,
        is_identity_note: row.try_get("is_identity_note")?,
    }))
}

fn extract_str(value: &serde_json::Value, key: &str) -> Option<String> {
    value.get(key).and_then(|v| v.as_str()).map(str::to_owned)
}

/// Builds the [`CardInput`] this worker plans from ([`build_projection_plan`], for the rebuild verifier too, through
/// [`plan_slots`]) from a [`ResolvedMemory`].
/// `content` is arbitrary `jsonb` (§8.5) — `title`/`key_claim`/`evidence_excerpt` are read as
/// optional string fields on it, falling back to a truncated stringified `content` for `title`
/// only (never for `key_claim`/`evidence_excerpt` — a missing one of those is a genuine §18.4
/// "缺字段", not something to paper over here). A bare JSON string is not a record with missing
/// fields: it is the whole statement, so it is the claim and the title.
fn card_input(memory: &ResolvedMemory, workspace_id: WorkspaceId) -> CardInput {
    // ADR-0057 D-B: `memory.correct` stores the user's corrected text verbatim as a JSON string
    // (gateway `memory_correct`); read as an object it had no claim, so every correction settled
    // FAILED `card_unbuildable` and the corrected memory never reached the index.
    let statement = memory.content.as_str();
    let title = extract_str(&memory.content, "title")
        .or_else(|| statement.map(|text| text.chars().take(80).collect()))
        .unwrap_or_else(|| memory.content.to_string().chars().take(80).collect());
    let entities = memory
        .content
        .get("entities")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    CardInput {
        memory_id: memory.memory_id,
        memory_type: memory.memory_type,
        data_class: memory.data_class,
        egress_disposition: egress_disposition_for(memory.data_class),
        workspace_id: Some(workspace_id),
        topic: extract_str(&memory.content, "topic"),
        effective_from: to_system_time(
            memory
                .effective_from
                .or(memory.occurred_at)
                .unwrap_or(memory.created_at),
        ),
        title,
        key_claim: extract_str(&memory.content, "key_claim")
            .or_else(|| statement.map(str::to_owned)),
        entities,
        evidence_excerpt: extract_str(&memory.content, "evidence_excerpt"),
    }
}

/// One row's disposition, decided before any `stream_log` write (module doc's per-row order
/// (i)) — `stream_seq`/`error_class` are supplied by the caller, this only carries the state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowTerminal {
    Done,
    SkippedByPolicy,
    /// Permanent: the identical attempt would fail again (ADR-0052 D-E).
    Failed,
    /// Transient: back to the pool, still `ISSUED`, one attempt spent (ADR-0052 D-E). Never a
    /// terminal state; bounded by `max_attempts` in [`run_claimed_pass`].
    Retry,
    /// Not a terminal: the Evidence behind this ticket has not been distilled yet (its
    /// `ops.outbox` row is still PENDING/PROCESSING, ADR-0016 D6) — the row stays `ISSUED` and
    /// is re-read next pass. Never written as a state.
    Pending,
}

/// ADR-0052 D-E, PG half: a lost connection, an exhausted or closed pool, a serialization
/// failure, a deadlock, a lock timeout, an admin shutdown or a resource shortage can succeed on
/// retry; a data or constraint error cannot.
fn pg_is_transient(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Io(_)
        | sqlx::Error::Tls(_)
        | sqlx::Error::PoolTimedOut
        | sqlx::Error::PoolClosed
        | sqlx::Error::WorkerCrashed => true,
        sqlx::Error::Database(db) => db.code().is_some_and(|code| {
            code.starts_with("08")
                || code.starts_with("57P")
                || code.starts_with("53")
                || matches!(code.as_ref(), "40001" | "40P01" | "55P03")
        }),
        _ => false,
    }
}

/// A PG failure at `class`'s site, classified.
fn pg_failure(error: &sqlx::Error, class: &'static str) -> (RowTerminal, &'static str) {
    if pg_is_transient(error) {
        (RowTerminal::Retry, class)
    } else {
        (RowTerminal::Failed, class)
    }
}

/// ADR-0052 D-E, `ErrorCode` half (embedding provider and local secret scanner): the callee
/// refused this input or this caller — retrying the identical call cannot help — versus
/// everything else (rate limits, 5xx, budget, key pending, a scanner process that did not run).
fn code_is_transient(code: ErrorCode) -> bool {
    !matches!(
        code,
        ErrorCode::ProviderPermanent
            | ErrorCode::InvalidInput
            | ErrorCode::Forbidden
            | ErrorCode::Unauthorized
            | ErrorCode::EntitlementRequired
            | ErrorCode::TenantBoundary
            | ErrorCode::NotFound
    )
}

/// Review 2026-09-29 P1: of the transient classes, the ones that say "a dependency this worker
/// needs for every ticket is unavailable" — Qdrant (transport, 5xx, 429, and a refused permit),
/// the embedding provider (429/5xx, quota, cost budget, key pending), the scanner process, a lost
/// PG connection — as opposed to a race or probe about this one ticket (`registry_failed`,
/// `visibility_not_confirmed`, `embedding_batch_empty`), which always spends.
fn is_dependency_outage(class: &str) -> bool {
    matches!(
        class,
        "qdrant_upsert_failed" | "qdrant_delete_failed" | "embedding_failed" | "secret_scan_failed"
    ) || class.starts_with("db_")
}

/// ADR-0052 D-E, registry half. A source that stopped being live or changed, a lost race and a
/// transient DB error resolve on the next attempt (which re-reads the memory's current state);
/// an identity conflict, a scope violation or a data error does not.
fn registry_failure(error: &PrivateProjectionRegistryError) -> (RowTerminal, &'static str) {
    match error {
        PrivateProjectionRegistryError::SourceNotLive
        | PrivateProjectionRegistryError::SourceChanged
        | PrivateProjectionRegistryError::RegistryRaceLost => {
            (RowTerminal::Retry, "registry_failed")
        }
        PrivateProjectionRegistryError::Db(e) => pg_failure(e, "registry_failed"),
        PrivateProjectionRegistryError::PointIdCollision
        | PrivateProjectionRegistryError::IdentityAlreadyBound => {
            (RowTerminal::Failed, "registry_conflict")
        }
        PrivateProjectionRegistryError::CrossTenant
        | PrivateProjectionRegistryError::CrossWorkspace
        | PrivateProjectionRegistryError::InvalidInput
        | PrivateProjectionRegistryError::MissingAuthenticatedUser
        | PrivateProjectionRegistryError::FingerprintMismatch => {
            (RowTerminal::Failed, "registry_failed")
        }
    }
}

/// ADR-0016 D6: what a ticket whose `ops.outbox` row resolves to no memory means, decided from
/// the status of its Evidence's `EVIDENCE_ACCEPTED` row (ADR-0058 D-U). Distill is asynchronous to remember (§15.5 "0/1/N later"), so "no
/// memory yet" is only a gap while the row is still open; a DONE row with no memory is the
/// legitimate 0-memory outcome and settles as a no-op (`SKIPPED_BY_POLICY`, counted toward the
/// contiguous prefix like every policy exclusion), and a FAILED row fails the ticket
/// (permanently: 0167's retirable classes).
fn terminal_for_missing_memory(outbox_status: Option<&str>) -> (RowTerminal, &'static str) {
    match outbox_status {
        Some("DONE") => (RowTerminal::SkippedByPolicy, "no_memory_distilled"),
        Some("PENDING" | "PROCESSING") => (RowTerminal::Pending, "distill_pending"),
        Some("FAILED") => (RowTerminal::Failed, "distill_failed"),
        _ => (RowTerminal::Failed, "no_visible_memory_record"),
    }
}

/// Runs (b)-(h) of the module doc's per-row order for exactly one `stream_seq`, given its
/// `commit_seq`. Never returns an `Err` — every failure mode short-circuits into a classified
/// [`RowTerminal`] plus a fixed `error_class` tag, because a row failure must never abort the
/// batch (module doc).
async fn process_row(
    ctx: &RowCtx<'_>,
    stream_seq: i64,
    commit_seq: i64,
) -> (RowTerminal, &'static str) {
    let workspace_id = WorkspaceId(ctx.family.scope_id);

    let prepared = match resolve_and_embed(ctx, workspace_id, commit_seq).await {
        Ok(prepared) => prepared,
        Err(terminal) => return terminal,
    };

    // One ticket, N memories (see `resolve_memories`). The row's disposition is the fold:
    //   * the FIRST failure short-circuits the whole row (Retry or Failed as classified) — §15.7
    //     already requires one unsettled seq to block the prefix, and the retry is safe because
    //     every step `finish_row` performs is idempotent on a deterministic `point_id` (upsert,
    //     `AlreadyRegistered`, verify), so the memories that already landed simply land again;
    //   * `SKIPPED_BY_POLICY` is per-memory (§18.2 secret material), so it only becomes the
    //     row's terminal when NO memory on this Evidence was indexable;
    //   * one indexed memory makes the row `DONE`;
    //   * a memory that is no longer live (ADR-0049) is retired instead of indexed, and a
    //     retirement that lands counts toward `DONE` like an index write.
    let mut any_done = false;
    let mut skipped: Option<(RowTerminal, &'static str)> = None;
    for memory in prepared.dead {
        match retire_row(ctx, stream_seq, workspace_id, &memory).await {
            (RowTerminal::Done, _) => any_done = true,
            other => return other,
        }
    }
    for live in prepared.live {
        // ADR-0083 D-B: asked here, at the first write of the pass to this collection, not at the claim.
        let Some(collection_has_bm25) = ctx.bm25.holds(ctx).await else {
            return (RowTerminal::Retry, "qdrant_upsert_failed");
        };
        let fingerprint = prepared.fingerprint;
        match finish_row(
            ctx,
            stream_seq,
            workspace_id,
            live,
            (fingerprint, collection_has_bm25),
        )
        .await
        {
            (RowTerminal::Done, _) => any_done = true,
            (RowTerminal::SkippedByPolicy, class) => {
                skipped = Some((RowTerminal::SkippedByPolicy, class));
            }
            other => return other,
        }
    }
    if any_done {
        (RowTerminal::Done, "")
    } else {
        // `resolve_and_embed` returns a non-empty vec or an `Err`, so `skipped` is `Some` here.
        skipped.unwrap_or((RowTerminal::Failed, "no_visible_memory_record"))
    }
}

/// One expected point slot of a live memory (ADR-0068 D-C): its profile and ordinal, the card that fills it, and the
/// sha256 of that card's text — the input half of the vector key (ADR-0064 D-B). `memory` indexes the [`Planned`]
/// list it was built with.
struct SlotCard {
    memory: usize,
    profile: &'static str,
    ordinal: u32,
    card: RetrievalCard,
    input_sha256: [u8; 32],
}

impl SlotCard {
    fn new(memory: usize, profile: &'static str, ordinal: u32, card: RetrievalCard) -> Self {
        // ADR-0064 D-B: the embedded bytes are the card text (`seal_card` seals it unchanged).
        let input_sha256 = Sha256::digest(card.card_text.as_bytes()).into();
        Self {
            memory,
            profile,
            ordinal,
            card,
            input_sha256,
        }
    }
}

/// A live memory the plan kept. `source` is `Some((title, body))` iff its profile is `NoteChunksV1`: the whole
/// source ADR-0068 D-G seals before any of its chunk cards.
struct Planned {
    memory: ResolvedMemory,
    source: Option<(String, String)>,
}

/// One slot of a [`LiveMemory`], ready to write: its identity, its input digest and its vector.
struct LiveSlot {
    profile: &'static str,
    ordinal: u32,
    input_sha256: [u8; 32],
    vector: Vec<f32>,
    /// The card text the vector was embedded from (ADR-0064 D-B), which ADR-0083 D-A also hands Qdrant as the `bm25`
    /// Document: chunk cards included, the same bytes as the dense input.
    card_text: String,
}

/// A live memory with one entry per expected point slot (ADR-0068 D-F). `chunked` = profile `NoteChunksV1`: every
/// slot gets a v2 id and chunk payload fields, and the completion step retires the legacy point.
struct LiveMemory {
    memory: ResolvedMemory,
    chunked: bool,
    slots: Vec<LiveSlot>,
}

/// What [`resolve_and_embed`] hands [`process_row`]: the live memories with every slot's vector, the memories whose
/// ticket means retirement (ADR-0049), and the worker label's fingerprint. Never both empty.
struct Prepared {
    live: Vec<LiveMemory>,
    dead: Vec<ResolvedMemory>,
    /// ADR-0064 D-C: `None` only while the label is unbound — the retrieval worker binds it before
    /// its first pass, so a resident worker always has it; an unbound label stores no vector.
    fingerprint: Option<[u8; 32]>,
}

/// (b)-(d) of the module doc's per-row order: resolve the bound Evidence's Memories, plan each one's slots, and embed
/// them in ONE batched call. Split out of [`process_row`] purely to stay under this repo's line-count lint — see that
/// function for the full per-row order. Returns a non-empty vec or an `Err`.
async fn resolve_and_embed(
    ctx: &RowCtx<'_>,
    workspace_id: WorkspaceId,
    commit_seq: i64,
) -> Result<Prepared, (RowTerminal, &'static str)> {
    // dep: PostgreSQL(any) — transaction entry for `resolve_and_embed`
    let mut txn = ctx
        .pool
        .pool()
        .begin()
        .await
        .map_err(|e| pg_failure(&e, "db_begin_failed"))?;
    set_worker_rls_context(&mut txn, ctx.family.tenant_id.0)
        .await
        .map_err(|e| pg_failure(&e, "db_rls_context_failed"))?;
    let memories = resolve_memories(&mut txn, ctx.family.tenant_id.0, commit_seq)
        .await
        .map_err(|e| pg_failure(&e, "db_resolve_failed"))?;
    // ADR-0058 D-U: the distill state of the Evidence the ticket's carrier binds, whichever
    // carrier it is — a remember ticket's own EVIDENCE_ACCEPTED row, or the MEMORY_LIFECYCLE
    // successor `ops.requeue_dead_distill` issues, which must wait for the re-armed job, not fail.
    let outbox_status: Option<String> = if memories.is_empty() {
        sqlx::query_scalar(
            "SELECT ea.status FROM ops.outbox c \
             JOIN ops.outbox ea ON ea.tenant_id = c.tenant_id AND ea.evidence_id = c.evidence_id \
              AND ea.event_type = 'EVIDENCE_ACCEPTED' \
             WHERE c.tenant_id = $1 AND c.commit_seq = $2 ORDER BY ea.created_at DESC LIMIT 1",
        )
        .bind(ctx.family.tenant_id.0)
        .bind(commit_seq)
        .fetch_optional(&mut *txn)
        .await
        .map_err(|e| pg_failure(&e, "db_resolve_failed"))?
    } else {
        None
    };
    if memories.is_empty() {
        txn.commit()
            .await
            .map_err(|e| pg_failure(&e, "db_commit_failed"))?;
        return Err(terminal_for_missing_memory(outbox_status.as_deref()));
    }
    // ADR-0049: a memory that stopped being live (superseded / revoked / expired) gets no card,
    // no vector and no registration — the registry binds live sources only
    // (`current_source_matches`), so the ticket's consequence for it is retirement
    // (`retire_row`). Before this the supersede ticket failed `registry_failed` every time
    // (card 24 rehearsal 2026-09-26) and wedged the §15.4 prefix behind it.
    let (dead, memories): (Vec<ResolvedMemory>, Vec<ResolvedMemory>) = memories
        .into_iter()
        .partition(|memory| memory.status != AuthorityStatus::Active);

    let (planned, slots) = plan_slots(memories, workspace_id, ctx.policy)?;
    // ADR-0064 D-B stored-first, in the same read transaction and before any sealing.
    // ponytail: payload-only slots still read PG memory_vectors, M10-4 removes this read.
    let kept_ids: Vec<Uuid> = planned.iter().map(|p| p.memory.memory_id.0).collect();
    let (fingerprint, stored) = stored_vectors(&mut txn, ctx, &kept_ids)
        .await
        .map_err(|e| pg_failure(&e, "db_resolve_failed"))?;
    txn.commit()
        .await
        .map_err(|e| pg_failure(&e, "db_commit_failed"))?;
    if planned.is_empty() {
        if dead.is_empty() {
            return Err((RowTerminal::SkippedByPolicy, "secret_material"));
        }
        return Ok(Prepared {
            live: Vec::new(),
            dead,
            fingerprint,
        });
    }
    let vectors = slot_vectors(ctx, commit_seq, &planned, &slots, &stored).await?;

    let mut live: Vec<LiveMemory> = planned
        .into_iter()
        .map(|entry| LiveMemory {
            chunked: entry.source.is_some(),
            memory: entry.memory,
            slots: Vec::new(),
        })
        .collect();
    // `vectors` is per slot, in `slots` order, built by `slot_vectors` from the vector key — not a provider batch.
    for (slot, vector) in slots.into_iter().zip(vectors) {
        live[slot.memory].slots.push(LiveSlot {
            profile: slot.profile,
            ordinal: slot.ordinal,
            input_sha256: slot.input_sha256,
            vector,
            card_text: slot.card.card_text,
        });
    }
    Ok(Prepared {
        live,
        dead,
        fingerprint,
    })
}

/// The planned memories of one row and the slots they expand to (ADR-0068 D-A).
type SlotPlan = (Vec<Planned>, Vec<SlotCard>);

/// ADR-0068 D-A: every live memory through [`build_projection_plan`] under the pass's policy, as one entry per
/// expected slot. §18.2 `ExcludedSecret` is a property of ONE memory, not of the ticket: on an Evidence that carries a
/// secret memory and an ordinary one, the ordinary one must still be indexed, so an excluded memory is dropped and the
/// row is `SKIPPED_BY_POLICY` only when nothing is left. `Unbuildable` stays a whole-row permanent failure — the stored
/// record itself is malformed (§18.4).
fn plan_slots(
    memories: Vec<ResolvedMemory>,
    workspace_id: WorkspaceId,
    policy: NoteChunkPolicy,
) -> Result<SlotPlan, (RowTerminal, &'static str)> {
    let mut planned = Vec::with_capacity(memories.len());
    let mut slots = Vec::with_capacity(memories.len());
    for memory in memories {
        let input = card_input(&memory, workspace_id);
        let plan = build_projection_plan(PlanInput {
            card: input.clone(),
            is_identity_note: memory.is_identity_note,
            policy,
        });
        let index = planned.len();
        let source = match plan {
            ProjectionPlan::LegacyCardV1(CardBuildOutcome::Card(card)) => {
                slots.push(SlotCard::new(index, LEGACY_CARD_PROFILE_HASH, 0, *card));
                None
            }
            ProjectionPlan::LegacyCardV1(CardBuildOutcome::ExcludedSecret) => continue,
            ProjectionPlan::LegacyCardV1(CardBuildOutcome::Unbuildable) => {
                return Err((RowTerminal::Failed, "card_unbuildable"));
            }
            ProjectionPlan::NoteChunksV1(chunks) => {
                for chunk in &chunks {
                    let ordinal = u32::try_from(chunk.chunk_ordinal)
                        .expect("ADR-0068 D-B: a 64 KiB body has at most 158 chunks");
                    let card = chunk_card(&input, chunk);
                    slots.push(SlotCard::new(index, chunk.card_profile_hash, ordinal, card));
                }
                Some((input.title, input.key_claim.unwrap_or_default()))
            }
        };
        planned.push(Planned { memory, source });
    }
    Ok((planned, slots))
}

/// (c)-(d) per slot, ADR-0068 D-F. Stored-first per slot: a slot whose vector is stored under the label's fingerprint
/// and its exact input bytes reuses it, so a retry after a partial failure embeds only the slots that never
/// committed (`retry_reuses_committed_batch_vectors`). When every slot is stored, nothing is sealed or sent.
/// Otherwise each distinct vector key `(memory, input_sha256)` without a stored vector — the fingerprint is the
/// label's, one per worker — is sealed and embedded once, and its vector is handed to every slot with that key,
/// looked up by key, never by position. Every chunked source of the ticket is still sealed before that call (D-G).
async fn slot_vectors(
    ctx: &RowCtx<'_>,
    commit_seq: i64,
    planned: &[Planned],
    slots: &[SlotCard],
    stored: &[(Uuid, Vec<u8>, Vec<f32>)],
) -> Result<Vec<Vec<f32>>, (RowTerminal, &'static str)> {
    let reused: Vec<Option<Vec<f32>>> = slots
        .iter()
        .map(|slot| {
            let memory_id = planned[slot.memory].memory.memory_id.0;
            stored
                .iter()
                .find(|(id, sha, v)| {
                    *id == memory_id
                        && sha[..] == slot.input_sha256[..]
                        && v.len() == ctx.dimension as usize
                })
                .map(|(_, _, v)| v.clone())
        })
        .collect();
    if reused.iter().all(Option::is_some) {
        // No provider call, so no egress and nothing for the §1.2.3 scanner to gate.
        return Ok(reused.into_iter().flatten().collect());
    }
    let mut distinct: Vec<&SlotCard> = Vec::new();
    let mut by_key: HashMap<(usize, [u8; 32]), usize> = HashMap::new();
    for (slot, _) in slots.iter().zip(&reused).filter(|(_, v)| v.is_none()) {
        by_key
            .entry((slot.memory, slot.input_sha256))
            .or_insert_with(|| {
                distinct.push(slot);
                distinct.len() - 1
            });
    }
    let vectors = seal_and_embed(ctx, commit_seq, planned, &distinct).await?;
    Ok(slots
        .iter()
        .zip(reused)
        .map(|(slot, stored)| {
            stored.unwrap_or_else(|| vectors[by_key[&(slot.memory, slot.input_sha256)]].clone())
        })
        .collect())
}

/// ADR-0068 D-B/D-C: the worker label's fingerprint and the non-purged vectors stored under it for `memory_ids`, as
/// `(memory_id, input_sha256, vector)` — every slot of a memory shares its rows (the vector key has no ordinal). An
/// unbound label reads `(None, [])`.
async fn stored_vectors(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &RowCtx<'_>,
    memory_ids: &[Uuid],
) -> Result<(Option<[u8; 32]>, Vec<(Uuid, Vec<u8>, Vec<f32>)>), sqlx::Error> {
    let fingerprint: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT fingerprint_sha256 FROM projection.embedding_fingerprints WHERE embedding_version = $1",
    )
    .bind(ctx.embedding_version)
    .fetch_optional(&mut **txn)
    .await?;
    let Some(fingerprint) = fingerprint.and_then(|f| <[u8; 32]>::try_from(f).ok()) else {
        return Ok((None, Vec::new()));
    };
    if memory_ids.is_empty() {
        return Ok((Some(fingerprint), Vec::new()));
    }
    let rows = sqlx::query(
        "SELECT memory_id, input_sha256, vector FROM projection.memory_vectors \
          WHERE tenant_id = $1 AND fingerprint_sha256 = $2 AND memory_id = ANY($3) AND vector IS NOT NULL",
    )
    .bind(ctx.family.tenant_id.0)
    .bind(&fingerprint[..])
    .bind(memory_ids.to_vec())
    .fetch_all(&mut **txn)
    .await?;
    let stored = rows
        .iter()
        .map(|row| {
            Ok((
                row.try_get("memory_id")?,
                row.try_get("input_sha256")?,
                row.try_get("vector")?,
            ))
        })
        .collect::<Result<_, sqlx::Error>>()?;
    Ok((Some(fingerprint), stored))
}

/// ADR-0052 D-E: a scanner process that did not run (`DependencyUnavailable`) is environmental; a gitleaks finding
/// (`Forbidden`) or an unsealable card or source (`InvalidInput`) is a verdict on this input and would be the same
/// verdict on every retry.
fn seal_failure(code: ErrorCode) -> (RowTerminal, &'static str) {
    if code_is_transient(code) {
        (RowTerminal::Retry, "secret_scan_failed")
    } else {
        (RowTerminal::Failed, "secret_scan_rejected")
    }
}

/// Runs `job` on its own OS thread and resolves with its result, so a blocking step never occupies the thread that
/// polls [`while_running`]'s lease heartbeat (#79: the scanner subprocess is waited on synchronously, and a poll that
/// does not return starves every future driven by the same parent). std-only — this crate has no async runtime: the
/// thread hands the result over a channel and wakes the last [`Waker`] the future registered. `Err` = the thread could
/// not be spawned; a panic in `job` is re-raised in the awaiting task, as if `job` had run inline.
///
/// Cancellation: dropping the future drops the receiver, but the thread still runs `job` to completion and its result
/// is discarded. That is sound only for a `job` with no side effect beyond its return value; sealing is one (the
/// scanner subprocess's verdict is its only output, and it is bounded by the scanner's own timeout).
// ponytail: one OS thread per sealing row; a bounded pool if rows in flight grow
fn run_off_thread<T: Send + 'static>(
    job: impl FnOnce() -> T + Send + 'static,
) -> impl Future<Output = std::io::Result<T>> {
    let (tx, rx) = mpsc::channel();
    let waker: Arc<Mutex<Option<Waker>>> = Arc::default();
    let parked = Arc::clone(&waker);
    let mut spawn_error = std::thread::Builder::new()
        .name("projection-seal".to_owned())
        .spawn(move || {
            // A closed channel (the future was dropped) is the cancellation case above: nobody wants the result.
            let _ = tx.send(std::panic::catch_unwind(std::panic::AssertUnwindSafe(job)));
            let waiting = parked.lock().unwrap_or_else(PoisonError::into_inner).take();
            if let Some(waiting) = waiting {
                waiting.wake();
            }
        })
        .err();
    std::future::poll_fn(move |cx| {
        if let Some(error) = spawn_error.take() {
            return Poll::Ready(Err(error));
        }
        // Register before looking: a result sent after `try_recv` below finds the waker already stored.
        *waker.lock().unwrap_or_else(PoisonError::into_inner) = Some(cx.waker().clone());
        match rx.try_recv() {
            Ok(Ok(value)) => Poll::Ready(Ok(value)),
            Ok(Err(panic)) => std::panic::resume_unwind(panic),
            Err(mpsc::TryRecvError::Empty) => Poll::Pending,
            Err(mpsc::TryRecvError::Disconnected) => Poll::Ready(Err(std::io::Error::other(
                "the sealing thread ended without a result",
            ))),
        }
    })
}

/// A chunked note's whole source as the sealing thread owns it (ADR-0068 D-G).
struct SourceText {
    memory_id: Uuid,
    data_class: DataClass,
    title: String,
    body: String,
}

/// The synchronous sealing phase of one row, the body of the job [`seal_and_embed`] hands to [`run_off_thread`]:
/// ADR-0068 D-G, every chunked note's whole source first and only then each card, `sources` indexed like the plan and
/// `cards` as `(index into sources, card)`. The first failure ends the phase.
fn seal_all(
    scanner: &LocalSecretScanner,
    sources: &[Option<SourceText>],
    cards: &[(usize, RetrievalCard)],
) -> Result<Vec<SealedRetrievalCard>, ErrorCode> {
    let sealed: Vec<Option<SealedSource>> = sources
        .iter()
        .map(|source| {
            source
                .as_ref()
                .map(|s| scanner.seal_source(s.memory_id, s.data_class, &s.title, &s.body))
                .transpose()
        })
        .collect::<Result<_, _>>()?;
    cards
        .iter()
        .map(|(memory, card)| match &sealed[*memory] {
            Some(source) => scanner.seal_chunk_card(source, card),
            None => scanner.seal_card(card),
        })
        .collect()
}

/// (c')-(d): seal every distinct input and embed them in one embedder call; reject a short batch or a dimension
/// mismatch. Reached only when some slot of the Evidence has no stored vector (ADR-0064 D-B). ADR-0068 D-G: every
/// chunked note's whole source is sealed first, so a secret anywhere in it — the last window, or across a window
/// boundary — fails the row `secret_scan_rejected` exactly like a secret in a legacy card, before any card is sealed
/// and before any provider call. The sealing phase runs off the polling thread ([`run_off_thread`]), so a row with
/// hundreds of scanner calls cannot keep the pass's lease heartbeat from being polled (#79). The provider splits the
/// call into requests of at most its `max_batch_items` (ADR-0068 D-F); any failed request fails the whole call and
/// nothing from this attempt is persisted, so the retry embeds these inputs again (slots committed by an earlier
/// attempt are reused by [`slot_vectors`]).
async fn seal_and_embed(
    ctx: &RowCtx<'_>,
    commit_seq: i64,
    planned: &[Planned],
    inputs: &[&SlotCard],
) -> Result<Vec<Vec<f32>>, (RowTerminal, &'static str)> {
    // The sealing thread outlives this borrow, so it gets its own copies.
    let scanner = Arc::clone(ctx.scanner);
    let sources: Vec<Option<SourceText>> = planned
        .iter()
        .map(|entry| {
            entry.source.as_ref().map(|(title, body)| SourceText {
                memory_id: entry.memory.memory_id.0,
                data_class: entry.memory.data_class,
                title: title.clone(),
                body: body.clone(),
            })
        })
        .collect();
    let cards: Vec<(usize, RetrievalCard)> = inputs
        .iter()
        .map(|slot| (slot.memory, slot.card.clone()))
        .collect();
    // A thread that cannot even be spawned is the scanner not having run: transient, like a failed scan process.
    let sealed_cards = run_off_thread(move || seal_all(&scanner, &sources, &cards))
        .await
        .map_err(|_| {
            ctx.record_error(ErrorCode::DependencyUnavailable);
            seal_failure(ErrorCode::DependencyUnavailable)
        })?
        .map_err(|code| {
            ctx.record_error(code);
            seal_failure(code)
        })?;
    let memory_ids: Vec<Uuid> = inputs
        .iter()
        .map(|slot| planned[slot.memory].memory.memory_id.0)
        .collect();

    // One embedder call for the whole Evidence — `embed_cards` is batch-shaped, so N inputs
    // cost ceil(N / max_batch_items) provider round trips, not N (§19.2, ADR-0068 D-F).
    let vectors = ctx
        .embedder
        .embed_cards(
            ctx.family.tenant_id,
            ctx.dimension,
            &sealed_cards,
            &memory_ids,
        )
        .await
        .map_err(|code| {
            ctx.record_error(code);
            // Operator signal only: the wire `ErrorCode` variant, never provider text (§7.x).
            eprintln!("projection_worker: commit_seq={commit_seq} embedding_failed code={code:?}");
            if code_is_transient(code) {
                (RowTerminal::Retry, "embedding_failed")
            } else {
                (RowTerminal::Failed, "embedding_rejected")
            }
        })?;
    // (d): reject a short batch or a dimension mismatch, per distinct input — checked against the actual returned
    // vector lengths, since this trait carries no separate `EmbeddingBatch::dimension` field
    // (see `CardEmbedder`'s doc). A provider that returns fewer vectors than inputs would
    // otherwise silently drop the tail slots of a multi-memory Evidence. A short batch is a
    // provider blip (transient); a wrong width is configuration (permanent).
    if vectors.len() != inputs.len() {
        return Err((RowTerminal::Retry, "embedding_batch_empty"));
    }
    if vectors.iter().any(|v| v.len() != ctx.dimension as usize) {
        return Err((RowTerminal::Failed, "embedding_dimension_mismatch"));
    }
    Ok(vectors)
}

/// (e): THE payload builder of a private memory point (ADR-0064 D-F E4: the rebuild verifier
/// rebuilds payloads from PostgreSQL with this same function, so there is no second builder).
/// `None` = §18.2 secret material, never indexable.
pub(crate) fn point_payload(
    tenant_id: TenantId,
    workspace_id: WorkspaceId,
    embedding_version: &str,
    projection_version: &str,
    source_stream_seq: i64,
    memory: &ResolvedMemory,
) -> Option<IndexablePayload> {
    let payload = QdrantPointPayload {
        memory_id: memory.memory_id,
        tenant_id,
        workspace_id,
        visibility_class: memory.visibility.class,
        visibility_user_id: memory.visibility.user_id,
        visibility_workspace_id: memory.visibility.workspace_id,
        object_type: "memory_record".to_owned(),
        memory_type: memory.memory_type,
        status: memory.status,
        authority: memory.authority,
        created_at: memory.created_at,
        effective_at: memory
            .effective_from
            .or(memory.occurred_at)
            .unwrap_or(memory.created_at),
        embedding_version: embedding_version.to_owned(),
        projection_version: projection_version.to_owned(),
        source_stream_seq,
        data_class: memory.data_class,
        egress_disposition: egress_disposition_for(memory.data_class),
    };
    // §18.2: `into_indexable` is the sole index-write gate.
    Some(
        payload
            .into_indexable()?
            // ADR-0029 D-A: subject linkage rides the indexable payload (`subject_ids` array field).
            .with_subject_ids(memory.subject_ids.clone())
            // ADR-0030 D-D: affect annotations ride the same payload (six flat array fields).
            .with_affects(memory.affects.clone())
            // ADR-0055 D-B: the lifecycle prefilter flag, from the PG row this ticket resolved.
            .with_archived(memory.archived),
    )
}

/// ADR-0068 D-C/D-E: one slot's registry identity and payload. A legacy slot keeps the v1 id and today's payload; a
/// chunk slot is re-keyed to its v2 id and its payload names the profile and ordinal. The worker writes through it and
/// the rebuild verifier's [`expected_points`] derives through it, so the two cannot disagree on a slot's point.
fn slot_point(
    legacy: &PrivateMemoryPointRegistration,
    indexable: &IndexablePayload,
    chunked: bool,
    profile: &str,
    ordinal: u32,
) -> (PrivateMemoryPointRegistration, IndexablePayload) {
    if chunked {
        (
            legacy.clone().for_chunk(profile, ordinal),
            indexable.clone().with_chunk(profile, ordinal),
        )
    } else {
        (legacy.clone(), indexable.clone())
    }
}

/// ADR-0064 D-F X/E4: one point Project(PG) yields for an input, computed with the projector's own steps
/// (`resolve_memories` → `card_input` → [`plan_slots`] → [`slot_point`] → [`point_payload`]), so the
/// verifier has no second card or payload builder. `payload` is the point's canonical payload JSON object
/// without `source_stream_seq` (which differs between generations by design).
pub(crate) struct ExpectedPoint {
    pub(crate) point_id: Uuid,
    pub(crate) memory_id: Uuid,
    pub(crate) payload: serde_json::Map<String, serde_json::Value>,
}

/// Opens a read transaction under the projector's RLS view (`role_retrieval_worker`'s 0140 arm: every row of
/// the tenant whatever its visibility), READ ONLY: the rebuild verifier never writes PostgreSQL (ADR-0064 D-F).
pub(crate) async fn begin_projector_read(
    pool: &RetrievalWorkerDbPool,
    tenant_id: Uuid,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, sqlx::Error> {
    // dep: PostgreSQL(role_retrieval_worker) — transaction entry for `begin_projector_read`
    let mut txn = pool.pool().begin().await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *txn)
        .await?;
    set_worker_rls_context(&mut txn, tenant_id).await?;
    Ok(txn)
}

/// The points the projector writes for the input whose home commit is `commit_seq` (ADR-0064 D-F X): one per
/// expected slot of every Active memory, planned under `policy` by the worker's own [`plan_slots`] and keyed by
/// [`slot_point`] (ADR-0068 D-D: the verifier's manifest is per slot, so a chunked note is C points with their v2
/// ids). An Unbuildable memory yields nothing here (its ticket fails `card_unbuildable`, which E3 accounts as an
/// outcome exclusion); secret material yields nothing.
pub(crate) async fn expected_points(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    family: &StreamFamily,
    embedding_version: &str,
    projection_version: &str,
    commit_seq: i64,
    policy: NoteChunkPolicy,
) -> Result<Vec<ExpectedPoint>, sqlx::Error> {
    let workspace_id = WorkspaceId(family.scope_id);
    let mut points = Vec::new();
    for memory in resolve_memories(txn, family.tenant_id.0, commit_seq).await? {
        if memory.status != AuthorityStatus::Active {
            continue;
        }
        let Some(indexable) = point_payload(
            family.tenant_id,
            workspace_id,
            embedding_version,
            projection_version,
            0,
            &memory,
        ) else {
            continue;
        };
        let legacy = PrivateMemoryPointRegistration::deterministic(
            family.clone(),
            projection_version.to_owned(),
            embedding_version.to_owned(),
            memory.memory_id,
            memory.updated_at,
            memory.body_sha256.clone(),
        );
        let memory_id = memory.memory_id.0;
        let Ok((planned, slots)) = plan_slots(vec![memory], workspace_id, policy) else {
            continue;
        };
        let chunked = planned.first().is_some_and(|entry| entry.source.is_some());
        for slot in &slots {
            let (registration, payload) =
                slot_point(&legacy, &indexable, chunked, slot.profile, slot.ordinal);
            let point_id = registration.point_id.as_uuid();
            let mut body = qdrant::upsert_point_body(PointId::Uuid(point_id), &payload);
            let mut payload = match body.get_mut("payload").map(serde_json::Value::take) {
                Some(serde_json::Value::Object(map)) => map,
                _ => serde_json::Map::new(),
            };
            payload.remove(qdrant::SOURCE_STREAM_SEQ_FIELD);
            points.push(ExpectedPoint {
                point_id,
                memory_id,
                payload,
            });
        }
    }
    Ok(points)
}

/// (e)-(h) of the module doc's per-row order for one live memory: build the payload, then per slot upsert and
/// register (with the stored vector, ADR-0064 D-B), then verify every slot, then — for a chunked note — retire its
/// legacy point. ADR-0068 D-F: the memory counts toward DONE only when every expected slot is registered and
/// confirmed visible; any slot that is not leaves the whole ticket not-DONE through the same classified failure.
async fn finish_row(
    ctx: &RowCtx<'_>,
    stream_seq: i64,
    workspace_id: WorkspaceId,
    live: LiveMemory,
    (fingerprint, collection_has_bm25): (Option<[u8; 32]>, bool),
) -> (RowTerminal, &'static str) {
    let LiveMemory {
        memory,
        chunked,
        slots,
    } = live;
    // §18.2: `build_card` already refused a `SecretMaterial` input, so this can only fail if the
    // two disagree — kept as a belt-and-braces check rather than an `expect`, per repo fail-loud
    // convention (§50).
    let Some(indexable) = point_payload(
        ctx.family.tenant_id,
        workspace_id,
        ctx.embedding_version,
        ctx.projection_version,
        stream_seq,
        &memory,
    ) else {
        return (RowTerminal::SkippedByPolicy, "secret_material");
    };

    let legacy = PrivateMemoryPointRegistration::deterministic(
        ctx.family.clone(),
        ctx.projection_version.to_owned(),
        ctx.embedding_version.to_owned(),
        memory.memory_id,
        memory.updated_at,
        memory.body_sha256,
    );
    let authorization = worker_authorization_scope(ctx.family, workspace_id);
    let mut point_ids = Vec::with_capacity(slots.len());
    for slot in slots {
        // ADR-0068 D-C/D-E: the legacy slot keeps the v1 id and today's payload; a chunk slot is re-keyed to its v2 id
        // and its payload names the profile and ordinal.
        let (registration, payload) =
            slot_point(&legacy, &indexable, chunked, slot.profile, slot.ordinal);
        let stored = fingerprint.map(|fingerprint_sha256| StoredVector {
            fingerprint_sha256,
            input_sha256: slot.input_sha256,
            vector: slot.vector.clone(),
        });
        // ADR-0083 D-B: the sparse vector rides every slot's write — rebuild generation tickets included (a rebuild
        // runs `ensure_collection` first), which is how an existing point gains it in place — unless the tenant's
        // policy forbids in-cell text processing or the collection predates the vector (dense-only; the verifier's E6
        // counts the point and a rebuild backfills it).
        let bm25_text = (in_cell_text_processing_allowed(ctx.family.tenant_id)
            && collection_has_bm25)
            .then_some(slot.card_text.as_str());
        if let Err(failure) = write_slot(
            ctx,
            stream_seq,
            &authorization,
            &registration,
            (&payload, slot.vector, bm25_text),
            stored.as_ref(),
        )
        .await
        {
            return failure;
        }
        point_ids.push(PointId::Uuid(registration.point_id.as_uuid()));
    }

    match verify_visible_via_transport(
        ctx.transport,
        ctx.permit,
        &ctx.placement.collection_name,
        &point_ids,
    )
    .await
    {
        // ADR-0068 D-F: the completion check — `verify_visible` confirms only when every slot's point is observed,
        // not "some point of the memory" (§17.4), so a confirmation here covers the whole slot set.
        Ok(Some(_)) => {}
        // ADR-0052 D-E: not yet observed is a retry, not a verdict — the points are registered,
        // so the next attempt re-upserts the same ids and probes again.
        _ => return (RowTerminal::Retry, "visibility_not_confirmed"),
    }
    if chunked {
        // ADR-0068 D-I: every chunk slot is now registered and visible, so a legacy point (one projected before the
        // policy was enabled) retires in this same completion step; until here it kept answering recall.
        return match retire_legacy_point_for_memory(
            ctx.pool,
            &authorization,
            ctx.family,
            ctx.projection_version,
            ctx.embedding_version,
            memory.memory_id,
        )
        .await
        {
            Ok(points) => delete_retired(ctx, stream_seq, &points).await,
            Err(error) => registry_failure(&error),
        };
    }
    (RowTerminal::Done, "")
}

/// §17 / M10-2: NULL or mismatched bindings, rebuild tickets and missing points require a full upsert.
async fn payload_only_slot(
    ctx: &RowCtx<'_>,
    stream_seq: i64,
    registration: &PrivateMemoryPointRegistration,
    stored: Option<&StoredVector>,
) -> Result<bool, (RowTerminal, &'static str)> {
    let Some(stored) = stored else {
        return Ok(false);
    };
    // dep: PostgreSQL(any) — tenant-scoped live binding and rebuild-ticket read (§17, ADR-0064 D-N).
    let mut txn = ctx
        .pool
        .pool()
        .begin()
        .await
        .map_err(|e| pg_failure(&e, "db_begin_failed"))?;
    set_worker_rls_context(&mut txn, ctx.family.tenant_id.0)
        .await
        .map_err(|e| pg_failure(&e, "db_rls_context_failed"))?;
    let eligible: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM projection.private_memory_points \
           WHERE tenant_id = $1 AND point_id = $2 AND projection_live \
             AND fingerprint_sha256 = $3 AND input_sha256 = $4) \
         AND NOT EXISTS (SELECT 1 FROM projection.rebuild_tickets \
           WHERE tenant_id = $1 AND scope_kind = $5 AND scope_id = $6 AND domain = $7 \
             AND projection_kind = $8 AND projection_version = $9 AND stream_seq = $10)",
    )
    .bind(ctx.family.tenant_id.0)
    .bind(registration.point_id.as_uuid())
    .bind(&stored.fingerprint_sha256[..])
    .bind(&stored.input_sha256[..])
    .bind(&ctx.family.scope_kind)
    .bind(ctx.family.scope_id)
    .bind(&ctx.family.domain)
    .bind(&ctx.family.projection_kind)
    .bind(ctx.projection_version)
    .bind(stream_seq)
    .fetch_one(&mut *txn)
    .await
    .map_err(|e| pg_failure(&e, "db_resolve_failed"))?;
    txn.commit()
        .await
        .map_err(|e| pg_failure(&e, "db_commit_failed"))?;
    if !eligible {
        return Ok(false);
    }
    let point = PointId::Uuid(registration.point_id.as_uuid());
    let observed = qdrant::scroll_by_ids(
        ctx.transport,
        ctx.permit,
        &ctx.placement.collection_name,
        &[point],
    )
    .await
    .map_err(|_| (RowTerminal::Retry, "visibility_not_confirmed"))?;
    Ok(observed == [point])
}

/// (f)-(g) for one slot: the fenced upsert, then the registration with its stored vector. A registration the
/// registry refuses deletes the point the upsert just landed (ADR-0052 D-E (b)).
async fn write_slot(
    ctx: &RowCtx<'_>,
    stream_seq: i64,
    authorization: &AuthorizationScope,
    registration: &PrivateMemoryPointRegistration,
    (payload, vector, bm25_text): (&IndexablePayload, Vec<f32>, Option<&str>),
    stored: Option<&StoredVector>,
) -> Result<(), (RowTerminal, &'static str)> {
    let point_id = PointId::Uuid(registration.point_id.as_uuid());

    // ADR-0057 D-I: fenced on this ticket's seq — a stalled worker whose lease was reclaimed
    // cannot overwrite a point a later ticket of the same memory already wrote.
    // ponytail: no tombstone behind the seq fence — a stale upsert after a retire delete finds no
    // point and re-inserts it (reads as A2 overshoot, never a false close; ADR-0057 known limits
    // 9-10). `humaux-maintenance projection rebuild` detects it in its id-set check and deletes it
    // as an orphan (ADR-0064 D-F E3); a Qdrant-side tombstone is the upgrade path if it recurs.
    // ponytail: one upsert request per slot (up to 158 for a 64 KiB note); batch the slots of a memory into one fenced
    // request if chunk backfill latency (40d-2) says the round trips matter.
    let payload_only = payload_only_slot(ctx, stream_seq, registration, stored).await?;
    let write = if payload_only {
        // ponytail: one set_payload request per slot, batch if latency matters (§17.4).
        // ponytail: sparse bm25 is not refreshed here, rebuild tickets backfill it (ADR-0083 D-B).
        qdrant::set_payload_fenced(
            ctx.transport,
            ctx.permit,
            &ctx.placement.collection_name,
            point_id,
            payload,
        )
        .await
    } else {
        qdrant::upsert_fenced(
            ctx.transport,
            ctx.permit,
            &ctx.placement.collection_name,
            (point_id, payload, vector),
            bm25_text,
            ha_profile_for(QdrantOperation::NormalImmutableUpsert),
        )
        .await
    };
    if let Err(error) = write {
        // ADR-0052 D-E: 400/422 (payload, schema, vector width) is permanent; transport, 5xx,
        // 404, 408, 409, 429 are transient. Operator signal: the status class only.
        eprintln!(
            "projection_worker: stream_seq={stream_seq} qdrant_upsert transient={}",
            error.is_transient()
        );
        ctx.record_error(if error.is_transient() {
            ErrorCode::DependencyUnavailable
        } else {
            ErrorCode::InvalidInput
        });
        return Err(if error.is_transient() {
            (RowTerminal::Retry, "qdrant_upsert_failed")
        } else {
            (RowTerminal::Failed, "qdrant_upsert_rejected")
        });
    }

    match private_projection_registry::register_private_memory_point_with_vector(
        ctx.pool,
        authorization,
        registration,
        if payload_only { None } else { stored },
    )
    .await
    {
        Ok(
            RegistrationOutcome::Inserted
            | RegistrationOutcome::AlreadyRegistered
            | RegistrationOutcome::Revived,
        ) => Ok(()),
        Err(error) => {
            let (terminal, class) = registry_failure(&error);
            // ADR-0052 D-E (b): the upsert above landed a point the registry refused to bind, so
            // no later retirement could ever find it (retirement walks registered points only,
            // D-A's race). Delete that deterministic id before returning — except on a point-id
            // collision, where the id IS registered, to another source, and deleting it would
            // take that source's live point with it. A failed compensation is transient: the
            // retry re-upserts the same id and tries again.
            if !matches!(error, PrivateProjectionRegistryError::PointIdCollision)
                && delete_points(
                    ctx.transport,
                    ctx.permit,
                    &ctx.placement.collection_name,
                    &[point_id],
                    stream_seq,
                    ha_profile_for(QdrantOperation::CorrectionDeleteSupersede),
                )
                .await
                .is_err()
            {
                return Err((RowTerminal::Retry, class));
            }
            Err((terminal, class))
        }
    }
}

/// ADR-0049: the projection consequence of a memory that is no longer live. The registry binds
/// live sources only, so the memory's bindings in this family are retired and every point ever
/// bound for it (live or already retired — retry-safe; every chunk slot included, ADR-0068 D-H) leaves the index.
/// `DONE` settles the ticket and lets the §15.4 prefix advance past it; the reader's PG re-check
/// (`resolve_private_memory_points`) never served the dead memory anyway, so this is hygiene
/// plus settlement, not a visibility change.
async fn retire_row(
    ctx: &RowCtx<'_>,
    stream_seq: i64,
    workspace_id: WorkspaceId,
    memory: &ResolvedMemory,
) -> (RowTerminal, &'static str) {
    let authorization = worker_authorization_scope(ctx.family, workspace_id);
    match retire_points_for_memory(
        ctx.pool,
        &authorization,
        ctx.family,
        ctx.projection_version,
        ctx.embedding_version,
        memory.memory_id,
    )
    .await
    {
        Ok(points) => delete_retired(ctx, stream_seq, &points).await,
        Err(error) => registry_failure(&error),
    }
}

/// The Qdrant half of a retirement the registry already committed: delete every returned point, fenced on this
/// ticket's seq. Nothing to delete is `DONE`.
async fn delete_retired(
    ctx: &RowCtx<'_>,
    stream_seq: i64,
    points: &[private_projection_registry::ProjectionPointId],
) -> (RowTerminal, &'static str) {
    if points.is_empty() {
        return (RowTerminal::Done, "");
    }
    let ids = points
        .iter()
        .map(|point| PointId::Uuid(point.as_uuid()))
        .collect::<Vec<_>>();
    if let Err(error) = delete_points(
        ctx.transport,
        ctx.permit,
        &ctx.placement.collection_name,
        &ids,
        // ADR-0057 D-I: the delete mirror of the upsert fence (a later ticket's revive survives).
        stream_seq,
        ha_profile_for(QdrantOperation::CorrectionDeleteSupersede),
    )
    .await
    {
        ctx.record_error(if error.is_transient() {
            ErrorCode::DependencyUnavailable
        } else {
            ErrorCode::InvalidInput
        });
        return if error.is_transient() {
            (RowTerminal::Retry, "qdrant_delete_failed")
        } else {
            (RowTerminal::Failed, "qdrant_delete_rejected")
        };
    }
    (RowTerminal::Done, "")
}

/// Builds the fixed, non-impersonating [`AuthorizationScope`] this headless worker presents to
/// [`private_projection_registry::register_private_memory_point`] — module doc's RLS note: a
/// worker principal, not a real user, `principal`/`user_id` both the nil sentinel
/// (`remember::set_authorization_local`'s own precedent for a headless write).
fn worker_authorization_scope(
    family: &StreamFamily,
    workspace_id: WorkspaceId,
) -> AuthorizationScope {
    AuthorizationScope::new(
        family.tenant_id,
        PrincipalId(Uuid::nil()),
        Some(UserId(Uuid::nil())),
        BoundedSet::new([workspace_id]).expect("one-element set is always within MAX_LEN"),
    )
}

/// The legacy single-key read: up to `batch` `ISSUED` rows for `key`, ascending `stream_seq`,
/// returning `(stream_seq, commit_seq, attempts)`. Unleased on purpose — it takes only rows no
/// `--serve` process holds (`lease_owner IS NULL`) and whose backoff has elapsed; a second
/// concurrent `run_once` against the same key would race it (single-worker-per-key assumption,
/// same as `humaux_public_pool::public_repo`'s own `run_once`). The resident path claims instead
/// ([`stream_repo::claim_issued`]).
async fn fetch_issued_rows(
    pool: &RetrievalWorkerDbPool,
    key: &StreamKey,
    batch: i64,
) -> Result<Vec<(i64, i64, i32)>, ErrorCode> {
    // dep: PostgreSQL(role_retrieval_worker) — transaction entry for `fetch_issued_rows`
    let mut txn = pool.pool().begin().await.map_err(|_| ErrorCode::Internal)?;
    set_worker_rls_context(&mut txn, key.tenant_id.0)
        .await
        .map_err(|_| ErrorCode::Internal)?;
    let rows = sqlx::query(
        "SELECT stream_seq, commit_seq, attempts FROM projection.stream_log \
         WHERE tenant_id = $1 AND scope_kind = $2 AND scope_id = $3 AND domain = $4 \
           AND projection_kind = $5 AND projection_version = $6 AND state = 'ISSUED' \
           AND lease_owner IS NULL \
           AND (next_attempt_at IS NULL OR next_attempt_at <= clock_timestamp()) \
         ORDER BY stream_seq ASC LIMIT $7",
    )
    .bind(key.tenant_id.0)
    .bind(&key.scope_kind)
    .bind(key.scope_id)
    .bind(&key.domain)
    .bind(&key.projection_kind)
    .bind(&key.projection_version)
    .bind(batch)
    .fetch_all(&mut *txn)
    .await
    .map_err(|_| ErrorCode::Internal)?;
    txn.commit().await.map_err(|_| ErrorCode::Internal)?;
    rows.into_iter()
        .map(|row| {
            Ok((
                row.try_get::<i64, _>("stream_seq")
                    .map_err(|_| ErrorCode::Internal)?,
                row.try_get::<i64, _>("commit_seq")
                    .map_err(|_| ErrorCode::Internal)?,
                row.try_get::<i32, _>("attempts")
                    .map_err(|_| ErrorCode::Internal)?,
            ))
        })
        .collect()
}

/// Writes one row's terminal state — the sole legal `role_retrieval_worker` transition,
/// `ISSUED -> {DONE,SKIPPED_BY_POLICY,FAILED}` (`migrations/0011_roles_and_grants.sql`'s
/// `stream_log_guard_state_transition`) — and clears the lease in the same statement. Fenced on
/// `fence` (ADR-0052 D-D): returns `false`, not an error, when the fence matched nothing (the
/// row already left `ISSUED`, or its lease was re-claimed by another worker).
async fn settle_row(
    pool: &RetrievalWorkerDbPool,
    key: &StreamKey,
    stream_seq: i64,
    commit_seq: i64,
    terminal: RowTerminal,
    error_class: &str,
    fence: TicketFence<'_>,
) -> Result<bool, ErrorCode> {
    let state = match terminal {
        RowTerminal::Done => "DONE",
        RowTerminal::SkippedByPolicy => "SKIPPED_BY_POLICY",
        RowTerminal::Failed => "FAILED",
        RowTerminal::Retry | RowTerminal::Pending => return Ok(false),
    };
    // dep: PostgreSQL(role_retrieval_worker) — transaction entry for `settle_row`
    let mut txn = pool.pool().begin().await.map_err(|_| ErrorCode::Internal)?;
    set_worker_rls_context(&mut txn, key.tenant_id.0)
        .await
        .map_err(|_| ErrorCode::Internal)?;
    let error_class = (!error_class.is_empty()).then_some(error_class);
    let settled = sqlx::query(
        "UPDATE projection.stream_log \
            SET state = $8, error_class = $7, \
                lease_owner = NULL, lease_expires_at = NULL, next_attempt_at = NULL \
         WHERE tenant_id = $1 AND scope_kind = $2 AND scope_id = $3 AND domain = $4 \
           AND projection_kind = $5 AND projection_version = $6 AND stream_seq = $9 \
           AND state = 'ISSUED' \
           AND lease_owner IS NOT DISTINCT FROM $10 AND attempts = $11",
    )
    .bind(key.tenant_id.0)
    .bind(&key.scope_kind)
    .bind(key.scope_id)
    .bind(&key.domain)
    .bind(&key.projection_kind)
    .bind(&key.projection_version)
    .bind(error_class)
    .bind(state)
    .bind(stream_seq)
    .bind(fence.lease_owner)
    .bind(fence.attempts)
    .execute(&mut *txn)
    .await
    .map_err(|_| ErrorCode::Internal)?
    .rows_affected()
        == 1;
    if !settled {
        txn.commit().await.map_err(|_| ErrorCode::Internal)?;
        return Ok(false);
    }
    // ADR-0049 D-C: the ticket's carrier row. A MEMORY_LIFECYCLE / MEMORY_PUBLISHED outbox row
    // exists to bind `evidence_id` to this ticket (ADR-0018 §4); no distiller ever claims it,
    // so until now it stayed PENDING forever and every "backlog drained" measure (the soak's
    // `backlog_drained`, the rehearsal's undrained-writes assertion) counted it as open work.
    // The settled ticket is its completion, and the carrier MIRRORS the ticket's terminal:
    // DONE / SKIPPED_BY_POLICY settle it DONE, a FAILED ticket leaves it FAILED — a failed
    // lifecycle projection must not read as drained work (card 24 review P1). EVIDENCE_ACCEPTED
    // rows belong to the distiller and are kept apart by the event_type filter, not by status.
    let carrier_status = if terminal == RowTerminal::Failed {
        "FAILED"
    } else {
        "DONE"
    };
    sqlx::query(
        "UPDATE ops.outbox SET status = $4, processed_at = now() \
         WHERE tenant_id = $1 AND commit_seq = $2 AND event_type = ANY($3) \
           AND status = 'PENDING'",
    )
    .bind(key.tenant_id.0)
    .bind(commit_seq)
    .bind(vec![remember::MEMORY_LIFECYCLE, remember::MEMORY_PUBLISHED])
    .bind(carrier_status)
    .execute(&mut *txn)
    .await
    .map_err(|_| ErrorCode::Internal)?;
    txn.commit().await.map_err(|_| ErrorCode::Internal)?;
    Ok(true)
}

/// The legacy single-key consumer loop, one batch: see module doc for the per-row order and the
/// §15.7 checkpoint discipline. No lease and no `max_attempts` of its own — nothing resident
/// drives it any more (the binary's `--run-once` is one [`run_claimed_pass`]); a transient row is
/// returned with one attempt spent and no backoff, and the next caller decides.
pub async fn run_once(
    deps: &ProjectionWorkerDeps,
    batch: usize,
) -> Result<RunOnceOutcome, ErrorCode> {
    if deps.family.scope_kind != "workspace" {
        return Err(ErrorCode::InvalidInput);
    }
    let key = StreamKey::new(
        deps.family.tenant_id,
        deps.family.scope_kind.clone(),
        deps.family.scope_id,
        deps.family.domain.clone(),
        deps.family.projection_kind.clone(),
        deps.projection_version.clone(),
    );
    let policy = pass_policy(
        &deps.pool,
        &deps.family.domain,
        &deps.family.projection_kind,
        &deps.projection_version,
    )
    .await?;
    let probes = Bm25Probes::default();
    let ctx = RowCtx::of(deps, policy, &probes);

    let rows = fetch_issued_rows(&deps.pool, &key, batch as i64).await?;
    let mut outcome = RunOnceOutcome::default();
    for (stream_seq, commit_seq, attempts) in rows {
        let fence = TicketFence {
            lease_owner: None,
            attempts,
        };
        let (terminal, error_class) = process_row(&ctx, stream_seq, commit_seq).await;
        match terminal {
            RowTerminal::Retry => {
                stream_repo::release_for_retry(
                    &deps.pool,
                    &key,
                    stream_seq,
                    fence,
                    error_class,
                    None,
                    true,
                )
                .await
                .map_err(|_| ErrorCode::Internal)?;
            }
            RowTerminal::Pending => {}
            _ => {
                settle_row(
                    &deps.pool,
                    &key,
                    stream_seq,
                    commit_seq,
                    terminal,
                    error_class,
                    fence,
                )
                .await?;
            }
        }
        match terminal {
            RowTerminal::Done => outcome.done += 1,
            RowTerminal::SkippedByPolicy => outcome.skipped_by_policy += 1,
            RowTerminal::Failed => outcome.failed += 1,
            RowTerminal::Retry => outcome.retried += 1,
            RowTerminal::Pending => outcome.pending += 1,
        }
    }

    // (j): one `advance_prefix` call for the whole batch. §15.7: a not-yet-DONE seq blocks
    // every later seq — that discipline lives entirely inside `advance_prefix`'s own
    // `contiguous_done_prefix` arithmetic, so this call needs no special-casing here.
    // `Inconsistent` means the ledger's own §15.4 identity did not hold — a real fault, not a
    // retry signal, so it surfaces as `ErrorCode::Internal` rather than a guessed fallback.
    // The watermark carries this worker's §7.4 identity into `projection_processor_id`
    // (migration 0171): the checkpoint this process advanced says which process advanced it.
    outcome.projection_highwater = stream_repo::advance_prefix(&deps.pool, &key, deps.processor_id)
        .await
        .map_err(|_| ErrorCode::Internal)?;
    Ok(outcome)
}

/// ADR-0052 D-F: one resident pass across every placed tenant — see the module doc's "resident
/// path" section for the order. Returns `Err` only when the database is unreachable for the
/// policy read, the unplaced count or the claim itself (the caller logs it and polls again), or when the projection's
/// note chunk policy names a profile this build does not know (`InvalidInput`, ADR-0068 D-I); a per-ticket failure
/// is classified and counted, never propagated. A settle/retry/release that cannot reach the
/// database either leaves the ticket leased, and the lease expiry returns it (the expired-lease
/// arm of the claim).
pub async fn run_claimed_pass(
    shared: &SharedProjectionDeps,
    cfg: &PassConfig,
) -> Result<PassOutcome, ErrorCode> {
    claimed_pass(shared, cfg, None).await
}

/// [`run_claimed_pass`] whose claim takes only the generation tickets of `only_run`
/// ([`stream_repo::claim_run_tickets`], ADR-0064 D-N(g)): the restore drill's in-process pass, which must never
/// re-drive a restored generation-1 ticket. The resident worker calls [`run_claimed_pass`] (no run scope).
pub async fn run_claimed_pass_for_run(
    shared: &SharedProjectionDeps,
    cfg: &PassConfig,
    only_run: OnlyRun,
) -> Result<PassOutcome, ErrorCode> {
    claimed_pass(shared, cfg, Some(only_run)).await
}

async fn claimed_pass(
    shared: &SharedProjectionDeps,
    cfg: &PassConfig,
    only_run: Option<OnlyRun>,
) -> Result<PassOutcome, ErrorCode> {
    let mut outcome = PassOutcome::default();
    // ADR-0068 D-I: one policy read per pass, before anything is claimed.
    let policy = pass_policy(
        &shared.pool,
        &cfg.claim.domain,
        &cfg.claim.projection_kind,
        &cfg.claim.projection_version,
    )
    .await?;

    let batch = claim_for_pass(shared, cfg, only_run, &mut outcome).await?;
    let mut claimed = batch.tickets;
    outcome.claimed = (claimed.len() + batch.unplaceable.len()) as u64;
    // Review 2026-09-29 P1: a placement this build cannot parse (deploy skew) parks only its own
    // tickets — lease cleared, attempt given back, backoff so it is not re-claimed every poll —
    // and every co-claimed ticket is processed as usual.
    for ticket in batch.unplaceable {
        eprintln!(
            "projection_worker: placement_invalid tenant={} stream_seq={}",
            ticket.tenant_id, ticket.stream_seq
        );
        let key = StreamKey::new(
            TenantId(ticket.tenant_id),
            ticket.scope_kind,
            ticket.scope_id,
            ticket.domain,
            ticket.projection_kind,
            ticket.projection_version,
        );
        let fence = TicketFence {
            lease_owner: Some(&cfg.lease_owner),
            attempts: ticket.attempts,
        };
        let parked = stream_repo::release_for_retry(
            &shared.pool,
            &key,
            ticket.stream_seq,
            fence,
            "placement_invalid",
            Some(cfg.backoff),
            false,
        )
        .await;
        outcome.last_error = Some(ErrorCode::InvalidInput);
        if parked.is_ok_and(|written| written) {
            outcome.placement_invalid += 1;
        } else {
            outcome.lost_lease += 1;
        }
    }

    // D-A: one family, one worker, `stream_seq` order. `RETURNING` has no order of its own.
    claimed.sort_by(|a, b| {
        (a.key.tenant_id.0, a.key.scope_id, a.stream_seq).cmp(&(
            b.key.tenant_id.0,
            b.key.scope_id,
            b.stream_seq,
        ))
    });
    let families: Vec<&[ClaimedTicket]> = claimed.chunk_by(|a, b| a.key == b.key).collect();
    // ADR-0083 D-B: one pass, one set of probe answers.
    let bm25 = Bm25Probes::default();
    // ponytail: families run one after another inside a pass; run them concurrently if the
    // projection-lag p95 (ADR-0052 measurements) says a pass is the bottleneck.
    let work = async {
        for family in &families {
            run_family(shared, cfg, policy, &bm25, family, &mut outcome).await;
        }
    };
    // Review 2026-09-29 P0: every family this pass holds is renewed while ANY of them is being
    // worked, so the tail of a slow batch keeps its leases (before this, only the family in
    // hand was renewed and later families expired, were re-claimed, and burned attempts to
    // `transient_exhausted` without ever being tried). The lease is a liveness signal: it has
    // to outlast `lease_secs / 3` plus one renew round, not the batch.
    let heartbeat = async {
        loop {
            (shared.sleep)(Duration::from_secs_f64(cfg.lease_secs / 3.0)).await;
            for family in &families {
                // A failed renew is not acted on here: the per-ticket renew in `run_family`
                // sees the lost lease and stops that family before any write.
                let _ = stream_repo::renew_family_leases(
                    &shared.pool,
                    &family[0].key,
                    &cfg.lease_owner,
                    cfg.lease_secs,
                )
                .await;
            }
        }
    };
    while_running(work, heartbeat).await;
    Ok(outcome)
}

/// The claim of one pass: the run-scoped claim (ADR-0064 D-N(g)), or the unplaced count plus the cross-tenant
/// claim (ADR-0052 D-C).
async fn claim_for_pass(
    shared: &SharedProjectionDeps,
    cfg: &PassConfig,
    only_run: Option<OnlyRun>,
    outcome: &mut PassOutcome,
) -> Result<stream_repo::ClaimBatch, ErrorCode> {
    Ok(match only_run {
        // ADR-0064 D-N(g): one run of one tenant; the cross-tenant unplaced count is not this pass's concern.
        Some(run) => timed(
            outcome,
            stream_repo::claim_run_tickets(
                &shared.pool,
                &cfg.claim,
                run,
                &cfg.lease_owner,
                cfg.lease_secs,
                cfg.batch,
            ),
        )
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?,
        None => {
            let unplaced = stream_repo::unplaced_issued(&shared.pool, &cfg.claim)
                .await
                .map_err(|_| ErrorCode::DependencyUnavailable)?;
            outcome.placement_missing = unplaced.iter().map(|(_, n)| *n as u64).sum();
            if let Some((first, _)) = unplaced.first() {
                // One line per pass, not per tenant: a poll every second must not flood the log.
                eprintln!(
                    "projection_worker: placement_missing tenants={} tickets={} first_tenant={first}",
                    unplaced.len(),
                    outcome.placement_missing
                );
            }
            timed(
                outcome,
                stream_repo::claim_issued(
                    &shared.pool,
                    &cfg.claim,
                    &cfg.lease_owner,
                    cfg.lease_secs,
                    cfg.batch,
                    cfg.per_tenant_cap,
                ),
            )
            .await
            .map_err(|_| ErrorCode::DependencyUnavailable)?
        }
    })
}

/// Awaits the claim alone and records its wall time in `claim_ms`.
async fn timed<T>(outcome: &mut PassOutcome, claim: impl Future<Output = T>) -> T {
    let started = std::time::Instant::now();
    let claimed = claim.await;
    outcome.claim_ms = started.elapsed().as_millis() as u64;
    claimed
}

/// Drives `work` to completion while also polling `side` (a loop that never finishes); `side` is
/// dropped the moment `work` is done. std-only: this crate has no async runtime dependency.
async fn while_running(work: impl Future<Output = ()>, side: impl Future<Output = ()>) {
    let mut work = std::pin::pin!(work);
    let mut side = std::pin::pin!(side);
    let mut side_done = false;
    std::future::poll_fn(|cx| {
        if work.as_mut().poll(cx).is_ready() {
            return Poll::Ready(());
        }
        if !side_done {
            side_done = side.as_mut().poll(cx).is_ready();
        }
        Poll::Pending
    })
    .await
}

/// One claimed family of [`run_claimed_pass`]: per ticket exhaustion → heartbeat → fresh permit →
/// [`process_row`] → fenced settle / retry / release, then one `advance_prefix`.
async fn run_family(
    shared: &SharedProjectionDeps,
    cfg: &PassConfig,
    policy: NoteChunkPolicy,
    bm25: &Bm25Probes,
    tickets: &[ClaimedTicket],
    outcome: &mut PassOutcome,
) {
    let Some(first) = tickets.first() else {
        return;
    };
    let key = &first.key;
    let family = StreamFamily::new(
        key.tenant_id,
        key.scope_kind.clone(),
        key.scope_id,
        key.domain.clone(),
        key.projection_kind.clone(),
    );
    for (index, ticket) in tickets.iter().enumerate() {
        let fence = TicketFence {
            lease_owner: Some(&cfg.lease_owner),
            attempts: ticket.attempts,
        };
        // A worker that dies on this ticket every time never reaches the retry branch below;
        // the claim's increment is what still bounds it.
        if ticket.attempts > cfg.max_attempts {
            tally(
                outcome,
                settle_exhausted(shared, ticket, fence).await,
                RowTerminal::Failed,
            );
            continue;
        }
        let renewed =
            stream_repo::renew_family_leases(&shared.pool, key, &cfg.lease_owner, cfg.lease_secs)
                .await;
        if !renewed.is_ok_and(|seqs| seqs.contains(&ticket.stream_seq)) {
            // The lease is gone (expired, maybe re-claimed): nothing of this family may be
            // written by this worker any more.
            outcome.last_error = Some(ErrorCode::DependencyUnavailable);
            outcome.lost_lease += (tickets.len() - index) as u64;
            break;
        }
        process_and_write(shared, cfg, policy, bm25, &family, ticket, outcome).await;
    }
    // One watermark move per family (j). A failure here is logged: the next pass over this
    // family (or the next write) moves it, and the settled rows above stay settled.
    if let Err(error) = stream_repo::advance_prefix(&shared.pool, key, shared.processor_id).await {
        outcome.last_error = Some(ErrorCode::DependencyUnavailable);
        eprintln!(
            "projection_worker: advance_prefix failed tenant={} scope={}: {error}",
            key.tenant_id.0, key.scope_id
        );
    }
}

/// One leased, heartbeated ticket of [`run_family`]: a fresh permit, [`process_row`], then the
/// fenced write its disposition calls for, counted into `outcome` ([`tally`]).
async fn process_and_write(
    shared: &SharedProjectionDeps,
    cfg: &PassConfig,
    policy: NoteChunkPolicy,
    bm25: &Bm25Probes,
    family: &StreamFamily,
    ticket: &ClaimedTicket,
    outcome: &mut PassOutcome,
) {
    let key = &ticket.key;
    let fence = TicketFence {
        lease_owner: Some(&cfg.lease_owner),
        attempts: ticket.attempts,
    };
    // A permit the cell registry refused is a Qdrant-side outage of this ticket like any other.
    let (terminal, class) = match (shared.mint_permit)() {
        Some(permit) => {
            let ctx = RowCtx {
                last_error: Mutex::new(None),
                pool: &shared.pool,
                embedder: shared.embedder.as_ref(),
                scanner: &shared.scanner,
                transport: shared.transport.as_ref(),
                permit: &permit,
                placement: &ticket.placement,
                family,
                embedding_version: &shared.embedding_version,
                projection_version: &key.projection_version,
                dimension: shared.dimension,
                policy,
                bm25,
            };
            let result = process_row(&ctx, ticket.stream_seq, ticket.commit_seq).await;
            if let Some(code) = *ctx
                .last_error
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
            {
                outcome.last_error = Some(code);
            } else if matches!(result.0, RowTerminal::Retry | RowTerminal::Failed) {
                outcome.last_error = Some(if result.0 == RowTerminal::Retry {
                    ErrorCode::DependencyUnavailable
                } else {
                    ErrorCode::InvalidInput
                });
            }
            result
        }
        None => {
            outcome.last_error = Some(ErrorCode::DependencyUnavailable);
            (RowTerminal::Retry, "qdrant_upsert_failed")
        }
    };
    if terminal == RowTerminal::Done {
        // Every dependency answered: the next outage failure is charged again.
        shared.dependency_down.store(false, Ordering::Relaxed);
    }
    // Review 2026-09-29 P1: an outage failure while the dependency is already known down is not
    // evidence against this ticket, so it spends no attempt and cannot exhaust — a Qdrant or
    // provider outage (or a quota/budget window) longer than the backoff series no longer FAILs
    // every ticket written during it. The first outage failure after a DONE is charged like any
    // transient, so a ticket that fails alone while others succeed is still bounded
    // (ADR-0048); the backoff still spaces the uncharged retries.
    let refund = terminal == RowTerminal::Retry
        && is_dependency_outage(class)
        && shared.dependency_down.swap(true, Ordering::Relaxed);
    let written = match terminal {
        RowTerminal::Retry if !refund && ticket.attempts >= cfg.max_attempts => {
            eprintln!(
                "projection_worker: stream_seq={} transient_exhausted last_class={class}",
                ticket.stream_seq
            );
            tally(
                outcome,
                settle_exhausted(shared, ticket, fence).await,
                RowTerminal::Failed,
            );
            return;
        }
        RowTerminal::Retry => stream_repo::release_for_retry(
            &shared.pool,
            key,
            ticket.stream_seq,
            fence,
            class,
            Some(cfg.backoff),
            !refund,
        )
        .await
        .ok(),
        RowTerminal::Pending => {
            stream_repo::release_pending(&shared.pool, key, ticket.stream_seq, fence)
                .await
                .ok()
        }
        _ => settle_row(
            &shared.pool,
            key,
            ticket.stream_seq,
            ticket.commit_seq,
            terminal,
            class,
            fence,
        )
        .await
        .ok(),
    };
    if written.is_none() {
        outcome.last_error = Some(ErrorCode::DependencyUnavailable);
    }
    if refund && written == Some(true) {
        outcome.refunded += 1;
    }
    tally(outcome, written, terminal);
}

/// Settles `ticket` `FAILED` `transient_exhausted` (ADR-0052 D-E); `Some(false)` = lease lost.
async fn settle_exhausted(
    shared: &SharedProjectionDeps,
    ticket: &ClaimedTicket,
    fence: TicketFence<'_>,
) -> Option<bool> {
    settle_row(
        &shared.pool,
        &ticket.key,
        ticket.stream_seq,
        ticket.commit_seq,
        RowTerminal::Failed,
        "transient_exhausted",
        fence,
    )
    .await
    .ok()
}

/// Counts one ticket's written outcome: `Some(true)` under its disposition, `Some(false)` (the
/// fence matched nothing) as a lost lease, `None` (the write itself failed; the lease expiry
/// returns the ticket) as a lost lease too — this worker no longer owns what happens to it.
fn tally(outcome: &mut PassOutcome, written: Option<bool>, terminal: RowTerminal) {
    if written != Some(true) {
        outcome.lost_lease += 1;
        return;
    }
    match terminal {
        RowTerminal::Done => outcome.done += 1,
        RowTerminal::SkippedByPolicy => outcome.skipped += 1,
        RowTerminal::Failed => outcome.failed += 1,
        RowTerminal::Retry => outcome.retried += 1,
        RowTerminal::Pending => outcome.pending += 1,
    }
}

#[cfg(test)]
mod classification_tests {
    use super::{RowTerminal, code_is_transient, pg_is_transient, terminal_for_missing_memory};
    use humaux_domain::error::ErrorCode;

    /// ADR-0052 D-E, the `ErrorCode` (embedding + secret scanner) and PG halves of the table (the
    /// Qdrant half is pinned in `qdrant.rs`). `Forbidden` is the scanner's gitleaks finding: the
    /// 2026-09-29 rehearsal retried one to `transient_exhausted` before this row existed. Fault
    /// injection: classify `ProviderPermanent` as transient ⇒ red, and a provider 4xx would retry
    /// to `transient_exhausted` instead of failing `embedding_rejected`.
    #[test]
    fn embedding_and_pg_errors_classify_per_the_adr_0052_table() {
        for transient in [
            ErrorCode::ProviderRateLimited,
            ErrorCode::ProviderTransient,
            ErrorCode::DependencyUnavailable,
            ErrorCode::RateLimited,
            ErrorCode::QuotaExhausted,
            ErrorCode::CostBudgetExceeded,
            ErrorCode::WaitingKey,
            ErrorCode::Internal,
        ] {
            assert!(code_is_transient(transient), "{transient:?}");
        }
        for permanent in [
            ErrorCode::ProviderPermanent,
            ErrorCode::InvalidInput,
            ErrorCode::Forbidden,
            ErrorCode::Unauthorized,
            ErrorCode::EntitlementRequired,
            ErrorCode::TenantBoundary,
        ] {
            assert!(!code_is_transient(permanent), "{permanent:?}");
        }
        assert!(pg_is_transient(&sqlx::Error::PoolTimedOut));
        assert!(pg_is_transient(&sqlx::Error::PoolClosed));
        assert!(!pg_is_transient(&sqlx::Error::RowNotFound));
        // 0167's retirable classes stay permanent; an open distill is not a failure at all.
        assert_eq!(
            terminal_for_missing_memory(Some("FAILED")).0,
            RowTerminal::Failed
        );
        assert_eq!(
            terminal_for_missing_memory(Some("PENDING")).0,
            RowTerminal::Pending
        );
    }
}

#[cfg(test)]
mod bm25_policy_tests {
    use super::in_cell_text_processing_allowed;
    use humaux_domain::ids::TenantId;

    /// ADR-0083 U4 / G6b-4 (T-RET-6b): the gate "a tenant whose policy forbids in-cell text processing gets no `bm25`
    /// and verify does not count it as missing" is `not_applicable` (§57.1): no tenant policy field for in-cell text
    /// processing exists (TenantDataPolicy has none, `control.egress_policies` carries only the external-retrieval
    /// switch), so the seam answers `true` for every tenant. The missing object is in this test's name, where libtest
    /// and the junit report show it. It is also the tripwire: the card that adds a policy field changes the seam, must
    /// change this assertion, and with it owns the real gate (a forbidding tenant's write carries no `bm25` and the
    /// verifier's missing count skips it). Fault: return `false` ⇒ red.
    #[test]
    fn not_applicable_no_tenant_policy_field_for_in_cell_text_processing() {
        for _ in 0..3 {
            assert!(in_cell_text_processing_allowed(TenantId::new()));
        }
    }
}

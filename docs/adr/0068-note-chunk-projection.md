# ADR-0068 — Note chunk projection: long verbatim notes as several retrieval points of one Memory (card 40d)

- Status: Accepted (2026-10-14). Implements ADR-0067 D-I's staged promise and lifts declared limit L-4.
  - Research: web-GPT batch 11 (ChatGPT Pro, 2026-10-14; TW `research_gpt_batch11_20261014.md`), checked against the code
    at main e26dbf4 (a code map of projection, registry, ledger, recall and embedding). This ADR is the main line's
    adjudication of that research and overrides it.
  - Delivered in slices 40d-0 … 40d-2 (below), one PR each. L-4 stays declared until 40d-2 has chunked every long note on the serving
    projection.
- Relates to: ADR-0067 (D-I, L-4), ADR-0062 (L7: PG cannot recompute card text), ADR-0057 (lifecycle tickets),
  §18.2 (card budget), §22–§23 (census, ledger, A2), §55 (single `build_request`), §78.1 (no hardcoded business
  config).

## Context

A note's body is up to 64 KiB, but the projection embeds one 600-char card: title + the first ~590 chars. The rest is
never recalled (L-4). The code assumes one retrieval point per Memory in 14 places:

| Area | Where |
|---|---|
| Point identity | `private_memory_points` identity and its UNIQUE key |
| Worker | `build_card` per memory, the vectors zip and length check, `Prepared.live`, `finish_row`, `expected_points` |
| Ledger | the `projection.stream_point_ledger` function, which counts memories |
| A2 | compares Qdrant point counts with that memory ledger |
| Recall | `candidate_count == cand_k` |
| Rebuild | the per-memory `without_stored_vector` |
| Serve switch | criterion ① compares visible point counts across versions |

Two facts frame every decision:

- Re-embedding every ordinary Memory to fix long notes is not acceptable.
- Four quantities are different and must never be conflated:
  - Memories;
  - expected point slots;
  - distinct vector inputs;
  - provider calls.

## Decisions

### D-A — Scope: notes over the legacy capacity only

- **Which memories are chunked.** Only a Memory with an identity contract (`identity_note_materializations`, i.e. a
  note) whose legacy card cannot hold it losslessly gets the chunk profile. The test is
  `char_length(title) + 3 + char_length(body) > 600`: a note has no entities or excerpt, and the template has three
  separators.
- **Everyone else.** Every other Memory goes through the unchanged `build_card`, profile `LegacyCardV1`. Its card bytes,
  `input_sha256`, fingerprint and v1 point id are byte-identical.
- **One construction entry.** `build_projection_plan(memory, target) -> ProjectionPlan` has two branches, and both the
  worker and rebuild use it.
- **Rejected:**
  - chunking every over-budget Memory, which changes ordinary memories' representation;
  - editing the global `build_card` / `CARD_TEMPLATE_HASH`, which re-embeds everything;
  - keying on `memory_type`, because a note can be any type.

### D-B — Algorithm `NoteChunksV1`: fixed scalar windows, count recomputable in SQL

- **Parameters.** Over the body's Unicode scalars: window W = 480, overlap 64, stride 416, ordinals from 0, half-open
  ranges.
- **Card text.** `title_prefix + "\n" + body[start..end]`, where the title prefix is at most 119 scalars. There is no
  trim and no normalisation.
- **Chunk count.** `C(L) = 1 + ceil(max(0, L − 480) / 416)`. Rust is the only constructor of chunk text. SQL implements
  only the count (`char_length`), and a parity test pins the two together.
- **Size.** 64 KiB of ASCII is at most 158 chunks.
- **Profile hash.** The parameters are frozen into the profile and hashed into a `card_profile_hash`. Changing a
  parameter makes a new profile; nothing reads it from a moving env.
- **Fingerprint (amended 2026-10-14, PR #15 review P1-2).** There is one embedding fingerprint per projection, as today
  (ADR-0064). It hashes the model, the contract (`projection_version`) and `CARD_TEMPLATE_HASH`. Chunking adds no
  per-profile fingerprint:
  - Migration 0232 allows one fingerprint per `embedding_version`, and a fingerprint already moves with
    `projection_version`.
  - A chunk card's profile is identified by the registry identity (`card_profile_hash`, `chunk_ordinal`) and its exact
    text by `input_sha256`, which is all a vector cache key needs. The vector depends only on the model and the input
    text.
  - `NoteChunksV1` keeps its own template hash constant, so `CARD_TEMPLATE_HASH`, and with it every legacy fingerprint,
    is untouched. The gate is `legacy_fingerprint_golden_unchanged`.
- **Title rule.** "Title is never cut" still governs `LegacyCardV1`. Chunk cards carry a bounded title prefix, and PG
  keeps the full title.
- **Rejected:**
  - paragraph/sentence chunking, which can come later as a new profile;
  - keeping only the first N chunks, which would be L-4 under another name;
  - a persisted `chunk_count`, which cannot describe two projection versions at once.

### D-C — Point identity v2 for chunks only

- **Legacy points.** They keep the v1 derivation, byte for byte. The registry UNIQUE key gains `card_profile_hash` and
  `chunk_ordinal`, and a v1 row must be legacy profile, ordinal 0.
- **Chunk points.** Their id is a length-prefixed SHA-256 UUIDv8 over `humaux.private-memory-point.v2`, all v1 fields,
  `card_profile_hash` and `chunk_ordinal`.
- **Duplicate chunk text.** It shares one `memory_vectors` row (same vector key) but stays distinct points.
- **No new projection version.** 40d ships on the serving projection in place (D-I below), so `projection_version`
  does not move and every legacy v1 point id stays byte-identical. A future `projection_version` bump would move every
  fingerprint and point id anyway, and that is outside this ADR.

### D-D — Ledger in point slots

- **Expected.** `projection.stream_point_ledger` counts expected point slots computed from PG: the legacy profile gives
  1, and a chunked note gives C(char_length(body)). Expected is never computed from the registry; an unbuilt note
  still expects all of its slots.
- **Settled.** A slot with a live registry point for its full identity and a DONE latest ticket.
- **Partial progress.** A note with 3 of 10 chunks done is S=3, U=7, never "Memory done".
- **A2.** `S ≤ visible ≤ S + U` stays a necessary, not sufficient, condition. The envelope labels the basis
  `projection_points`.
- **Serve switch.** Criterion ① no longer compares visible counts across versions. Each version must meet its own
  expected manifest (missing = 0, unexpected = 0, through the existing verifier keyed by point id).

### D-E — Recall grouped by Memory

- **Payload.** Each point gets a scalar keyword payload `memory_id` (plus `chunk_ordinal` and `card_profile_hash`).
  `memory_id` gets a keyword index.
- **Query.** Recall uses Qdrant `query_points_groups` with `group_by = "memory_id"`, `group_size = 1`, and
  `limit = candidate_memory_budget`. The budget keeps today's number, `min(top_k × 5, 200)`, but counts Memories now.
- **Verification.** Each group id is checked against the PG registry's resolution of its point; a mismatch is a
  projection inconsistency, never a result. The PG final gate stays the authority.
- **Refill.** A bounded refill (configured rounds and limit) applies when the gate leaves fewer than `top_k`.
- **Counts.** `candidate_count == cand_k` is replaced by `candidate_point_count`, `candidate_memory_count`,
  `eligible_memory_count` and `returned_count`, plus the budget. A response with fewer groups than the budget is valid.
- **`truncated`.** Carries a reason.
- **Scoring.** Score is max-over-chunks. A length-stratified eval goes with the switch (D-H), because max-score
  favours long notes.

### D-F — Embedding calls: bounded batches, per-call accounting, per-slot completion

- **Batch cap.**
  - Each provider call carries at most `max_batch_items` inputs: provider capability config, §78.1.
  - DashScope `text-embedding-v4` is documented at 10.
  - Today one call carries every card of an Evidence. That is already wrong for an Evidence with more than 10 memories,
    so the cap ships first as slice 40d-0.
- **Per call.** Each real call is one budget reservation, one model-call ledger row and one disclosure. The disclosure
  has one source row per (memory, ordinal) the input serves.
- **Response mapping.** Responses are mapped by their input index, never zipped blindly.
- **Retries.** A committed batch's vectors are reused on retry.
- **Completion.** A ticket becomes DONE only through a completion check that every expected slot is settled. Partial
  success is never DONE.
- **Admission cap.** `max_chunks_per_note_admission` is a config resource guard. It may block admission, but it never
  truncates C.

**40d-0 as shipped.**

- **Cap.** `EmbeddingModelDescriptor.max_batch_items` (`NonZeroU32`). The retrieval worker reads it from
  `HUMAUX_RETRIEVAL_WORKER_EMBEDDING_MAX_BATCH_ITEMS`; the key is required, so an unset key or `0` refuses boot (exit 2)
  in every mode, including `--run-once` and `--serve`, the only ones that batch cards. Those two check it before any
  connection.
  The bundle value is 10.
- **Where the split lives.** It lives in the DashScope adapter (`embed_cards` / `embed_cards_for_memories`): it splits
  the cards into consecutive slices and sends each slice through the existing single-call `embed`. The adapter is the
  one path every card embedding takes, so it already does the per-call accounting and knows the cap. As a result, the
  worker's `CardEmbedder` seam, its deps and the rebuild path are unchanged. Every slice is validated before the first
  request is sent. `embed` itself refuses any request over the cap, which covers the query path; query batching is not
  needed today.
- **Response mapping.** Responses were already mapped by index. The compatible-mode endpoint returns OpenAI-shaped
  `index` (not the native API's `text_index`), and `parse_embedding_response` refuses a short, long, duplicated or
  out-of-range index set and any wrong-width vector.
- **Retries.** A failed slice fails the whole call and returns no vectors. Earlier slices stay billed. The worker
  persists vectors only per memory in `finish_row`, after every vector is in hand, so the ticket retries whole and
  re-embeds every slice. Reusing a committed batch's vectors on retry (gate `retry_reuses_committed_batch_vectors`) is
  deferred to 40d-1b with the slot ledger (shipped in 40d-1b-iii-c: committed slots are reused per slot).
- **Gates.** `embedding_batches_respect_provider_limit` (7 cards with a cap of 3: requests 3/3/1, one ledger row,
  reservation and disclosure per request, and each card gets its own vector under reversed responses) and
  `a_duplicate_index_in_a_later_batch_returns_no_vectors`, both in `retrieval-provider::adapters`.
  `embedding_batch_cap_is_required_and_non_zero` is in `retrieval-worker::tests::exit_codes`.

### D-G — Whole-source seal before any outbound call

- **Order.** A note's full, untruncated title and body are sealed once (`SealedSource`, which can never be sent). Only
  then are its chunk cards sealed (`SealedCard`, as today), and only then does any provider call happen.
- **Failure.** A scan error, timeout or skip is never clean. A secret anywhere blocks every chunk of that Memory.
- **No self-exemption.** Note text cannot exempt itself: `gitleaks:allow` is disabled for source seals.
- **Excluded data.** `SECRET_MATERIAL` stays excluded before any of this (`indexing: "excluded"`).
- **Title cap.** The source seal needs a bounded title. `memory.note_put` already caps the title at 1024 bytes
  (ADR-0067 D-E).

### D-H — Output and lifecycle

- **Recall output.** Recall returns the whole PG Memory, never a chunk. Chunk ordinal and range stay an internal
  witness, used only after the final gate.
- **Response size.** The response byte budget is met by returning fewer Memories, never by cutting a body.
- **Lifecycle.**
  - Retire and tombstone already cover every point of a Memory.
  - Archive and unarchive must update every chunk's payload, and a lifecycle ticket is DONE only when all of them have
    been updated.
  - The PG final gate, not the index, guarantees that a superseded version is never returned.

### D-I — In-place delivery (amended 2026-10-14, PR #15 review P1-2)

- **No second projection.** Chunking is enabled on the serving projection. Because a new target projection version
  would move every ordinary Memory's fingerprint and point id (D-B), it would either re-embed everything or block. So
  the 40d-2 switch is a profile-policy flag, not a rebuild-and-switch.
- **Step 1: payload backfill.** Grouped recall needs `memory_id` on every point. Existing points get it by a fenced
  `set_payload` backfill: no vector is rewritten and no provider is called.
- **Step 2: chunk the long notes.** Only notes over the legacy capacity are re-projected, by a lifecycle ticket on
  their Evidence. Their chunk points are added under the same `projection_version`, and their legacy point is retired
  as described under "Retirement timing" below.
- **Ledger during backfill.** The slot ledger reports the backfill honestly: expected slots jump to C before the chunks
  exist, so the gap shows as unsettled, never as complete.
- **Serve switch.** Criterion ① stays as it is, because no version switch happens.
- **Where the profile policy lives (amended 2026-10-14, PR #15 review P2).** The policy is held in PG, keyed by the
  projection, and it is the one source that both the worker (which profile to build) and the ledger SQL (how many
  slots to expect) read. An env flag or a worker-side config would let the two disagree, and the ledger would then
  count slots the worker never builds, or the reverse.
  - Nothing that exists fits:
    - `projection.family_activations` (0185) is a per-tenant receipt of a VerifiedEmpty first activation. Its CHECKs
      pin `evidence_kind = 'VERIFIED_EMPTY'`, and a family that predates it has no row.
    - `projection.embedding_fingerprints` (0232) is keyed by `embedding_version`.
  - Shape (built in 40d-1b-i, below; `enabled_at` was dropped, because the enabling migration's
    `ops.schema_migrations` row already records when): `projection.card_profile_policies`, with columns
    `(domain, projection_kind, projection_version)` as PK and `note_chunk_profile_hash text NULL`.
    - The key is the projection, across tenants, and there is one row per projection. A missing row or a NULL hash
      means legacy only, which is today's behaviour.
    - Owner `role_migration_owner`. It is written only by a migration, so enabling a profile is a reviewed, versioned
      change (§78.1 forbids a moving config).
    - SELECT goes to `role_retrieval_worker`. The ledger definer reads it as its owner.
    - A non-NULL hash must equal a profile the code knows: `NOTE_CHUNKS_V1_PROFILE_HASH` today. The worker refuses
      to boot on an unknown hash.
- **Retirement timing (amended 2026-10-14, PR #15 review P2).** A long note's legacy point stays live until every one
  of its chunk slots is settled, so it keeps answering recall throughout. It is retired in the same completion step
  that settles the last chunk slot, in the same registry transaction and under the same ticket fence. This way the
  note never vanishes from recall: there is no window in which it has no live point.
  - A ticket that settles some of the slots, but not all, leaves the legacy point in place.
  - Until that step, the ledger counts the legacy point as an extra live point of the Memory. It is neither one of
    the C expected slots nor a missing one. A2's `visible ≤ S + U` therefore gets one point of slack per note that is
    mid-backfill, and 40d-1b's ledger must model that slack explicitly (a `points_retiring` term), never by loosening
    the bound.

**40d-1a as shipped.**

- **Rust.** `humaux_projection::note_chunks` holds the frozen `NoteChunksV1` constants (W 480, overlap 64, stride
  416, title prefix 119, separator `"\n"`, all in Unicode scalars). It provides:
  - `legacy_capacity_holds(title, body)`, which is title + 3 + body ≤ `CardBudget::default().max_chars`. The 3 is the
    legacy template's three `\n`. `fit_budget` drops the evidence placeholder whole before it cuts the body, so this
    is exactly the condition for the body to survive the legacy card.
  - `chunk_count`, `chunk_ranges`, `scalar_slice` (it slices only at scalar boundaries) and `chunk_card_text`.
  - `NOTE_CHUNKS_V1_PROFILE_HASH`.
  - `build_projection_plan(PlanInput { card, is_identity_note }) -> ProjectionPlan`, which returns either
    `LegacyCardV1(build_card's outcome)` or `NoteChunksV1(Vec<NoteChunk>)`.
    - A SECRET_MATERIAL note, or a note with no body, takes the legacy branch, where `build_card` excludes it or marks
      it unbuildable.
- **Chunk text.** Chunk entries carry plain `String` text, not a `RetrievalCard`. Sealing them (D-G) is 40d-1b's.
- **Not wired.** The worker and rebuild still call `build_card`.
- **SQL.** Migration 0237 adds `projection.note_chunk_count(text, text)`: IMMUTABLE STRICT PARALLEL SAFE, owner
  `role_migration_owner`, EXECUTE `role_retrieval_worker` only. The ledger definer runs as the owner and needs no
  grant. Its precheck refuses a non-UTF8 database, because `char_length` counts code points only in UTF8.
- **Gates.**
  - `legacy_cards_are_byte_identical`, `note_budget_boundary_is_exact`, `chunk_ranges_cover_entire_body`,
    `chunk_count_matches_ranges`, `profile_hash_is_pinned` and `multibyte_bodies_round_trip_without_splitting_a_scalar`
    are in `projection::note_chunks`.
  - `rust_sql_chunk_count_parity` is in `adapters::tests::note_chunk_count_parity`. It compares SQL, the Rust closed
    form and the slot count of the real plan.

**40d-1b-i as shipped (schema and identity; the worker is not wired).**

- **Legacy predicate in SQL.** Migration 0238 adds `projection.note_legacy_capacity_holds(title, body) -> boolean`,
  the twin of `legacy_capacity_holds`, with 0237's function shape and grants. A note's slot is legacy iff it holds
  (or the Memory is not a note, or the policy is legacy only), never because `note_chunk_count` is 1: a note with
  title 150 and body 460 is one `NoteChunksV1` slot, because its legacy card would cut the body.
  `rust_sql_chunk_count_parity` compares SQL, Rust and the real plan's branch and count over the whole matrix, and
  it requires the matrix to contain one-slot `NoteChunksV1` cases.
- **Empty body.** `legacy_capacity_holds` is true for an empty body (the legacy card loses nothing; `build_card`
  marks it unbuildable), so a long title with no body is never a title-only chunk. The SQL predicate has the same
  `char_length(body) = 0` arm, and 0237's count already returned 1 for that case.
- **Policy.** `projection.card_profile_policies` exists as D-I describes.
  - The 0011 projection defaults are REVOKEd, and `role_retrieval_worker` gets SELECT. No role but the owner can
    write it.
  - No RLS: there is no tenant column, and this is global config (the 0232 `embedding_fingerprints` precedent).
    The ledger definer's owner, `role_migration_owner`, owns the table, so it reads every row without a grant or a
    policy.
  - Seed: `private_memory` / `PRIVATE_MEMORY` / `v1` with a NULL hash. 40d-2 flips it with a migration.
  - A CHECK keeps `LegacyCardV1` out of the hash column. The rls-check matrix and Baseline §6.2.2 have the new
    column.
- **Plan input.** `PlanInput.policy: NoteChunkPolicy` (`LegacyOnly` | `NoteChunksV1`). It is parsed once by
  `NoteChunkPolicy::from_profile_hash(Option<&str>)`. A hash the build does not know (the legacy marker included)
  is `Err(UnknownNoteChunkProfile)`, never legacy. The refusal sits at the parse, not in the plan, so it fires once
  at worker boot (D-I) instead of per Memory in the middle of a ticket. An unknown hash cannot reach
  `build_projection_plan`, which stays infallible. A slice that falls outside the body's boundaries is a panic with
  an invariant message, not a dropped slot.
- **Registry identity v2.**
  - `private_memory_points` gains `card_profile_hash text NOT NULL DEFAULT 'LegacyCardV1'`
    (`LEGACY_CARD_PROFILE_HASH`) and `chunk_ordinal integer NOT NULL DEFAULT 0`.
  - CHECKs: length 1–128, ordinal ≥ 0, and legacy ⇒ ordinal 0.
  - Both columns are appended to `private_memory_points_exact_identity_unique`, which is dropped and re-added under
    its 0119 name. No FK references it, and the precheck asserts that.
  - `PrivateMemoryPointRegistration` carries the two fields. `deterministic` still mints the legacy slot with the v1
    id, byte for byte. `for_chunk(profile, ordinal)` re-keys to v2: the v2 tag, the v1 fields, then the profile hash
    and the big-endian `u32` ordinal, each length-prefixed.
  - Every existing caller and row is `(LegacyCardV1, 0)`.
- **Gates.**
  - `legacy_point_id_golden_unchanged` and `chunk_point_ids_are_distinct_and_bound_to_profile` are in
    `adapters::private_projection_registry`. Both pin ids recomputed outside Rust.
  - `repeated_chunks_share_vector_not_point` is in `adapters::tests::private_projection_registry` (PG only).
  - `plan_follows_the_projection_policy` is in `projection::note_chunks`.
  - `serving_projection_policy_is_seeded_legacy_and_read_only` and the extended `rust_sql_chunk_count_parity` are in
    `adapters::tests::note_chunk_count_parity`.
- **Left for 40d-1b-ii.** The worker reads the policy at boot (refusing an unknown hash), builds through
  `build_projection_plan`, seals the source, registers one point per slot with vector-key dedupe, and uses the slot
  ledger and the DONE completion check. Rebuild works per vector key, and the legacy point retires in the
  last-slot step.

**40d-1b-ii as shipped (the worker; the slot ledger is not wired).**

- **Policy.** `--serve` / `--run-once` read the `card_profile_policies` row of their claim family after the
  fingerprint binding and before the first pass. A missing row or a hash the build does not know refuses boot
  (exit 2, `card_profile_policy_missing` / `card_profile_policy_unknown`); a database failure is a failed pass, as
  for the fingerprint. Each pass (and each `run_once`) then reads the row once, before it claims anything, and plans
  every ticket under it. At pass time a missing row reads as NULL, as the ledger reads the same row, so a test or
  rebuild family with no row stays legacy only; only the binary's own projection is required to have one. An
  unknown hash at pass time refuses the pass (`InvalidInput`) before any ticket is touched.
- **Identity note.** `resolve_memories` reads `EXISTS (identity_note_materializations.output_memory_id = memory_id)`
  in the statement that resolves the ticket's Memories. Migration 0239 grants `role_retrieval_worker` SELECT on the
  contract table (0235's FORCE RLS policy unchanged); the rls-check matrix and §6.2.2 carry the cell.
- **Plan.** Every live Memory goes through `build_projection_plan` with the pass's policy. `LegacyCardV1` is
  exactly the old path: one slot, `deterministic`'s v1 id, the old payload. `NoteChunksV1` is C slots, each a
  `RetrievalCard` from `note_chunks::chunk_card`: `card_text` = the chunk text (what is sealed, hashed and
  embedded), the note's `memory_id` / `data_class` / §18.2 fields, the full title in `title`, the window in
  `key_claim`, and the legacy `card_builder_version` / `card_template_hash` pair (§18.4: one hash per builder
  version; the fingerprint is per projection, D-B). The profile is named by the registry identity, never by the
  card.
- **Source seal (D-G).** `local-secret-scan::SealedSource`: no text and no accessor to any, accepted by nothing but
  `seal_chunk_card`, which refuses a card of another Memory or data class. `seal_source` scans
  `title + "\n" + body` once with the same gitleaks invocation (`--ignore-gitleaks-allow`), under
  `SEALED_SOURCE_MAX_BYTES` = 1024 + 1 + 65 536 (ADR-0067 D-E's caps), not the 16 KiB card cap or the configured
  disclosure cap. Every chunked note of a ticket is source-sealed before any card is sealed and before the one
  embedder call. A finding is `FAILED secret_scan_rejected` for the whole ticket and a scanner that did not run is a
  retry, exactly the legacy card path; no chunk of the note is sent.
- **Per-slot preparation.** `Prepared.live` is one entry per live Memory holding one entry per expected slot
  (profile, ordinal, `input_sha256`, vector): the per-memory grouping is what the completion step and the legacy
  retirement need. Stored-first is unchanged (all slots stored ⇒ no seal, no call). Otherwise each distinct vector
  key (memory, `input_sha256`; the fingerprint is the label's) is sealed and embedded once, in the 40d-0 bounded
  batches, and its vector is handed to every slot with that key through a key lookup. The length and width checks
  are per distinct input. Duplicate slots share one `memory_vectors` row and stay distinct points.
- **Register and upsert.** Per slot, in ordinal order: the seq-fenced upsert, then the registration with its
  vector, as before. A chunk slot uses `deterministic(...).for_chunk(NOTE_CHUNKS_V1_PROFILE_HASH, ordinal)` and its
  payload gains `card_profile_hash` and `chunk_ordinal` (`IndexablePayload::with_chunk`); a legacy payload is byte
  for byte what it was. One upsert request per slot (marked `ponytail:`).
- **DONE.** A Memory counts toward DONE only when the visibility probe confirms every one of its slot ids; any
  failed or unconfirmed slot leaves the whole ticket on the existing retry / fail outcome.
- **Legacy retirement (D-I).** After every chunk slot of a note is registered and confirmed, the same completion
  step retires the note's `(LegacyCardV1, 0)` bindings (`retire_legacy_point_for_memory`, a narrowed
  `retire_points_for_memory`) and deletes their points under the ticket's seq fence. It is a registry transaction of
  its own right after the last slot's, not the same one: the registry has no multi-binding write, and the order
  (every slot registered and visible, then retire) already rules out a window with no live point. A failed retire or
  delete leaves the ticket not-DONE; the retry re-registers the chunks (`AlreadyRegistered`) and retires again
  (every legacy id ever bound is returned).
- **Gates.** `legacy_cards_are_byte_identical_end_to_end`, `long_note_is_projected_as_chunks`,
  `repeated_chunk_text_embeds_once`, `source_seal_blocks_a_secret_anywhere` (the last-window token, a PEM block
  straddling a window boundary that no chunk holds whole, and the legacy control), `legacy_point_retired_only_with_last_chunk`
  and `partial_chunks_are_not_done` are in `adapters::tests::projection_worker::note_chunk_projection`; they hold one
  process-wide lock on the global policy row and restore it on drop. `boot_refuses_unknown_or_missing_policy` is in
  `retrieval-worker::main::config_tests` (the refusal → exit-2 mapping, no database; `boot_checks` reaching
  `check_policy`, and a missing row reaching the refusal, are not covered without a database — left for 40d-1b-iii).
  The policy lock is per process: the suite relies on `cargo test` running test binaries one after another.
  `secret_material_note_is_never_chunked` and `chunk_card_carries_the_chunk_text_and_the_note_identity` are in
  `projection::note_chunks`; `source_seal_scans_the_whole_note_under_its_own_cap` and
  `chunk_card_seal_is_bound_to_its_own_source` in `local-secret-scan`; `chunk_fields_ride_only_chunk_payloads` in
  `adapters::qdrant`. `rust_sql_chunk_count_parity` gained the NULL-body arm: both SQL functions are STRICT, and a
  caller coalesces the predicate to true (legacy), as the plan treats a Memory with no body.
- **Left for 40d-1b-iii.**
  - The slot ledger (shipped in 40d-1b-iii-a, below).
  - Rebuild per slot (shipped in 40d-1b-iii-b, below).
  - Retry reuse of committed batch vectors (shipped in 40d-1b-iii-c, below).
  - Disclosure granularity: the embedder receives one Memory id per distinct input, not one source row per
    (memory, ordinal) the input serves (D-F) — declared in 40d-1b-iii-c, below.
  - The ADR gates `chunk_backfill_embeds_only_note_chunk_inputs` (shipped in 40d-1b-iii-c),
    `ledger_counts_unbuilt_chunk_slots` and `partial_projection_does_not_settle_memory` (40d-1b-iii-a) and
    `equal_counts_do_not_prove_manifest_equality` (40d-1b-iii-b); `source_seal_cannot_be_disabled_by_note_text` as a
    named gate is still open (the source seal reuses the invocation that already passes `--ignore-gitleaks-allow`).

**40d-1b-iii-a as shipped (the slot ledger).**

- **Ledger v3 (migration 0240).** `projection.stream_point_ledger` counts expected point slots. A Memory is CHUNKED
  when the projection's policy names a profile, it is the output of an identity contract, its content carries string
  `title` and `key_claim` (what `note_repo::memory_content` writes), and `note_legacy_capacity_holds` is false:
  `build_projection_plan`'s predicate, with the secret term carried by the `indexable` fence every count already has.
  A CHUNKED Memory is C = `note_chunk_count(title, body)` slots, any other one slot.
  - Settled: a legacy Memory exactly as v2; a CHUNKED one by its built slots (distinct live registry ordinals < C
    under the policy's profile), and only under v2's settled filter (no pending ticket, latest DONE). A note whose
    chunks were never built settles 0 of C, and a note whose chunk ticket is still retrying settles none of its slots
    (they are in flight).
  - Unsettled: v2's term in slots, plus `C - built` of a CHUNKED Memory settled short (the backfill gap).
  - `points_retiring` (a fifth column): CHUNKED, indexable, not tombstoned Memories that still hold a live
    `LegacyCardV1` row, or any `LegacyCardV1` row while the latest ticket is not settled DONE: the completion step
    retires the binding, then deletes the point, then settles the ticket, so between the first and the last a retired
    binding can still be a visible point (0 or 1). The return shape changes, so the function is dropped and re-created in one transaction (the
    0200 precedent), one definer as before. With no policy row or a NULL hash, v3's four v2 columns equal v2's and
    retiring is 0.
- **A2 (Baseline §23.1② amended).** `L <= visible <= L + Q + R` is closed and `<= L + Q + R + F` in flight; the
  ratio is `(visible - R) / U`. `points_retiring` rides on `ProjectionReads` and on the wire's `pipeline.projection`
  block (`contracts/mcp/context.output.schema.json`).
- **Gates.** `ledger_counts_unbuilt_chunk_slots` and `partial_projection_does_not_settle_memory` in
  `adapters::tests::projection_worker::note_chunk_projection` read the real definer as `role_gateway`;
  `retiring_legacy_point_is_band_slack_not_ratio` in `retrieval::envelope`.
- **Declared (ledger).**
  - The policy is one-way: a hash set back to NULL after chunks are built counts each note as one slot while its C
    chunk points stay visible, so its streams read `cannot_establish` until every such note is re-projected legacy.
    Turning chunking off is a re-projection, not a policy edit.
  - A retired legacy row is kept, so a fully chunked note counts 1 retiring again whenever a later ticket on it
    (an archive, say) is in flight or failed: one point of extra top slack, never a lower bound.
  - `points_retiring` widens only the band's top. A legacy point lost from Qdrant while 0 of C chunks exist leaves
    the note unrecallable and the ledger closed: the same shape as Q's slack (ADR-0057 known limit 12), now per
    note mid-backfill.
  - The definer reads `identity_note_materializations` under 0235's policy, whose Evidence arm the caller's
    visibility must admit. `note_repo` gives a note's Evidence and Memory the same visibility, so a Memory the
    caller counts is a Memory whose contract row it sees; the gates seed TENANT_SHARED notes only.
- **Declared.** The SQL predicate reads `title` and `key_claim` as strings; the worker's `card_input` falls back to a
  truncated rendering when `title` is not one. An identity note always carries both (ADR-0067 D-E), so the two agree
  on every Memory the policy can chunk.

**40d-1b-iii-b as shipped (the rebuild verifier per slot).**

- **Project(PG).** `projection_worker::expected_points` takes the projection's policy and plans each Active memory
  through the worker's own `plan_slots`; every slot's id and payload come from `slot_point`, which `finish_row` now
  writes through as well. So a chunked note is C expected points with their v2 ids and chunk payload fields, a legacy
  memory exactly one point as before, and the verifier still has no second card, plan or payload builder (ADR-0064
  D-F X).
- **Policy.** `rebuild::read_pg_side` reads `card_profile_policies` for the stream's projection once per verify, as
  the worker's pass does (a missing row is legacy only); a hash this build has no profile for refuses the verify
  (`InvalidInput`, exit 2). The registry side, the vector join on `input_sha256` and E3's id-set differences were
  already per point.
- **Gate.** `equal_counts_do_not_prove_manifest_equality` in `adapters::tests::rebuild` (S3): a chunked stream verifies
  `equivalent`, and moving one chunk point to a foreign id at an unchanged count names both ids.

**40d-1b-iii-c as shipped (retry reuse; the remaining 40d-1b gates).**

- **Retry reuse.** `slot_vectors` is stored-first per slot: a slot whose vector is stored under the label's
  fingerprint and its exact input reuses it, and only the distinct keys without one are sealed and embedded. A retry
  after a partial failure therefore embeds only the slots that never committed. The all-stored case is unchanged (no
  seal, no call); when some key is missing, every chunked source of the ticket is still sealed before the call.
- **Gates.** `retry_reuses_committed_batch_vectors` and `chunk_backfill_embeds_only_note_chunk_inputs` in
  `adapters::tests::projection_worker::note_chunk_projection`.
- **Declared, not built.**
  - Disclosure granularity stays one Memory id per distinct embedded input: an `ops.data_disclosure_sources` row
    names the Memory and the input's position in the call, not which chunk was sent (no input digest is recorded).
    So the audit answers "this note left in this call", never "this window of it" — when several chunks of one note
    share a call, or the note is later replaced, the chunk-level trail is lost. Upgrade path: record the input
    digest per source row (a disclosure-schema change, its own card). Signal: an audit that needs the window.
  - The boot wiring (`boot_checks` reaching `check_policy`, and a missing row reaching the refusal) stays covered by
    the refusal mapping only: exercising it end to end means booting `--run-once` with the full Qdrant, gitleaks and
    cell configuration against a migrated throwaway database. Upgrade signal: a boot-path refactor in
    `bins/retrieval-worker`.

**40d-1c-i as shipped (the `memory_id` payload and its index).**

- **Payload.** `QdrantPointPayload` carries `memory_id` (a required field, so every constructor names it), written as
  the scalar keyword `memory_id` on every point, legacy and chunk alike. The projection worker fills it from the
  resolved Memory; the rebuild verifier's Project(PG) derives the same payload through the same builder.
- **Index.** `collection_setup_puts` PUTs a third payload index, `memory_id` keyword, after `tenant_id` and
  `subject_ids`; it is part of the collection's generation digest, so a collection created earlier reads
  `collection_misconfigured` until `collection ensure` (idempotent) adds it — runbook §3 says so.
- **Gate.** `every_point_names_its_memory` (`adapters::qdrant`), and the provisioning sentinel pins the third index.
- **Declared.** A point written before this slice has no `memory_id` until 40d-2's `set_payload` backfill (or a
  re-projection) writes it, so a rebuild verify of such a stream reports a payload difference on every such point.
  Recall does not read the field yet: grouped recall (40d-1c-ii) is gated on the backfill.

## Slices

| slice | scope | L-4 |
|---|---|---|
| 40d-0 | Provider `max_batch_items` (config) + index-mapped responses + per-call accounting for every projection call. Fixes today's latent >10-cards-per-Evidence bug. | declared |
| 40d-1a | Pure `ProjectionPlan` + `NoteChunksV1` + profile hash + SQL count function + Rust↔SQL parity test. Not wired. Zero-re-embed gates for legacy cards. | declared |
| 40d-1b | Registry identity v2 + UNIQUE key migration; worker per expected point with vector-key dedupe; source seal; slot ledger; DONE completion check; rebuild per vector key. Target projections admit only the legacy profile, so behaviour is unchanged. | declared |
| 40d-1c | Qdrant `memory_id` payload + keyword index; grouped recall behind a flag; envelope count fields. | declared |
| 40d-2 | In place on the serving projection (D-I): a `set_payload` backfill of `memory_id` on every live point (no vector, no embed); enable `NoteChunksV1` through the frozen profile policy; re-project only notes over the legacy capacity (lifecycle tickets on their Evidence); enable grouped recall; length-stratified recall eval. | lifted when every long note's slots are settled |

## Gates (each shown red once on CI before it counts)

- **Zero re-embed.** `legacy_cards_are_byte_identical`; `chunk_backfill_embeds_only_note_chunk_inputs`, with a provider
  spy that fails on any ordinary-Memory source.
- **Boundary.** `note_budget_boundary_is_exact`.
- **Chunking.** `rust_sql_chunk_count_parity` (CJK, emoji, combining marks, CRLF, boundaries) and
  `chunk_ranges_cover_entire_body`.
- **Identity.** `legacy_point_id_golden_unchanged` and `repeated_chunks_share_vector_not_point`.
- **Ledger.** `ledger_counts_unbuilt_chunk_slots` and `partial_projection_does_not_settle_memory`.
- **Verification.** `equal_counts_do_not_prove_manifest_equality`.
- **Fingerprint.** `legacy_fingerprint_golden_unchanged`.
- **Recall.** `one_long_note_cannot_monopolize_candidates` and `group_identity_is_verified_against_registry`.
- **Embedding calls.** `embedding_batches_respect_provider_limit` and `retry_reuses_committed_batch_vectors`.
- **Source seal.** `source_seal_detects_cross_chunk_secret`, `source_seal_cannot_be_disabled_by_note_text` and
  `secret_in_last_chunk_blocks_first_batch`.
- **Output and lifecycle.** `tail_chunk_hit_returns_full_memory`, `archive_updates_every_chunk` and
  `superseded_chunks_never_escape_final_gate`.

## Declared limits

- **L-7.** Two races already exist for single points and are not widened in kind; one availability effect is new (third
  bullet). They are bounded by the PG final gate
  and by retire convergence; neither can return content the gate refuses.
  - A Qdrant upsert can arrive late, after a retire, and insert a point the registry never saw.
  - Payload ordering of lifecycle re-upserts rides on `source_stream_seq`, not a payload revision.
  - New with grouping (`group_size = 1`): a stray point can become a Memory's group representative, fail registry
    verification, and hide that Memory's real chunks for that query. It hides; it never leaks.
  - Signal: a reconciliation finding of unexpected points, or a lifecycle payload regression.
- **L-8.** Max-over-chunks scoring favours long notes. Grouping fixes candidate monopoly, not ranking bias. Signal: the
  length-stratified eval at the 40d-2 switch.

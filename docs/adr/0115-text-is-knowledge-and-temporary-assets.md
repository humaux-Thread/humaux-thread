# ADR-0115 — Text is the knowledge; the uploaded file is a temporary asset

- Status: Accepted (2026-10-26). Card M17-1 (docs only, wave D, module M17). ADR-M17-a (this ADR). Records module
  design note M17 v2 D1 and D2 (note :59, :68), the untagged M17 decisions that serve the same topic — D3 (:75), D4
  (:85), D5 (:90), D12 (:155), D15 (:168) — and the ADR-0079 amendment set A1 (note §4.1, :172-180). Content authority:
  the owner's 2026-10-23 ruling, owner (49166827), and the lead rulings at note :9-11. This ADR records them and
  re-decides none. No code, migration or gate lands with it.
- Amends: ADR-0079 D-B, D-C, D-J, D-K and D-L through amendment A1 (below); Baseline §29, where the store holds a
  session temp prefix instead of content-addressed originals.
- Relates to: Baseline §4.1, §4.3, §8.1, §8.3.1, §10.1, §28, §29, §37, §52, §78.1, §78.2, §80.1; ADR-0079 (document
  layer), ADR-0082 (`DROP NOT NULL` path, note :71), ADR-0092 (deletion pipeline), ADR-0117 (self-check before publish),
  ADR-0119 (parse sandbox).

## Context

- The owner's 2026-10-23 ruling, owner (49166827), is that originals are not kept: after extraction only text remains,
  and processing uses the user's own model (note :7-9). It overrides ADR-0079's original-retention parts (note :9).
- What exists today (note :35-46): `private.evidence_objects(payload_sha256 bytea NOT NULL …)`; `private.artifacts(
  artifact_kind …, object_locator text NOT NULL, processing_manifest jsonb)`; `private.artifact_parts` (0 rows); no
  upload session; `contracts/mcp/artifact.schema.json` declared only; `adapters::audit_sink::ObjectStore` is one `put`
  with no implementation; `adapters/src/s3.rs` is a stub; ADR-0079 accepted but T-DOC-1…6 not built.
- The gap (note :51): ADR-0079 keeps originals (D-B/D-C/D-J/D-K), so text-only knowledge needs an amendment, one
  temporary store with one deadline, and one copy of the text in PostgreSQL.
- The note supersedes its v1 rows "receipt points at a retained object", presigned POST, version sealing, §29 object keys
  per receipt, and ranged-GET hydrate (note :19-23).

## Decisions

### D-A (D1) Text is the knowledge; the file is a temporary asset

Upload → `private.upload_sessions` (PENDING → ACCEPTED → PROCESSING → PUBLISHED | PARTIAL_ACCEPTED | WAITING | REJECTED
| EXPIRED) with `received_at`, `deadline_at`, `review_window bool` chosen before upload, temp `content_sha256` and a
nonce (note :59-62).

The original and every derived item (page images, extracted embedded images, audio segments, archive members) live
under one temp prefix `tmp/<tenant>/<session>/` of the ObjectStore fs implementation (note :62-64).

Deadline = `received_at` + 24 h, or + 72 h if the user opted in; DB CHECK `deadline_at <= received_at + 7 days`. Nothing
(waiting for key, budget, capability, retry) ever moves it (note :64-65). N=0: at the PUBLISH commit the purge is
enqueued in the same transaction; review-window sessions purge at the deadline (note :65-66).

Rejected: keeping originals (owner); a user-extendable window (lead ruling); UNLOGGED session rows — a crash would orphan
temp files without their deadline, so rows stay logged (≈ 300 B, purged 7 d after terminal) (note :66-67).

### D-B (D2) Evidence is born at PUBLISH, from the text

One transaction: receipt Evidence (`UploadedArtifact`, kind per route) whose `payload_sha256` =
`evidence::payload_sha256(canonical extraction text)` — the single constructor, never the original's bytes, so G-DOC-16
holds; `private.artifacts.object_locator` → NULL (DROP NOT NULL; ADR-0082 path); `document_receipts`
(`received_payload_kind = ORIGINAL_BYTES`, `original_bytes_verified` = hashed during processing, a new
`original_retained = false` CHECK, `coverage`); `document_extractions` (+ `unit_outcomes jsonb`, `scan_state`,
`confidence_label`); text blocks; an Observation through the M07 door; outbox (note :68-73).

§28/DOD-034 holds: parse and model calls run only after the session is ACCEPTED, and nothing is indexed before PUBLISH
(note :73-74). A delete during processing → `STALE_INPUT` (note :74).

### D-C (D3) `private.document_nodes` is authoritative (amends ADR-0079 D-C)

Row = (extraction_id, ordinal, kind, body text 1..cap B, start_cp, end_cp, anchor jsonb, derivation {LOCAL_TEXT,
MODEL_VISIBLE_TEXT, MODEL_DESCRIPTION, MODEL_INFERENCE, LEGACY_UNVERIFIED}) (note :75-77).

`body` is the only copy of the text; a Qdrant payload carries ids and filter fields only. The cap comes from config,
start 1,500 B (§78.1) (note :77-78). Kinds = the ADR-0079 DoCO set + formula, ui_element, transcript_segment,
audio_missing, unit_gap, a closed enum plus CHECK (§78.2) (note :78-79). Visible text, description and inference are
separate blocks; an unreadable value is a `unit_gap`, never guessed (note :79-80).

Anchors (closed set): pdf page+bbox(pt), docx part+paragraph/table id (no pages), pptx slide+shape (reading order flagged
unknown), xlsx sheet+A1 range, email part path, archive member path, audio track+start_ms+end_ms, image region; plus a
code-point range (W3C TextPosition). ADR-0079 selectors resolve over the concatenation of blocks in ordinal order (note
:80-83).

Rejected: B32's separate `text_block` table (a second home for Extraction text); a text object in the store (an original
by another name) (note :83-84).

### D-D (D4) Dedupe: a live session's hash, and nothing after purge

Message identity stays M06 D1 (unchanged). An uploaded file's identity = its receipt. `content_sha256` exists only on the
live session, scoped to (tenant, owner user): an identical upload while one is live reuses that session's model results
(one paid call) and gets its own receipt and blocks (G-DOC-1 kept) (note :85-87). The hash is nulled at purge; disclosure
rows hash `sha256(nonce‖payload)` with the session nonce, which dies with the session. After purge only "similar text"
(M15 consolidation) can be said. No cross-tenant or external existence query (G-DOC-16) (note :87-89).

### D-E (D5) Per-type routes: local = sandboxed Rust, model = the user's BYOK binding

Each unit gets an outcome (note :90):

- image/screenshot: `infer` sniff, header dims, frame count, 40 MP/frame + cumulative cap, EXIF stripped and scanned as
  text → model OCR plus table/chart/UI description; resize in the sandbox only to fit the model's limit, recorded
  `downscaled` (note :91-93).
- PDF text layer: `lopdf` per-page manifest + `pdf-extract` candidate text; pages with image XObjects, tables, formulas,
  multi-column order or anomalies (U+FFFD, duplicate runs, order breaks) → embedded images to vision, or native PDF
  input when probed; local text stays `LOCAL_TEXT` until the self-check passes (note :94-96).
- scanned PDF: native PDF if probed, otherwise extractable page images to vision; no Rust renderer in v1; else WAITING
  ("switch model or re-upload as images"), clock running; mixed = per page; encrypted PDF → REJECTED `encrypted` (note
  :97-99).
- DOCX/PPTX/XLSX: `zip` + OPC + `quick-xml`; `calamine` values + formula text (no macros, external links or evaluation);
  embedded media → image route (note :100-101).
- email (`.eml` uploaded as a file): `mail-parser` MIME tree, charsets, CID; HTML → safe text, no remote fetch; each
  attachment → its route; `From` recorded as a claim, never an identity; agent-relayed messages stay M06 (note :102-103).
- audio: `symphonia` 0.6.1 audio codecs only, duration cross-checked by decode; segments 2–5 min with overlap, written as
  WAV sized under the model's per-request limit → ASR (diarization only if probed; speaker labels local, never
  identities); undecodable codecs (e.g. SILK/AMR) → REJECTED `unsupported_codec` (note :104-106).
- "screenshot with voice": (a) an image showing a voice bubble → an `audio_missing{visible_duration}` block, never a
  transcript; (b) image + audio uploaded together (one `bundle_id`) → both routes, blocks cross-anchored; (c) a screen
  recording = video → REJECTED `video_not_supported_v1` (lead ruling) (note :107-109).
- archives (zip only in v1): bounded recursion, actual decompressed bytes counted, path checks, members routed;
  encrypted/unknown members stay visible as `unit_gap` (note :110-111).
- md/plain text: strict UTF-8 → blocks (ADR-0079 T-DOC-2 path; `text_sha256` no longer equals a retained object) (note
  :112).

### D-F (D12) Upload transport: gateway streaming, resumable chunks

Gateway streaming upload in Rust with resumable chunks (`create_upload` → `PUT chunk n` → `commit`), the size cap
enforced while streaming, server SHA-256 over the received bytes (note :155-157). It replaces D-K's presigned POST (no
crate does POST policy; OCI lacks PostObject). Temp store = the ObjectStore fs implementation (single node; M23 v2 never
backs up temp assets). The S3 implementation is deferred; SeaweedFS is the CI emulator when it lands (note :157-158).

### D-G (D15) Deletion: ADR-0079 D-J, blocks in steps 2–3, a temp prefix at step 6

ADR-0079 D-J applies with: blocks deleted at steps 2–3 with the `document_*` rows; step 6 = the live temp prefix of any
in-flight session for R (delete + stat-verify; an API ack is not "verified absent"); no extraction objects exist (note
:168-170). Temp purge is independent of job success (a janitor by `deadline_at`) (note :170).

## ADR-0079 amendment A1 (recorded here, note §4.1)

| ADR-0079 point | was | becomes |
|---|---|---|
| D-B receipt | original bytes kept | `original_retained=false` (CHECK); `original_bytes_verified` = hashed during processing only |
| D-C extraction | md text = original object, nodes derived/rebuildable | text only in `document_nodes.body`; nodes authoritative; parser upgrade needs re-upload |
| D-J step 6 | delete original, excerpts, extraction objects (all versions) | delete live temp prefix only; blocks go with steps 2–3 |
| D-K upload | presigned POST + version seal; PDF/DOCX deferred | gateway streaming; temp store; PDF/OOXML/image/audio routes in sandbox |
| D-L legacy | replay originals, keep as legacy Version | C-M17-6: legacy text import or owner-key re-extraction; old MinIO untouched |
| Deferred | renditions, physical dedupe, PDF/DOCX | PDF/DOCX/OCR leave the list; renditions + physical dedupe rejected (no originals) |

C-M17-6 (note §5.1) has two deliverables and two states per legacy id. Text state, exactly one: `legacy_text_imported`
(default; no model call), `reextracted_complete|partial` (the owner opted in; that owner's binding only, never an admin
key), `needs_model`, `no_owner` (control list only, never written to a tenant), `missing_or_unreadable`,
`rejected(reason)`. The retirement state is `legacy_original_retirement_pending` for all; M25 reads the old MinIO by S3
GET only and owns the census, and deleting there is owner-only (note :192-198).

## Consequences

- Positive: a document's knowledge survives its file, and the file lives under one prefix with one deadline; Evidence is
  born from the canonical text, so the receipt's `payload_sha256` is never the original's bytes; the text has
  exactly one home.
- Cost: a parser upgrade needs a re-upload, because the original is gone (note :176); the temp volume is single-node
  (note :157, :323); every derived asset must be purged by the same deadline (note :65-66).
- Asks M26 and M25: consume C-M17-1 `artifact.*` v2 — create_upload, put_chunk, commit, status with §28 stages + unit
  outcomes + deadline, accept_partial, get/list/search, and no download of originals (note :183-185).
- Asks M14 and M15: resolve C-M17-4 over blocks; M14 hydrates artifact Evidence from blocks instead of
  `artifact_unavailable` (note :186-187).
- Asks M25: revise M25-9 to C-M17-6 (note :192).
- Asks M19: call M17 for step 6's live temp prefix (note :32, :190).
- Asks M07: the receipt Evidence and the Observation enter only through the M07 doors (note :30-31, :73).
- Asks M23: catalogue `document_*` as KNOWLEDGE and `upload_sessions`, `artifact_poison` and the probes as EXCLUDED; temp
  assets are never backed up (note :211).
- Neutral: no code, migration, config key or wire format changes with this card.

## Gates

Planned, implementer-owned, tri-state (§57.1); none exists in this card (note :249). ADR-0079's G-DOC-1…17 stay as
mapped, and M17-11 owns G-DOC-13 and G-M17-6 (note :241, :249). A missing database is a fail in CI, never
`not_applicable` (ADR-0050).

| gate | owner card | test file | injected fault | expected red |
|---|---|---|---|---|
| G-M17-1 quarantine (DOD-034) | M17-6 | `crates/adapters/tests/artifact_intake.rs` | enqueue a job at PENDING | a REJECTED upload has a job, block or Evidence |
| G-M17-2 server hash | M17-6 | same | trust client sha256 | mismatched bytes ACCEPTED |
| G-M17-8 ObjectStore contract | M17-2 | `crates/adapters/tests/object_store_contract.rs` | `delete_prefix` skips nested dirs | suite red on a derived asset |
| G-M17-6 temp purge | M17-11 | `crates/adapters/tests/object_purge.rs` | trust delete ack | DONE while a temp file still stats |
| A-3 type sniff | M17-6 | `artifact_intake.rs` + `testkit/ingest-threat` | trust extension | PNG-named PDF/polyglot accepted |
| A-5 image bomb | M17-6 | `artifact_intake.rs` | skip pixel cap | 1-kB 50k×50k PNG decoded |
| B-5 voice-bubble hallucination | M17-21 | `extract.rs` / `audio.rs` | transcribe without audio | transcript block without an audio unit |
| C-6 deadline extension | M17-15 | `crates/adapters/tests/upload_deadline.rs` | reset on WAITING; allow > 7 d | deadline moves; derived asset outlives parent |
| C-7 cleanup independence | M17-15 | same | purge only on success | failed job leaves temp past deadline |
| C-8 residual copies | M17-15 | same | skip N=0 purge | original present after PUBLISHED; temp in M23 set |
| C-11 hash residue | M17-15 | `upload_deadline.rs` | keep sha / unsalted disclosure hash | original's sha256 findable after purge |
| C-9 outbox vs delete | M17-7 | `document_repo` tests | skip overlay re-check | publish after tombstone succeeds |
| C-12 10 KB | M17-4a | `document_repo` tests + xtask storage-measure (M23) | lift block cap | 1,501-B block stored; harness p95 > target |

Each needs its inject → red → fix → green record (§80.1) in the implementing card.

## Owner-gated (listed, not decided)

Red lines, owner only (note :310-313): real model spend in production (probes, extraction, legacy re-extraction on
users' keys; CI uses fakes and test keys); deleting legacy originals in the old MinIO; live keys of any provider or
store. Open owner questions: none (lead rulings applied; v1 Q1 closed by "no originals") (note :313).

## Open research

- **U1.** Multi-node or large M16 content → an S3 implementation (SeaweedFS in CI); until then the fs store only (note
  :303).
- **U3.** A pure-Rust PDF renderer exists in no v1 route; a scanned PDF needs native PDF capability or a re-upload as
  images (note :305).
- **U4.** SILK/AMR decode → REJECTED `unsupported_codec`; the user exports MP3/M4A (note :306).
- **R5.** A maintained pure-Rust PDF page renderer, or confirmation that hayro has left experimental (note :314).
- **R6.** A Rust SILK/AMR decoder (MIT/Apache) (note :315).

## Alternatives rejected

Keeping originals (owner); a user-extendable retention window (lead ruling); UNLOGGED session rows (note :66-67); a
second `text_block` table (note :83); a text object in the store (note :84); presigned POST with version sealing (note
:19-20, :156-157); renditions and physical dedupe, rejected with no originals retained (note :180); the v1 ranged-GET hydrate
(note :22).

## References

- Module design note M17 v2 §4 (D1–D5, D12, D15), §4.1 (ADR-0079 amendment rows), §5 and §5.1 (contracts, C-M17-6), §6,
  §11 (UNKNOWNs with fallbacks), §12.
- Baseline §4.3, §4.1, §8.1, §8.3.1, §10.1, §28, §29, §37, §52, §78.1, §78.2, §80.1.
- ADR-0079 (document layer, D-B/D-C/D-J/D-K/D-L), ADR-0082 (amending an applied migration body), ADR-0092 (one deletion
  pipeline), ADR-0117 (self-check), ADR-0119 (sandbox).

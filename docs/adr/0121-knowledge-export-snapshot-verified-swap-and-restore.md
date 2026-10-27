# ADR-0121 — Knowledge export: one exported snapshot, a classified catalog, latest verified only, and a scratch-postmaster drill

- Status: Accepted (2026-10-23). Card M23-1 (docs only, wave F, module M23). Content authority: module design note M23
  v2, §3 (C7 v2, C-M23-0, C-M23-4), §7 D1–D11, §9 and §13. This ADR records those decisions and re-decides none of
  them, except the labelled lead ruling on issue #332 (D-A, D-F). No code, migration, gate or deployment lands with it.
- Supersedes in scope: ADR-0064 (note :192). One pointer line is added to ADR-0064; its text is not rewritten.
- Amends: Baseline §44 (backup/DR) and §66 (automatic operation); the C7 recovery contract shared with M10 (note :46,
  :192). The M10 note's ADR-M10-b has no real ADR id in this tree; the C7 amendment is recorded here only.
- Relates to: Baseline §16.3, §37, §44, §66, §81, §78.2; ADR-0064 (backup/PITR, drill, Qdrant rebuild); ADR-0062
  (bounded owner purge doors); ADR-0063 (partitions and retention); ADR-0084 (local rerank); ADR-0092 D-F (the erasure
  ledger and restore re-apply, M19); module design notes M10 (C7), M19 (D6/D8) and M21 (schedule register).

## Context

- The owner's ruling of 2026-10-23 is the highest authority: "只要把知识备份出来就行了，不要备份整个系统。备份到oracle服务器就好了，
  没有其他的异地备份地方。" (note :7-8). The lead interpretation recorded with it is memory `dc5792f5` `[decision] …
  backup = KNOWLEDGE only` (note :8). Still in force: keep only the latest backup (`06d03e76`); OSS users deploy
  locally to a standard (`29f37ded` → charter `829c952f`); Linux arm64 containers + compose, launchd/systemd rejected
  (`2614a613`) (note :8-10).
- Today backup is ADR-0064: pgBackRest (backup types full/diff/incr, WAL archiving, `restore drill|pitr`) and a host
  crontab (note :30-35, :137-138). Host loss = total loss (L37; note :36, :141-142).
- The only all-tenant reader today is the superuser one-shot; `rls_check.rs:2405` asserts every login role is NOT
  SUPERUSER / NOBYPASSRLS (note :39-40).
- M23 v2 supersedes its own v1 where it says so: the single pgBackRest full, the WAL boundary (the disk guard is kept),
  the Qdrant snapshot in the recovery generation, C7 v1 contents, `ops.recovery_items`, the v1 cards and gates, and
  the pgBackRest sidecar experiment (note :14-16).

## Decisions

### D-A Knowledge only, every table classified by a catalog

The export is the KNOWLEDGE catalog only (note :74-78): `private.{events, evidence_*, event_identity, messages,
conversations, observations, memory_records, memory_evidence, memory_subjects, memory_subject_*, memory_affects,
memory_projects, memory_project_revocations, memory_consolidation_inputs, note_heads, subjects, subject_keys,
subject_roles, relations, entities, continuity_*}`, `public.*` (pool knowledge + provenance),
`coord.{tasks, canvases, canvas_elements, handoffs}` and `ops.memory_lifecycle_events`; ownership tables
`control.{tenants, users, user_emails, workspaces, memberships, workspace_memberships, agents}`; governance tables
`control.{deletion_requests, retention_policies, partition_registry, contribution_policies,
contribution_confirmations}` plus M19's `deletion_targets` and `erasure_ledger` (note :78-82). A proposed knowledge
table (graph versions, applicability, `run_acceptances`, attribution columns on `memory_records`) joins by a catalog
row in its own card (note :82-83).

EXCLUDED: `projection.*` (derived), all other `ops.*` (logs, query log, jobs, outbox, receipts),
`coord.{leases, locks, task_runs}` (ephemeral/past retention), billing/quota/credit/referral (`credit_ledger` is
unused by any billing flow; Creem rebuilds the rest), credentials/sessions/challenges (D9),
`private.{ingest_tickets, distill_candidates, processing_runs, code_*, memory_rollups*, worktree_overlays}` (derived
or re-indexable), images/binaries/caches and Qdrant (note :83-87). Every catalog row is reviewed by
the table's owner module in M23-2 (note :87-88). Rejected: a physical full (owner: not the whole system) and a
schema-wide dump (drags derived data) (note :88).

**Lead ruling (2026-10-26, issue #332; draft authority, the owner may revise):** the catalog is closed under foreign
keys. For every NOT NULL foreign key from a KNOWLEDGE table, the referenced table is KNOWLEDGE too, or the
referencing table leaves KNOWLEDGE; the catalog row records which. `private.processing_runs` moves to KNOWLEDGE:
`private.observations.processing_run_id` references it NOT NULL (migrations/0005_private_pipeline.sql:33), and
observations without their run lose provenance. Every other crossing is resolved by this rule in M23-2's catalog
review, not here. The crossings known on 2026-10-26 (static read of `migrations/*.sql`):
`private.evidence_task_runs` → EXCLUDED `coord.task_runs` (0251:32, :39); and, to tables in neither list,
`private.evidence_objects` → `control.private_reasoning_domains` (0004:31, 0159:26-29),
`private.memory_consolidation_inputs` → `private.memory_consolidation_runs` (0005:64), and
`control.contribution_confirmations` → `staging.contribution_candidates` (0107:125-126). A nullable foreign key from
KNOWLEDGE to a non-KNOWLEDGE table (known: three to `staging.contribution_releases`, 0104:48-50, 0106:73, 0106:115)
is a catalog error unless its catalog row names the restore action `set_null`. M23-2 decides where that action
runs (the M23-4 drill and the M23-5 restore), before the restore FK audit.

### D-B Format: PG logical, `pg_dump -Fd --compress=zstd:3`, data-only, as the superuser

The dump is `pg_dump -Fd --compress=zstd:3`, data-only, run as the PG superuser (note :89). PG 18 defaults
`row_security=off`, and a user without bypass privilege gets an error, so a mis-roled run fails loudly rather than
producing a silently tenant-filtered dump (note :90-91). `--enable-row-security` is forbidden (G-M23-2; note :91-92).
Partitioned parents are selected with `--table-and-children` because `-t` does not add partitions (note :92-93).

A controller transaction in REPEATABLE READ calls `pg_export_snapshot()`, counts rows per table, and runs `pg_dump
--snapshot=<id>`, so the manifest counts and the dump see one snapshot (note :93-94). `-j` starts at 1 (the directory
format is the only parallel format) on 4 vCPU (note :94-95). The weighing recorded: exact rows, ids, enums
and timestamps over JSONL needing an unbuilt importer; superuser bypass with the docs' error-not-filter default over
an app JSONL loop where a missed tenant is silent; zstd binary COPY over per-row JSON; and no per-tenant reuse,
because `pg_dump` cannot filter by tenant, so M19 D8 keeps its own JSONL for user export while the shared fact is the
catalog (note :95-99).

Rejected: app JSONL per tenant (fidelity, silent-miss risk); a BYPASSRLS `role_backup` (§6.2.0 frozen set,
`rls_check`); `-Fc` (single file, no parallel dump, no per-table checksums) (note :99-100).

### D-C Embeddings are not part of the export

No embeddings sidecar (note :101). At 1024-d and fp16 the sidecar is ≈ 2,048 B/point × ≈ 1.1 points/memory ≈
2,250 B/memory (22% of the R11 ≤ 10,000 B/memory budget, held permanently); float32 is ≈ 4,500 B (45%). Qdrant's
turbo4 bytes are not exportable as stored, and a dequantized re-upsert is not guaranteed bit-stable (note :101-104).
Re-embed on restore is ≈ 15M tokens ≈ $1 and ≈ 50 min per 50k memories, unconfirmed until R11-K; OSS e5-small
re-embed is free CPU (note :104-105). Restore is rare and owner-run (note :105). The upgrade signal: R11-K re-embed
time above an owner-stated RTO, or measured B_all-in leaving ≥ 2.5 KB/memory headroom, reopens the question as an
fp16 `vectors/<fingerprint>.f16` sidecar with per-file sha256 (note :105-107). Rejected now: an fp16/fp32 sidecar
(budget for a ≈ $1 saving) (note :107).

### D-D Latest verified export only, swapped after the drill

Nightly: write `<ts>.partial/` → fsync → rename `<ts>/` → verify (sha256 every file, `pg_restore --list`, counts) →
drill (D-F) → write the `VERIFIED` marker → atomically swap the `current` symlink → delete the previous export
(note :108-110). A failure at any step leaves the previous `current` untouched and removes the failed candidate,
which is never verified; the receipt is FAILED and an alert fires (note :110-111). Peak disk is old + candidate +
drill scratch (note :111). Authority: the owner's "latest only" (`06d03e76`) and "verify before removing"
(`dc5792f5`) (note :111-112). Rejected: keeping 2 (owner); delete-then-write (a gap with no backup) (note :112).

### D-E Restores never resurrect deleted data

The export carries `deletion_requests/targets/erasure_ledger` as of its snapshot (note :113-114). Deletions after
it are covered by `erasure/journal.jsonl` on the export volume: M19's executor appends `{request_id, scope_kind,
target sha256 set, confirmed_at}` (content-free, fsync) as its first daemon step after confirm; lines older than the
current export's snapshot are pruned on swap (note :114-116). Restore re-applies journal lines after the export's
`erasure_journal_upto` through the purge door and resumes exported non-terminal requests BEFORE serving opens; the
residual window is confirm → journal write (seconds, priority lane) (note :116-118). The backup age-out is disclosed
to M19: until the next verified export (≈ 24 h normally, longer while exports fail — alert) (note :118-119).

### D-F The drill is a scratch postmaster inside the `dr` sidecar, with no Docker socket

The `dr` target is rebuilt FROM the pg image (the same PG 18.6 `pg_dump`/`pg_restore`/`initdb` as the server) plus
`humaux-maintenance` (note :120-121). Drill: `initdb` on a temporary directory → `migrate` to `schema_version` →
create `partition_months` → `pg_restore --data-only --disable-triggers` → per-table counts equal the manifest →
journal re-apply → `rls-check` → witness rows (note :121-123). The nightly drill is PG-only; the Qdrant rebuild leg
runs in CI/conformance with a stub or local embedder, with no weekly paid re-embed (note :123-124). The testkit
disposable guard refuses a live DSN (the G-M19-11 pattern; note :124-125). Rejected: a drill DB in the live cluster
(production DDL nightly); a compose project via `docker.sock` (no Docker socket, ADR-0064 L21) (note :125-126). The
gate is X-M23-1 (note :125).

**Lead ruling (2026-10-26, issue #332; draft authority, the owner may revise):** before the counts are accepted, the
drill audits every foreign key among the restored tables and fails naming any constraint with an orphan row, because
`--disable-triggers` skips FK checks and equal counts do not prove referential integrity.

### D-G Restore path

`restore knowledge --from <dir>` (runbook §11 rewrite) is: fresh install of the manifest's release → PG only → the
steps of D-F against the real cluster → M04 Creem reconciliation (until then tenants read as Free, data kept, owner
`c1152a05`) → open the gateway with exact/lexical lanes → M10 creates the generation for `embedding_fingerprint`,
paced re-embed, §16.3 switch → the semantic lane serves (note :127-130). Users sign in by email code (note :130). D7's
step said agents get new API keys (D9) (note :131); the owner's Q3 answer carries API-key hashes, so agents keep
working after a restore (note :254). Rejected: re-attaching the surviving Qdrant (the point registry is not exported
and A2 is unprovable) (note :131).

### D-H Disk guard

`DR_EVIDENCE` publishes `disk_used_ratio`; M03 refuses space-consuming work at 65% and warns at 60% (note :132-133).
The export preflight is estimate(previous export × 1.2) + drill scratch, and the export is refused if that does not
fit (note :133).

### D-I Credentials: the default is excluded; the owner answer carries API-key hashes

D9 records credentials as excluded under the owner's "knowledge only" — no secret hashes in files beside the data,
pepper rotation unaffected — with every agent re-keying after a restore, and D9 itself says the owner Q3 can flip it
(note :134-135). The owner answered Q3 on 2026-10-23: the export carries API-key **hashes** (never plaintext), so
agents keep working after a restore (note :254).

**Lead question (unresolved):** D-A excludes credentials/sessions/challenges (note :85-86) and D-G records the note's D7 step
"agents get new API keys" (note :130-131) beside the Q3 answer, which has the export carrying API-key hashes
(note :254). The exclusion and the answer are both recorded here; this ADR does not resolve the tension.

### D-J Schedule: `dr serve` inside the compose bundle

The nightly export + verify + drill + swap and the daily `deploy-check --running` drift check run from `dr serve` in
compose, driven by the M21 `resident.rs` loop; the export key defaults to 00:30 UTC (note :136-137). This retires the
host crontab and pgBackRest/WAL archiving: `archive_mode=off`, RPO = the last verified export (≤ ~24 h), and PITR is
gone (accepted with the owner scope) (note :137-139). Retiring pgBackRest and WAL archiving is card M23-7, after the
first verified production export, owner-gated (note :198, :239). It connects to PG as superuser over the shared unix
socket, with the secret via render-secrets (note :139). Rejected: host cron (outside the bundle); systemd timers
(rejected); the `--serve` daemon (`role_maintenance` cannot read all tenants) (note :139-140).

### D-K Stated risk: one disk, no offsite copy

The export lives on the same disk as the database; if that disk is lost, the data and the backup are lost together
(note :141-142). No off-host copy exists (owner) (note :142). The export protects against logical damage — bad
migration, operator error, corruption — only (note :143). The local export is unencrypted (same disk as plaintext
PGDATA; encrypt if a copy ever leaves the host) (note :143-144).

## Contracts

- **C7 v2 (with M10), knowledge export**: a `pg_dump` directory of the KNOWLEDGE catalog plus `manifest.json`
  `{format "humaux-knowledge-export/1", created_at, release digests, schema_version (last migration), pg_version,
  catalog_sha256, embedding_fingerprint, partition_months, tables[{name, rows}], files[{path, bytes, sha256}],
  erasure_journal_upto}` and a `VERIFIED` marker written last; Qdrant is NOT in C7 and is rebuilt from PG by M10
  re-embed (note :46-49).
- **C-M23-0** `docs/architecture/backup_catalog.toml`: every table → `KNOWLEDGE | EXCLUDED(reason)` (note :50).
- **C-M23-4 restore hooks**: erasure re-apply (M19 C-M19-2 + journal, D-E), Creem reconciliation before billing
  state is trusted, and the M10 rebuild before the semantic lane serves (note :52-53).
- Consumed: M10 rebuild/generation switch (§16.3), M19 erasure ledger + journal writer (M19-9 scope grows), M21
  resident loop + schedule register, M22 families, M04 reconciliation, M24 `experiment.yml` + image jobs, M11 rerank
  (note :54-55).

## Consequences

- Positive: the backup matches the owner's scope; one snapshot backs the manifest and the dump; the drill runs the
  same PostgreSQL binaries as the server without a Docker socket; a restore cannot resurrect a deletion that reached
  the journal; there is a single verified export on disk.
- Cost: RPO grows to the last verified export and PITR is gone (note :137-139); peak disk is old + candidate +
  drill scratch (note :111); a restore is owner-run and needs a re-embed before the semantic lane serves
  (note :104-105, :127-130). The owner's Q3 answer has the export carrying API-key hashes (note :254); the conflict
  with D-A's credential exclusion and D-G's re-key step is listed above as a lead question.
- Neutral for this card: no code, DDL, config key or gate is added; the gates below belong to later cards.

## Gates

Planned and tri-state (§57.1); none exists here. DB/compose tests treat a missing
`HUMAUX_TEST_PG_DSN`/Docker in CI as fail (ADR-0050) (note :165).

| gate | test file | inject | expected red |
|---|---|---|---|
| G-M23-1 latest-only swap | `bins/maintenance/tests/knowledge_export.rs` | delete previous before `VERIFIED`; skip delete after swap | failed candidate leaves no verified export; two verified exports in steady state (note :168) |
| G-M23-2 not RLS-filtered | same, two-tenant fixture | add `--enable-row-security` and run as a NOBYPASSRLS role | restored rows for tenant B ≠ manifest count (or run must exit non-zero) (note :169) |
| G-M23-3 catalog complete | `xtask` architecture check | add a table with no `backup_catalog.toml` row | check fails naming the table (note :170) |
| G-M23-3b FK closure (lead ruling, #332) | same `xtask` check + `knowledge_export.rs` drill | catalog `processing_runs` as EXCLUDED; skip the restore FK audit | check fails naming (`private.observations`, `private.processing_runs`); a restored orphan passes the drill |
| G-M23-4 scope honest | `knowledge_export.rs` | add `projection.memory_vectors` / a billing table; drop `memory_evidence` | excluded table in TOC; drill provenance check red (note :171) |
| G-M23-5 integrity | same | flip one byte; delete one file; edit a manifest count | verify refuses, no `VERIFIED`, `current` unchanged (note :172) |
| G-M23-6 one snapshot | same, concurrent-writer fixture | count rows in a separate txn | manifest counts ≠ restored counts (note :173) |
| G-M23-7 no resurrection | `bins/maintenance/tests/restore_erasure.rs` (shared G-M19-10) | skip journal re-apply; open serving first | deleted tenant readable after restore (note :174) |
| G-M23-8 drill isolation | `crates/testkit/tests/disposable_guard.rs` (extend) | point drill at the live DSN | drill runs instead of refusing (note :175) |
| G-M23-9 Qdrant from PG | `bins/maintenance/tests/restore_rebuild.rs` (stub embedder) | skip one stream; wrong fingerprint | A2 visible ≠ expected; switch refused (note :176) |
| G-M23-11 schedule runs | `bins/maintenance/tests/dr_serve.rs` + promtool | disable the export task | no `VERIFIED` in 26 h → `KnowledgeExportStale` fires; test red (note :178) |
| G-M23-12 no socket | `deploy-check` rule + compose test | mount `docker.sock` in `dr serve` | deploy-check exits 3 naming the service (note :179) |
| G-M23-13 disk preflight | `knowledge_export.rs` | omit scratch from preflight | test passes when it must refuse (note :180) |
| G-M23-19 backup_type enum | contract test (§78.2) | add `'knowledge'` in Rust only | Rust ≠ DB CHECK (note :186) |

Kept green: the card-39 deploy-check and rehearsal gates and `c39_budget_sums` (note :187). The card-37 suites retire
with M23-7 (note :187).

## Owner-gated (listed, not decided)

- **Q3** (genuine): "After a restore, should API keys survive (export credential hashes) or must every agent re-key
  (default, D9)?" (note :236). Owner answer 2026-10-23: "the export carries API-key **hashes** (never plaintext), so
  agents keep working after a restore." (note :254).
- Red lines (owner only, not decided here): "Running anything against production: first export / verify / drill on
  [the production node], enabling `dr serve` in prod, any `restore knowledge` or upgrade, retiring pgBackRest/WAL archiving and
  its repo in prod (M23-7)." — "Deleting the old export in production for the first time (first automatic
  swap-and-delete)." — "Also: live keys in any env." (note :237-241).

## Open research

- **U3** Whether the 12 GiB repo image exists on the production node (note :226). Fallback: bind directory + the D8
  guard; no production action (note :226).
- **U4** Whether the M10 rebuild works from KNOWLEDGE tables alone (empty outbox/stream_log/registry) (note :227).
  Fallback: add the minimal stream rows to the catalog as KNOWLEDGE (catalog change only); proven by G-M23-9
  (note :227-228).
- **U5** A DegradeCode for "semantic lane rebuilding" may not exist (note :229). Fallback: the gateway stays closed
  until the §16.3 switch (note :229).
- **U6** Exact KNOWLEDGE membership of borderline tables (`identity_note_materializations`, `memory_rollups*`,
  `public.poisoning_signals`) (note :230-231). Fallback: the owner module decides in M23-2; default EXCLUDED only if
  rebuildable without an LLM (note :231).
- Measurements that gate the cards, not open questions: X-M23-1 (scratch postmaster on arm64: initdb + restore of the
  10k fixture, RAM ≤ 1.5 GiB, no socket, no write to the live cluster → M23-4) (note :213-214); X-M23-4 (export at
  10k/50k: bytes/memory zstd:3 vs gzip, wall time `-j1`/`-j2`, p95 impact on live queries, drill time → M23-3/-4
  keys; with R11-K → the D-C revisit and the RTO statement) (note :218-219).

## Alternatives rejected

- A physical full backup (owner: not the whole system) and a schema-wide dump (drags derived data) (note :88).
- App JSONL per tenant (fidelity, silent-miss risk); a BYPASSRLS `role_backup` (§6.2.0 frozen set, `rls_check`); `-Fc`
  (single file, no parallel dump, no per-table checksums) (note :99-100).
- An fp16/fp32 embeddings sidecar (budget for a ≈ $1 saving) (note :107).
- Keeping 2 exports (owner); delete-then-write (a gap with no backup) (note :112).
- A drill DB in the live cluster (production DDL nightly); a compose project via `docker.sock` (no Docker socket,
  ADR-0064 L21) (note :125-126).
- Re-attaching the surviving Qdrant (point registry not exported; A2 unprovable) (note :131).
- Host cron (outside the bundle); systemd timers (rejected); the `--serve` daemon (`role_maintenance` cannot read all
  tenants) (note :139-140).

## References

Module design note M23 v2, §3, §7 D1–D11, §9, §11, §12, §13 and the owner answers of 2026-10-23; module design
notes M10 (C7) and M19 (D6/D8); Baseline §16.3, §37, §44, §66, §78.2, §81; ADR-0062; ADR-0063; ADR-0064; ADR-0084;
ADR-0092.

## Amendments

- **Amended (M23-2):** the `set_null` restore action named in D-A is one restore step, shared by the M23-5 `restore knowledge` and the M23-4 drill, run right after `pg_restore` and before the restore FK audit (D-F): for every `set_null` column of every KNOWLEDGE row of `docs/architecture/backup_catalog.toml` (C-M23-0) it sets the column to NULL, because the referenced table is not exported and every non-NULL value would dangle. G-M23-3b checks the catalog against the `fk:` lines of `db_objects.md`, which `dep-map` generates from `pg_constraint` (static half; the drill's orphan audit stays M23-4).

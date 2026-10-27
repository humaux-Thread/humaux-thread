# ADR-0092 — M19 deletion: one pipeline for five scopes, a narrow physical purge door, an erasure ledger, Export Manifest v1, and compression that never deletes knowledge

- Status: Accepted (2026-10-23). Card M19-1 (docs only, wave D, module M19). Content authority: module design note M19
  (§4 D1–D11, §12), whose owner answers of 2026-10-22 accepted the lead's defaults. This ADR is the repository home of
  those decisions and re-decides none of them. No code, migration or gate lands with it.
- Amends: Baseline §6.2.1 and §37.2 ("physical delete only by the migration owner's partition drop" — a second, narrow
  owner door is added); §37 (one pipeline, the erasure ledger, compression); §81 (the Export Manifest's v1 shape).
  Corrects the earlier plan-v2 forget ruling's "logical deletion only" (module design note M19 §2).
- Relates to: §6.2.1, §6.3, §33.10 rule 9, §37, §37.1, §37.2, §41.2, §48.1, §78.6, §81; ADR-0018 (two-step confirm),
  ADR-0062 (bounded owner purge doors), ADR-0063 (retention and partitions), ADR-0079 D-J (document deletion closure),
  ADR-0081 (retrieval query log). Cross-module: module design notes M17 (v2), M23 (v2), M25, M26.

## Context

- The deletion pipeline exists as a plan with one row per `stream_seq` (migration 0054): `DeletionStep::ORDER` (eight
  steps, tombstone first), `DeletionPlan`, `DeletionState` (seven states, legal transitions) and
  `DeletionGraph::cascade_closure` in `application::forget`; `adapters::forget_repo` owns the sole `TOMBSTONED` writer
  and the step receipts. No caller outside tests.
- `control.deletion_requests` has no request/target split and no confirm binding; `ops.deletion_plan_steps` records
  outcomes. There is no MCP `memory.forget`, no `DestructiveOp` variant for forget or account deletion, no per-person
  delete, no account deletion, no export (audit finding E182) and no compression.
- Retention has a register and an executor (`bins/maintenance/src/retention.rs`, ADR-0063 D-H/D-I; one-shot superuser,
  owner functions), but `control.retention_policies` v2 holds 0 rows and EVENTS / AUDIT_EVENTS are excluded from drops
  by CHECK. The PITR-coverage hold and the partition-error mapping are unmerged.
- §6.2.1 and §37.2 require runtime roles to hold no DELETE and name the migration owner's partition drop as the only
  physical delete. The owner's account-deletion ruling (immediate deletion of live data) therefore had no physical path;
  the earlier plan promised logical deletion only. Restores had no mechanism against resurrecting deleted data.
- A large library must be compressed automatically, with the user emailed **before** compression; stopping payment
  keeps all data (Free), and account deletion deletes live data immediately while backups age out by rotation. Deleting
  production data stays an owner act (module design note M19 §12).

## Decisions

### D-A  One pipeline, five scopes

`control.deletion_requests` becomes one row per request (`scope_kind` = `MEMORY` | `EVIDENCE_CLOSURE` | `SUBJECT` |
`DOCUMENT` | `TENANT`, scope id, state, requested_by, `manifest_hash`, confirm-token id, `logical_deleted_at`,
`completed_at`), and `control.deletion_targets(request_id, kind, id)` holds the frozen closure. The 0054 per-seq rows
become targets; the migration prechecks 0 rows and refuses otherwise. Closure rules: `MEMORY` keeps its source
Evidence (`source_retained = true`, R-43); `EVIDENCE_CLOSURE` starts from explicit roots; `DOCUMENT` is ADR-0079 D-J
closure C; every Memory with **any** input in the closure loses eligibility as a whole (ADR-0079 common dependency).

Rejected: one pipeline per scope; taking the closure from the generic `evidence_edges` `DERIVED_FROM` (ADR-0079 D-J);
`ON DELETE CASCADE`.

### D-B  Two-step confirm, no exceptions

Round 1 returns the impact preview — counts and titles only of objects the caller may read, `restore_supported:false`,
multi-person Evidence listed — plus a token bound to `manifest_hash`; round 2 executes. A closure that changed between
rounds is refused. The legacy `memory_delete` through the M25 facade is the same two rounds, with
`source_retained=true` in the preview. Account deletion additionally needs a fresh login proof (M02 email code, ≤ 10 min,
config). `DestructiveOp` gains `MemoryForget` and `AccountDelete`, with the scope inside the digest. Authority:
ADR-0018, §33.10 rule 9, owner instruction.

Rejected: facade auto-confirm (owner); a single call for an author's own memory; a cooling-off period for accounts
(owner: immediate).

### D-C  Logical at commit, physical by a narrow door

The accept transaction tombstones every outbox seq of the closure (step 1, all event types — ADR-0079 D-J), appends
`FORGOTTEN` to `ops.memory_lifecycle_events` (ids only), and the overlay hides everything from that commit. Late writers
(distill, consolidation, rollup, projection publish) re-check their inputs against the overlay in their own commit
transaction and return `STALE_INPUT` (ADR-0079 shape; no separate fence table).

Amended (M19-3a, lead resume2/3 ruling):
- "FORGOTTEN" is the existing op `TOMBSTONE`, reason `USER_DELETE`, one event per MEMORY target.
- MEMORY targets are hidden by `status='revoked'`; only EVIDENCE targets' seqs are tombstoned. The §41.2 gauge counts deletion targets past SLA without a DONE QDRANT_POINTS step.
- The deletion accept door (owner, EXECUTE role_gateway only) is the second `* -> TOMBSTONED` exit, limited to the frozen EVIDENCE targets of the request it accepts; 0278 adds the owner arm to the stream_log state guard.
- 0278 adds a tenant-bounded, revoke-only `role_migration_owner` arm to `memory_records` WITH CHECK so the accept door can revoke closure Memories the accepter cannot read (WITH CHECK sees only the new row: an owner door can write an invisible row only by leaving it revoked); USING and every other branch are unchanged.
- **Amended (M19-3a, M26-1 reconciliation):** `DestructiveOp::wire()` classifies each confirm-gated op as Mcp | McpPending | Rest. The M26-1 catalog invariant covers Mcp ops only, both directions. `memory.forget` is McpPending until M19-6 adds its registry row; `account.delete` is Rest (C-M19-1).

Physical erasure of live rows runs through one owner `SECURITY DEFINER` function,
`control.purge_deletion_request(request_id)`: owner `role_migration_owner`, EXECUTE to `role_maintenance` only, deleting
exactly the frozen targets (for `TENANT`, every row of the tenant) in FK order. Runtime roles still hold no DELETE
grant. This amends §6.2.1 and §37.2 and supersedes the "logical deletion only" promise.

Rejected: logical-only (fails the owner's ruling); granting DELETE to `role_maintenance` (whole-table blast radius);
per-tenant partitions (partitions are by time, ADR-0063).

### D-D  Per-person delete is `SUBJECT` scope

The closure is the Evidence linked to the subject in `evidence_subjects` (any role) ∪ the Evidence behind memories in
`memory_subjects`; derived memories go whole (D-A); `subject_keys` rows and the subject row are purged. Reminders for the
person die at M22's recheck once the Evidence is gone. A multi-person source (an email thread with A and B) is deleted
whole and named in the preview, including what is lost about B. Identity is a registered subject id only (N09).

Rejected: B20's "block until a sanitized replacement" (it rewrites immutable Evidence, §8.2, or manufactures content);
name matching.

### D-E  Account deletion is `TENANT` scope, immediate

The confirm transaction moves the tenant to `DELETING`, revokes every credential and session (M02 port) in the same
transaction, and tombstones every seq. The daemon (M21) runs this request ahead of all other work (B17 priority:
revocation/forget first): public contributions revoked first through `PublicRevocationPort::revoke_scope` (M20; order
per ADR-0091 D-E (ADR-0091 lands with PR #237) and module_design_M20.md:140, "revoke_scope runs BEFORE M19's purge
(FKs)") → purge door
(PostgreSQL) → Qdrant delete-by-tenant filter (M10 guest) → object prefix, all versions (M17; receipt is a no-op until
the object store exists) → cache epoch bump (M12) → disclosure ledger: per processor `DONE` / `EXTERNAL_PENDING` /
`PARTIAL_CANNOT_ERASE` (open research R1–R2) → `COMPLETED`. The completion census requires every table with `tenant_id`
to hold 0 rows for the tenant except the RETAIN list (the erasure ledger; billing rows if Q3 says keep). No completion
email — the address is part of what is deleted; the UI shows the receipt at confirm. The live-data SLA is measured
(X-M19-1) and disclosed with the backup age-out window.

### D-F  Restores never resurrect deleted data

`control.erasure_ledger(request_id, scope_kind, target-id hash set, completed_at)` is content-free and kept until the
next verified export — the backup age-out window (module_design_M23.md:118-119: "Backup age-out disclosed to M19:
until the next verified export"). Each backup manifest carries a copy (M23 guest); the restore runbook
re-applies the ledger before serving opens, and the restore drill asserts it. The M23 v2 note (2026-10-23) extends this
with `erasure/journal.jsonl` on the export volume: M19's executor writes `{request_id, scope_kind, target sha256 set,
confirmed_at}` as its first daemon step after confirm, and restore re-applies journal lines through the purge door before
serving opens. Card M19-9 gains that writer; the residual confirm → journal window is seconds on the priority lane.

Rejected: relying on age-out alone (a restore inside the window brings deleted users back).

### D-G  Retention register: user knowledge is never age-dropped

EVENTS, evidence, memories and messages are kept forever (owner ruling); operational tables use the ADR-0063 machinery.
M19 proposes values and the owner approves them with `retention approve` (§12 Q1–Q2): `RETRIEVAL_QUERY_LOG` 1 month,
`MODEL_CALL_LEDGER` 13 months, `STAGE_RUNS` 3 months, `MAINTENANCE_RECEIPTS` 13 months, notifications 90 days (M22),
usage journal 7 days (M04 D6); terminal outbox is never dropped by age (card 35 rejection: outbox rows are the existence
authority; M09-3 conditional). No drop runs without the PITR-coverage hold (37c content, card M19-10).

Rejected: per-tenant retention (ADR-0063 D-A: per table, all tenants).

### D-H  Export is §81's Export Manifest v1

An asynchronous job (`ops.jobs` kind `EXPORT`, zero-meter per M04) runs under the user's own RLS context and writes a tar
of JSONL per entity — tenant/workspace metadata, Evidence with payload, Memory revisions with provenance,
subjects/relations, lifecycle events, applications/acceptances, tasks/canvas/handoffs, artifact bytes once M17 exists,
processor/projection metadata as fingerprints — plus `manifest.json` (version, counts, sha256 per file). No vectors
(re-embeddable, vendor-specific). It is stored on the node's export directory (object store once M17 lands), fetched
once through a signed console URL (M26), expires in 7 days (config); "export ready" goes through M22. Space-consuming
work is refused above the 65% disk guard (B23b). Import is M25's replay path consuming the same schema
(`contracts/export/manifest.v1.schema.json`, fingerprinted).

Rejected: synchronous MCP export; base64 in MCP; CSV.

### D-I  Compression: plan → notice → accepted → wait → execute

The trigger is per tenant (B23b start values as config; numbers after R11 and M04's storage allowance): ≥ 100,000
retained memories, or ≥ 1 GB attributed, or forecast exhaustion ≤ 30 days. The plan lists actions, a byte estimate and
its guarantees. M22 sends the notice to the verified address; execution starts only when the provider reports
`ACCEPTED` (`BOUNCED` / `SUBMISSION_UNKNOWN` / suppressed → `BLOCKED`, visible) and the notice period has passed (§12
Q4). Allowed actions never lose current knowledge: (a) a per-tenant payload codec rewrite only if R11-C/D adopts
application zstd (M07-7); (b) retire vector/chunk points of superseded, archived and forgotten memories (history stays
exact/lexical-readable; current memories keep their embeddings — owner "embed all content"); (c) drop stale derived
products (rollups/caches, rebuildable). It never deletes Evidence or current Memories; disk pressure blocks ingestion,
never deletes (B23b).

Rejected: semantic summarisation that replaces sources (§11.6); compression without notice (owner); deleting old
memories.

### D-J  Downgrade keeps data

Stopping payment makes the tenant Free; no retention applies to user data for Free. Above the storage allowance, D-I
runs first, then M04 admission refuses new space-consuming writes — never deletion.

### D-K  Throwaway databases only

Every destructive test runs on a disposable cluster/schema (`HUMAUX_TEST_PG_DSN`; DDL in the serial lane, #146) and
test Qdrant collections. A testkit guard refuses to call the purge door or the retention executor unless the database
name carries the disposable prefix (G-M19-11). Running any of it against production data is an owner red line. Tests
assert exact counts and sets, never a non-empty check.

## Consequences

- Positive: the owner's immediate account deletion has a real physical path without a runtime DELETE grant; one request
  model covers memory, Evidence closure, subject, document and tenant; a restore cannot resurrect a deleted tenant;
  users can leave with an export (§81, no lock-in); compression protects capacity without losing knowledge.
- Cost: the purge door is the widest delete surface in the system, so it is one owner function per request, audited and
  narrowly granted; the tenant completion census must read every `tenant_id` table and will fail closed on a new table
  without a catalog row; export duplicates disk on a single node until M17; compression needs an accepted email and a
  waiting period before any byte is saved; the erasure ledger grows with deletions and is content-free by design.
- Neutral for this card: no table, migration, gate, config key or wire format changes. The gates below belong to later
  cards and are listed so each card starts from a recorded expected red.

## Baseline text changed in this PR

- §6.2.1, the fenced global-constraint block: "物理删行唯一出口" becomes an explicit list of three exits — the
  partition drop, the ADR-0062 sweep doors and the ADR-0092 door named as owner-owned, `role_maintenance` EXECUTE only,
  frozen targets only, with its §6.2.2 row landing with M19-5.
- §37, new closing paragraphs after the `DeletionGraph` states: the five scopes and the frozen closure, the two-step
  confirm bound to `manifest_hash`, logical-at-commit / physical-by-door, the erasure ledger and restore re-apply, the
  retention register, compression with notice first. Normative detail stays in this ADR.
- §37.2, first paragraph: the physical-delete sentence now names the ADR-0092 door beside the partition drop, and says
  the runtime-role DELETE prohibition is unchanged.
- §81, after the Export Manifest contents list: the v1 shape (JSONL per entity, `manifest.json` with counts and per-file
  sha256, no vectors, tenant-scoped, 7-day expiry, M25 replay for import), pointing at this ADR.

## Contracts and table ownership

Produced: **C-M19-1** `application::forget::{preview, confirm, status}` → M26 `memory.forget` (two rounds),
`memory.forget_status`, REST `account.delete`; M25 facade row `memory_delete`. **C-M19-2** erasure ledger plus the
restore re-apply hook (M23). **C-M19-3** Export Manifest v1 schema (M25 import, OSS users). **C-M19-4** purge catalog
`docs/architecture/purge_catalog.toml` (every `tenant_id` table → PURGE | RETAIN(reason)), checked by xtask (M24).
**C-M19-5** compression plan plus the `STORAGE_NOTICE` category (M22).

Consumed: M09 tombstone door and tickets; M10 `retire_points_for_memory` and a new `delete_points_by_tenant`; M12 epoch
bump; M17 object delete (all versions, ADR-0079 D-J); M20 revoke/rebuild; M02 credential revocation, re-auth and email
door; M22 notification record and delivery state; M04 storage allowance and usage summary; M08 read gate (preview);
ADR-0079 T-DOC-6 document closure; M21 daemon scheduling; M23 backup manifest.

Owned today: `control.{retention_policies, partition_registry, deletion_requests}`, `ops.deletion_plan_steps`; the
retention executor and owner functions of ADR-0063. New: `control.deletion_targets`, `control.erasure_ledger`,
`control.export_artifacts(export_id, tenant, sha256, bytes, expires_at, fetched_at)`, `ops.compression_plans(plan_id,
tenant, trigger, actions jsonb, bytes_est, notification_id, state PLANNED | NOTICE_SENT | NOTICE_ACCEPTED | BLOCKED |
EXECUTING | DONE)`. Reads only: `evidence_subjects`, `memory_subjects`, `memory_evidence`, `ops.outbox`,
`projection.stream_log`, `document_excerpts` (ADR-0079), M22 delivery state. Layer L5; may depend on M01, M02, M04, M07,
M08, M09, M10, M12, M17, M20 ports; forbidden: other modules' tables except through their doors, and any cloud crate
(deletion is core).

## Cards and order

M19-1 (this ADR plus Baseline text) → M19-2 (requests v2, targets, closures, preview, throwaway guard) → M19-3a (accept
transaction, confirm tokens, `FORGOTTEN` event) → (M19-3b, M19-4, M19-6) → M19-5 (physical purge door, purge catalog,
completeness gate) → (M19-7, M19-8a → M19-8b, M19-9). M19-10 and M19-11a start in parallel; M19-12a/-12b follow
M04/M22. ADR-0079 T-DOC-6 lands on top of M19-5. Sixteen cards: twelve unconditional, four waiting on other modules or
R11 (M19-11b, M19-12a, M19-12b, M19-8a's M02 re-auth). Deletion cards get two reviewers (card 43 rule) and an
injected-red record per gate.

## Gates

Each gate exists only once its card builds it and CI has recorded inject → red → fix → green (§80.1). This docs card
adds none and has no red record of its own.

| gate | test file | injected fault | expected red |
|---|---|---|---|
| G-M19-1 preview honesty | `crates/adapters/tests/forget_preview.rs` | count before the visibility filter | an unreadable memory changes the impact count |
| G-M19-2 two-step bound to manifest | `crates/adapters/tests/forget_confirm.rs` + gateway MCP test | accept round 2 without a token; ignore `manifest_hash` | executes without a token; executes after the closure grew |
| G-M19-3 tombstone first | `crates/adapters/tests/forget_confirm.rs` | skip step 1 | recall/get/grep/enumerate still show the memory after confirm |
| G-M19-4 late publish | `crates/adapters/tests/forget_race.rs` | remove the commit-time re-check in distill | a memory derived from a forgotten source is published |
| G-M19-5 failure keeps tombstone | `bins/maintenance/tests/forget_steps.rs` | revert the tombstone on step failure | memory visible again after a failed step 5 |
| G-M19-6 purge exactness | `crates/adapters/tests/purge_door.rs` | widen the predicate to the tenant | another document's memory or another tenant's row disappears |
| G-M19-7 catalog completeness | `xtask architecture_check.rs` | add a `tenant_id` table without a catalog row | architecture-check fails, naming the table |
| G-M19-8 per person | `crates/adapters/tests/forget_subject.rs` | keep a memory while another source remains; match by name | thread-derived memory survives; homonym deleted |
| G-M19-9 account deletion | `crates/adapters/tests/forget_tenant.rs` | skip one catalog table; revoke credentials at the end | census > 0; a key works after confirm |
| G-M19-10 no resurrection | `bins/maintenance/tests/restore_erasure.rs` | skip the ledger re-apply | restored database serves the deleted tenant |
| G-M19-11 throwaway guard | `crates/testkit/tests/disposable_guard.rs` | point the DSN at a non-prefixed database | the purge test runs instead of refusing |
| G-M19-12 export round-trip | `crates/adapters/tests/export_manifest.rs` | drop a file; flip a byte | checksum verification passes |
| G-M19-13 export isolation | same | drop the tenant predicate (RLS off) | tenant B rows in A's export |
| G-M19-14 notice first | `crates/adapters/tests/compression.rs` | start on `NOTICE_SENT`; ignore `BOUNCED` | compression runs without an accepted notice |
| G-M19-15 compression keeps knowledge | same | include current memories in (b) | a current memory has no point; Evidence count changes |
| G-M19-16 PITR hold | `bins/maintenance/tests/retention.rs` (extend) | drop the hold predicate | leaf dropped with no verified backup covering it |
| G-M19-17 closed set | domain contract test (§78.2) | add a `DestructiveOp` only in Rust | Rust ≠ DB CHECK / catalog |

## Owner answers in force

- 2026-10-15: stopping payment → Free, data kept permanently; a too-large library is compressed automatically and the
  user is emailed **before** compressing; account deletion deletes live data at once, backups age out by rotation,
  disclosed. 2026-10-22: embed all content (M10-8 won't-do).
- Q1 `RETRIEVAL_QUERY_LOG` retention = 1 month.
- Q2 `MODEL_CALL_LEDGER` 13 months, `STAGE_RUNS` 3 months, `MAINTENANCE_RECEIPTS` 13 months, notifications 90 days.
- Q3 keep anonymous billing rows after account deletion (no name, no email).
- Q4 7-day notice period; compression may retire the vectors of superseded and archived memories, history staying
  exact/lexical-readable.

## Owner gates (not decided here)

Any deletion, purge or retention drop against production data, including the first production enable of `memory.forget`
and `account.delete`; `retention execute` on production; the first live send of a compression notice or an export-ready
email; live provider keys in tests.

- **Owner ruling (2026-10-24, AskUserQuestion; recorded in this PR's body):** account deletion covers the new system
  only. The 1,041 legacy originals in the old MinIO are deleted when the old system is retired as a whole, an owner step
  in the M25 retirement runbook; the new system never writes to or deletes from the old store. The deletion receipt
  discloses this, and the TENANT completion census excludes the old MinIO and carries the disclosure line instead
  (module_design_M17.md:192-198, C-M17-6: deleting there is owner-only).

## Open research

1. Alibaba Model Studio text-embedding-v4 (DashScope): are request inputs retained or logged, for how long, and is there
   a customer deletion procedure? (sets the disclosure-ledger state at step 6 of a deletion)
2. Resend: are sent message bodies stored, for how long, and can they be deleted by API? (notification copies of a
   deleted account)
3. With Creem as merchant of record, which payment records must we (not Creem) keep after an account is deleted, and for
   how long, in the owner's jurisdiction? (feeds Q3)

## UNKNOWNs and fallbacks

- Account-deletion live-data SLA → until X-M19-1, disclose "within 24 hours" and alert on
  `tombstoned_unpurged_over_sla`.
- Backup age-out window → closed: until the next verified export (≈ 24 h, longer while exports fail), and the erasure
  ledger is kept until then (module_design_M23.md:118-119: "Backup age-out disclosed to M19: until the next verified
  export"). M19's earlier "cadence × retained generations + off-site expiry" wording is superseded.
- External processors' deletion → `EXTERNAL_PENDING`, then `PARTIAL_CANNOT_ERASE` with the processor named (§37: never
  claim deletion on a 200).
- Compression trigger numbers → B23b start values as config, disabled until R11 and M04's storage-allowance numbers
  exist.
- Org tenants (several owners) → not built (no seats); §6.3's last-owner rule stays M02's.

## Rejected alternatives

Consolidated from the decisions above: one pipeline per scope; a closure from generic `evidence_edges`; `ON DELETE
CASCADE`; facade auto-confirm; a single-call delete of the author's own memory; a cooling-off period for accounts;
logical-only deletion; a table-wide DELETE grant to `role_maintenance`; per-tenant partitions; B20's sanitized
replacement of immutable Evidence; name matching for a person; relying on backup age-out without an erasure ledger;
per-tenant retention; synchronous MCP export, base64 in MCP, CSV; semantic summarisation that replaces sources;
compression without notice; deleting old memories.

## References

- Baseline §6.2.1, §6.3, §33.10 rule 9, §37, §37.1, §37.2, §41.2, §48.1, §78.6, §81.
- ADR-0018 (confirm token, two-step confirm), ADR-0062 (bounded owner purge doors, receipts), ADR-0063 (per-table
  retention and partition drops), ADR-0079 D-J (document deletion closure and commit-time overlay), ADR-0081
  (`ops.retrieval_query_log`).
- Module design note M19 §4 (D1–D11), §8 (gates), §10 (UNKNOWNs), §12 (owner questions and red lines); the M23 v2
  follow-up. Module design notes M17 (v2) and M23 (v2) as cited by their module names.

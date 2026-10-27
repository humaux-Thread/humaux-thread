# ADR-0123 — M21 schedule register: the closed maintenance task set, §65 coverage, report-only repair and the deletion priority lane

- Status: Accepted (2026-10-26). Card M21-1 (docs plus the G-M21-1 xtask gate, wave F, module M21). Content
  authority: module design note M21 §8 D1–D8 (:115-143) and the frozen Baseline §65 table. This ADR records those
  decisions and re-decides none of them. No maintenance task lands with this card (note :168); its files are the ADR,
  the register and the xtask gate.
- Amends: ADR-0062 D-C (the closed `MaintenanceTask` list): a §65 daily job is a resident task whose
  `EVERY_SECONDS` cadence is compared on the DB clock, so no scheduler library enters the daemon (note :115-116,
  :119).
- Relates to: Baseline §15.2, §15.6, §23.1, §41.2, §48.1, §57.1, §59.1 G59-4, §65, §66, §78.6, §80.1; ADR-0018
  (two-step confirm), ADR-0050 (CI-missing database is a fail), ADR-0062 D-C, ADR-0063 D-H/D-K, ADR-0064 D-K,
  ADR-0072 D-C; C-M21-3 (note :50).

## Context

- Baseline §65 freezes the repair-job list — a repair job exists only if the table lists it — and defines the
  "Maintenance period" as once daily, with rows that need another frequency marked in the table
  (`docs/architecture/Baseline_2.9.md:12637`; note :62). The frozen table has twelve rows, from `PG <-> Qdrant diff`
  to `config drift`.
- C-M21-3 creates the register `docs/architecture/schedule_register.toml`, checked by xtask (note :50), and D2
  makes the §65 table the authority for "what exists": every §65 row maps to a task label or
  `not_applicable(owner, reason)`, and xtask fails on an unmapped row (note :120-121).
- The resident daemon's task set is a closed enum: `bins/maintenance/src/serve.rs:61` imports
  `maintenance_repo::MaintenanceTask` as `Task` and runs twelve variants in cycle order — `Lost`,
  `QuotaReservations`, `QuotaRenewal`, `ProviderBudgets`, `ConfirmTokens`, `Snapshots`, `RateBuckets`, `Jobs`,
  `Reissue`, `Redrive`, `Partitions`, `DrEvidence` (note :24-29).
- The §65 gaps on the baseline: `ops.i4_authority_consistency_scan()` has no caller (D137/D173, W0 P0); there is no
  ISSUED→EXPIRED sweep of `private.ingest_tickets`; no PG↔Qdrant diff, orphan relation scan, projection watermark
  audit, waiting_key visibility or config drift job; `ops.column_vitality` has no nightly writer; `distill_candidates`
  expiry has an UPDATE grant but no caller; partition creation is a monthly manual superuser step (note :36-42).
- D7 records a conflict: §66 says retention runs automatically, while the owner red line forbids any deletion
  against production data (note :139-141).
- M23 v2 moves the config-drift schedule row to M23-6 and retires the host crontab (note :209-210).

## Decisions

### D1  One daemon, closed list, no scheduler library

Keep ADR-0062's shape: enum + door + two keys; cadence is `EVERY_SECONDS` compared on the DB clock; daily §65 jobs
are tasks with `EVERY = 86400` (note :115-117). ADR-M21-a (this ADR) amends ADR-0062 D-C (note :119).

Rejected: a cron expression engine / `tokio-cron` (new dep, civil-time bugs, B20 red 5); `ops.jobs` rows per
maintenance run (one job table is for work items, M09 D6 — a periodic sweep is not a work item); pg_cron (extension
in the OSS bundle, superuser) (note :117-119).

### D2  The §65 table is the authority for "what exists"

Every §65 row maps in `schedule_register.toml` to a task label or `not_applicable(owner, reason)`; xtask fails on an
unmapped row (G-M21-1); frequencies default to daily per §65 (note :120-121).

### D3  Report-only vs safe-automatic per §65

I4, orphan relations, watermark, config drift and cross-tenant anomalies write `ops.repair_findings` + gauge +
alert, never UPDATE (§65 "只报数，不 UPDATE"). Safe automatic: a missing projection goes through the existing
`Reissue` door (already the compensation path), and expired tickets/candidates/tokens are expired automatically
(note :122-124).

Rejected: an operator `repair i4 --fix` command (§65 forbids erasing the root cause; correction goes through M07
verbs with ADR-0018 confirm) (note :124-126).

### D4  ISSUED→EXPIRED is a state transition, not a purge

Door `private.expire_ingest_tickets(interval, int)` is owned by the ticket state machine (M09 reviews), with a TTL
key per §15.6; `EXPIRED` stays in the §23.1 denominator (M13 counts it as `expected` not met, never silently
dropped) (note :127-129).

Rejected: DELETE of stale tickets (breaks census truth) (note :129).

### D5  Partition create-ahead in the daemon (create only)

A new owner definer wraps `control.partition_create_month` with EXECUTE to `role_maintenance`, creating leaves up to
`PARTITION_HORIZON_MONTHS` (3) ahead; drops stay the superuser one-shot with owner approval (note :130-132).
Authority: §48.1 + runbook §5.3 failure mode ("every tenant at the same instant") + the owner OSS standard (a
self-hoster will not run a monthly superuser step) (note :132-133). A later ADR (placeholder ADR-M21-b in the note)
amends ADR-0063 D-H (create is additive DDL; the daemon still refuses the migrator DSN) (note :134-135).

Rejected: keep manual (OSS footgun; alerts only page 1–2 months ahead); DEFAULT partition (runbook §5.3 forbids)
(note :133-134).

### D6  Priority lane

Each cycle first drains deletion requests (M19 D5, B17 "revocation/forget first") up to a time slice, then the rest
in D-C order (note :136-137). The daemon gains an M10-owned Qdrant face (`delete by filter` door only) for M19
step 3 (note :137-138).

Rejected: a separate forget process (4 vCPU, one more credential set) (note :138).

### D7  Retention execution stays an operator one-shot

§66 says retention runs automatically; the owner red line (any deletion against production data, M19 §12) outranks
spec. The daemon proposes, the owner executes. Recorded conflict, not an owner question (already ruled)
(note :139-141).

### D8  Keep one maintenance binary

Split only by process mode, not crate (note :142).

Rejected: per-module binaries (seven images, seven credential sets on a 4-vCPU node) (note :142-143).

## Consequences

- Positive: every §65 repair job now has a register entry naming either its resident task or the owning card/module
  recorded by the note's job table, and an unmapped §65 row turns G-M21-1 red (note :120-121).
- Cost: adding a job means an owner door (owner module) + a variant + keys + a register row (G-M21-1) (note
  :202-203); cadence values stay in `values/maintenance.env` (note :202-203).
- Neutral for this card: no maintenance task lands (note :168); the gate's own injected-red record is produced on the
  card, not in this ADR.

## Gates

G-M21-1 (§65 coverage) is implemented by this card and exists only once CI records inject → red → fix → green
(§80.1). The gate is tri-state (§57.1); the note's gate section states that DB tests need `HUMAUX_TEST_PG_DSN` and
that a missing DSN in CI is a fail per ADR-0050 (note :151).

| gate | test file | inject | expected red |
|---|---|---|---|
| G-M21-1 §65 coverage | `xtask/src/schedule_register.rs` (new) | delete one register row / map to unknown label | xtask exits 1 naming the §65 job |
| G-M21-2 I4 scan (G59-4 inject b) | `bins/maintenance/tests/i4_scan.rs` | drop the CHECK, insert 1 violating row; then hard-code `SELECT 0` | gauge reads 1 then 0 on compliant fixture; hard-coded 0 → red |
| G-M21-3 report-only | same + `architecture_check.rs` | task issues UPDATE on memory_records | xtask sentinel: no UPDATE/DELETE text in maintenance_repo task SQL |
| G-M21-4 EXPIRED sweep | `crates/adapters/tests/ingest_ticket_expiry.rs` | ignore TTL / expire a REDEEMED row | REDEEMED or fresh ISSUED becomes EXPIRED |
| G-M21-5 create-ahead | `bins/maintenance/tests/partitions.rs` (extend) | disable task; grant DROP via the definer | horizon < 3 after a cycle; definer drops a leaf |
| G-M21-6 diff repair | `bins/maintenance/tests/projection_diff.rs` | delete one Qdrant point; add one foreign-tenant point | missing point not reissued; foreign point auto-deleted (must alert only) |
| G-M21-7 priority | `bins/maintenance/tests/serve.rs` (extend) | move deletion lane after Jobs | deletion request completes after a purge in the same cycle |
| G-M21-8 column_vitality | `bins/maintenance/tests/column_vitality.rs` | register-free column with live=0,total>0 | gate stays pass |
| G-M21-9 candidate expiry | `crates/adapters/tests/candidate_expiry.rs` | expire before `expires_at` | unexpired candidate EXPIRED |

Kept green: card-35 suite (310 tests), `MaintenanceCountersAbsent` promtool cases, G59-4 CHECK half (M07)
(note :163).

Experiments gating cards:

- X-M21-1 cycle cost at 300 tenants × 25 tasks on the 4-vCPU box (CPU, PG active backends, cycle wall time) →
  `TENANTS_PER_RUN` / daily task cadences; gates M21-5 rollout (diff scroll is the heaviest) (note :180-181).
- R11-G (M09) gates the outbox purge task. Nothing else is experiment-gated (note :182).

(note :152-163, :179-182)

## Owner gates (not decided here)

- The first `--serve` start against a production database holding residue (runbook §5.2: backup + impact +
  `sweep once` first) (note :194-195).
- Any purge or retention drop against production data (note :195; D7 keeps execution an owner one-shot).
- Any manual repair of I4 violations on production rows (note :196; D3 makes the I4 scan report-only).

Owner questions: none (note :193).

## Open research

1. U1 — Config drift needs a per-process config fingerprint source; none found on main. Fallback: `deploy-check
   --running` daily in `dr serve` (M23-5) reports drift by exit code + gauge; daemon task added when processes
   publish digests (note :185-186).
2. U2 — Who flips M18 waits to TIMED_OUT: M18 D6 says "timeout escalates (M22 notification)" without naming the
   scanner. Fallback: M21-9 task calling an M18 door; M22 polls the resulting rows (its rule: producers never call
   M22) (note :187-188).
3. U3 — Whether `ops.i4_authority_consistency_scan()` is SECURITY DEFINER and returns ids (0004 returns bigint
   only). Fallback: M21-2 replaces it by a definer returning count + ≤100 ids, keeping the old name's count
   semantics (note :189-190).

## References

- `docs/architecture/Baseline_2.9.md` §65 "自动化 Repair Jobs" (the frozen table and the §59.1 I4 landing point),
  §66 "全系统自动运行原则"; §15.2, §15.6, §23.1, §48.1, §57.1, §59.1 G59-4, §78.6, §80.1.
- Module design note M21: §5 job table (:64-99), §8 D1–D8 (:115-143), §10 gates (:151-163), §13 UNKNOWNs
  (:184-190), §15 where-to-change-what (:202-203).
- ADR-0062 D-C (the closed task set this ADR amends); ADR-0063 D-H/D-K; ADR-0064 D-K; ADR-0072 D-C; ADR-0018;
  ADR-0050.
- `docs/architecture/schedule_register.toml` (C-M21-3) and `xtask/src/schedule_register.rs` (G-M21-1).

## M21-2 resolution and red records (appended 2026-10-27)

Card M21-2 lands D3's I4 scan as the AUTHORITY_I4 task of `humaux-maintenance --serve` (report-only; `EVERY` =
86400 from `deploy/env/values/maintenance.env`), migration 0287, the `authority_i4_violations` gauge and the §42
`AuthorityI4Violation` alert. Nothing above is re-decided.

- U3 resolved: `ops.i4_authority_scan()` (owner SECURITY DEFINER, STABLE, `search_path = pg_catalog, pg_temp`, EXECUTE
  `role_maintenance` only, count plus at most 100 ids ordered by `memory_id`) replaces the PUBLIC-executable
  `ops.i4_authority_consistency_scan()` of 0004, which no code called; the old name is dropped in 0287. The two
  mentions of the old name above are this ADR's historical text and stay as written. The run appends one row to the
  append-only `ops.repair_findings` (`role_maintenance` SELECT + INSERT, no UPDATE or DELETE for anyone; `job` is the
  exact §65 name, `tenant_id` NULL for a cluster-level job).
- A failed run resets the gauge to absent, never to 0 (§41.2): a 0 would silence `authority_i4_violations > 0` while the
  scan is broken; the failure shows on `maintenance_task_runs_total{task="authority_i4",outcome="failed"}`.

Red records (§80.1; each a throwaway branch cut from `c0aeb2cb` with one mutation, dispatched through
`targeted.yml`, then deleted; the green is the card's PR CI). Line numbers are those of `c0aeb2cb`.

| gate | injection | run | fails at |
|---|---|---|---|
| G-M21-2 | `red/m21-2-r1` (`dc526418`): the definer's `SELECT (SELECT count(*) FROM v),` becomes `SELECT 0::bigint,` (a hard-coded 0) | 40503024799 (`-p humaux-maintenance --test i4_scan`, as root) | `bins/maintenance/tests/i4_scan.rs:192` in `a_violating_row_is_counted_sampled_and_left_unchanged`, `left: 0.0, right: 1.0`; the compliant-database and grant tests stay green |
| G-M21-3 | `red/m21-2-r2` (`2f61e420`): `scan_authority_i4` also runs `UPDATE private.memory_records SET superseded_by = NULL WHERE status = 'active' AND superseded_by IS NOT NULL` | 40503487507 (`-p xtask g_m21_3_real_repo_passes`) | `xtask/src/architecture_check.rs:18859`, `Fail(["... `fn scan_authority_i4(` holds 1 write(s) against private.*; the scan is report-only (expected 0)"])` |
| alert | `red/m21-2-r3` (`fadeb972`): `authority_i4_violations > 0` becomes `> 1` | 40503999626 (`prom_rules=true`) | promtool case `alertname: AuthorityI4Violation, time: 8m` (`deploy/prometheus/tests/alerts.test.yml:440`), expected the critical alert, got none |

The same alert token is the `mutations.sh` row `i4_gt0`; the unmutated tree records it red (run 40501327275:
`mutation=i4_gt0 red`, `red=50/50`).

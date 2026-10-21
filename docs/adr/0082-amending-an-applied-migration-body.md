# ADR-0082 — Amending an applied migration body: reviewed `accepted_prior_checksums`, never a rewritten ledger row

- Status: Accepted (card T-MIG-1, 2026-10-21, issue #137 and its lead decision).
- Spec: Baseline §46, §46.1, §78.6, §80.1; ADR-0050 D-D; ADR-0059 D-C (SEC-2); ADR-0060 (0206 note); ADR-0063.

## Context

- `migrate` (`apply_locked`) records an FNV-1a checksum of the whole file in `ops.schema_migrations` and refuses any
  applied file whose checksum changed. ADR-0060: no command rewrites a recorded checksum, and a hand edit of the table
  is the SEC-2 forgery `deploy-check` exists to catch.
- #137: 0228's F3 precheck builds `array_agg(… ORDER BY 1)`, ordered by the constant 1, and compares it with a
  fixed-order literal, so a catalog scan returning the message FK first refused a correct database (CI run
  39447034544). 0229 has the idiom on a one-element array and cannot misfire.
- 0228 is applied on dev and runs again on every fresh install, so no later migration can repair it: the body has to
  change, and the repository had no legal way to say so.

## Decisions

### D-A  A manifest may list the checksums its file had before an amendment
`accepted_prior_checksums = [{ checksum = "<fnv1a hex>", reason = "<why the body changed>" }]`, optional, parsed by
`migration_manifest::parse_manifest` for every reader. The checksum is 16 lowercase hex digits, the reason is not
blank, an entry has no other key; anything else is an error naming the manifest file.

### D-B  One rule decides "recorded vs file"
`migration_manifest::compare_recorded(current, recorded, accepted)` answers `Same`, `Amended { reason }` or `Drift`.
`migrate::apply_locked` is the only place that compares a file with the ledger; `deploy-check` reads no checksum,
`xtask` migrate paths and `dep-map` read ids, and the restore drill compares ledger rows with ledger rows. A new
comparison site calls the function; it does not copy it.

### D-C  The ledger row is never written
On `Amended`, `migrate` logs one line naming the migration, the recorded checksum and the current one, counts the
migration as skipped and goes on. No code path updates `ops.schema_migrations`. A forged row still fails: the list is
in git under review, and a recorded value outside it is drift. Databases keep the old checksum, so entries stay.

### D-D  What an amendment may change
Only statements without schema effect: prechecks, postchecks (manifest or in-body guards that only raise) and
comments. A DDL change, a function body, a default or a grant is not an amendment; it takes a new migration (§46).
Review enforces this. The listed checksum is the file as merged before the change, computed with the runner's FNV-1a.
`ponytail: no automated schema-equivalence proof until a migration-rehearsal digest exists` (`compare_recorded`).

### D-E  Gates (each with an injected-fault record in the PR)
- Throwaway database: a listed checksum is accepted and the row (`xmin` included) is unchanged after each replay; an
  empty list, a list naming another checksum and a forged row are refused with the existing message (`migrate::tests`).
- 0228's precheck passes with the aggregate's input forced both ways and with the FKs created in each order
  (`tests/partitions.rs`).
- `xtask migration-rehearsal` fails any `*_agg(… ORDER BY <integer literal>)` in `migrations/*.sql`, naming the line.

## Consequences

- 0228 and 0229 order by the expression and list their pre-#137 checksums (`d09c6b3d81a0c99c`, `e9e52faff81ba4d6`,
  the files at 5df129c). Databases that applied either accept; fresh ones record the new checksum.
- The scan found a third site, `0224_partition_machinery.sql` (`string_agg(… ORDER BY 1)` in the function
  `control.partition_catalog_fingerprint`). A function body is schema effect, so D-D forbids amending it; the fix is a
  forward migration (`CREATE OR REPLACE FUNCTION`, issue #141). 0224's text never changes, so the check exempts it by
  file and count for as long as 0224 exists; the exemption is red only if that count changes. Not scanned: dynamic
  SQL inside string literals, and `ORDER BY (1)` / `1 COLLATE` / `1 USING` / window `OVER (ORDER BY 1)` forms.

## Rejected

- Re-baselining dev's recorded checksum by hand: it is the SEC-2 forgery (ADR-0059 D-C, ADR-0060).
- Rebuilding the shared dev cluster: destructive, needs an owner go-ahead.

# ADR-0075 — The stream ticket door: issuer ownership moves from `remember` to `stream_repo`

- Status: Accepted (2026-10-15). Card M09-1 (module design M09 §2, §6 D1, D5, §8 G-M09-1 / G-M09-2; this is the
  design note's ADR-M09-a).
- Relates to: Baseline §14, §15.1, §60, §60.1; ADR-0031 (the six-column `StreamKey` is the stream identity);
  ADR-0057 D-M (a ticket goes to the memory's home stream); ADR-0067 (the note lane issues its ticket through the same
  door); card M07-1 (G-M07-1, the INSERT-door scan this gate reuses); card M06-5 (moves `remember`'s sequence
  allocation).

## Context

Every private-evidence ticket is three writes in one transaction: a `commit_seq` from `ops.commit_seq_seq`, a
`projection.stream_log` row (after the `stream_checkpoints` bootstrap and `issued_highwater` bump), and the
`ops.outbox` row that binds the ticket to its Evidence. That code lived in `remember.rs` (module M06) and was imported
by `memory_governance_repo`, `distill_repo`, `consolidate_repo` and `affect_repo`, while the contribution repos took the
sequence value from the same file. The A1 identity (`expected == done + open_gaps + pending`, §15.4) is a property of
the ledger, not of the Evidence write path, so the invariant's owner (M09) did not own the code that makes it true, and
nothing stopped a sixth writer from skipping the outbox row.

## Decision

- **D-A The door moves, behaviour does not.** `stream_repo::issue_ticket_in_txn(txn, &StreamKey, evidence_id,
  event_type, commit_seq)` runs, on the caller's transaction and in §60's statement order: sequence value, checkpoint
  bootstrap `INSERT ... ON CONFLICT DO NOTHING`, `issued_highwater + 1`, `stream_log` ISSUED row, `ops.outbox` row. It
  returns `TicketIssued { commit_seq, stream_seq }`, never commits, and fails with `sqlx::Error` (each caller's
  `db_error` maps it exactly as the former `RememberError::Db` was). The outbox `tenant_id` is the key's; every
  governance entry point already refuses a request stream whose tenant is not the authenticated one. The statements
  and their order are the former `issue_stream_log_row` + `insert_outbox`, merged. `stream_repo::next_commit_seq` is the
  one `nextval('ops.commit_seq_seq')`; the public-release outbox writers (M20, `PUBLIC_*` rows without a stream
  ticket) call it too. The ticket callers (`remember`, `memory_governance_repo`, `distill_repo`, `consolidate_repo`,
  `affect_repo`) changed their call and error mapping; no transaction was reordered.
- **D-B The pre-allocated sequence contract.** `commit_seq: Option<i64>`. `None` (every caller but one) takes the
  sequence value inside the door, directly before the checkpoint bump, as before. `Some(n)` is **`remember` only**: it
  takes its sequence value as the first write of its transaction (§60 step 1) and issues the ticket last, and the door
  stamps `n` verbatim rather than allocating a second value. The parameter lives until card M06-5 moves `remember`'s
  allocation next to the ticket; M06-5 deletes it (it carries a `ponytail:` marker). The guard of the `Some` branch is
  `crates/adapters/tests/outbox_batch_remember.rs::m09_1_ticket_door_issues_one_outbox_row_equal_to_the_stream_log_row_and_the_returned_ticket`:
  after one call per path there is exactly one outbox row for the returned `commit_seq`, equal to the one `stream_log`
  row and to the returned ticket. It reaches the `pub(crate)` door through `stream_repo::issue_ticket_in_txn_for_test`,
  compiled only under the `test-support` feature that this crate's own dev-dependency turns on.
- **D-C Gate G-M09-1 (`xtask architecture-check`).** In non-test code of the whole workspace, `INSERT INTO
  projection.stream_log` appears exactly once and `nextval('ops.commit_seq_seq'` exactly once (the needle stops before
  the `)` so `::regclass` and padded spellings count), both in `crates/adapters/src/stream_repo.rs`. It is the same scan
  as G-M07-1 (`sole_door_statements`: test trees by path structure, text cut at the trailing `#[cfg(test)] mod`,
  comments dropped, `\`-continuations joined, case and whitespace, and spaces around parentheses normalised); 0 in the
  home file is red, a copy elsewhere is red, a missing home file is red when the statement exists anywhere.
  `xtask/src/e2e_onboard.rs` seeds one ISSUED `stream_log` row with a `nextval` as the DB owner to stage a fault
  scenario; it is **bounded, not exempt**: at most 1 `stream_log` INSERT and 1 `nextval` there, a second copy is red.
  Scope: Rust-side doors only. Migrations also issue tickets in SQL (definer functions and backfills: 0123, 0127, 0155,
  0198, 0200, 0220, 0223, 0233); those are reviewed with their migrations and are not counted here.
- **D-D Ownership note (module design M09 D5).** `projection.stream_point_ledger` reads the point registry and card
  policies, so it is M10's. M09 exports ticket arithmetic only. This is an ownership statement for headers and the
  dependency map; no SQL changed in this card.

## Rejected

- Leaving the trio in `remember.rs` and testing it from five modules: the invariant's owner would not own its code.
- Allocating the sequence value inside the door for `remember` too: it moves the `nextval` from the first write to the
  last of `remember`'s transaction, which is card M06-5's reordering, not this card's.
- A second door function for the pre-allocated case: two functions each holding half of the INSERT/`nextval` pair is
  what G-M09-1 counts against.

## Consequences and ceilings

- A new ticket writer in Rust edits `stream_repo.rs` or turns G-M09-1 red; skipping the outbox row is not expressible
  by a caller, and a door that skips it turns the projection and receipt tests red (G-M09-2: the existing DB suite).
- The scan matches spelled-out statement text; a statement assembled with `format!` or from separate pieces evades it
  (`ponytail:` in the gate). The bounded e2e fixture is bounded per statement, not per call site.
- `Option<i64>` is a deliberate wart with an owner and a removal card (M06-5).

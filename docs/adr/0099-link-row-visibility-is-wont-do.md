# ADR-0099 — 35b-iii link-row visibility is won't-do

- Status: Accepted (2026-10-23). Card M08-6 closes plan row 35b-iii (`module_map_v3.md:10`, `:898`) as won't-do; the
  M08 design note records the same ruling as ADR-M08-a (`module_design_M08.md:68`, `:109`). Docs only: no code, DDL,
  grant or gate changes.
- Relates to: Baseline §6.1.1, §8.6, §6.2.0, §34.0.1, §48.2; M07 D8 (no share verb), M08 D1/D2; owner decision D2
  (`module_design_M08.md:66`, `module_design_waveB_overview.md:55`; the item it answered at `arch_audit_SUMMARY.md:64`).

## Context

- 35b is the plan's "Set-based subject visibility" card (`module_map_v3.md:864`); 35b-i and 35b-ii merged and 35b-iii
  stayed open (`module_map_v3.md:10`). 35b-iii is the link-row option: "allow tenant-wide link-row visibility (ids
  only) for 2× bulk / 1.7× point" (`arch_audit_SUMMARY.md:64`), i.e. link existence/count for memories the caller
  cannot see (`research_gpt_batch15_evidence_visibility.md:6`).
- What exists today: `private.memory_evidence` is tenant-scoped through its parent Memory row
  (`migrations/0012_rls.sql:219-235`), so a link is readable exactly when its Memory is. Visibility itself is frozen at
  write into `USER_PRIVATE | WORKSPACE_SHARED | TENANT_SHARED` and decided by `can_read` (Baseline §6.1.1,
  `Baseline_2.9.md:1009-1085`); the same section refuses an RLS policy that checks `tenant_id` alone
  (`Baseline_2.9.md:1085`).
- Owner decision D2 ruled out widening: "No widening, no 35b-iii" (`module_design_M08.md:66`), "35b-iii closed as
  won't-do (already owner D2)" (`module_design_waveB_overview.md:55`) — no cross-user sharing, no share verb (M07
  D8, `module_design_M07.md:123`), visibility set at write and only narrowing afterwards (Baseline §34.0.1, `:9338`).
  The audit states the D2 item as "allow tenant-wide link-row visibility (ids only) for 2× bulk / 1.7× point"
  (`arch_audit_SUMMARY.md:64`); that is the question the ruling answered.
- The option's measured price was 2× bulk and 1.7× point cost (`arch_audit_SUMMARY.md:42`; M08 note D2, `:67-68`) for a
  capability the owner had already ruled out. The other researched shape — a SECURITY DEFINER bulk authorizer owned by
  a new non-login `role_read_authorizer` — needed a role that does not exist, which §6.2.0 forbids: its two tables are
  the exhaustive role set and one role more or fewer is CI red (`Baseline_2.9.md:1188`). That conflict is why the row
  was parked as a decision item instead of implemented (`research_gpt_batch15_evidence_visibility.md:11`).

## Decision

D1. **35b-iii is won't-do.** No tenant-wide policy is added to `private.memory_evidence`; no runtime reader gets link
existence, link count or Evidence ids for a Memory it cannot read. The M08 note records the rejection of the policy
itself: "Rejected: 35b-iii policy (measured 2× bulk / 1.7× point cost for a capability the owner ruled out)"
(`module_design_M08.md:67-68`). The per-option reasons are the research note's: (a) a tenant-only link policy, "real
leak (link existence/count for memories the caller can't see)" → reject — this ADR reads that leak as also contrary
to §6.1.1's refusal of a `tenant_id`-only policy (`Baseline_2.9.md:1085`); (b) an uncorrelated `IN` policy, "full
visible-set scan per point read" → not universal; (c) a definer with copied visibility, "second authorization
impl" → reject; (d) a per-memory visibility certificate, "heavy write-side invariant" → **deferred**, not rejected;
(e) the `role_read_authorizer` definer, which conflicts with the frozen §6.2.0 role set
(`research_gpt_batch15_evidence_visibility.md:6`, `:11`). The 2× bulk / 1.7× point measurement above is the note's,
not re-measured here.

D2. **The need 35b-iii was meant to serve is already the read gate's job.** Link completeness is the load-bearing
invariant of the §8.6 provenance relation (every Memory carries at least one link, `Baseline_2.9.md:2030-2060`), and
the all-backing-evidence closure is a conjunct of the one read gate (`context_repo::readable_memory_ids` today; M08 D1
moves it to one home). It is not expressible as a per-row policy without recursion, and the link policy must not
depend on the Memory policy (M08 D1, `:64-65`). The closure is gated by G-M08-1, table-driven over get, enumerate,
grep, recall, context and continuity (`module_design_M08.md:92`).

D3. **No mechanism changes here.** No policy, table, column, role or grant is added, removed or re-pinned, so §48.2's
enumeration and §6.2.0's role set stay as they are. The row is retired, not deferred.

## Consequences

- Positive: visibility can only narrow (§34.0.1); an invisible Memory has no link-existence oracle
  (`Baseline_2.9.md:1085`); the frozen role set (§6.2.0) and the §48.2 grant/RLS enumeration are untouched; the gate
  keeps one home (M08 D1).
- Cost: there is no tenant-wide link enumeration. A future tenant-wide consumer takes the gate's candidate list
  instead (`module_design_M08.md:21`), and `private.memory_evidence` stays readable only through its parent.
- Not done here: the wire, the gate and the relocations belong to M08-1..M08-5; this ADR adds no code and no test.

## Gates

- n/a (doc): the M08-6 row's gate column is `n/a (doc)` (`module_design_M08.md:109`), and a declined mechanism has no
  unit to red-test. The table it would have changed keeps ENABLE + FORCE RLS, its tenant policy and its grant row,
  which the existing §48.2 enumeration (`bins/maintenance/src/rls_check.rs`, G80-26; M08 note `:97`) already checks.

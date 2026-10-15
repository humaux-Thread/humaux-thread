# ADR-0073 — Open-core edition boundary and licence timing

- Status: Accepted (2026-10-15). Owner rulings of 2026-10-15; card M24-1 (this file), M01-1 (boundary gate), M24-14
  (LICENSE family at the split).
- Supersedes: Baseline §81 "Apache-2.0 full OSS, no closed core" (the business model and edition list), and the
  Day-1 / §81.1 expectation that this repository carries a LICENSE file during development.

## Context
§81 chose full open source with only hosted services sold. The owner decided on 2026-10-15 that the product is
open-core: some capabilities are cloud-only. All development nevertheless happens in this public repository until the
system is complete; then the repository turns private and a separate open-source repository is created.

## Decision
- **D-A Edition split.** Open-source core: memory write / recall / share within one user's agents / forget / recover,
  single user × many agents over MCP, task canvas and coordination, deterministic curation (exact dedupe,
  supersession, stale marking, project/task state), RLS, audit, backup/restore, BYOK provider plane, local
  deployment. Cloud-only: the public knowledge pool; LLM-driven curation and reports (session brief, digest email,
  gap/health report, rule distillation, cross-project lessons, repeated-question detection); the knowledge graph and
  cross-project problem→solution reuse. No team seats.
- **D-B Dependency direction.** Cloud crates may depend on core crates, never the reverse; every crate declares its
  edition and a gate (card M01-1) fails on any core → cloud dependency.
- **D-C No licence until the split.** While cloud-to-be code lives here the workspace declares no licence
  (`workspace.package` has no `license`; every member is `publish = false`) and there is no LICENSE file. The
  open-source repository created at the split carries the Apache-2.0 LICENSE, NOTICE and third-party notices
  (M24-14). Earlier commits that declared `license = "Apache-2.0"` stay as they are — the removal is not
  retroactive.
- **D-D Repository split at the end.** The open-source repository is a fresh-history export of the core crates by
  allowlist (GPT batch 24); the cloud crates stay in the private repository.

## Consequences
- cargo-deny treats members as private (`[licenses] private = { ignore = true }`); third-party crates are still
  checked.
- Anyone re-adding a licence key or a LICENSE file before the split contradicts this ADR; change it here first.

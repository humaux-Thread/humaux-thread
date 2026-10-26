# ADR-0119 — Parse sandbox without network namespaces, and the processing limits

- Status: Accepted (2026-10-26). Card M17-1 (docs only, wave D, module M17). ADR-M17-e (this ADR). Records module design
  note M17 v2 D10 (note :144) and the untagged M17 decision D11 (:151) that serves the same topic. Content authority: the
  lead rulings at note :9-11; the note's v1 `CLONE_NEWNET` decision is superseded (note :20). This ADR records them and
  re-decides none. No code, migration or gate lands with it.
- Amends: Baseline §4.3 — the parse sandbox no longer relies on `CLONE_NEWNET`; Landlock, a seccomp allowlist that denies
  `socket(AF_INET*/AF_INET6)`, cleared env, frame fds and rlimits stand in, and a failed start-up probe disables parsing
  instead of running unsandboxed.
- Relates to: Baseline §4.3, §45.1, §57.1, §78.1, §80.1; ADR-0115 (per-type routes), ADR-0118 (the scanner runs in this
  runner), ADR-0116 (capabilities); M16 (sandbox runner contract C-M17-3).

## Context

- Baseline §4.3 requires `CLONE_NEWNET` among the sandbox constraints. The research found no unprivileged netns in the
  default Compose (note :14-15).
- No sandbox exists on the tree; `deploy/env/sizing-a5.env`:58 reserves 512 MiB (note :46). Every parser route in
  ADR-0115 depends on one (note :90).
- The v1 decision that the sandbox would use `CLONE_NEWNET` is superseded (note :20). The note's ceiling is recorded in
  the decision below: the seccomp crate is stale, with a hand-built BPF fallback (note :150).
- Limits are business configuration, not code constants (§78.1); the note gives start values from the research findings
  (note :11-13, :151).

## Decisions

### D-A (D10) `humaux-worker parse-sandbox <processor>`

Exec per input, cleared env, only frame fds, `no_new_privs`, Landlock (ABI ≥ 4 on kernel 6.8: FS limited to the input and
the session temp dir, TCP bind/connect denied), a seccomp allow-list (aarch64 + x86_64; `socket(AF_INET*/AF_INET6)`
denied), rlimits AS/CPU/FSIZE/NOFILE/CORE=0, and wall-clock and output-size caps; a cgroup if delegated (note :144-148).

Start-up probe: if Landlock or seccomp is unavailable, the parser paths are disabled and intake answers WAITING, never a
silent plain subprocess (note :147-149).

Over a limit → `private.artifact_poison`, no retry until the processor version changes (note :149).

`ponytail:` seccompiler 0.5.0 is stale (2025-03); the fallback is a hand-built BPF via `libc` `prctl` (note :150).

### D-B (D11) Limits come from config (§78.1), with start values from the research findings

PDF/Office 100 MiB, PDF ≤ 200 pages; audio 512 MiB or 60 min; image 40 MP/frame + cumulative 200 MP/session; zip 512 MiB
actual, 1,000 members, depth 3; worker 512 MiB (PDF heavy 1 GiB); temp 8 GiB per node. Intake stops (WAITING, not
REJECTED) when free disk < 30 GiB or RAM < 4 GiB. Per-request provider limits come from the probe rows, never from a
vendor table in code (note :151-154).

## Consequences

- Positive: parsing stays isolated on a kernel that has no usable network namespace for the deployment, and a kernel
  without Landlock or seccomp degrades to WAITING rather than to an unsandboxed parser; cap values are configuration, so
  a change needs no code change.
- Cost: parsing needs a Linux target with Landlock ABI ≥ 4 and seccomp; the deployment must probe at start-up and expose
  the disabled state (note :147-149); the seccomp crate is stale, so the fallback is hand-built BPF (note :150).
- Asks M16: consume C-M17-3 (frames, limits, POISON, start-up probe) as the sandbox runner contract (note :186).
- Consumes M01: the D11 limit keys, the disk/RAM intake thresholds and the temp cap are registered in config (note :151-153,
  §78.1).
- Neutral: no code, migration, config key or wire format changes with this card.

## Gates

Planned, implementer-owned, tri-state (§57.1); none exists in this card (note :249).

| gate | owner card | test file | injected fault | expected red |
|---|---|---|---|---|
| A-7 sandbox network | M17-5 | `bins/worker/tests/sandbox.rs` (Linux CI) | drop seccomp socket rule | `socket(AF_INET)` succeeds |
| A-8 sandbox degradation | M17-5 | same | ignore failed Landlock probe | parser runs unsandboxed |
| A-4 zip bomb | M17-19, M17-20 | `bins/worker/tests/sandbox_zip.rs` | count declared sizes | 42.zip-style member exceeds cap |
| A-6 overlong media | M17-21 | `bins/worker/tests/audio.rs` | trust container duration | 3 h file with 1 min header processed |

Each needs its inject → red → fix → green record (§80.1) in the implementing card.

## Owner-gated (listed, not decided)

Red lines, owner only (note :310-313): real model spend in production (probes, extraction, legacy re-extraction on
users' keys; CI uses fakes and test keys); deleting legacy originals in the old MinIO; live keys of any provider or
store. Open owner questions: none (lead rulings applied; v1 Q1 closed by "no originals") (note :313).

## Open research

- **U2.** Landlock/seccomp on the production kernel → the start-up probe disables parsers (intake WAITING), never
  unsandboxed (note :304).
- **R7.** seccompiler maintenance status against the hand-built BPF fallback (note :315).
- **X-M17-3.** Sandbox on target — Landlock ABI and seccomp on arm64 Compose and CI, cold start; gates: M17-5 (note :299).

## Alternatives rejected

`CLONE_NEWNET` (superseded: no unprivileged netns in the default Compose; note :14-15, :20); a plain subprocess when
Landlock or seccomp is unavailable (note :147-149); retrying a poisoned input before the processor version changes (note
:149); a vendor table for per-request provider limits (note :154).

## References

- Module design note M17 v2 §4 (D10, D11), §5 (sandbox runner contract), §8 (cards), §9 (gates), §10 (X-M17-3), §11
  (UNKNOWNs with fallbacks), §12 (research needed, owner red lines), §13 (`ponytail:` ceilings).
- Baseline §4.3 (parse sandbox security boundary), §45.1, §57.1, §78.1, §80.1.
- ADR-0115 (routes), ADR-0118 (scanner), ADR-0116 (capabilities).

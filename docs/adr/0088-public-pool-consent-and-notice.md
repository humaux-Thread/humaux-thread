# ADR-0088 — Public pool consent: default-on, versioned notice, popup, self-service off

- Status: Accepted (2026-10-23). Card M20-1 (docs only), ADR-M20-a. The decisions are the design lead's record of the
  owner's 2026-10-23 rulings (module design note M20 v2, D2' and §14); this ADR records them and does not re-decide.
  Code lands in M20-4 (notice, events, AUTO successor gated on SHOWN, toggle, withdraw-all entry, floor) and M20-28
  (migrated-user effective date).
- Relates to: Baseline §12.1, §12.1.1, §12.6, §13, §7.1; ADR-0078 (work-attribution axis); ADR-0090 (admission); ADR-0091
  (withdrawals).

## Context

- §12.1.1 opens with "默认只开放 MANUAL" and closes with "AUTO_AFTER_USER_DISTILLATION ... 保持关闭"; the database
  defaults stay DISABLED/MANUAL. There is no notice version, shown/ack record, "no contribution before shown" gate or
  withdraw-all (module design note M20, §2 and §3).
- The owner's 2026-10-23 ruling is default-on for the cloud edition, delivered as a popup the user may close, with
  self-service off; the same model as the 2026-07-24 and 2026-10-15 rulings. The GDPR risk was explained and accepted;
  PIPL is not the frame ("not a Chinese system"). The batch-33 public-pool research digest (B33) recommended a scoped
  opt-in; that recommendation is recorded and **not adopted**.

## Decisions

### D-A Cloud default is a policy successor gated on a shown notice

Cloud onboarding appends `AUTO_AFTER_USER_DISTILLATION`. The contribution sweep selects nothing for a tenant until a
`SHOWN` exists for the **current** notice version; a new category, sensitivity class or widened scope is a new notice
version and re-gates the tenant. Core never appends AUTO; DB defaults stay DISABLED/MANUAL. §12.1's policy snapshot and
consent/grant version stay, with the notice version beside them. Per member: a member's memories are selectable only
after that member's SHOWN on the current version (`control.contribution_authorized(tenant, user)`, called with the memory's author).

### D-B One notice table and one append-only event table

`control.contribution_notices(notice_version PK, text_sha256, scope_categories[], licence_text 'CC-BY-4.0',
licence_code 'MIT', published_at)`; `control.contribution_notice_events(tenant, user, notice_version, kind
SHOWN|ACKED|TOGGLED_ON|TOGGLED_OFF|WITHDRAW_ALL, at, channel)`, append-only: every toggle and withdrawal leaves a row.
The popup is rendered by the UI modules (M02/M26); M20 owns the record and the gate, not the visuals. The licence
labels are the F2 labels of ADR-0090.

### D-C Toggle and withdraw-all are two actions

`TOGGLED_ON` writes the AUTO successor while a `SHOWN` for the current version exists; `TOGGLED_OFF` writes DISABLED.
The toggle is OWNER-only in both directions (the policy row is tenant-wide, so there is no per-member opt-out) and OFF is
never blocked for lack of a notice: with none published the event's `notice_version` is NULL (only for `TOGGLED_OFF`).
Withdraw-all is not a policy value: it runs W1 over the tenant (ADR-0091). A toggle does not recall earlier releases; a
withdrawal does. For migrated users the effective date is max(notice email + 14 days, `SHOWN`) and only Memories
created after it are selectable; sending the email is owner-gated, so this ADR does not schedule it.

### D-D Attribution is always `contributor`; the text is never called anonymous

Every public surface shows the literal attribution `contributor`, in every phase: no alias, no real name (owner
2026-10-23). Legally the pool text is pseudonymous personal data for us — we hold the contributor map — and public copy
never calls it "anonymous": identifiability is judged from the controller's side at collection (CJEU C-413/23 P,
remitted to the General Court). The display label and the legal characterisation are different statements.

## Consequences

- Positive: Phase 9's MANUAL path keeps its exact-byte checks; cloud contributions start only after a visible versioned
  notice; choice changes have one append-only audit; withdraw-all has a defined home.
- Cost: a notice version bump re-gates every tenant; the popup is UI work outside M20; the migrated-user email is
  owner-gated.
- Neutral: nothing compiles or runs for this card; no migration, code or gate in this PR.

## Gates

Planned, implementer-owned, tri-state (§57.1); none exists here:

| gate | owner card | injected fault | expected red |
|---|---|---|---|
| G-M20-1 core never AUTO | M20-4 | core onboarding appends AUTO | the core tenant has AUTO (red runs 40301237329 leg 1, 40300523163 leg 2) |
| G-M20-2 floor + migrated | M20-4, M20-28 | ignore the floor or the 14-day rule | a memory below the floor or before the effective date is selected |
| G-M20-3 notice shown | M20-4 | skip the SHOWN check; count an old version's SHOWN | a release with no SHOWN for the current version (red run 40299157074) |
| G-M20-4 opt-out race + withdraw-all | M20-4 | skip the policy re-check at finalize; withdraw-all only toggles | a release after `TOGGLED_OFF`; a prior revision still servable |

Each needs its inject → red → fix → green record (§80.1) in the implementing card; a missing database is a fail in CI,
never `not_applicable` (ADR-0050).

## Owner-gated (listed, not decided)

The migrated-user notice email and its send date; publishing a real tenant's content in production (AUTO successors for
real tenants, the sweep or a resident worker against production, the online E-M20-5 run); M20 go-live as a whole; any
platform-paid model spend (ADR-0090 D-D).

## Open research

- **R4.** CC BY 4.0 legalcode §3(a)(3): is a licensor's request to remove attribution (an anonymous contribution)
  honoured? Irrevocability is confirmed via the CC FAQ; the legalcode was not read. Open; nothing here depends on it.
- **R5.** Quotation limits for RESEARCH units (how much source text F2 may let through) are open; see ADR-0090.

## Alternatives rejected

B33's scoped opt-in (the owner overruled it); signup terms as the notice (no version, no shown record, no re-gating);
per-item confirmation (the owner chose automatic; the Phase 9 preview/confirm stays for the MANUAL/legacy path, not as
a precondition of the cloud AUTO path); calling the pool text "anonymous" in public copy.

## References

Module design note M20 v2, D2' and §13 to §15; batch-33 public-pool research digest (B33) and its first-hand
verification note; Baseline §12.1, §12.1.1, §12.6, §13, §7.1; ADR-0078; ADR-0090; ADR-0091; CJEU C-413/23 P.

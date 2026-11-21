# Number registry for humaux-thread: ADRs and migrations. The lead assigns numbers at dispatch time.
Main at 17b4b9f. The last ADR on main is 0084 and the last migration on main is 0258.

| number | kind | holder | status |
|---|---|---|---|
| 0085 | ADR | #170 M07-2 canonical memory text view | merged af1dea1 |
| 0086 | ADR | #171 M10-1 collection spec per embedding generation | merged 6120d3b |
| 0259 | migration | #170 M07-2 memory_text_v | merged af1dea1 |
| 0260 | migration | M02-1 SEC-1 secret-table grants (note said 0259: reassigned) | merged db950bf (#203) |
| 0261 | migration | M22-2 tenants_active_* in ops.health_snapshot() | merged e45ade1 (#205) |

| 0087 | ADR | #186 workspace UTC instant type = time::OffsetDateTime normalised at construction | merged bbff1c8 (#206) |

| 0262 | migration | M04-1 plan catalogue + versions + entitlement templates | merged 8080405 (#216) |

| 0088-0091 | ADR | M20-1 ADR-M20-a/b/c/d (public pool v2) | merged d3b8021 (#237) |
| 0092 | ADR | M19-1 ADR-M19-a (erasure: scopes, purge door, ledger, Export Manifest v1) | merged #233 (7373bcbc) |
| 0093-0097 | ADR | M14-1 ADRs M14-a..e | merged b9a10f6 (#232) |
| 0263 | migration | M02-4 email door | merged 299fb7b (#240) |
| 0264 | migration | M06-1a evidence_sources table + sourced entry (split) | merged 3050029 (#241) |
| 0265 | migration | M06-1b receipt-trigger amendment | merged 5c4f697 (#245) |
| 0098 | ADR | M06-a (dedupe key D1, classification D2, receipt-trigger amendment rationale) | merged 3050029 (#241) |

| 0266 | migration | M02-5 login challenge | merged 237bb96 (#246) |

| 0267 | migration | M04-2 onboard_tenant plan_version (entitlement projector) | merged 5a3a2bb (#258) |

| 0268 | migration | M02-8 OAuth persistence + definers | merged 6a19510 (#259) |

| 0269 | migration | M06-3 identity-note dedupe index | merged #262 |

| 0099 | ADR | M08-6 ADR-M08-a close 35b-iii won't-do | merged (#266) |

| 0270 | migration | M02-6 console session + signed CSRF | merged fdd1c1b (#276) |

| 0271 | migration | M14-4 project_channels + rollup | merged #290 (0ddded5d) |

| 0272 | migration | M19-2 deletion requests v2 + targets | merged #293 (97b90bf8) |
| 0273 | migration | M14-5 memory_applicability | merged #301 (374b4e67) |
| 0137 | ADR | M02-10-CHOOSER-CONTRACT | reserved 2026-11-21 for Proposed chooser contract |

Next free: ADR 0138, migration 0312. (0311 = M02-10c #708 OAuth loopback redirect / registration, 2026-11-20.) (ADR-0136 = M26 legacy MCP HTTP independent resource, reserved 2026-11-20 for M26-LEGACY-WIRE.) (ADR-0135 = PG19-SWITCH adopt PostgreSQL 19 baseline per owner 2026-11-20, ctx pending.) (0310 = M03-4 #688 per-key RETURNING touch door, reserved 2026-11-20, ctx_a1f4d342953b.) (ADR-0134 tentatively reserved for M01-4-TERMINAL-PRE context consistency_token decision, 2026-11-20, ctx_b58c10236d88; release if unused.) (0309 + ADR-0133 = M03-4-PRE shared cache primitive + identity revoke epoch, reserved 2026-11-20, dispatch ctx_71672968f987.) (0308 = M02-10b OAuth authorize/consent, reserved 2026-11-20 by controller, dispatch ctx_6266779ebc2b.) (0307 = M04-11b2a-C1 slot observe + atomic handover doors, coord442559a2-4865-49ad-a40a-3f59055f1c5f, 2026-11-12; no processor wiring; 0303 remains retired.) (0306 = M04-11b2a-A legacy PLAN guard only, 402d969f-6214-4c49-a6fd-e61077816a91, 2026-11-11; replaces unused 0303 reservation because 0305 would overwrite the same definer during fresh migration; pack credit remains M04-11b2b and gets a later number.) (0305 = M04-11b1b own-subscription PLAN revoke, card/m04-11b1b-revoke, 2026-10-29.) (0304 = M19-3b-fix1 source-row fence door, card/m19-3b-overlay-recheck, 2026-10-29.) (0303 historical M04-11b2 reservation from 2026-10-29 is retired unused, not reusable; current legacy-guard assignment is 0306; slot handover gets a later number at its own dispatch.) (0302 = M21-3 ticket expiry if needed, card/m21-3-ticket-expiry, 2026-10-29.) (0300 = M04-11a billing processor owner doors, card/m04-11a-processor, 2026-10-29; 0301 = M04-11b billing_payments rows reserved, 2026-10-29.) (0299 = M10-2 if needed.) (0297 = M15-11 if needed; 0298 = released (M13-6 needed none) if needed; 2026-10-28.) (2026-10-28 wave: ADR 0128 = M04-8b billing backup KNOWLEDGE (card/m04-8b-billing-backup); ADR 0129 = M04-9 if needed (card/m04-9-creem-adapter); migration 0294 = M04-15 cost door + margin view; 0295 = M04-10 webhook ingress if needed; 0296 = M03-8 if needed.) (0292 + ADR 0126 = M02-10 reserved (oauth http), card/m02-10-oauth-http, 2026-10-27; 0293 + ADR 0127 = M19-6 reserved (memory.forget MCP), card/m19-6-forget-mcp, 2026-10-27; 0291 = M16-3 code symbols + edges, card/m16-3-symbols-edges, 2026-10-27; 0289 = M18-3a task project_id + Unfiled marker, card/m18-3a-task-project, 2026-10-27; 0290 = M18-3b reserved (task kinds + phases), 2026-10-27; 0288 = M04-8 billing core: customers, subscriptions, subscription_events, payments, inbox, card/m04-8-billing-core, 2026-10-27; 0287 = M21-2 repair_findings + I4 scan definer, card/m21-2-i4-scan, 2026-10-27; 0286 = M20-5 eligibility predicate + notice scope categories, card/m20-5-eligibility, 2026-10-27; 0285 = M13-7 reserved, used only if a predicate-registry row must change, card/m13-7-project-census, 2026-10-27; 0284 = M16-2 code snapshots/files/active + repositories key, card/m16-2-code-snapshots, 2026-10-27; ADR 0125 = M02-7 ADR-M02-a/b AS+RS one process, passwordless /auth/*, card/m02-7-auth-pages, 2026-10-27; ADR 0124 + 0283 = M07-5 ADR-M07-d note kinds + epistemic_status, card/m07-5-kinds-epistemic, 2026-10-27; 0282 = M29-g1 memory_in_project predicate, card/m29-g1-in-project, 2026-10-27; 0281 = M18-1 project tree, card/m18-1-project-tree; 0280 = M14-fix-289 list-merge sources, card/m14-fix-289-merge-sources; ADR 0123 = M21-1 ADR-M21-a, card/m21-1-schedule-register; 0279 = M03-3 retire PG rate path, card/m03-3-retire-pg-rate; ADR 0121-0122 = M23-1 ADR-M23-a/b, card/m23-1-adrs; ADR 0114 = M16-1 ADR-M16-a, card/m16-1-adr; ADR 0115-0120 = M17-1 ADR-M17-a..f, card/m17-1-adrs; 0278 = M19-3a accept txn, card/m19-3a-accept; ADR 0112-0113 = M15-0 ADR-M15-a/b, card/m15-0-adrs; ADR 0110-0111 = M13-1 ADR-M13-a/b, card/m13-1-adrs; ADR 0101-0109 = M18-0 ADR-M18-a..i, card/m18-0-adrs; 0277 = M15-1 candidates, card/m15-1-candidates; 0276 = M20-17 vocabulary, card/m20-17-vocab; 0274 = M20-4a notice + events, card/m20-4a-notice; 0275 = M20-7 units, card/m20-7-units; ADR 0100 = M03-2 in-process limiter (ADR-M03-a), card/m03-2-limiter; all 2026-10-26.) Assign these in the dispatch card. Agents never pick numbers themselves.

## Merge train hold (2026-10-23, until T-CI-3 lands)
Generated docs conflict on every main merge, so merges that touch docs/architecture/* are serialised:
1. #179 (M22-1 winner): merge-179b in progress. Merge it as soon as it is green.
2. #168 (M09-2): merge main AFTER #179 lands; ds-merge-168 is running now, so expect one more cycle.
3. T-CI-3 PR: merge last, then rebase-free merges should stop conflicting.
#194 (DeepSeek ci): touches xtask plus targeted.yml; check its overlap before merging.

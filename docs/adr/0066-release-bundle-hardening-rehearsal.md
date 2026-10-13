# ADR-0066 — Release bundle (linux/arm64 containers), process hardening, runbook v2, clean-node rehearsal

- Status: Accepted (2026-10-07; design `card_39_design.md` rev 2, decisions D-A–D-T, review findings RF-1–RF-21,
  main-line rulings R-1–R-12). Implemented in serial slices S1–S7; S8 (image builds) and S9 (node rehearsal) are
  main-line runs (R-1). Open: O-1 (A5 re-measure, below); the DEPLOYABLE acceptance (S9) ran on 2026-10-08 (section
  "S8 / S9 — main-line runs" below).
  - S1 (2026-10-07, uncommitted): UDS hardening — D-K, D-L, D-M below. One module, `crates/infra-cell/src/uds.rs`,
    is the only bind / connect site of every worker RPC socket; the retrieval and private workers refuse to boot on
    a vacuous peer check; the gateway and the consolidation worker verify the serving uid before writing a byte;
    the socket directory and file modes are enforced at bind. The dev launchers (`docs/ops/rehearse.sh`,
    `xtask e2e-onboard`) carry the §2 env lines. No migration.
  - S2 (2026-10-07, uncommitted): exit codes, versions, probe modes, DSN aliases — D-D, D-N, D-O below. Every
    binary has `--version`; every resident mode prints the start line first; the gateway and the maintenance
    resident modes gain the shell-free healthcheck probes; no binary exits 0 without arguments; the two
    unprefixed worker DSNs gain their `HUMAUX_` names with a one-release alias. No migration.
  - S3 (2026-10-07, uncommitted): DNS pin counter and alert — D-P below. `dns_pin_deferred_total` (§41.2) counts a
    distill RETRY settle with class `TRANSPORT` while `HUMAUX_PRIVATE_WORKER_DNS_PINS` pins a host; the private
    worker exports it; §42 `DnsPinDeferred` is loaded, promtool-tested and has its mutation row. No migration.
  - S4 (2026-10-07, uncommitted): routine ops into `humaux-maintenance` (D-Q), `deploy-check` as the release gate
    (D-R), the rollback restore target (D-H), the A5 load flags (D-S) — below. `migrate`, `rls-check`,
    `projection serve` and `member` are library modules of `humaux-maintenance`; `cargo xtask` keeps every
    subcommand name as a thin delegation, so each inherited chain gate still runs. No migration.
  - S5 (2026-10-07, uncommitted): generated env examples and the placeholder secret fixture — D-T below.
    `cargo xtask dep-map --write` writes `deploy/env/example/<process>.env` for the six deployed processes and
    `deploy/env/secret-fixture/`; `dep-map --check` keeps them in sync; supervision.md points at them. No migration.
  - S6 (2026-10-07, uncommitted): the bundle files, no build — D-A (as replaced by R-2), D-C, D-E, D-G, D-H, D-I,
    D-J, D-S (gate script) below. `deploy/compose/prod.yml`, the COPY-only `deploy/images/humaux/Dockerfile`,
    `deploy/release/{build,snapshot,compose,budget_sums,render-secrets,deploy_rehearsal,a5_load_remeasure}.sh`, the
    sizing / values / node files under `deploy/env/`, the PostgreSQL and Qdrant configs, `deploy/prometheus/render.sh`;
    `deploy/compose/observability.yml` is retired. Nothing was built and no compose project was brought up (R-1). No
    migration.
  - S7 (2026-10-07, uncommitted): runbook v2 and the documents — `docs/ops/runbook.md` rewritten for the bundle as 39
    executor-run steps (§3 / §4 below, "Runbook v2"), the executor's lint extended to refuse any operator command
    outside a step, the transcript classifier `TW/c39_steplog_check.sh` with its 6-line sample (R-8), the ADR-0037
    addendum (exit-code contract), the Baseline §4.4 / §67.4 sentences, supervision.md / delivery_point_report.md /
    delivery_plan_v2 rows, the card-39 TW runner twins and the final gate list (R-9). This file is complete: decisions
    D-A–D-T, the rulings, the Tests tables, declared deviations, known limits L-1–L-16, the spec text, O-1. No
    migration. S8 (image builds) and S9 (node rehearsal) are the main line's runs (R-1).

## Context

ADR-0012 authenticates the caller of a worker RPC by its kernel peer credential. Three gaps made that check weaker
than it reads (audit rows ARCH-6 / SEC-5 / OPS-5 and SEC-4): the expected client uid is plain configuration and
nothing refused it when it equals the server's own uid (every local process of that uid then passes); clients never
checked who serves the socket; and no code set the socket directory or file mode (0755 under umask 022).

## Main-line rulings (R-1–R-12, 2026-10-07; they win over the design's §1–§12)

- **R-1 Order.** S1–S7 (code, bundle files, documents) ran in the implementation workflow; S8 (image builds) and S9
  (node rehearsal) are main-line runs after S7, never alongside the chain.
- **R-2 Build method (this is decision D-A's compile step).** No BuildKit `RUN` compile: `build.sh` compiles inside
  `docker run --memory <HUMAUX_BUILD_MEM_MIB>m --memory-swap <same> --cpus <n>` of the digest-pinned builder (target
  and registry on the named volumes `humaux-target-cache` / `humaux-cargo-cache`), and a COPY-only Dockerfile packages
  the binaries. The cap is a sizing value (rehearsal 2560 MiB / jobs 2; A5 8192 MiB / jobs 4); a build over it is
  killed by its own cgroup and reported `build_oom`, never by the VM's global OOM killer. The owner raised the Docker
  VM to 6 GiB on 2026-10-07 (MemTotal 5 922 MiB).
- **R-3 Snapshot objects** are allowed: `snapshot.sh` writes unreferenced objects only (no ref, index or HEAD); a
  production release is built from a commit on main.
- **R-4 Secrets** (E-6): the declared deviations L-13 / L-14 / per-process 0600 env files (below).
- **R-5 Spec text and files** (E-2–E-5): the §41.2 / §42 rows, the §4.4 / §67.4 wording and the ADR-0037 addendum go
  through "Spec text changed" (§78.6); `deploy_rehearsal.sh` lives in `deploy/release/`.
- **R-6 Spend and disk** (E-7–E-9): about 12 provider calls per node rehearsal from the existing keys; pulled images
  and the two cache volumes are kept between runs and listed as "kept on purpose"; S8 requires ≥ 20 GiB free on `/`.
- **R-7 Exposure** (E-10): the gateway is published on loopback only; TLS / public exposure is card 53.
- **R-8 Transcript export** (E-11): the main line copies the cheap agent's JSONL (`<session>/tasks/<agentId>.output`)
  to `<evidence>/agent_calls.jsonl`; the classifier parses that format (decision "Transcript classifier" below).
- **R-9 Chain shape**: card 38's lines minus `release_build` / `rehearse_c38`, `compose_observability` re-pointed at
  `prod.yml`, the card-39 lines, then `release_build`, `rehearse_c39`, `rehearse_node_c39` last; the Docker VM sampler
  runs for the whole lane + chain.
- **R-10 Numbers stay labelled**: every `sizing-*` value is "dev-host start value, A5 re-measure required" until
  `a5_load_remeasure` passes on A5 (O-1); `c39_budget_sums` and `c39_pg_connect_sites` pin the arithmetic.
- **R-11 Research dispositions**: distroless `cc-debian13:nonroot` by digest; compose service-level limits proven by
  `deploy-check --running`; peer-cred across containers proven only by the rehearsal's four scratch statuses; the
  PostgreSQL numbers are inferred (R-10). A W-item found wrong is a blocker, not a workaround.
- **R-12 Discipline**: runner conventions unchanged; no slice migrates the dev database; nothing touches the dev
  stores, `dev.yml` or an lc-* object; every new script is POSIX `sh` with `sh -n` in a gate; secrets are never
  printed.

## Decisions

### D-B — Process set in the bundle

Ships: gateway; retrieval-worker (`--serve-rpc`, `--serve`); private-worker (`--serve-rpc`, `--distill-serve`);
consolidation-worker (`--serve`); maintenance (`health serve`, `--serve`, the one-shots `ops` / `migrate` / `dr`);
admin (one-shot CLI); pg (card-37 image), Qdrant, Prometheus, Alertmanager, otel-collector. Not shipped, each named
`not_applicable` with its owner (L-9): the §4.3 parse sandbox (`humaux-worker`, scaffold only), `humaux-public-worker`
(no resident mode while Public Evolution is not enabled, §67.2), the reranker (card 52), OpenBao (card 54), OAuth
(card 50).

### D-K — Same-uid refusal at boot

`uds::server_policy(process, EXPECTED_KEY, expected, ALLOW_KEY)` runs in `--serve-rpc` of the retrieval worker
(`HUMAUX_RETRIEVAL_WORKER_GATEWAY_UID` / `HUMAUX_RETRIEVAL_WORKER_ALLOW_SAME_UID`) and of the private worker
(`HUMAUX_PRIVATE_WORKER_CONSOLIDATION_UID` / `HUMAUX_PRIVATE_WORKER_ALLOW_SAME_UID`), after the uid is parsed and
before any connection is opened. An expected uid equal to the process's own uid (read with `peer_cred` on a fresh
socket pair) or 0 refuses boot with exit 2 and a line naming the key, unless the allow key is exactly `1`; any other
non-empty allow value refuses boot. The opt-in prints a WARN at boot, and `uds::admit_peer` prints
`WARN <process>: same-uid peer accepted uid=<n>` for every accepted same-uid peer and
`<process>: rpc peer refused uid=<n> expected=<m>` for every refused one (the 403 stays). The allow keys are dev-only:
the generated production examples leave them out (D-T, S5) and deploy-check refuses a non-empty value (D-R, S4).

S1 note: `--distill-serve` binds no socket and reads no peer uid, so there is no check to run there; the §2 env lines
still append `HUMAUX_PRIVATE_WORKER_ALLOW_SAME_UID=1` to its rehearsal starts (unread, harmless).

### D-L — Clients verify the server's peer uid

`uds::connect_verified(path, expected_server_uid)` refuses a socket file with any `other` bit, connects, and refuses
when the kernel peer uid of the serving process is not the expected one, before any byte is written. Keys:
`HUMAUX_GATEWAY_RETRIEVAL_RPC_SERVER_UID` (gateway typed registry, in the group gated by
`HUMAUX_GATEWAY_RETRIEVAL_RPC_SOCKET_PATH`: required whenever the socket path is set) and
`HUMAUX_CONSOLIDATION_WORKER_RPC_SERVER_UID` (required by `--run-once`, `--serve` and `--readyz`). A wrong uid is a
TRANSPORT failure naming `retrieval rpc peer uid` / `inference rpc peer uid`; the gateway's readiness shows it.
The admin's connect-only cell probe is unchanged (its ponytail names the upgrade).

### D-M — Socket directory and file permissions

`uds::bind_guarded(path)`: the parent directory must be owned by the server's uid with mode `& 0o027 == 0` (0750 or
stricter), else boot is refused naming the directory and its octal mode; an existing file at the path is removed
only after a connect probe to it failed (a live server keeps its socket); the bound socket is chmod 0660 explicitly
and re-checked. The rehearsal's socket directory is created 0750; test sockets live in 0700 directories.

### D-D — Probe, version and start-line modes in every binary

- `--version` on all six binaries (`humaux-admin version` is the same line): one stdout line
  `<binary> <crate version> git_sha=<40 hex> build_time=<t|missing>`, exit 0. A build whose
  `HUMAUX_BUILD_GIT_SHA` is absent or not 40 hex exits 2 naming the object (`missing object: HUMAUX_BUILD_GIT_SHA (not
  burned in at build)`). One construction point, `humaux_telemetry::version_line`; each binary passes its own
  `option_env!` values (the crate reads no environment, §78.3). Read before any configuration.
- Source of the sha: the five non-admin binaries get it only from the `cargo build` environment
  (`HUMAUX_BUILD_GIT_SHA=$(snapshot.sh)`, the `release_build` gate and `build.sh`, §2 / R-2); `bins/admin/build.rs`
  keeps its `git rev-parse HEAD` fallback for dev builds; `bins/gateway/build.rs` (Review fix 2) has the same fallback
  because the gateway's `provenance.binary_build` is that line. A dev build of the other four honestly answers exit 2
  to `--version` and `git_sha=missing` on its start line.
- Start line: every resident mode prints `<binary>: start mode=<mode> version=<v> git_sha=<sha|missing>` as its
  first stderr line, before any configuration is read (`humaux_telemetry::start_line`). Resident modes: gateway
  (no argument), retrieval `--serve` / `--serve-rpc`, private `--serve-rpc` / `--distill-serve`, consolidation
  `--serve`, maintenance `--serve` / `health serve`. One-shot modes print none.
- Probes for compose healthchecks (no shell, no curl in distroless): `humaux-gateway --readyz` / `--livez` GET
  `/readyz` / `/livez` on `HUMAUX_GATEWAY_BIND_ADDR`; `humaux-maintenance readyz serve` / `readyz health-serve` GET
  `/metrics` on `HUMAUX_MAINTENANCE_SERVE_METRICS_ADDR` / `HUMAUX_MAINTENANCE_HEALTH_SERVE_METRICS_ADDR`. One
  std-only HTTP/1.0 client, `humaux_telemetry::probe_http`, bounded by `metrics::IO_TIMEOUT` (2 s) per phase:
  200 ⇒ 0; any other status, a missing / unparsable address or a failed connect ⇒ 2 with the status and the body's
  first line on stderr. The workers keep their existing `--readyz` modes (live dependency round trips, 0 / 2).

### D-N — Exit-code contract (ADR-0037 addendum)

0 = clean stop (drained) or one-shot success; 2 = usage or configuration (an operator must change something;
restarting is pointless); 3 = refused (maintenance doors); 1 / 101 = runtime failure or panic (restart helps).
Changes in S2: private-worker and consolidation-worker take exactly one mode argument — none (formerly the Phase 4
probe, exit 0) or more prints usage and exits 2; `--probe-connection` stays an explicit mode (0 connected, 2
missing / conflicting DSN, 1 connect failure). The gateway: no argument = serve; any other argument than
`--metrics-families`, `--version`, `--readyz`, `--livez` is usage, exit 2 (before: silently ignored, it booted); a
configuration error from `GatewayBootstrap::load_from_env` exits 2 (before: 1 through `main`'s `Result`); a runtime
failure after it exits 1. Retrieval, maintenance and admin already refused no / unknown arguments with 2.
Review fix 1 (2026-10-08): the resident modes of retrieval-, private- and consolidation-worker exited 2 on a runtime
failure too (a database down at boot, a failed one-shot pass, the serve loop failing). Their mode functions now return
`humaux_telemetry::ModeFailure` (private, consolidation) or `Outcome::Runtime` (retrieval): `From<String>` is the
configuration case, so every `?` on a parse / required-key helper stays 2, and only the call sites that mark themselves
runtime (each pool connect, the signal-handler install, the serve loop, a failed pass) exit 1. A connect failure of the
explicit `--readyz` probe stays 2 (probe contract 0 / 2). Admin and xtask answer `--version` through the shared
`telemetry::version_mode`, whose refusal branch is tested where it lives.

### D-O — `HUMAUX_` prefix for every DSN

`HUMAUX_PRIVATE_WORKER_PG_DSN` and `HUMAUX_CONSOLIDATION_WORKER_PG_DSN` are canonical. `<worker>::dsn::resolve` (lib
module, injected lookup) over `humaux_telemetry::renamed_key`: the new name wins; only the old name set ⇒ used, and
one boot line `WARN PRIVATE_WORKER_PG_DSN is deprecated; rename it to HUMAUX_PRIVATE_WORKER_PG_DSN (accepted until the
release after card 39)`; both set with different values ⇒ exit 2 naming both; neither ⇒ the missing-key refusal
naming the NEW key; an empty value counts as unset. The module headers declare `env=[HUMAUX_…_PG_DSN,
alias:…_PG_DSN]`; `dep-map` learned the `alias:` prefix and `env_vars.md` lists the old names as
`deprecated-alias`. `rehearse.sh`, `live_env.sh` and the existing tests keep the old names this release (the alias
keeps the 144-assertion rehearsal unchanged); values files and runbook v2 use only the new names (S6 / S7).

### D-P — DNS pin refresh + `dns_pin_deferred_total`

Static pins (`HUMAUX_PRIVATE_WORKER_DNS_PINS`, `PinnedDnsResolver`, no TTL) go stale silently: a pinned address that
stops answering surfaces only as `ReasoningProviderError::Transport` → class `TRANSPORT` → `JobOutcome::Retry`.
Changes in S3:

- `families::DNS_PIN_DEFERRED_TOTAL` (counter, no labels). The static and its one `.inc(` live in
  `telemetry::metrics` (`count_dns_pin_deferred`), not in the private worker: the G80-6 witness may depend on library
  crates only, and `cargo xtask metrics-registry` scans `crates/` for emit sites (the same placement as
  `telemetry::admission`, ADR-0065 D-C). The design text "incremented in `distill.rs`" holds for the decision: the one
  production caller is `private-worker::distill::count_dns_pin_deferral`, called in `run_claimed`'s RETRY arm, which
  counts only when `DistillDispatchConfig::dns_pins_configured` (main: the parsed pin map is non-empty) and the
  settle's class is `TRANSPORT`. `// ponytail:` per-host attribution (L-6).
- `humaux-private-worker` renders the family in both ops listeners (`render_metrics`, read like the card-34b
  counters); D7 now reads four private-worker families.
- §42 `DnsPinDeferred` (warning): `increase(dns_pin_deferred_total[30m]) > 0 and
  increase(private_distill_outputs_total[30m]) == 0`, `for: 15m`. promtool: a fire block (pending at 10m, firing at
  45m) and an "outputs grow ⇒ silent" block; mutation row `dns_pin_and` drops the `and` clause (built-in rows 33 → 34).
- No `ErrorCode` / `DegradeCode` change (§52): a metric family, not a third error enum. Refresh procedure: runbook
  v2 §O-DNS (S7).

### D-Q — Routine ops move into `humaux-maintenance` (S4)

- `bins/maintenance/src/lib.rs` (a lib target beside `main.rs`, not a new crate) holds `migrate`,
  `migration_manifest` (the §46.1 manifest type and its one parser, moved out of `xtask::migration_rehearsal`),
  `rls_check`, `projection_serve`, `switch_visible`, `member` and `deploy_check`. `main` runs them before it builds
  its runtime (each owns its own) and passes their exit code through; they keep the output form they had in xtask.
  `cargo xtask migrate | rls-check | projection-serve | member` are delegations; `soak` reads
  `humaux_maintenance::switch_visible`, `dep_map` the role sets of `humaux_maintenance::rls_check`.
- **The migration set is embedded.** `bins/maintenance/build.rs` writes a table of every `migrations/*.sql` with
  its sibling manifest, each pulled in by `include_str!`, and reruns when `migrations/` changes. Without
  `--migrations-dir` the binary applies that set, so the image needs no source tree and carries exactly the set its
  binary was built with; `--migrations-dir DIR` reads a directory (the xtask delegation passes `migrations`, so the
  dev chain is unchanged). Checksums are FNV-1a of the bytes at run time from either source, so drift detection does
  not depend on the source; `migrate::tests::embedded_set_equals_the_migrations_directory` pins the equality.
  Recorded difference from design D-Q, which rejected a build.rs table in favour of a `COPY` of the directory into
  the `ops` image: ruling R-2 makes the Dockerfile COPY-only for binaries and the S4 task card requires an embedded
  set, so the table is the binding form; the runbook's `--migrations-dir /usr/share/humaux/migrations` still works
  if S6 ships the directory, but nothing needs it. `rls-check`'s R4 registry check reads 0131 from the same table.
- DSNs: `migrate` and `rls-check` take `--dsn <url>` or `HUMAUX_MIGRATOR_PG_DSN` (the superuser path, L-13); a
  missing DSN is usage (exit 2) for `migrate`, a `fail` for `rls-check` (G80-26 is must-pass). The delegations
  pass `HUMAUX_TEST_PG_DSN`, keeping the dev default. `rls-check --spec PATH` runs the spec-derived table-set check;
  without it that check is `not_applicable` naming the missing Baseline (the image ships none).
- **OPS-9 live-session refusal.** `migrate` reads `pg_stat_activity` for sessions of `rls_check::RUNTIME_ROLES`
  and `role_maintenance` with `datname = current_database()` (other than its own) and refuses with exit 3,
  `live_runtime_sessions:<role>=<n>,…`, 0 applied, unless `--allow-live-sessions`. The filter matters because the
  view is cluster-wide and the dev chain migrates throwaways while its gateway is connected to another database
  (RF-16). The HXMIGRAT advisory lock, `lock_timeout`, the per-file transaction, the manifest pre/postchecks, the
  checksum drift stop and the `--dev-placeholder-roles` guard are unchanged.
- Test support: the disposable-database guard (`throwaway`, `DisposableDatabase`, the process-wide `CLUSTER_DDL`
  lock) moved to `maintenance::throwaway`, compiled for this crate's tests and for the `test-support` feature, which
  only xtask's dev-dependency enables (its lane and seed tests use the same guard). The moved tests keep their
  names under `-p humaux-maintenance --lib`; fourteen inherited gate lines were rewritten to that package (same
  assertions), and `c33b_worker_reads_0207` greps `bins/maintenance/src/rls_check.rs`.

### D-R — `deploy-check` becomes the release gate (S4)

`deploy-check` routes to `maintenance::deploy_check` when any of `--compose-json`, `--env`, `--release`,
`--running`, `--secrets-readable` is given; `--roles-sql` keeps the five ADR-0059 checks. One JSON receipt
`{"command":"deploy-check","checks":[{check,status,reasons}]}`; exit 0 pass/not_applicable, 3 any fail, 2 usage or
`resolved_env_input`, 1 an unreadable input or a docker failure. Every reason carries names only.

- `--compose-json FILE|-`: the `docker compose … config --format json --no-env-resolution` document. A
  `_DSN`/`_KEY`/`_CREDENTIALS`/`*_PASSWORD*`/`*_PEPPER*` key with a value in any service `environment` is
  `resolved_env_input:<svc>:<key>` (exit 2, nothing else parsed). A Humaux service is one whose image is
  `humaux-<t>` for a D-A target (the pg image may be named `humaux-…` as well). Per Humaux service:
  `user_missing` / `user_not_numeric` / `user_root` (except `dr`), `read_only_missing`, `cap_drop_missing`,
  `cap_add_unexpected` (only `dr` == `[DAC_READ_SEARCH]`), `no_new_privileges_missing`, `limit_missing:<svc>:<key>`
  for `mem_limit`/`memswap_limit`/`cpus`/`pids_limit` absent or not `> 0` (`0` / `-1` are Docker's "unlimited"),
  `memswap_not_mem_limit`, `healthcheck_missing` (a resident without a test, or with `disable` / `NONE`),
  `privileged`, `network_mode_unexpected` (`service:netns`; `dr` exactly `host`), `host_namespace:<svc>:<key>`
  (`pid`/`ipc`/`uts`/`userns_mode`/`cgroup` = host), `devices_unexpected`, `docker_socket_bind` (any service but
  `dr`), `migrator_dsn_service:<svc>` (the migrator secret file on any service but `migrate`, or the key named in an
  `environment`); globally `migrator_dsn_service:none`, `peer_service_missing`; the D-C uid rule over EVERY Humaux
  service — `uid_out_of_range` (not 10101–10107, `dr` exempt), `uid_shared:<a>,<b>` unless both are modes of one
  binary (`private-rpc`/`private-distill`, `retrieval-rpc`/`retrieval-serve`, `maintenance-health`/
  `maintenance-serve`/`ops`), `uid_identity_foreign` (a non-Humaux service outside the `rehearsal` profile running as
  an identity uid); per pair `pair_group_unexpected:<svc>:<gid>` / `socket_volume_unexpected:<svc>:<volume>` for any
  service but the pair's members (server modes, client, `admin`; the `rehearsal`-only probes exempt), and
  `socket_volume_mode` / `socket_volume_owner` (`driver_opts.o` names `mode=0750`, `uid=<server uid>` and
  `gid=<pair gid>` exactly once each — a later `mode=` overrides an earlier one in the mount). Review fix 1
  (2026-10-08): before it, only the four peer services' uids were compared (admin as the gateway's uid passed) and the
  hardening keys were checked for presence only (`privileged: true`, a docker socket bind, a missing healthcheck,
  `mode=0750,mode=0777` and `mem_limit: 0` passed).
- `--env --values-dir D --secrets-dir S (--examples-dir E --compose-json …| --placement-only)`: placement over every
  file (`dev_only_key_set:<KEY>:<file>`, `migrator_dsn_misplaced:<file>`, `role_password_misplaced:<KEY>:<file>` — the
  role passwords belong in `migrate.secret.env` only, D-J); presence per example key of process `<p>`: declared in
  `values/<p>.env`, its secret home (`<p>.secret.env`; `migrate.secret.env` for `HUMAUX_ROLE_PASSWORD_*`) or the
  compose sources of `<p>`'s services (their `environment:` and their other env_files, read at the document's paths —
  `env_file_unreadable:<svc>:<path>` otherwise; `dr` mounts node.env at its host path for this), else
  `key_missing:<p>:<KEY>`; `key_in_both:<p>:<KEY>`; a secret (not a `*_PREVIOUS*` rotation twin, not the
  `*_CREDENTIALS` map runbook O4 writes after `up`) with only empty values is `secret_empty:<p>:<KEY>`;
  `migrator_dsn_missing`. Presence without `--examples-dir` or without `--compose-json` is a usage error (exit 2) —
  review fix 1 (2026-10-08): it was `not_applicable` (exit 0) and runbook R2/U2 omitted the flag, so an empty secret
  file passed PRECHECK; R2/U2 now pass `--examples-dir /usr/share/humaux/env/example` (the image's copy, D-T), and the
  chain gate `c39_deploy_check_presence_live` runs presence over the live prod.yml: red over the empty fixture
  (`secret_empty`, no `key_missing`), green over a placeholder-filled copy. `DEV_ONLY_KEYS` (the two `…_ALLOW_SAME_UID` keys) is a `pub const` of this module,
  for the S5 example generator to read. With `--compose-json` too: `expected_uid_mismatch:<KEY>` for each of the
  four expected-uid keys against its peer's `user` uid.
- `--release TAG --manifest FILE --expect-sha SHA40`: per manifest `IMAGE` line, `docker image inspect` and
  `docker run --rm --network none --read-only … --version`, then four comparisons with four reasons —
  `image_id_mismatch:<t>`, `image_sha_mismatch:<t>` (label or manifest sha), `image_binary_mismatch:<t>`,
  `version_sha_mismatch:<t>` (design D-R folded (4) into `image_sha_mismatch`; a distinct name makes each
  comparison separately observable). `image_missing:<t>`, `manifest_empty`.
- `--running --project P --compose-json FILE`: `docker ps` + `docker inspect` of the project; per resident Humaux
  service `service_not_running`, `service_unhealthy`, `service_restarted`, `limit_mismatch:<svc>:<memory|memswap|
  cpus|pids>`, `user_mismatch`, `read_only_mismatch`, and what the daemon granted (review fix 1): `privileged`,
  `cap_drop_mismatch` (no `ALL`), `cap_add_mismatch` (any), `no_new_privileges_mismatch`, `docker_socket_bind` (in
  `HostConfig.Binds` or `Mounts`); every container `dev_only_key_set:<KEY>:<svc>`.
- `--secrets-readable DIR`: `secret_unreadable:<path>` per file it cannot read (contents go to a sink).
- The compose fixture `bins/maintenance/tests/fixtures/prod.compose.json` is a `--no-env-resolution` capture of a
  stand-in for the D-C service set with the node prefix rewritten to `/srv/humaux-node`; S6 recaptures it from
  `deploy/compose/prod.yml` (the tests assert the fixture green, then one mutation red).

### D-H — The rollback restore target (S4)

`restore pitr --target-backup <label>` restores that set to its own consistency point:
`pgbackrest --set=<label> --type=immediate --target-action=promote restore`, never a `--target=` time; the set must
exist in `info` and passes the existing `verify --set` refusal first. `--target end`, `--target-time` and
`--target-backup` are mutually exclusive (usage, exit 2); a label that is not a pgBackRest set label is usage.

### D-S — A5 load flags (S4)

`xtask load --host-class <name>` labels `host=<name>-<cpus>cpu-vm<GiB>`; `--meminfo-path <file>` reads
MemTotal/MemAvailable from that file instead of `docker exec <pg> cat /proc/meminfo`, and then `--pg-container` is
not required. Without either flag the card-38 label is unchanged. `e2e-seed` and `load` read no repository file at
run time: the one live `read_to_string` in `load.rs` is the meminfo file (gate `c39_loadgen_no_repo_reads`).

### D-T — Generated env examples and the secret fixture (S5)

`cargo xtask dep-map --write` writes, from the same rows as `env_vars.md`, `deploy/env/example/<p>.env` for the six
D-B processes (`admin`, `consolidation-worker`, `gateway`, `maintenance`, `private-worker`, `retrieval-worker`): one
`KEY=` line per key, sorted, each under a comment with its `env_vars.md` kind and registry, and secret-shaped keys
(`deploy_check::is_secret_key`: `_DSN`, `_KEY`, `_KEY_PREVIOUS`, `_CREDENTIALS`, `_PASSWORD`, `_PEPPER`) marked
`secret: goes in <p>.secret.env`. A key is listed when (all of): its kind contains `runtime`; it is a production
read of that process — declared in the `Depends-on env=[…]` header of a non-test file the process reaches, and, when
that file spells it, spelled by a runtime read outside `#[cfg(test)]` code; it starts `HUMAUX_` but not
`HUMAUX_TEST_` / `HUMAUX_REQUIRE_`; it is not in `deploy_check::DEV_ONLY_KEYS` (D-K; one list, shared with
deploy-check); and it is not `HUMAUX_MIGRATOR_PG_DSN` (D-J: that key lives only in `migrate.secret.env`, so a
`maintenance` example asking for it would make D-R placement red). The same run writes
`deploy/env/secret-fixture/<p>.secret.env` (the secret keys of `<p>`, empty values), `migrate.secret.env`
(`HUMAUX_MIGRATOR_PG_DSN=`), `pg.secret.env` (`PGBACKREST_REPO1_CIPHER_PASS=`, D-J's pg env file) and an empty
`pg_superuser`. `dep-map --check` reports drift in any of them (`doc-drift`).

Deviation from the design wording, recorded: D-T's "at least one non-`tests::` module" became the production-read
rule above. An inline `#[cfg(test)] mod tests` keeps its file's canonical module name, so the module-name rule
listed test-only keys (`HUMAUX_CONTINUITY_*`, read only inside `gateway::mcp_application`'s test module) as gateway
runtime keys; and a module that only *names* keys (`maintenance::deploy_check`, `allow env-undeclared`) put the
peer-uid keys of other processes into the maintenance example. `is_secret_key` gained `_KEY_PREVIOUS` so the
gateway's previous token key is routed to the secret file (and counts as resolved input in `--compose-json`).

### D-A — One commit per build, compiled in a capped builder, packaged COPY-only (S6; R-2 replaces the BuildKit RUN)

- `deploy/release/snapshot.sh [--child <sha40>]` prints the sha of a commit whose tree is the working tree as
  `git add -A` sees it: a copy of the real index as a temporary `GIT_INDEX_FILE`, `add -A`, `write-tree`; HEAD itself
  when the tree is HEAD's, else `commit-tree <tree> -p HEAD` with identity `humaux-snapshot` and both dates = HEAD's
  committer date (deterministic). `--child` makes the same kind of commit with `-p <sha40>` (the rehearsal's UPGRADE
  build). Objects only: no ref, index or HEAD moves (R-3). Not executed in the implementation workflow.
- `deploy/release/build.sh <sha40> --sizing <file> [--unreleased] [--with-loadgen] [--manifest-dir D] [--dry-run]`:
  exit 2 naming a missing or malformed `<sha40>` / `--sizing`; exit 3 for a sha that is not a commit, or not an
  ancestor of `main` without `--unreleased`. Steps: `git archive <sha> -- <allowlist>` (Cargo.toml Cargo.lock
  rust-toolchain.toml .cargo crates bins xtask migrations contracts config docs/architecture deploy/images
  deploy/env/example) extracted and `rsync -rc --delete --exclude /target` into `$HUMAUX_IMAGE_CONTEXT_DIR`
  (default `$HOME/humaux-image-context`); `docker run --name humaux-build-<sha12>-<pid> --memory <M>m --memory-swap
  <M>m --cpus <n> -e CARGO_BUILD_JOBS -e HUMAUX_BUILD_GIT_SHA -e HUMAUX_BUILD_TIME -e RUSTUP_TOOLCHAIN=<channel>
  -v humaux-cargo-cache:/usr/local/cargo/registry -v humaux-target-cache:/work/target -v <ctx>:/work:ro -v <out>:/out
  rust:1.99.0-slim-trixie@sha256:24e632c0… cargo build --release --locked --workspace` (M, n, jobs read from the
  sizing file: rehearsal 2560 MiB / 2 / 2, A5 8192 MiB / 4 / 4); `State.OOMKilled` ⇒ `build_oom`, exit 1; then one
  `docker buildx build --platform linux/arm64 --target <t>` per image with the out dir as context and the four
  `org.opencontainers.image.*` labels, the card-37 PostgreSQL image as `humaux-pg:<tag>`, and the manifest
  `release-<ver>-<sha12>.manifest` (`IMAGE humaux-<t>:<tag> id=… size=… binary=… git_sha=…` per target, plus one
  `PGIMAGE humaux-pg:<tag> id=… size=…` line, which `deploy-check --release` ignores). `RUSTUP_TOOLCHAIN` pins the
  builder's toolchain so rustup never reads the toolchain file's component list. `--dry-run` prints every command.
- `deploy/images/humaux/Dockerfile`: COPY-only; final targets gateway, retrieval-worker (+ gitleaks 8.30.1 from the
  pinned image, the scanner pin), private-worker, consolidation-worker, maintenance, admin, ops (maintenance + the
  generated env examples at `/usr/share/humaux/env/example`), dr (ops + static docker CLI + compose plugin +
  gitleaks, `USER 0:0`), loadgen (xtask). Runtime `gcr.io/distroless/cc-debian13:nonroot` by index digest; every FROM
  has its resolution date on the line above (gate `c39_digest_lines_dated`). Migrations are embedded in the
  maintenance binary (S4), so the image ships no migration directory.

### D-C / D-F — `deploy/compose/prod.yml` (S6)

One service per §4.2 process and mode exactly as the D-C table (uids 10101–10107, pair groups 10201/10202 via
`group_add`, admin in both; `dr` 0:0 with `cap_add: [DAC_READ_SEARCH]`), the YAML anchor `x-humaux` carrying
`network_mode: service:netns`, `read_only`, `/tmp` tmpfs, `cap_drop: [ALL]`, `no-new-privileges`, `restart:
on-failure:5` (review fix 9: residents `unless-stopped`, one-shots `"no"`), the json-file log caps; limits from
`${HUMAUX_SIZE_<SVC>_{MEM,CPUS,PIDS}:?}` (`mem_limit` =
`memswap_limit`); healthchecks in exec form (`--readyz`, `readyz serve|health-serve`, `pg_isready`, busybox `wget`
for Prometheus/Alertmanager); `depends_on` in runbook §5 order; the two tmpfs socket volumes with the server uid, the
pair gid and 0750. Recorded choices:
- **Three value sources, one rule.** `deploy/env/values/<p>.env` (git) holds bundle constants only;
  `$HUMAUX_SECRETS_DIR/<p>.secret.env` holds the process's secrets and its provider route
  (`HUMAUX_PRIVATE_WORKER_{CREDENTIALS,DNS_PINS,EGRESS_RECIPIENTS,REGIONS}`, `DASHSCOPE_API_KEY`); node values
  (cell id, egress processor id, reasoning domain, Qdrant / netns addresses, ports, paths, project) are
  `environment:` entries interpolated from `node.env` (`${HUMAUX_NODE_*:?}`), never copied into a values file (one
  source per value). Consequence: `deploy-check --env` presence (`--examples-dir`) does not see the `environment:`
  keys — see Known limits (S6).
- **Role passwords live in `migrate.secret.env`.** `roles rotate` reads them with the migrator DSN, so only the
  `migrate` one-shot (which already holds the superuser DSN) loads them; no resident carries another role's
  password. The S5 example lists them under `maintenance` — see Known limits (S6).
- **`pg`** keeps the card-37 binds (pgbackrest.conf, the repository host bind with `create_host_path: false`) and
  `-c listen_addresses=${HUMAUX_PG_LISTEN_ADDRESSES?}` (restore pitr's socket-only boot); everything else is
  `config_file=/etc/humaux/postgresql.conf` + the sizing conf (D-G). `POSTGRES_PASSWORD_FILE` points at the one
  compose secret; deploy-check's resolved-input guard now skips `*_FILE` keys (a path, never the secret; test
  `compose_resolved_env_input_is_refused` extended).
- **`qdrant`** listens on its own project address (`QDRANT__SERVICE__HOST`), uid 1000, `cap_drop: [ALL]`, not
  read-only (W-6: the writable paths of the unprivileged image are confirmed in S9 before it is made read-only).
- **`dr` runs in the host network namespace** (`network_mode: host`): `restore drill` dials the drill cluster on its
  published `127.0.0.1` port (card 37). It loads the sizing file, `node.env` (through `${HUMAUX_NODE_ENV_FILE}`),
  `values/maintenance.env`, `dr.secret.env` (review fix 6; it was `maintenance.secret.env`, whose DSN names `pg:5432`)
  and `pg.secret.env`, never `migrate.secret.env`, and mounts the deploy dir, the secrets dir, the repository, the
  evidence and releases dirs at their host paths.
- `deploy/compose/a5-load.yml` (A5 only): the `loadgen` service (profile `a5`) and the gateway's load-window
  overrides (rate buckets out of the way, the netns peer trusted, the netns Host accepted). `HUMAUX_TEST_PG_DSN`
  (what `e2e-seed` and `load --pg-dsn-env` read) comes from `a5-load.secret.env`.

### D-E / D-G — sizing (S6)

`deploy/env/sizing-{a5,rehearsal}.env` (equal key sets; A5 sum 18 064 MiB, rehearsal 3 600 MiB; also
`HUMAUX_NODE_SIZING`, the PostgreSQL sizing conf path and `shm_size`, the drill caps, and R-2's
`HUMAUX_BUILD_MEM_MIB` / `HUMAUX_BUILD_CPUS` / `CARGO_BUILD_JOBS`), `deploy/postgres/{postgresql.conf,
sizing-a5.conf,sizing-rehearsal.conf}` (max_connections 190 both), `deploy/qdrant/config.yaml`. Every number is
labelled "dev-host start value, A5 re-measure required" (R-10). `deploy/release/budget_sums.sh --mem-total-mib N
[--compose prod.yml]` asserts N − Σ`HUMAUX_SIZE_*_MEM` ≥ 4 096, equal key sets, and (with `--compose`) that every
budget line but the parse-sandbox peak is some service's `mem_limit` and every `mem_limit`/`memswap_limit` reads a
sizing key.

### D-I — observability in prod.yml, one renderer (S6)

Prometheus / Alertmanager / otel-collector moved into prod.yml with the card-34 pins, flags and 30 d retention, in
the shared namespace; `observability.yml` is deleted; `check-compose.sh` and `selftest.sh` target prod.yml
(`--no-env-resolution` over the checked-in sizing + node example; images built by build.sh, `humaux-<name>:<tag>`,
are exempt from the digest rule because the release manifest is their identity; a new T-E5 case reds a tag-only
bundle image). `deploy/prometheus/render.sh <out> <sha40> <alert_url_dir>` (POSIX sh + sed + printf) writes
prometheus.yml with the sha, the two rule files, `targets/humaux.json` and alertmanager.yml; rehearse.sh's
observability step now calls it with the sha from `humaux-admin version` (no `python3` in the renderer) and only
rewrites the Alertmanager port.

### D-J — secrets (S6)

`deploy/release/render-secrets.sh <dir>` refuses an existing file, writes under `umask 077` (dir 0700, files 0600)
`pg_superuser`, `pg.secret.env`, `migrate.secret.env` (migrator DSN + the eight role passwords), and one
`<p>.secret.env` per process (DSNs on `pg:5432/humaux`, the shared pepper, the token key, empty provider route keys
for the operator); it prints file and key names only. Amended by review fix 6: it also writes `dr.secret.env`, the
maintenance DSN with the same role and password at `127.0.0.1:<HUMAUX_PG_PORT>` (read from `<dir>/../node.env`, else
5432), because `dr` runs on the host network where `pg:5432` is not PostgreSQL. `deploy/release/compose.sh` is `$C` (exit 2 naming an unset
`HUMAUX_NODE_{SIZING,DIR,PROJECT}`). The scheduler is `deploy/pgbackrest/humaux-backup.crontab` (two `compose.sh run
--rm -T dr …` lines); `humaux-dr.sh` stays for card-37 hosts with a header pointer.

### Runbook executor (S6 part of §4 / R-8)

`deploy/release/deploy_rehearsal.sh` (`--list`, `--show <id>`, `--lint`, `[--fault-path-extra DIR] run <id>`):
markers `<!-- step: <ID> expect: <n> [match: <s>] [value: <KEY>=<ERE>] -->` before a fenced `sh` block; each
block runs whole under `env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin HOME=$HUMAUX_NODE_DIR/home
LANG=C.UTF-8 … /bin/sh -eu -c`, after a NOTOOLCHAIN probe in that same environment (a toolchain refuses the step,
exit 3). exec.log is written by the executor, one line per step: `STEP <id> BLOCK <sha256> EXIT <rc> NOTOOLCHAIN
<ok|FAIL> EXPECT <n>[ match=<s>] RESULT <ok|mismatch> START <t> END <t>`, then `VALUE <KEY>=<v>` for a captured
value (values.env, 0600). This is the single-line form of §4's record (the task card's format); the S7/S9 transcript
checker parses this line.

### D-S — `deploy/release/a5_load_remeasure.sh` (S6)

Three-state, `--out D [--l16-before-p95-ms N] [--facts F] [--replay-log F]`; on a non-A5 host it prints
`GATE a5_load_remeasure not_applicable: missing object = A5 runner (Linux aarch64, 4 CPUs, MemTotal 22-25 GiB)
absent: host facts: …` and exits 0; on A5 it runs budget (measured MemTotal) → every runbook step through the
executor → the manifest identity of the deployed release → seed LA/LB and the card-38 phase set through `loadgen`
with `--host-class a5 --meminfo-path /proc/meminfo` → PASS iff identity + one fresh `host=a5-4cpu-vm2[2-5]` LOAD
line per level + 0 `ASSERTION FAIL`; it always prints `SIGNAL L16 <reopen|hold> enumerate_p95_l16=… bound=2×N`.
O-1 stays open. The chain wrapper is `TW/c39_a5_load_remeasure.sh`.

### Runbook v2 (S7; design §3, §4, §5)

`docs/ops/runbook.md` is rewritten for the bundle. Every executable step is a fenced `sh` block behind a marker
(`<!-- step: <ID> expect: <n> [match: <s>] [value: <KEY>=<ERE>] -->`) and runs only through the executor; the
39 ids, in order: P1–P2 (preflight: tools, node files, absolute paths, free host ports, ≥ 20 GiB free, the sizing's
ceilings against Docker's MemTotal — `budget_sums.sh` on A5; the secrets directory 0700 / files 0600, the provider
route keys filled), R1–R10 (images by manifest → the release gate `deploy-check --release` + `--compose-json --env`
→ pg + stanza + `backup check` → `roles rotate --create-missing` → embedded `migrate` → `role_admin` → `rls-check` +
`deploy-check --roles-sql` → render with the sha of `humaux-admin version` → `up --wait` in `depends_on` order →
`deploy-check --running` + version + eight targets up), O1–O4 (deploy-init, the two smoke tenants `smoke-a` /
`smoke-b` with their keys as 0600 header files, their reasoning routes, the credential map + recreate), V1–V3
(gateway probes, every `--readyz`, every ops listener; remember → recall per smoke tenant, the canary of `smoke-a` =
marker M1; cross-tenant 0), A1–A4 (acceptance drills on the `rehearsal` profile: the four exact peer-cred statuses
and the refusal log line; the Watchdog receipt with the sha; `HealthGaugesAbsent` firing and resolved), B1 (first
VERIFIED backup), U1–U9 (upgrade: next images + captured `PREV_TAG`, the pre-upgrade backup under the running
release with captured `PRE_UPGRADE_LABEL` and the schema head (PR #2 round 4: before the next checkout is used), the
release gate for the next tag, stop the writers and remove the previous release's orphans, migrate and `rls-check`
with the next image, switch `node.env` + render + start, verify, smoke = marker M2), RB1–RB6 (rollback: the release
gate on PREV — a swapped tag is a STOP —, `down --remove-orphans` without `-v`, `restore pitr --target-backup` into
`<project>-rb1` with `node.env` switched first (a stable target across retries), re-LOGIN the four locked roles + start
pg / qdrant / the projector only, Qdrant rebuild, then every other service, and the proof
— running image ids == PREV manifest, disjoint from the upgrade's, PREV sha, schema head equal, M1 recalled, M2
absent —, a backup on the new timeline). Values a step needs are literal, read from a named file of the node
directory (`node.env`, `providers.env`, `release.next`, the smoke files) or captured by the executor; nothing needs
the repository's code. Recorded choices:

- **Smoke tenants.** The runbook onboards two canary tenants on every node; they carry the smoke, the isolation check
  and the rollback markers, so no test touches a customer tenant (§9 rule 2).
- **`providers.env`** (`deploy/env/providers.env.example`, no secret): the embedding provider of `deploy-init` and the
  smoke route's `reasoning register` values. A file, so a step never asks the operator for a value.
- **`node.env` is the single source of the project and tag.** P1 asserts the executor's `HUMAUX_NODE_PROJECT` equals
  it; U7 and RB3 rewrite it (tag, pg image, project) through `awk` + `mv`; RB3–RB6 re-read the project from it.
- **Lint.** `deploy_rehearsal.sh --lint` now also refuses an operator invocation outside a step: a line of another
  fenced block, or an inline code span, that starts with `[sudo] docker` / `cargo` / `$C` / `humaux-<binary>` followed
  by arguments, or runs a `deploy/` script. Naming a binary, file or service is not an invocation; the executor itself
  is the one command a reader is told to run. Reference procedures (rotation, retention, DR, customer onboarding) are
  therefore written as "`<subcommand> <flags>` on the `<service>` one-shot", and the extractor and executor are the
  only two sections of the script that name a Docker, Humaux or toolchain command (gate `c39_runbook_steps`).
- **`a5_load_remeasure.sh` deploys with the first-install prefix** of `--list` (up to the first `A` step): the drills,
  the backup and the release steps need a second release and measure nothing about load.
- **The secrets renderer stays outside the executor**: the operator edits its output (provider keys) by hand, and in
  the rehearsal the main line renders them; P2 verifies the result.

### Transcript classifier (S7; R-8, RF-19)

`TW/c39_steplog_check.sh <executor evidence dir> <runbook>` (POSIX sh + `jq`): (1) exec.log ids == `--list`, in order,
each once; every `BLOCK` hash == the hash of the runbook block computed as the executor computes it; every
`NOTOOLCHAIN ok` and `RESULT ok`; (2) every `tool_use` of `agent_calls.jsonl` is ALLOWED — a Bash command that is one
line of the shape `[cd <dir> && ][HUMAUX_NODE_DIR=… ][HUMAUX_NODE_SIZING=… ][HUMAUX_NODE_PROJECT=… ][sh
][<path>/]deploy_rehearsal.sh (run <ID> | --list | --show <ID>)`, or a Read of the runbook or of a node-directory
file — else IMPROVISED; every step id was run by an allowed call; (3) no `IMPROVISED` line in `agent_notes.txt`. A
missing evidence dir or transcript export prints `not_applicable: missing object = …` and exits 2 (the gate is not
green). `--classify <jsonl> [<node dir>]` runs half (2) alone; the fixture `TW/agent_calls.sample.jsonl` (a
prompt, `--list`, `run P1`, an improvised `docker compose … logs gateway`, a Read of `bins/gateway/src/main.rs`, the
three review-fix-1 bypasses, a tool result: 9 lines) classifies 2 ALLOWED / 5 IMPROVISED and is red — the gate's
standing self-test (`c39_steplog_classifier`). Review fix 1 (2026-10-08, P0): the shape ERE ran on jq's `@tsv`
rendering, which writes a newline as a literal `\n`, so a two-line command and a `HUMAUX_NODE_DIR=$(docker${IFS}ps)`
value classified ALLOWED. The charset test now runs in jq on the RAW string before the shape test: a Bash command of
`[A-Za-z0-9_./=:+, &-]` only (no newline, `$`, parentheses, quotes, backslash, `;`, `|`, `<`, `>`), a Read path of
`[A-Za-z0-9_./+-]` without a `..` segment (`<node>/../..` was a read outside the node dir).

## Review fix 1 (2026-10-08; one fault each, reds in `TW/c39_red_fix1.log`, gate `c39_red_fix1`)

Each finding was changed at its root; none was refuted. Besides the D-N / D-R / classifier / limits text above:
- **A5 runner script** (`deploy/release/a5_load_remeasure.sh`): every node value (secrets dir, tag, releases dir,
  netns address, egress processor) is read from `$HUMAUX_NODE_DIR/node.env` as the runbook reads it — the script read
  `$HUMAUX_SECRETS_DIR` from its own environment, and under `set -u` an unset one only emptied a `$( )` subshell, so
  the seed ran with an empty pepper. The pepper now travels by name (`-e HUMAUX_A5_SEED_PEPPER_HEX`,
  `xtask e2e-seed --pepper-hex-env HUMAUX_A5_SEED_PEPPER_HEX`; `--pepper-hex` stays for the dev rehearsal) — it was a
  `docker compose run` argument, visible in `ps` and `docker inspect` Args. An empty pepper is an `ASSERTION FAIL`.
  The gateway is recreated with a5-load.yml's load-window overrides before seeding (they were never applied) and from
  prod.yml alone after the load.
- **xtask `--version`** (the `loadgen` image's entrypoint): the shared `telemetry::version_mode` line with first token
  `xtask` — without it `deploy-check --release` reported `image_binary_mismatch:loadgen` and R2 stopped on the A5 node.
  `xtask` now depends on `humaux-telemetry` (`# why` in Cargo.toml; nothing new in Cargo.lock).
- **Chain gates re-pointed by the S4 move** (`migrate` / `rls-check` / `switch_visible` left `xtask/`, which those
  gates never scanned): the five `one_*_call_site` gates drop `bins/maintenance/src/rls_check.rs` lines (its typed
  signature catalogue, not call sites) and `stream_count_off_request_path` allows `bins/maintenance/src/switch_visible.rs`
  — each the exact scope the gate had before the move. `c38_witness_admission` was a parallel-test race on the
  process-global admission counters (red once under the gate ceiling, green on rerun): both witness tests hold one
  `Mutex`. The private worker's ops-listener test expects the four families it exports (ADR-0066 D-P added
  `dns_pin_deferred_total`; the test names keep their card-34b wording because ADR-0061 cites them).

| test / gate | fault | red observed |
|---|---|---|
| gate `c39_steplog_classifier` (sample now 2 ALLOWED / 5 IMPROVISED) | the classifier without the raw-string charset whitelist | the two bypasses and the `..` Read classified ALLOWED, counts 2 ≠ 5, EXIT 1 |
| `deploy_check::tests::compose_identity_uid_rules` | uid-shared arm replaced by `false` | `case admin as gateway`, EXIT 101 |
| `deploy_check::tests::compose_identity_uid_rules` | the pre-fix peers-only comparison | `case admin as gateway` (and migrate as maintenance), EXIT 101 |
| `deploy_check::tests::compose_socket_volume_options_are_exact` | `contains("mode=0750")` instead of exactly one mode | the `mode=0750,mode=0777` case, EXIT 101 |
| `deploy_check::tests::compose_hardening_arms_each_red` | read_only arm dropped | `case read_only`, EXIT 101 |
| `deploy_check::tests::compose_hardening_arms_each_red` | cap_drop arm dropped | `case cap_drop`, EXIT 101 |
| `deploy_check::tests::compose_hardening_arms_each_red` | cap_add arm dropped | `case cap_add`, EXIT 101 |
| `deploy_check::tests::compose_hardening_arms_each_red` | limits checked for presence only | `case mem_limit 0`, EXIT 101 |
| `deploy_check::tests::compose_hardening_arms_each_red` | privileged arm dropped | `case privileged`, EXIT 101 |
| `deploy_check::tests::compose_hardening_arms_each_red` | network_mode arm dropped | `case network_mode`, EXIT 101 |
| `deploy_check::tests::compose_hardening_arms_each_red` | docker-socket arm dropped | `case docker socket`, EXIT 101 |
| `deploy_check::tests::compose_hardening_arms_each_red` | healthcheck arm dropped | `case healthcheck removed`, EXIT 101 |
| `deploy_check::tests::compose_pair_membership_is_closed` | pair-gid scan dropped | `case group`, EXIT 101 |
| `deploy_check::tests::env_key_missing_is_red` | an empty secret accepted | `secret_empty:gateway:HUMAUX_GATEWAY_PG_DSN` missing, EXIT 101 |
| `deploy_check::tests::env_key_missing_is_red` | compose `environment:` sources ignored | extra `key_missing:gateway:HUMAUX_GATEWAY_CELL_ID`, EXIT 101 |
| `deploy_check::tests::env_key_missing_is_red` | role passwords looked up in `<p>.secret.env` | extra `key_missing:maintenance:HUMAUX_ROLE_PASSWORD_ADMIN`, EXIT 101 |
| `deploy_check::tests::env_role_password_outside_migrate_is_red` | role-password placement rule dropped | no reason, EXIT 101 |
| `deploy_check::tests::env_presence_needs_examples_and_compose` | missing `--examples-dir` falls back to `not_applicable` (pre-fix) | exit 0 ≠ 2, EXIT 101 |
| `deploy_check::tests::release_checks_each_comparison_is_load_bearing` | manifest `git_sha` comparison dropped (only the label compared) | the stale-manifest case passes, EXIT 101 |
| `deploy_check::tests::running_hardening_arms_each_red` | `HostConfig.Privileged` arm dropped | `case /HostConfig/Privileged`, EXIT 101 |
| gate `c39_deploy_check_presence_live` | `HUMAUX_GATEWAY_REMEMBER_TENANT_ID` removed from `values/gateway.env` | `key_missing=1`, filled copy EXIT 3, RESULT fail, EXIT 1 |
| gate `dep-map --check` | generator routes role passwords back to `maintenance.secret.env` | fixture / example drift, EXIT 1 |
| `{private,consolidation,retrieval}-worker --test exit_codes resident_runtime_failure_exits_1` | runtime failure mapped to 2 (the pre-fix code), once per binary | `left: Some(2) right: Some(1)`, EXIT 101 ×3 |
| `telemetry tests::mode_failure_exit_codes` | runtime exit code 2 | EXIT 101 |
| `telemetry tests::version_without_sha_exits_2` | `version_line` loses the missing-object name (`unwrap_or("missing")`) | `invalid object` ≠ `missing object`, EXIT 101 |
| `telemetry tests::version_without_sha_exits_2` | `version_mode` refusal returns 0 (the admin `version` Err branch now lives here) | EXIT 101 |
| `xtask --test version version_flag_prints_the_xtask_line` | no `--version` arm in xtask | usage text, EXIT 101 |
| `xtask load::tests::file_hook_waits_for_the_launcher_ack` | the file hook succeeds without the ack | EXIT 101 |
| `a5_load_remeasure.sh --facts A5 --replay-log` (skipped BURST-W) | a replay whose BURST-W was skipped (`LOAD_SKIP`, no `LOAD BURST-W` line) | `FAIL: no_a5_load_line:BURST-W load_skip:1`, EXIT 1 (the pre-fix script printed pass, EXIT 0) |
| gate `c39_no_secrets_in_deploy` | the gitleaks image absent on this host (the real state) | `not_applicable: missing object = gitleaks image …`, EXIT 2 (pre-fix EXIT 0) |

## Review fix 2 (2026-10-08; one fault each, reds in `TW/c39_red_fix2.log`, gates `c39_binary_build_burned_in`, `c39_red_fix2`)

Round-1 findings were spot-checked in place (git diff), not redone. One new main-line finding, changed at its root:
- **Gateway build identity read from disk** (`bins/gateway/src/context.rs`, was `executable_fingerprint()`): the §23.1③
  `binary_build` was a sha256 over the whole `current_exe()` (64 KiB reads, once per process), paid on the first
  context assembly / at boot. Measured on GitHub's `ubuntu-24.04-arm` runner (the §67.2 host class, cold disk): a
  272 MiB debug binary took ~20 s (3074 sequential 64 KiB reads in the strace of CI runs 37640665708 / 37644606777),
  missing the 5 s listen deadline of `mcp_gateway.rs` and the 15 s `/livez` deadline of `ops_listener.rs`; x64 8 s;
  the dev Mac (SSD + page cache) under 1 s for the gateway, 2.6 s for the lib test binary under the fault below;
  with `CARGO_PROFILE_DEV_DEBUG=0` the same CI tests went green (run 37646055641), so the cost scaled with binary size.
  A release binary is smaller but its first readiness still paid a full sequential read on the ARM host class.
- **Decision**: `binary_build` is a build-time value, the build's `--version` line
  (`humaux_telemetry::version_line("humaux-gateway", CARGO_PKG_VERSION, HUMAUX_BUILD_GIT_SHA, HUMAUX_BUILD_TIME)`),
  so it is the same string `deploy-check --release` compares with the release manifest's `git_sha` (D-A / RF-1).
  Wire field and semantics kept: same build ⇒ same value; another commit or another release build time ⇒ another
  value. `bins/gateway/build.rs` burns `git rev-parse HEAD` in when the build environment does not set the sha
  (admin's fallback); a build with no sha at all makes `ContextBootstrap::new` refuse (`provenance unavailable`,
  exit 2 at boot) rather than report a placeholder (§23.1③ / G23-6). No key, no dependency added (`humaux-telemetry`
  was already a gateway dependency); `env_vars.md` / `dependency_map.md` regenerated.
- **Known limit** (ponytail in `bins/gateway/build.rs`): a dev build from a dirty tree carries HEAD's identity, so two
  uncommitted builds of one HEAD share it; release builds compile one `git archive` commit (D-A), where commit ==
  build. Upgrade: add a source-tree digest to the build script if a dev e2e ever needs G23-5 across uncommitted builds.

| test / gate | fault | red observed |
|---|---|---|
| `gateway --lib context::tests::binary_build_is_the_burned_in_version_line` | the runtime `current_exe()` sha256 hash restored | `left: "sha256:990d…"` ≠ the version line, EXIT 101 |
| gate `c39_binary_build_burned_in` | the same fault (a live `current_exe` line in `bins/gateway/src`) | count 1 ≠ 0, EXIT 1 |
| `gateway --lib context::tests::binary_build_is_the_burned_in_version_line` | the sha not burned in (`Some("")`) | `ContextBootstrap::new` refuses, EXIT 101 |

The existing `binary_build` assertions in `mcp_gateway.rs` (in-process routes and the spawned real binary) now
compare with the burned-in line instead of re-hashing the test binary.

## Review fix 3 (2026-10-08; one fault each, reds in `TW/c39_red_fix3.log`)

One main-line finding from the S9 node rehearsal (replay prep2, runbook step R7), changed at its root (the check, not
the secrets layout and not the runbook):
- **`deploy-check --roles-sql` assumed the dev env layout** (`bins/maintenance/src/roles.rs` `deploy_check`, ADR-0059
  D-F): four checks (`placeholder_login`, `probe_valid`, `owner_nologin`, `schema_migrations_write`) read
  `HUMAUX_MAINTENANCE_PG_DSN`, the superuser probe reads `HUMAUX_MIGRATOR_PG_DSN`. In this bundle (D-J) the `migrate`
  one-shot loads only `migrate.secret.env` (the migrator DSN and the eight `HUMAUX_ROLE_PASSWORD_*`) and `ops` only
  `maintenance.secret.env`, so no service has both; R7 (`run --rm -T migrate deploy-check --roles-sql …`) exited 3
  with four `not_applicable` "missing object: HUMAUX_MAINTENANCE_PG_DSN" (`TW/card39_rehearsal/cprep2/node/evidence/
  steps/R7.out`).
- **Decision**: when `HUMAUX_MAINTENANCE_PG_DSN` is unset or blank and both `HUMAUX_MIGRATOR_PG_DSN` and
  `HUMAUX_ROLE_PASSWORD_MAINTENANCE` are present, the maintenance DSN is the migrator URL (scheme, host, port,
  database, query) logging in as `role_maintenance` with that password (`role_hygiene::role_dsn`, a pure function next
  to `dsn_user`; the password is percent-encoded into the userinfo). An explicit `HUMAUX_MAINTENANCE_PG_DSN` still
  wins. The receipt gains `maintenance_dsn_source`: `"env"` | `"derived:HUMAUX_MIGRATOR_PG_DSN+HUMAUX_ROLE_PASSWORD_
  MAINTENANCE"` | `null` (no route). With no route the four checks stay `not_applicable` naming
  `HUMAUX_MAINTENANCE_PG_DSN or <the missing derivation inputs>`. Names only; no DSN or password is printed. Env reads
  stay in `deploy_check` (a lookup closure, the existing `rotate` pattern); no new env name, so `env_vars.md` /
  `dependency_map.md` are unchanged (`dep-map --check` in sync).
- **Gotcha** (dep-map lexer): a whole-string `HUMAUX_*` literal in test code counts as a literal read; it flipped
  `HUMAUX_ROLE_PASSWORD_MAINTENANCE` from `declared-only` to `literal` and the regenerated `deploy/env` files dropped
  the key. The tests name it through `env_name(ROLE_MAINTENANCE)` instead.

| test (`humaux-maintenance --bin humaux-maintenance roles::tests::…`) | fault | red observed |
|---|---|---|
| `maintenance_dsn_is_derived_from_the_migrator_url_and_the_role_password` | `role_dsn` returns the migrator DSN unchanged | "derived DSN keeps host/port/db/query, user role_maintenance, the env password", EXIT 101 |
| `an_explicit_maintenance_dsn_wins_over_derivation` | derivation applied even when `HUMAUX_MAINTENANCE_PG_DSN` is set | `left: "derived:…"` ≠ `right: "env"`, EXIT 101 |
| `without_either_route_the_four_checks_name_both_missing_objects` | the detail names only `HUMAUX_MAINTENANCE_PG_DSN` | "placeholder_login: missing object: HUMAUX_MAINTENANCE_PG_DSN lacks HUMAUX_MIGRATOR_PG_DSN", EXIT 101 |

`roles` is a module of the binary target, so its tests run under `--bin humaux-maintenance` (`--lib roles::` selects
none).

## Review fix 4 (2026-10-08; one fault per test, reds in `TW/c39_red_fix4.log`)

One main-line finding from the S9 node rehearsal (replay prep7, runbook step R9 `compose up --wait`), changed at its
root (the key names, not the runbook and not compose):
- **The gateway restarted with exit 2** `gateway bootstrap configuration HUMAUX_GATEWAY_RATE_PREAUTH_IP_CAPACITY:
  missing or undeclared` (`TW/card39_rehearsal/cprep7/node/evidence/diag/humaux-prod-rehearsal-cprep7-gateway-1.log`).
  `bins/gateway/src/bootstrap.rs` built the ten ADR-0065 D-D bucket keys with `format!("HUMAUX_GATEWAY_RATE_{name}_…")`
  in `registry()` and `rate()`, and its `//! Depends-on: env=[…]` did not declare them. `dep-map` sees only literal
  reads and header declarations, so it never attributed them to the gateway: `env_vars.md` listed them for
  `cargo-xtask` only (registry `raw`), the D-T generator left them out of `deploy/env/example/gateway.env`, and
  `deploy/env/values/gateway.env` (keyed off that list) lacked them. The dev rehearsal (`docs/ops/rehearse.sh`) and
  `xtask e2e-onboard` set all ten, which is why only the bundle failed.
- **Decision**: one table `RATE_BUCKET_KEYS: [(class, capacity key, refill key); 5]` in `bootstrap.rs`, every key a
  whole string literal; `registry()` and `rate()` read it (behaviour unchanged: same names, same `i64` parse, same
  error keys). The header declares `HUMAUX_GATEWAY_RATE_{PREAUTH_IP,CREDENTIAL,USER,TENANT,OPERATION}_{CAPACITY,
  REFILL_PER_SECOND}`. With the names literal, dropping one from the header is a `dep-map --check` violation
  (`env-undeclared` + `env-unregistered`) instead of a silent gap. `values/gateway.env` gains the ten keys at 100
  (rehearsal profile 100/100), dev-host start values, A5 re-measure required (O-1, R-10). `cargo xtask dep-map
  --write` regenerated `example/gateway.env` (+10 keys), `env_vars.md` (the ten rows now `process(humaux-gateway)`,
  `gateway::bootstrap`, registry `gateway`) and `dependency_map.md` (the `gateway::bootstrap` env cell); nothing else
  changed.
- **Gotcha** (dep-map, `env_rows`): a header-declared key with no literal in the file counts as a production read
  ("built at runtime"). So once the header declares the ten, reverting one key to a built name alone does NOT drop it
  from the example (logged as a non-red in the red log). The finding needed both halves, a built name and no
  declaration. Faults 2a / 2b isolate each half.

| test / gate | fault | red observed |
|---|---|---|
| `bootstrap::tests::rate_bucket_keys_are_the_five_classes_with_literal_key_pairs` | `…_TENANT_REFILL_PER_SECOND` misspelled `…_TENANT_REFIL_PER_SECOND` | `ends_with("_REFILL_PER_SECOND")` panic, EXIT 101 |
| example gate: after `dep-map --write`, `grep -cE '^HUMAUX_GATEWAY_RATE_.*_(CAPACITY\|REFILL_PER_SECOND)=' deploy/env/example/gateway.env` == 10 | 2a: OPERATION refill key built (`concat!`, the `const` form of `format!`) AND dropped from the header (the pre-fix shape) | count 9, EXIT 1 |
| `cargo xtask dep-map --check` | 2b: literal kept, OPERATION refill key dropped from the header | `[env-undeclared]` + `[env-unregistered]` at `bootstrap.rs:143`, EXIT 1 |

## Review fix 5 (2026-10-08; one fault per test, reds in `TW/c39_red_fix5.log`)

One main-line finding from the S9 node rehearsal (replay prep9), changed at its root (the free-bytes read, not the
image and not compose):
- **Every DR_EVIDENCE cycle failed in the bundle** `dr_evidence: 1 failed call(s), first: df -Pk /srv/humaux/repo: No
  such file or directory (os error 2)` (container `humaux-prod-rehearsal-cprep9-maintenance-serve-1`). The error is
  the spawn, not the path: `bins/maintenance/src/serve.rs` ran ADR-0064 10.11 D's live free bytes as a `df -Pk`
  child, and the release image is COPY-only onto distroless cc (D-A), which has no coreutils. The repository bind is
  correct (prod.yml mounts `HUMAUX_PG_REPO_DIR` at `/srv/humaux/repo`). The dev rehearsal runs the binary on the host,
  where `df` exists, so it never showed. So the six DR families (ADR-0064 D-K) never published in the bundle, and the
  node rehearsal's Watchdog / backup assertions could not be trusted.
- **Decision**: an in-process `libc::statvfs` (`libc` was already in Cargo.lock; `nix` is not; no new package, the lock
  gains one line in `humaux-maintenance`'s dependency list). Free bytes = `f_bavail × f_frsize` (`df`'s Available for
  an unprivileged caller). The read runs in `spawn_blocking` under the same `tokio::time::timeout(CYCLE_SECONDS)` (a
  hung mount must not stall the loop); errors keep the `Err(String)` shape naming the path (`statvfs <path>: <os
  error>`). The header and the tag move from `subprocess(df)` to `fs(statvfs of the DR paths)`; tokio's `process`
  feature is dropped (no other user in the crate); `dep-map --write` regenerated `dependency_map.md` only.
- **Other host-tool spawns** (swept `bins/*/src`, `crates/*/src`): none runs on the plain maintenance image in a
  resident mode. `docker` in `backup.rs`, `drill.rs`, `deploy_check.rs` runs from the `dr` image (docker CLI + compose
  copied in), with `du`/`df` inside `pg` via `docker compose exec`; `gitleaks` (local-secret-scan) ships in the
  retrieval-worker and `dr` images; `ps` (`throwaway.rs`, feature `test-support`), `true` (`migrate.rs` tests), the
  fake scanner (`retrieval_query_source.rs` tests) and `sleep`/`kill` (testkit) are test-only. Prose still saying
  `df -Pk` for this read (outside this fix's files): `docs/ops/runbook.md` (the dr_evidence row), `docs/ops/
  supervision.md`, `crates/telemetry/src/dr.rs` `//!`, `crates/telemetry/src/metrics.rs`, `crates/adapters/src/
  maintenance_repo.rs` (field doc), Baseline §41.2 row `backup_disk_free_bytes`.

| test / gate | fault | red observed |
|---|---|---|
| `serve::tests::available_is_bavail_times_frsize` (crafted statvfs: bsize 4096, frsize 512, bfree 100, bavail 60) | multiply by `f_bsize` instead of `f_frsize` | left 245760 ≠ right 30720, EXIT 101 |
| same | read `f_bfree` instead of `f_bavail` | left 51200 ≠ right 30720, EXIT 101 |
| `serve::tests::statvfs_reads_cwd_and_names_a_missing_path` | (positive control: cwd > 0; `/nonexistent/humaux-fix5` → `Err` naming the path) | — |

## Review fix 6 (2026-10-08; one fault per test, reds in `TW/c39_red_fix6.log`)

One main-line finding from the S9 node rehearsal (replay prep11), fixed in the secrets layout:
- **Finding.** Runbook step B1 (`$C run --rm -T dr backup run`) exited with `connect HUMAUX_MAINTENANCE_PG_DSN: …
  expected to read 5 bytes, got 0 bytes at EOF`, and the pg log shows no connection from `role_maintenance`
  (`TW/card39_rehearsal/cprep11/node/evidence/steps/B1.out`). Root cause: `dr` runs with `network_mode: host` (card 37:
  `restore drill` dials the drill cluster on its published loopback port; it drives compose through the socket) but
  loaded `maintenance.secret.env`, whose DSN render-secrets.sh composes on `pg:5432/humaux`, the compose-internal
  address the residents use through the shared netns. On the host network that address is not PostgreSQL (the
  published one is `127.0.0.1:${HUMAUX_PG_PORT}`). R4–R10, O1–O4, V1–V3 and A1–A4 passed because they run inside the
  compose network; B1 is the first step that dials the maintenance DSN from the host network.
- **Decision (main-line ruling).** A separate `dr.secret.env`: `HUMAUX_MAINTENANCE_PG_DSN` only (the `dr` modes
  `backup *`, `restore drill|pitr` and `deploy-check --release|--running` read no other key of
  `maintenance.secret.env`: the pepper serves `apikey`/`onboard`, the retrieval DSN `projection rebuild`), same role
  and password, host `127.0.0.1:<HUMAUX_PG_PORT>` from `<secrets dir>/../node.env` (runbook §1 layout), else 5432; a
  non-numeric port is refused (exit 3). It joins FILES (an existing file is a refusal) and the names printed.
  `prod.yml` `dr` loads it instead of `maintenance.secret.env`; the drill's `drill_target_is_live` comparison is
  unchanged (the drill publishes on another port). `deploy/env/secret-fixture/dr.secret.env` is hand-maintained (D-T's
  generator renders the six deployed processes; `dr` is a mode, not a process), names only, empty value.
  `bins/maintenance/tests/fixtures/prod.compose.json` was recaptured with the D-R command (one-line diff: dr's
  env_file).
- **Checks** (`deploy_check.rs`): `--compose-json` refuses `dr.secret.env` on any service but `dr`
  (`dr_secret_file_service:<svc>`; `migrator_dsn_service` unchanged); `--env` placement allows
  `HUMAUX_MAINTENANCE_PG_DSN` in `secrets/maintenance.secret.env` and `secrets/dr.secret.env` only
  (`maintenance_dsn_misplaced:<file>`); with `--env` and `--compose-json` together, the new check `host_network_dsn`
  refuses a `*_DSN` whose host is a compose service name in a secret file loaded by a `network_mode: host` service
  (`host_network_dsn_internal:<svc>:secrets/<file>:<key>`; an empty value — the placeholder fixture — is not judged,
  so on a clean checkout only the unit tests see the old layout; on a node PRECHECK runs it on the real secrets dir).

| test / gate | fault | red observed |
|---|---|---|
| render-secrets on a temp node dir with `node.env` `HUMAUX_PG_PORT=28701` (dr host `127.0.0.1:28701`, user `role_maintenance`, password equal to `maintenance.secret.env`'s, compared with sed and never printed; default 5432; an existing `dr.secret.env` refused exit 3) | before the fix | `FAIL dr.secret.env missing`, EXIT 1 |
| same | the node.env port read replaced by `:` | `FAIL dr host is not 127.0.0.1:28701 (got host=127.0.0.1 port=5432)`, EXIT 1 |
| `deploy_check::tests::compose_hardening_arms_each_red` case `dr.secret.env on a resident` | drop the `dr_secret_file_service` arm | case red (no reason), EXIT 101 |
| `deploy_check::tests::env_maintenance_dsn_outside_its_homes_is_red` | drop the `maintenance_dsn_misplaced` rule | `[] ≠ ["maintenance_dsn_misplaced:secrets/admin.secret.env"]`, EXIT 101 |
| `deploy_check::tests::host_network_dsn_internal_is_red` | drop the `network_mode: host` filter (residents judged) | green layout red, EXIT 101 |
| same | drop the service-name comparison (any host refused) | the 127.0.0.1 DSN red, EXIT 101 |
| same | drop the rule | old layout green, EXIT 101 |
| same | drop the wiring into `--env` | no `host_network_dsn` check, EXIT 101 |
| all three tests | before the fix (all rules and the wiring off) | 3 failed, EXIT 101 |

The test count of `deploy_check::tests` goes 17 → 19 and the secret fixture 8 → 9 files; the main line's gates
`c39_deploy_check_compose` (`= 17`) and `c39_env_examples_generated` (`= 8`) pin the old counts.

## Review fix 7 (2026-10-08; one fault per test, red in `TW/c39_red_fix7.log`)

One main-line finding from the S9 node rehearsal (replay prep12), fixed in `restore pitr` refusal 3:
- **Finding.** Runbook step RB3 (`$C run --rm -T dr restore pitr --target-backup …` in the rollback project
  `<project>-rb1`) and the design-§5 fault (c) (`restore pitr --target-time` in `<project>-rbx`) both exited 3 with
  `production_pg_running:humaux-prod-rehearsal-cprep12-rb1-dr-run-74c71c8469fe`: the refusal named the `dr` one-shot
  that was running the restore (`TW/card39_rehearsal/cprep12/node/evidence/steps/RB3.out`, `TW/c39_rehearse_node.log`
  RECORDED RED … rbx). Root cause: refusal 3 (`bins/maintenance/src/drill.rs` `pitr`) listed every running container
  of `HUMAUX_MAINTENANCE_BACKUP_PROJECT`; in the bundle `dr` is a compose service of that project (prod.yml sets the
  variable to `${HUMAUX_NODE_PROJECT}`), so the guard always found its own `docker compose run dr` container. Card 37
  ran the binary on the host, outside the project, so it never matched itself.
- **Decision (main-line ruling).** Refusal 3 looks for a running PostgreSQL of that project only: `docker ps` gains
  `--filter label=com.docker.compose.service=pg` (service `pg` is the convention of drill.rs, prod.yml and backup.yml).
  The hazard of ADR-0064 D-U / 10.11 B is a second cluster archiving into the stanza, not any container. The reason
  string `production_pg_running:<container>` is unchanged; the guard is not widened to other projects (runbook RB2's
  `down` of the previous project stays the ordering guarantee).

| test / gate | fault | red observed |
|---|---|---|
| `tests/drill.rs` `pitr_refusal_3_names_only_a_running_pg_of_the_backup_project` (a `docker` shell shim on PATH: under the project filter alone it lists `<p>-dr-run-74c71c8469fe`, under project + `service=pg` nothing → `restore pitr` passes refusal 3; listing `<p>-pg-1` under both → exit 3 `production_pg_running:<p>-pg-1`) | drop the `service=pg` filter (the pre-fix guard) | `the dr one-shot refused its own restore: … production_pg_running:humaux-prod-rehearsal-fix7-rb1-dr-run-74c71c8469fe`, EXIT 101 |

## Review fix 8 (2026-10-12; four findings — three from the 2026-10-08 chain, one from the 2026-10-12 lane rerun)

Three main-line findings from the first full lane + chain over the card-39 tree (lane 126/126 green; chain 567 gates,
3 red, `CHAIN_EXIT 1` at 16:13), each fixed at its root:
- **`workers_tests` (T34 `slow_provider_tenant_cannot_take_all_slots`, `B held 3 of 4 slots`, `done_a=500`).** The
  sampler folded a sample in while tenant A had a PENDING *or PROCESSING* `DERIVED_DISTILL` job. ADR-0060 D-F bounds
  B's share only while A has *claimable* work; a PROCESSING job already holds its slot, so at A's tail (one job in
  flight, nothing left to claim) B legitimately takes the other three and the guard still counted the sample. Decision:
  the guard counts `status = 'PENDING'` only (the claimable predicate; A's jobs never retry, so PENDING is READY). The
  bound `max_slots_b <= 2` is unchanged. Same lesson as the 2026-10-05 fix (an untyped count): the fairness window
  must be the exact READY predicate of the work under test.
- **`dep_map` (`derived_dispatch_e2e.rs:4271 [callsite-untagged] tcp`).** The E10 black-hole probe
  (`literal_endpoint_black_holes`, the CI portability fix ported into this tree on 2026-10-08) connects with
  `TcpStream::connect_timeout` and carried no `// dep:` tag. Decision: tag it `HTTP(literal endpoint)` — the probe
  dials the literal chat address and nothing else; the file header declares the service and `dependency_map.md` gains its
  row (`dep-map --write`); no exemption.
- **`rehearse_c39` (`version_line_present`: 13 start lines — the 3 gateway logs `git_sha=<HEAD 559f013>`, the other
  ten `git_sha=missing` — wanted the snapshot sha).** `docs/ops/rehearse.sh` step 0 rebuilt the seven packages after the
  `release_build` gate without `HUMAUX_BUILD_GIT_SHA`; cargo tracks `option_env!` inputs, so the burned-in sha was
  rebuilt away (the gateway's `build.rs` fell back to HEAD, the binaries without a `build.rs` to `missing`). Decision:
  the launcher exports `HUMAUX_BUILD_GIT_SHA="${HUMAUX_BUILD_GIT_SHA:-$(sh deploy/release/snapshot.sh)}"` before its
  build — the same sha the release_build gate burns in for the same tree (snapshot.sh is deterministic per tree,
  R-3), so the release_build binaries are reused unchanged and a dev (`debug`) rehearsal names its own tree too. An
  explicit value is never shadowed. No gate line changes.

- **Lane rerun of 2026-10-12 (after the three fixes): `distill_poison_live`, `every good job DONE at attempt 1`,
  `good_final=[("DONE",1),("DONE",2)]`, phase-B lane `claimed=3 completed=2 deferred=1`.** The second good job's first
  phase-B call was a MiniMax RETRY_WAIT deferral and it completed at attempt 2. M6's property is that the poison lane
  never spends a good job's budget (asserted by `good_attempts_after_poison_phase=[0,0]`), not that the provider has
  capacity; the same §57.1 reading as the fairness M1 guard (fix 1). Decision: phase B asserts exact accounting — every
  good job DONE and `sum(attempt) == phase_b.attempts == good jobs + phase_b.deferred` — so an attempt that is neither
  the DONE call nor a deferral still fails; no slack, no `not_applicable`.

| test / gate | fault | red observed |
|---|---|---|
| lane `distill_poison_live` (phase-B accounting) | the pre-fix assertion `attempt == 1` | lane 2026-10-12 15:05 `every good job DONE at attempt 1` (`good_final=[("DONE",1),("DONE",2)]`, `deferred=1`), EXIT 1 |
| `workers_tests` → `derived_dispatch_e2e::slow_provider_tenant_cannot_take_all_slots` | the pre-fix guard (`status IN ('PENDING','PROCESSING')`) | chain 2026-10-08 13:19 `B held 3 of 4 slots` (samples=56 done_a=500), EXIT 101 (observed by the main line on 2026-10-12 from that chain log, `TW/gates_card39_mainline.log`, before the rerun overwrote it; quoted from that reading; per-run copies start with chain #2) |
| `dep_map` | drop the `// dep: HTTP(literal endpoint)` tag | chain 2026-10-08 14:11 `callsite-untagged … tcp needs a // dep: tag`, EXIT 1 (observed by the main line on 2026-10-12 from that chain log, `TW/gates_card39_mainline.log`, before the rerun overwrote it; quoted from that reading; per-run copies start with chain #2) |
| `rehearse_c39` → `version_line_present` (`TW/c39_version_lines.sh`) | drop the `HUMAUX_BUILD_GIT_SHA` export from `rehearse.sh` step 0 | chain 2026-10-08 16:03 `want git_sha=09d890ac… in 13 start lines`; 3 gateway lines `git_sha=559f013…` (HEAD), 10 others `git_sha=missing`, EXIT 1 (observed by the main line on 2026-10-12 from that chain log, `TW/gates_card39_mainline.log`, before the rerun overwrote it; quoted from that reading; per-run copies start with chain #2) |

## Review fix 9 (2026-10-12; pre-PR review wf_17c25e0e-ac3, 39 confirmed findings; reds in `TW/c39_red_fix9.log`, `TW/c39_red_fix9_gates.log`, `TW/c39_red_s8.log`)

**Source.** A read-only pre-PR review of the uncommitted card-39 tree, run while chain #2 (2026-10-12) held the tree
frozen: six lenses (hard boundaries, isolation / security, operability, ADR truthfulness, gate truthfulness, the fix-8
delta), every finding put to two adversarial refuters, then a completeness critic (CC-1–CC-4); 159 agents. Outcome:
39 confirmed, 30 contested, 7 refuted. The review injected no fault (cargo and every script were forbidden while the
chain ran), so each red in the table below is recorded by the main line or the gates agent in the three logs named in
the heading. Chain #2 itself was red on one test (E1 below). This section records decisions; it claims neither a green
chain nor DEPLOYABLE — both wait for the chain rerun over the final tree.

**Rulings (main line, C1–C9).**
- **C1 restart policy (OP-3).** `restart: on-failure:5` brought nothing back after a host reboot or a dockerd restart
  and gave a runtime exit 1 about 3 s of retries, while supervision.md said exit 1 / 101 "restart". Decision: every
  resident of `prod.yml` (netns, pg, qdrant, the eight Humaux residents, prometheus, alertmanager, otel-collector) is
  `unless-stopped`; one-shots (profiles `ops` / `rehearsal`) keep `"no"`; deploy-check rule
  `restart_policy:<svc>:<value>`. L-2 rewritten; supervision.md §3 states Docker's real semantics.
- **C2 checkout tree guard (OP-4).** Section R never installed the next release's `checkout/` (`deploy/`, the runbook,
  the 0011 roles file), so an upgrade ran NEXT's images under PREV's prod.yml and values. Decision: `build.sh` writes a
  manifest line `CHECKOUT tree=<id of SHA:deploy> runbook=<id of SHA:docs/ops/runbook.md>
  roles=<id of SHA:migrations/0011_roles_and_grants.sql>` and `humaux-checkout-<tag>.tar.gz` (+ `.sha256`), a
  `git archive` of those paths plus the one-line `CHECKOUT_TREE`; `deploy-check --release --checkout-tree "<line>"`
  reds `checkout_tree_mismatch:<field>`, `checkout_tree_missing`, `checkout_tree_not_in_manifest`. Runbook R2 / U3 / RB1 pass
  `--checkout-tree "$(cat CHECKOUT_TREE)"`; a mismatch is a STOP whose remedy is installing that tarball (`.sha256`
  verified) as `<node dir>/checkout-<tag>/` and restarting the section inside it. The S9 pair (snapshot + `--child`,
  one tree) matches without an install.
- **C3 rollback roles (OP-2).** RB4 re-enabled four hard-coded roles, but `restore pitr` sets NOLOGIN on every LOGIN
  role except postgres, role_maintenance and role_retrieval_worker, so role_admin and role_batch_issuer stayed locked.
  *Found by the cheap-agent run (agent3, RB5's new `rls-check` tail):* the first draft read `nologin_roles` AFTER the
  quarantine as every NOLOGIN `role_*`, so RB4 also gave LOGIN to `role_migration_owner` and `role_health_reader`,
  which are NOLOGIN by design (ADR-0059 D-A, ADR-0061) — `rls-check` red on both. `restore pitr` now records the LOGIN
  roles it is about to lock, read before the DO block (`locked_roles_sql`), so `nologin_roles` is exactly the set RB4
  must restore.
  Decision: RB4 re-enables exactly `rollback-1.json`'s `nologin_roles` (sed / tr, no jq; a missing file or field is
  exit 1); RB5 ends with `migrate rls-check` and `deploy-check --roles-sql` (the U6 / R7 shapes); the "four roles …
  §11.6 step 5" prose is corrected.
- **C4 rendered configs (OP-6).** prometheus and alertmanager run as their image user (no `user:`) and could not read
  configs rendered 0700 / 0600 on a Linux node. Decision: R8 renders under `umask 022` (`rendered/` and `alert-urls/`
  0755, files 0644; nothing there is secret: the git sha, `url_file` paths, two URL files); limit L-19.
- **C5 red-record gates (gate F1, gate F2; gate F4).** `c39_red_s2` compared without a floor (green on a missing log)
  and the siblings pinned `-ge` floors below their real counts. Decision: every `c39_red_*` gate pins the exact fault
  header count and header == non-zero-EXIT count (repo rule `== N`); the fix3–fix7 logs get one gate each in their own
  format; new `c39_red_fix9`, `c39_red_fix9_gates` and `c39_red_s8` (gate F4: three image-build faults — a manifest
  line dropped, one id in both manifests, another sha in admin — each with its green restore).
- **C6 one UDS site (LENS-2 / ISO-17).** `c39_one_uds_site` matched the strings `UnixListener::bind` /
  `UnixStream::connect`, so `use tokio::net::UnixStream as Sock; Sock::connect(` evaded it. Decision: the identifiers
  `UnixStream` / `UnixListener` appear on non-comment, non-test lines only in `crates/infra-cell/src/uds.rs` (its
  imports and signatures) and `bins/admin/src/cell_resources.rs` (the connect-only probe, L-11); the count is the exact
  allow-list and a `use … as` alias anywhere else is red; fixture red in `c39_red_fix9_gates.log`.
- **C7 builder toolchain (F10).** `build.sh` named a gate that did not exist. Decision: gate
  `c39_builder_matches_toolchain` — the `BUILDER=` digest answers `rustc --version` with rust-toolchain.toml's
  channel; `not_applicable` naming the image where docker cannot run it.
- **C8 per-run chain logs (F2 adr).** The 2026-10-12 rerun overwrote the 2026-10-08 chain log, so fix 8's red cells
  cited a file that no longer held them. Decision: `TW/c39_mainline.sh` copies the chain log to
  `gates_card39_mainline.<YYYYmmdd-HHMM>.log` after each chain and appends `CHAIN_EXIT <n> <stamp> <copy>` to
  `c39_run_notes.txt`; fix 8's cells say where their quotes come from. Per-run copies start with chain #2.
- **C9 statvfs wording (OP-8 / F11).** Review fix 5 replaced the `df -Pk` child with in-process `statvfs(3)`
  (`bins/maintenance/src/serve.rs` `statvfs_free_bytes`), but the runbook, supervision.md and the Baseline §41.2 row
  still named `df -Pk`. Decision: all say "statvfs(3) of the path (f_bavail × f_frsize), in-process"; the §41.2 row is
  listed under "Spec text changed".

**deploy-check hardening (`bins/maintenance/src/deploy_check.rs`; one fixture red per rule).**
- ISO-5: `security_opt` equals `["no-new-privileges:true"]` exactly (compose; `--running` HostConfig.SecurityOpt less
  the daemon's own defaults) — `seccomp:unconfined` / `apparmor:unconfined` / `label:disable` beside it were green.
- ISO-8: the env parser follows Compose's env_file reading — a leading `export ` stripped, the last occurrence wins —
  and reports `key_duplicated:<file>:<key>`; before, the first duplicate decided the uid / placement checks while the
  container got the last.
- ISO-4: every `ports` entry carries host_ip `127.0.0.1` (compose; `--running` HostConfig.PortBindings HostIp) — R-7 /
  L-12 had no gate.
- ISO-3: a service loads only its own process's `*.secret.env` (+ `migrate.secret.env` for `migrate`; `dr.secret.env`
  and `pg.secret.env` for `dr`): `secret_file_foreign:<svc>:<file>`.
- ISO-2: bind mounts on Humaux services other than `dr` are read-only and come from the checkout or the node dirs
  named in node.env; `/`, `/var/run`, `/run`, `/proc`, `/sys`, `/dev`, `/etc` and the secrets dir are refused:
  `bind_mount_unexpected:<svc>:<target>`.
- CC-1: the privilege subset (privileged, host namespaces, devices, docker.sock, `cap_add`, `security_opt`) applies to
  every service but `dr` — pg, qdrant, netns, prometheus, alertmanager, otel-collector and alert-sink were outside
  every rule; read-only, uid and limits stay Humaux-only.
- OP-7: a mode flag without its value, or an empty check list, exits 2 (D-N: no argument-less success); before,
  `--compose-json` with a dropped value exited 0 with `{"checks":[]}`.

**Tests.**
- E1 (chain #2 red, `workers_tests` → `derived_dispatch_e2e::one_hung_provider_call…`, "nothing else is READY"): two
  hazards, both real, and the chain's exact trigger is not reconstructible (the suite had been SIGKILLed mid-run at
  16:03 by a session teardown; a fixture tenant is deleted only on Drop, so its READY rows outlive a kill). (a) The
  sweeper's claim is DB-wide (lane(a:shared_db)) and the assertion was untyped: at 19:35 the shared dev database held
  two READY `DERIVED_DISTILL` jobs of two rehearsal tenants (`e2e-seed-…`, seeded 18:18 by chain #2's own
  `rehearse_c39`), the sweeper claimed one, and the red reproduced alone, outside any load; a foreign claim also
  takes a dispatcher seat, so B's rows settle behind the hang (the ordering assertion reds too). (b) The sweeper
  started after a fixed 300 ms; on a loaded host the pass has not claimed yet and the sweeper takes a READY B row.
  Decision: the sweeper waits (≤ 10 s) until none of the four seeded jobs is READY by the claim predicate, sweeps
  only while the shared queue holds no foreign READY job (checked before every sweep), and asserts that no seeded
  job is swept; a skipped sweep makes the scenario `not_applicable: missing object = an empty shared
  DERIVED_DISTILL queue (…)` naming the residue tenants (§57.1) — never red, never quietly green. Housekeeping on
  2026-10-12: the two rehearsal tenants were torn down with `xtask e2e-seed --teardown`; no fixture residue remained.
- C39-F8-1: the T34 sampler's tenant-A guard is the claim function's READY predicate verbatim (fix 8's
  `status = 'PENDING'` missed a claimable RETRY_WAIT row and counted a PENDING row with a future `next_retry_at`).
- C39-F8-2: phase-B accounting counts the ADR-0048 re-asks:
  `attempts == good_jobs + deferred + empty_retries + malformed_retries`.
- C39-F8-4: one injected red for the phase-B accounting (one extra attempt on a good job → red, restored → green) in
  `c39_red_fix9.log`; fix 8's row records only the pre-fix assertion.
- LENS-1 / ISO-7: one `uds.rs` test per D-L / D-M branch — a 0o770 socket dir refused naming `0770`, a dir owned by
  another uid (pure helper), `connect_verified` on a 0o666 socket returns `Mode` and writes no byte, a bind over a live
  listener is `AddrInUse` while the first still accepts, a bind over a dead socket file succeeds; one red each;
  `c39_uds_unit` re-pinned from 5.

**Documents and scripts.**
- F1 adr: `delivery_point_report.md` §6.27 rewritten — S8 run11 pass; S9 prep16 25/25 and agent1 39/39 on the
  2026-10-08 tree; chain 2026-10-08 3 red (fix 8); chain #2 2026-10-12 red on one test (this fix); DEPLOYABLE not
  claimed until the chain is green on the final tree; O-1 open.
- F15: the report lists the three declared deviations' reopening signals separately, as the R-4 table does.
- F3: the S9 gitleaks sentence states the 4 `credential_ref=` findings and that the scan is not a gate.
- F4 adr: D-C names `dr.secret.env` (review fix 6).
- F6: the S4 loadgen and S7 limits are marked closed; the consolidated heading reads L-1–L-19; the S9 paragraph counts
  the review fixes truthfully.
- F7: the `// ponytail:` markers this ADR lists for `uds.rs` (`own_uid`, the own uid cached per boot) and
  `deploy_check.rs` (`release_check`, one container per image in series) are added to the code.
- F8 / ISO-16: the deploy_check module invariant says what the code does — a missing check input is an exit-2 usage
  error naming the flag (fail-closed, D-R review fix 1); the receipt has no `not_applicable` state.
- LENS-4: rustdoc on the items that became public API of the `humaux-maintenance` lib (`member::run`, the manifest
  types) and `maintenance::main` in lib.rs Called-by.
- OP-11: the Dockerfile's loadgen comment no longer calls the BURST-W hook an open `sh -c` follow-up (`xtask load
  --restart … =file:`, review fix 1); one `# ponytail:` line says the `sh -c` fallback is unreachable in that image.
- OP-1: the runbook's PG-lost / rollback prose says `restore pitr` refusal 3 sees only the dr project's own pg (review
  fix 7); RB2's `down` of the previous project is the guard against a second cluster on the stanza.
- PR #2 (2026-10-13), third round — Codex (P1: every process image must be in the manifest —
  `manifest_image_missing:<t>` / `manifest_image_unknown:<t>`, `loadgen` optional; P1: the A5 release check passes
  `--checkout-tree`; P2: `cargo xtask rls-check` adds `--spec` / `--dsn` defaults only when absent) and two
  owner-account comments (the probe's timeout arm is tested with an injected slow probe, not a zero budget;
  `secrets_readable_reports_names_only` is `not_applicable` under root, where DAC_OVERRIDE makes the premise false —
  CI runs this crate with sudo).
- PR #2 (2026-10-13), second round — Codex P1/P2 and six owner-account inline comments (one P1), all closed in the
  same PR: `deploy-check --release` compares the PostgreSQL image too (`PGIMAGE` line: `manifest_pgimage_missing`,
  `pg_image_missing`, `pg_image_id_mismatch`, `pg_image_sha_mismatch`); `cargo xtask migrate` honours an explicit
  `--migrations-dir`; `dr` gains `CAP_DAC_OVERRIDE` (L-14) so the evidence files can be created in the operator's
  0700 directory on Linux; RB4 re-renders the observability configs with the previous release's sha before `up`;
  `build.sh` pins the builder to `--platform linux/arm64` and refuses a binary whose ELF `e_machine` is not AArch64;
  `expected_uid_keys` reads the value the container gets (values → secrets → other env_files → `environment:`, last
  wins); the stale-socket probe in `uds::bind_guarded` is bounded (1 s; no answer = occupied, socket left in place);
  the fairness M1 safety bounds (`max_bound`, I-SLOT) are asserted before the provider-capacity skip. Rehearsal-only:
  the `alert-sink` probe (uid 10199) writes the same evidence directory — on a Linux node that needs a group-writable
  evidence dir; it is not a production service (declared with L-14's reopening signal).
- PR #2 (2026-10-13) independent review (PASS, six P2) and Codex review (one P1), all closed in the same PR: the host
  crontab reads `HUMAUX_NODE_DEPLOY_DIR` from `node.env` at run time so a checkout switch moves the schedule (Codex
  P1); the ADR-0037 addendum says `unless-stopped` (P2-1); `deploy-check --release` names a malformed `IMAGE` line
  (`manifest_line_malformed:<n>`, P2-3) and `--compose-json` refuses a `humaux-*` image outside the target list
  (`unknown_humaux_image:<svc>:<target>`, P2-4); Baseline §25.3 names `bins/maintenance/src/rls_check.rs` and §78.6 lists
  it (P2-5); L-20 records the checkout-tree guard's scope (P2-6); the PR title says what the chain evidence is (P2-2).
- OP-5: `restore pitr` wrote its evidence file only after promotion (an unwritable path lost `nologin_roles`, which
  RB4 now reads); ruled to the main line's Rust window — open the file before any refusal or restore, print the
  receipt to stdout first.
- CC-3: `deploy/postgres/sizing-a5.conf` says gate `c39_pg_connect_sites` pins `DbPool::connect` call sites only; the
  arithmetic is the design's D-G table (152 counted consumers × 1.25 headroom = `max_connections` 190, D-E / D-G).
- CC-4: `build.sh` writes the `git archive` to `$STAGE.tar` and extracts it in a second step, each `|| fail` (POSIX
  sh has no pipefail; tar's status masked a failing archive).
- C39-F8-6: `docs/ops/rehearse.sh` takes the snapshot sha into a plain variable and stops at step 0 when it is empty
  (`export` swallowed snapshot.sh's status).
- F9: `a5_load_remeasure.sh` lists `$HUMAUX_SECRETS_DIR/a5-load.secret.env` as an input; absent, it prints
  `GATE a5_load_remeasure not_applicable: missing object = <path> …` and exits 0 (the A5-runner convention).

**Rejected / accepted as limits (critic verdicts).**
- ISO-1: the node replay's print-only gitleaks scan is the ruled informative check (S8 / S9 "Evidence hygiene").
- ISO-6: `--running`'s field set is the D-R contract and prod.yml is always brought up from one `-f`; the static gap
  it pointed at is CC-1 (fixed above).
- ISO-9: `c39_rehearsal_secrets.sh` is outside the repo and reads the operator's own providers.env.
- ISO-10: an interrupted A5 run leaves the runner's gateway on load overrides; the next `up` restores it and O-1
  needs a pass line.
- ISO-11: the 0777 hook dir sits under the single-operator model (L-13 / L-14); its ponytail names the ceiling.
- ISO-12: private-distill shares uid 10103 with private-rpc (D-C), so peer-cred would stop nothing; the unused mount
  is hygiene.
- ISO-13: the gitleaks arm of `c39_no_secrets_in_deploy` exits 2 `not_applicable` naming the image, never green
  unscanned; its missing red is the open E-8 item.
- ISO-14: `rsync --delete` into the dedicated staging dir is the design; the variable is operator-only.
- ISO-15: the no-API-key half is dropped; the read-only / tmpfs half is W-6, which stays open (prod.yml qdrant has
  neither; `deploy/qdrant/config.yaml`'s comment overstates it).
- OP-9: a stopped pg refuses fast and is named inside the 5 s probe timeout; supervision.md's paragraph predates the
  card (suggestion).
- OP-10: snapshot.sh's "1 = a git step failed" is a doc nit; every caller tests non-zero.
- OP-12: D-O keeps the old DSN names for xtask / rehearse.sh this release; the WARN is the signal.
- F5 (adr): fix 6's pin sentence is a dated per-stage note; the env file's pins are the authority.
- F13 (adr): `agent_notes.txt` is exceptions-only and optional; improvisation is detected from the transcript.
- F14 (adr): W-6 stays declared open; S9 did not settle it (suggestion).
- Gate F3: `c39_red_s3` fault 3 is attributable (D5 shows the family flip; the other 40 families are the pre-existing
  unimplemented set).
- Gate F5: the R-8 Read allow-list admits node files by runbook appendix A; the transcript is gitleaks-scanned and S9
  read no secret file.
- Gate F6: the final argv is pinned, the agent cannot create a script, and the exec.log hashes are executor-written.
- Gate F7: the jq export is harness-written and full mode needs every step id from an ALLOWED call (suggestion).
- Gate F9: `c39_image_build` precedes `rehearse_node_c39` in the chain and its START line logs prev / next.
- Gate F13: a rehearse run overwriting its log is covered by the ADR table as the record of each red.
- Gate F17: `c39_compose_check` twins `compose_observability` on purpose.
- C39-F8-3: `deferred` counts any Retry settle, not only a provider RETRY_WAIT; M6 isolation is asserted separately by
  `good_attempts_after_poison_phase` (suggestion).
- C39-F8-7: `distill_fairness_live`'s `!served.met && deferred > 0` → `not_applicable` is the ruled §57.1 reading.
- Folded into findings above: LENS-3 (= ISO-16 / F8), F16 adr (= CC-3), gate F14 (= C39-F8-4), gate F16 (= LENS-2 /
  ISO-17); suggestions only: LENS-5 (statvfs under a timeout leaks at most one blocking thread per run), gate F10 (the
  `version_line` Ok arm is covered by telemetry tests, `version_line_present` and `deploy-check --release`).

| test / gate | fault | red observed |
|---|---|---|
| `c39_red_fix9` #1: uds bind_guarded: directory mask 0o027 -> 0o007 (group-write accepted) | the fault named | `dir_with_group_write_refuses_bind` red, EXIT 101 |
| `c39_red_fix9` #2: uds connect_verified: drop the client-side mode & 0o007 refusal | the fault named | `connect_refuses_a_socket_with_other_bits_before_dialling` red, EXIT 101 |
| `c39_red_fix9` #3: uds bind_guarded: drop the live-server probe (always unlink) | the fault named | `bind_over_a_live_server_is_addr_in_use` red, EXIT 101 |
| `c39_red_fix9` #4: uds bind_guarded: refuse any existing file (no stale-removal arm) | the fault named | `bind_replaces_a_dead_socket_file` red, EXIT 101 |
| `c39_red_fix9` #5: uds bind_guarded: drop the directory owner comparison | the fault named | `dir_owned_by_another_uid_refuses_bind` red, EXIT 101 |
| `c39_red_fix9` #6: deploy_check security_opt: exact match back to contains | the fault named | `compose_fix9_arms_each_red` red, EXIT 101 |
| `c39_red_fix9` #7: deploy_check EnvFile::value: first occurrence wins again | the fault named | `env_file_parse_follows_compose_semantics` red, EXIT 101 |
| `c39_red_fix9` #8: deploy_check compose_reasons: drop port_reasons | the fault named | `port` red, EXIT 101 |
| `c39_red_fix9` #9: deploy_check compose_reasons: drop restart_reasons | the fault named | `restart` red, EXIT 101 |
| `c39_red_fix9` #10: deploy_check compose_reasons: drop secret_file_reasons | the fault named | `foreign` red, EXIT 101 |
| `c39_red_fix9` #11: deploy_check bind_reasons: deny-list ignored (bind_source_denied always false) | the fault named | `secrets` red, EXIT 101 |
| `c39_red_fix9` #12: deploy_check escape_reasons applied to Humaux services only (third-party pg/qdrant/prometheus unchecked) | the fault named | `third` red, EXIT 101 |
| `c39_red_fix9` #13: deploy_check checkout_tree_reasons: a manifest without a CHECKOUT line passes | the fault named | `checkout_tree_not_in_manifest` red, EXIT 101 |
| `c39_red_fix9` #14: deploy_check checks(): drop the flag-without-value guard | the fault named | `checks_refuse_a_flag_without_value` red, EXIT 101 |
| `c39_red_fix9` #15: deploy_check running_reasons: drop the RestartPolicy arm | the fault named | `running_fix9_arms_each_red` red, EXIT 101 |
| `c39_red_fix9` #16: deploy_check running_reasons: port bindings on every interface accepted | the fault named | `running` red, EXIT 101 |
| `c39_red_fix9` #17: drill evidence_arg: the write probe never fails (is_dir-only era) | the fault named | `drill_and_pitr_refuse_an_evidence_path` red, EXIT 101 |
| `c39_red_fix9` #18 (live MiniMax, C39-F8-4): poison-live phase-B accounting given one unexplained attempt (`explained + 1`) | the identity mutated | `distill_poison_live` red on a live green run (37 s), EXIT 101; unmutated green again (27 s) |
| `c39_red_fix9` #19 (`drill.rs` `locked_roles_sql`, agent3 RB5 finding): list `NOT rolcanlogin` (the post-quarantine reading) | the query mutated | `locked_roles_sql_selects_login_roles_outside_keep` red, EXIT 101 |
| `c39_red_fix9` #20 (`deploy_check.rs` `malformed_image_lines`, PR #2 review P2-3): a malformed `IMAGE` line dropped silently again | the filter mutated | `malformed_manifest_lines_and_unknown_humaux_images_are_red` red, EXIT 101 |
| `c39_red_fix9` #21 (`deploy_check.rs` `unknown_humaux_image`, PR #2 review P2-4): the call dropped | the arm dropped | same test red, EXIT 101 |
| `c39_red_fix9` #22 (`deploy_check.rs` `pg_image_reasons`, PR #2 Codex P1): the id comparison skipped | the arm dropped | `pg_image_reasons_each_named` red, EXIT 101 |
| `c39_red_fix9` #23 (`pg_image_reasons`): a manifest without a `PGIMAGE` line accepted | the arm mutated | same test red, EXIT 101 |
| `c39_red_fix9` #24 (`xtask/src/migrate.rs`, PR #2 Codex P2): the dev `--migrations-dir` default inserted ahead of an explicit one | the shaping mutated | `explicit_migrations_dir_is_not_shadowed_by_the_default` red, EXIT 101 |
| `c39_red_fix9` #25 (`deploy_check.rs` `uid_key_reasons`, PR #2 review): first source wins again | `.next_back()` → `.next()` | `compose_peer_uid_keys_mismatch_is_red` red, EXIT 101 |
| `c39_red_fix9` #26 (`uds.rs` `probe_with`, PR #2 review): the timeout arm dropped (no answer in time read as Dead) | the `Err(_)` arm mutated | `stale_probe_is_bounded` red (deterministic: an injected probe that overruns a 50 ms budget), EXIT 101 |
| `c39_red_fix9` #27 (`derived_dispatch_e2e.rs` M1, PR #2 review): safety bounds moved back behind the capacity skip — recorded by reading only: the live test needs MiniMax and a capacity-starved round to differ; the reorder is a pure statement move | — | not run (named here, not claimed) |
| `c39_red_fix9` #27 (`deploy_check.rs` `manifest_target_reasons`, PR #2 Codex P1 round 3): a missing process image accepted | the filter mutated | `manifest_target_reasons_each_named` red, EXIT 101 |
| `c39_red_fix9` #28 (`xtask/src/rls_check.rs`, PR #2 Codex P2): the `--spec` default always prepended | the guard dropped | `explicit_flags_are_not_shadowed_by_the_defaults` red, EXIT 101 |
| `c39_red_fix9` #29 (`deploy_check.rs` `rehearsal_probe`, PR #2 Codex P2 round 4): exempt by the rehearsal profile alone | the allow-list bypassed | `compose_identity_uid_rules` red (case `unlisted rehearsal helper`), EXIT 101 |
| `c39_red_fix9` #30 (`deploy_check.rs` `release_reasons`, PR #2 Codex P1 round 4): version comparisons judged before the identity holds | `None` read as an empty line | `release_identity_is_judged_before_the_version_run` red, EXIT 101 |
| `c39_red_fix9` #31 (`rls_check.rs` `flag_without_value`, PR #2 owner review P2): a bare `--spec` / `--dsn` read as absent | the guard disabled | `value_flags_without_a_value_are_usage_errors` red, EXIT 101 |
| `c39_red_fix9` #32 (`migrate.rs` `run`, PR #2 Codex P1 round 5): a bare `--migrations-dir` / `--dsn` / `--through` read as absent | the guard filtered out | `bare_value_flags_are_usage_errors_before_any_default` red (exit 1, not 2: the embedded set and a connect attempt), EXIT 101 |
| `c39_red_fix9` #33 (`migrate.rs`, gate-reviewer round 5 P2): the guard filtered out, against the strengthened test (each case discriminates, all judged before the assert) | the guard filtered out | `bare_value_flags_are_usage_errors_before_any_default` red naming all four cases (exit 1 each), EXIT 101 |
| `c39_red_fix9` #34 (`deploy_check.rs` `EnvFile::parse`, PR #2 Codex P2 round 7): values kept as raw text | `compose_value` bypassed | `env_file_values_follow_compose_quoting` red, EXIT 101 |
| `c39_red_fix9` #35 (`deploy_check.rs` `running_reasons`, PR #2 Codex P2 round 7): third-party residents skipped | the resident filter made empty | `running_checks_third_party_residents` red, EXIT 101 |
| `c39_red_fix9` #36 (`budget_sums.sh` drill arm, PR #2 Codex P1 round 8): a copy of `sizing-a5.env` whose drill PostgreSQL cap is 4g (the pre-round-8 A5 numbers were red the same way, reserve 1392 MiB) | the input | `budget: fail — reserve 1392 MiB < 4096 MiB`, EXIT 1; the real file passes (reserve 4464) |
| `c39_red_fix9` #37 (`deploy_check.rs` `secret_file_reasons`, PR #2 Codex P1 round 8): own values / secret files not required | the new arm skipped | `compose_fix9_arms_each_red` red (case `own secret file dropped`), EXIT 101 |
| `c39_red_fix9` #38 (`serve.rs` `df_free_bytes`, PR #2 Codex P2 round 8): the in-flight guard dropped | the guard made always-true | `statvfs_keeps_one_read_in_flight_per_path` red, EXIT 101 |
| `c39_red_fix9` #39 (`deploy_check.rs` `pg_service_image_reasons`, PR #2 Codex P1 round 9): the pg image not compared | the call dropped | `compose_fix9_arms_each_red` red (case `pg on an upstream image`), EXIT 101 |
| `c39_red_fix9` #40 (`deploy_check.rs` `secret_key_foreign_reasons`, PR #2 Codex P1 round 9): only the key's expected home examined | the reason never pushed | `secret_key_in_a_foreign_file_is_red` red, EXIT 101 |
| `c39_red_fix9` #41 (`deploy_check.rs` `service_target_reasons`, card 39b / PR #2 Codex round 10): a service on another valid target accepted | the mismatch arm disabled | `compose_fix9_arms_each_red` red (case `dr on the ops image`), EXIT 101 |
| `c39_red_fix9` #42 (`deploy_check.rs` `uid_key_reasons`, card 39b / Codex round 10): any mode's compose source taken for every mode | the per-service filter widened | `compose_peer_uid_keys_mismatch_is_red` red, EXIT 101 |
| `c39_red_fix9` #43 (`deploy_check.rs` `judge_image`, card 39b / gate-reviewer round 4 P2-1): the entrypoint run before the identity verdict | the runner called first | `judge_image_runs_the_entrypoint_only_on_a_verified_image` red, EXIT 101 (a first attempt that did not compile was removed from the log and re-run) |
| `c39_red_fix9` #44 (`deploy_check.rs` `rehearsal_probe`, card 39b / round 4 P2-3): named `group_add` entries ignored | the numeric clause widened | `rehearsal_probe_clauses_each_hold` red, EXIT 101 |
| `c39_red_fix9` #45 (`migrate.rs` `flag_without_value`, card 39b): the `--flag=value` form read as absent | the `=` arm disabled | `value_flags_without_a_value_are_usage_errors` red, EXIT 101 |
| `c39_red_fix9` #46 (`budget_sums.sh`, card 39b / round 8 P2-3): a drill cap of `0g` (no cap) | the input | `budget: fail — … missing, zero, or not <n>g / <n>m`, EXIT 1; the real file passes |
| `c39_red_fix9` #47 (runbook U4, card 39b / round 8b P2): a service list naming only `gateway-old` | the input (stubbed compose / docker, `/bin/sh -eu`) | `refusing to remove anything`, EXIT 1; a list naming `gateway` passes |
| `c39_red_fix9` #48 (`deploy_check.rs` `service_target_reasons`, PR #4 independent review W1): a listed service missing accepted | the arm emptied | `compose_fix9_arms_each_red` red (case `a listed service removed`), EXIT 101 |
| `c39_red_fix9` #49 (same, W1): an unlisted service on a process image accepted | the arm disabled | same test red (case `an unlisted service on a process image`), EXIT 101 |
| `c39_red_fix9` #50 (`deploy_check.rs` `flag_without_value`, W3): `--compose-json=F` beside another check dropped silently | the `=` arm disabled | `checks_refuse_a_flag_without_value_and_an_empty_selection` red, EXIT 101 |
| `c39_red_fix9_gates` (26 fixture-tree faults, one per changed gate: exact red-record pins, `c39_one_uds_site.sh` allow-list and alias forms, the builder-toolchain gate stub) | each gate's own fault on a $TMPDIR copy | 26 red EXIT lines, green restore after each |
| `c39_red_s8` #1 (`c39_build_images.sh`, build and docker stubbed to chain #2's manifests) | one IMAGE line dropped from manifest 1 (image_lines check) | `CHECK image_lines 7+8 != 8+8` → RESULT fail, EXIT 1 |
| `c39_red_s8` #2 (`c39_build_images.sh`, build and docker stubbed to chain #2's manifests) | manifest 2 carries manifest 1's gateway image id (ids_disjoint check) | `CHECK image_lines 16` → RESULT fail, EXIT 1 |
| `c39_red_s8` #3 (`c39_build_images.sh`, build and docker stubbed to chain #2's manifests) | humaux-admin version answers another git_sha (admin_version_sha check) | `CHECK image_lines 16` → RESULT fail, EXIT 1 |

**PR #2 round 4 (2026-10-13, Codex on 2a18379).** (1) `deploy-check --release` runs an image's `--version` only
after its id and revision label match the manifest, by the inspected immutable id (`--pull never`, no network,
read-only root, `--cap-drop ALL`, `no-new-privileges`, the image's own non-root `USER`, 128 MiB / 32 pids / 1 cpu), and removes a run that
has not answered in 30 s by name (`image_version_timeout:<target>`); a stale or retargeted tag is now named by
`image_id_mismatch` / `image_sha_mismatch` alone and its entrypoint never runs (the S9 rehearsal's RB1 fault (a)
now expects `image_id_mismatch:gateway` for its second reason too). (2) The rehearsal exemption from the uid and pair rules is
an allow-list of the five probes by name with their exact `user` and gids (`REHEARSAL_PROBES`); the profile alone
exempts nothing. (3) Runbook: the pre-upgrade backup moves to U2, before the next release's checkout or images are
used, and first proves the executor's checkout is the running release's (`deploy-check --release PREV_TAG
--checkout-tree`); the precheck on the next release is U3, and a checkout switch continues from U3. (4) V3's
cross-tenant negative check counts only on a successful tool result (`curl --fail`, a `"result"` without
`"isError":true`). (5) A2–A4 search only the alert receipts written after the step began (byte offset taken before
the action), so a retry cannot pass on an earlier run's Watchdog / firing / resolved lines. Runbook step blocks
changed: V3, A2, A3, A4, U2, U3 (S9 agent-run evidence predates them, as with review fix 9). (6) `rls-check` refuses
`--spec` / `--dsn` without a value (last, empty, or another `--flag` next) with exit 2 before any check, so a bare
`cargo xtask rls-check --spec` no longer suppresses the Baseline default and exits 0 on `not_applicable`.

**PR #2 round 5 (2026-10-13, Codex on 1a5a039).** (1) The release verifier is checked before it runs: R2, U2, U3
and RB1 compare `humaux-dr:<tag>`'s image id with the manifest's `dr` line from the host (`docker image inspect`)
before `run dr deploy-check --release`, which would otherwise start an unverified root image holding the docker
socket. (2) RB2 is `down --remove-orphans` and ends only when no container carries the project label (a service the
upgraded release added is not in the previous `prod.yml`). (3) `migrate` refuses a bare `--dsn` / `--migrations-dir`
/ `--through` (exit 2) before the embedded set or the environment DSN can stand in; the guard
(`migrate::flag_without_value`) is shared with `rls-check`. (4) `alert-sink` writes to its own
`$HUMAUX_NODE_EVIDENCE_DIR/alerts` (P2: mode 1733), not the operator's 0700 evidence dir it cannot write as uid
10199 without capabilities; A2–A4 read `alerts/alert_receipts.jsonl`; the fixture's bind source follows. Runbook
blocks changed: P2, R2, U2, U3, RB1, RB2, A2, A3, A4. Gate-reviewer on 5ce5814 (FAIL, one P1): RB1 ran `dr` under
`node.env`'s tag, which U7 had already switched to the next release, so the host check inspected `humaux-dr:PREV` while
`humaux-dr:NEXT` ran; RB1 now exports `HUMAUX_IMAGE_TAG=$PREV_TAG` before the check (the previous release's verifier,
under its own checkout). The four host checks name an image that is not loaded as `<not loaded>`; the bare-flag test's
second case now discriminates without the guard and all cases are judged before the assert (red #33).

**PR #2 round 7 (2026-10-13, Codex on bea2f5f).** (1) `deploy-check --env` reads env_file values the way Compose
does: `'…'` literal, `"…"` and unquoted values lose their quotes, so `KEY=""` is empty (`secret_empty` fires); a value
that would need Compose's interpolation, escapes or inline-comment strip (`$`, `\`, a stray quote, ` #`) is
`value_unreadable:<file>:<key>` instead of passing as non-empty text. (2) `deploy-check --running` also requires every
third-party resident without a profile (`restart: unless-stopped`: pg, qdrant, netns, prometheus, alertmanager,
otel-collector) to be running, not restarted, and healthy where the container has a healthcheck. (3) Upgrade: U4 removes
every project container whose service the next `prod.yml` no longer defines, and U7's `up` passes `--remove-orphans`.
(4) Rollback: RB3 records its target in `evidence/rb3.target` before `node.env` changes and removes it only after a
restore, so a retry re-uses `<project>-rb1`, removes the partial target (`down -v`, a copy of the backup) and restores
again; a target whose evidence already says `restored` STOPs ("continue at RB4"). (5) `migrate.rs`'s `Called-by`
gains `tests` (dep-map red since 5ce5814: rls_check's tests call `migrate::flag_without_value`). Runbook blocks
changed: U4, U7, RB3.

**PR #2 round 8 (2026-10-13, Codex on d19f5ce).** (1) `deploy-check --compose-json` also requires every Humaux
service to load its OWN files: the values file of its binary (`values_file_missing:<svc>:values/<p>.env`) and its
secret file(s) (`secret_file_missing:<svc>:<f>.secret.env`; `migrate` → `migrate`, `dr` → `dr` + `pg`), since the
presence check reads `--secrets-dir`, not what a service loads. (2) `budget_sums.sh` counts the restore drill's
`HUMAUX_DRILL_*_MEM_LIMIT` (it runs beside production); the A5 numbers were red (reserve 1392 MiB at the 22 GiB floor),
so 1.5 GiB of PostgreSQL's in-cgroup page cache moves to the drill: `HUMAUX_SIZE_PG_MEM` 8704 → 7168 MiB
(`effective_cache_size` 6 → 5 GB; shared_buffers and the ~4.7 GiB working set unchanged), drill caps 2g / 1g → 1g /
512m; reserve 4464 MiB again. These stay dev-host start values under L-1 / O-1. (3) `serve.rs` keeps at most one
`statvfs` read in flight per DR path, so a hung mount pins one blocking thread, not one per cycle (ponytail: a
killable helper if that ever matters). (4) `build.sh` recreates `$OUT/env-example` before copying, so a removed
example cannot survive into the ops / dr images. Gate-reviewer on eac06b6 (PASS) P2s fixed in the same round: U4 takes
`config --services` as its own command (a failure stops the step; a list without `gateway` refuses to remove
anything) instead of inside a pipeline, whose hidden failure removed every project container including pg and
qdrant; RB3's first run sets an earlier rollback's `rollback-1.json` aside (timestamped), so a retry after a refused
restore is never told "already restored". Both exercised on stubs (U4: config ok → only the orphan removed, config
failing → exit 1, nothing removed; RB3: stale evidence + refused first run → the retry restores).

**PR #2 round 9 (2026-10-13, Codex on a2b75a4).** (1) `--compose-json`: the `pg` service runs exactly
`humaux-pg:<tag>` with the one tag every process image carries (`pg_image_unverified:<image>`), so an upstream or
another release's PostgreSQL image cannot start while `--release` verifies an unused `humaux-pg:<tag>`. (2) `--env`:
a key some example declares may sit only in a secret file whose process holds it (its own example declares it; `dr`
holds the maintenance example's keys; `migrate` its DSN and the role passwords): `secret_key_foreign:<file>:<key>`
even when the key's own home is set. (3) RB3 writes `evidence/rb3.done` after a restore and U1 clears it; a rerun of a
completed RB3 STOPs ("continue at RB4") instead of deriving `<project>-rb1-rb1` beside the promoted cluster. (4) RB4
starts only pg, qdrant and the projector `retrieval-serve`; RB5 brings up the gateway and every other service only
after `projection rebuild --all`. Not changed: the checkout-content finding (the executor trusts the shipped
`CHECKOUT_TREE` marker) is the declared limit L-20. Runbook blocks changed: U1, RB3, RB4, RB5.

**Card 39b (2026-10-13, after PR #2 merged): the card-39 follow-up backlog.** Codex round 10 on 9e420bd: (1)
`--compose-json` binds every Humaux service to its release target (`SERVICE_TARGETS`; `image_target_mismatch:<svc>:<t>`,
`service_missing:<svc>`, `image_target_unexpected:<svc>`) — `dr` on `humaux-ops` (no docker CLI) passed before; (2)
`expected_uid_keys` judges the value EACH mode of a binary receives (process-wide files plus that service's own compose
sources), so a pair-uid key set on `retrieval-serve` alone no longer satisfies `retrieval-rpc`. Presence of other keys
stays per binary (a ponytail names it): `dr`'s backup / drill keys sit on `dr` only and no other maintenance mode reads
them, so a per-mode rule needs per-mode consumption lists first. (3) `a5_load_remeasure.sh`'s EXIT trap also puts the
gateway back on prod.yml (an interrupted run left the 1 ms BURST-W admission wait deployed); the BURST-W listener is
stopped through a stop file and waited for, never killed, so a recreate it has already started finishes before the
restore (PR #4 Codex P2: a killed subshell orphaned its compose child, which could recreate the 1 ms gateway after it);
HUP joins TERM / INT in the `exit 143` trap (dash runs no EXIT trap on SIGHUP: a dropped ssh session skipped the
restore — PR #4 independent review W2, measured by the reviewer). `deploy-check` itself refuses `--flag=value` as
`migrate` / `rls-check` do (W3); `service_missing` / `image_target_unexpected` have their own cases (W1). Deferred P2s closed:
`judge_image` makes "the entrypoint runs only on a verified image" testable; each `REHEARSAL_PROBES` clause has its own
case and named `group_add` entries are refused; `version_of` names its container with pid + nanos and reports a failed
removal; the `--flag=value` form is a usage error in `migrate` / `rls-check`; a `0g` drill cap fails the budget; U4
matches `gateway` exactly; stale text (the dr USER wording, the alert-sink exemption doc, the U/RB step order above).

## Tests (S7; one fault each, reds in `c39_red_s7.log`)

| test / gate | fault | red observed |
|---|---|---|
| gate `c39_runbook_steps` | a live `docker ps` line appended to a copy of `deploy_rehearsal.sh` (outside the extractor / executor) | count 1 ≠ 0, EXIT 1 |
| gate `c39_runbook_steps` | a ```` ```bash ```` block with `docker compose logs gateway` in a runbook copy | `LINT invocation outside an executor block`, EXIT 1 |
| gate `c39_runbook_steps` | the same command as an inline code span in prose | `LINT invocation outside an executor block`, EXIT 1 |
| gate `c39_runbook_steps` | a step marker before a non-`sh` block | `LINT marker before a non-sh block: Z9` (and `--list` ≠ markers), EXIT 1 |
| gate `c39_runbook_steps` | step V3 deleted | `lint pass (38 steps)`, 38 ≠ 39, EXIT 1 |
| `c39_steplog_check.sh --classify` | the 6-line R-8 sample | `CALL 3 Bash IMPROVISED … logs gateway`, `CALL 4 Read IMPROVISED …/main.rs`, `improvised=2 RESULT fail`, EXIT 1 |
| `c39_steplog_check.sh` | a real executor run with S2 never run | `EXEC ids_mismatch`, `EXEC S2 missing`, `TRANSCRIPT S2 never run`, EXIT 1 |
| `c39_steplog_check.sh` | a clean run's transcript plus the sample's improvised call | `improvised=1 RESULT fail`, EXIT 1 |
| `c39_steplog_check.sh` | S2's block edited in the runbook after the run | `EXEC S2 block_hash_mismatch`, EXIT 1 |
| `c39_steplog_check.sh` | S2 run with `--fault-path-extra $HOME/.cargo/bin` (real executor refusal) | `EXEC S2 notoolchain_not_ok`, `result_not_ok`, EXIT 1 |
| `c39_steplog_check.sh` | `agent_notes.txt` with one `IMPROVISED` line | `NOTES improvised=1`, EXIT 1 |
| `c39_steplog_check.sh` | no `agent_calls.jsonl` | `not_applicable: missing object = agent transcript export (E-11)`, EXIT 2 (not green) |
| gate `c39_steplog_classifier` | a checker copy whose Bash rule allows every command | 0 ≠ 2 IMPROVISED, EXIT 1 |
| gate `c39_docs` | ADR copy without the O-1 section; without the D-B heading | EXIT 1 each |
| gate `c39_cheap_agent_log` | before S9 (no evidence dir) | `not_applicable: missing object = rehearsal evidence dir …`, EXIT 2 (not green) |

Green controls in the same run: the unmutated gate lines EXIT 0; a real three-step executor run with an all-allowed
transcript → `steps=3 improvised=0 notes_improvised=0 RESULT pass`. Gates (before `release_build`):
`c39_runbook_steps`, `c39_steplog_classifier`, `c39_cheap_agent_log` (S9), `c39_lane_under_supervisor`,
`c39_runner_scripts_parse`, `c39_docs`, `c39_red_s7`, `c39_image_build` (S8; `TW/c39_build_images.sh`); then
`release_build`, `rehearse_c39`, `rehearse_node_c39` (S9; its script `TW/c39_rehearse_node.sh` is written with S9).

## Tests (S6; one fault each, reds in `c39_red_s6.log`)

| test / gate | fault | red observed |
|---|---|---|
| `maintenance --lib deploy_check::tests::compose_resolved_env_input_is_refused` | `*_FILE` exemption removed | `left: Some("resolved_env_input:pg:POSTGRES_PASSWORD_FILE") right: None` |
| `deploy_rehearsal.sh run` | `--fault-path-extra $HOME/.cargo/bin` | `NOTOOLCHAIN FAIL`, step refused, EXIT 3 |
| `deploy_rehearsal.sh --lint` | a fenced `sh` block without a marker | `LINT sh block without a step marker`, EXIT 1 |
| `deploy_rehearsal.sh run` | output lacks the step's `match:` | `RESULT mismatch`, EXIT 1 |
| `a5_load_remeasure.sh` (replay) | facts = A5, no LOAD line | `FAIL: no_a5_load_line:L8 …`, EXIT 1 |
| `a5_load_remeasure.sh` (replay) | facts = A5, LOAD lines `host=10cpu-vm3.8` | `FAIL: no_a5_load_line:…`, EXIT 1 |
| `a5_load_remeasure.sh` (replay) | L16 enumerate p95 300 ms | `SIGNAL L16 reopen` (gate pass, O-1 open) |
| `a5_load_remeasure.sh` | MemTotal 21 GiB | `not_applicable`, exit 0 |
| `TW/c39_version_lines.sh` (`version_line_present`) | the six resident start lines of a build without `HUMAUX_BUILD_GIT_SHA` | `ASSERTION FAIL … git_sha=missing`, EXIT 1 |
| gate `c39_compose_config` | a `:?` variable deleted from node.env.example; a secret-fixture file removed | EXIT 1 each |
| gate `c39_deploy_check_live` | `user:` removed (card fault); `ALLOW_SAME_UID=1` in a values copy; `migrate.secret.env` on `ops` | `user_missing:maintenance-serve` / `dev_only_key_set:…` / `migrator_dsn_service:ops`, EXIT 3 each |
| gate `c39_budget_sums` | pg 9216; `--mem-total-mib 22000`; a literal `mem_limit`; unequal key sets | EXIT 1 each |
| gate `c39_no_secrets_in_deploy` | a password DSN in a prod.yml copy; the same in the S4 fixture copy | EXIT 1 each |
| gate `c39_render_portable` | the old `python3` renderer line pasted | EXIT 1 |
| gate `c39_bundle_scripts_parse` | an eighth, unparsable script | EXIT 1 |
| gate `c39_values_no_dev_only` | the allow key in `values/private-worker.env` | EXIT 1 |
| gate `c39_digest_lines_dated` | a pin line without its date | EXIT 1 |
| gate `c39_compose_check` | a tag-only bundle image (qdrant) | `qdrant: image is not name:tag@sha256:<digest>`, EXIT 1 |

Gates (before `release_build`): `c39_compose_config`, `c39_compose_check`, `c39_deploy_check_live`,
`c39_budget_sums`, `c39_no_secrets_in_deploy`, `c39_render_portable`, `c39_bundle_scripts_parse`,
`c39_values_no_dev_only`, `c39_digest_lines_dated`, `a5_load_remeasure`, `c39_red_s6`; `compose_observability` now
checks prod.yml; `rehearse_c39` also greps `version_line_present` (graded by `c39_rehearse.sh` after the run).

## Tests (S5; one fault each, reds in `c39_red_s5.log`)

| test | fault | red observed |
|---|---|---|
| `xtask dep_map::tests::example_lists_runtime_keys_of_the_process_only` | `HUMAUX_TEST_*` filter removed | `left: [… "HUMAUX_TEST_PG_DSN="] right: ["HUMAUX_GATEWAY_BIND_ADDR=", "HUMAUX_GATEWAY_PG_DSN="]` |
| `dep_map::tests::example_excludes_dev_only_keys` | `DEV_ONLY_KEYS` filter dropped | `left: ["HUMAUX_PRIVATE_WORKER_ALLOW_SAME_UID=", …] right: ["HUMAUX_PRIVATE_WORKER_PG_DSN="]` |
| `dep_map::tests::secret_fixture_has_empty_values_only` | the fixture writer emits a value | ``HUMAUX_GATEWAY_PG_DSN=changeme` is not `KEY=`` |
| gate `c39_env_examples_generated` | a value in `secret-fixture/gateway.secret.env` | EXIT 1 |
| gate `c39_env_examples_generated` | `HUMAUX_PRIVATE_WORKER_ALLOW_SAME_UID=` added to `example/private-worker.env` | EXIT 1 |
| inherited gate `dep_map` | `example/gateway.env` hand-edited | `deploy/env/example/gateway.env:19: [doc-drift]`, EXIT 1 |

Gates (before `release_build`): `c39_env_examples_unit` (the three tests, count = 3), `c39_env_examples_generated`,
`c39_red_s5`.

## Tests (S4; one fault each, reds in `c39_red_s4.log`)

| test | fault | red observed |
|---|---|---|
| `maintenance --lib migrate::tests::live_runtime_session_refuses` (DB) | skip the `pg_stat_activity` query | `left: [] right: ["role_gateway=1"]` |
| `migrate::tests::live_session_in_another_database_is_ignored` (DB) | drop the `datname = current_database()` filter | `left: 3 right: 0` |
| `migrate::tests::embedded_set_equals_the_migrations_directory` | `build.rs` embeds no manifests | the embedded side carries `None` manifests |
| `deploy_check::tests::compose_service_without_user_is_red` (card fault) | drop the `user_missing` arm | `left: [] right: ["user_missing:maintenance-serve"]` |
| `deploy_check::tests::compose_peer_uid_keys_mismatch_is_red` | compare each key against its own service | all four keys red on the green fixture |
| `deploy_check::tests::compose_resolved_env_input_is_refused` | skip the guard | the inlined DSN is not refused |
| `deploy_check::tests::compose_migrator_env_file_on_two_services_is_red` | skip the env_file scan | `left: [] right: ["migrator_dsn_service:ops"]` |
| `deploy_check::tests::env_dev_only_key_set_is_red` | drop the DEV_ONLY check | `left: [] right: ["dev_only_key_set:…ALLOW_SAME_UID:values/private-worker.env"]` |
| `deploy_check::tests::env_migrator_dsn_outside_migrate_is_red` | accept the key in any `*.secret.env` | `left: [] right: ["migrator_dsn_misplaced:secrets/maintenance.secret.env"]` |
| `deploy_check::tests::env_key_missing_is_red` | an empty value counts as present | `key_missing:gateway:HUMAUX_B` missing |
| `deploy_check::tests::release_checks_each_comparison_is_load_bearing` (card fault: corrupt tag) | drop comparison (1), (2), (3), (4) in turn — four runs | each run: `left: [] right: ["image_id_mismatch:ops"]` / `["image_sha_mismatch:ops"]` / `["image_binary_mismatch:ops"]` / `["version_sha_mismatch:ops"]` |
| `deploy_check::tests::running_dev_only_env_is_red` | skip the `Config.Env` scan | `left: [] right: ["dev_only_key_set:…:gateway"]` |
| `deploy_check::tests::secrets_readable_reports_names_only` | report every file | the readable file is reported too |
| `maintenance --bin drill::tests::pitr_target_backup_is_type_immediate` | `--target-backup` falls back to `--type=time` | `--target=` present |
| `drill::tests::target_backup_and_time_are_exclusive` | `--target-backup` wins over the others | the pair is accepted |
| `xtask load::tests::host_class_prefixes_the_label` | ignore the class | `left: "10cpu-vm22.0" right: "a5-10cpu-vm22.0"` |
| `xtask load::tests::meminfo_path_is_read_without_docker` | ignore `--meminfo-path` | no source without `--pg-container` |
| gate `c39_pg_connect_sites` (`TW/c39_pg_connect_sites.sh`, pins of D-G) | one extra live connect in a copy of retrieval-worker `main.rs` | `connect_sites bins/retrieval-worker/src/main.rs expected=4 actual=5` |
| gate `c39_loadgen_no_repo_reads` | one live `read_to_string` of a repository file added to `e2e_seed.rs` | count 2 ≠ 1 |

Gates (before `release_build`): `c39_pg_connect_sites`, `c39_migrate_live_sessions`, `c39_migrate_embedded`,
`c39_pitr_target_backup`, `c39_deploy_check_compose` (exactly 10 `deploy_check::tests … ok`),
`c39_deploy_check_release`, `c39_load_flags`, `c39_loadgen_no_repo_reads`, `c39_red_s4`.
Pinned connect sites (live non-test `DbPool::connect(` / `connect_with(` lines, `#[cfg(test)] mod` blocks excluded;
total 29): admin `mechanism.rs` 1, `probe.rs` 1; consolidation `main.rs` 3; gateway `bootstrap.rs` 1; maintenance
`drill.rs` 4, `health_serve.rs` 1, `main.rs` 1, `member.rs` 1, `projection_serve.rs` 1, `rebuild_cli.rs` 1,
`roles.rs` 2, `serve.rs` 2; private `main.rs` 3; public `main.rs` 2; retrieval `main.rs` 4, `rpc.rs` 1. The probe
and one-shot connects are counted per site, not per pool; D-G's `max_connections` arithmetic is by process.

## Tests (S3; one fault each, reds in `c39_red_s3.log`)

| test | fault | red observed |
|---|---|---|
| `private-worker --lib distill::tests::transport_retry_with_pins_counts_dns_pin_deferred` + twin `no_pins_no_count` | count a TRANSPORT retry without the pin condition | `no_pins_no_count`: `left: 2 right: 1` |
| promtool `DnsPinDeferred` (fire block + "outputs grow ⇒ silent" block; mutation row `dns_pin_and`) | drop the `and increase(private_distill_outputs_total[30m]) == 0` clause | `alertname: DnsPinDeferred, time: 45m` (the silent block fires) |
| Witness `crates/testkit/tests/metrics/dns_pin_deferred_total.rs` (G80-6, run by `cargo xtask metrics-registry`) | remove the emit (`count_dns_pin_deferred` no longer increments) | D1 / D2 / D5 fail naming `dns_pin_deferred_total` (`=1/0`) |

Gates: `c39_dns_pin_counter` (the two named tests, exactly one live RETRY-arm call, exactly one live production
caller of `count_dns_pin_deferred()`, the witness header), `c39_dns_pin_rule` (test-rules green, one live
`DnsPinDeferred` rule, its three `alertname` checks, the mutation row), `promtool_mutations` now `red=34/34`,
`c34b_metrics_registry` now `private-worker=4`.

## Tests (S2; one fault each, reds in `c39_red_s2.log`)

| test | fault |
|---|---|
| `private-worker --test exit_codes::no_args_exits_2_with_usage` (+ consolidation, retrieval, maintenance, admin twins) | restore the argument-less arm (exit 0) |
| `gateway --test exit_codes::unknown_arg_exits_2` (+ the five twins) | ignore an unknown argument (exit 0) |
| `gateway --test exit_codes::readyz_probe_exit_code` (+ maintenance `readyz serve|health-serve`) | exit 0 on any status line |
| `telemetry tests::probe_http_maps_503_to_2` | the same |
| `telemetry tests::version_line_names_sha`, `tests::version_without_sha_exits_2` | answer without a sha |
| `<bin> --test exit_codes::version_mode_matches_the_burned_in_sha` (six bins) | exit 0 without a sha |
| `<bin> --test exit_codes::resident_start_line_comes_first` (five resident bins) | start line after the configuration / missing |
| `private-worker --lib dsn::tests::{new_name_wins,old_name_warns,both_different_refuse}` (+ consolidation twin) | old name wins / WARN dropped / disagreement accepted |
| `xtask dep_map::tests::env_alias_key_is_declared_and_rendered_deprecated_alias` | render arm dropped |

## Tests (S1; one fault each, reds in `c39_red_s1.log`)

| test | fault | red observed |
|---|---|---|
| `infra-cell uds::tests::own_uid_matches_a_created_files_owner` | `own_uid` returns 0 | `left: 0 right: 501` |
| `uds::tests::dir_with_other_bits_refuses_bind` | drop the directory mode check | the bind succeeded in a 0755 dir |
| `uds::tests::bound_socket_is_0660` | skip the explicit chmod | the re-check refused mode 0755 |
| `uds::tests::connect_refuses_unexpected_server_uid_before_writing` | skip the peer-uid comparison | the dial succeeded |
| `uds::tests::allow_value_other_than_1_refuses` | accept any non-empty allow value | `true` was accepted |
| `retrieval-worker --test same_uid_boot::same_uid_expected_gateway_refuses_boot_without_allow` | drop the `server_policy` call | exit 2 on the next missing key, no refusal line |
| `retrieval-worker --test same_uid_boot::same_uid_with_allow_boots_and_warns_on_accept` | drop the accept-time WARN | `same-uid peer accepted` missing |
| `private-worker --test same_uid_boot::same_uid_expected_consolidation_refuses_boot_without_allow` | drop the `server_policy` call | exit 2 on `PRIVATE_WORKER_PG_DSN`, no refusal line |
| `private-worker --test same_uid_boot::same_uid_with_allow_boots_and_warns_on_accept` | plain uid compare instead of `admit_peer` | `same-uid peer accepted` missing |
| `gateway --lib retrieval_embedding_client::tests::wrong_server_uid_is_transport_without_a_request` | dial verified against whoever serves | 64 request bytes reached the worker |
| `consolidation-worker --lib inference_client::tests::wrong_server_uid_is_refused` | the same | 64 request bytes reached the worker |

Gate `c39_one_uds_site` (live non-test lines naming `UnixListener::bind` / `UnixStream::connect` outside `uds.rs` =
exactly the admin probe): red with a second live bind line in an uncompiled probe file, green with the same line
commented out.

## Known limits (S1)

- On macOS `getpeereid` answers ENOTCONN once the serving end has hung up, so a verified dial of a server that
  accepts and closes at once fails; Linux records the peer credential at connect time. Production is Linux (§67.2);
  the dev chain's servers hold their connections. Found by the consolidation `--readyz` test, whose stand-in now
  holds the accepted connection until the probe closes it.

## Known limits (S4)

- `deploy-check` docker calls have no per-call timeout (`// ponytail:` in `deploy_check::docker`): a hung daemon
  hangs the one-shot. Upgrade: a bounded wait if the `dr` container ever runs it unattended.
- (Closed by review fix 1 / S9 prep16: xtask answers `--version`.) `--release` cannot check the `loadgen` target
  until xtask answers `--version` (D-S); its manifest line would be
  `image_binary_mismatch` / `version_sha_mismatch`. Upgrade: give xtask the telemetry version mode in S8 or skip
  that line by target.
- (Closed in S6: the compose fixture is recaptured from `prod.yml`.)

## Known limits (S3)

- L-6: `dns_pin_deferred_total` has no host label: while any pin is configured, every TRANSPORT deferral counts,
  including one against an unpinned host (`// ponytail:` in `private-worker::distill`). Upgrade: a `{host}` label
  bounded by the pin map once a second pinned provider exists.

## Known limits (S5)

- The example lists are only as precise as `dep-map`'s literal scan. The two names `maintenance::drill` only writes
  into the drill project's environment (`HUMAUX_DRILL_ID`, `HUMAUX_DRILL_PG_LISTEN_ADDRESSES`) are left out by the
  explicit `deploy_check::CHILD_ONLY_KEYS` (review fix 1); `HUMAUX_PG_LISTEN_ADDRESSES` is a real read (`restore
  pitr`) and comes from node.env through `dr`'s env_file; the gateway's two accepted-and-ignored
  `HUMAUX_GATEWAY_REMEMBER_{TENANT,WORKSPACE}_ID` keys are declared empty in `values/gateway.env`. Upgrade: classify
  tuple-built child env as `child` in `dep_map::env_found` and drop the list.
- Provider key variables named by `HUMAUX_PRIVATE_WORKER_CREDENTIALS` are operator-chosen names, not `HUMAUX_`
  rows; the fixture cannot list them (the runbook step names them, D-J).

## Known limits (S6)

- (Closed by review fix 1, 2026-10-08.) `deploy-check --env` presence now counts the compose `environment:` and
  env_file sources, accepts declared-empty non-secret keys, requires every secret non-empty, and the generator routes
  the role passwords to `migrate.secret.env` and the private-worker route keys to `private-worker.secret.env`; runbook
  R2/U3 pass `--examples-dir`. What remains is L-17.
- `HUMAUX_RETRIEVAL_WORKER_GITLEAKS_SHA256` was empty in `values/{retrieval-worker,maintenance}.env` until S8 read it
  from the built image (2026-10-08, main line: `docker create humaux-retrieval-worker:<tag>` + `docker cp` of
  `/usr/local/bin/gitleaks`, sha256 `db4d43dd4ab54f047a2d18d210a8d2294e2e5cc26d1e26a299a9675916f5647d`, 21 904 478 bytes —
  the distroless image has no shell for `sha256sum`). Its `version` output is `v8.30.1` (the GitHub release tarball
  the dev Mac pins prints `8.30.1`), and the scanner pin is an exact string compare (local-secret-scan `run_version`),
  so `HUMAUX_RETRIEVAL_WORKER_GITLEAKS_VERSION=v8.30.1` in both values files (S9 replay prep6 found the mismatch the
  same way: exit 2 at R9); S9 replay prep5 proved the empty value's effect: `retrieval-rpc`
  exits 2 "invalid local secret scanner configuration" and R9's `up --wait` stops on it (L-17); the path
  `/usr/bin/gitleaks` in that image and that it runs on the cc base are S8 checks (W-11).
- `c39_no_secrets_in_deploy` runs its gitleaks half only once the main line pulls
  `zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0…` (E-8); until then it prints the named `not_applicable` and exits 2:
  the gate is NOT green (design §12 RF-9; review fix 1 reverted an undeclared "grep half alone decides", which had
  exited 0). The grep half still runs and still reports.
- (Closed by review fix 1.) `xtask load --restart <PHASE>=file:<dir>` speaks the req/ack protocol itself (no shell in
  `loadgen`); `a5_load_remeasure.sh` passes `--restart BURST-W=file:$HUMAUX_NODE_DIR/load-hook`, runs the listener
  that recreates the gateway with `HUMAUX_A5_GATEWAY_MAX_WAIT_MS=1` (a5-load.yml interpolates the admission wait;
  otherwise the values file's own value), and PASS requires a fresh `LOAD BURST-W` line and no `LOAD_SKIP` line.
- `dr` uses the host network namespace for `restore drill` (card 37 dials the drill on loopback); on Docker Desktop
  that is the VM's namespace, unproven because §5 runs no drill. Upgrade: publish the drill on the project network.
- Qdrant runs without `read_only` until S9 shows which paths the unprivileged image writes (W-6).

## Known limits (S7)

- (Closed by S9 prep16: 39/39 steps `RESULT ok`.) The runbook's step blocks are syntax-checked (`sh -n` of every
  `--show` output) and linted, not yet executed: S9's
  cheap-agent run is their first execution, and every IMPROVISED or STOP it records is a runbook bug fixed before the
  rerun (§4 rule). Facts the steps assume and S9 must confirm: `roles rotate` on a fresh cluster before migration
  (runbook v1 order), the receipt keys the steps read with `sed` (`tenant_id`, `workspace_id`, `owner_user_id`,
  `reasoning_domain_id`, `profile_id`, `profile_version`, `credential_ref`, `backup_label`), a bind-mounted file inside
  a read-only one-shot (`-v …/0011_roles_and_grants.sql:/usr/share/humaux/…:ro`), the alert sink writing into
  `HUMAUX_NODE_EVIDENCE_DIR` as uid 10199, and the distill output keeping the canary token verbatim.
- (Closed by S9 agent1: transcript exported, `RESULT pass`.) `c39_cheap_agent_log` is `not_applicable` (not green)
  until S9 exports a transcript; the zero-improvisation
  acceptance stays at E0 until then (E-11).
- The classifier allows exactly one command shape. A cheap agent that wraps the call differently (another `cd`, an
  `export` line) is classified IMPROVISED; that is intended — the agent's prompt names the shape.

## Declared deviations (R-4; each with its reopening signal)

| id | deviation | why it is acceptable now | reopening signal |
|---|---|---|---|
| L-13 | The node keeps a PostgreSQL superuser DSN permanently (`migrate.secret.env`, loaded only by the `migrate` one-shot; deploy-check refuses any other placement) — plan amendment 5 asks for a non-superuser migrator with a 0210 grant/revoke window | single node, the owner is the only operator; 0210's `ALTER FUNCTION … OWNER TO` needs SET on `role_health_reader` otherwise (ADR-0063 L14, F26) | a second operator or an external tenant; a managed PostgreSQL; OpenBao dynamic credentials (card 54) |
| L-14 | `dr` can read every secret on the node while it runs (`CAP_DAC_READ_SEARCH` + the secrets mount), writes into the operator's evidence directory as root (`CAP_DAC_OVERRIDE`, PR #2 review P1: a native-Linux node could not create `rollback-1.json` without it) and holds the docker socket (L-5) | backup / restore / deploy-check need the compose CLI with every env_file; the owner already holds all of them | a second operator; a dedicated repository host or provider backup (ADR-0064 L5) |
| (D-J) | Per-process 0600 env files outside git instead of compose `secrets:` for the Rust processes (the values are container env, visible to `docker inspect`, L-4) | the processes read env, not files; one operator | as L-13 (card 54 OpenBao) |
| L-15 | Unchanged files keep their mtimes only through `rsync -c` staging and the builder's named target volume (R-2); a cache loss recompiles every crate (correct, slower) | builds run on the build host, never on a node | a warm build 2 in S8 that rebuilds more than the sha-reading crates (W-3); then `build.sh` touches those crates |
| L-21 | The release bundle is not signed: `humaux-<tag>.sha256` and `humaux-checkout-<tag>.sha256` travel with the archives and the manifest, so they detect corruption, not substitution; R1 / U1 then trust the manifest as the identity every later check (R2's host-side `dr` id check, `deploy-check --release`) compares against (PR #2 Codex security review on bea2f5f) | one operator builds on their own build host and copies the three files to their own node over ssh (`scp` / `rsync -e ssh`), which authenticates the transfer; an attacker who can write `releases/` on the node already holds the operator's account and could replace a pinned public key and the runbook just as well, so a signature would add a key to manage without moving the trust boundary | the bundle passes through storage or hands other than the operator's ssh copy (an artifact store, CI publishing, a second operator) — then `build.sh` signs both `.sha256` files with a deployment key (`ssh-keygen -Y sign`, key path from env) and R1 / U1 verify against an `allowed_signers` file pinned at P1, before `sha256sum -c` and `docker load` |
| L-16 | Chain and rehearsal images carry the sha of an unreferenced snapshot commit; `git gc` prunes it after the default expiry | the manifest records sha and tree; production releases are commits on main (`build.sh` refuses others without `--unreleased`) | a snapshot sha needed after its expiry (an investigation of a chain image) — then keep a ref for chain builds |

## Known limits (L-1–L-20; consolidated)

- **L-1** Every size, pool and PostgreSQL number is a dev-host start value, frozen only by `a5_load_remeasure` (O-1);
  runbook §8.1 stays "(dev-host)"; no `ops.mechanism_observations` row from this host.
- **L-2** (rewritten by review fix 9, C1) Residents run `restart: unless-stopped`, so a node comes back after a host
  reboot or a dockerd restart with no operator. Docker cannot tell exit 2 from a crash: a configuration error now
  restarts under Docker's exponential backoff instead of stopping after five tries. Guards: `deploy-check --env`
  before every `up` (R2 / U3) and `deploy-check --running` (`service_restarted:<svc>` is red), so a looping resident
  cannot pass R10 or the U-steps.
- **L-3** The rollback rehearsal crosses no schema change (both builds share migration head 0234); the first
  schema-crossing rollback is rehearsed at go-live (card 53).
- **L-4** DSN passwords and provider keys are container environment variables (visible to `docker inspect`). Upgrade:
  OpenBao (card 54).
- **L-5** `dr` holds the docker socket (root-equivalent) while it runs. Upgrade: a dedicated repository host or
  provider backup (ADR-0064 L5).
- **L-6** `dns_pin_deferred_total` has no host label (ponytail in `private-worker::distill`).
- **L-7** One shared network namespace: every Humaux process can reach every loopback ops listener (as on a native
  host).
- **L-8** No registry: images move by image archive + `sha256` file (runbook R0 / R1).
- **L-9** The parse sandbox (§4.3), public-worker, reranker, OpenBao and OAuth are not in the bundle (D-B).
- **L-10** Deploy artifacts offsite: `deploy/OFFSITE.list` names `deploy/**`; the offsite copy itself is card 37d
  (host loss = total loss until then; Baseline §67.4 row).
- **L-11** Admin's socket probe stays connect-level (its existing ponytail).
- **L-12** The gateway is published on loopback only (R-7).
- **L-13 / L-14** declared deviations above.
- **L-15 / L-16** declared above.
- **L-17** (review fix 1) `deploy-check --env` presence cannot tell a required non-secret key left empty from an
  empty-by-design one (`GLOBAL_DENYLIST=`, `TRUSTED_PROXY_CIDRS=`, `DNS_PINS=`, …): only secrets must be non-empty. A
  required one left empty (today `HUMAUX_RETRIEVAL_WORKER_GITLEAKS_SHA256`, filled by S8) makes its binary refuse boot
  (exit 2) and the runbook's verify step stop, after `up` instead of before it. Upgrade: an `optional` flag per key in
  the generated example (from the typed registry and a raw-key list), presence requiring every other key non-empty.
- **L-18** (review fix 9, CC-2) The bundle ships `HUMAUX_GATEWAY_TRUSTED_PROXY_CIDRS=` empty, so the gateway's
  client identity is always the TCP peer: behind any front proxy every external client shares one peer address, one
  pre-auth IP bucket and one IP-policy decision. Acceptable while the gateway is published on loopback only (R-7,
  L-12). Reopening signal: card 53 (TLS / public exposure) — the proxy's peer address goes into that variable first.
- **L-19** (review fix 9, C4) The two Alertmanager webhook URL files (`alert-urls/log_sink.url`, `watchdog.url`) are
  world-readable on the node (0644 under 0755; R8 renders under `umask 022` because prometheus and alertmanager run
  as their image user). Today they name the loopback log sink and the watchdog. Reopening signal: a URL that carries
  a secret token → a `user:`-pinned Alertmanager or a secret-bearing file mount (card 53).
Ponytails in code: `uds.rs` (own uid through a socketpair, one syscall pair per boot), `distill.rs` (L-6),
`deploy_check.rs` (`--release` runs one container per image sequentially; docker calls without a per-call timeout),
`render-secrets.sh` (openssl on the operator host), `prod.yml` (`dr` in the host network namespace for the drill).
Follow-ups: card 38b (pool keys of every process; would lower `max_connections`), O-1 (A5), card 53 (TLS / public
exposure, schema-crossing rollback), card 54 (secrets), card 37d (offsite), the public-worker deployment when Public
Evolution is enabled.

- **L-20** The checkout-tree guard (`deploy-check --release --checkout-tree`) compares `CHECKOUT_TREE`, a label shipped
  inside the checkout, with the manifest: it detects a wrong or stale tarball, not a hand-edited `deploy/` on the node.
  Accepted under the single-operator model (L-13); reopening signal: a second operator or an audit requirement — then
  the executor hashes the checkout tree itself (PR #2 independent review P2-6).
## S8 / S9 — main-line runs (2026-10-08; design §5, rulings R-1 / R-6 / R-8 / R-12)

Evidence root: `TW/c39_image_build/` (S8 logs `run1..run11.log`, `releases/*.manifest`) and `TW/card39_rehearsal/<id>/`
(node dir, `proof/`, the copied `c39_rehearse_node.log`); the chronological record is `TW/c39_run_notes.txt`.

**S8 — image pair.** `TW/c39_build_images.sh` run11: `RESULT pass`, PREV `0.1.0-8b5d48c2798e` (snapshot of the
card-39 tree), UPGRADE `0.1.0-81159ef42ad0` (its snapshot child), 16 IMAGE lines, ids disjoint, `admin version` sha ==
snapshot sha, `tree_unchanged`. Rule learnt the hard way (run10 failed `tree_changed_since_snapshot`): the working tree
is frozen for the whole build. The host floors (20 GiB free on `/` for S8, 20 GiB under `/Volumes/data` for S9) were
met by removing only session-owned objects (the regenerable `target/metrics-witness-probe-out`, superseded release
image tags of earlier S8 runs); shared Docker volumes were not touched (owner's call).

**S9 — clean-node replay** (`TW/c39_rehearse_node.sh`, the chain gate `rehearse_node_c39`). Sixteen replays
(prep1–prep16) drove review fixes 1–7 above (of nine: fix 8 came from the chain, fix 9 from the pre-PR review) and these runbook/replay corrections: `--profile ops` on every
`config` / `deploy-check --running` site, the V1 probe loop (19106 serves no metric family by design), the
`dr.secret.env` presence line, the gateway rate-bucket keys in `values/gateway.env`, the executor's own `C config`
call. **prep16: 25/25 assertions PASS, 39/39 runbook steps `RESULT ok` + `NOTOOLCHAIN ok` in `--list` order,
`c39 node rehearsal EXIT 0`, 9 min wall clock**, teardown proof green (no container/volume/network of the three
projects; leftover-volume red recorded), dev stores untouched (same container id + StartedAt; both substituted-snapshot
reds recorded), gitleaks over log + evidence: 4 findings, all `credential_ref=<uuid>` reference ids (verified finding
by finding with --redact -v); the scan is informative, not a gate.

- *Fault (c) finding (prep14).* `restore pitr --target-time $PRE_UPGRADE_TIME` RESTORED cleanly with an exact
  `lost_window` (the target, 3 s after the backup start, lay inside the WAL segment `pg_backup_stop` archives). That is
  a correct PITR, not a defect — but it shows RF-5's "no archived WAL after it" is a timing accident. The recorded red
  `pitr_time_target_red` therefore targets PRE_UPGRADE_TIME + 1 h (beyond every archived WAL on any node): exit 1 with
  PostgreSQL's "recovery ended before configured recovery target was reached" (F22: never a silent partial restore).
- *Mac deviations (logged per run, R-12):* the pgBackRest repository is a plain directory under the node dir (Linux:
  a 12 GiB loop ext4 owned 999:999); the node HOME links Docker Desktop's compose plugin.
- *Evidence hygiene:* step O3 prints `credential_ref=<uuid>` per smoke tenant (a route's credential reference id, not
  a secret; it also lands in `<evidence>/<tenant>.cred`). gitleaks' `generic-api-key` rule flags exactly those lines
  and nothing else (prep16: 4 findings — `steps/O3.out` ×2 and the copied log ×2; agent1: 2 — `steps/O3.out` and the
  transcript), verified finding by finding with `--redact -v`. The replay's `CHECK secret_scan` line is informative
  (it does not decide EXIT); `// ponytail:` an allowlist for `credential_ref=` would make a non-zero count meaningful.

**S9 — cheap-agent run** (design §5 "run by a cheap agent", R-8; node `cagent1`, prepared and torn down by
`C39_MODE=prepare | teardown zsh c39_rehearse_node.sh agent1`). A light model with the runbook, the node dir and the
executor's three call shapes as its only instructions ran **39/39 steps `RESULT ok`**; its transcript (41 tool calls:
40 Bash, 1 Read, all ALLOWED, 0 IMPROVISED) is `cagent1/node/evidence/agent_calls.jsonl` (E-11), and
`TW/c39_steplog_check.sh` reports `steps=39 improvised=0 notes_improvised=0 RESULT pass` (gate `c39_cheap_agent_log`,
which selects the newest evidence dir carrying a transcript). Teardown proof green, dev stores untouched.

**CI portability (PR #1 of the public repository, same day).** Two tests of the card-38 tree were red only on the
GitHub arm runner: the consolidation hop e2e `t2` body write raced the server's 403 close (EPIPE; and ECONNRESET on the
read side) — tolerated, the assertion stays on the 403 bytes; the private-worker E10 was inconclusive because
`192.88.99.1` answers a connection error at once there (every attempt DEAD TRANSPORT in 5.6 s, no call open while
worker 1 is stopped) — a black-hole probe now makes that `not_applicable: missing object = a black-holing literal
endpoint …` (§57.1) while the dev host (a TUN proxy accepts every connect and relays nothing) still runs the full E10.
Both are in the card-39 tree too.

## Spec text changed (§78.6)

- Baseline §41.2: row `dns_pin_deferred_total` (S3, D-P).
- Baseline §25.3 (D0 checker owner note): the rls checker path is `bins/maintenance/src/rls_check.rs` (D-Q; xtask keeps a
  delegation shell) — PR #2 independent review P2-5.
- Baseline §42: row "DNS pin deferred" (`DnsPinDeferred`, S3, D-P).
- Baseline §41.2: row `backup_disk_free_bytes` — the free bytes are `statvfs(3)` of the path (f_bavail × f_frsize),
  in-process, not a `df -Pk` child (review fix 5's mechanism; wording by review fix 9, C9 / OP-8 / F11).
- Baseline §4.4: the release bundle moves the `deploy.binary` name-versus-reality check before deployment — every
  binary answers `--version` (exit 2 without a burned-in sha), each build writes a release manifest, and
  `deploy-check --release` compares image id, revision label, binary name and the self-reported sha with it before
  any service starts or any rollback proceeds (S7, D-D / D-R).
- Baseline §67.4: the dead-man payload's sha comes from the deployed image's `humaux-admin version` at render time
  and has been compared with the release manifest by `deploy-check --release`; the offsite list of `deploy/` is
  `deploy/OFFSITE.list`, the copy itself card 37d (S7, D-I / D-R, L-10).
- ADR-0037 addendum "Exit-code contract (ADR-0066 D-N)": 0 / 1 / 2 / 3 / 101 per mode, no argument-less success,
  probe modes 0 / 2, `--version` 0 / 2, and what a supervisor does with each (S7).

## O-1 — A5 re-measure (open)

`deploy/release/a5_load_remeasure.sh --out DIR [--l16-before-p95-ms N] [--facts F] [--replay-log F]` (D-S), run by the
chain gate `a5_load_remeasure` through `TW/c39_a5_load_remeasure.sh`. Contract: on a host that is not the A5 runner
(`Linux aarch64`, 4 CPUs, MemTotal 22–25 GiB) it prints `GATE a5_load_remeasure not_applicable: missing object = A5
runner …` with the host facts and exits 0 — never PASS. On A5: (1) `budget_sums.sh` with the measured MemTotal, (2) the
runbook's first-install steps through the executor, (3) the card-38 phase set from the `loadgen` image with
`--host-class a5 --meminfo-path /proc/meminfo`, the gateway recreated with the a5-load.yml load-window overrides and
BURST-W's restart answered by the script's listener, (4) PASS iff the loadgen manifest identity passes, every phase
L8/L16/L32/L64/BURST-W has a fresh `LOAD … host=a5-4cpu-vm2[2-5]…` line, there is no `LOAD_SKIP` line and no
`ASSERTION FAIL` (review fix 1: a skipped BURST-W passed before); (5) always `SIGNAL L16 <reopen|hold>
enumerate_p95_l16=<ms> bound=<2 × 136.8>ms`. **O-1 closes only on `pass` AND `SIGNAL L16 hold`**: the main line then
appends the LOAD lines to ADR-0065 and retitles runbook §8.1. On `pass` + `reopen`, O-1 stays open and ADR-0065 L16
reopens with the number. Until then every `sizing-*` number, the §8.1 table and the PostgreSQL sizing stay labelled
"dev-host start value, A5 re-measure required" (R-10), and `delivery_point_report.md` lists O-1 as open.

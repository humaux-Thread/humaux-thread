#!/bin/sh
# deploy/release/a5_load_remeasure.sh — the A5 re-measure of the card-38 load set (ADR-0066 D-S; closes ADR-0065 O-1
# only on `pass` AND `SIGNAL L16 hold`). Three-state (§57.1): pass / FAIL / not_applicable naming the missing A5 runner.
# Caller: the chain gate a5_load_remeasure through TW/c39_a5_load_remeasure.sh (this Mac: always not_applicable), and
#   the A5 runner's own gate run (same file, same arguments).
# Usage: a5_load_remeasure.sh --out DIR [--l16-before-p95-ms N] [--facts FILE] [--replay-log FILE]
# Inputs:
#   --out DIR            evidence dir (load log, budget output); created.
#   --l16-before-p95-ms  ADR-0065 L16's BEFORE enumerate p95 (the gate passes 136.8); SIGNAL bound = 2 x this.
#   --facts FILE         overrides the host facts (lines UNAME=<kernel> <machine>, NPROC=<n>, MEMTOTAL_MIB=<n>); fault
#                        runs only.
#   --replay-log FILE    evaluates a recorded load log instead of deploying and loading; fault runs only.
#   On A5 (live): HUMAUX_NODE_DIR / HUMAUX_NODE_SIZING=a5 / HUMAUX_NODE_PROJECT for the runbook executor and compose.sh,
#   and the loadgen image of the deployed tag (deploy/compose/a5-load.yml). Every other node value (the secrets dir,
#   the tag, the netns address, the egress processor) is read from $HUMAUX_NODE_DIR/node.env, as the runbook reads it.
#   On A5 (live) also $HUMAUX_SECRETS_DIR/a5-load.secret.env (HUMAUX_TEST_PG_DSN: the runner's superuser DSN for the loadgen,
#   a5-load.yml env_file; created by the operator per runbook §O-1, never by this script). Absent -> not_applicable
#   naming that path (review fix 9, F9); the superuser-DSN placement is declared deviation L-13's sibling on a runner.
# Host facts: `uname -s -m`, the online CPU count, MemTotal from /proc/meminfo (Darwin: sysctl hw.memsize). A5 <=>
#   `Linux aarch64`, 4 CPUs and MemTotal 22-25 GiB (22528-25600 MiB; 22 GiB is ADR-0066 D-E's budget floor).
# Steps on A5: (1) deploy/release/budget_sums.sh --mem-total-mib <measured> (else FAIL); (2) deploy by runbook v2: its
#   first-install steps (§1-§3 and §7: P*, R*, O*, V*, every one through deploy_rehearsal.sh; the acceptance drills, the backup
#   and the release steps of §A/§B/§R need a second release and are not part of a load measurement); (3) seed LA (16 workspaces) / LB (1) and run the card-38 phase set through the
#   loadgen image with --host-class a5 --meminfo-path /proc/meminfo, the gateway first recreated with the a5-load.yml
#   load-window overrides; BURST-W's restart is asked through the hook dir (`--restart BURST-W=file:<dir>`, the
#   loadgen image has no shell) and answered by this script's listener, which recreates the gateway with
#   HUMAUX_A5_GATEWAY_MAX_WAIT_MS=1; afterwards the gateway is recreated from prod.yml alone; (4) PASS iff the loadgen
#   image's manifest identity check passed, every phase L8/L16/L32/L64/BURST-W has >= 1 `LOAD … host=a5-4cpu-vm2[2-5]…
#   measured_at=` line not older than this run's start, there is no `LOAD_SKIP` line and 0 `ASSERTION FAIL` lines;
#   (5) always `SIGNAL L16 <reopen|hold> …`.
# Output (stdout, and DIR/a5_load_remeasure.log): `GATE a5_load_remeasure <pass | FAIL: reasons | not_applicable: …>`
#   and, on A5, the SIGNAL line. No secret: the bearers and the pepper stay in the environment and are passed to
#   compose by NAME (`-e NAME`, `--pepper-hex-env`), never as an argument (review P1, 2026-10-08).
# Exit: 0 = pass or not_applicable; 1 = FAIL; 2 = usage.
set -u
usage() { echo "usage: a5_load_remeasure.sh --out DIR [--l16-before-p95-ms N] [--facts FILE] [--replay-log FILE]" >&2; exit 2; }
OUT=; BEFORE=; FACTS=; REPLAY=
while [ $# -gt 0 ]; do
  case $1 in
    --out) [ $# -ge 2 ] || usage; OUT=$2; shift 2 ;;
    --l16-before-p95-ms) [ $# -ge 2 ] || usage; BEFORE=$2; shift 2 ;;
    --facts) [ $# -ge 2 ] || usage; FACTS=$2; shift 2 ;;
    --replay-log) [ $# -ge 2 ] || usage; REPLAY=$2; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$OUT" ] || usage
DEPLOY=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$OUT"
LOG=$OUT/a5_load_remeasure.log
: > "$LOG"
say() { echo "$*" | tee -a "$LOG"; }
START=$(date -u +%Y-%m-%dT%H:%M:%SZ)

if [ -n "$FACTS" ]; then
  fact() { grep -E "^$1=" "$FACTS" | tail -1 | cut -d= -f2-; }
  UNAME=$(fact UNAME); NPROC=$(fact NPROC); MEM_MIB=$(fact MEMTOTAL_MIB)
else
  UNAME=$(uname -s -m)
  NPROC=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 0)
  if [ -r /proc/meminfo ]; then MEM_MIB=$(awk '/^MemTotal:/ { print int($2 / 1024) }' /proc/meminfo)
  else MEM_MIB=$(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1048576 )); fi
fi
FACTLINE="host facts: $UNAME ${NPROC}cpu $((MEM_MIB / 1024))GiB (MemTotal ${MEM_MIB} MiB)"
if [ "$UNAME" != "Linux aarch64" ] || [ "$NPROC" != 4 ] || [ "$MEM_MIB" -lt 22528 ] || [ "$MEM_MIB" -gt 25600 ]; then
  say "GATE a5_load_remeasure not_applicable: missing object = A5 runner (Linux aarch64, 4 CPUs, MemTotal 22-25 GiB) absent: $FACTLINE"
  exit 0
fi
[ -n "$BEFORE" ] || { say "GATE a5_load_remeasure FAIL: --l16-before-p95-ms is required on A5"; exit 2; }
say "a5_load_remeasure: A5 runner recognised: $FACTLINE start=$START"

REASONS=
# (1) The budget against the MEASURED MemTotal (ADR-0066 D-E, RF-11).
if ! sh "$DEPLOY/release/budget_sums.sh" --mem-total-mib "$MEM_MIB" --compose "$DEPLOY/compose/prod.yml" \
     "$DEPLOY/env/sizing-a5.env" "$DEPLOY/env/sizing-rehearsal.env" >> "$LOG" 2>&1; then
  REASONS="$REASONS budget"
fi

LOADLOG=$OUT/load.log
if [ -n "$REPLAY" ]; then
  cp "$REPLAY" "$LOADLOG"
else
  # (2a) F9: the loadgen's env_file. Nothing creates it, so a missing file is a missing object, not a load FAIL.
  A5SEC=$(sed -n 's/^HUMAUX_SECRETS_DIR=//p' "${HUMAUX_NODE_DIR:-/nonexistent}/node.env" 2>/dev/null | tail -n 1)
  if [ -n "$A5SEC" ] && [ ! -r "$A5SEC/a5-load.secret.env" ]; then
    say "GATE a5_load_remeasure not_applicable: missing object = $A5SEC/a5-load.secret.env (HUMAUX_TEST_PG_DSN for the loadgen; create it per runbook §O-1)"
    exit 0
  fi
  # (2) Deploy by runbook v2, every step through the executor (no toolchain, ADR-0066 §4).
  : > "$LOADLOG"
  # ADR-0066 S7: the --list prefix up to the first acceptance-drill step (A1) is the first install.
  for step in $(sh "$DEPLOY/release/deploy_rehearsal.sh" --list | awk '/^(A|B|U|RB)[0-9]/ { exit } { print }'); do
    sh "$DEPLOY/release/deploy_rehearsal.sh" run "$step" >> "$OUT/deploy.log" 2>&1 || { REASONS="$REASONS deploy:$step"; break; }
  done
  if [ -z "$REASONS" ]; then
    nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
    C="sh $DEPLOY/release/compose.sh -f $DEPLOY/compose/a5-load.yml"
    TAG=$(nv HUMAUX_IMAGE_TAG); RELEASES=$(nv HUMAUX_NODE_RELEASES_DIR); SECRETS=$(nv HUMAUX_SECRETS_DIR)
    SHA=$(grep -E '^IMAGE humaux-loadgen:' "$RELEASES/release-$TAG.manifest" | sed -n 's/.* git_sha=\([0-9a-f]\{40\}\).*/\1/p')
    # The loadgen identity: the manifest's four comparisons (D-R) over the release the node runs.
    # PR #2 Codex P1: the release gate also compares the checkout (R2 / U3 / RB1 pass the same line).
    CKTREE=$(cat "$DEPLOY/../CHECKOUT_TREE" 2>/dev/null || true)
    if [ -n "$CKTREE" ] && sh "$DEPLOY/release/compose.sh" run --rm -T dr deploy-check --release "$TAG" --manifest "$RELEASES/release-$TAG.manifest" \
         --expect-sha "$SHA" --checkout-tree "$CKTREE" >> "$OUT/deploy.log" 2>&1; then echo "MANIFEST_IDENTITY pass" >> "$LOADLOG"
    else echo "MANIFEST_IDENTITY fail${CKTREE:+}${CKTREE:-:checkout_tree_missing}" >> "$LOADLOG"; fi
    # The load window's gateway: a5-load.yml's overrides, the admission wait at the deployed value (BURST-W lowers
    # it through the listener below).
    HUMAUX_A5_GATEWAY_MAX_WAIT_MS=$(sed -n 's/^HUMAUX_GATEWAY_ADMISSION_MAX_WAIT_MS=//p' "$DEPLOY/env/values/gateway.env")
    export HUMAUX_A5_GATEWAY_MAX_WAIT_MS
    # Card 39b (PR #2 Codex round 10, PR #4 Codex P2 ×2): from the first overlay recreate on, any exit — normal,
    # TERM / INT, or HUP (dash runs no EXIT trap on SIGHUP: a dropped ssh session) — puts the gateway back on
    # prod.yml alone, never leaving a5-load.yml's overrides or the 1 ms BURST-W wait deployed. The trap is installed
    # BEFORE that recreate. The BURST-W listener (started below) is asked to stop and waited for, never killed: a
    # kill mid-`up` would orphan its compose child, which could recreate the 1 ms gateway AFTER the restore.
    HOOK=$HUMAUX_NODE_DIR/load-hook
    LISTENER=
    stop_listener() { [ -n "$LISTENER" ] || return 0; touch "$HOOK/stop"; wait "$LISTENER" 2>/dev/null; }
    trap 'stop_listener; sh "$DEPLOY/release/compose.sh" up -d --no-deps gateway >> "$OUT/deploy.log" 2>&1' EXIT
    trap 'exit 143' TERM INT HUP
    $C up -d --no-deps gateway >> "$OUT/deploy.log" 2>&1 || echo "ASSERTION FAIL load_window_gateway_recreated" >> "$LOADLOG"
    # BURST-W listener (ADR-0065 hook protocol, ADR-0066 D-S): xtask load writes load_burst_w.req into the hook dir
    # (bind-mounted at the same path); this recreates the gateway with a 1 ms admission wait and acks; load's own
    # readiness wait follows. Stopped by the EXIT trap; bounded like rehearse.sh's listener.
    mkdir -p "$HOOK" && rm -f "$HOOK/load_burst_w.req" "$HOOK/load_burst_w.ack" "$HOOK/stop"
    # ponytail: world-writable so the loadgen uid 10198 can write the request; the dir carries no data. Chown it to
    # 10198 when the runner's operator is root.
    chmod 0777 "$HOOK"
    ( i=0
      while [ ! -f "$HOOK/load_burst_w.req" ]; do
        [ -f "$HOOK/stop" ] && exit 0
        sleep 1; i=$((i + 1)); [ $i -ge 3600 ] && exit 0
      done
      HUMAUX_A5_GATEWAY_MAX_WAIT_MS=1 $C up -d --no-deps gateway >> "$OUT/deploy.log" 2>&1 && touch "$HOOK/load_burst_w.ack"
    ) &
    LISTENER=$!
    # (3) Seed and load: the card-38 phase set (ADR-0065) through the loadgen image. e2e-seed hashes the keys with
    # the node's pepper; it reaches the container by NAME (`-e`, `--pepper-hex-env`), never in argv, `ps` or
    # `docker inspect` Args (review P1, 2026-10-08). An empty pepper stops the run.
    HUMAUX_A5_SEED_PEPPER_HEX=$(sed -n 's/^HUMAUX_MAINTENANCE_CREDENTIAL_PEPPER_HEX=//p' "$SECRETS/maintenance.secret.env" | tail -n 1)
    export HUMAUX_A5_SEED_PEPPER_HEX
    [ -n "$HUMAUX_A5_SEED_PEPPER_HEX" ] || echo "ASSERTION FAIL seed_pepper_present ($SECRETS/maintenance.secret.env)" >> "$LOADLOG"
    PROC=$(nv HUMAUX_NODE_RETRIEVAL_EGRESS_PROCESSOR_ID)
    seed() { $C --profile a5 run --rm -T -e HUMAUX_A5_SEED_PEPPER_HEX loadgen e2e-seed --pepper-hex-env HUMAUX_A5_SEED_PEPPER_HEX \
      --scopes memory:write,context:read \
      --limit 10000000 --no-lane --processor-id "$PROC" --collection humaux_private_memory_v1 --dimension 1024 \
      --embedding-provider dashscope --embedding-region cn-beijing --workspaces "$1"; }
    val() { printf '%s\n' "$1" | grep -iE "^[[:space:]]*$2[[:space:]]*[:=]" | head -1 | sed -E 's/^[^:=]*[:=][[:space:]]*//' | tr -d ' '; }
    SA=$(seed 16 2>> "$OUT/seed.stderr"); SB=$(seed 1 2>> "$OUT/seed.stderr")
    LOAD_A_BEARER_1=$(printf '%s\n' "$SA" | sed -n 's/^Authorization: Bearer //p' | head -1); export LOAD_A_BEARER_1
    LOAD_B_BEARER_1=$(printf '%s\n' "$SB" | sed -n 's/^Authorization: Bearer //p' | head -1); export LOAD_B_BEARER_1
    LANES="--lane a=$(val "$SA" workspace_id):LOAD_A_BEARER_1 --lane b=$(val "$SB" workspace_id):LOAD_B_BEARER_1"
    ENVS="-e LOAD_A_BEARER_1 -e LOAD_B_BEARER_1"
    k=2
    while [ $k -le 16 ]; do
      eval "LOAD_A_BEARER_$k=\$(val \"\$SA\" bearer_$k); export LOAD_A_BEARER_$k"
      LANES="$LANES --lane a=$(val "$SA" "workspace_id_$k"):LOAD_A_BEARER_$k"; ENVS="$ENVS -e LOAD_A_BEARER_$k"
      k=$((k + 1))
    done
    # shellcheck disable=SC2086 # word lists on purpose
    # The card-38 phase set and bounds (rehearse_c38 / ADR-0065 D-C, D-F: W 5 s, handler 20 s, P 18, 80 backends, ISO
    # floor 7 ms); BURST-W through the hook dir above.
    NETNS_IP=$(nv HUMAUX_NODE_NETNS_IP)
    $C --profile a5 run --rm -T $ENVS loadgen load --gateway-url "http://$NETNS_IP:8080/mcp" \
      --ops-url http://127.0.0.1:19101/metrics $LANES --levels 8,16,32,64 --burst 128 --warmup-secs 5 --level-secs 45 \
      --burst-secs 20 --iso-pairs 3 --iso-secs 20 --iso-base-clients 4 --iso-burst-clients 64 --burst-w-secs 15 \
      --max-wait-ms 5000 --burst-w-max-wait-ms 1 --handler-timeout-secs 20 --pool-max 18 --max-backends 80 \
      --iso-floor-ms 7 --ready-timeout-secs 90 --lock-sample-ms 10 --pg-dsn-env HUMAUX_TEST_PG_DSN \
      --host-class a5 --meminfo-path /proc/meminfo --restart "BURST-W=file:$HOOK" >> "$LOADLOG" 2>> "$OUT/load.stderr" \
      || echo "load: xtask load exited non-zero" >> "$LOADLOG"
    stop_listener
    # Out of the load window: the gateway from prod.yml alone (the deployed admission and rate values).
    sh "$DEPLOY/release/compose.sh" up -d --no-deps gateway >> "$OUT/deploy.log" 2>&1 \
      || echo "ASSERTION FAIL gateway_restored_after_load" >> "$LOADLOG"
    trap - EXIT
  fi
fi

# (4) Evaluate the load log.
grep -q '^MANIFEST_IDENTITY pass$' "$LOADLOG" || REASONS="$REASONS manifest_identity"
# RF-18 / review P1 (2026-10-08): BURST-W is a required phase; a skipped phase is a FAIL, never a quiet pass.
for level in L8 L16 L32 L64 BURST-W; do
  n=$(grep -E "^LOAD $level .* host=a5-4cpu-vm2[2-5][^ ]* measured_at=" "$LOADLOG" \
      | sed -n 's/.* measured_at=\([^ ]*\).*/\1/p' | awk -v s="$START" '$1 >= s' | grep -c .)
  [ "$n" -ge 1 ] || REASONS="$REASONS no_a5_load_line:$level"
done
S=$(grep -c '^LOAD_SKIP' "$LOADLOG")
[ "$S" = 0 ] || REASONS="$REASONS load_skip:$S"
F=$(grep -c 'ASSERTION FAIL' "$LOADLOG")
[ "$F" = 0 ] || REASONS="$REASONS assertion_fail:$F"
if [ -z "$REASONS" ]; then say "GATE a5_load_remeasure pass"; RC=0
else say "GATE a5_load_remeasure FAIL:$REASONS"; RC=1; fi

# (5) The ADR-0065 L16 reopening signal, always printed on A5: hold iff max enumerate p95 at L16 <= 2 x BEFORE.
P95=$(grep -E '^LOAD L16 .* op=(memory\.)?enumerate ' "$LOADLOG" | sed -n 's/.* p95=\([0-9.]*\)ms.*/\1/p' | sort -n | tail -1)
BOUND=$(awk -v b="$BEFORE" 'BEGIN { printf "%.1f", 2 * b }')
if [ -n "$P95" ] && awk -v p="$P95" -v b="$BOUND" 'BEGIN { exit !(p <= b) }'; then SIG=hold; else SIG=reopen; fi
say "SIGNAL L16 $SIG enumerate_p95_l16=${P95:-none}${P95:+ms} bound=${BOUND}ms"
exit $RC

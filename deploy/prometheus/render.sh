#!/bin/sh
# deploy/prometheus/render.sh — the one renderer of the observability configs (ADR-0066 D-I; ADR-0061 D-G deployer
# contract of prometheus.yml / alertmanager.yml).
# Caller: runbook v2 §2 on a node (the sha from `$C run --rm -T admin version` through sed), and docs/ops/rehearse.sh's
#   observability step (the sha from the dev build's admin `version` line). POSIX sh + sed + printf only: no python,
#   no toolchain, no Humaux binary (gate c39_render_portable).
# Usage: render.sh <out_dir> <git_sha40> <alert_url_dir>
# Inputs: <git_sha40> the deployed sha (every alert, the §42.1 Watchdog included, carries it as external label git_sha,
#   §67.4); <alert_url_dir> the directory Alertmanager reads the webhook URL files from (in prod.yml:
#   /run/humaux-alert-urls); the URL files themselves (log_sink.url, watchdog.url) are the operator's, never written here.
# Writes: <out_dir>/prometheus/prometheus.yml (sha substituted), <out_dir>/prometheus/{invariants,alerts}.rules.yml
#   (copies, resolved relative to prometheus.yml), <out_dir>/prometheus/targets/humaux.json (the eight resident ops
#   listeners 127.0.0.1:19101-19108 with {job, mode} labels, ADR-0061 D-B), <out_dir>/alertmanager/alertmanager.yml
#   (url_file placeholders -> <alert_url_dir>/log_sink.url and watchdog.url). Prints the written paths; no secret.
# Exit: 0 = written; 2 = usage (the bad argument named); 1 = a write failed.
set -eu
[ $# -eq 3 ] || { echo "usage: render.sh <out_dir> <git_sha40> <alert_url_dir>" >&2; exit 2; }
OUT=$1; SHA=$2; URLS=$3
printf '%s' "$SHA" | grep -Eqx '[0-9a-f]{40}' || { echo "render.sh: <git_sha40> is not a 40-hex sha: $SHA" >&2; exit 2; }
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT/prometheus/targets" "$OUT/alertmanager"
sed "s#__HUMAUX_GIT_SHA__#$SHA#" "$HERE/prometheus.yml" > "$OUT/prometheus/prometheus.yml"
cp "$HERE/invariants.rules.yml" "$HERE/alerts.rules.yml" "$OUT/prometheus/"
# One entry per resident mode (process, mode, port): the ports are values/*.env's *_METRICS_ADDR.
{
  printf '[\n'
  sep=' '
  while read -r proc mode port; do
    printf '%s{"targets": ["127.0.0.1:%s"], "labels": {"job": "humaux-%s", "mode": "%s"}}\n' "$sep" "$port" "$proc" "$mode"
    sep=','
  done <<'TARGETS'
consolidation-worker serve 19106
gateway serve 19101
maintenance health-serve 19107
maintenance serve 19108
private-worker distill-serve 19105
private-worker serve-rpc 19104
retrieval-worker serve 19103
retrieval-worker serve-rpc 19102
TARGETS
  printf ']\n'
} > "$OUT/prometheus/targets/humaux.json"
sed -e "s#__HUMAUX_ALERTMANAGER_LOG_SINK_URL_FILE__#$URLS/log_sink.url#" \
    -e "s#__HUMAUX_ALERTMANAGER_WATCHDOG_URL_FILE__#$URLS/watchdog.url#" \
    "$HERE/alertmanager.yml" > "$OUT/alertmanager/alertmanager.yml"
echo "render.sh: wrote $OUT/prometheus/prometheus.yml $OUT/prometheus/targets/humaux.json $OUT/alertmanager/alertmanager.yml (git_sha=$SHA)"

#!/bin/sh
# deploy/release/compose.sh — `$C` of runbook v2: the one way to run docker compose on a node (ADR-0066 §3).
# Caller: every runbook v2 block (through deploy/release/deploy_rehearsal.sh), host cron (backup / drill through `dr`),
#   the operator.
# Usage: compose.sh <docker compose arguments…>   e.g. `compose.sh up -d --wait --wait-timeout 300`,
#   `compose.sh run --rm -T dr backup run`.
# Inputs (environment, all required): HUMAUX_NODE_SIZING (a5 | rehearsal: picks deploy/env/sizing-<it>.env),
#   HUMAUX_NODE_DIR (holds node.env), HUMAUX_NODE_PROJECT (the compose project name).
# Runs: docker compose --env-file deploy/env/sizing-$HUMAUX_NODE_SIZING.env --env-file $HUMAUX_NODE_DIR/node.env
#   -p $HUMAUX_NODE_PROJECT -f deploy/compose/prod.yml "$@" (paths relative to this checkout). Prints only what docker
#   compose prints; reads no secret itself (env_file values are read by compose, never echoed).
# Exit: docker compose's own exit code; 2 = a required variable unset or its file missing (named).
set -u
DEPLOY=$(cd "$(dirname "$0")/.." && pwd)
for v in HUMAUX_NODE_SIZING HUMAUX_NODE_DIR HUMAUX_NODE_PROJECT; do
  eval "val=\${$v:-}"
  [ -n "$val" ] || { echo "compose.sh: missing object: $v is not set" >&2; exit 2; }
done
SIZING="$DEPLOY/env/sizing-$HUMAUX_NODE_SIZING.env"
[ -r "$SIZING" ] || { echo "compose.sh: missing object: $SIZING (HUMAUX_NODE_SIZING=$HUMAUX_NODE_SIZING)" >&2; exit 2; }
[ -r "$HUMAUX_NODE_DIR/node.env" ] || { echo "compose.sh: missing object: $HUMAUX_NODE_DIR/node.env" >&2; exit 2; }
exec docker compose --env-file "$SIZING" --env-file "$HUMAUX_NODE_DIR/node.env" -p "$HUMAUX_NODE_PROJECT" \
  -f "$DEPLOY/compose/prod.yml" "$@"

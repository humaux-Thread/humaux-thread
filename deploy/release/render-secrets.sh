#!/bin/sh
# deploy/release/render-secrets.sh — writes a fresh node's secrets dir (ADR-0066 D-J; declared deviation L-13/L-14, R-4).
# Caller: runbook v2 §2 (first install), through deploy/release/deploy_rehearsal.sh; the rehearsal's secrets helper.
# Usage: render-secrets.sh <secrets_dir>
# Inputs: <secrets_dir> — absent or empty (it is created 0700). Never overwrites: any existing target file is a refusal.
# Writes (umask 077: dir 0700, files 0600, owned by the caller): one <process>.secret.env per deployed process holding
#   only that process's secrets (its DSN composed with pg:5432/humaux, its pepper / token key), migrate.secret.env
#   (HUMAUX_MIGRATOR_PG_DSN, the superuser path, L-13, plus the HUMAUX_ROLE_PASSWORD_* values `roles rotate` sets: only
#   the migrate one-shot loads them, never a resident), dr.secret.env (the maintenance DSN again, same role and
#   password, at the host-network address 127.0.0.1:<HUMAUX_PG_PORT>: `dr` runs with network_mode host, where pg:5432
#   is not PostgreSQL; ADR-0066 review fix 6), pg.secret.env (PGBACKREST_REPO1_CIPHER_PASS) and pg_superuser
#   (POSTGRES_PASSWORD_FILE). HUMAUX_PG_PORT comes from <secrets_dir>/../node.env when that file exists (runbook §1
#   layout: <node dir>/secrets), else 5432. Values come from `openssl rand -hex`. The provider route keys stay EMPTY for the operator:
#   DASHSCOPE_API_KEY (retrieval-worker.secret.env) and HUMAUX_PRIVATE_WORKER_{CREDENTIALS,DNS_PINS,EGRESS_RECIPIENTS,
#   REGIONS} + the provider key the credential map names (private-worker.secret.env); the runbook step names them.
# Output (stdout): file and key NAMES only, never a value.
# Exit: 0 = written; 2 = usage; 3 = refused (a target file exists, or openssl is missing); 1 = a write failed.
# ponytail: openssl on the operator host is assumed; a node without it renders on another host and copies the dir.
set -eu
[ $# -eq 1 ] || { echo "usage: render-secrets.sh <secrets_dir>" >&2; exit 2; }
DIR=$1
command -v openssl >/dev/null 2>&1 || { echo "render-secrets: refused: missing object: openssl" >&2; exit 3; }
umask 077
FILES="pg_superuser pg.secret.env migrate.secret.env gateway.secret.env retrieval-worker.secret.env private-worker.secret.env consolidation-worker.secret.env maintenance.secret.env dr.secret.env admin.secret.env"
for f in $FILES; do
  [ ! -e "$DIR/$f" ] || { echo "render-secrets: refused: $DIR/$f exists (secrets are rendered once; rotation is runbook §10)" >&2; exit 3; }
done
NODE_ENV=$(dirname "$DIR")/node.env
PG_PORT=5432
if [ -f "$NODE_ENV" ]; then
  PG_PORT=$(sed -n 's/^HUMAUX_PG_PORT=//p' "$NODE_ENV" | tail -n 1)
  case $PG_PORT in ''|*[!0-9]*) echo "render-secrets: refused: HUMAUX_PG_PORT in $NODE_ENV is not a port" >&2; exit 3 ;; esac
fi
echo "render-secrets: HUMAUX_PG_PORT=$PG_PORT (dr.secret.env host 127.0.0.1)"
mkdir -p "$DIR"
chmod 0700 "$DIR"
rand() { openssl rand -hex "$1"; }
DB=pg:5432/humaux
dsn() { printf 'postgres://%s@%s' "$1:$2" "${3:-$DB}"; }
SUPER=$(rand 24); CIPHER=$(rand 32); PEPPER=$(rand 32); TOKEN=$(rand 32)
P_GATEWAY=$(rand 24); P_RETRIEVAL=$(rand 24); P_PRIVATE=$(rand 24); P_CONSOLIDATION=$(rand 24)
P_MAINTENANCE=$(rand 24); P_ADMIN=$(rand 24); P_BATCH=$(rand 24); P_PUBLIC=$(rand 24)
put() { # $1 = file, then KEY=VALUE lines on stdin; prints the file and its key names
  cat > "$DIR/$1"
  chmod 0600 "$DIR/$1"
  echo "render-secrets: wrote $DIR/$1 (keys: $(grep -E '^[A-Z0-9_]+=' "$DIR/$1" | cut -d= -f1 | tr '\n' ' '))"
}
printf '%s' "$SUPER" > "$DIR/pg_superuser"; chmod 0600 "$DIR/pg_superuser"; echo "render-secrets: wrote $DIR/pg_superuser"
put pg.secret.env <<EOT
PGBACKREST_REPO1_CIPHER_PASS=$CIPHER
EOT
put migrate.secret.env <<EOT
HUMAUX_MIGRATOR_PG_DSN=$(dsn postgres "$SUPER")
HUMAUX_ROLE_PASSWORD_ADMIN=$P_ADMIN
HUMAUX_ROLE_PASSWORD_BATCH_ISSUER=$P_BATCH
HUMAUX_ROLE_PASSWORD_CONSOLIDATION_WORKER=$P_CONSOLIDATION
HUMAUX_ROLE_PASSWORD_GATEWAY=$P_GATEWAY
HUMAUX_ROLE_PASSWORD_MAINTENANCE=$P_MAINTENANCE
HUMAUX_ROLE_PASSWORD_PRIVATE_WORKER=$P_PRIVATE
HUMAUX_ROLE_PASSWORD_PUBLIC_WORKER=$P_PUBLIC
HUMAUX_ROLE_PASSWORD_RETRIEVAL_WORKER=$P_RETRIEVAL
EOT
put gateway.secret.env <<EOT
HUMAUX_GATEWAY_PG_DSN=$(dsn role_gateway "$P_GATEWAY")
HUMAUX_GATEWAY_CREDENTIAL_PEPPER_HEX=$PEPPER
HUMAUX_GATEWAY_CREDENTIAL_PEPPER_PREVIOUS_HEX=
HUMAUX_GATEWAY_TOKEN_HMAC_KEY=$TOKEN
HUMAUX_GATEWAY_TOKEN_HMAC_KEY_PREVIOUS=
EOT
put retrieval-worker.secret.env <<EOT
HUMAUX_RETRIEVAL_WORKER_PG_DSN=$(dsn role_retrieval_worker "$P_RETRIEVAL")
DASHSCOPE_API_KEY=
EOT
put private-worker.secret.env <<EOT
HUMAUX_PRIVATE_WORKER_PG_DSN=$(dsn role_private_worker "$P_PRIVATE")
HUMAUX_PRIVATE_WORKER_CREDENTIALS=
HUMAUX_PRIVATE_WORKER_DNS_PINS=
HUMAUX_PRIVATE_WORKER_EGRESS_RECIPIENTS=
HUMAUX_PRIVATE_WORKER_REGIONS=
EOT
put consolidation-worker.secret.env <<EOT
HUMAUX_CONSOLIDATION_WORKER_PG_DSN=$(dsn role_consolidation_worker "$P_CONSOLIDATION")
EOT
# The maintenance pepper is the gateway's (one credential hash space); the retrieval DSN serves `projection rebuild`.
put maintenance.secret.env <<EOT
HUMAUX_MAINTENANCE_PG_DSN=$(dsn role_maintenance "$P_MAINTENANCE")
HUMAUX_MAINTENANCE_CREDENTIAL_PEPPER_HEX=$PEPPER
HUMAUX_RETRIEVAL_WORKER_PG_DSN=$(dsn role_retrieval_worker "$P_RETRIEVAL")
EOT
# dr (network_mode host): the same role and password, at the published address (backup / restore drill / pitr read
# only this key from it).
put dr.secret.env <<EOT
HUMAUX_MAINTENANCE_PG_DSN=$(dsn role_maintenance "$P_MAINTENANCE" "127.0.0.1:$PG_PORT/humaux")
EOT
put admin.secret.env <<EOT
HUMAUX_ADMIN_PG_DSN=$(dsn role_admin "$P_ADMIN")
EOT
echo "render-secrets: operator fills: retrieval-worker.secret.env:DASHSCOPE_API_KEY private-worker.secret.env:HUMAUX_PRIVATE_WORKER_CREDENTIALS private-worker.secret.env:HUMAUX_PRIVATE_WORKER_DNS_PINS private-worker.secret.env:HUMAUX_PRIVATE_WORKER_EGRESS_RECIPIENTS private-worker.secret.env:HUMAUX_PRIVATE_WORKER_REGIONS (+ the provider key the credential map names)"

# Deploy runbook v2 — the container bundle: install, verify, release, rollback, operate

> Scope: the **ordered, literal** steps that stand a Humaux node up from release images, prove it is up, move it
> to a new release and back, and operate it (ADR-0066). Semantics live elsewhere and are only pointed at:
> process and probe semantics `docs/ops/supervision.md`, every environment key `docs/architecture/env_vars.md`,
> load sizing `docs/ops/soak.md`, the evidence behind the delivery claim `docs/ops/delivery_point_report.md`.
>
> **How to run it.** Every executable step is a fenced `sh` block directly preceded by a marker
> `<!-- step: <ID> expect: <exit code> [match: <fixed string>] [value: <KEY>=<ERE>] -->`. A step is never pasted
> into a shell: it runs through the executor, from the node's checkout root (the directory that holds `deploy/`
> and `docs/`), as `sh deploy/release/deploy_rehearsal.sh run <ID>`; `--list` prints the ids in this file's order
> and `--show <ID>` prints one step. The executor runs the whole block under `env -i` (no toolchain, no profile,
> only `PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin`, `HOME=$HUMAUX_NODE_DIR/home`, `HUMAUX_NODE_DIR`,
> `HUMAUX_NODE_SIZING`, `HUMAUX_NODE_PROJECT` and the values captured by earlier steps) and writes
> `$HUMAUX_NODE_DIR/evidence/exec.log` itself (appendix A). Text outside the blocks is explanation; nothing outside
> a block is ever run. A step whose result is not its `expect` / `match` is a **STOP**: report it, never work around
> it (appendix A, "improvisation").

## 0. What this node is

One Docker Compose project per node (`deploy/compose/prod.yml`), started only through `deploy/release/compose.sh`
(below: "the compose wrapper"), which adds `--env-file deploy/env/sizing-$HUMAUX_NODE_SIZING.env --env-file
$HUMAUX_NODE_DIR/node.env -p $HUMAUX_NODE_PROJECT`. The node has **no Rust toolchain and needs no repository
code**: every binary is in a release image, the migrations are embedded in `humaux-maintenance`, and every step
below runs images, the compose wrapper and POSIX tools.

| service | image | uid:gid (+ groups) | role |
|---|---|---|---|
| `netns` | pause (digest-pinned) | 65535 | anchor of the shared network namespace; publishes the gateway on `127.0.0.1` only |
| `pg` | `humaux-pg:<tag>` (card 37: PostgreSQL 18 + pgBackRest) | 999 inside | the database; pgBackRest repository on its own host filesystem |
| `qdrant` | qdrant unprivileged (digest-pinned) | 1000 | the vector index (rebuilt from PostgreSQL, never backed up) |
| `private-rpc` / `private-distill` | `humaux-private-worker:<tag>` | 10103:10202 | inference RPC server / distill dispatcher |
| `retrieval-rpc` / `retrieval-serve` | `humaux-retrieval-worker:<tag>` | 10102:10201 | retrieval RPC server / projection runner |
| `consolidation` | `humaux-consolidation-worker:<tag>` | 10104 (+10202) | client of the inference socket |
| `maintenance-health` / `maintenance-serve` | `humaux-maintenance:<tag>` | 10105 | health gauges / resident sweeps |
| `gateway` | `humaux-gateway:<tag>` | 10101 (+10201) | MCP endpoint, client of the retrieval socket |
| `prometheus`, `alertmanager`, `otel-collector` | digest-pinned | image default | observability (30 d) |
| one-shots `admin`, `ops`, `migrate`, `dr` (profile `ops`) | `humaux-admin` / `humaux-ops` / `humaux-dr` | 10106 / 10105 / 10107 / 0 (`DAC_READ_SEARCH` only) | CLI, maintenance doors, migrator (superuser DSN), backup / restore / deploy-check |
| `alert-sink`, `scratch-*` (profile `rehearsal`) | python / curl (digest-pinned) | 10199 / the twins' uids | acceptance drills (§A) |

The four peer-credential participants run as four distinct uids (Baseline §4.2, ADR-0012); the two socket
volumes are `0750` with one pair group each, so only the client of a pair can reach its server's socket, and each
server refuses any other uid (ADR-0066 D-K/D-L/D-M). `deploy-check --running` (step R10) proves the uids, the
cgroup limits and the hardening on the running containers; a same-uid check is not a property one machine can
fake, which is why §A1 proves it with four scratch identities. The network layout is ADR-0066 D-F: pg and Qdrant on
the project bridge, every Humaux process and the observability trio in the namespace of `netns`, the ops listeners
on `127.0.0.1:19101-19108` inside it.

## 1. Prerequisites and the node directory

**Host facts.** Production is a Linux arm64 host of the §67.2 class (4 vCPU, 24 GB; sized against the 22 GiB
floor, `deploy/env/sizing-a5.env`). The rehearsal node is a compose project on the development Mac (Docker
Desktop VM, MemTotal 5 922 MiB since 2026-10-07; `deploy/env/sizing-rehearsal.env`, 3 908 MiB of ceilings). Every
number in both sizing files is a **dev-host start value, A5 re-measure required** (open item O-1, ADR-0066 R-10):
§8.1 keeps its "(dev-host)" title until `a5_load_remeasure` passes on the A5 host.

**Tools on the host:** `docker` with the compose plugin, `sed`, `awk`, `grep`, `curl`, `find`, `od`, `tar`,
`gzip`, `sha256sum` or `shasum`; nothing else (step P1 checks them).

**The node directory** (`$HUMAUX_NODE_DIR`, owned by the operator; every path in `node.env` is absolute):

| path | what | mode |
|---|---|---|
| `node.env` | from `deploy/env/node.env.example`: project, image tag, every directory below, network, ports, node identity | 0600 or 0644 (no secret) |
| `providers.env` | from `deploy/env/providers.env.example`: embedding provider and the reasoning route of the smoke tenants (no secret) | 0644 |
| `release.next` | one line: the tag of the release to move to (only for §R) | 0644 |
| `checkout/` | the release's `deploy/`, `docs/ops/runbook.md`, `migrations/0011_roles_and_grants.sql` and the one-line file `CHECKOUT_TREE` (`tree=… runbook=… roles=…`, the git ids the manifest's `CHECKOUT` line pins): the unpacked `humaux-checkout-<tag>.tar.gz` of `releases/` (a `git archive` of the release commit made on the build host; verify `humaux-checkout-<tag>.sha256` first); the executor runs from here, and `HUMAUX_NODE_DEPLOY_DIR` is its `deploy/`. A release with a different checkout is unpacked beside it as `checkout-<tag>/` (§R) | read-only for services |
| `secrets/` (`HUMAUX_SECRETS_DIR`) | the per-process `*.secret.env`, `migrate.secret.env`, `dr.secret.env`, `pg.secret.env`, `pg_superuser` | dir 0700, files 0600 |
| `releases/` (`HUMAUX_NODE_RELEASES_DIR`) | `release-<tag>.manifest` per release, and for a shipped release `humaux-<tag>.tar.gz` + `humaux-<tag>.sha256` (images) and `humaux-checkout-<tag>.tar.gz` + `humaux-checkout-<tag>.sha256` (its checkout) | 0644 |
| `evidence/` | the executor's `exec.log`, `values.env`, `steps/` (and `HUMAUX_NODE_EVIDENCE_DIR` for `dr` evidence; its `alerts/` (mode 1733: alert-sink, uid 10199, creates and appends `alert_receipts.jsonl`; other uids cannot list it, and the 0700 parent keeps host users out) for the alert receipts) | 0700 |
| `smoke/` | the smoke tenants' receipts, API-key header files and canary tokens (written by §3 / §7) | 0700 |
| `rendered/`, `alert-urls/` | the rendered observability configs (step R8) and the two Alertmanager URL files `log_sink.url`, `watchdog.url` (the operator's; during §A they point at `http://127.0.0.1:19194/log` and `/watchdog`) | dirs 0755, files 0644: R8 renders under `umask 022`, because Prometheus and Alertmanager run as their images' unprivileged user and must read them; nothing in them is secret (the sha, the URL file paths). Declared limit L-19: the two URL files are world-readable on the node; reopening signal: a URL that carries a secret token (move to a `user:`-pinned Alertmanager or a secret-bearing file mount, card 53) |
| `home/` | `HOME` of every step | 0700 |

**Secrets, once per node** (ADR-0066 D-J; declared deviations L-13 / L-14). Before P1 and outside the executor,
because the operator edits the result by hand: the bundle's renderer `deploy/release/render-secrets.sh` (one
argument, the secrets directory `<node dir>/secrets`, which must not exist yet) writes every file 0600 under a 0700
directory from `openssl rand` and prints names only; it is not a Docker, Humaux or toolchain command. Write
`node.env` first: `dr.secret.env` (the `dr` one-shot's copy of the maintenance DSN, same role and password, because
`dr` runs on the host network) points at `127.0.0.1:<HUMAUX_PG_PORT>` read from `<node dir>/node.env` (5432 when the
file is absent); after changing `HUMAUX_PG_PORT`, edit its port by hand. Then fill, by
editing the files,
the provider route keys it names: `DASHSCOPE_API_KEY` (retrieval worker), `HUMAUX_PRIVATE_WORKER_EGRESS_RECIPIENTS`
(`<HUMAUX_NODE_ROUTE_EGRESS_PROCESSOR_ID>=<endpoint host>`), `HUMAUX_PRIVATE_WORKER_REGIONS`, the key variable
named by `HUMAUX_NODE_ROUTE_KEY_ENV` in `providers.env` (for example `MINIMAX_API_KEY=…`), and
`HUMAUX_PRIVATE_WORKER_DNS_PINS` when the node's resolver is not trusted for the provider host (§10.5). Leave
`HUMAUX_PRIVATE_WORKER_CREDENTIALS` empty: step O4 writes it. **Write the backup password**
(`PGBACKREST_REPO1_CIPHER_PASS` in `pg.secret.env`) down away from the node (§11).

**The migrator prerequisite** (L-13, plan amendment 5). `migrate.secret.env` holds `HUMAUX_MIGRATOR_PG_DSN`, the
superuser of the bundle's own PostgreSQL, and the eight `HUMAUX_ROLE_PASSWORD_*` values; only the `migrate`
one-shot loads it, never a resident service (`deploy-check --compose-json` / `--env` refuse any other placement).
It stays on the node permanently: a declared deviation until OpenBao dynamic credentials (card 54). A managed
PostgreSQL with a non-superuser migrator is not this bundle; for it see §R "Migration 0210 and a non-superuser
migrator".

**The pgBackRest repository filesystem** (card 37, ADR-0064), before the first install: a fixed-size filesystem
outside Docker's data root, owned by uid:gid 999:999 (the `postgres` user of the pinned image), mounted where
`HUMAUX_PG_REPO_DIR` points. On a Linux node, as root:

```text
fallocate -l 12G /srv/humaux/pgbackrest.img && mkfs.ext4 -q -m 0 /srv/humaux/pgbackrest.img && install -d /srv/humaux/pgbackrest
# /etc/fstab:
# /srv/humaux/pgbackrest.img /srv/humaux/pgbackrest ext4 loop,nodev,nosuid,noexec 0 2
mount /srv/humaux/pgbackrest && chown 999:999 /srv/humaux/pgbackrest && chmod 0750 /srv/humaux/pgbackrest
```

It takes 12 GiB of the disk at once and never more; when it is full, backups stop, the database does not. It is a
host bind with `create_host_path: false`, never a Docker volume, so `down -v` or a volume prune cannot delete it.

<!-- step: P1 expect: 0 match: PREFLIGHT ok -->
```sh
nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
for t in docker sed awk grep curl find od tar gzip; do
  command -v "$t" >/dev/null || { echo "preflight: missing tool $t"; exit 1; }
done
command -v sha256sum >/dev/null || command -v shasum >/dev/null || { echo "preflight: missing tool sha256sum"; exit 1; }
docker compose version
for f in node.env providers.env; do [ -r "$HUMAUX_NODE_DIR/$f" ] || { echo "preflight: missing $HUMAUX_NODE_DIR/$f"; exit 1; }; done
[ "$(nv HUMAUX_NODE_PROJECT)" = "$HUMAUX_NODE_PROJECT" ] || { echo "preflight: HUMAUX_NODE_PROJECT differs from node.env"; exit 1; }
[ "$(nv HUMAUX_NODE_DEPLOY_DIR)" = "$PWD/deploy" ] || { echo "preflight: HUMAUX_NODE_DEPLOY_DIR is not $PWD/deploy"; exit 1; }
[ "$(nv HUMAUX_NODE_ENV_FILE)" = "$HUMAUX_NODE_DIR/node.env" ] || { echo "preflight: HUMAUX_NODE_ENV_FILE is not $HUMAUX_NODE_DIR/node.env"; exit 1; }
for k in HUMAUX_SECRETS_DIR HUMAUX_NODE_EVIDENCE_DIR HUMAUX_NODE_RELEASES_DIR HUMAUX_OBSERVABILITY_RENDERED_DIR HUMAUX_ALERTMANAGER_URL_DIR HUMAUX_PG_REPO_DIR; do
  v=$(nv "$k"); case $v in /*) ;; *) echo "preflight: $k is not an absolute path"; exit 1 ;; esac
  [ -d "$v" ] || { echo "preflight: $k=$v is not a directory"; exit 1; }
done
[ -r "$PWD/migrations/0011_roles_and_grants.sql" ] || { echo "preflight: the checkout lacks migrations/0011_roles_and_grants.sql"; exit 1; }
for p in "$(nv HUMAUX_NODE_GATEWAY_HOST_PORT)" "$(nv HUMAUX_PG_PORT)"; do
  rc=0; curl -s --max-time 2 "telnet://127.0.0.1:$p" </dev/null >/dev/null 2>&1 || rc=$?
  [ "$rc" = 7 ] || { echo "preflight: 127.0.0.1:$p is in use (an environment collision: STOP)"; exit 1; }
done
FREE_KB=$(df -Pk "$HUMAUX_NODE_DIR" | awk 'NR == 2 { print $4 }')
[ "$FREE_KB" -ge 20971520 ] || { echo "preflight: less than 20 GiB free under $HUMAUX_NODE_DIR"; exit 1; }
MEM_MIB=$(( $(docker info --format '{{.MemTotal}}') / 1048576 ))
SUM_MIB=$(awk -F= '/^HUMAUX_SIZE_[A-Z_]*_MEM=/ { s += $2 } END { print s }' "deploy/env/sizing-$HUMAUX_NODE_SIZING.env")
echo "preflight: docker MemTotal=${MEM_MIB} MiB, ceilings of sizing $HUMAUX_NODE_SIZING = ${SUM_MIB} MiB"
if [ "$HUMAUX_NODE_SIZING" = a5 ]; then
  sh deploy/release/budget_sums.sh --mem-total-mib "$MEM_MIB" deploy/env/sizing-a5.env deploy/env/sizing-rehearsal.env
else
  [ "$MEM_MIB" -gt "$SUM_MIB" ] || { echo "preflight: the ceilings do not fit the Docker memory"; exit 1; }
fi
echo "PREFLIGHT ok"
```

<!-- step: P2 expect: 0 match: SECRETS ok -->
```sh
nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
pv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/providers.env" | tail -n 1; }
S=$(nv HUMAUX_SECRETS_DIR)
[ -n "$(find "$S" -maxdepth 0 -type d -perm 0700)" ] || { echo "secrets: $S is not a 0700 directory"; exit 1; }
for f in pg_superuser pg.secret.env migrate.secret.env gateway.secret.env retrieval-worker.secret.env private-worker.secret.env consolidation-worker.secret.env maintenance.secret.env admin.secret.env dr.secret.env; do
  [ -n "$(find "$S/$f" -type f -perm 0600 2>/dev/null)" ] || { echo "secrets: $S/$f is missing or not 0600"; exit 1; }
done
KEYENV=$(pv HUMAUX_NODE_ROUTE_KEY_ENV)
for kv in retrieval-worker.secret.env:DASHSCOPE_API_KEY private-worker.secret.env:HUMAUX_PRIVATE_WORKER_EGRESS_RECIPIENTS private-worker.secret.env:HUMAUX_PRIVATE_WORKER_REGIONS "private-worker.secret.env:$KEYENV"; do
  grep -Eq "^${kv#*:}=.+" "$S/${kv%%:*}" || { echo "secrets: ${kv#*:} is empty in ${kv%%:*} (the operator fills it, §1)"; exit 1; }
done
grep -q "^HUMAUX_PRIVATE_WORKER_EGRESS_RECIPIENTS=.*$(pv HUMAUX_NODE_ROUTE_EGRESS_PROCESSOR_ID)=" "$S/private-worker.secret.env" \
  || { echo "secrets: HUMAUX_PRIVATE_WORKER_EGRESS_RECIPIENTS does not name HUMAUX_NODE_ROUTE_EGRESS_PROCESSOR_ID"; exit 1; }
for d in evidence smoke home; do mkdir -p "$HUMAUX_NODE_DIR/$d"; chmod 0700 "$HUMAUX_NODE_DIR/$d"; done
A="$(nv HUMAUX_NODE_EVIDENCE_DIR)/alerts"  # alert-sink (uid 10199, no capabilities) appends its receipts here
mkdir -p "$A"; chmod 1733 "$A"
echo "SECRETS ok (names only)"
```

## 2. First install (R1–R10)

The release to install is the tag in `node.env` (`HUMAUX_IMAGE_TAG`, with `HUMAUX_PG_IMAGE=humaux-pg:<tag>`). It is
built on the build host, never on the node (**R0**, not a step here): `deploy/release/build.sh <sha40> --sizing
deploy/env/sizing-<profile>.env` compiles inside a memory-capped builder container and packages COPY-only images
(ADR-0066 D-A as ruled by R-2); a production `<sha40>` is a commit on main. It prints one line per image,
`IMAGE humaux-<target>:<tag> id=<image id> size=<bytes> binary=<binary> git_sha=<sha40>`, and writes them to
`release-<tag>.manifest`: the manifest is the identity every later check compares against. To ship: an image archive
(Docker's `save`) of the manifest's images through `gzip` into `humaux-<tag>.tar.gz`, and `humaux-<tag>.sha256` over the tarball
and the manifest; copy the three files (and the checkout pair) into `releases/` **over ssh from the build host**
(`scp` / `rsync -e ssh`): the `.sha256` files travel with the archives, so they detect corruption, not a substituted
bundle — the authenticated copy is the trust anchor (declared deviation L-21, ADR-0066; never stage a release through
a shared drive, an artifact store or another person). On the rehearsal node the images are already local and step R1
only checks them.

<!-- step: R1 expect: 0 match: IMAGES ok -->
```sh
nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
TAG=$(nv HUMAUX_IMAGE_TAG); REL=$(nv HUMAUX_NODE_RELEASES_DIR); M="$REL/release-$TAG.manifest"
[ -r "$M" ] || { echo "images: missing manifest $M"; exit 1; }
[ "$(nv HUMAUX_PG_IMAGE)" = "humaux-pg:$TAG" ] || { echo "images: HUMAUX_PG_IMAGE is not humaux-pg:$TAG"; exit 1; }
if [ -r "$REL/humaux-$TAG.tar.gz" ]; then
  if command -v sha256sum >/dev/null; then (cd "$REL" && sha256sum -c "humaux-$TAG.sha256"); else (cd "$REL" && shasum -a 256 -c "humaux-$TAG.sha256"); fi
  gzip -dc "$REL/humaux-$TAG.tar.gz" | docker load
else
  echo "images: no tarball for $TAG in $REL; the images must already be local (build host or rehearsal)"
fi
n=0
for img in $(awk '$1 == "IMAGE" || $1 == "PGIMAGE" { print $2 }' "$M"); do
  docker image inspect "$img" >/dev/null || { echo "images: $img is not loaded"; exit 1; }
  n=$((n + 1))
done
echo "IMAGES ok $n images of $TAG"
```

R2 is the release gate before anything starts: the four manifest comparisons of every image (image id, the
`org.opencontainers.image.revision` label, the binary name, the sha its own `--version` prints; ADR-0066 D-R),
then the unresolved compose document and the values / secrets files (every service has a `user:`, the peer-uid
keys agree with the compose uids, no dev-only key such as `*_ALLOW_SAME_UID` is set, the migrator DSN and the role
passwords exist only in `migrate.secret.env` and only `migrate` loads it, and every runtime key of every process —
the list shipped in the image at `/usr/share/humaux/env/example` — is declared for its services, every secret with a
non-empty value: an empty secret file stops here, before `up`, ADR-0066 D-N / D-R (a)). Only the unresolved document (`--no-env-resolution`) ever
crosses the pipe, so no secret value does (D-J). The release check also compares the checkout's `CHECKOUT_TREE`
with the manifest's `CHECKOUT` line (review fix 9: a first install from a checkout that is not the release's stops
here too). Any non-zero exit is a STOP.

<!-- step: R2 expect: 0 match: PRECHECK ok -->
```sh
C="sh deploy/release/compose.sh"
nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
TAG=$(nv HUMAUX_IMAGE_TAG); M="$(nv HUMAUX_NODE_RELEASES_DIR)/release-$TAG.manifest"
SHA=$(sed -n 's/^IMAGE .* git_sha=\([0-9a-f]\{40\}\).*/\1/p' "$M" | head -n 1)
case "$TAG" in *-"$(printf '%s' "$SHA" | cut -c1-12)") ;; *) echo "precheck: tag $TAG does not end in the manifest's sha $SHA"; exit 1 ;; esac
[ -r CHECKOUT_TREE ] || { echo "precheck: $PWD/CHECKOUT_TREE is missing (unpack humaux-checkout-$TAG.tar.gz, §1)"; exit 1; }
DR=$(awk -v r="humaux-dr:$TAG" '$1 == "IMAGE" && $2 == r { sub(/^id=/, "", $3); print $3 }' "$M")  # the verifier, checked from the host before it runs
GOT=$(docker image inspect -f '{{.Id}}' "humaux-dr:$TAG" 2>/dev/null) || GOT="<not loaded>"
[ -n "$DR" ] && [ "$GOT" = "$DR" ] \
  || { echo "precheck: humaux-dr:$TAG is $GOT; the manifest's dr image is ${DR:-<none>}"; exit 1; }
$C run --rm -T dr deploy-check --release "$TAG" --manifest "$M" --expect-sha "$SHA" --checkout-tree "$(cat CHECKOUT_TREE)"
$C --profile ops config --format json --no-env-resolution | $C run --rm -T dr deploy-check --compose-json - --env \
  --values-dir "$(nv HUMAUX_NODE_DEPLOY_DIR)/env/values" --secrets-dir "$(nv HUMAUX_SECRETS_DIR)" \
  --examples-dir /usr/share/humaux/env/example
echo "PRECHECK ok $TAG git_sha=$SHA"
```

R3 starts PostgreSQL alone, creates the pgBackRest stanza and checks the repository: `backup check` refuses
(`repo_shares_pgdata_fs`) a repository on the database's own filesystem (an unmounted image looks like that) and
must report `repo_cipher=aes-256-cbc` and `weak_subkeys=0`. Archiving runs from the first segment, so the stanza
comes before any write.

<!-- step: R3 expect: 0 match: weak_subkeys=0 -->
```sh
C="sh deploy/release/compose.sh"
$C up -d --wait --wait-timeout 300 pg
$C exec -T --user postgres pg pgbackrest --stanza=humaux stanza-create
$C run --rm -T dr backup check
```

R4 creates the seven 0011 LOGIN roles with the passwords of `migrate.secret.env` (client-side SCRAM verifiers) and
the owner NOLOGIN, before any migration (ADR-0059 D-A; `migrate` refuses `missing object: role <name>` without
it). The placeholder file is mounted read-only into the one-shot; the command prints only generated values, and
none is generated because every `HUMAUX_ROLE_PASSWORD_*` is set — the filter keeps a value off the step log in any
case.

<!-- step: R4 expect: 0 -->
```sh
C="sh deploy/release/compose.sh"
O="$HUMAUX_NODE_DIR/evidence/roles-R4.out"
if ! $C run --rm -T -v "$PWD/migrations/0011_roles_and_grants.sql:/usr/share/humaux/0011_roles_and_grants.sql:ro" migrate \
     roles rotate --create-missing --roles-sql /usr/share/humaux/0011_roles_and_grants.sql \
     --actor runbook-v2 --reason "runbook v2 R4 first install" --ticket "$HUMAUX_NODE_PROJECT" --step-up-auth runbook-v2-executor > "$O" 2>&1; then
  sed '/^HUMAUX_ROLE_PASSWORD_/d' "$O"; rm -f "$O"; exit 1
fi
sed '/^HUMAUX_ROLE_PASSWORD_/d' "$O"; rm -f "$O"
```

R5 applies the embedded migration set (no repository files: the set is inside the binary, ADR-0066 D-Q). Each
pending migration runs in one transaction: manifest precheck → SQL → postcheck → `ops.schema_migrations` row. One
migrator at a time (advisory lock `HXMIGRAT`, `lock_timeout = 30s`); a migration that queues behind a live
session's lock is refused with drift 0. It refuses `live_runtime_sessions:<role>=<n>` while a runtime role holds a
session in this database (OPS-9): on a first install nothing runs yet; on an upgrade U4 stops the workers first.
§46's drift gate refuses any applied migration whose text changed — the fix is a new migration, never an edit. The one exception is a reviewed no-schema-effect amendment (a precheck, postcheck or comment) whose old checksum its manifest lists under `accepted_prior_checksums`: `migrate` logs it, continues and never rewrites the ledger row (ADR-0082).

<!-- step: R5 expect: 0 match: migrate: pass ( -->
```sh
C="sh deploy/release/compose.sh"
$C run --rm -T migrate migrate
```

<!-- step: R6 expect: 0 -->
```sh
C="sh deploy/release/compose.sh"
O="$HUMAUX_NODE_DIR/evidence/roles-R6.out"
if ! $C run --rm -T -v "$PWD/migrations/0011_roles_and_grants.sql:/usr/share/humaux/0011_roles_and_grants.sql:ro" migrate \
     roles rotate --roles-sql /usr/share/humaux/0011_roles_and_grants.sql --role role_admin \
     --actor runbook-v2 --reason "runbook v2 R6 role_admin password" --ticket "$HUMAUX_NODE_PROJECT" --step-up-auth runbook-v2-executor > "$O" 2>&1; then
  sed '/^HUMAUX_ROLE_PASSWORD_/d' "$O"; rm -f "$O"; exit 1
fi
sed '/^HUMAUX_ROLE_PASSWORD_/d' "$O"; rm -f "$O"
```

R7 verifies the schema before any traffic: `rls-check` walks the §6.2.2 matrix row for row (every check `pass`,
the spec check `not_applicable: --spec` on a node; any `fail` is a STOP), and `deploy-check --roles-sql` runs the
five ADR-0059 role checks (names only; it logs in as every role over TCP with `scram-sha-256`, so SQLSTATE 28000 is
red by design).

<!-- step: R7 expect: 0 match: ROLES ok -->
```sh
C="sh deploy/release/compose.sh"
$C run --rm -T migrate rls-check
$C run --rm -T -v "$PWD/migrations/0011_roles_and_grants.sql:/usr/share/humaux/0011_roles_and_grants.sql:ro" migrate \
  deploy-check --roles-sql /usr/share/humaux/0011_roles_and_grants.sql
echo "ROLES ok"
```

R8 renders the observability configs with the sha the release reports about itself (every alert, the §42.1
Watchdog included, carries it as `git_sha`; §67.4). The renderer is POSIX sh + sed (ADR-0066 D-I). It renders under
`umask 022` and leaves both directories 0755 with 0644 files (§1, L-19): the executor's own `umask 077` would leave
them unreadable to Prometheus and Alertmanager on a Linux node.

<!-- step: R8 expect: 0 match: RENDER ok -->
```sh
C="sh deploy/release/compose.sh"
nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
umask 022
SHA=$($C run --rm -T admin version | sed -n 's/.* git_sha=\([0-9a-f]\{40\}\).*/\1/p')
[ -n "$SHA" ] || { echo "render: humaux-admin version printed no sha"; exit 1; }
sh deploy/prometheus/render.sh "$(nv HUMAUX_OBSERVABILITY_RENDERED_DIR)" "$SHA" /run/humaux-alert-urls
chmod -R u=rwX,go=rX "$(nv HUMAUX_OBSERVABILITY_RENDERED_DIR)"
chmod 0755 "$(nv HUMAUX_ALERTMANAGER_URL_DIR)"
for u in log_sink.url watchdog.url; do
  [ -s "$(nv HUMAUX_ALERTMANAGER_URL_DIR)/$u" ] || { echo "render: $(nv HUMAUX_ALERTMANAGER_URL_DIR)/$u is missing or empty"; exit 1; }
  chmod 0644 "$(nv HUMAUX_ALERTMANAGER_URL_DIR)/$u"
done
echo "RENDER ok git_sha=$SHA"
```

R9 starts every resident service in `depends_on` order — pg → private-rpc → retrieval-rpc → retrieval-serve →
consolidation → private-distill → maintenance-health → maintenance-serve → gateway → observability — each waiting
for its predecessor's own `--readyz` (healthchecks are readiness, never a restart signal; supervision.md §4).
Every resident has `restart: unless-stopped` (supervision.md §3, ADR-0066 L-2): Docker restarts it on every exit,
whatever the code, after a delay that doubles from 100 ms up to one minute. A service that exits 2 has a
configuration error that restarting cannot fix: it loops under that backoff, `up --wait` fails at its timeout, and
R10's `deploy-check --running` names it (`service_restarted:<svc>`). Fix the configuration (R2 catches most of it
before this point).

<!-- step: R9 expect: 0 -->
```sh
C="sh deploy/release/compose.sh"
$C up -d --wait --wait-timeout 300
```

R10 proves what is running: `deploy-check --running` inspects every container of the project (distinct uids, the
cgroup memory / swap / CPU / PID limits, read-only root, `cap_drop: ALL`, `no-new-privileges`, no dev-only key in
the container environment); the `admin` one-shot's `version` names the manifest's sha; Prometheus scrapes exactly the eight
resident ops listeners, all up.

<!-- step: R10 expect: 0 match: VERIFY ok -->
```sh
C="sh deploy/release/compose.sh"
nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
TAG=$(nv HUMAUX_IMAGE_TAG); M="$(nv HUMAUX_NODE_RELEASES_DIR)/release-$TAG.manifest"
SHA=$(sed -n 's/^IMAGE .* git_sha=\([0-9a-f]\{40\}\).*/\1/p' "$M" | head -n 1)
$C --profile ops config --format json --no-env-resolution | $C run --rm -T dr deploy-check --running --project "$HUMAUX_NODE_PROJECT" --compose-json -
$C run --rm -T admin version | grep -F "git_sha=$SHA"
i=0
until $C exec -T prometheus wget -qO- 'http://127.0.0.1:9090/api/v1/query?query=count%28up%7Bjob%3D~%22humaux-.%2A%22%7D%3D%3D1%29' | grep -q '"8"\]'; do
  i=$((i + 1)); [ "$i" -lt 24 ] || { echo "verify: fewer than 8 humaux targets are up after 120 s"; exit 1; }; sleep 5
done
echo "VERIFY ok git_sha=$SHA targets_up=8"
```

**After a host reboot or a dockerd restart.** Nothing is started by hand: every resident (pg, qdrant, netns, the
eight Humaux services, the observability set) comes back by its `unless-stopped` policy. The daemon ignores
`depends_on`, so a service that comes up before its dependency exits non-zero and is retried under the backoff until
the dependency answers; one-shots stay down. Docker starts these containers with a restart count of 0, so once the
host is up re-run step R10: green means every resident runs, healthy, on the manifest's sha; `service_restarted:<svc>`
names one that crashed since (read its logs, supervision.md §2). A service stopped on purpose (`stop`) stays stopped
across the reboot; after `down` nothing comes back.

## 3. Tenants and reasoning routes

### 3.0 The two smoke tenants (O1–O4)

Every node carries two smoke tenants, `smoke-a` and `smoke-b`, onboarded exactly like a customer tenant. They are
the subjects of every smoke test (§7), of the cross-tenant check and of the rollback proof (§R). Their API keys
are written as header files into `$HUMAUX_NODE_DIR/smoke/` (0700) and never printed.

<!-- step: O1 expect: 0 -->
```sh
C="sh deploy/release/compose.sh"
pv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/providers.env" | tail -n 1; }
$C run --rm -T ops deploy-init --provider "$(pv HUMAUX_NODE_EMBEDDING_PROVIDER)" --region "$(pv HUMAUX_NODE_EMBEDDING_REGION)" \
  --tpm "$(pv HUMAUX_NODE_EMBEDDING_TPM)" --rpm "$(pv HUMAUX_NODE_EMBEDDING_RPM)" \
  --actor runbook-v2 --reason "runbook v2 O1 deployment admission" --ticket "$HUMAUX_NODE_PROJECT" --step-up-auth runbook-v2-executor
```

<!-- step: O2 expect: 0 match: SMOKE TENANTS ok -->
```sh
C="sh deploy/release/compose.sh"
pv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/providers.env" | tail -n 1; }
D="$HUMAUX_NODE_DIR/smoke"
# ADR-0072: the first period ends at the next UTC month start; maintenance-serve's quota_renewal task renews it.
m=$(date -u +%m | sed 's/^0//'); y=$(date -u +%Y)
if [ "$m" -eq 12 ]; then y=$((y + 1)); m=1; else m=$((m + 1)); fi
PERIOD_END=$(printf '%04d-%02d-01T00:00:00Z' "$y" "$m")
for t in a b; do
  $C run --rm -T ops onboard tenant --name "smoke-$t" --owner-email "smoke-$t@$HUMAUX_NODE_PROJECT.invalid" \
    --plan-limit 1000 --period-end "$PERIOD_END" --scopes memory:write,context:read --key-name smoke \
    --provider "$(pv HUMAUX_NODE_EMBEDDING_PROVIDER)" --region "$(pv HUMAUX_NODE_EMBEDDING_REGION)" \
    --tenant-tpm "$(pv HUMAUX_NODE_SMOKE_TENANT_TPM)" --tenant-rpm "$(pv HUMAUX_NODE_SMOKE_TENANT_RPM)" \
    --actor runbook-v2 --reason "runbook v2 O2 smoke tenant" --ticket "$HUMAUX_NODE_PROJECT" --step-up-auth runbook-v2-executor > "$D/$t.out"
  if grep -q '^Authorization: Bearer ' "$D/$t.out"; then grep '^Authorization: Bearer ' "$D/$t.out" > "$D/$t.auth"; fi
  [ -s "$D/$t.auth" ] || { echo "onboard: smoke-$t printed no key and none is kept in $D/$t.auth"; exit 1; }
  sed '/^Authorization: Bearer /d' "$D/$t.out" > "$D/$t.receipt.json"; rm -f "$D/$t.out"
  : > "$D/$t.ids"
  for k in tenant_id workspace_id owner_user_id reasoning_domain_id; do
    v=$(sed -n "s/.*\"$k\": *\"\([0-9a-f-]\{36\}\)\".*/\1/p" "$D/$t.receipt.json" | head -n 1)
    [ -n "$v" ] || { echo "onboard: the smoke-$t receipt names no $k"; exit 1; }
    echo "$k=$v" >> "$D/$t.ids"
  done
  sed "s/^/smoke-$t /" "$D/$t.ids"
done
echo "SMOKE TENANTS ok"
```

O3 routes each smoke tenant's reasoning domain (ADR-0060 D-H): `register` one Profile@version from
`providers.env`, `bind` both derived purposes to it, `attest-health`. Both tenants declare the same
`--account-ref`, so their credential references may share one key variable (ADR-0060 D-J).

<!-- step: O3 expect: 0 match: ROUTES ok -->
```sh
C="sh deploy/release/compose.sh"
pv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/providers.env" | tail -n 1; }
D="$HUMAUX_NODE_DIR/smoke"
A="--actor runbook-v2 --ticket $HUMAUX_NODE_PROJECT --step-up-auth runbook-v2-executor"
for t in a b; do
  T=$(sed -n 's/^tenant_id=//p' "$D/$t.ids"); U=$(sed -n 's/^owner_user_id=//p' "$D/$t.ids"); R=$(sed -n 's/^reasoning_domain_id=//p' "$D/$t.ids")
  $C run --rm -T ops reasoning register --tenant "$T" --owner-user "$U" \
    --provider-id "$(pv HUMAUX_NODE_ROUTE_PROVIDER_ID)" --provider-model-id "$(pv HUMAUX_NODE_ROUTE_MODEL)" \
    --model-revision "$(pv HUMAUX_NODE_ROUTE_MODEL_REVISION)" --capabilities "$(pv HUMAUX_NODE_ROUTE_CAPABILITIES)" \
    --request-extras "$(pv HUMAUX_NODE_ROUTE_REQUEST_EXTRAS)" --account-ref "$(pv HUMAUX_NODE_ROUTE_ACCOUNT_REF)" \
    --endpoint-ref "$(pv HUMAUX_NODE_ROUTE_ENDPOINT)" --region "$(pv HUMAUX_NODE_ROUTE_REGION)" \
    --service-tier "$(pv HUMAUX_NODE_ROUTE_SERVICE_TIER)" --egress-processor-id "$(pv HUMAUX_NODE_ROUTE_EGRESS_PROCESSOR_ID)" \
    $A --reason "runbook v2 O3 register" > "$D/$t.route.json"
  P=$(sed -n 's/.*"profile_id": *"\([0-9a-f-]\{36\}\)".*/\1/p' "$D/$t.route.json" | head -n 1)
  V=$(sed -n 's/.*"profile_version": *\([0-9][0-9]*\).*/\1/p' "$D/$t.route.json" | head -n 1)
  F=$(sed -n 's/.*"credential_ref": *"\([0-9a-f-]\{36\}\)".*/\1/p' "$D/$t.route.json" | head -n 1)
  [ -n "$P" ] && [ -n "$V" ] && [ -n "$F" ] || { echo "routes: the register receipt of smoke-$t lacks profile_id / profile_version / credential_ref"; exit 1; }
  for purpose in PRIVATE_DISTILL_TEXT PRIVATE_CONSOLIDATE; do
    $C run --rm -T ops reasoning bind --tenant "$T" --domain "$R" --purpose "$purpose" --profile "$P" --profile-version "$V" $A --reason "runbook v2 O3 bind"
  done
  $C run --rm -T ops reasoning attest-health --tenant "$T" --profile "$P" --profile-version "$V" \
    --valid-for-secs "$(pv HUMAUX_NODE_ROUTE_ATTEST_VALID_SECS)" $A --reason "runbook v2 O3 attest"
  echo "credential_ref=$F" > "$D/$t.cred"
  echo "routes: smoke-$t profile=$P@$V credential_ref=$F"
done
echo "ROUTES ok"
```

O4 writes the private worker's credential map from the two register receipts (`<credential_ref>=<key variable
name>`, names only, ADR-0059 D-I) into `private-worker.secret.env` and restarts both private-worker modes so they
read it (a new credential reference needs a restart before traffic, L15).

<!-- step: O4 expect: 0 match: CREDENTIALS ok -->
```sh
C="sh deploy/release/compose.sh"
nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
pv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/providers.env" | tail -n 1; }
D="$HUMAUX_NODE_DIR/smoke"; F="$(nv HUMAUX_SECRETS_DIR)/private-worker.secret.env"; KEYENV=$(pv HUMAUX_NODE_ROUTE_KEY_ENV)
MAP="$(sed -n 's/^credential_ref=//p' "$D/a.cred")=$KEYENV,$(sed -n 's/^credential_ref=//p' "$D/b.cred")=$KEYENV"
awk -v map="$MAP" '/^HUMAUX_PRIVATE_WORKER_CREDENTIALS=/ { print "HUMAUX_PRIVATE_WORKER_CREDENTIALS=" map; next } { print }' "$F" > "$F.new"
chmod 0600 "$F.new"; mv "$F.new" "$F"
grep -c '^HUMAUX_PRIVATE_WORKER_CREDENTIALS=..*' "$F"
$C up -d --wait --wait-timeout 300 --no-deps --force-recreate private-rpc private-distill
echo "CREDENTIALS ok (names only)"
```

### 3.1 Reasoning routes — which LLM a domain uses (ADR-0060 D-H)

A freshly onboarded tenant's reasoning domain has **no route**: its distill and consolidation jobs park
`NO_DISTILL_BINDING` until an operator binds it. Every step is a `reasoning …` subcommand on the `ops` one-shot
(same exit codes, §77 flags and one-JSON-receipt rule as onboarding; a refusal names its `reason` and writes only
its DENIED audit row). `<A>` below means `--actor <who> --reason <why> --ticket <ref> --step-up-auth <evidence>`.

**Register** one Profile@version: `reasoning register --tenant <id> --owner-user <domain owner user id>
--provider-id <processor id> --provider-model-id <model> [--model-revision <catalog label>] --capabilities
TEXT,STRUCTURED_OUTPUT[,TOOL_CALLS|JSON_OBJECT…] --request-extras '<json object>' --account-ref <vendor account
reference text> --endpoint-ref https://<host>/<path> --region <region> --service-tier <tier>
--egress-processor-id <recipient uuid of this vendor/region> [--credential-ref <existing ref bound to this
account>] [--successor-of <profile id>] <A>`.

- `--request-extras` is required (`'{}'` for none): vendor fields such as a thinking switch are profile data; an
  adapter-owned key (`model`, `messages`, `tools`, `response_format`, `max_tokens`, …) is refused
  `request_extras_invalid`.
- The catalog row is append-only: declaring more capabilities than an existing (provider, model, revision) row is
  refused `capabilities_exceed_catalog` — use a new `--model-revision` label (convention `caps-<sorted
  capabilities joined by .>`; never sent on the wire).
- `--account-ref` is hashed (sha256) before it leaves the CLI. Profiles whose references will share one key
  variable **must** name the same account reference, or the worker refuses to boot (ADR-0060 D-J).
- The receipt prints `credential_map_entry: "<credential_ref>=<ENV_NAME>"`: add it to
  `HUMAUX_PRIVATE_WORKER_CREDENTIALS` in `private-worker.secret.env` with the variable that holds the key (§10.4;
  O4 is the worked example). The key never passes through the CLI.
- A re-run with the same values answers `existing`.

**Bind** a domain to it, both derived purposes separately: `reasoning bind --tenant <id> --domain <reasoning domain
id> --purpose PRIVATE_DISTILL_TEXT|PRIVATE_CONSOLIDATE --profile <profile id> --profile-version <n> <A>`. One
PINNED policy, exactly one candidate, one current binding. Refused: `purpose_not_bindable`, `owner_mismatch`,
`profile_disabled`, `profile_lacks_structured_output`.

**Attest health** — a bound route is admitted only with valid provider and account observations:
`reasoning attest-health --tenant <id> --profile <id> --profile-version <n> --valid-for-secs <n> <A>`.
`--valid-for-secs` has no default. Traffic renews a route on its own (`HUMAUX_PRIVATE_WORKER_HEALTH_RENEW_SECS`,
§10.4), so the value only has to cover the time until the first successful call and any quiet period you accept.
A route idle for longer parks `ROUTE_HEALTH_STALE` (no spend) until re-attested.

**Status** — `reasoning status --tenant <id>` lists every ACTIVE domain × purpose with its binding, profile,
provider/model, recipient, credential reference, the latest verdicts, `valid_until` and `health`: `UNBOUND`,
`MISSING`, `STALE`, `DENIED` or `ADMISSIBLE`.

**Switch model** (no restart, history kept): `register --successor-of <profile id>` with the new model / revision /
endpoint / capabilities, then `bind` the new Profile@version, then `attest-health`. Old rows stay. If the new
profile has a new credential reference, add its map entry and recreate `private-rpc` and `private-distill`
**before** `bind` (L15).

**Disable** one route at once: `reasoning profile-state --tenant <id> --profile <id> --profile-version <n>
--enabled false <A>`; the next admission refuses it (`reasoning route not admitted`), nothing is sent.
`--enabled true` re-enables it.

**Add a provider** (any OpenAI-compatible chat endpoint): mint one recipient uuid for that vendor/region, add
`<uuid>=<host>[|<host>]` to `HUMAUX_PRIVATE_WORKER_EGRESS_RECIPIENTS` and its region to
`HUMAUX_PRIVATE_WORKER_REGIONS` (and a DNS pin if the node's resolver is not trusted for the host, §10.5), put its
key under a variable name in `private-worker.secret.env`, `register` with `--egress-processor-id <uuid>`, add the
map entry, recreate the two private-worker services, `bind`, `attest-health`.

What to do when a job line or the status says:
- `NO_DISTILL_BINDING` / `UNBOUND` — the domain has no route: `register` (if needed) and `bind`.
- `CREDENTIAL_NOT_MAPPED` — the route's credential reference is not in the worker's map: add the register
  receipt's `credential_map_entry` with the right variable and recreate the worker.
- `ROUTE_HEALTH_STALE` / `STALE` / `MISSING` — no valid observation: check the provider, then `attest-health`.
  `ROUTE_HEALTH_DENIED` / `DENIED` after a 401: rotate the key (§10.4), then `attest-health`.
- `EGRESS_PROCESSOR_NOT_ALLOWED` / `EGRESS_HOST_NOT_ALLOWED` / `REGION_NOT_ALLOWED` — the deployment's lists do not
  cover the route: fix the lists (never the route) and recreate.
- `ENDPOINT_REJECTED` — the endpoint failed the §11.4 check before any request (not a bare `https` host, or the
  host resolves into a forbidden range). On a node whose resolver answers with a fake IP (198.18.0.0/15 and
  similar), pin the host (§10.5); a wrong endpoint is fixed with a successor profile, never by weakening the check.
- `TRANSPORT` when the job parks — the worker could not build the egress client (TLS / client setup on this node);
  nothing was sent. A `TRANSPORT` failure of a call that was sent is an outage (next bullet); a steady
  `dns_pin_deferred_total` with no distill output is the `DnsPinDeferred` alert (§10.5).
- `ROUTE_PROVIDER_MISMATCH` — a seam or cache defect, never a configuration choice: recreate the worker, keep the
  job line, file a defect.
- `PROFILE_LACKS_STRUCTURED_OUTPUT` — `register --successor-of` with the capability, then `bind` and
  `attest-health`.
- A provider outage is **not** parked: jobs retry with backoff and go DEAD at `max_attempts` (ADR-0060 D-G). Once
  it is back: `jobs requeue-dead --tenant <id> --error-class <class>` on the `ops` one-shot (§7.1).

### 3.2 Customer tenants

Onboarding is `humaux-maintenance` (the §4.2 operator-write process) on the `ops` one-shot — never raw SQL and
never `xtask e2e-seed` (the seed refuses any host but `127.0.0.1`; ADR-0053). It is the same command as O2 with
the customer's values: `onboard tenant --name <unique name> --owner-email <email> --plan-limit <n> --period-end
<RFC 3339> --scopes memory:write,context:read --key-name <name> --provider <embedding provider> --region <region>
--tenant-tpm <n> --tenant-rpm <n> [--workspace <name>]` plus the §77 fields `--actor --reason --ticket
--step-up-auth`. Every subcommand is one-shot and idempotent, prints ONE JSON receipt on stdout, and exits `0`
created/existing, `3` refused (a named `reason`, nothing written), `2` usage, `1` infrastructure.

It writes, in ONE transaction, the owner user (email stored unverified, §74 is post-go-live), the tenant
(`onboarding_name` = `--name`, the idempotency key), the OWNER membership, the reasoning domain, the entitlement
snapshot, the TENANT + two PURPOSE tiers, the workspace in `PROVISIONING` with its OWNER workspace membership and
zeroed checkpoint rows, the placement row and — only when the tenant was created — the API key; then issues the
quota window, ensures the Qdrant collection with its three payload indexes (`tenant_id`, `subject_ids`, `memory_id`), and
performs the VerifiedEmpty first activation (§6), which flips the workspace to `READY`. The receipt lists
`tenant_id`, `workspace_id`, `owner_user_id`, `reasoning_domain_id`, `api_key.fingerprint`, `admission_tiers`,
`placements`, `collection`, `activations[]` and `lifecycle`. **The API key is printed once**, as the line
`Authorization: Bearer <prefix>.<secret>` before the JSON, only when it was created: redirect stdout into a 0600
file, as O2 does. A re-run with the same `--name` writes nothing, prints `"outcome":"existing"` and no key: a lost
key is revoked (`apikey revoke --tenant <id> --key-name <name>`) and a new one issued (`apikey issue --tenant
--user --workspace --scopes --key-name <new name>`).

`--period-end` is the end of the tenant's **first** period only (the period starts at the onboarding second). From
then on `maintenance-serve`'s `quota_renewal` task (§5.1, ADR-0072) renews every ACTIVE tenant: from
`QUOTA_RENEWAL_LEAD_SECONDS` (14 days) before the end it stages the next period on the snapshot and issues its quota
window, contiguous and `QUOTA_RENEWAL_SUBSCRIPTION_MONTHS` long, with the snapshot's limit; the gateway switches to it
at the boundary by itself. Pick `--period-end` on the day of month the customer's periods should turn over, at most
the 28th: an anchor on the 29th–31st drifts to the 28th/29th after the first shorter month and stays there
(ADR-0072 L2). Onboarding always writes `subscription_period`; true calendar-month billing (`calendar_month`) has no
producer and is untested. A change to a tenant's `effective` entitlement drops its staged successor, which the next
daemon visit re-stages from the new value (ADR-0072 L3). Never give a far-future date to dodge
renewal: it hides a stopped daemon until the date arrives. To stop renewing a tenant, suspend it (ADR-0072 L1: there
is no cancel-at-period-end yet). `QuotaWindowRenewalMissing` (CRITICAL) fires when any renewing tenant's last window
ends within 7 days: check `maintenance_task_runs_total{task="quota_renewal",outcome="failed"}` and the daemon's
`/status`, then `sweep once` (§5.1) to renew at once.

More workspaces and users: `onboard workspace --tenant <id> --name <n> --owner <user id>`, `onboard user --tenant
<id> --email <e> --role OWNER|ADMIN|MEMBER [--workspace <id>]`. Repair steps after an interrupted run:
`placement ensure --tenant <id>`, `collection ensure`, `activate --tenant <id> --workspace <id>`; `status --tenant
<id>` shows workspaces + lifecycle, families, activation receipts, placement, key prefixes and tiers. A collection
created before card 24 lacks the `subject_ids` index, and one created before card 40d-1c-i lacks the `memory_id` keyword
index (ADR-0068 D-E); `collection ensure` PUTs every index idempotently. Until it does, the collection's generation
reads `collection_misconfigured` (a rebuild verify's E1 and onboarding both refuse), so run it once after deploying
40d-1c-i. The same holds for the `bm25` sparse vector (ADR-0083 D-B, T-RET-6b): run `humaux-maintenance collection
ensure` after deploying that change (it adds the vector with `PUT /collections/{c}/vectors/bm25`, idempotent). Until
then the retrieval worker writes dense-only and logs `collection lacks bm25 collection=<name> (run collection
ensure; a rebuild backfills)` once per pass; afterwards `projection rebuild` (or `projection verify`) re-projects the
dense-only points in place and its receipt's `bm25_missing_points` reads 0 (a verify reports `e6:bm25_missing=N`
until it does).

## 4. Environment

Every key, its reader and its kind is `docs/architecture/env_vars.md` (generated); the per-process lists the bundle
uses are `deploy/env/example/<process>.env` (generated from the same rows, dev-only keys excluded) and the secret
names `deploy/env/secret-fixture/` (empty values). Values: `deploy/env/values/<process>.env` (bundle constants, in
git), `$HUMAUX_SECRETS_DIR/<process>.secret.env` (secrets and the provider route), node values through `node.env`
(ADR-0066 D-C, D-J). Rules that are not obvious from the names:

- **Secrets never reach a log or argv.** Steps redirect any secret-bearing output into 0600 files (R4, O2).
- **Dev-only keys never reach a node.** `HUMAUX_<PROCESS>_ALLOW_SAME_UID` exists for the single-uid dev chain;
  `deploy-check --env` and `--running` are red when it is set (ADR-0066 D-K, RF-2).
- **If the node's resolver lies about a provider host, pin it** (§10.5); run proxy-free — a proxy makes the client
  CONNECT by hostname and the checked resolver is never consulted.
- **The gateway has no default write pair** (card 29 / ADR-0054): every write lands on the caller's own (tenant,
  workspace). `HUMAUX_GATEWAY_REMEMBER_TENANT_ID` / `_WORKSPACE_ID` are accepted and ignored.
- **The gateway holds no secret scanner** (ADR-0056); it refuses unknown `HUMAUX_GATEWAY_*` keys. The retrieval
  worker's `HUMAUX_RETRIEVAL_WORKER_GITLEAKS_*` are the one egress seal; the scanner binary is in the
  `humaux-retrieval-worker` image (root-owned, read-only root filesystem).
- **`HUMAUX_GATEWAY_PROJECTION_LAG_SECONDS` is required** (ADR-0057 D-F): above the normal put → `DONE` time, below
  `HUMAUX_MAINTENANCE_SERVE_LOST_AFTER_SECONDS`.
- **Qdrant ≥ 1.19.0** (ADR-0057 D-I): the bundle pins `v1.19.0-unprivileged` by digest.
- **Private retrieval egress runs gitleaks only** (ADR-0056 D-A): e-mail addresses, phone numbers, dates and long
  numbers in private memories and recall queries are sent to the retrieval provider (recorded in
  `ops.data_disclosures`).
- **DSN names carry the `HUMAUX_` prefix** (ADR-0066 D-O): `PRIVATE_WORKER_PG_DSN` / `CONSOLIDATION_WORKER_PG_DSN`
  are accepted for one release with a deprecation WARN; the bundle uses only the new names.

## 5. Scheduled operations

| operation | cadence | how | evidence / alert |
|---|---|---|---|
| backup (full + verify + expire after VERIFIED) | daily 00:30 UTC | host cron: `deploy/pgbackrest/humaux-backup.crontab` line 1, the `dr` one-shot's `backup run` through the compose wrapper | `ops.backup_receipts`; `BackupFailure` (26 h) |
| restore drill | Wednesdays 03:00 UTC | the same crontab, line 2: `restore drill --evidence <dir>/drill-<date>.json` on `dr` | `ops.restore_drills`, the evidence file; `RestoreDrillFailure` (8 d) |
| `backup verify` / `backup status` | on demand | `dr` one-shot | §11 |
| retention approve / execute | monthly, operator (§5.4) | `migrate` one-shot (superuser, ADR-0063 L14) | registry receipt + §77 `PARTITION_DROPPED` |
| create-partitions | monthly, first week; at once on a horizon alert (§5.3) | `migrate` one-shot: `retention create-partitions --months-ahead 3 …` | `partition_horizon_months{table}` = 3; `PartitionHorizonShort` / `Exhausted` / `Absent` |
| sweeps: confirm tokens, rate buckets, terminal jobs, snapshots, quota and provider-budget reservations, reissue, redrive, LOST, partitions proposal, DR evidence | resident | the `maintenance-serve` service; cadence keys `HUMAUX_MAINTENANCE_SERVE_*` in `deploy/env/values/maintenance.env` (§5.1) | `maintenance_task_runs_total{task,outcome}`; `MaintenanceTaskFailing` |
| role-password rotation | quarterly | §10.1 | `deploy-check --roles-sql` green |
| pepper / token key / provider key rotation | on schedule or compromise | §10.2 – §10.4 | §10 |
| DNS pin check | monthly, and on `DnsPinDeferred` | §10.5 | `dns_pin_deferred_total` flat |
| image rebuild | every release | §2 R0 on the build host, then §R | the release manifest |

The two cron lines run `deploy/release/compose.sh` of the ACTIVE checkout — each line reads `HUMAUX_NODE_DEPLOY_DIR`
from `node.env` at run time, so a checkout switch (§R) moves the schedule with it and the crontab is never
re-installed for an upgrade — with `HUMAUX_NODE_SIZING`, `HUMAUX_NODE_DIR` and `HUMAUX_NODE_PROJECT` set in the
crontab's environment; install them once with `crontab -l | cat - <checkout>/deploy/pgbackrest/humaux-backup.crontab
| crontab -` after editing the three values. No gate proves the crontab is installed: `BackupFailure` and
`RestoreDrillFailure` are the proof that it runs (ADR-0064 L6).

### 5.1 Scheduled maintenance (`maintenance-serve`, card 35, ADR-0062)

One resident service, one instance. It reads `HUMAUX_GATEWAY_PROJECTION_LAG_SECONDS` and
`HUMAUX_PRIVATE_WORKER_DISTILL_BUDGET_WINDOW_SECS` under their own names from `values/maintenance.env`; they must
equal the gateway's and the private worker's values (ADR-0062 L4). Every `HUMAUX_MAINTENANCE_SERVE_CYCLE_SECONDS`
it runs each **due** task (its `<T>_EVERY_SECONDS` has passed, ≥ CYCLE) over one page of
`HUMAUX_MAINTENANCE_SERVE_TENANTS_PER_RUN` tenants (`control.maintenance_tenant_page`, ids only), one transaction
and **one statement** per tenant with LIMIT `<T>_LIMIT`. Every key is required with no default (prefix
`HUMAUX_MAINTENANCE_SERVE_`, full list and readers in `docs/architecture/env_vars.md`); every age is sent as an
interval and compared with the **DB clock** inside the door. A full rotation takes `ceil(tenants /
TENANTS_PER_RUN) × EVERY` (ADR-0062 L1).

| task (`task` label) | door (one statement per tenant) | cadence / limit keys | age key | never touches | evidence |
|---|---|---|---|---|---|
| `lost` | `stream_repo::sweep_lost`: ISSUED → LOST, oldest first | `LOST_EVERY_SECONDS`, `LOST_LIMIT` | `LOST_AFTER_SECONDS` (> `HUMAUX_GATEWAY_PROJECTION_LAG_SECONDS`) | a ticket under a live runner lease, a ticket in retry backoff, a ticket with an in-flight job, a ticket whose Evidence is still being distilled | the row itself: `state = LOST`, `error_class = ORPHANED_PIPELINE_ITEM`, `lost_at` |
| `quota_reservations` | `control.reap_quota_reservations` (0113) | `QUOTA_RESERVATIONS_*` | — (reservation TTL) | live reservations | the reaped reservations' state |
| `quota_renewal` (ADR-0072) | `control.renew_quota_period` (0245): promote a due successor; within the lead, stage the next period and issue its window | `QUOTA_RENEWAL_*` (LIMIT = periods per call) | `QUOTA_RENEWAL_LEAD_SECONDS`, `QUOTA_RENEWAL_SUBSCRIPTION_MONTHS` | a tenant not ACTIVE; a tenant with a successor pending; an issued window (limit and bounds immutable) | `control.entitlement_snapshots.successor` / `successor_from`; the new `control.quota_windows` row; `quota_window_horizon_seconds` |
| `provider_budgets` | `ops.reap_expired_retrieval_provider_budget` (0117) | `PROVIDER_BUDGETS_*` | — (reservation TTL) | live reservations | the reaped reservations' state |
| `confirm_tokens` | `control.sweep_confirm_tokens(interval, integer)` (0218) | `CONFIRM_TOKENS_*` | `CONFIRM_TOKENS_CONSUMED_RETENTION_SECONDS` | an unexpired token; a consumed token younger than the retention | `ops.maintenance_receipts` task `confirm_tokens` |
| `snapshots` | `ops.purge_expired_selection_snapshots(integer)` (0218) | `SNAPSHOTS_*` | — (DB `expires_at`) | an unexpired snapshot; a page read already running | receipts task `selection_snapshots` |
| `rate_buckets` | `control.purge_idle_rate_buckets(interval, integer)` (0218) | `RATE_BUCKETS_*` | `RATE_BUCKETS_IDLE_SECONDS` | a bucket that would not be full now; a bucket a consumer holds | receipts task `rate_buckets` |
| `jobs` | `ops.purge_terminal_jobs(interval, interval, interval, integer)` (0218) | `JOBS_*` | `JOBS_DONE_RETENTION_SECONDS`, `JOBS_DEAD_RETENTION_SECONDS`, budget window | a job with a provider call inside the budget window; a contribution-linked job; a DEAD distill job `jobs requeue-dead` could still re-arm; every outbox row | receipts task `terminal_jobs` |
| `reissue` | `projection.reissue_unsettled_tickets(uuid, interval, integer)` (0220, 0223) | `REISSUE_*` | `REISSUE_COOLDOWN_SECONDS` (> 0) | a tombstoned or non-indexable memory; a memory with a ticket in flight; a deterministic failure already reissued once | `projection.ticket_reissues` |
| `redrive` | `ops.auto_redrive_schema_failed(uuid, interval, integer)` (0221) + one §77 row | `REDRIVE_*` | `REDRIVE_COOLDOWN_SECONDS` (> 0) | any class but `FAILED_OUTPUT_SCHEMA`; a job already re-driven once | `control.audit_events` action `DISTILL_AUTO_REDRIVE` |
| `partitions` (cluster-level, ADR-0063 D-K) | one `UPDATE control.partition_registry` of the two proposal columns + one horizon read | `PARTITIONS_EVERY_SECONDS` | the policy's `retention_months` | every DDL, every DROP, every hold | `proposed_at` / `proposed_policy_revision`; `partition_horizon_months{table}` |
| `dr_evidence` (cluster-level, card 37, ADR-0064 D-K) | one statement over `ops.backup_receipts`, `ops.restore_drills` and `pg_stat_archiver`, then statvfs(3) of `HUMAUX_MAINTENANCE_DR_REPO_FS_PATH` / `HUMAUX_MAINTENANCE_DR_PGDATA_FS_PATH` (f_bavail × f_frsize, in-process: no `df` child; in the bundle: the repository bind and the pgdata volume, mounted read-only) | `DR_EVIDENCE_EVERY_SECONDS` | — | every backup and every repository file | the six DR families, §11 |

- **What an operator reads**, as `role_maintenance` with the tenant GUC: `SELECT task, sum(affected),
  max(ran_at) FROM ops.maintenance_receipts WHERE tenant_id = $1 AND ran_at > now() - interval '1 day' GROUP BY
  task`. Fleet-wide: `maintenance_task_rows_total{task}` and `maintenance_task_runs_total{task,outcome}`;
  `MaintenanceCountersAbsent` (WARNING) fires while the daemon answers 503 or is not scraped, and
  `MaintenanceTaskFailing` (WARNING) records any failed call of the last hour. A call that deletes nothing writes no
  receipt.
- **Pause one task**: raise its `<T>_EVERY_SECONDS` in `values/maintenance.env` and recreate the service (there is
  no per-task off switch: a disabled purge is unbounded growth).
- **The jobs door frees `idempotency_key`** (ADR-0062 L5): safe while every producer's key derives from a row
  created once. A new producer that re-presents an old key must keep its jobs out of the door first.
- **Manual one-shot**: `sweep once <A>` on the `ops` one-shot reads the same keys except `METRICS_ADDR` and the
  `*_EVERY_SECONDS`, runs every task for one page, prints one receipt with per-task counts and exits 1 if any call
  failed (ADR-0062 D-Q).

### 5.2 Running the daemon against a database that already holds residue (ruling E8)

The first sweep against a long-lived database deletes shared rows across every tenant and makes irreversible
ISSUED → LOST transitions, permanent reissue tickets and live re-drive model calls. A fresh node has no residue;
a node that imported data does. Before the first `maintenance-serve` start there: (1) a VERIFIED `backup run`
(§B); (2) state the impact (the counts each door would take now); (3) `sweep once` with explicit retentions and
the §77 fields, read its receipt; (4) only then start the resident service.

### 5.3 Partitions: the monthly create-partitions step and the horizon alerts (ADR-0063 D-F)

The §48.1 tables have **no DEFAULT partition**. The first insert whose key is at or past the last pre-created month
fails with SQLSTATE 23514 for **every tenant at the same instant** (00:00 UTC on the 1st). No data is lost (every
failure is a refused write), but most repositories map 23514 to 409 / 400, not 5xx (card 36b fixes the mapping),
so the outage does not page through 5xx monitoring. The alarm is the three horizon alerts, one to two months
earlier.

**Monthly step** (first week of each month): on the `migrate` one-shot (it alone carries the superuser
`HUMAUX_MIGRATOR_PG_DSN`; no resident does, and both resident maintenance modes refuse to boot when it is set):
`retention create-partitions --months-ahead 3 --lock-timeout-ms 5000 --actor <you> --reason "monthly partitions"
--ticket <ticket> --step-up-auth <ref>`. It prints one JSON receipt (`outcome` `created` or `existing`), writes
one §77 `PARTITIONS_CREATED` row when it created a leaf, and the next PARTITIONS run shows
`partition_horizon_months{table} = 3`. Nothing restarts. Exit 1 = busy (another `retention` command holds
`HXRETAIN`) or a lock wait past `--lock-timeout-ms`: re-run.

| alert | meaning | do |
|---|---|---|
| `PartitionHorizonShort` (WARNING, ≤ 1 for 1h) | one monthly step was missed; the outage is two months away | run the monthly step now |
| `PartitionHorizonExhausted` (CRITICAL, ≤ 0 for 10m) | the current month's leaf is the last one (or the table has none): inserts fail from the next 1st | run the monthly step now; check its receipt lists the table; confirm the gauge reads 3 on the next PARTITIONS run |
| `PartitionHorizonAbsent` (CRITICAL, absent for 2h) | the daemon's PARTITIONS run has not succeeded or the daemon is not scraped | read `maintenance_task_runs_total{task="partitions",outcome="failed"}` and the `maintenance-serve` log (`partitions: …`): usually a revoked grant or an unreachable database; fix it. Until then run the monthly step by hand |

**Never attach a DEFAULT partition** as a stop-gap: it hides the miss, makes every later month creation scan and
move rows, and forbids `DETACH … CONCURRENTLY`.

### 5.4 Retention execute (ADR-0063 D-C, D-G, D-I, D-J)

Retention drops one whole month of one table for **all tenants at once** (per-tenant deletion stays §37
tombstones). `EVENTS` and `AUDIT_EVENTS` cannot have a policy. Every command below runs on the `migrate` one-shot,
takes the §77 fields plus `--lock-timeout-ms`, and exits 0 = done / no-op, 1 = infra or busy (re-run), 2 =
configuration, 3 = refused (`{"outcome":"refused","reason":"<code>"}`).

1. **Precondition — backup.** A VERIFIED `backup run` (§B) covers the leaf; keep it until the drop is reviewed.
2. **Approve** a policy (a row IS the approval; the newest revision of a table is the current one; `forever`
   withdraws): `retention approve --table MODEL_CALL_LEDGER --months 12 --effective-at <rfc3339>`.
3. **Wait for the proposal**: the daemon's next PARTITIONS run (after `effective_at`) marks each expired leaf. The
   proposal corroborates; it authorises nothing.
4. **List**: `retention execute --policy <id> --export-dir <dir> --dry-run` — every due leaf with `registry_id`,
   bounds, row count and the verdict of `control.partition_drop_check` (`ok` or the refusal, e.g.
   `hold:unsettled_ledger_calls`, `hold:open_budget_reservations`, `hold:open_contribution_executions`,
   `hold:running_stage`, `not_due`, `newest_leaf`, `not_proposed`, `registry_catalog_mismatch <leaf>` —
   investigate, never edit the row to make it pass). Nothing is written. `<dir>` is a path inside the `migrate`
   container that a bind of an owner-only (0700) host directory provides.
5. **Review one leaf**: `retention execute --policy <id> --registry-id <id> --export-dir <dir> --dry-run` prints the
   exact `DETACH PARTITION` / `DROP TABLE … RESTRICT` statements.
6. **Run it**: the same command without `--dry-run`. In one transaction the database re-derives every predicate,
   the leaf is exported (`COPY` to `<dir>/<leaf>__<registry_id>.copy`, mode 0600, fsync, rename, directory fsync,
   row count checked, sha256; the file holds every tenant's rows of the month), detached, dropped RESTRICT, and the
   registry row becomes the receipt (`rows_dropped`, `export_path`, `export_sha256`, `dropped_by`) with one §77
   `PARTITION_DROPPED` row. One leaf per run.
7. **After exit 1**: re-run the same command. A dropped leaf answers `already_dropped` with its stored receipt.
8. **Restore from the export**: `CREATE TABLE <scratch> (LIKE <parent>)` in a scratch database, `COPY <scratch>
   FROM '<file>'`, compare `count(*)` with `rows_dropped` and the file's sha256 with `export_sha256`. Re-attaching
   a past month is owner DDL that needs its own reviewed decision.

## 6. First activation — performed by onboarding (ADR-0053)

A family (tenant, workspace, `private_memory`/`PRIVATE_MEMORY`/`v1`) is first activated by `onboard tenant` /
`onboard workspace` themselves, with **VerifiedEmpty** evidence: the family's checkpoint row, stream log, outbox,
point registry and gaps are all zero (derived by the DB), a Qdrant count of the family in the collection's current
generation is zero, and the workspace is still `PROVISIONING` — while a workspace is `PROVISIONING`, every
stream-issuing write is refused with `CONFLICT` (SQLSTATE 55000 `workspace_provisioning`). The receipt lands in
`projection.family_activations`; when the last family of the workspace serves, it becomes `READY`. From that
moment `memory.get` answers `NOT_FOUND`, `memory.enumerate` an exact empty census, `recall.search` an empty result
with `current = true`, `context.assemble` an empty envelope, and the resident runner's projections are read as
they land. `activate --tenant <id> --workspace <id>` on the `ops` one-shot repeats it idempotently or finishes a
run that crashed between the PostgreSQL transaction and the activation.

`projection serve` (on the `ops` one-shot) is only for **version upgrades** of a family (and for `LEGACY` pairs made
before card 28): `projection serve --tenant <tenant_id> --workspace <workspace_id> --domain private_memory
--projection-kind PRIVATE_MEMORY --version <v> [--retire-failed distill_failed,no_visible_memory_record]`. For the
version onboarding activated it prints "already serving" and exits 0. `--retire-failed <classes>` first moves that
family's `FAILED` tickets of exactly those classes to `RETIRED_FAILED` (0167, audited), because one `FAILED` ticket
pins the §15.4 prefix. Version upgrades go through the §16.2 two-version comparison — see
`docs/ops/delivery_point_report.md` §6.1: a tenant with any live projected `USER_PRIVATE` point makes the switch
refuse with `VisibleUnavailable`.

## 7. Verify it is up (V1–V3)

<!-- step: V1 expect: 0 match: PROBES ok -->
```sh
C="sh deploy/release/compose.sh"
nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
P=$(nv HUMAUX_NODE_GATEWAY_HOST_PORT)
for path in livez readyz; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P/$path")
  [ "$code" = 200 ] || { echo "probes: gateway /$path answered $code"; exit 1; }
done
$C exec -T retrieval-rpc /usr/local/bin/humaux-retrieval-worker --readyz
$C exec -T retrieval-serve /usr/local/bin/humaux-retrieval-worker --readyz
$C exec -T private-rpc /usr/local/bin/humaux-private-worker --readyz
$C exec -T private-distill /usr/local/bin/humaux-private-worker --readyz
$C exec -T consolidation /usr/local/bin/humaux-consolidation-worker --readyz
$C exec -T maintenance-health /usr/local/bin/humaux-maintenance readyz health-serve
$C exec -T maintenance-serve /usr/local/bin/humaux-maintenance readyz serve
for port in 19101 19102 19103 19104 19105 19106 19107 19108; do
  body=$($C exec -T prometheus wget -qO- "http://127.0.0.1:$port/metrics") || { echo "probes: 127.0.0.1:$port/metrics did not answer"; exit 1; }
  # 19106 (consolidation --serve) counts no §41.2 family yet: its exposition is empty by design (ADR-0061 E10) and
  # Prometheus' `up` is its liveness signal; every other listener must declare at least one family.
  [ "$port" = 19106 ] || echo "$body" | grep -q '^# TYPE ' || { echo "probes: 127.0.0.1:$port/metrics has no metric family"; exit 1; }
done
echo "PROBES ok"
```

V2 (§O-SMOKE) is one real round trip for `smoke-a`: `remember.put` of a canary sentence → distill (the provider) → projection
(the embedding provider) → `recall.search` returns it. The canary token is the rollback proof's marker **M1**
(§R). A deployment that answers `/readyz` but cannot complete this is not up. The wait covers one distill and one
projection hop (§8: about 0.23 Evidence/s per provider slot).

<!-- step: V2 expect: 0 match: SMOKE ok smoke-a -->
```sh
nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
P=$(nv HUMAUX_NODE_GATEWAY_HOST_PORT); D="$HUMAUX_NODE_DIR/smoke"
mcp() { # $1 = API-key header file, $2 = tool, $3 = arguments JSON
  curl -sS -X POST "http://127.0.0.1:$P/mcp" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H "Mcp-Name: $2" -H "Origin: http://127.0.0.1:$P" -H @"$1" \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":$3,\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientInfo\":{\"name\":\"runbook-v2\",\"version\":\"1\"},\"io.modelcontextprotocol/clientCapabilities\":{}}}}"
}
uuid() { h=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n'); echo "$(echo "$h" | cut -c1-8)-$(echo "$h" | cut -c9-12)-4$(echo "$h" | cut -c14-16)-a$(echo "$h" | cut -c18-20)-$(echo "$h" | cut -c21-32)"; }
TOK=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n'); echo "$TOK" > "$D/m1.token"
WS=$(sed -n 's/^workspace_id=//p' "$D/a.ids")
mcp "$D/a.auth" remember "{\"operation\":\"put\",\"content\":\"The node smoke canary codename is $TOK and it ships on Fridays.\",\"idempotency_key\":\"$(uuid)\",\"workspace_id\":\"$WS\"}" > "$D/m1.put.json"
grep -q '"isError":true' "$D/m1.put.json" && { echo "smoke: remember.put failed: $(head -c 300 "$D/m1.put.json")"; exit 1; }
i=0
until mcp "$D/a.auth" recall "{\"query\":\"What is the node smoke canary codename?\",\"workspace_id\":\"$WS\",\"mode\":\"semantic\"}" | grep -q "$TOK"; do
  i=$((i + 1)); [ "$i" -lt 60 ] || { echo "smoke: recall did not return canary $TOK within 600 s"; exit 1; }; sleep 10
done
echo "SMOKE ok smoke-a canary=$TOK"
```

V3 is the same round trip for `smoke-b`, then the isolation check on the same gateway: each tenant asks the
other's question in its own workspace and must not see the other's canary (a hit would be a cross-tenant read).

<!-- step: V3 expect: 0 match: SMOKE ok smoke-b cross_tenant=0 -->
```sh
nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
P=$(nv HUMAUX_NODE_GATEWAY_HOST_PORT); D="$HUMAUX_NODE_DIR/smoke"
mcp() { # $1 = API-key header file, $2 = tool, $3 = arguments JSON
  curl -sS --fail -X POST "http://127.0.0.1:$P/mcp" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H "Mcp-Name: $2" -H "Origin: http://127.0.0.1:$P" -H @"$1" \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":$3,\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientInfo\":{\"name\":\"runbook-v2\",\"version\":\"1\"},\"io.modelcontextprotocol/clientCapabilities\":{}}}}"
}
uuid() { h=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n'); echo "$(echo "$h" | cut -c1-8)-$(echo "$h" | cut -c9-12)-4$(echo "$h" | cut -c14-16)-a$(echo "$h" | cut -c18-20)-$(echo "$h" | cut -c21-32)"; }
TOK=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n'); echo "$TOK" > "$D/b.token"
WSA=$(sed -n 's/^workspace_id=//p' "$D/a.ids"); WSB=$(sed -n 's/^workspace_id=//p' "$D/b.ids"); TOKA=$(cat "$D/m1.token")
mcp "$D/b.auth" remember "{\"operation\":\"put\",\"content\":\"The node smoke canary codename is $TOK and it ships on Fridays.\",\"idempotency_key\":\"$(uuid)\",\"workspace_id\":\"$WSB\"}" > "$D/b.put.json"
grep -q '"isError":true' "$D/b.put.json" && { echo "smoke: remember.put failed: $(head -c 300 "$D/b.put.json")"; exit 1; }
i=0
until mcp "$D/b.auth" recall "{\"query\":\"What is the node smoke canary codename?\",\"workspace_id\":\"$WSB\",\"mode\":\"semantic\"}" > "$D/b.recall.json" && grep -q "$TOK" "$D/b.recall.json"; do
  i=$((i + 1)); [ "$i" -lt 60 ] || { echo "smoke: recall did not return canary $TOK within 600 s"; exit 1; }; sleep 10
done
grep -q "$TOKA" "$D/b.recall.json" && { echo "smoke: smoke-b sees smoke-a's canary: cross-tenant read"; exit 1; }
X="$D/a.cross.json"  # the negative check counts only on a successful tool result (a failed call shows no canary either)
mcp "$D/a.auth" recall "{\"query\":\"What is the node smoke canary codename?\",\"workspace_id\":\"$WSA\",\"mode\":\"semantic\"}" > "$X" \
  || { echo "smoke: smoke-a cross-tenant recall failed (curl exit $?)"; exit 1; }
grep -q '"result"' "$X" && ! grep -q '"isError":true' "$X" \
  || { echo "smoke: smoke-a cross-tenant recall returned no tool result: $(head -c 300 "$X")"; exit 1; }
grep -q "$TOK" "$X" && { echo "smoke: smoke-a sees smoke-b's canary: cross-tenant read"; exit 1; }
echo "SMOKE ok smoke-b cross_tenant=0"
```

### 7.1 Reading the private-worker dispatch line

`humaux-private-worker: distill dispatch claimed=N completed=N failed=N not_ready=N parked=N deferred=N dead=N lost_lease=N errors=N heartbeat_lost=N attempts=N unknown=N memories=N rejected=N empty_retries=N malformed_retries=N affects_dropped=N channel_fallback=N stopped=no_work|no_slot|-`

One line per pass (`--distill-once`) or per resident run (the `private-distill` service, printed at exit).
ADR-0058: `claimed` = jobs claimed (one job = one Evidence), `attempts` = admitted provider requests
(`ops.begin_call`), `deferred` = failed calls backed off for a retry, `parked` = jobs parked `WAITING_KEY`,
`unknown` = calls cut at the HTTP window whose outcome is unknown, `lost_lease` / `heartbeat_lost` = a job's
generation was superseded (its late result is discarded, its cost still ledgered) — fence refusals only; `errors`
= jobs an error escaped (a database, reasoner or membership failure the job could not settle; the claim is
reconciled by the sweep), each named on its job line. `affects_dropped` = written replies whose inferred affects
were discarded as invalid (the memories were kept). `channel_fallback` (ADR-0058 R9) = written replies that, on
the tool channel, came back with no tool call and the answer object in `content`; the same parser accepted them,
so they are not malformed — a steady rate says the model often ignores the tool and the content channel may
measure better (R10). `stopped` (ADR-0058 R5) = why a `--distill-once` pass ended: `no_work` = a provider slot was
free and no READY job was left for it; `no_slot` = all four slots were bound, so READY work may be left for the
next pass; `-` for the resident mode, which never stops on an empty claim. A healthy run reads `lost_lease=0
errors=0 heartbeat_lost=0`. Read it with `docker compose logs` through the compose wrapper on the operator host
(`logs private-distill`).

Every job also prints one line:
`humaux-private-worker: distill job=<uuid> tenant=<uuid> evidence=<uuid> gen=<n> outcome=<DONE|RETRY|NOT_READY|PARKED|DEAD|LEASE_LOST|ERROR|UNKNOWN> attempt=<n>/<max> error_class=<class|-> next_retry_s=<n|-> channel_fallback=<0|1>`
(`channel_fallback=1`: the written reply arrived in `content` on the tool channel, ADR-0058 R9)

- `outcome=NOT_READY error_class=<reason>` — nothing was sent (no admitted binding, `CREDENTIAL_NOT_MAPPED`,
  `EGRESS_PROCESSOR_NOT_ALLOWED` / `EGRESS_HOST_NOT_ALLOWED` / `REGION_NOT_ALLOWED` — the route's recipient, host or
  region is not in this deployment's lists —, `ROUTE_HEALTH_STALE` — the route's latest health observation ran
  out —, `ROUTE_HEALTH_DENIED` — it is valid but not HEALTHY/VALID, e.g. a key the provider rejected —, or
  `DOMAIN_MISMATCH`); no attempt is spent. Past `HUMAUX_PRIVATE_WORKER_DISTILL_NOT_READY_PARK_SECS` the job is
  `PARKED` (`ops.jobs.status = 'WAITING_KEY'`, re-checked once per park interval): fix the tenant's binding; the
  job resumes by itself.
- `outcome=NOT_READY error_class=PROVIDER_BUDGET` — the tenant spent its §72.3 distill budget
  (`HUMAUX_PRIVATE_WORKER_DISTILL_BUDGET_MAX_CALLS` admitted requests in the last `_BUDGET_WINDOW_SECS`, counted in
  `ops.distill_calls`, ADR-0058 D-T); nothing was sent and no attempt spent. Every request passes it, including
  the resend after `EXECUTION_UNCERTAIN`.
- `outcome=RETRY error_class=WORKER_DB_ERROR` after a counted call — a database error after the provider
  answered; the job was settled at once in a fresh transaction (slot freed), never left to the hard deadline
  (ADR-0058 D-E).
- `outcome=ERROR error_class=<class>` — an error escaped the job before it could settle (e.g. `WORKER_DB_ERROR` on
  taking the outbox row); the job stays claimed until the sweep reconciles it (an unexpired lease first). Never
  counted as a lost lease (ADR-0058 R3).
- `outcome=DONE error_class=affect_invalid` — the reply's memories were written, but an inferred affect was
  outside the menu (unknown key, MOOD, target, out of range, confidence over 5 000 bp), so every inferred affect of
  that reply was dropped (ADR-0058 R1). Not a failure; a steady rate is a prompt/model issue.
- `outcome=PARKED error_class=WAITING_KEY` — the provider answered 401: the tenant's key is invalid. Never DEAD,
  the attempt is not counted (§11); rotate the key.
- `outcome=DEAD` — `attempt` reached `HUMAUX_PRIVATE_WORKER_DISTILL_MAX_ATTEMPTS` real provider requests (or
  `ATTEMPTS_EXHAUSTED` / `PRE_DISPATCH_ABANDONED` / `FAILED_OUTPUT_SCHEMA`); the outbox row is `FAILED` in the same
  transaction and the ticket ends `distill_failed`. The tenant's other Evidence keeps flowing.
- `re-claimed after EXECUTION_UNCERTAIN (T6) uncertain_model_call_id=<uuid>` — a worker died (or stalled past
  `HARD_DEADLINE_SECS`) mid-call; the slot was held until the hard deadline, then the job was re-queued with
  backoff and this call counted. The named ledger row stays `RESERVED` (its outcome is unknown, ADR-0058 L5).
- `humaux-reasoning: provider call failed purpose=PRIVATE_DISTILL_TEXT tenant=<uuid> model_call_id=<uuid>
  error_class=<class> latency_ms=<n>` — `RETRY_WAIT` with latency ≈ `HTTP_TIMEOUT_SECS` is a timeout, with a short
  latency a 429/5xx; `PROVIDER_PERMANENT` is a refusal.
- In-flight is bounded by the four rows of `ops.provider_slots` across every process (§67.2):
  `select slot_no, job_id, bound_until from ops.provider_slots` shows who holds them.
- `distill evidence=<id> failed: InvalidInput (<reason>)` — the parser refused the model's reply. `<reason>` is
  structural, never payload text: `not_json`, `top_level_shape`, `memories_missing`, `too_many_memories`,
  `item_shape`, `content_empty_or_too_long`, `memory_type_unknown`, `class_unknown`, `confidence_invalid` (ADR-0048
  addendum), `nul_character` (ADR-0058 R8), `tool_call_shape` (ADR-0058 D-M/R9). The worker re-asks once on its own
  (`malformed retry 1/1`, counted in `malformed_retries`); a row that still fails is a `FAILED` outbox row and a
  `FAILED` ticket, which blocks the §15.4 prefix until `role_maintenance` retires it
  (`projection.retire_failed_ticket`, ADR-0042). A steady `memory_type_unknown` rate above a few percent means the
  model is ignoring rule (3) of the distill prompt — check the model, not the parser.
- `memory_candidate_rejections_total{reason="origin_authority_ceiling"} 1 …` — an over-ceiling candidate persisted
  as PENDING (`memory.confirm` can promote it). Not a failure; the row is still `done=1`.
- A `MEMORY_LIFECYCLE` ticket for a superseded / revoked / expired memory settles `DONE` by retiring its registry
  binding and deleting its point (ADR-0049). `registry_failed` on such a ticket means the retrieval worker binary
  predates ADR-0049.

#### Operator procedure for a terminal or stuck distill job (ADR-0058 R4)

Read the state first (database owner session: a `psql` in the `pg` service; no runtime role reads these tables):
`select job_id, status, dispatch_state, attempt, abandoned_claims, last_error_class, next_retry_at,
hard_deadline from ops.jobs where tenant_id = '<tenant>' and job_type = 'DERIVED_DISTILL' and status in ('DEAD',
'WAITING_KEY', 'PROCESSING') order by status, last_error_class`.

- **DEAD** — terminal; nothing retries it. 1) Inspect the class (`last_error_class`, the job line's `error_class`,
  and the `humaux-reasoning: provider call failed` lines of the same `tenant=`): `RETRY_WAIT` / `TRANSPORT` =
  provider outage or timeout, `PROVIDER_PERMANENT` = refusal, `FAILED_OUTPUT_SCHEMA` = the model kept breaking the
  output contract, `ATTEMPTS_EXHAUSTED` / `PRE_DISPATCH_ABANDONED` = a crash loop, `WORKER_DB_ERROR` = the
  database. 2) Fix the cause — re-driving an unfixed cause spends `MAX_ATTEMPTS` more billed requests and dies
  again. 3) Re-drive on the `ops` one-shot with the §77 fields: `jobs requeue-dead --tenant <tenant> --job
  <job_id> <A>` or `jobs requeue-dead --tenant <tenant> --error-class RETRY_WAIT <A>`.

  Exactly one of `--job` / `--error-class` (exit 2 otherwise); `--error-class` matches the stored class exactly and
  re-arms only that tenant's DEAD jobs. One transaction (`ops.requeue_dead_distill`, 0197): job `PENDING`,
  `attempt 0`, `last_error_class` kept as the record, the Evidence's outbox row `FAILED -> PENDING`, the tenant's
  scheduler row admitted; the next pass claims it. When the Evidence's projection ticket had already settled
  `FAILED distill_failed` (or was retired / `LOST`), the same transaction issues a successor ticket on that stream
  (0198): it waits while the job is open and indexes the re-distilled memories once it is DONE. The old `FAILED`
  ticket stays an open gap until you retire it — `projection serve … --retire-failed distill_failed` on the `ops`
  one-shot — which is safe now, since the successor carries the Evidence. The receipt lists every re-armed
  `job_id` / `evidence_id` / `last_error_class` / `attempt_spent` under `requeued` and the §77 audit id. With
  `--error-class` it also lists, under `skipped`, every matching DEAD job it left DEAD (0200), each with `reason`:
  `evidence_gone` (the Evidence has no outbox row: a re-armed job could only die again) or `outbox_settled` (the
  Evidence is already DONE — nothing to re-drive); the SUCCESS audit row carries the same `skipped` list.
  `outcome` is `requeued`, or `nothing_requeued` when every match was skipped (exit 0 both; read `skipped` to see
  why):

  ```text
  {"outcome":"requeued","tenant_id":"…","requeued":[{"job_id":"…","evidence_id":"…",
   "last_error_class":"FAILED_OUTPUT_SCHEMA","attempt_spent":3}],
   "skipped":[{"job_id":"…","evidence_id":"…","last_error_class":"FAILED_OUTPUT_SCHEMA",
   "attempt_spent":3,"reason":"evidence_gone"}],"audit_event_id":"…"}
  ```

  Exit 3 = refused, nothing written but a DENIED audit row: `job_not_found` (wrong tenant or id), `job_not_dead`,
  `evidence_gone` / `outbox_settled` (`--job` only — the same reasons as above), `no_dead_job` (no DEAD job with
  that class at all). A re-run is refused `job_not_dead` (`--job`) or answers only what is still DEAD
  (`--error-class`), never a second re-arm.
- **WAITING_KEY** (`outcome=PARKED`) — never DEAD and never re-driven by hand: rotate the tenant's provider key
  (`error_class=WAITING_KEY`, a 401) or bind/admit its `PRIVATE_DISTILL_TEXT` route profile (any other NOT_READY
  class). The claim re-checks it once per `HUMAUX_PRIVATE_WORKER_DISTILL_NOT_READY_PARK_SECS` and it resumes by
  itself; no attempt is spent.
- **EXECUTION_UNCERTAIN** (`status = 'PROCESSING'`, `dispatch_state = 'EXECUTION_UNCERTAIN'`) — a worker died or
  stalled mid-call; its slot stays bound on purpose. Wait for `hard_deadline`: the next claim re-queues it with
  backoff (`last_error_class = 'EXECUTION_UNCERTAIN'`, the uncertain call counted) and the resend is automatic,
  admitted by the tenant budget, and printed as `re-claimed after EXECUTION_UNCERTAIN (T6)
  uncertain_model_call_id=<uuid>`. Do not edit the row or free the slot.
- **A ledger row left `RESERVED`** (ADR-0058 L5) — a provider request whose outcome is unknown (the worker died
  before finalizing it). For billing it means: the provider may or may not have charged the tenant's account for
  it; Humaux's ledger holds only the pre-call `estimated_cost`, never an `actual_cost`, and nothing finalizes it
  later. The resend after `EXECUTION_UNCERTAIN` is a separate, counted, ledgered request — so one Evidence can show
  one `RESERVED` row plus one `SUCCEEDED` row (at most one extra billed call per uncertain claim, bounded by
  `MAX_ATTEMPTS`). List them (owner session): `select l.model_call_id, l.tenant_id, l.called_at,
  l.estimated_cost, c.job_id, c.attempt from ops.model_call_ledger l left join ops.distill_calls c using
  (model_call_id) where l.purpose = 'PRIVATE_DISTILL_TEXT' and l.status = 'RESERVED' and l.called_at < now() -
  interval '<hard deadline>' order by l.called_at`. Reconcile against the provider's usage console by time window
  when a tenant disputes a charge; a `RESERVED` row with no `distill_calls` row was reserved but never admitted by
  `ops.begin_call` (a crash between the two, ADR-0058 L13): no request was sent.

### 7.2 What `PROJECTION_LAG` means and what to do (ADR-0057 D-E)

A read answers `completeness.class = cannot_establish`, `reason = projection_lag`, with `PROJECTION_LAG` in
`degradations`, when the stream it read has a pending projection ticket older than
`HUMAUX_GATEWAY_PROJECTION_LAG_SECONDS`. The items are still served; the envelope says the index is behind the
ledger, so a recent write may be missing. `projection.current` does not change (its formula is frozen), so watch
the class, not `current`. With `PROJECTION_INVISIBLE_LOSS` at the same time both codes are reported, loss first.

1. Is the runner alive and claiming? The `retrieval-serve` service's pass line (`projection pass claimed= done= …
   pending= lost_lease=`) every poll interval. No line ⇒ the process is stopped or hung: restart that service
   through the compose wrapper (never by port or pattern, §9).
2. Is the oldest pending ticket waiting on distill? An `EVIDENCE_ACCEPTED` ticket stays `ISSUED` until its distill
   job closes; a growing private-worker backlog (§8) reads as lag. Fix the distill hop, not the runner.
3. Is one ticket retrying? `attempts` / `next_attempt_at` / `error_class` on the oldest `ISSUED` row of the stream.
   A poison ticket makes its whole family lag until it settles `FAILED`; that is intended. `FAILED` then shows as
   `open_gaps`, which `role_maintenance` retires (ADR-0042).
4. It clears by itself once the oldest pending ticket settles; no restart of the gateway is needed.

### 7.3 Reading probes, metrics and alerts

A `--readyz` failure always **names the object that is down** (§4.4 坑5). Never read a probe failure as a zero: if
a dashboard shows `0` where a probe failed, the dashboard is wrong. The gateway's `/readyz` is
dependency-truthful (ADR-0061 D-F): 503 `not_ready` means PostgreSQL, the retrieval RPC round trip or Qdrant is
down — do **not** restart the gateway for it; its loopback `/status` names the dependency (supervision.md §2).
503 with `draining` means it received SIGTERM.

Every resident mode serves `/metrics` and `/status` on its own loopback ops listener (`127.0.0.1:19101-19108`
inside the shared namespace, supervision.md §1); Prometheus scrapes exactly those eight (R10). `/status` names
`process`, `mode`, `git_sha` and every degrade code.

- The Watchdog receipt (the sink or the external healthchecks service) carries `labels.git_sha` equal to the sha the
  `admin` one-shot's `version` prints. A receipt that says `__HUMAUX_GIT_SHA__` means the render (R8 / U7) was skipped:
  fix it before trusting any alert (§42.1, §67.4).
- `HealthGaugesAbsent` firing means the `maintenance-health` service is down or its sample fails (its `/metrics`
  answers 503 naming why); INV-3, projection lag and dead-letter are blind until it is back (supervision.md §2).
- `DistillNoOutput` (CRITICAL, §42 no-output stage, card 34b) means the private worker finished distill runs in the
  last hour and wrote no memory record. Read the `private-distill` scrape (`private_distill_runs_total` rising,
  `private_distill_outputs_total` flat), then the distill parser (the dispatch line's `memories=` / `rejected=`
  counts, §7.1), the provider replies (`reasoning status --tenant <id>`, the `error_class` of recent
  `ops.model_call_ledger` rows), then `q jobs.stuck` on the `admin` one-shot. Do not restart the worker for it — a
  restart resets the counters and silences the alert without fixing the stage.
- `DnsPinDeferred` (WARNING, ADR-0066 D-P): `dns_pin_deferred_total` grew while no distill output was written —
  a pinned provider address probably stopped answering; refresh the pins (§10.5).
- `AdmissionRejected`: §8.1.

**Manual §69 step — the external dead-man (§42.1), once per deployment and after every change to the Watchdog
route.** Not a gate, because the endpoint is outside the bundle: stop the `alertmanager` service for 5 minutes and
confirm the external healthchecks endpoint reports the missing ping; start it again and confirm the next ping
clears it. Record the date, the endpoint and its alert in the deployment log.

## A. Acceptance drills (once per node, before go-live; profile `rehearsal`)

These prove properties a configuration file cannot: the peer-credential checks refuse a wrong uid on the running
node, and an alert reaches its receiver with the deployed sha. They use the bundle's `rehearsal` profile (the
scratch identities and the alert sink); during them, `alert-urls/log_sink.url` and `watchdog.url` point at
`http://127.0.0.1:19194/log` and `http://127.0.0.1:19194/watchdog` (§1). Afterwards point the two URL files at the
real receivers and recreate `alertmanager`.

A1 — peer credentials (ADR-0066 D-K/D-L, W-5). Each scratch identity has exactly the uid and pair group of its
real twin and mounts both socket volumes. Exact statuses: on `retrieval.sock`, the server's own uid gets `403`
(and the server logs `rpc peer refused uid=10102`) and the gateway identity gets `200`; on `inference.sock`, the
server's own uid gets `403` and the consolidation identity gets `422` (the uid check runs before the JSON
extractor, so an authorised peer reaches the extractor's refusal of `{}` and no provider call is made).

<!-- step: A1 expect: 0 match: PEERCRED ok -->
```sh
C="sh deploy/release/compose.sh"
probe() { # $1 = scratch service, $2 = expected HTTP status, then the curl arguments
  s=$1; want=$2; shift 2
  got=$($C run --rm -T "$s" -sS -o /dev/null -w '%{http_code}' "$@" || true)
  echo "peer-cred: $s -> $got (expected $want)"
  [ "$got" = "$want" ] || exit 1
}
RS=/run/humaux/sock-retrieval/retrieval.sock; IS=/run/humaux/sock-inference/inference.sock
probe scratch-as-retrieval 403 --unix-socket "$RS" http://localhost/internal/v1/retrieval/readyz
probe scratch-as-gateway 200 --unix-socket "$RS" http://localhost/internal/v1/retrieval/readyz
probe scratch-as-private 403 --unix-socket "$IS" -X POST -H 'content-type: application/json' --data '{}' http://localhost/internal/v1/private/infer
probe scratch-as-consolidation 422 --unix-socket "$IS" -X POST -H 'content-type: application/json' --data '{}' http://localhost/internal/v1/private/infer
$C logs --no-log-prefix retrieval-rpc | grep -F 'rpc peer refused uid=10102' | tail -n 1
echo "PEERCRED ok"
```

<!-- step: A2 expect: 0 match: ALERT watchdog ok -->
```sh
C="sh deploy/release/compose.sh"
nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
TAG=$(nv HUMAUX_IMAGE_TAG); SHA=$(sed -n 's/^IMAGE .* git_sha=\([0-9a-f]\{40\}\).*/\1/p' "$(nv HUMAUX_NODE_RELEASES_DIR)/release-$TAG.manifest" | head -n 1)
F="$(nv HUMAUX_NODE_EVIDENCE_DIR)/alerts/alert_receipts.jsonl"
O=0; [ -e "$F" ] && O=$(wc -c < "$F")  # only receipts written after this step began count (a retry's old lines do not)
$C up -d alert-sink
i=0
until [ -r "$F" ] && tail -c +$((O + 1)) "$F" | grep -F 'Watchdog' | grep -qF "$SHA"; do
  i=$((i + 1)); [ "$i" -lt 60 ] || { echo "alert: no Watchdog receipt carrying git_sha=$SHA within 600 s"; exit 1; }; sleep 10
done
echo "ALERT watchdog ok git_sha=$SHA"
```

<!-- step: A3 expect: 0 match: ALERT firing ok -->
```sh
C="sh deploy/release/compose.sh"
nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
F="$(nv HUMAUX_NODE_EVIDENCE_DIR)/alerts/alert_receipts.jsonl"
O=0; [ -e "$F" ] && O=$(wc -c < "$F")  # only receipts written after this step began count (a retry's old lines do not)
$C stop maintenance-health
i=0
until tail -c +$((O + 1)) "$F" | grep -F 'HealthGaugesAbsent' | grep -qF '"status":"firing"'; do
  i=$((i + 1)); [ "$i" -lt 60 ] || { echo "alert: HealthGaugesAbsent did not fire within 600 s"; exit 1; }; sleep 10
done
echo "ALERT firing ok HealthGaugesAbsent"
```

<!-- step: A4 expect: 0 match: ALERT resolved ok -->
```sh
C="sh deploy/release/compose.sh"
nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
F="$(nv HUMAUX_NODE_EVIDENCE_DIR)/alerts/alert_receipts.jsonl"
O=0; [ -e "$F" ] && O=$(wc -c < "$F")  # only receipts written after this step began count (a retry's old lines do not)
$C start maintenance-health
i=0
until tail -c +$((O + 1)) "$F" | grep -F 'HealthGaugesAbsent' | grep -qF '"status":"resolved"'; do
  i=$((i + 1)); [ "$i" -lt 90 ] || { echo "alert: HealthGaugesAbsent did not resolve within 900 s"; exit 1; }; sleep 10
done
echo "ALERT resolved ok HealthGaugesAbsent"
```

## B. The first backup (B1)

The nightly backup is a host cron line (§5); B1 runs it once by hand so the node has a VERIFIED full before any
traffic depends on it. `backup run` exits 0 only on a VERIFIED receipt; `backup status` prints the PITR window.

<!-- step: B1 expect: 0 match: BACKUP ok -->
```sh
C="sh deploy/release/compose.sh"
$C run --rm -T dr backup run
$C run --rm -T dr backup status
echo "BACKUP ok"
```

## R. Release: upgrade (U1–U9) and rollback (RB1–RB6)

The system is **forward-only**: no migration has a down step. An upgrade is R1–R10 for the next tag with a backup
and a worker stop around the migration; a rollback is a restore of the pre-upgrade backup into a new project on the
previous tag. Put the next tag into `$HUMAUX_NODE_DIR/release.next` and its manifest (and tarballs) into
`releases/` first, copied over ssh from the build host as in §2 (L-21).

**The checkout belongs to the release** (ADR-0066 review fix 9, OP-4). U3 and RB1 compare the checkout the executor
runs from — its `CHECKOUT_TREE`, the git ids of `deploy/`, the runbook and the 0011 roles file — with the release
manifest's `CHECKOUT` line (`deploy-check --release --checkout-tree`: `checkout_tree_mismatch:<field>`,
`checkout_tree_missing`, `checkout_tree_not_in_manifest`). An upgrade or a rollback whose release carries a different
checkout STOPs there: `prod.yml`, `values/*.env`, the renderer and the executor would be the other release's. The
remedy: check `releases/humaux-checkout-<tag>.tar.gz` against its `humaux-checkout-<tag>.sha256`, unpack it as
`<node dir>/checkout-<tag>/` (read-only for services, §1), set `HUMAUX_NODE_DEPLOY_DIR` in `node.env` to its
`deploy/`, and continue from U3 with the executor of that checkout (U1–U2 stay done: U2's backup was taken under
the running release, which is the rollback point; RB1 for a rollback onto the previous release's checkout); the host crontab (§5) follows `node.env` and needs no change. A
release built from the running checkout's tree (the S9 rehearsal pair: the snapshot and its `--child`) matches
without an install.

<!-- step: U1 expect: 0 match: NEXT IMAGES ok value: PREV_TAG=PREV_TAG=[0-9A-Za-z._-]+ -->
```sh
nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
PREV=$(nv HUMAUX_IMAGE_TAG); NEXT=$(cat "$HUMAUX_NODE_DIR/release.next"); REL=$(nv HUMAUX_NODE_RELEASES_DIR)
[ -n "$NEXT" ] && [ "$NEXT" != "$PREV" ] || { echo "upgrade: release.next is empty or equals the running tag $PREV"; exit 1; }
rm -f "$HUMAUX_NODE_DIR/evidence/rb3.done"  # a new upgrade: an earlier rollback's completion marker no longer applies
M="$REL/release-$NEXT.manifest"; [ -r "$M" ] || { echo "upgrade: missing manifest $M"; exit 1; }
if [ -r "$REL/humaux-$NEXT.tar.gz" ]; then
  if command -v sha256sum >/dev/null; then (cd "$REL" && sha256sum -c "humaux-$NEXT.sha256"); else (cd "$REL" && shasum -a 256 -c "humaux-$NEXT.sha256"); fi
  gzip -dc "$REL/humaux-$NEXT.tar.gz" | docker load
fi
for img in $(awk '$1 == "IMAGE" || $1 == "PGIMAGE" { print $2 }' "$M"); do docker image inspect "$img" >/dev/null || { echo "upgrade: $img is not loaded"; exit 1; }; done
echo "NEXT IMAGES ok $NEXT"
echo "PREV_TAG=$PREV"
```

U2 takes the pre-upgrade backup and records the schema head; the rollback restores exactly the end of this backup
(`--target-backup`, PostgreSQL `--type=immediate`: no WAL after it is needed, ADR-0066 D-H). The executor captures
its label as `PRE_UPGRADE_LABEL`. It runs before anything of the next release is used (PR #2 round 4): the `dr`
image, `prod.yml` and the environment layout are all the running release's, and U2 first proves the executor's
checkout is that release's (`deploy-check --release PREV_TAG --checkout-tree`, which also proves the rollback images
are still loaded) — a backup taken with one release's image under another release's checkout is no rollback point.

<!-- step: U2 expect: 0 match: VERIFIED value: PRE_UPGRADE_LABEL=PRE_UPGRADE_LABEL=[0-9A-Za-z_-]+ -->
```sh
C="sh deploy/release/compose.sh"
nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
: "${PREV_TAG:?captured by U1}"
M="$(nv HUMAUX_NODE_RELEASES_DIR)/release-$PREV_TAG.manifest"
SHA=$(sed -n 's/^IMAGE .* git_sha=\([0-9a-f]\{40\}\).*/\1/p' "$M" | head -n 1)
[ "$(nv HUMAUX_IMAGE_TAG)" = "$PREV_TAG" ] || { echo "upgrade: node.env's tag is not the running tag $PREV_TAG"; exit 1; }
[ -r CHECKOUT_TREE ] || { echo "upgrade: $PWD/CHECKOUT_TREE is missing (the running release's checkout, §R)"; exit 1; }
DR=$(awk -v r="humaux-dr:$PREV_TAG" '$1 == "IMAGE" && $2 == r { sub(/^id=/, "", $3); print $3 }' "$M")  # the verifier, checked from the host before it runs
GOT=$(docker image inspect -f '{{.Id}}' "humaux-dr:$PREV_TAG" 2>/dev/null) || GOT="<not loaded>"
[ -n "$DR" ] && [ "$GOT" = "$DR" ] \
  || { echo "upgrade: humaux-dr:$PREV_TAG is $GOT; the manifest's dr image is ${DR:-<none>}"; exit 1; }
$C run --rm -T dr deploy-check --release "$PREV_TAG" --manifest "$M" --expect-sha "$SHA" --checkout-tree "$(cat CHECKOUT_TREE)"
O="$HUMAUX_NODE_DIR/evidence/backup-U2.json"
if ! $C run --rm -T dr backup run > "$O"; then cat "$O"; exit 1; fi
cat "$O"
L=$(sed -n 's/.*"backup_label": *"\([^"]*\)".*/\1/p' "$O" | head -n 1)
[ -n "$L" ] || { echo "upgrade: the backup receipt names no backup_label"; exit 1; }
$C exec -T pg psql -U postgres -d humaux -Atc 'select max(migration_id) from ops.schema_migrations' > "$HUMAUX_NODE_DIR/smoke/schema_head.pre"
echo "schema head before upgrade: $(cat "$HUMAUX_NODE_DIR/smoke/schema_head.pre")"
echo "VERIFIED backup PRE_UPGRADE_LABEL=$L"
```

U3 is the gate on the next release: its images, its checkout (`--checkout-tree`) and the next environment.

<!-- step: U3 expect: 0 match: PRECHECK ok -->
```sh
C="sh deploy/release/compose.sh"
nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
NEXT=$(cat "$HUMAUX_NODE_DIR/release.next"); M="$(nv HUMAUX_NODE_RELEASES_DIR)/release-$NEXT.manifest"
SHA=$(sed -n 's/^IMAGE .* git_sha=\([0-9a-f]\{40\}\).*/\1/p' "$M" | head -n 1)
case "$NEXT" in *-"$(printf '%s' "$SHA" | cut -c1-12)") ;; *) echo "precheck: tag $NEXT does not end in the manifest's sha $SHA"; exit 1 ;; esac
export HUMAUX_IMAGE_TAG="$NEXT" HUMAUX_PG_IMAGE="humaux-pg:$NEXT"
[ -r CHECKOUT_TREE ] || { echo "precheck: $PWD/CHECKOUT_TREE is missing (unpack humaux-checkout-$NEXT.tar.gz, §R)"; exit 1; }
DR=$(awk -v r="humaux-dr:$NEXT" '$1 == "IMAGE" && $2 == r { sub(/^id=/, "", $3); print $3 }' "$M")  # the verifier, checked from the host before it runs
GOT=$(docker image inspect -f '{{.Id}}' "humaux-dr:$NEXT" 2>/dev/null) || GOT="<not loaded>"
[ -n "$DR" ] && [ "$GOT" = "$DR" ] \
  || { echo "precheck: humaux-dr:$NEXT is $GOT; the manifest's dr image is ${DR:-<none>}"; exit 1; }
$C run --rm -T dr deploy-check --release "$NEXT" --manifest "$M" --expect-sha "$SHA" --checkout-tree "$(cat CHECKOUT_TREE)"
$C --profile ops config --format json --no-env-resolution | $C run --rm -T dr deploy-check --compose-json - --env \
  --values-dir "$(nv HUMAUX_NODE_DEPLOY_DIR)/env/values" --secrets-dir "$(nv HUMAUX_SECRETS_DIR)" \
  --examples-dir /usr/share/humaux/env/example
echo "PRECHECK ok $NEXT git_sha=$SHA"
```

U4 stops every writer (OPS-9); PostgreSQL, Qdrant and observability keep running. It also removes every container of
the project whose service the next release's `prod.yml` no longer defines (a removed or renamed writer would
otherwise keep using the database through the migration, and `deploy-check --running` only sees the new document's
services; PR #2 round 7). U7's `up` passes `--remove-orphans` for the same reason.

<!-- step: U4 expect: 0 -->
```sh
C="sh deploy/release/compose.sh"
$C stop gateway consolidation private-distill private-rpc retrieval-serve retrieval-rpc maintenance-serve maintenance-health
SV=$($C --profile ops --profile rehearsal config --services)  # a failure stops the step (no pipeline hides it)
printf '%s\n' "$SV" | grep -qx gateway || { echo "upgrade: config --services listed no gateway; refusing to remove anything"; exit 1; }
S=" $(printf '%s\n' "$SV" | tr '\n' ' ') "
for c in $(docker ps -aq --filter "label=com.docker.compose.project=$HUMAUX_NODE_PROJECT"); do
  s=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.service"}}' "$c")
  case "$S" in *" $s "*) ;; *) echo "upgrade: removing $s (a service the next release's prod.yml no longer has)"; docker rm -f "$c" >/dev/null ;; esac
done
```

<!-- step: U5 expect: 0 match: migrate: pass ( -->
```sh
C="sh deploy/release/compose.sh"
export HUMAUX_IMAGE_TAG="$(cat "$HUMAUX_NODE_DIR/release.next")"
$C run --rm -T migrate migrate
```

<!-- step: U6 expect: 0 -->
```sh
C="sh deploy/release/compose.sh"
export HUMAUX_IMAGE_TAG="$(cat "$HUMAUX_NODE_DIR/release.next")"
$C run --rm -T migrate rls-check
```

U7 makes the next tag the node's tag, renders the observability configs with its sha, and starts everything in
order (services whose image changed are recreated; Prometheus and Alertmanager are restarted to read the new
render).

<!-- step: U7 expect: 0 match: SWITCHED -->
```sh
C="sh deploy/release/compose.sh"
nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
NEXT=$(cat "$HUMAUX_NODE_DIR/release.next"); E="$HUMAUX_NODE_DIR/node.env"
awk -v t="$NEXT" '/^HUMAUX_IMAGE_TAG=/ { print "HUMAUX_IMAGE_TAG=" t; next } /^HUMAUX_PG_IMAGE=/ { print "HUMAUX_PG_IMAGE=humaux-pg:" t; next } { print }' "$E" > "$E.new"
mv "$E.new" "$E"
SHA=$($C run --rm -T admin version | sed -n 's/.* git_sha=\([0-9a-f]\{40\}\).*/\1/p')
[ -n "$SHA" ] || { echo "upgrade: humaux-admin version printed no sha"; exit 1; }
umask 022
sh deploy/prometheus/render.sh "$(nv HUMAUX_OBSERVABILITY_RENDERED_DIR)" "$SHA" /run/humaux-alert-urls
$C up -d --wait --wait-timeout 300 --remove-orphans
$C restart prometheus alertmanager
echo "SWITCHED to $NEXT git_sha=$SHA"
```

<!-- step: U8 expect: 0 match: VERIFY ok -->
```sh
C="sh deploy/release/compose.sh"
nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
TAG=$(nv HUMAUX_IMAGE_TAG); M="$(nv HUMAUX_NODE_RELEASES_DIR)/release-$TAG.manifest"
SHA=$(sed -n 's/^IMAGE .* git_sha=\([0-9a-f]\{40\}\).*/\1/p' "$M" | head -n 1)
$C --profile ops config --format json --no-env-resolution | $C run --rm -T dr deploy-check --running --project "$HUMAUX_NODE_PROJECT" --compose-json -
$C run --rm -T admin version | grep -F "git_sha=$SHA"
i=0
until $C exec -T prometheus wget -qO- 'http://127.0.0.1:9090/api/v1/query?query=count%28up%7Bjob%3D~%22humaux-.%2A%22%7D%3D%3D1%29' | grep -q '"8"\]'; do
  i=$((i + 1)); [ "$i" -lt 24 ] || { echo "verify: fewer than 8 humaux targets are up after 120 s"; exit 1; }; sleep 5
done
echo "VERIFY ok git_sha=$SHA targets_up=8"
```

U9 is the smoke on the new release; its canary is the rollback proof's marker **M2** (written after the
pre-upgrade backup, so a correct rollback must not know it).

<!-- step: U9 expect: 0 match: SMOKE ok smoke-a m2 -->
```sh
nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
P=$(nv HUMAUX_NODE_GATEWAY_HOST_PORT); D="$HUMAUX_NODE_DIR/smoke"
mcp() { # $1 = API-key header file, $2 = tool, $3 = arguments JSON
  curl -sS -X POST "http://127.0.0.1:$P/mcp" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H "Mcp-Name: $2" -H "Origin: http://127.0.0.1:$P" -H @"$1" \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":$3,\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientInfo\":{\"name\":\"runbook-v2\",\"version\":\"1\"},\"io.modelcontextprotocol/clientCapabilities\":{}}}}"
}
uuid() { h=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n'); echo "$(echo "$h" | cut -c1-8)-$(echo "$h" | cut -c9-12)-4$(echo "$h" | cut -c14-16)-a$(echo "$h" | cut -c18-20)-$(echo "$h" | cut -c21-32)"; }
TOK=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n'); echo "$TOK" > "$D/m2.token"
WS=$(sed -n 's/^workspace_id=//p' "$D/a.ids")
mcp "$D/a.auth" remember "{\"operation\":\"put\",\"content\":\"The node smoke canary codename is $TOK and it ships on Fridays.\",\"idempotency_key\":\"$(uuid)\",\"workspace_id\":\"$WS\"}" > "$D/m2.put.json"
grep -q '"isError":true' "$D/m2.put.json" && { echo "smoke: remember.put failed: $(head -c 300 "$D/m2.put.json")"; exit 1; }
i=0
until mcp "$D/a.auth" recall "{\"query\":\"What is the node smoke canary codename?\",\"workspace_id\":\"$WS\",\"mode\":\"semantic\"}" | grep -q "$TOK"; do
  i=$((i + 1)); [ "$i" -lt 60 ] || { echo "smoke: recall did not return canary $TOK within 600 s"; exit 1; }; sleep 10
done
echo "SMOKE ok smoke-a m2 canary=$TOK"
```

**Rollback.** "Previous state" = the database as of the end of backup `PRE_UPGRADE_LABEL`, every service on the
previous tag `PREV_TAG` (both captured by the executor above). RB1 is the gate: if the previous images are not the
ones the previous manifest recorded (a corrupt or swapped tag), or the checkout the executor runs from is not the
previous release's (`checkout_tree_mismatch`: install it as the paragraph before U1 says), STOP — the rollback must
not proceed.

<!-- step: RB1 expect: 0 match: PREV IMAGES ok -->
```sh
C="sh deploy/release/compose.sh"
nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
: "${PREV_TAG:?captured by U1}"
export HUMAUX_IMAGE_TAG="$PREV_TAG"  # node.env names the next tag since U7: run (and check) the previous release's dr
M="$(nv HUMAUX_NODE_RELEASES_DIR)/release-$PREV_TAG.manifest"
SHA=$(sed -n 's/^IMAGE .* git_sha=\([0-9a-f]\{40\}\).*/\1/p' "$M" | head -n 1)
case "$PREV_TAG" in *-"$(printf '%s' "$SHA" | cut -c1-12)") ;; *) echo "rollback: tag $PREV_TAG does not end in the manifest's sha $SHA"; exit 1 ;; esac
[ -r CHECKOUT_TREE ] || { echo "rollback: $PWD/CHECKOUT_TREE is missing (unpack humaux-checkout-$PREV_TAG.tar.gz, §R)"; exit 1; }
DR=$(awk -v r="humaux-dr:$PREV_TAG" '$1 == "IMAGE" && $2 == r { sub(/^id=/, "", $3); print $3 }' "$M")  # the verifier, checked from the host before it runs
GOT=$(docker image inspect -f '{{.Id}}' "humaux-dr:$PREV_TAG" 2>/dev/null) || GOT="<not loaded>"
[ -n "$DR" ] && [ "$GOT" = "$DR" ] \
  || { echo "rollback: humaux-dr:$PREV_TAG is $GOT; the manifest's dr image is ${DR:-<none>}"; exit 1; }
$C run --rm -T dr deploy-check --release "$PREV_TAG" --manifest "$M" --expect-sha "$SHA" --checkout-tree "$(cat CHECKOUT_TREE)"
echo "PREV IMAGES ok $PREV_TAG git_sha=$SHA"
```

RB2 stops and removes the upgraded project's containers. **Never `-v`**: the old volumes stay for forensics.
`--remove-orphans` takes the containers of services the upgraded release added or renamed (RB1 switched the executor
to the previous checkout, whose `prod.yml` does not name them), and the step ends only when no container carries the
project's label (PR #2 round 5).

<!-- step: RB2 expect: 0 -->
```sh
C="sh deploy/release/compose.sh"
$C --profile ops --profile rehearsal down --remove-orphans
L="label=com.docker.compose.project=$HUMAUX_NODE_PROJECT"
[ -z "$(docker ps -aq --filter "$L")" ] || { echo "rollback: containers of $HUMAUX_NODE_PROJECT remain after down:"; docker ps -a --filter "$L" --format '{{.Names}}'; exit 1; }
```

RB3 points the node at a new project `<project>-rb1` on the previous tag and restores the pre-upgrade backup into
it (`restore pitr` refuses when the new data volume is not empty, while a `pg` container of the project it runs
under — the new one — is running, when the disk would drop below its floor, and when the set does not verify). That
refusal cannot see the old project: RB2's `down` is the only guard against two clusters archiving into one stanza, so
never skip RB2. It boots the restored cluster socket-only, sets NOLOGIN on every LOGIN role but `postgres`,
`role_maintenance` and `role_retrieval_worker`, records those roles (`nologin_roles`) and the in-flight state in the
evidence file, then boots with TCP: the restored cluster archives on its new timeline and is the new production.
From here on, every step reads the project from `node.env`. A retried RB3 keeps the same target (PR #2 round 7):
the target name is written to `evidence/rb3.target` before `node.env` changes and removed only after a restore, so a
retry after a part-way failure re-uses `<project>-rb1` (never `<project>-rb1-rb1`, which would leave the partial
cluster running beside a second one archiving into the same stanza), removes that partial target (`down -v`: its
volumes are a copy of the backup, never the upgraded project's) and restores again; a target whose evidence already
says `restored` STOPs with "continue at RB4".

<!-- step: RB3 expect: 0 match: RESTORED -->
```sh
C="sh deploy/release/compose.sh"
nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
: "${PREV_TAG:?captured by U1}" "${PRE_UPGRADE_LABEL:?captured by U2}"
E="$HUMAUX_NODE_DIR/node.env"; EVF="$(nv HUMAUX_NODE_EVIDENCE_DIR)/rollback-1.json"
MK="$HUMAUX_NODE_DIR/evidence/rb3.target"  # exists only while an RB3 is in flight or failed part-way
if [ -r "$MK" ]; then
  NEW=$(cat "$MK")
  [ "$(nv HUMAUX_NODE_PROJECT)" = "$NEW" ] || { echo "rollback: $MK names $NEW but node.env names $(nv HUMAUX_NODE_PROJECT)"; exit 1; }
  S=""; [ -r "$EVF" ] && S=$(tr -d ' \t\r\n' < "$EVF")
  case "$S" in *'"outcome":"restored"'*) echo "rollback: $NEW is already restored ($EVF): continue at RB4"; exit 1 ;; esac
  export HUMAUX_NODE_PROJECT="$NEW"
  echo "rollback: removing the partial target $NEW a failed RB3 left (its volumes are a copy of the backup)"
  $C --profile ops --profile rehearsal down -v --remove-orphans
else
  DONE="$HUMAUX_NODE_DIR/evidence/rb3.done"  # this upgrade's completed restore (U1 clears it)
  [ ! -r "$DONE" ] || [ "$(cat "$DONE")" != "$(nv HUMAUX_NODE_PROJECT)" ] \
    || { echo "rollback: $(nv HUMAUX_NODE_PROJECT) is this rollback's restored project: continue at RB4"; exit 1; }
  [ -e "$EVF" ] && mv "$EVF" "$EVF.$(date -u +%Y%m%dT%H%M%SZ)"  # an earlier rollback's evidence is not this one's
  NEW="$(nv HUMAUX_NODE_PROJECT)-rb1"; echo "$NEW" > "$MK"
  awk -v t="$PREV_TAG" -v p="$NEW" '/^HUMAUX_IMAGE_TAG=/ { print "HUMAUX_IMAGE_TAG=" t; next } /^HUMAUX_PG_IMAGE=/ { print "HUMAUX_PG_IMAGE=humaux-pg:" t; next } /^HUMAUX_NODE_PROJECT=/ { print "HUMAUX_NODE_PROJECT=" p; next } { print }' "$E" > "$E.new"
  mv "$E.new" "$E"
  export HUMAUX_NODE_PROJECT="$NEW"
fi
$C run --rm -T dr restore pitr --compose-file "$(nv HUMAUX_NODE_DEPLOY_DIR)/compose/prod.yml" --project "$NEW" \
  --target-backup "$PRE_UPGRADE_LABEL" --evidence "$EVF"
echo "$NEW" > "$HUMAUX_NODE_DIR/evidence/rb3.done"
rm -f "$MK"
echo "RESTORED project=$NEW tag=$PREV_TAG backup=$PRE_UPGRADE_LABEL"
```

RB4 re-enables exactly the roles `restore pitr` locked — the `nologin_roles` array of the evidence file
`rollback-1.json` (§11.6 step 4); it refuses when the file or the field is missing — and starts the
new project's PostgreSQL, Qdrant and the retrieval projector (`retrieval-serve`) — nothing that serves or writes:
the gateway and the other writers start in RB5 only after the rebuild, so no recall sees an empty or half-built index
and no write moves the rebuild boundary (PR #2 round 9). Before `up`, RB4 re-renders the observability configs with the PREVIOUS release's sha (U7 had rendered the upgrade's; the shared `rendered/` directory would otherwise make every later alert and the Watchdog report the rolled-back version — PR #2 review).

<!-- step: RB4 expect: 0 -->
```sh
C="sh deploy/release/compose.sh"
nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
HUMAUX_NODE_PROJECT=$(nv HUMAUX_NODE_PROJECT); export HUMAUX_NODE_PROJECT
EVF="$(nv HUMAUX_NODE_EVIDENCE_DIR)/rollback-1.json"
[ -r "$EVF" ] || { echo "rollback: restore evidence $EVF is missing or unreadable"; exit 1; }
FLAT=$(tr -d ' \t\r\n' < "$EVF")
case "$FLAT" in *'"nologin_roles":['*) ;; *) echo "rollback: $EVF has no nologin_roles field"; exit 1 ;; esac
ROLES=$(printf '%s' "$FLAT" | sed -n 's/.*"nologin_roles":\[\([^]]*\)\].*/\1/p' | tr -d '"' | tr ',' ' ')
SQL=""
for r in $ROLES; do
  case "$r" in *[!a-z0-9_]*) echo "rollback: $EVF names a malformed role: $r"; exit 1 ;; esac
  SQL="$SQL ALTER ROLE $r LOGIN;"
done
if [ -n "$SQL" ]; then $C exec -T pg psql -U postgres -d humaux -v ON_ERROR_STOP=1 -c "$SQL"; fi
echo "rollback: LOGIN re-enabled: ${ROLES:-none}"
: "${PREV_TAG:?captured by U1}"
SHA=$(sed -n 's/^IMAGE .* git_sha=\([0-9a-f]\{40\}\).*/\1/p' "$(nv HUMAUX_NODE_RELEASES_DIR)/release-$PREV_TAG.manifest" | head -n 1)
[ -n "$SHA" ] || { echo "rollback: the previous manifest carries no git_sha"; exit 1; }
umask 022
sh deploy/prometheus/render.sh "$(nv HUMAUX_OBSERVABILITY_RENDERED_DIR)" "$SHA" /run/humaux-alert-urls
$C up -d --wait --wait-timeout 300 pg qdrant retrieval-serve  # no gateway, no writer until RB5's rebuild completes
```

RB5 rebuilds Qdrant from the restored PostgreSQL (the new project's Qdrant volume is empty; ADR-0064 rebuild
generation, no provider call), then proves the previous state: the running images are exactly the previous
manifest's (and none of the upgrade's), the sha is the previous one, the schema head equals the pre-upgrade value,
marker M1 is recalled and marker M2 is absent; it ends with R7's `rls-check` and `deploy-check --roles-sql`
(every role logs in again, the 0011 hygiene holds). Restored jobs that were in flight at the backup are reconciled by
the resident sweeps; a ledger row left `RESERVED` is read as §7.1 says.

<!-- step: RB5 expect: 0 match: ROLLBACK VERIFIED -->
```sh
C="sh deploy/release/compose.sh"
nv() { sed -n "s/^$1=//p" "$HUMAUX_NODE_DIR/node.env" | tail -n 1; }
HUMAUX_NODE_PROJECT=$(nv HUMAUX_NODE_PROJECT); export HUMAUX_NODE_PROJECT
: "${PREV_TAG:?captured by U1}"
REL=$(nv HUMAUX_NODE_RELEASES_DIR); M="$REL/release-$PREV_TAG.manifest"; MN="$REL/release-$(cat "$HUMAUX_NODE_DIR/release.next").manifest"
SHA=$(sed -n 's/^IMAGE .* git_sha=\([0-9a-f]\{40\}\).*/\1/p' "$M" | head -n 1)
$C run --rm -T ops projection rebuild --all --batch 100 --wait-seconds 900
$C up -d --wait --wait-timeout 300  # the gateway and every other service, only now
$C --profile ops config --format json --no-env-resolution | $C run --rm -T dr deploy-check --running --project "$HUMAUX_NODE_PROJECT" --compose-json -
$C run --rm -T admin version | grep -F "git_sha=$SHA"
for pair in gateway:gateway retrieval-rpc:retrieval-worker retrieval-serve:retrieval-worker private-rpc:private-worker \
            private-distill:private-worker consolidation:consolidation-worker maintenance-health:maintenance maintenance-serve:maintenance; do
  svc=${pair%%:*}; tgt=${pair#*:}
  run=$(docker inspect -f '{{.Image}}' "$($C ps -q "$svc")")
  want=$(awk -v i="humaux-$tgt:$PREV_TAG" '$1 == "IMAGE" && $2 == i { sub(/^id=/, "", $3); print $3 }' "$M")
  [ "$run" = "$want" ] || { echo "rollback: $svc runs $run, the previous manifest says $want"; exit 1; }
  grep -q "id=$run " "$MN" && { echo "rollback: $svc runs an image of the upgrade manifest"; exit 1; }
done
POST=$($C exec -T pg psql -U postgres -d humaux -Atc 'select max(migration_id) from ops.schema_migrations')
[ "$POST" = "$(cat "$HUMAUX_NODE_DIR/smoke/schema_head.pre")" ] || { echo "rollback: schema head $POST differs from the pre-upgrade head"; exit 1; }
P=$(nv HUMAUX_NODE_GATEWAY_HOST_PORT); D="$HUMAUX_NODE_DIR/smoke"; WS=$(sed -n 's/^workspace_id=//p' "$D/a.ids")
recall() {
  curl -sS -X POST "http://127.0.0.1:$P/mcp" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: recall' -H "Origin: http://127.0.0.1:$P" -H @"$D/a.auth" \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"recall\",\"arguments\":{\"query\":\"What is the node smoke canary codename?\",\"workspace_id\":\"$WS\",\"mode\":\"semantic\"},\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientInfo\":{\"name\":\"runbook-v2\",\"version\":\"1\"},\"io.modelcontextprotocol/clientCapabilities\":{}}}}"
}
recall > "$D/rollback.recall.json"
grep -q "$(cat "$D/m1.token")" "$D/rollback.recall.json" || { echo "rollback: marker M1 is not recalled"; exit 1; }
grep -q "$(cat "$D/m2.token")" "$D/rollback.recall.json" && { echo "rollback: marker M2 is still recalled"; exit 1; }
$C run --rm -T migrate rls-check
$C run --rm -T -v "$PWD/migrations/0011_roles_and_grants.sql:/usr/share/humaux/0011_roles_and_grants.sql:ro" migrate \
  deploy-check --roles-sql /usr/share/humaux/0011_roles_and_grants.sql
echo "ROLLBACK VERIFIED tag=$PREV_TAG git_sha=$SHA m1=present m2=absent schema_head=$POST"
```

RB6 takes a VERIFIED backup on the new timeline at once. Then make `HUMAUX_NODE_PROJECT` of the operator's
environment and of the host crontab (§5) the new project name (node.env already carries it), and never start the
old project again; to read its data, ask first.

<!-- step: RB6 expect: 0 match: BACKUP ok -->
```sh
C="sh deploy/release/compose.sh"
HUMAUX_NODE_PROJECT=$(sed -n 's/^HUMAUX_NODE_PROJECT=//p' "$HUMAUX_NODE_DIR/node.env" | tail -n 1); export HUMAUX_NODE_PROJECT
$C run --rm -T dr backup run
echo "BACKUP ok project=$HUMAUX_NODE_PROJECT (set HUMAUX_NODE_PROJECT=$HUMAUX_NODE_PROJECT for every later step and in the crontab)"
```

**Migration 0210 and a non-superuser migrator** (ADR-0061 review-fix 3, F2; documented, not executed by this
bundle). 0210 makes the NOLOGIN `role_health_reader` the owner of `ops.health_snapshot(timestamptz)` and
`ops.admin_probe_snapshot()` with `ALTER FUNCTION … OWNER TO`. The bundle's migrator is the superuser (L-13), so
0210 runs as written. Any other executor needs, for the duration of 0210 only: membership in
`role_health_reader` with the SET option (`GRANT role_health_reader TO <migrator> WITH INHERIT FALSE, SET TRUE`) and
`GRANT CREATE ON SCHEMA ops TO role_health_reader`; revoke both right after 0210 (`REVOKE role_health_reader FROM
<migrator>`, `REVOKE CREATE ON SCHEMA ops FROM role_health_reader`), then run `rls-check`: it is red while the
reader has a member or the extra grant.

## 8. Load sizing — read before the first real traffic

The Distill hop makes **one serial provider round trip per Evidence**, so its throughput is the provider's, not the
database's. Measured on this deployment: **0.229 Evidence/s** (n = 140 `processing_runs` over 611 s, MiniMax, one
resident distill dispatcher). Ingest above that number builds a backlog no amount of correct code will drain. Size
for `tenants × sessions / (think_secs + round_trip_secs) < 0.229`, and **re-measure that line whenever the provider
or model changes**. `docs/ops/soak.md` §"Size the load to the distill hop's capacity" has the full rule.

On the A5 host the load phases run from the `loadgen` image (no toolchain): `deploy/release/a5_load_remeasure.sh`
(ADR-0066 D-S) deploys by this runbook's first-install steps (§1–§3 and §7), seeds two load tenants and runs the card-38 phase set with
`--host-class a5 --meminfo-path /proc/meminfo`; it passes only with fresh `host=a5-4cpu-vm2[2-5]` LOAD lines for
every level, and always prints `SIGNAL L16 reopen|hold`.

### 8.1 Gateway admission and pool (dev-host)

ADR-0065. Every key below is required with no default: a gateway without it, or with it empty, refuses to boot
naming the key. The values are **dev-host start values, A5 re-measure required** (10 CPU, PostgreSQL in a 3.8 GiB
Docker VM). This table stays titled "(dev-host)" until card 39's gate `a5_load_remeasure` has run the same load
phases on the 4-vCPU / 24 GiB ARM host (open item O-1). Each value cites the ADR-0065 line it rests on
("Measurement" → AFTER, run `after-fix` 2026-10-07 11:12, `host=10cpu-vm3.8`).

| Key (`HUMAUX_GATEWAY_…`) | Start value | Why this value | Boot rule |
|---|---|---|---|
| `ADMISSION_CONCURRENCY` (C) | 16 | §67.2; `SWEEP C=8/16/24`: same throughput, C only trades enumerate p95 against tools/list p95 | ≥ 1 |
| `ADMISSION_QUEUE_DEPTH` (Q) | 64 | §67.2 | ≥ 0 (0 = no waiting) |
| `ADMISSION_MAX_WAIT_MS` (W) | 5000 | §67.2; `LOAD BURST` 503 p100 within W + 200 ms | > 0 |
| `ADMISSION_PER_KEY_LIMIT` (K) | 8 | = C / 2, measured: at K = C one key held every permit and tenant B's p95 was 2.5× its baseline; K = 8 gives 1.8× (`ISO_RATIO`); K = C + Q gives 9.4× (F-K) | 1 ≤ K ≤ C + Q |
| `ADMISSION_BODY_READ_TIMEOUT_MS` (B) | 5000 | protective bound: `MAX_REQUEST_BODY_BYTES` / B is the slowest accepted upload | > 0, ≤ handler timeout |
| `PG_POOL_MAX_CONNECTIONS` (P) | 18 | P = C·k + 2 + H, k = 1, H = 0: `LOAD L64` 0 drops, 0 acquire timeouts (D-A) | ≥ 1 |
| `PG_POOL_MIN_CONNECTIONS` | 2 | keeps two connections warm | ≤ max |
| `PG_ACQUIRE_TIMEOUT_MS` | 1000 | fail as `DEPENDENCY_UNAVAILABLE` long before the handler timeout | > 0 |
| `PG_IDLE_TIMEOUT_SECONDS` / `PG_MAX_LIFETIME_SECONDS` | 300 / 1800 | sqlx's lifetime default; idle shortened | > 0; lifetime > idle |
| `PG_STATEMENT_TIMEOUT_MS` | 10000 | below the 20 s handler timeout, so the server cancels first (D-B) | lock < statement < handler |
| `PG_IDLE_IN_TRANSACTION_TIMEOUT_MS` | 10000 | same scale | > 0, ≤ handler |
| `RATE_LOCK_TIMEOUT_MS` | 2000 | the former literal (D-D) | > 0, < statement |
| `RATE_PREAUTH_IPV6_PREFIX_BITS` | 64 | one bucket per IPv6 /64 (D-E) | 1..=128 |

Measured (`LOAD` lines in ADR-0065 "Measurement", each with its n):

| Phase (LA clients) | BEFORE: HEAD, no admission, sqlx pool 10 (2026-10-06, `host=10cpu-vm3.8`) | AFTER: start values above (2026-10-07 `after-fix`, `host=10cpu-vm3.8`) |
|---|---|---|
| L8 enumerate p95 | 71.1 ms (n = 4917) | 65.4 ms (n = 5580) |
| L16 enumerate p95 | 136.8 ms (n = 5076) | 263.1 ms (n = 5658; p50 87.5 ms; not the tenant lock, ADR-0065 L16) |
| L32 enumerate p95 | 258.4 ms (n = 5029) | 353.2 ms (n = 5666) |
| L64 enumerate p95 | 488.2 ms (n = 5052), 0 failed, 0 drops | 542.4 ms (n = 5616), 0 failed, 0 drops |
| L64 tenant-lock wait (`LOCKWAIT`) | not measured | p99 9.7 ms over 8974 takes, longest 100.9 ms (resolution 10 ms) |
| BURST (128) enumerate p95 | 1067.6 ms (n = 2136), 0 refused: nothing bounds the queue | 607.1 ms (n = 2572) admitted; 960 `queue_full` 503s |
| BURST-W (W = 1 ms) | not run (no admission) | 1680 `wait_timeout` 503s, 0 failed |
| tenant B p95 next to a 64-client one-key burst | ≈ 45 ms → ≈ 500 ms, median ratio 11.40 over 3 pairs | 40–41 ms → 71–73 ms, median ratio 1.78 (K = 8) |
| throughput | flat ≈ 155 calls/s from L8 to BURST | flat ≈ 178 calls/s from L16 up (CPU-bound host) |
| PG backends peak | 24 client backends, role_gateway 11 | 34 client backends, role_gateway 20 (18 + the rehearsal gateway's 2) |

**Reading a gateway 503.** An MCP request refused by admission gets `503`, an integer `Retry-After` (1–30 s) and
the text body `RATE_LIMITED`; the process is healthy and full. `/readyz` and `/livez` are outside admission, so
only `/readyz` → `503` means "do not route here" (`docs/ops/supervision.md`).
`admission_rejected_total{class="gateway_inbound",reason}` tells which bound refused it; the `AdmissionRejected`
alert fires on any increase over 5 min:

| `reason` | What filled up | First thing to check |
|---|---|---|
| `key_limit` | one credential has K requests in flight or waiting | which client fans out on one key; give it more keys or lower its concurrency |
| `queue_full` | C requests in flight and Q waiting | service time: `/status`, PG backends of `role_gateway`, slow statements |
| `wait_timeout` | a waiter got no permit within W | the same, sustained; a provider blip on recall holds permits for one provider timeout each (ADR-0065 L12) |

A `DEPENDENCY_UNAVAILABLE` 503 without `Retry-After` is not admission: it is a pool acquire past
`PG_ACQUIRE_TIMEOUT_MS`, a statement past `PG_STATEMENT_TIMEOUT_MS`, or a rate-lock wait past
`RATE_LOCK_TIMEOUT_MS`. Abandoned statements keep their pool slot until statement_timeout ends them (ADR-0065 L13).
`max_connections` of the bundle's PostgreSQL (190, `deploy/postgres/sizing-*.conf`) is the D-G sum of every
process's pools plus headroom; the worker pool caps are card 38b.

## 9. Operating rules that outrank convenience

- **Never kill by port.** `lsof -ti :PORT | xargs kill` and `fuser -k` are banned. On 2026-09-09 that exact command
  terminated the user's WeChat, which happened to hold port 8080. On a node, stop services only through the
  compose wrapper and only those of this project.
- **Never run a DELETE-class command against shared state as a smoke test.** The smoke tenants (§3.0) exist for
  that. See `docs/ops/delivery_point_report.md` §5.2 for the time this rule was learned.
- **Never stop or restart shared infrastructure containers to simulate an outage.** The acceptance drills (§A)
  stop only this project's `maintenance-health`.
- **Never `down -v`** a production project: the volumes are the data (§R RB2).
- **A STOP is a STOP.** A step whose result is not its expectation is a runbook or release bug: report it with the
  step id and the executor's exec.log line, never work around it (appendix A).

## 10. Rotate — role passwords, API-key pepper, token key, provider keys, DNS pins

ADR-0059. Every value below lives in the node's secrets directory (0600 files) and reaches a process as an
environment variable through its `env_file`; none is ever on argv, in a tracked file or in a log. Rotation never
needs a migration. After editing a secret file, recreate the services that load it through the compose wrapper
(`up -d --no-deps --force-recreate <service>…`); compose does not reread an `env_file` of a running container.

### 10.1 PostgreSQL role passwords

Preconditions: new values in `migrate.secret.env` as `HUMAUX_ROLE_PASSWORD_<SUFFIX>` (at least 32 characters of
`[A-Za-z0-9._~-]`, not built on the 0011 placeholder prefix; `openssl rand -hex 24` gives one), or let `rotate`
generate them. `rotate` refuses, naming the variable, any value that equals or contains a repository placeholder.

1. `deploy-check --roles-sql <0011 file>` on the `migrate` one-shot (as step R7 mounts it) — record the state.
2. `roles rotate --roles-sql <0011 file> <A> [--role role_x]` on the `migrate` one-shot (the first install uses
   `roles rotate --create-missing`, step R4). One transaction; only SCRAM verifiers reach the server; generated
   values print once after COMMIT — redirect them into the secrets file, never into a log. Crash or unknown
   outcome: re-run with the variables set — idempotent (same passwords, fresh salts). The rotating principal is
   never a target.
3. Put each new password into the DSN of the process's `<process>.secret.env` and recreate **one service at a
   time**. Open sessions survive; only new connections need the new value (ADR-0059 L2).
4. `deploy-check --roles-sql` → exit 0.
5. The superuser itself: `\password postgres` in a `psql` of the `pg` service, then update `pg_superuser` and
   `HUMAUX_MIGRATOR_PG_DSN` in `migrate.secret.env`.

### 10.2 API-key pepper — rolling phases, never one restart (gateway replicas ≥ 2, §67.5)

Generate a new 32-byte hex value N; O is the current one. The single-node bundle runs one gateway replica, so each
"rolling restart" below is one recreate of `gateway`; the phases still apply because the database rehash window
is shared state.

1. **Verify both.** Every gateway replica: `HUMAUX_GATEWAY_CREDENTIAL_PEPPER_HEX=O`,
   `HUMAUX_GATEWAY_CREDENTIAL_PEPPER_PREVIOUS_HEX=N`; rolling restart until **all** replicas run it. Maintenance
   stays on O.
2. **Switch current.** Maintenance `HUMAUX_MAINTENANCE_CREDENTIAL_PEPPER_HEX=N`, recreate `maintenance-serve` and
   `maintenance-health`; then every replica `…_PEPPER_HEX=N`, `…_PEPPER_PREVIOUS_HEX=O`, rolling restart. A replica
   still in phase 1 that sees an N-hashed key matches it as previous and asks to rehash; the closed rehash window
   refuses that (non-fatal), so keys never ping-pong.
3. **Open rehash.** Only after all replicas are in phase 2: `apikey pepper-epoch advance <A>` on the `ops` one-shot
   (next epoch, rehash window open). A key used from now on is rehashed to N once (migrations 0202–0204). Run it
   once: while the window is open a second `advance` is refused, exit 3, `"reason": "rehash_window_open"`, epoch
   unchanged (migration 0205).
4. **Close.** After the window you chose: `apikey pepper-epoch close <A>`, then unset `…_PEPPER_PREVIOUS_HEX` with a
   rolling restart. A key not used in the window is refused from then on: re-issue it.

Side effects: outstanding enumerate cursors and email verification codes die when a replica's current pepper
changes (phase 2). Between `advance` and `close`, the role_gateway database credential can rewrite each
not-yet-rehashed key's verifier once, audited (L12), so keep the window no longer than it must be.

Rollback. Before phase 3, undo the phases in reverse: maintenance back to O, then every replica
`…_PEPPER_HEX=O`, `…_PEPPER_PREVIOUS_HEX=N`, rolling restart; unset `…_PREVIOUS_HEX` only once no key was issued
under N. After `advance`, keys already rehashed verify only under N: `close` first, then make O current and N
previous — every key still verifies — and never unset N while a key is hashed under it. Never roll back by
unsetting `…_PREVIOUS_HEX` mid-rotation: every key on the other pepper is refused at once.

Card-33 rollout: a pre-card-33 gateway reads no `…_PEPPER_PREVIOUS_HEX` and never calls the rehash door, so do not
start phase 1 until every replica runs the card-33 build.

### 10.3 Consistency-token key — same shape

1. Every replica `HUMAUX_GATEWAY_TOKEN_HMAC_KEY=O`, `HUMAUX_GATEWAY_TOKEN_HMAC_KEY_PREVIOUS=N` (hex, ≥ 32 bytes,
   N ≠ O); rolling restart until all run it.
2. Every replica `…_TOKEN_HMAC_KEY=N`, `…_PREVIOUS=O`; rolling restart.
3. After one token TTL (`HUMAUX_GATEWAY_REMEMBER_TOKEN_TTL_SECONDS`), unset `…_PREVIOUS` with a rolling restart.

The token MAC proves only that a gateway issued those fields unchanged; it is not authorization.

Rollback. Before step 3, swap back: every replica `…_TOKEN_HMAC_KEY=O`, `…_PREVIOUS=N`, rolling restart. After
step 3 (O gone), going back to O is the same three steps with O as the new key; unsetting N earlier refuses every
outstanding token N signed (`token_malformed`) until it expires.

Card-33 rollout (mixed versions): a pre-card-33 gateway issues unsigned tokens, which a card-33 gateway refuses,
and refuses the card-33 wire form. Avoid a mixed roll: start the full set of card-33 replicas with the same key,
switch all traffic at once, then stop the old set; only tokens issued before the switch are refused, for at most
one TTL (L4).

### 10.4 Provider keys (private worker)

`HUMAUX_PRIVATE_WORKER_CREDENTIALS = <credential_ref>=<ENV_NAME>[,…]` names, per credential reference, the variable
holding its key (ADR-0059 D-I), both in `private-worker.secret.env`. To rotate: put the new key under a **new**
variable name in that file, point the map entry at it, recreate `private-rpc` and `private-distill`, then revoke
the old key at the provider and delete the old variable. A reference missing from the map parks its distill jobs
`WAITING_KEY` with class `CREDENTIAL_NOT_MAPPED` — no ledger row, no provider call, no attempt spent — re-checked
every `HUMAUX_PRIVATE_WORKER_DISTILL_NOT_READY_PARK_SECS`. References that share one key must all be bound to one
vendor account, or the worker refuses to start naming them (ADR-0060 D-J); boot prints one `credential ref=<uuid>
env=<NAME> account_hash=<8 hex|unregistered>` line per entry.

The provider, model, endpoint and capabilities of every call come from its admitted route (ADR-0060 D-B). The
worker env names only the deny-only lists `HUMAUX_PRIVATE_WORKER_EGRESS_RECIPIENTS =
<egress_processor_id>=<host>[|<host>…][,…]` and `HUMAUX_PRIVATE_WORKER_REGIONS = <region>[,…]`; both are required,
an explicitly empty value allows nothing. `HUMAUX_PRIVATE_WORKER_HEALTH_RENEW_SECS` (required, ruling E3): after a
SUCCEEDED call the worker appends a HEALTHY observation valid for this many seconds when the admitted one has less
than half left; after a provider 401 it appends one INVALID credential verdict, so the next admission is refused
`ROUTE_HEALTH_DENIED` at once.

### 10.5 DNS pins — §O-DNS (OPS-10, ADR-0066 D-P)

`HUMAUX_PRIVATE_WORKER_DNS_PINS` (`<host>=<ip>[|<ip>…][,…]`, in `private-worker.secret.env`) pins a provider host
for a node whose resolver is not trusted for it. Pins are static: an address that stops answering surfaces only as
a `TRANSPORT` retry, counted by `dns_pin_deferred_total` while any pin is configured; `DnsPinDeferred` (WARNING)
fires when that counter grows and no distill output is written for 30 min. **Refresh** monthly and on the alert:
resolve each pinned host from an authoritative resolver (a DNS-over-HTTPS query on the operator host), check each
address is outside the §11.4 forbidden ranges (the worker re-checks at boot and refuses a forbidden pin), write the
new list, recreate `private-rpc` and `private-distill`, and confirm one distill call succeeds (`private_distill_
outputs_total` grows, the alert resolves).

## 11. Disaster recovery (card 37, ADR-0064)

What card 37 ships is the go-live class **`local_only`**: one encrypted pgBackRest repository on its own fixed-size
filesystem on this server (§1), a nightly checked full backup, continuous WAL archiving, a weekly restore drill and
a real restore (`restore pitr`). Qdrant is never backed up: it is rebuilt from PostgreSQL (`projection rebuild`),
which holds every point's vector. In the bundle every arm runs on the `dr` one-shot through the compose wrapper
(`humaux-dr.sh` stays only for card-37 hosts that predate the bundle).

**NOT OFFSITE.** All backups are on the same server and disk as the database. **host loss = total loss.** The
system says so on every backup arm, in `backup status`, in every drill and restore evidence file, and with the
`BackupNotOffsite` warning, which repeats once a week until card 37d's NAS copy works. The deploy artifacts
themselves are listed for the offsite copy in `deploy/OFFSITE.list` (ADR-0066 L-10).
中文：**目前所有备份与数据库在同一台服务器、同一块盘；服务器或磁盘丢失 = 全部丢失。** 在卡 37d 的 NAS 副本生效之前，
`BackupNotOffsite` 每周提醒一次（不会被静音）。

### 11.1 Before go-live (once, in this order)

1. The repository filesystem (§1, `mkfs.ext4` of a 12 GiB image, uid:gid 999:999).
2. The node's secrets (§1); `PGBACKREST_REPO1_CIPHER_PASS` written down away from the server (ADR-0064 L14).
3. `pg` started and the stanza created and checked: step R3.
4. Import the production data and run the E12 re-embed (`projection rebuild --all --allow-reembed <legacy count>`
   on the `ops` one-shot; provider cost = legacy points × the embedding price) **before** the first backup.
5. The first VERIFIED backup: step B1.
6. The two cron lines (§5); the drill evidence directory must exist (a drill whose evidence directory is missing
   refuses before it starts).
7. The DR evidence keys of `maintenance-serve` are in `values/maintenance.env`: `HUMAUX_MAINTENANCE_DR_REPO_FS_PATH`
   and `HUMAUX_MAINTENANCE_DR_PGDATA_FS_PATH` name the two read-only mounts of that service (prod.yml), and
   `HUMAUX_MAINTENANCE_SERVE_DR_EVIDENCE_EVERY_SECONDS` its cadence. They are not secrets; the budget keys are not
   daemon keys (each receipt records the limits the arm used).

### 11.2 What is protected today (`local_only`)

- Every night at 00:30 UTC: a full backup of PostgreSQL, a read-back check of every file (`pgbackrest verify --set`
  plus the manifest identity), and only then removal of backups older than the newest two (`repo1-retention-full=2`,
  expire only after VERIFIED). A failed check removes nothing.
- Between backups, changes are copied into the backup store at least once an hour (`archive_timeout` = 3600 s).
- Every Wednesday a drill restores the latest backup into a throw-away copy, checks it, rebuilds search from it with
  no provider call, deletes the copy and checks that the backup directory was not touched (`repo_intact`).
- You can undo a mistake from up to 24–48 hours ago, **as long as `backup status` shows
  `pitr_window_unbroken_since` that far back**.

### 11.3 What is NOT protected today

- **All backups are on the same server and disk as the database. If the server or its disk is lost, everything is
  lost** (host loss = total loss, L37). The backup filesystem is separate from the root filesystem, not from disk
  or host loss (L25).
- 中文：**目前所有备份与数据库在同一台服务器、同一块盘；服务器或磁盘丢失 = 全部丢失。**
- A compromised server (root or docker access) can wipe or corrupt the backup store and forge receipts (L21). The
  `dr` one-shot holds the docker socket and can read every secret while it runs (ADR-0066 L-5, L-14).

### 11.4 Disk: what uses it, its cap, what happens at the cap, how to check

| what | cap | at the cap | check |
|---|---|---|---|
| backup store (2 fulls + WAL since the older one) | its own 12 GiB filesystem; `REPO_MAX_BYTES` (8 GiB) and `MIN_FREE_BYTES` (2 GiB left) checked **before** each backup | the next backup is refused before writing, existing backups stay, `BackupBudgetLow` warns; if WAL then fills the filesystem, archiving stops and `WalArchiveFailing` (critical) fires — the database keeps running | `backup status` on `dr`; `backup_repo_bytes`, `backup_budget_headroom_bytes`, `backup_disk_free_bytes{volume="repo"}` |
| free space on the main disk | `DiskFreeLow` (critical) below 7.5 GiB; drills and restores refuse to go below 7.5 GiB | you are paged before PostgreSQL stops | `backup_disk_free_bytes{volume="pgdata"}` |
| unarchived WAL (`pg_wal`) when archiving breaks | 2 GiB (`archive-push-queue-max`) | after about 5 days at light load the oldest unarchived changes are dropped from the backup; `WalArchiveFailing` fires within 15 minutes and **stays on until a new nightly backup has been checked** | `wal_archive_failing`; fix the cause, then `backup run` |
| weekly drill copy | refuses below its memory floor or when the copy would leave less than 7.5 GiB free (`drill_free_bytes:<need>/<have> …`) | drill skipped; `RestoreDrillFailure` after 8 days | the drill evidence file |
| Docker images and build cache | not capped | pruning is the operator's decision; **never needed for backups** (the repository is not a Docker volume) | Docker's disk usage (`system df`) |

### 11.5 After a refused backup

`backup run` exit 3 means it refused before writing anything (`budget_repo_max:<bytes>`, `budget_free_floor:<bytes>`
or `repo_shares_pgdata_fs`) and wrote a FAILED receipt; the existing backups stay. If `backup status` shows room,
raise `HUMAUX_MAINTENANCE_BACKUP_REPO_MAX_BYTES` in `values/maintenance.env` and run `backup run` again. If it does
not, grow the filesystem (stop `pg`, `umount`, `truncate -s +4G` the image, `e2fsck -f`, `resize2fs`, mount, start
`pg`) or free the main disk. **Never delete a verified backup to make room.**

### 11.6 When something must be restored on this server ("PG lost")

Keep the damaged data. Default target: **end of archive**; `--target-time <rfc3339>` only to undo a logical mistake
inside the window `backup status` shows; `--target-backup <label>` to return exactly to the end of one backup (the
release rollback, §R RB3). The release rollback (RB2–RB6) is the worked, rehearsed form of this procedure:

1. Stop and remove the damaged project's containers — **never with `-v`**: the damaged data volume stays.
2. `restore pitr --compose-file <deploy dir>/compose/prod.yml --project <new project> --target end --evidence
   <file>` on the `dr` one-shot with `HUMAUX_NODE_PROJECT` set to the new project (RB3 shows the form). It refuses
   (exit 3) while a `pg` container of the project it runs under — the new one — is running
   (`production_pg_running:<container>`); it does not see the damaged project, so step 1 is the only guard that
   one cluster alone archives into the stanza. It also refuses when the new project's data volume is not empty,
   when the disk would drop below 7.5 GiB (`restore_free_bytes:<need>/<have>`), and when the backup does not
   verify (`repo_set_unverifiable:<label>`). It restores, boots socket-only, sets **NOLOGIN** on every LOGIN role
   but `postgres`, `role_maintenance` and `role_retrieval_worker`, records them (`nologin_roles`) and the restored
   in-flight state in the evidence, then boots with TCP.
3. Point `node.env` at the new project and take a VERIFIED backup at once (RB6).
4. `projection rebuild --all --batch <n> --wait-seconds <n>` (Qdrant from the restored PostgreSQL), reconcile the
   restored job state (RESERVED ledger rows, in-flight jobs; L8; §7.1), re-run `retention execute` for approved
   policies, then `ALTER ROLE … LOGIN` exactly the roles the evidence's `nologin_roles` lists (RB4), and re-run
   `rls-check` and `deploy-check --roles-sql` (RB5). Deletions committed after the target are lost with
   every other write of that window: re-submit them from the requester's side.

Never start the old project again; to read its data, ask first. A restore needs free disk of about one database.
Recorded once (ADR-0066 §5 fault c): a `--target-time` at the moment of an upgrade, with no WAL archived after it,
ends recovery before the target and fails — which is why the release rollback uses `--target-backup`.

### 11.7 Qdrant lost

`projection rebuild --all --batch <n> --wait-seconds <n>` on the `ops` one-shot before traffic (plus
`--allow-reembed <legacy count>` while pre-card-37 points without a stored vector remain). The rebuild issues a new
generation of tickets on the same streams, the `retrieval-serve` runner re-projects them from
`projection.memory_vectors` (no provider call), and `projection verify --all` proves the collection equals
PostgreSQL. A changed embedding fingerprint is refused `re_embed_required` (card 37b re-embeds).

### 11.8 Measured RPO and RTO (measured, not promised)

Numbers from ADR-0064 "S7 measurements" (dev-sized data, the dev Mac, n = 3 medians):

| quantity | value | from |
|---|---|---|
| full backup | 3.9 s | M1 `full_backup_s` (770 MB cluster) |
| verify of one set | 0.75 s | M1 `verify_full_s` |
| restore to promotion (`restore pitr`) | 8.5 s | M1 `pitr_restore_s` |
| rebuild of 17,435 points (issue + project + verify) | 147 s (0.15 + 126 + 21) | M2 |
| **RTO (dev size)** = restore + drill checks + rebuild + verify | ≈ 156 s (2.6 min) | M1 + drill `checks_s` 0.43 s + M2 |
| **RPO with the WAL archive intact** | ≤ 1 h at light load (`archive_timeout` 3600 s) | D-V |
| **RPO if the WAL archive is lost** | the age of the last verified full (≤ 24 h) | D-V |

Production scales roughly linearly in database bytes and points; re-measure at the first production drill (L13).
§67.2's RTO/RPO bound is 24 h.

### 11.9 Other routine

- **After a killed drill:** `restore drill --destroy-stale` on `dr` (removes only resources labelled
  `humaux.drill`; the next drill refuses `stale_drill` until then).
- **Reading a drill evidence file:** `succeeded`, `repo_intact`, `repo_class` (always `local_only`), the notice, and
  each check (`witness_a_present`, `witness_b_absent`, `migrations_drift`, `rls_unforced`, `isolation_violations`,
  `payload_digest_mismatches`, `provider_calls`, `rebuild.equivalent`, `residue`); the timings are `restore_s`,
  `checks_s`, `rebuild_s`, `destroy_s`, `rto_seconds`.
- **Cipher pass custody:** readers are the postgres user in `pg` (hence every PostgreSQL superuser), docker users on
  the host, the `dr` one-shot and the owner of the secrets directory — all of whom already read the live database.
  Losing it loses every backup.
- **Deletion bound** (§37 DeletionGraph "Backups"): data deleted from the database leaves the backups **3 days**
  after the last set holding it expires ((2 + 1) × 1 d, D-T).

### 11.10 When the NAS arrives

Tell us four things: the NAS brand and model and its operating-system version; whether it can run a scheduled shell
script with `ssh`, `rsync`, `sha256sum`, `awk` and `find`, or can run Docker; whether your home internet has a fixed
IP address; and how much space the share has (about two full backups plus a day of changes, plus the snapshots you
keep). Also confirm that the backup password is written down away from the server. Card 37d then wires the NAS copy,
and until it is done nothing on the server will call any copy "offsite".

## 12. Rerank model artifact — build, publish, pin (ADR-0084 D-A, card T-RET-7b)

The local rerank lane loads one int8 cross-encoder from files. The files are built **only in GitHub Actions** (never on a
node or a developer machine) from a public model pinned by commit, and published as one release asset.

- **What it is.** The prerelease `rerank-mmarco-int8-v1` holds `rerank-mmarco-int8-v1.tar.gz` and its `.sha256`. The tarball
  holds `model_quantized.onnx`, `tokenizer.json` and the tokenizer config files, `MODEL_CARD.md` and `manifest.json`. The
  manifest carries the model identity (repo, revision, recipe version, onnx sha256, tokenizer sha256), the licence read from the
  pinned model card, the tool versions, the graph's operator list, and whether two builds in one job were byte-identical.
- **Build and publish.** `gh workflow run rerank-artifact.yml --ref <branch> -f publish=false` builds twice, packages, and runs
  the two gates: G7b-1 (the tarball's files match `manifest.json`) and G7b-2 (re-scoring the committed parity fixtures with
  the packaged model reproduces the stored scores within the tolerance in the fixture header). `-f publish=true` also creates
  the prerelease from the same run. The build job's token is read-only; only the publish job can write, and it refuses to
  overwrite an existing release. The build refuses to start unless the pinned model card's licence is Apache-2.0 or MIT.
- **Deploy pins the tarball sha256** (the `.sha256` asset, repeated in the release notes), not the tag and not the recipe: if
  the export is not byte-deterministic (the manifest says), the published file is the only pin. The worker refuses to start on a
  mismatch (G-RET-14). T-RET-7c wires the fetch into the image; until then nothing on a node reads this artifact and
  `rerank_enabled` stays false.
- **Changing it.** Any change to the identity is a new `calibration_profile` (Baseline §19, Rerank Provider Failover): publish
  it under a new tag, never over this one.

## Appendix A. The step log and the improvisation rule

The executor (`deploy/release/deploy_rehearsal.sh`) is the only way a step runs. Before the block it asserts, in the
block's own environment, that no Rust toolchain resolves (`cargo`, `rustc`, `rustup`): a toolchain on `PATH` refuses
the step (exit 3, `NOTOOLCHAIN FAIL`). It runs the block whole with `/bin/sh -eu` (which reads no shell profile) and
writes one line per step to `$HUMAUX_NODE_DIR/evidence/exec.log` itself:

```text
STEP <ID> BLOCK <sha256 of the block text> EXIT <rc> NOTOOLCHAIN <ok|FAIL> EXPECT <n>[ match=<s>] RESULT <ok|mismatch> START <UTC> END <UTC>
VALUE <KEY>=<value>        (only after a step with a value: marker)
```

The block's output is kept in `evidence/steps/<ID>.out` (0600). Captured values (`PREV_TAG`, `PRE_UPGRADE_LABEL`)
live in `evidence/values.env` (0600) and reach later steps as environment variables, so nobody copies a value by
hand. A STOP or an observation goes into `evidence/agent_notes.txt` as `STOP <ID> <reason>` or `IMPROVISED <what,
why>` — the only lines that file holds.

**Improvisation.** An executor run is the only allowed action besides reading this file and the node directory's
files: `sh deploy/release/deploy_rehearsal.sh run <ID>`, `--list`, `--show <ID>`. Any other command — a `docker`
call, a compose `logs`, a changed flag, a re-run with an edited block, a read of the source code — is IMPROVISED,
whether or not it is written down. The rehearsal checks this from the exported tool-call transcript
(`TW/c39_steplog_check.sh`, ADR-0066 R-8), not from the agent's own notes; omissions show as a gap between the
exec.log ids and `--list`. **Every IMPROVISED is a runbook bug:** the runbook is fixed and the run starts again
from P1 on a fresh project. A mismatch is a STOP, never a workaround.

## Appendix B. The §48.1 partition conversions (0224–0230, card 36, ADR-0063 D-D / D-M)

Migrations 0224–0230 turn `ops.stage_runs`, `private.messages`, `ops.maintenance_receipts`, `private.events`,
`control.audit_events` and `ops.model_call_ledger` into monthly RANGE parents (the heap becomes one leaf, the
current month plus three future months are pre-created, no DEFAULT partition). All seven are `FORWARD_ONLY` with
`backup_restore_requirement = "pg_dump before apply"`: there is no down migration. Each holds ACCESS EXCLUSIVE on
its table and SHARE ROW EXCLUSIVE on every FK neighbour for its whole transaction, so **every writer is stopped
first** (U4 does that on a node; milliseconds on an empty database). A conversion refuses `c36 precheck: <fk>: <n>
orphan rows - repair data first` when rows violate an FK it re-creates. A node installed from the bundle applies
them in R5 on an empty database. The conversion of a long-lived database with data (the shared dev database, run
once by the main line with a dump, a copy rehearsal and counts compared) is recorded in ADR-0063; its rollback is a
restore of the pre-conversion dump into a fresh database. Since 0231 a leaf is identified by its name and bounds,
verified against the catalog, never by a stored OID, so a logical restore runs retention without a rebind step.

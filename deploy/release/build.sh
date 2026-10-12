#!/bin/sh
# deploy/release/build.sh — runbook v2 R1: one commit -> one set of release images + its release manifest
# (ADR-0066 D-A identity rules, compile step as replaced by ruling R-2).
# Caller: the operator on the build host (this Mac or the A5 runner's build host, never the node), the S8 build runs,
#   the chain gate c39_image_build (via TW/c39_build_images.sh). Never run by an agent in the implementation workflow.
# Usage: build.sh <sha40> --sizing <sizing env file> [--unreleased] [--with-loadgen] [--manifest-dir DIR] [--dry-run]
# Inputs:
#   <sha40>          the commit to build: a commit on main, or with --unreleased any commit (the chain and the
#                    rehearsal pass `$(sh deploy/release/snapshot.sh)`, an unreferenced snapshot of the working tree).
#   --sizing FILE    deploy/env/sizing-<profile>.env: HUMAUX_BUILD_MEM_MIB (the builder's cgroup cap, swap = same),
#                    HUMAUX_BUILD_CPUS and CARGO_BUILD_JOBS (R-2).
#   --with-loadgen   also the `loadgen` image (D-S; the A5 runner gets images, never a toolchain).
#   --manifest-dir   where release-<tag>.manifest goes (default: the current directory).
#   --dry-run        prints every command it would run (`DRY …`) after the read-only argument and git checks; writes
#                    nothing, runs no docker.
#   env HUMAUX_IMAGE_CONTEXT_DIR  the staging dir (default $HOME/humaux-image-context, outside the repo); the binaries
#                    land in $HUMAUX_IMAGE_CONTEXT_DIR-out.
# Steps: (1) `git archive <sha> -- <allowlist>` extracted to a temp dir and synchronised into the staging dir with
#   `rsync -rc --delete` (content compare: an unchanged file keeps its mtime, so cargo's fingerprints stay valid, D-A);
#   the working tree is never the context, so no local file (.env.local) can enter it. (2) `cargo build --release
#   --locked --workspace` inside `docker run --memory <cap>m --memory-swap <cap>m --cpus <n>` of the digest-pinned
#   builder, staging dir mounted read-only, target dir and cargo registry on the two named cache volumes kept between
#   runs (R-6), HUMAUX_BUILD_GIT_SHA / HUMAUX_BUILD_TIME burned in (F9). An OOM-killed builder is reported as
#   `build_oom` and never reaches the VM's global OOM killer. (3) Per target, `docker buildx build --platform
#   linux/arm64 --target <t>` of the COPY-only deploy/images/humaux/Dockerfile (from the staged commit) with the out dir
#   as context, labels org.opencontainers.image.{revision,version,created,source}. (4) The card-37 PostgreSQL image
#   (deploy/images/postgres) tagged humaux-pg:<tag>. (5) One manifest line per image, one CHECKOUT line, and the
#   checkout tarball (ADR-0066 review fix 9, OP-4): `git archive <sha> --add-file=CHECKOUT_TREE -- deploy
#   docs/ops/runbook.md migrations/0011_roles_and_grants.sql` through `gzip -n`, with its sha256 file.
# Output (stdout): `IMAGE humaux-<t>:<tag> id=<sha256 image id> size=<bytes> binary=<bin> git_sha=<sha40>` per target
#   (the D-R `--release` truth), `PGIMAGE humaux-pg:<tag> id=<id> size=<bytes>`, `CHECKOUT tree=<40-hex> runbook=<40-hex>
#   roles=<40-hex>` (git object ids of <sha>:deploy, <sha>:docs/ops/runbook.md, <sha>:migrations/0011_roles_and_grants.sql;
#   the deploy-check --release --checkout-tree truth), `CHECKOUT_TARBALL <path>` (humaux-checkout-<tag>.tar.gz in the
#   manifest dir, `humaux-checkout-<tag>.sha256` beside it in `<hex>  <basename>` form; the tarball root holds the
#   one-line file CHECKOUT_TREE `tree=... runbook=... roles=...`), then `MANIFEST <path>`. No secret is read or printed
#   (the context is the allowlist of a commit). With --dry-run the same lines are printed as `DRY ...`.
# Exit: 0 = every image built and the manifest written; 1 = a step failed (`build_failed:<step>`, or `build_oom` when
#   the builder's own cgroup killed it, or the stage archive/extract or the checkout tarball failed); 2 = usage (the missing or malformed argument is named); 3 = refused (the sha
#   is not a commit, or not on main without --unreleased).
set -eu

usage() { echo "usage: build.sh <sha40> --sizing <sizing env file> [--unreleased] [--with-loadgen] [--manifest-dir DIR] [--dry-run]" >&2; exit 2; }
SHA=; SIZING=; UNRELEASED=0; LOADGEN=0; MANIFEST_DIR=.; DRY=0
while [ $# -gt 0 ]; do
  case $1 in
    --sizing) [ $# -ge 2 ] || usage; SIZING=$2; shift 2 ;;
    --unreleased) UNRELEASED=1; shift ;;
    --with-loadgen) LOADGEN=1; shift ;;
    --manifest-dir) [ $# -ge 2 ] || usage; MANIFEST_DIR=$2; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    -*) echo "build.sh: unknown option $1" >&2; usage ;;
    *) [ -z "$SHA" ] || usage; SHA=$1; shift ;;
  esac
done
[ -n "$SHA" ] || { echo "build.sh: missing argument: <sha40> (the commit to build)" >&2; usage; }
printf '%s' "$SHA" | grep -Eqx '[0-9a-f]{40}' || { echo "build.sh: argument <sha40> is not a 40-hex sha: $SHA" >&2; exit 2; }
[ -n "$SIZING" ] || { echo "build.sh: missing argument: --sizing <sizing env file>" >&2; usage; }
[ -r "$SIZING" ] || { echo "build.sh: cannot read --sizing $SIZING" >&2; exit 2; }

REPO=$(cd "$(dirname "$0")/../.." && pwd)
git -C "$REPO" cat-file -e "$SHA^{commit}" 2>/dev/null || { echo "build.sh: refused: $SHA is not a commit of $REPO" >&2; exit 3; }
if [ "$UNRELEASED" = 0 ] && ! git -C "$REPO" merge-base --is-ancestor "$SHA" main; then
  echo "build.sh: refused: $SHA is not on main (a production release is a commit on main; pass --unreleased for a chain or rehearsal build)" >&2
  exit 3
fi

# The sizing values, read by name (the file is secret-free; never sourced, so it cannot run code).
size() { v=$(grep -E "^$1=" "$SIZING" | tail -1 | cut -d= -f2-); [ -n "$v" ] || { echo "build.sh: $SIZING has no $1" >&2; exit 2; }; printf '%s' "$v"; }
MEM_MIB=$(size HUMAUX_BUILD_MEM_MIB); CPUS=$(size HUMAUX_BUILD_CPUS); JOBS=$(size CARGO_BUILD_JOBS)

VERSION=$(git -C "$REPO" show "$SHA:Cargo.toml" | sed -n 's/^version = "\([^"]*\)"$/\1/p' | head -1)
[ -n "$VERSION" ] || { echo "build.sh: build_failed:version (no workspace version in $SHA:Cargo.toml)" >&2; exit 1; }
TOOLCHAIN=$(git -C "$REPO" show "$SHA:rust-toolchain.toml" | sed -n 's/^channel = "\([^"]*\)"$/\1/p')
[ -n "$TOOLCHAIN" ] || { echo "build.sh: build_failed:toolchain (no channel in $SHA:rust-toolchain.toml)" >&2; exit 1; }
SHA12=$(printf '%s' "$SHA" | cut -c1-12)
TAG="$VERSION-$SHA12"
# The commit's committer time: a rebuild of one commit is byte-stable in this field (D-A).
BUILD_TIME=$(git -C "$REPO" show -s --format=%cI "$SHA")

CTX=${HUMAUX_IMAGE_CONTEXT_DIR:-$HOME/humaux-image-context}
OUT="$CTX-out"
# D-A allowlist: what the workspace build reads (F10: the Baseline and contracts are include_str!'d), the Dockerfiles,
# the generated env examples. Nothing else of the commit (and nothing of the working tree) enters the build.
ALLOWLIST="Cargo.toml Cargo.lock rust-toolchain.toml .cargo crates bins xtask migrations contracts config docs/architecture deploy/images deploy/env/example"
# Builder: rust:1.99.0 on Debian 13 (glibc of the distroless cc-debian13 runtime, W-2); resolved 2026-10-07.
BUILDER=rust:1.99.0-slim-trixie@sha256:24e632c09342c20abf8312cf4f61430a911c01ed3a5e4c02b87292b1c39c5273
# The images and the binary each one runs (deploy-check --release comparison 3).
TARGETS="gateway:humaux-gateway retrieval-worker:humaux-retrieval-worker private-worker:humaux-private-worker consolidation-worker:humaux-consolidation-worker maintenance:humaux-maintenance admin:humaux-admin ops:humaux-maintenance dr:humaux-maintenance"
[ "$LOADGEN" = 1 ] && TARGETS="$TARGETS loadgen:xtask"
BINARIES="humaux-gateway humaux-retrieval-worker humaux-private-worker humaux-consolidation-worker humaux-maintenance humaux-admin xtask"
BUILD_NAME="humaux-build-$SHA12-$$"
MANIFEST="$MANIFEST_DIR/release-$TAG.manifest"

run() { if [ "$DRY" = 1 ]; then echo "DRY $*"; else "$@"; fi; }
fail() { echo "build.sh: build_failed:$1" >&2; exit 1; }

echo "build.sh: sha=$SHA tag=$TAG toolchain=$TOOLCHAIN cap=${MEM_MIB}MiB cpus=$CPUS jobs=$JOBS context=$CTX"

# (1) Stage the commit.
STAGE=; CKDIR=
cleanup() { [ -n "$STAGE" ] && rm -rf "$STAGE" "$STAGE.tar"; [ -n "$CKDIR" ] && rm -rf "$CKDIR"; [ "$DRY" = 1 ] || docker rm -f "$BUILD_NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT
trap 'exit 143' TERM INT
if [ "$DRY" = 1 ]; then
  echo "DRY git -C $REPO archive $SHA -o <tmp>.tar -- $ALLOWLIST && tar -x -C <tmp> -f <tmp>.tar"
  echo "DRY rsync -rc --delete --exclude /target <tmp>/ $CTX/"
else
  STAGE=$(mktemp -d)
  # CC-4: archive to a file first, so a failing `git archive` is not masked by the pipe's last command (no pipefail in sh).
  # shellcheck disable=SC2086 # the allowlist is a word list on purpose
  git -C "$REPO" archive "$SHA" -o "$STAGE.tar" -- $ALLOWLIST || fail archive
  tar -x -C "$STAGE" -f "$STAGE.tar" || fail archive-extract
  rm -f "$STAGE.tar"
  mkdir -p "$CTX/target" "$OUT/bin" "$OUT/env-example"
  rsync -rc --delete --exclude /target "$STAGE/" "$CTX/" || fail rsync
fi

# (2) Compile inside the capped builder (R-2). RUSTUP_TOOLCHAIN pins the image's toolchain, so rustup never reads the
# toolchain file's component list and never downloads (the builder's rustc must equal it: gate c39_builder_matches_toolchain).
# PR #2 review: the builder is pinned to linux/arm64 (a multi-arch builder on an x86-64 host would compile x86-64
# ELFs that the COPY-only Dockerfile packs unseen); the e_machine check below refuses anything but AArch64 (0xB7).
run docker run --name "$BUILD_NAME" --platform linux/arm64 \
  --memory "${MEM_MIB}m" --memory-swap "${MEM_MIB}m" --cpus "$CPUS" \
  -e CARGO_BUILD_JOBS="$JOBS" -e HUMAUX_BUILD_GIT_SHA="$SHA" -e HUMAUX_BUILD_TIME="$BUILD_TIME" \
  -e RUSTUP_TOOLCHAIN="$TOOLCHAIN" -e HOST_IDS="$(id -u):$(id -g)" \
  -v humaux-cargo-cache:/usr/local/cargo/registry -v humaux-target-cache:/work/target \
  -v "$CTX":/work:ro -v "$OUT/bin":/out -w /work \
  "$BUILDER" sh -c "cargo build --release --locked --workspace --target-dir /work/target && cd /work/target/release && cp $BINARIES /out/ && chown \"\$HOST_IDS\" /out/*" \
  || {
    rc=$?
    if [ "$DRY" = 0 ] && [ "$(docker inspect -f '{{.State.OOMKilled}}' "$BUILD_NAME" 2>/dev/null)" = true ]; then
      echo "build.sh: build_oom (the builder exceeded its ${MEM_MIB} MiB cap; raise HUMAUX_BUILD_MEM_MIB or lower CARGO_BUILD_JOBS in $SIZING)" >&2
      exit 1
    fi
    fail "compile (docker run exit $rc)"
  }
run docker rm "$BUILD_NAME"
if [ "$DRY" = 0 ]; then
  for b in "$OUT"/bin/*; do
    m=$(od -An -tx1 -j18 -N2 "$b" | tr -d ' \n')
    [ "$m" = "b700" ] || fail "arch:$(basename "$b") e_machine=$m is not AArch64 (b700)"
  done
fi
# Recreated, never merged into: a file the commit removed or renamed must not survive into the ops / dr images
# (deploy-check --env reads every file there; PR #2 round 8).
if [ "$DRY" = 1 ]; then
  echo "DRY rm -rf $OUT/env-example && mkdir -p $OUT/env-example && cp -R $CTX/deploy/env/example/. $OUT/env-example/"
else
  rm -rf "$OUT/env-example" && mkdir -p "$OUT/env-example" || fail env-example
  cp -R "$CTX/deploy/env/example/." "$OUT/env-example/" || fail env-example
fi

# (3) The COPY-only images.
for pair in $TARGETS; do
  t=${pair%%:*}
  run docker buildx build --platform linux/arm64 --target "$t" \
    --label "org.opencontainers.image.revision=$SHA" --label "org.opencontainers.image.version=$VERSION" \
    --label "org.opencontainers.image.created=$BUILD_TIME" --label "org.opencontainers.image.source=humaux-thread" \
    -t "humaux-$t:$TAG" -f "$CTX/deploy/images/humaux/Dockerfile" --load "$OUT" || fail "image:$t"
done
# (4) The card-37 PostgreSQL image (its own Dockerfile and context, deploy/images/postgres).
run docker buildx build --platform linux/arm64 --target pg -t "humaux-pg:$TAG" \
  --label "org.opencontainers.image.revision=$SHA" -f "$CTX/deploy/images/postgres/Dockerfile" --load \
  "$CTX/deploy/images/postgres" || fail image:pg

# (5) The manifest. OP-4: the CHECKOUT line pins the node's checkout (deploy tree, runbook, roles migration) to this
# commit; git object ids are content hashes, so the same bytes on the node give the same ids.
TREE_ID=$(git -C "$REPO" rev-parse "$SHA:deploy") || fail checkout-tree
RUNBOOK_ID=$(git -C "$REPO" rev-parse "$SHA:docs/ops/runbook.md") || fail checkout-tree
ROLES_ID=$(git -C "$REPO" rev-parse "$SHA:migrations/0011_roles_and_grants.sql") || fail checkout-tree
CHECKOUT_FIELDS="tree=$TREE_ID runbook=$RUNBOOK_ID roles=$ROLES_ID"
CKTAR="$MANIFEST_DIR/humaux-checkout-$TAG.tar.gz"; CKSUM="$MANIFEST_DIR/humaux-checkout-$TAG.sha256"
CKPATHS="deploy docs/ops/runbook.md migrations/0011_roles_and_grants.sql"
if [ "$DRY" = 1 ]; then
  for pair in $TARGETS; do echo "DRY IMAGE humaux-${pair%%:*}:$TAG id=<docker image inspect> size=<bytes> binary=${pair#*:} git_sha=$SHA"; done
  echo "DRY CHECKOUT $CHECKOUT_FIELDS"
  echo "DRY git -C $REPO archive $SHA --add-file=<tmp>/CHECKOUT_TREE -- $CKPATHS | gzip -n > $CKTAR"
  echo "DRY sha256 $CKTAR > $CKSUM"
  echo "DRY CHECKOUT_TARBALL $CKTAR"
  echo "DRY MANIFEST $MANIFEST"
  exit 0
fi
mkdir -p "$MANIFEST_DIR"
: > "$MANIFEST.tmp"
for pair in $TARGETS; do
  t=${pair%%:*}
  meta=$(docker image inspect --format '{{.Id}} {{.Size}}' "humaux-$t:$TAG") || fail "inspect:$t"
  line="IMAGE humaux-$t:$TAG id=${meta% *} size=${meta#* } binary=${pair#*:} git_sha=$SHA"
  echo "$line"; echo "$line" >> "$MANIFEST.tmp"
done
meta=$(docker image inspect --format '{{.Id}} {{.Size}}' "humaux-pg:$TAG") || fail inspect:pg
line="PGIMAGE humaux-pg:$TAG id=${meta% *} size=${meta#* }"
echo "$line"; echo "$line" >> "$MANIFEST.tmp"
line="CHECKOUT $CHECKOUT_FIELDS"
echo "$line"; echo "$line" >> "$MANIFEST.tmp"
mv "$MANIFEST.tmp" "$MANIFEST"
# The tarball: archive to a file first (no pipefail in sh), then gzip -n (no embedded mtime/name).
CKDIR=$(mktemp -d)
printf '%s\n' "$CHECKOUT_FIELDS" > "$CKDIR/CHECKOUT_TREE"
# shellcheck disable=SC2086 # CKPATHS is a word list on purpose
git -C "$REPO" archive "$SHA" --add-file="$CKDIR/CHECKOUT_TREE" -o "$CKDIR/checkout.tar" -- $CKPATHS || fail checkout-archive
gzip -n < "$CKDIR/checkout.tar" > "$CKTAR.tmp" || fail checkout-gzip
mv "$CKTAR.tmp" "$CKTAR"
# Same `<hex>  <basename>` form as the image tarball's humaux-<tag>.sha256 (runbook R1).
if command -v sha256sum >/dev/null 2>&1; then (cd "$MANIFEST_DIR" && sha256sum "humaux-checkout-$TAG.tar.gz") > "$CKSUM" || fail checkout-sha256
else (cd "$MANIFEST_DIR" && shasum -a 256 "humaux-checkout-$TAG.tar.gz") > "$CKSUM" || fail checkout-sha256; fi
echo "CHECKOUT_TARBALL $CKTAR"
echo "MANIFEST $MANIFEST"

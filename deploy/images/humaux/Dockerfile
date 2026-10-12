# syntax=docker/dockerfile:1
# deploy/images/humaux/Dockerfile — the release images of the bundle (ADR-0066 D-A as replaced by ruling R-2).
# COPY-ONLY: nothing compiles here. deploy/release/build.sh compiles the workspace inside a memory-capped builder
# container (`docker run --memory …`, R-2: a build that exceeds its cap is killed by its own cgroup, never by the VM's
# global OOM killer), copies the binaries into its out dir, and runs `docker buildx build --target <t>` with THAT dir as
# the context. Context layout (build.sh writes it): bin/<binary> (0755) and env-example/<process>.env (the generated
# deploy/env/example files, D-T, read by `deploy-check --env --examples-dir /usr/share/humaux/env/example`).
# One final target per process image; each is the runtime base + its binary + a numeric non-root USER (D-C table;
# compose's `user:` wins, this is the `docker run` fallback) + ENTRYPOINT. Identity labels
# (org.opencontainers.image.revision/version/created/source) are passed by build.sh with --label, and the release
# manifest it writes is the truth deploy-check --release compares against (D-R, RF-1).
# Every FROM is pinned by its multi-arch index digest, resolved 2026-10-07 with `docker buildx imagetools inspect`
# (each index carries linux/arm64).

# glibc + libgcc_s, no shell (W-2): the binaries are aarch64-unknown-linux-gnu from the Debian 13 builder.
# resolved 2026-10-07 (multi-arch index digest)
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2 AS runtime
# The scanner pin of the retrieval worker and of the restore drill's rebuild (values HUMAUX_RETRIEVAL_WORKER_GITLEAKS_*).
# W-11 / S8: confirm the binary path and that it runs on the cc base (`docker run --rm humaux-retrieval-worker:<t>` is
# not enough; the drill's rebuild exercises it).
# resolved 2026-10-07 (multi-arch index digest)
FROM zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f AS gitleaks
# W-9: the static docker CLI and the compose plugin for `dr` (D-H).
# resolved 2026-10-07 (multi-arch index digest)
FROM docker:29.8.1-cli@sha256:018edbc908e08fcc9dbf029c812c34251e9b4719e6f71ca0e5eae2a987d014ca AS dockercli
# resolved 2026-10-07 (multi-arch index digest)
FROM docker/compose-bin:v5.5.1@sha256:14162382692aae43977f79effa64a499d61de19d4645461881daaf88773f7e74 AS composebin

FROM runtime AS gateway
COPY bin/humaux-gateway /usr/local/bin/humaux-gateway
USER 10101:10101
ENTRYPOINT ["/usr/local/bin/humaux-gateway"]

FROM runtime AS retrieval-worker
COPY bin/humaux-retrieval-worker /usr/local/bin/humaux-retrieval-worker
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
USER 10102:10201
ENTRYPOINT ["/usr/local/bin/humaux-retrieval-worker"]

FROM runtime AS private-worker
COPY bin/humaux-private-worker /usr/local/bin/humaux-private-worker
USER 10103:10202
ENTRYPOINT ["/usr/local/bin/humaux-private-worker"]

FROM runtime AS consolidation-worker
COPY bin/humaux-consolidation-worker /usr/local/bin/humaux-consolidation-worker
USER 10104:10104
ENTRYPOINT ["/usr/local/bin/humaux-consolidation-worker"]

FROM runtime AS maintenance
COPY bin/humaux-maintenance /usr/local/bin/humaux-maintenance
USER 10105:10105
ENTRYPOINT ["/usr/local/bin/humaux-maintenance"]

FROM runtime AS admin
COPY bin/humaux-admin /usr/local/bin/humaux-admin
USER 10106:10106
ENTRYPOINT ["/usr/local/bin/humaux-admin"]

# The operator one-shots (doors, migrate with its embedded migration set, rls-check, projection, member; D-Q). The
# migrator identity 10107 is set by compose's `migrate` service; the image fallback is the doors' uid.
FROM maintenance AS ops
COPY env-example/ /usr/share/humaux/env/example/
USER 10105:10105

# D-H: backup / restore / drill / deploy-check. Root with only DAC_READ_SEARCH (compose cap_drop ALL + cap_add).
FROM ops AS dr
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=composebin /docker-compose /usr/local/lib/docker/cli-plugins/docker-compose
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
USER 0:0

# D-S: the A5 load generator (the xtask release binary: e2e-seed + load); built only with build.sh --with-loadgen and
# never part of prod.yml (deploy/compose/a5-load.yml).
# ponytail: `xtask load` takes the BURST-W restart through the req/ack hook dir (`--restart BURST-W=file:<dir>`), so its
# `sh -c` fallback is unreachable in this shell-less image; no shell is added here.
FROM runtime AS loadgen
COPY bin/xtask /usr/local/bin/xtask
USER 10198:10198
ENTRYPOINT ["/usr/local/bin/xtask"]

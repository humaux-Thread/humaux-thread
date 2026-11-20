# deploy/images/postgres/Dockerfile — the PostgreSQL 19 image with pgBackRest installed at build time
# (ADR-0064 D-H, R-37: pgBackRest lives IN the pinned PostgreSQL image; nothing is installed at container start).
# One stage, `pg` (ruling E17: card 37 builds no mirror stage).
#   base: the official PostgreSQL 19.0 OCI index (ADR-0135).
#   pgbackrest: exact version string from trixie-pgdg (the apt source the base image already carries); 2.59.3
#     carries the weak-subkey fix (pgBackRest NEWS), measured present by spike SP-4 (open point O2).
# deploy/pgbackrest/pgbackrest.conf is bind-mounted read-only by the compose files, never baked in.
# The base image defines the entrypoint and PGDATA=/var/lib/postgresql/19/docker. Scratch backup and drill build for linux/arm64.
# Pinned by T-H1 (`the_image_is_pinned_and_carries_pgbackrest`) and gate c37_image_pinned.
FROM postgres:19.0@sha256:bb6e70add742cd868fb62cb3b2f67d1dd2bdd2b65a521e778420748753687c60 AS pg

ARG PGBACKREST_VERSION=2.59.3-1.pgdg13+1

RUN apt-get update \
 && apt-get install -y --no-install-recommends "pgbackrest=${PGBACKREST_VERSION}" ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && pgbackrest version \
 && install -d -o postgres -g postgres -m 0750 /var/log/pgbackrest /var/lib/pgbackrest /tmp/pgbackrest

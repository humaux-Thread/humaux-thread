# ADR-0135 — PostgreSQL 19.0 baseline

Accepted · 2026-11-20 · M24-PG19-SWITCH · Baseline §5

## Decision

On November 20 the owner approved switching directly to the PostgreSQL 19
general release. PostgreSQL 19.0 was released on November 19. Development,
required CI, targeted CI and the release build use the official image pinned
to OCI index `sha256:bb6e70add742cd868fb62cb3b2f67d1dd2bdd2b65a521e778420748753687c60`.
The release script builds the same PostgreSQL 19.0 and pgBackRest Dockerfile
used by the scratch backup and restore tests. Required CI replaces the
temporary upgrade probe.

This decision supersedes the recommendation to wait for 19.1. The owner
confirmed that the production service uses the legacy knowledge database and
this repository's new database has yet to launch. First launch reruns L0 to
provision a fresh PostgreSQL 19 cluster. No database migration or major-version
rollback is needed for the new cluster. Before launch, a repository rollback
is a Git revert. Production launch requires separate owner authorization.

## Compatibility and acceptance

- PostgreSQL 19's lock allocator changed and `max_locks_per_transaction`
  defaults to 128, up from 64. Keep the upstream default and check any
  deployment override against the PostgreSQL 19 equivalent lock capacity.
- Paired probes recorded first-page enumeration p95 about 23% higher on
  PostgreSQL 19. PG19-P95-KEYSET-DESIGN tracks the residual regression. The
  cause remains unknown. Retain the PR #671 JIT-on measurement floor,
  same-run ratio, later-page latency and manifest cap. Record the absolute
  first-page 300 ms target separately.
- PostgreSQL 19 uses the database locale provider for FTS and `pg_trgm`
  character classification. The [PG19-FTS-LOCALE paired run](https://github.com/humaux-Thread/humaux-thread/actions/runs/44759667852)
  found identical vectors, queries, ranking, hits and snapshots for nine
  samples on 18.7 and 19.0 using libc and `en_US.utf8`. The release image,
  dev Compose and CI services explicitly initialize with `libc` and
  `LC_CTYPE = LC_COLLATE = en_US.utf8`. Databases created from either
  template inherit those values. The scratch drill checks the live catalog.
- The build, pgBackRest stanza and restore commands use PostgreSQL 19's
  `/var/lib/postgresql/19/docker` path. The scratch drill requires source
  `server_version_num = 190000`. ADR-0064 D-N still requires exact source and
  restored version equality and retains its other checks.

Sources: [PostgreSQL 19 versioning](https://www.postgresql.org/support/versioning/),
[PostgreSQL 19 release notes](https://www.postgresql.org/docs/19/release-19.html),
[PR #671](https://github.com/humaux-Thread/humaux-thread/pull/671),
and the OCI registry response from `docker buildx imagetools inspect postgres:19.0`
on 2026-11-20.

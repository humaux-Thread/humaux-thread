-- §62 / §78.2 / ADR-0114 D-B, D-C, D-J (M16-2): control.repositories gains its provider key; private.code_snapshots,
-- code_files and code_active_snapshots replace the 0006 skeletons that block their names.
--
-- Retired here, because they sit in the way of the new names and hold no row (the manifest precheck refuses otherwise):
-- private.code_edges, code_symbols (they reference the skeleton files/snapshots; M16-3 re-creates both with composite FKs),
-- code_files and code_snapshots. private.worktree_overlays references neither, so it stays until M16-9 retires it (D-H).
--
-- Visibility = the §62 tenant predicate AND an ACTIVE workspace membership of the caller in the repository's workspace,
-- the same inline EXISTS over control.workspace_memberships that 0163 gives WORKSPACE_SHARED rows. A repository without a
-- workspace is visible to nobody (fail closed). code_files and code_active_snapshots inherit it from their snapshot.
-- No runtime role holds a write privilege: the push and publish doors (M16-4, M16-6) bring their own grants.

ALTER TABLE control.repositories
  ADD COLUMN provider text NOT NULL
    CONSTRAINT repositories_provider_check CHECK (provider IN ('CLIENT', 'LEGACY_PROJECT')),
  ADD COLUMN external_id text NOT NULL
    CONSTRAINT repositories_external_id_check CHECK (external_id <> ''),
  ADD CONSTRAINT repositories_provider_key UNIQUE (tenant_id, provider, external_id),
  ADD CONSTRAINT repositories_tenant_repository_key UNIQUE (tenant_id, repository_id);

DROP TABLE private.code_edges;
DROP TABLE private.code_symbols;
DROP TABLE private.code_files;
DROP TABLE private.code_snapshots;

CREATE TABLE private.code_snapshots (
  tenant_id uuid NOT NULL,
  snapshot_id uuid NOT NULL DEFAULT uuidv7(),
  repository_id uuid NOT NULL,
  kind text NOT NULL CONSTRAINT code_snapshots_kind_check CHECK (kind IN ('COMMIT', 'WORKTREE')),
  commit_sha text,
  dirty_tree_sha256 bytea CONSTRAINT code_snapshots_dirty_tree_sha256_len CHECK (octet_length(dirty_tree_sha256) = 32),
  target_key text NOT NULL,
  lockfile_sha256 bytea CONSTRAINT code_snapshots_lockfile_sha256_len CHECK (octet_length(lockfile_sha256) = 32),
  generated_code_sha256 bytea
    CONSTRAINT code_snapshots_generated_code_sha256_len CHECK (octet_length(generated_code_sha256) = 32),
  tree_sitter_version text NOT NULL,
  grammar_set text NOT NULL,
  extractor_version text NOT NULL,
  identity_sha256 bytea NOT NULL CONSTRAINT code_snapshots_identity_sha256_len CHECK (octet_length(identity_sha256) = 32),
  base_snapshot_id uuid,
  manifest_sha256 bytea NOT NULL CONSTRAINT code_snapshots_manifest_sha256_len CHECK (octet_length(manifest_sha256) = 32),
  state text NOT NULL DEFAULT 'BUILDING'
    CONSTRAINT code_snapshots_state_check CHECK (state IN ('BUILDING', 'READY', 'FAILED', 'EXPIRED')),
  failure_reason text,
  created_at timestamptz NOT NULL DEFAULT now(),
  state_changed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, snapshot_id),
  CONSTRAINT code_snapshots_tenant_repository_snapshot_key UNIQUE (tenant_id, repository_id, snapshot_id),
  CONSTRAINT code_snapshots_repository_fkey FOREIGN KEY (tenant_id, repository_id)
    REFERENCES control.repositories (tenant_id, repository_id),
  CONSTRAINT code_snapshots_base_fkey FOREIGN KEY (tenant_id, repository_id, base_snapshot_id)
    REFERENCES private.code_snapshots (tenant_id, repository_id, snapshot_id)
);
-- D-C: re-pushing the same identity returns the live snapshot; FAILED and EXPIRED ones no longer block it.
CREATE UNIQUE INDEX code_snapshots_identity_live_key ON private.code_snapshots (tenant_id, repository_id, identity_sha256)
  WHERE state IN ('BUILDING', 'READY');

CREATE TABLE private.code_files (
  tenant_id uuid NOT NULL,
  snapshot_id uuid NOT NULL,
  file_id uuid NOT NULL DEFAULT uuidv7(),
  path text NOT NULL,
  sha256 bytea NOT NULL CONSTRAINT code_files_sha256_len CHECK (octet_length(sha256) = 32),
  size_bytes bigint NOT NULL CONSTRAINT code_files_size_bytes_check CHECK (size_bytes >= 0),
  PRIMARY KEY (tenant_id, snapshot_id, file_id),
  CONSTRAINT code_files_path_key UNIQUE (tenant_id, snapshot_id, path),
  CONSTRAINT code_files_snapshot_fkey FOREIGN KEY (tenant_id, snapshot_id)
    REFERENCES private.code_snapshots (tenant_id, snapshot_id)
);

-- D-H: this is the main-line view (one row per repository). The per-run overlay views add run_id in M16-9, which also
-- decides the key shape, because a primary key cannot hold the NULL that marks the main line.
CREATE TABLE private.code_active_snapshots (
  tenant_id uuid NOT NULL,
  repository_id uuid NOT NULL,
  snapshot_id uuid NOT NULL,
  generation bigint NOT NULL,
  PRIMARY KEY (tenant_id, repository_id),
  CONSTRAINT code_active_snapshots_snapshot_fkey FOREIGN KEY (tenant_id, repository_id, snapshot_id)
    REFERENCES private.code_snapshots (tenant_id, repository_id, snapshot_id)
);

ALTER TABLE private.code_snapshots OWNER TO role_migration_owner;
ALTER TABLE private.code_files OWNER TO role_migration_owner;
ALTER TABLE private.code_active_snapshots OWNER TO role_migration_owner;
ALTER TABLE private.code_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.code_snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE private.code_files ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.code_files FORCE ROW LEVEL SECURITY;
ALTER TABLE private.code_active_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.code_active_snapshots FORCE ROW LEVEL SECURITY;

-- D-B: tenant predicate AND repository visible. 0163 (migrations/0163_workspace_shared_membership_arm.sql) spells the
-- workspace expression; the repository's workspace is control.repositories.workspace_id (0003).
CREATE POLICY code_snapshots_scope ON private.code_snapshots
  USING (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid
    AND EXISTS (SELECT 1 FROM control.repositories r
                  JOIN control.workspace_memberships wm
                    ON wm.tenant_id = r.tenant_id AND wm.workspace_id = r.workspace_id
                 WHERE r.tenant_id = code_snapshots.tenant_id
                   AND r.repository_id = code_snapshots.repository_id
                   AND wm.user_id = NULLIF(current_setting('humaux.user_id', true), '')::uuid
                   AND wm.state = 'ACTIVE'))
  WITH CHECK (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid
    AND EXISTS (SELECT 1 FROM control.repositories r
                  JOIN control.workspace_memberships wm
                    ON wm.tenant_id = r.tenant_id AND wm.workspace_id = r.workspace_id
                 WHERE r.tenant_id = code_snapshots.tenant_id
                   AND r.repository_id = code_snapshots.repository_id
                   AND wm.user_id = NULLIF(current_setting('humaux.user_id', true), '')::uuid
                   AND wm.state = 'ACTIVE'));
-- The snapshot subquery is itself row-secured, so a file or active row is visible exactly when its snapshot is.
CREATE POLICY code_files_scope ON private.code_files
  USING (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid
    AND EXISTS (SELECT 1 FROM private.code_snapshots s
                 WHERE s.tenant_id = code_files.tenant_id AND s.snapshot_id = code_files.snapshot_id))
  WITH CHECK (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid
    AND EXISTS (SELECT 1 FROM private.code_snapshots s
                 WHERE s.tenant_id = code_files.tenant_id AND s.snapshot_id = code_files.snapshot_id));
CREATE POLICY code_active_snapshots_scope ON private.code_active_snapshots
  USING (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid
    AND EXISTS (SELECT 1 FROM private.code_snapshots s
                 WHERE s.tenant_id = code_active_snapshots.tenant_id
                   AND s.repository_id = code_active_snapshots.repository_id
                   AND s.snapshot_id = code_active_snapshots.snapshot_id))
  WITH CHECK (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid
    AND EXISTS (SELECT 1 FROM private.code_snapshots s
                 WHERE s.tenant_id = code_active_snapshots.tenant_id
                   AND s.repository_id = code_active_snapshots.repository_id
                   AND s.snapshot_id = code_active_snapshots.snapshot_id));

-- §6.2.2: gateway reads only. Every other role and PUBLIC end with nothing.
REVOKE ALL ON private.code_snapshots, private.code_files, private.code_active_snapshots
  FROM PUBLIC, role_gateway, role_private_worker, role_consolidation_worker, role_public_worker,
       role_retrieval_worker, role_batch_issuer, role_maintenance, role_admin;
GRANT SELECT ON private.code_snapshots, private.code_files, private.code_active_snapshots TO role_gateway;

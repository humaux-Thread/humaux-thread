-- §62 / §78.2 / ADR-0114 D-B (M16-3): private.code_symbols and private.code_edges, re-created with composite FKs after 0284
-- dropped their 0006 skeletons. No row to move: nothing wrote to the skeletons.
--
-- One-snapshot rule (D-B): every key carries (tenant_id, snapshot_id). A symbol names a file of its own snapshot, and both
-- ends of an edge name symbols of the edge's own snapshot, so an edge cannot join two snapshots. No single-column UNIQUE on
-- a symbol_id exists anywhere: it would be the key a looser FK could hang on.
--
-- Visibility is code_files' (0284): the tenant predicate AND a visible snapshot (the snapshot subquery is itself row-secured,
-- so the repository's workspace membership applies). No runtime role holds a write privilege: the extraction publish door
-- (M16-6) brings its own grants.

CREATE TABLE private.code_symbols (
  tenant_id uuid NOT NULL,
  snapshot_id uuid NOT NULL,
  symbol_id uuid NOT NULL DEFAULT uuidv7(),
  file_id uuid NOT NULL,
  kind text NOT NULL
    CONSTRAINT code_symbols_kind_check
      CHECK (kind IN ('CLASS', 'CONSTANT', 'FUNCTION', 'INTERFACE', 'MACRO', 'METHOD', 'MODULE', 'TYPE')),
  name text NOT NULL CONSTRAINT code_symbols_name_check CHECK (name <> ''),
  qualified_name text NOT NULL CONSTRAINT code_symbols_qualified_name_check CHECK (qualified_name <> ''),
  signature text,
  start_line int NOT NULL,
  end_line int NOT NULL,
  -- D-F "optional body by ranged read": the byte range into the stored file content.
  start_byte bigint NOT NULL,
  end_byte bigint NOT NULL,
  -- D-G history: "a qualified name existed with this content hash".
  content_sha256 bytea NOT NULL CONSTRAINT code_symbols_content_sha256_len CHECK (octet_length(content_sha256) = 32),
  -- D-F search: split camel/snake tokens of name; the tokenizer is the reader/writer's (M16-6/M16-7).
  name_tokens text[] NOT NULL DEFAULT '{}',
  PRIMARY KEY (tenant_id, snapshot_id, symbol_id),
  CONSTRAINT code_symbols_lines_check CHECK (1 <= start_line AND start_line <= end_line),
  CONSTRAINT code_symbols_bytes_check CHECK (0 <= start_byte AND start_byte <= end_byte),
  CONSTRAINT code_symbols_file_fkey FOREIGN KEY (tenant_id, snapshot_id, file_id)
    REFERENCES private.code_files (tenant_id, snapshot_id, file_id)
);
-- qualified_name is not unique: overloads, and the same name in two files, are legal.
CREATE INDEX code_symbols_qualified_name_idx ON private.code_symbols (tenant_id, snapshot_id, qualified_name);
CREATE INDEX code_symbols_name_prefix_idx ON private.code_symbols (tenant_id, snapshot_id, name text_pattern_ops);
CREATE INDEX code_symbols_name_tokens_idx ON private.code_symbols USING gin (name_tokens);
CREATE INDEX code_symbols_file_idx ON private.code_symbols (tenant_id, snapshot_id, file_id);

-- D-E: an ambiguous name stays to_unresolved_name, never force-linked. Top-level IMPORTS/REFERENCES start at the file-scope
-- MODULE symbol the extractor emits for every parsed file (ADR-0114 D-B amendment), so from_symbol_id is NOT NULL.
CREATE TABLE private.code_edges (
  tenant_id uuid NOT NULL,
  snapshot_id uuid NOT NULL,
  edge_id uuid NOT NULL DEFAULT uuidv7(),
  from_symbol_id uuid NOT NULL,
  to_symbol_id uuid,
  to_unresolved_name text CONSTRAINT code_edges_to_unresolved_name_check CHECK (to_unresolved_name <> ''),
  kind text NOT NULL
    CONSTRAINT code_edges_kind_check
      CHECK (kind IN ('DEFINES', 'REFERENCES', 'CALLS', 'IMPORTS', 'IMPLEMENTS', 'INHERITS')),
  evidence_level text NOT NULL
    CONSTRAINT code_edges_evidence_level_check
      CHECK (evidence_level IN ('syntax_candidate', 'semantic_resolved', 'runtime_observed')),
  PRIMARY KEY (tenant_id, snapshot_id, edge_id),
  CONSTRAINT code_edges_target_check CHECK (num_nonnulls(to_symbol_id, to_unresolved_name) = 1),
  -- ponytail: one fact is one row, so N call sites of one callee are one edge; a per-site table keyed by edge_id when a reader
  -- needs counts or spans. The key also serves forward BFS (leading tenant_id, snapshot_id, from_symbol_id).
  CONSTRAINT code_edges_fact_key UNIQUE NULLS NOT DISTINCT
    (tenant_id, snapshot_id, from_symbol_id, kind, evidence_level, to_symbol_id, to_unresolved_name),
  CONSTRAINT code_edges_from_symbol_fkey FOREIGN KEY (tenant_id, snapshot_id, from_symbol_id)
    REFERENCES private.code_symbols (tenant_id, snapshot_id, symbol_id),
  -- MATCH SIMPLE: a NULL to_symbol_id (an unresolved edge) skips this check.
  CONSTRAINT code_edges_to_symbol_fkey FOREIGN KEY (tenant_id, snapshot_id, to_symbol_id)
    REFERENCES private.code_symbols (tenant_id, snapshot_id, symbol_id)
);
-- Reverse BFS.
CREATE INDEX code_edges_to_symbol_idx ON private.code_edges (tenant_id, snapshot_id, to_symbol_id);

ALTER TABLE private.code_symbols OWNER TO role_migration_owner;
ALTER TABLE private.code_edges OWNER TO role_migration_owner;
ALTER TABLE private.code_symbols ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.code_symbols FORCE ROW LEVEL SECURITY;
ALTER TABLE private.code_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.code_edges FORCE ROW LEVEL SECURITY;

CREATE POLICY code_symbols_scope ON private.code_symbols
  USING (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid
    AND EXISTS (SELECT 1 FROM private.code_snapshots s
                 WHERE s.tenant_id = code_symbols.tenant_id AND s.snapshot_id = code_symbols.snapshot_id))
  WITH CHECK (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid
    AND EXISTS (SELECT 1 FROM private.code_snapshots s
                 WHERE s.tenant_id = code_symbols.tenant_id AND s.snapshot_id = code_symbols.snapshot_id));
CREATE POLICY code_edges_scope ON private.code_edges
  USING (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid
    AND EXISTS (SELECT 1 FROM private.code_snapshots s
                 WHERE s.tenant_id = code_edges.tenant_id AND s.snapshot_id = code_edges.snapshot_id))
  WITH CHECK (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid
    AND EXISTS (SELECT 1 FROM private.code_snapshots s
                 WHERE s.tenant_id = code_edges.tenant_id AND s.snapshot_id = code_edges.snapshot_id));

-- §6.2.2: gateway reads only. Every other role and PUBLIC end with nothing.
REVOKE ALL ON private.code_symbols, private.code_edges
  FROM PUBLIC, role_gateway, role_private_worker, role_consolidation_worker, role_public_worker,
       role_retrieval_worker, role_batch_issuer, role_maintenance, role_admin;
GRANT SELECT ON private.code_symbols, private.code_edges TO role_gateway;

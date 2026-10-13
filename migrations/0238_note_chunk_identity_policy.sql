-- §46 forward-fix (EXPAND_CONTRACT, first free number after 0237). ADR-0068 D-A / D-C / D-I (card 40d-1b-i): the
-- schema half of note chunk projection. No worker writes a chunk point yet; every existing and every new registration
-- stays the legacy profile at ordinal 0.
--
-- 1. projection.note_legacy_capacity_holds(title, body) -> boolean, the SQL twin of
--    humaux_projection::note_chunks::legacy_capacity_holds: true iff the legacy card loses none of the body, i.e. the
--    body is empty or char_length(title) + 3 + char_length(body) <= 600. A note's slot is legacy iff this holds (or
--    the Memory is not a note, or the projection's policy is legacy only); NoteChunksV1 otherwise. Never classify a
--    slot from projection.note_chunk_count(...) = 1: a note with title 150 and body 460 is one NoteChunksV1 slot (its
--    legacy card would cut the body), and only this predicate tells it from a legacy card. Same function shape and
--    grants as 0237's count (pure, owner role_migration_owner, EXECUTE role_retrieval_worker only); parity with Rust:
--    adapters::tests::note_chunk_count_parity.
--
-- 2. projection.card_profile_policies — one row per projection (domain, projection_kind, projection_version), across
--    tenants: note_chunk_profile_hash NULL = legacy only (a missing row reads the same), else the one chunk profile
--    the worker builds and the ledger counts (ADR-0068 D-I). Written only by migrations (a reviewed, versioned change,
--    §78.1); 40d-2 flips the serving row to NOTE_CHUNKS_V1_PROFILE_HASH. The 0011 projection default privileges are
--    REVOKEd, then role_retrieval_worker gets SELECT only; nobody else holds anything. No RLS: the table has no
--    tenant column and holds global config (the 0232 embedding_fingerprints precedent); the SECURITY DEFINER
--    projection.stream_point_ledger runs as its owner role_migration_owner, which owns this table, so it reads every
--    row with no grant and no policy to keep in step. The CHECK keeps the legacy marker out of the hash column; the
--    worker refuses to boot on a hash it has no profile for.
--
-- 3. Registry identity v2 on projection.private_memory_points: card_profile_hash text NOT NULL DEFAULT
--    'LegacyCardV1' (humaux_projection::note_chunks::LEGACY_CARD_PROFILE_HASH; no SHA-256 hex can equal it) and
--    chunk_ordinal integer NOT NULL DEFAULT 0, a legacy row only at ordinal 0, and both appended to the exact identity
--    UNIQUE key (dropped and re-added under its 0119 name; no FK references it, the precheck asserts that). Constant
--    defaults: no table rewrite; every existing row becomes (LegacyCardV1, 0), which is what its v1 point id encodes.
--    Grants unchanged (0119 domain defaults: role_retrieval_worker's table-level INSERT/UPDATE covers the new columns).
--
-- Locks: ACCESS EXCLUSIVE on projection.private_memory_points for the ADD COLUMNs + three CHECK validation scans +
-- one unique-index build over the registry; the new table and function lock nothing else.

CREATE FUNCTION projection.note_legacy_capacity_holds(p_title text, p_body text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
RETURN char_length(p_body) = 0 OR char_length(p_title) + 3 + char_length(p_body) <= 600;

ALTER FUNCTION projection.note_legacy_capacity_holds(text, text) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION projection.note_legacy_capacity_holds(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION projection.note_legacy_capacity_holds(text, text) TO role_retrieval_worker;

COMMENT ON FUNCTION projection.note_legacy_capacity_holds(text, text) IS
  'ADR-0068 D-A: true iff the legacy card loses none of a note''s body (body empty, or title + 3 + body <= 600 '
  'scalars). A note slot is legacy iff this holds; never infer it from note_chunk_count = 1. Parity: '
  'rust_sql_chunk_count_parity.';

CREATE TABLE projection.card_profile_policies (
  domain                  text NOT NULL CHECK (length(domain) BETWEEN 1 AND 128),
  projection_kind         text NOT NULL CHECK (length(projection_kind) BETWEEN 1 AND 128),
  projection_version      text NOT NULL CHECK (length(projection_version) BETWEEN 1 AND 128),
  note_chunk_profile_hash text CHECK (length(note_chunk_profile_hash) BETWEEN 1 AND 128
                                      AND note_chunk_profile_hash <> 'LegacyCardV1'),
  PRIMARY KEY (domain, projection_kind, projection_version)
);

ALTER TABLE projection.card_profile_policies OWNER TO role_migration_owner;
REVOKE ALL ON projection.card_profile_policies
FROM PUBLIC, role_gateway, role_private_worker, role_consolidation_worker, role_public_worker,
  role_retrieval_worker, role_batch_issuer, role_maintenance, role_admin, role_health_reader;
GRANT SELECT ON projection.card_profile_policies TO role_retrieval_worker;

-- ADR-0068 D-I: the serving projection (domain::ticket_family::TicketFamily::PrivateMemory) starts legacy only.
INSERT INTO projection.card_profile_policies (domain, projection_kind, projection_version, note_chunk_profile_hash)
VALUES ('private_memory', 'PRIVATE_MEMORY', 'v1', NULL);

COMMENT ON TABLE projection.card_profile_policies IS
  'ADR-0068 D-I: per projection, the note chunk profile the worker builds and the ledger counts; NULL or no row = '
  'legacy only. Written only by migrations; role_retrieval_worker SELECT; the ledger definer reads it as owner. No '
  'tenant column, no RLS.';

ALTER TABLE projection.private_memory_points
  ADD COLUMN card_profile_hash text NOT NULL DEFAULT 'LegacyCardV1',
  ADD COLUMN chunk_ordinal integer NOT NULL DEFAULT 0,
  ADD CONSTRAINT private_memory_points_card_profile_hash_length
    CHECK (length(card_profile_hash) BETWEEN 1 AND 128),
  ADD CONSTRAINT private_memory_points_chunk_ordinal_nonnegative CHECK (chunk_ordinal >= 0),
  ADD CONSTRAINT private_memory_points_legacy_single_slot
    CHECK (card_profile_hash <> 'LegacyCardV1' OR chunk_ordinal = 0);

ALTER TABLE projection.private_memory_points
  DROP CONSTRAINT private_memory_points_exact_identity_unique;

ALTER TABLE projection.private_memory_points
  ADD CONSTRAINT private_memory_points_exact_identity_unique
    UNIQUE (tenant_id, scope_kind, scope_id, domain, projection_kind, projection_version,
            embedding_version, memory_id, source_updated_at, body_sha256, card_profile_hash, chunk_ordinal);

COMMENT ON COLUMN projection.private_memory_points.card_profile_hash IS
  'ADR-0068 D-C: LegacyCardV1 (v1 point id, ordinal 0 only) or the chunk profile hash (v2 point id).';
COMMENT ON COLUMN projection.private_memory_points.chunk_ordinal IS
  'ADR-0068 D-C: the slot within the profile, from 0; part of the exact identity UNIQUE key.';

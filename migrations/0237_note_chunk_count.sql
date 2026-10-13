-- §46 forward-fix (EXPAND_CONTRACT, first free number after 0236). ADR-0068 D-B / D-D (card 40d-1a): the SQL twin of
-- the NoteChunksV1 slot count, so the 40d-1b point ledger can count a long note's expected slots from PG alone
-- (never from the registry: an unbuilt note still expects all of them).
--
-- projection.note_chunk_count(title, body) = the point slots a note with this title and body occupies:
--   1                                         when char_length(title) + 3 + char_length(body) <= 600 (the legacy card
--                                             holds the whole body: ADR-0068 D-A)
--   1 + ceil(max(0, char_length(body) - 480) / 416)   otherwise (ADR-0068 D-B: W = 480, overlap 64, stride 416)
-- The ceiling is integer arithmetic, (x + 415) / 416, never a float. The Rust twins are
-- humaux_projection::note_chunks::{legacy_capacity_holds, chunk_count}; Rust alone builds chunk text, and
-- adapters::tests::note_chunk_count_parity pins the two counts together (ADR-0068 gate rust_sql_chunk_count_parity).
-- char_length counts characters, which in a UTF8 database are Unicode code points — the unit Rust's chars() counts
-- (a combining mark, an emoji and each of CR LF are one each); the precheck refuses any other server encoding.
--
-- It is not told whether the Memory is a note: the caller applies the identity-contract test and the profile policy
-- (ADR-0068 D-A / D-I), and calls this only for an identity note.
--
-- Pure: LANGUAGE sql, IMMUTABLE, STRICT, PARALLEL SAFE, SECURITY INVOKER, reads no relation. Owner
-- role_migration_owner, which is also the owner of the SECURITY DEFINER projection.stream_point_ledger, so the
-- ledger needs no grant to call it. EXECUTE role_retrieval_worker only (the worker's completion check and
-- expected-points read, 40d-1b); PUBLIC revoked. No table grant, no DML.

CREATE FUNCTION projection.note_chunk_count(p_title text, p_body text)
RETURNS integer
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
RETURN CASE
  WHEN char_length(p_title) + 3 + char_length(p_body) <= 600 THEN 1
  ELSE 1 + (greatest(0, char_length(p_body) - 480) + 415) / 416
END;

ALTER FUNCTION projection.note_chunk_count(text, text) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION projection.note_chunk_count(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION projection.note_chunk_count(text, text) TO role_retrieval_worker;

COMMENT ON FUNCTION projection.note_chunk_count(text, text) IS
  'ADR-0068 D-B/D-D: point slots of a note (title, body): 1 when title + 3 + body <= 600 scalars (legacy card), else '
  '1 + ceil(max(0, body - 480) / 416) NoteChunksV1 windows. Count only; Rust builds the chunk text. Parity: '
  'rust_sql_chunk_count_parity.';

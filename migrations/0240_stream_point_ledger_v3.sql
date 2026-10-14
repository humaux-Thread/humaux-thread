-- §46 forward-fix (EXPAND_CONTRACT, first free number after 0239). ADR-0068 D-D / D-I (card 40d-1b-iii-a): v3 of
-- projection.stream_point_ledger counts point SLOTS, not memories, and names the legacy point a note keeps while its
-- chunks are built (`points_retiring`).
--
-- Why: under a NoteChunksV1 policy (0238 projection.card_profile_policies) a long identity note is C points, not one.
-- v2 counted it as one expected point, so a note with 3 of 10 chunks built read as settled, and the legacy point the
-- worker keeps live until the last chunk is visible (ADR-0068 D-I retirement timing) had no term at all: A2 would
-- have had to absorb it by loosening the bound.
--
-- What, per Memory the stream's tickets reach (the v2 CTEs are unchanged up to `reached`):
--   slots    1, or C = projection.note_chunk_count(title, body) when it is CHUNKED: the projection's policy names a
--            profile, the Memory is the output of an identity contract (0235), its content carries string `title` and
--            `key_claim` (note_repo::memory_content writes exactly that), and projection.note_legacy_capacity_holds is
--            false. This is humaux_projection::build_projection_plan's predicate; the secret term is the `indexable`
--            fence every count already carries.
--   built    for a CHUNKED Memory, the distinct ordinals < C with a live registry row under the policy's profile.
--   expected slots (v2's filter).
--   settled  a legacy Memory: 1 when v2 settled it; a CHUNKED one: `built`, under the same filter — so a note whose
--            latest ticket is DONE but whose chunks were never built (the policy was enabled after it was projected)
--            settles 0 of C, never C.
--   in_flight / unsettled  slots, under v2's filters; a CHUNKED Memory settled short also adds `slots - built` to
--            unsettled (the backfill gap: ADR-0068 D-I "the gap shows as unsettled, never as complete").
--   retiring a CHUNKED, indexable, not tombstoned Memory that still holds a live LegacyCardV1 registry row, or any
--            LegacyCardV1 row while its latest ticket is not settled DONE (the completion step retires the binding,
--            then deletes the point, then settles the ticket): the one extra visible point per note mid-backfill,
--            0 or 1 each. Its own column, so A2's band widens by exactly that term.
-- With no policy row or a NULL hash nothing is CHUNKED and v3 returns v2's four numbers plus retiring = 0.
--
-- The return shape gains a column, which CREATE OR REPLACE cannot do, so the function is dropped and re-created in
-- this one transaction (the 0200 precedent): still ONE definer, same name and argument signature, owner, SECURITY
-- DEFINER, STABLE, pinned search_path and grants as 0219. A caller that selects the four v2 columns by name keeps
-- working. The definer reads 0238's card_profile_policies as its owner (no grant), 0235's
-- identity_note_materializations and 0119's private_memory_points under their FORCE RLS tenant policies (the caller's
-- tenant GUC, asserted equal to p_tenant_id below).

DROP FUNCTION projection.stream_point_ledger(uuid, text, uuid, text, text, text, text, uuid[]);

CREATE OR REPLACE FUNCTION projection.stream_point_ledger(
  p_tenant_id uuid,
  p_scope_kind text,
  p_scope_id uuid,
  p_domain text,
  p_projection_kind text,
  p_projection_version text,
  p_secret_class text,
  p_workspace_ids uuid[]
) RETURNS TABLE (
  points_expected bigint,
  points_settled bigint,
  points_in_flight bigint,
  points_unsettled bigint,
  points_retiring bigint
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_user uuid := NULLIF(current_setting('humaux.user_id', true), '')::uuid;
  v_profile text;
BEGIN
  IF p_tenant_id IS DISTINCT FROM NULLIF(current_setting('humaux.tenant_id', true), '')::uuid THEN
    RAISE EXCEPTION 'tenant_context_mismatch' USING ERRCODE = '42501';
  END IF;
  IF p_secret_class IS NULL OR length(p_secret_class) = 0 THEN
    RAISE EXCEPTION 'invalid secret class' USING ERRCODE = '22023';
  END IF;
  -- ADR-0068 D-I: a missing row and a NULL hash both mean legacy only.
  SELECT cp.note_chunk_profile_hash INTO v_profile
    FROM projection.card_profile_policies cp
   WHERE cp.domain = p_domain AND cp.projection_kind = p_projection_kind
     AND cp.projection_version = p_projection_version;
  RETURN QUERY
  WITH tickets AS (
    SELECT me.memory_id, sl.stream_seq, sl.state
      FROM projection.stream_log sl
      JOIN ops.outbox ob ON ob.tenant_id = sl.tenant_id AND ob.commit_seq = sl.commit_seq
      JOIN private.memory_evidence me ON me.evidence_id = ob.evidence_id
     WHERE sl.tenant_id = p_tenant_id AND sl.scope_kind = p_scope_kind
       AND sl.scope_id = p_scope_id AND sl.domain = p_domain
       AND sl.projection_kind = p_projection_kind
       AND sl.projection_version = p_projection_version
  ), per_memory AS (
    -- latest = the state of the highest stream_seq ticket on m (W6: one family runs in seq order)
    SELECT t.memory_id,
           bool_or(t.state = 'TOMBSTONED') AS tomb,
           bool_or(t.state IN ('ISSUED', 'PROCESSING', 'WAITING_KEY', 'RETRY_WAIT')) AS in_flight,
           (array_agg(t.state ORDER BY t.stream_seq DESC))[1] AS latest
      FROM tickets t
     GROUP BY t.memory_id
  ), reached AS (
    SELECT pm.memory_id, pm.tomb, pm.in_flight, pm.latest,
           (m.status = 'active' AND m.superseded_by IS NULL) AS live,
           NOT EXISTS (
             SELECT 1 FROM private.memory_evidence pe
               JOIN private.evidence_objects eo
                 ON eo.evidence_id = pe.evidence_id AND eo.tenant_id = p_tenant_id
              WHERE pe.memory_id = m.memory_id AND pe.role = 'PRIMARY'
                AND eo.data_class = p_secret_class) AS indexable,
           -- ADR-0068 D-A: build_projection_plan's NoteChunksV1 predicate, in SQL.
           (v_profile IS NOT NULL
             AND jsonb_typeof(m.content -> 'title') = 'string'
             AND jsonb_typeof(m.content -> 'key_claim') = 'string'
             AND EXISTS (SELECT 1 FROM private.identity_note_materializations n
                          WHERE n.tenant_id = p_tenant_id AND n.output_memory_id = m.memory_id)
             AND NOT projection.note_legacy_capacity_holds(m.content ->> 'title', m.content ->> 'key_claim'))
             AS chunked,
           m.content ->> 'title' AS title,
           m.content ->> 'key_claim' AS body
      FROM per_memory pm
      JOIN private.memory_records m
        ON m.memory_id = pm.memory_id AND m.tenant_id = p_tenant_id
     WHERE COALESCE(private.visibility_allowed(m.visibility_class, true,
             m.visibility_user_id = v_user,
             m.visibility_workspace_id = ANY (p_workspace_ids)
               AND EXISTS (SELECT 1 FROM control.workspace_memberships wm
                            WHERE wm.tenant_id = p_tenant_id
                              AND wm.workspace_id = m.visibility_workspace_id
                              AND wm.user_id = v_user
                              AND wm.state = 'ACTIVE')), false)
  ), slotted AS (
    SELECT r.tomb, r.in_flight, r.latest, r.live, r.indexable, r.chunked, s.slots,
           CASE WHEN r.chunked THEN (
             SELECT count(DISTINCT p.chunk_ordinal)
               FROM projection.private_memory_points p
              WHERE p.tenant_id = p_tenant_id AND p.scope_kind = p_scope_kind AND p.scope_id = p_scope_id
                AND p.domain = p_domain AND p.projection_kind = p_projection_kind
                AND p.projection_version = p_projection_version AND p.memory_id = r.memory_id
                AND p.projection_live AND p.card_profile_hash = v_profile AND p.chunk_ordinal < s.slots)
           ELSE 1 END AS built,
           r.chunked AND EXISTS (
             SELECT 1 FROM projection.private_memory_points p
              WHERE p.tenant_id = p_tenant_id AND p.scope_kind = p_scope_kind AND p.scope_id = p_scope_id
                AND p.domain = p_domain AND p.projection_kind = p_projection_kind
                AND p.projection_version = p_projection_version AND p.memory_id = r.memory_id
                AND p.card_profile_hash = 'LegacyCardV1'
                -- the completion step retires the binding before it deletes the point and settles the ticket, so
                -- until the latest ticket is DONE a retired legacy binding may still be a visible point
                AND (p.projection_live OR r.in_flight OR r.latest IS DISTINCT FROM 'DONE')) AS retiring
      FROM reached r
      CROSS JOIN LATERAL (
        SELECT CASE WHEN r.chunked THEN projection.note_chunk_count(r.title, r.body)::bigint
                    ELSE 1::bigint END AS slots) s
  )
  SELECT COALESCE(sum(x.slots) FILTER (WHERE NOT x.tomb AND x.live AND x.indexable), 0)::bigint,
         COALESCE(sum(x.built) FILTER (WHERE NOT x.tomb AND x.live AND x.indexable AND NOT x.in_flight
                                        AND x.latest = 'DONE'), 0)::bigint,
         -- ADR-0062 D-M: a non-indexable memory never holds a point, so it is neither in flight nor slack.
         COALESCE(sum(x.slots) FILTER (WHERE NOT x.tomb AND x.in_flight AND x.indexable), 0)::bigint,
         -- ADR-0057 D-A: after FAILED/LOST/RETIRED_FAILED each slot holds 0 or 1 point (W5); slack, not settled,
         -- until a later ticket acts on the memory. ADR-0068 D-I: a CHUNKED Memory settled short adds its gap.
         (COALESCE(sum(x.slots) FILTER (WHERE NOT x.tomb AND NOT x.in_flight AND x.indexable
                                         AND x.latest IN ('FAILED', 'LOST', 'RETIRED_FAILED')), 0)
          + COALESCE(sum(x.slots - x.built) FILTER (WHERE x.chunked AND NOT x.tomb AND x.live AND x.indexable
                                                     AND NOT x.in_flight AND x.latest = 'DONE'), 0))::bigint,
         count(*) FILTER (WHERE x.retiring AND NOT x.tomb AND x.indexable)
    FROM slotted x;
END;
$$;

ALTER FUNCTION projection.stream_point_ledger(uuid, text, uuid, text, text, text, text, uuid[])
  OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION projection.stream_point_ledger(uuid, text, uuid, text, text, text, text, uuid[])
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION projection.stream_point_ledger(uuid, text, uuid, text, text, text, text, uuid[])
  TO role_gateway, role_retrieval_worker;

COMMENT ON FUNCTION projection.stream_point_ledger(uuid, text, uuid, text, text, text, text, uuid[]) IS
  '§23.1② A2 in the point unit (ADR-0057 D-A/D-L; v2 ADR-0062 D-M; v3 ADR-0068 D-D/D-I): points_expected / '
  'points_settled / points_in_flight / points_unsettled over the expected point slots of the indexable memories '
  'one stream''s tickets reach (a NoteChunksV1 note is C slots), plus points_retiring (live legacy points of '
  'chunked notes mid-backfill), under the caller''s §6.1 visibility. Counts only.';

-- §37 / ADR-0092 D-C: the accept door's stream rows serialize every derived publisher through commit.
CREATE FUNCTION private.lock_publish_source(p_tenant uuid, p_evidence uuid, p_memory uuid)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_state text;
  v_live boolean := true;
BEGIN
  IF p_tenant IS NULL OR p_tenant IS DISTINCT FROM NULLIF(current_setting('humaux.tenant_id', true), '')::uuid
     OR (p_evidence IS NULL) = (p_memory IS NULL) THEN
    RAISE EXCEPTION 'invalid publish scope' USING ERRCODE = '42501';
  END IF;
  FOR v_state IN
    SELECT sl.state FROM projection.stream_log sl
    WHERE sl.tenant_id = p_tenant AND EXISTS (
      SELECT 1 FROM ops.outbox ob WHERE ob.tenant_id = p_tenant AND ob.commit_seq = sl.commit_seq
      AND (ob.evidence_id = p_evidence OR EXISTS (
        SELECT 1 FROM private.memory_evidence me WHERE me.memory_id = p_memory AND me.evidence_id = ob.evidence_id)))
    ORDER BY sl.scope_kind, sl.scope_id, sl.domain, sl.projection_kind, sl.projection_version, sl.stream_seq
    FOR SHARE OF sl
  LOOP
    v_live := v_live AND v_state <> 'TOMBSTONED';
  END LOOP;
  RETURN v_live;
END;
$$;
ALTER FUNCTION private.lock_publish_source(uuid,uuid,uuid) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION private.lock_publish_source(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.lock_publish_source(uuid,uuid,uuid)
  TO role_private_worker, role_consolidation_worker, role_retrieval_worker;

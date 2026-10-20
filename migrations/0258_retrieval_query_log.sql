-- §46 FORWARD_ONLY (T-RET-1b / ADR-0081 D-A; Baseline §19.1, §48.1). ops.retrieval_query_log: one row per answered
-- recall, the query only as a per-tenant HMAC (never text), written by gateway::recall (the in-repo part of G-RET-6).
-- Created RANGE-partitioned on called_at from the start (ADR-0063 D-A), so there is no conversion and no history to
-- carry; it joins the §48.1 closed table_key set as RETRIEVAL_QUERY_LOG:
--   * both table_key CHECKs of 0224 are widened (the retention_policies one too: approving a policy is the owner's act
--     through control.retention_policy_approve, ADR-0063 D-I; this migration inserts NO policy row, so the log keeps
--     everything until the owner approves one; the proposal, 1 month, is in ADR-0081 D-A);
--   * control.partition_parent gains the arm; control.partition_drop_check (0231 body, restated whole because
--     CREATE OR REPLACE replaces a body, not a line) gains the key in the no-hold arm, i.e. the plain whole-month
--     predicate. Owner, SECURITY attribute, SET list and ACL are those of 0231 (CREATE OR REPLACE keeps owner and ACL).
-- The current UTC month plus 3 leaves are created by control.partition_create_month, like every §48.1 table: there is
-- no DEFAULT partition, so a missed `retention create-partitions` raises 23514 for the INSERT (gateway::recall logs the
-- SQLSTATE and still answers, ADR-0081 D-A).
--
-- Access (ADR-0081 D-A D4): FORCE RLS with the tenant policy and a WITH CHECK, so a cross-tenant INSERT is refused by
-- the table. role_gateway holds INSERT and nothing else; no runtime role holds SELECT, UPDATE or DELETE, and the owner
-- reads it for replay. No new role.
--
-- Locks: ACCESS EXCLUSIVE on control.partition_registry / retention_policies only for the CHECK swap (a handful of
-- rows); the new table is empty and unreferenced.

LOCK TABLE control.partition_registry, control.retention_policies IN ACCESS EXCLUSIVE MODE;

ALTER TABLE control.retention_policies DROP CONSTRAINT retention_policies_table_key;
ALTER TABLE control.retention_policies
  ADD CONSTRAINT retention_policies_table_key
  CHECK (table_key IN ('MODEL_CALL_LEDGER', 'STAGE_RUNS', 'MESSAGES', 'MAINTENANCE_RECEIPTS', 'RETRIEVAL_QUERY_LOG'));
ALTER TABLE control.partition_registry DROP CONSTRAINT partition_registry_table_key;
ALTER TABLE control.partition_registry
  ADD CONSTRAINT partition_registry_table_key
  CHECK (table_key IN ('MODEL_CALL_LEDGER', 'STAGE_RUNS', 'MESSAGES', 'MAINTENANCE_RECEIPTS', 'EVENTS', 'AUDIT_EVENTS',
                       'RETRIEVAL_QUERY_LOG'));

CREATE OR REPLACE FUNCTION control.partition_parent(p_table_key text, OUT parent regclass, OUT key_column name)
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog
AS $$
DECLARE
  v_rel text;
BEGIN
  SELECT m.rel, m.key INTO v_rel, key_column
    FROM (VALUES ('STAGE_RUNS', 'ops.stage_runs', 'started_at'),
                 ('MESSAGES', 'private.messages', 'created_at'),
                 ('MAINTENANCE_RECEIPTS', 'ops.maintenance_receipts', 'ran_at'),
                 ('EVENTS', 'private.events', 'recorded_at'),
                 ('AUDIT_EVENTS', 'control.audit_events', 'occurred_at'),
                 ('MODEL_CALL_LEDGER', 'ops.model_call_ledger', 'called_at'),
                 ('RETRIEVAL_QUERY_LOG', 'ops.retrieval_query_log', 'called_at')) m(table_key, rel, key)
   WHERE m.table_key = p_table_key;
  IF v_rel IS NULL THEN
    RAISE EXCEPTION 'partition: unknown table_key %', p_table_key USING ERRCODE = '22023';
  END IF;
  parent := to_regclass(v_rel);
  IF NOT EXISTS (
       SELECT 1 FROM pg_partitioned_table pt JOIN pg_attribute a ON a.attrelid = pt.partrelid
        WHERE pt.partrelid = parent AND pt.partstrat = 'r' AND pt.partnatts = 1
          AND a.attnum = pt.partattrs[0] AND a.attname = key_column) THEN
    RAISE EXCEPTION 'partition: % is not range-partitioned on % (ADR-0063 D-A)', v_rel, key_column
      USING ERRCODE = '55000';
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION control.partition_drop_check(p_policy_id uuid, p_registry_id uuid)
RETURNS TABLE (leaf text, lower_bound timestamptz, upper_bound timestamptz, row_count bigint)
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
SET row_security = off
AS $$
#variable_conflict use_column
DECLARE
  reg      control.partition_registry%ROWTYPE;
  pol      control.retention_policies%ROWTYPE;
  v_parent regclass;
  v_cutoff timestamptz;
  v_hold   boolean;
  v_rows   bigint;
BEGIN
  IF NOT coalesce((SELECT r.rolsuper FROM pg_roles r WHERE r.rolname = current_user), false) THEN
    RAISE EXCEPTION 'retention refused: executor_not_superuser';
  END IF;
  SELECT * INTO reg FROM control.partition_registry g WHERE g.registry_id = p_registry_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'retention refused: unknown_registry_row';
  END IF;
  IF reg.state <> 'ATTACHED' THEN
    RAISE EXCEPTION 'retention refused: not_attached';
  END IF;
  SELECT * INTO pol FROM control.retention_policies p WHERE p.policy_id = p_policy_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'retention refused: unknown_policy';
  END IF;
  IF pol.table_key <> reg.table_key THEN
    RAISE EXCEPTION 'retention refused: wrong_table';
  END IF;
  IF EXISTS (SELECT 1 FROM control.retention_policies p
              WHERE p.table_key = pol.table_key AND p.policy_revision > pol.policy_revision) THEN
    RAISE EXCEPTION 'retention refused: superseded';
  END IF;
  IF pol.effective_at > now() THEN
    RAISE EXCEPTION 'retention refused: not_effective';
  END IF;
  IF pol.retention_months IS NULL THEN
    RAISE EXCEPTION 'retention refused: keep_forever';
  END IF;
  -- D-J step 3: the current and future months can never be due (UTC, whatever the session TimeZone).
  v_cutoff := ((date_trunc('month', now(), 'UTC') AT TIME ZONE 'UTC')
               - make_interval(months => pol.retention_months)) AT TIME ZONE 'UTC';
  IF reg.upper_bound > v_cutoff THEN
    RAISE EXCEPTION 'retention refused: not_due';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM control.partition_registry g
                  WHERE g.table_key = reg.table_key AND g.state = 'ATTACHED' AND g.upper_bound > reg.upper_bound) THEN
    RAISE EXCEPTION 'retention refused: newest_leaf';
  END IF;
  -- D-J step 4 / 0231: the registry must still describe the catalog. The leaf is the relation its canonical name
  -- resolves to, and only if that is an ordinary table attached to this table_key's parent whose partition bound is
  -- exactly the registry's [lower, upper) (both rendered by this session, so equal text = equal instants); nothing
  -- below acts on a leaf that fails this.
  SELECT p.parent INTO v_parent FROM control.partition_parent(reg.table_key) p;
  IF NOT EXISTS (
       SELECT 1
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         JOIN pg_inherits i ON i.inhrelid = c.oid AND i.inhparent = v_parent
        WHERE c.oid = to_regclass(reg.leaf_name) AND c.relkind = 'r'
          AND format('%I.%I', n.nspname, c.relname) = reg.leaf_name
          AND pg_get_expr(c.relpartbound, c.oid)
              = format('FOR VALUES FROM (%s) TO (%s)', coalesce(quote_literal(reg.lower_bound), 'MINVALUE'),
                       quote_literal(reg.upper_bound))) THEN
    RAISE EXCEPTION 'retention refused: registry_catalog_mismatch %', reg.leaf_name;
  END IF;
  IF reg.proposed_policy_revision IS DISTINCT FROM pol.policy_revision OR reg.proposed_at IS NULL
     OR reg.proposed_at < pol.effective_at THEN
    RAISE EXCEPTION 'retention refused: not_proposed';
  END IF;
  -- D-J step 5: writes routed to this past month wait; the parent stays writable.
  EXECUTE format('LOCK TABLE %s IN SHARE MODE', reg.leaf_name);
  -- L13: exhaustive over the closed table_key set; a key without an arm is never dropped by default.
  CASE reg.table_key
    WHEN 'MODEL_CALL_LEDGER' THEN
      EXECUTE format('SELECT EXISTS (SELECT 1 FROM %s l WHERE l.status = ''RESERVED'')', reg.leaf_name)
        INTO v_hold;
      IF v_hold THEN
        RAISE EXCEPTION 'retention refused: hold:unsettled_ledger_calls';
      END IF;
      -- 0117:507-517: the reaper would settle such a reservation EXPIRED instead of RELEASED once its row is gone.
      EXECUTE format('SELECT EXISTS (SELECT 1 FROM ops.retrieval_provider_budget_reservations r JOIN %s l'
                     ' ON l.tenant_id = r.tenant_id AND l.model_call_id = r.model_call_id'
                     ' WHERE r.status = ''RESERVED'')', reg.leaf_name)
        INTO v_hold;
      IF v_hold THEN
        RAISE EXCEPTION 'retention refused: hold:open_budget_reservations';
      END IF;
      -- 0131:4-13 terminal states, written NOT IN so a state added later holds by default.
      EXECUTE format('SELECT EXISTS (SELECT 1 FROM private.contribution_executions e JOIN %s l'
                     ' ON l.tenant_id = e.tenant_id'
                     ' AND l.model_call_id IN (e.coverage_model_call_id, e.assessment_model_call_id)'
                     ' WHERE e.state NOT IN (''DONE'', ''NOT_CONTRIBUTABLE'', ''REJECTED_SAFETY'','
                     ' ''FAILED_TERMINAL''))', reg.leaf_name)
        INTO v_hold;
      IF v_hold THEN
        RAISE EXCEPTION 'retention refused: hold:open_contribution_executions';
      END IF;
    WHEN 'STAGE_RUNS' THEN
      EXECUTE format('SELECT EXISTS (SELECT 1 FROM %s l WHERE l.finished_at IS NULL)', reg.leaf_name) INTO v_hold;
      IF v_hold THEN
        RAISE EXCEPTION 'retention refused: hold:running_stage';
      END IF;
    -- 0258: the query-hash log has no hold rule; the plain whole-month predicate above is its whole gate.
    WHEN 'MESSAGES', 'MAINTENANCE_RECEIPTS', 'RETRIEVAL_QUERY_LOG' THEN
      NULL;
    ELSE
      RAISE EXCEPTION 'retention refused: no_hold_rule';
  END CASE;
  EXECUTE format('SELECT count(*) FROM %s', reg.leaf_name) INTO v_rows;
  RETURN QUERY SELECT reg.leaf_name, reg.lower_bound, reg.upper_bound, v_rows;
END;
$$;

-- The table. PK (log_id, called_at): a partitioned PK must contain the partition key; log_id is server-minted, so
-- uniqueness per (id, key) is the same ruling as ADR-0063 L10.
CREATE TABLE ops.retrieval_query_log (
  log_id       uuid        NOT NULL DEFAULT uuidv7(),
  tenant_id    uuid        NOT NULL REFERENCES control.tenants (tenant_id) ON DELETE CASCADE,
  workspace_id uuid        NOT NULL,
  -- NULL: a service principal acting on no user (AuthorizationScope::user_id, §6.1.1).
  user_id      uuid,
  called_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
  -- HMAC-SHA256(per-tenant key, query bytes) and the ADR-0059 kid of the key it was derived from (8 lower-case hex).
  -- No text column exists on this table that could hold the query.
  query_hmac   bytea       NOT NULL CONSTRAINT retrieval_query_log_query_hmac_len CHECK (octet_length(query_hmac) = 32),
  key_id       text        NOT NULL CONSTRAINT retrieval_query_log_key_id_hex CHECK (key_id ~ '^[0-9a-f]{8}$'),
  cand_k       integer     NOT NULL CHECK (cand_k >= 0),
  candidates   integer     NOT NULL CHECK (candidates >= 0),
  -- NULL: the live index count could not be established (visible_index_count answered None) or the recall answered
  -- from the no-serving-projection branch, which never counts.
  visible      integer     CHECK (visible >= 0),
  returned     integer     NOT NULL CHECK (returned >= 0),
  -- The same object as provenance.stage_ms; NULL exactly when the answer carried none (the no-serving-projection branch).
  stage_ms     jsonb,
  CONSTRAINT retrieval_query_log_pkey PRIMARY KEY (log_id, called_at),
  -- bins/gateway/src/recall.rs asks Qdrant for cand_k and adapters::qdrant (parse_dense_candidates,
  -- query_dense_groups_bounded) refuse a response above that limit, so the candidate count never exceeds it. The other
  -- pairs carry no CHECK: `returned` also counts the read-your-writes overlay items (they are not candidates), and
  -- `visible` is a live index count taken after the candidate query, so neither is bounded by another column.
  CONSTRAINT retrieval_query_log_candidates_le_cand_k CHECK (candidates <= cand_k)
) PARTITION BY RANGE (called_at);
-- ON DELETE CASCADE from control.tenants scans the log by tenant; the same index serves a per-tenant replay.
CREATE INDEX retrieval_query_log_tenant_called_at_idx ON ops.retrieval_query_log (tenant_id, called_at);
ALTER TABLE ops.retrieval_query_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.retrieval_query_log FORCE ROW LEVEL SECURITY;
CREATE POLICY retrieval_query_log_tenant_isolation ON ops.retrieval_query_log
  USING (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid);
ALTER TABLE ops.retrieval_query_log OWNER TO role_migration_owner;
-- 0011's default privileges fired for the migrate principal: revoke them, then the one cell (§6.2.2).
REVOKE ALL ON ops.retrieval_query_log
FROM PUBLIC, role_gateway, role_private_worker, role_consolidation_worker, role_public_worker,
  role_retrieval_worker, role_batch_issuer, role_maintenance, role_admin, role_health_reader;
GRANT INSERT ON ops.retrieval_query_log TO role_gateway;
COMMENT ON TABLE ops.retrieval_query_log IS
  'ADR-0081 D-A: one row per answered recall; the query only as a per-tenant HMAC (never text). Written by gateway::recall, read by the owner for replay.';

-- ADR-0063 D-F: the current UTC month plus 3, never a DEFAULT partition. partition_create_month takes the first
-- leaf of a key with no leaf yet only for the current month.
DO $$
DECLARE
  v_month timestamptz := date_trunc('month', now(), 'UTC');
  v_upper timestamptz := date_trunc('month', now(), 'UTC');
BEGIN
  WHILE v_upper < date_add(v_month, interval '4 months', 'UTC') LOOP
    PERFORM control.partition_create_month('RETRIEVAL_QUERY_LOG', v_upper);
    v_upper := date_add(v_upper, interval '1 month', 'UTC');
  END LOOP;
END
$$;

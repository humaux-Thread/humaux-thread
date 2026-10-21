-- §46 forward-fix (EXPAND_CONTRACT, number 0257). ADR-0081 D-A (D-RET-1), card T-RET-1a: the model-call ledger
-- could not say how much of a call's prompt the provider served from its prompt cache, so the cache hit rate
-- H = sum(cache-read tokens) / sum(total input tokens) was unmeasurable. `adapters::byok` already parses
-- `usage.prompt_tokens_details.cached_tokens` (`TokenUsage::cached_input_tokens`) and `finalize_from_usage` then had
-- nowhere to put it.
--
-- Shape: two nullable outcome columns on ops.model_call_ledger, written exactly once by finalize() and immutable
-- afterwards, exactly like 0168's `output_tokens`. `input_tokens` stays the TOTAL prompt tokens (the OpenAI-compatible
-- `prompt_tokens` already includes the cached part), so the four categories derive from one row without a second
-- convention: new input = input_tokens - read - coalesce(write, 0); cache write; cache read; output_tokens.
-- NULL means "the provider did not report it", never 0 (§19.1 "unknown usage stays NULL"): the OpenAI-compatible
-- protocol, the only one `byok` speaks, has no write counter, so `provider_cache_write_tokens` is NULL today.
--
-- Constraints (a good call must never be turned into a lost ledger row by the writer, so the writer also refuses to
-- emit a count the CHECK would refuse — `contribution_reasoner::finalize_from_usage`):
--   * each column >= 0 when present (same shape as its siblings);
--   * across columns: no cache count without `input_tokens`, and read + write never exceed it. The sum is written as
--     read <= input_tokens - write so two huge bigints cannot overflow into 22003 ahead of the 23514.
--
-- The table has been partitioned (RANGE called_at) since 0230. ADD COLUMN / ADD CONSTRAINT on the parent recurse into
-- every leaf and CREATE TABLE ... PARTITION OF (control.partition_create_month) inherits them, so no per-leaf step and
-- no `control.partition_catalog_fingerprint` consumer changes (it is only compared inside 0225..0230 themselves).
--
-- No new table, no new role, no new GRANT, no RLS change, no DML ⇒ no §6.2.2 matrix row and no rls_check cell: this
-- is a column on a table every writing role already holds INSERT+UPDATE on. The cross-column CHECK takes ACCESS
-- EXCLUSIVE on the parent and its leaves while it validates once over the existing rows, which all have both new
-- columns NULL and so can only pass (ADR-0063 measured 61,031 dev rows for 0230's longer lock).

ALTER TABLE ops.model_call_ledger
  ADD COLUMN provider_cache_read_tokens bigint
    CONSTRAINT model_call_ledger_provider_cache_read_tokens_nonneg
    CHECK (provider_cache_read_tokens IS NULL OR provider_cache_read_tokens >= 0),
  ADD COLUMN provider_cache_write_tokens bigint
    CONSTRAINT model_call_ledger_provider_cache_write_tokens_nonneg
    CHECK (provider_cache_write_tokens IS NULL OR provider_cache_write_tokens >= 0);

ALTER TABLE ops.model_call_ledger
  ADD CONSTRAINT model_call_ledger_provider_cache_tokens_within_input CHECK (
    CASE WHEN input_tokens IS NULL
         THEN provider_cache_read_tokens IS NULL AND provider_cache_write_tokens IS NULL
         ELSE coalesce(provider_cache_read_tokens, 0) <= input_tokens - coalesce(provider_cache_write_tokens, 0)
    END);

COMMENT ON COLUMN ops.model_call_ledger.provider_cache_read_tokens IS
  '§19.1 (0257, ADR-0081 D-A): prompt tokens the provider served from its prompt cache '
  '(OpenAI-compatible `usage.prompt_tokens_details.cached_tokens`). A SUBSET of input_tokens, which stays the '
  'TOTAL prompt tokens: new input = input_tokens - read - coalesce(write, 0). NULL = the provider did not report '
  'it, never 0 (a reported 0 is stored as 0); the cache hit rate is sum(read) / sum(input_tokens) over rows where '
  'this is NOT NULL. Outcome column: set once by finalize(), immutable after.';

COMMENT ON COLUMN ops.model_call_ledger.provider_cache_write_tokens IS
  '§19.1 (0257, ADR-0081 D-A): prompt tokens the provider WROTE to its prompt cache on this call (Anthropic-style '
  'cache creation). Part of input_tokens, disjoint from provider_cache_read_tokens. The OpenAI-compatible '
  'protocol does not report it, so NULL today and never 0 for "unknown". Outcome column: set once by finalize(), '
  'immutable after.';

COMMENT ON CONSTRAINT model_call_ledger_provider_cache_tokens_within_input ON ops.model_call_ledger IS
  '§19.1 (0257): no cache count without input_tokens, and read + coalesce(write, 0) <= input_tokens.';

-- ---------------------------------------------------------------------------------------------
-- The two functions that enumerate the outcome columns by name, as 0168 did for output_tokens. Both are the
-- currently installed bodies (guard_mutation from 0230, reasoning_model_call_validate from 0206) byte for byte
-- apart from the added provider_cache_* terms: a guard that does not name a new column leaves it the one outcome
-- column a second UPDATE could rewrite (0098 finding #6), and a validator that does not count it lets a reasoning
-- reservation be inserted already carrying a result.
-- ---------------------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION ops.model_call_ledger_guard_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'ops.model_call_ledger is append-only (§19.1) — % not permitted', TG_OP
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.model_call_id IS DISTINCT FROM NEW.model_call_id
     OR OLD.request_id IS DISTINCT FROM NEW.request_id
     OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
     OR OLD.workspace_id IS DISTINCT FROM NEW.workspace_id
     OR OLD.purpose IS DISTINCT FROM NEW.purpose
     OR OLD.provider IS DISTINCT FROM NEW.provider
     OR OLD.model IS DISTINCT FROM NEW.model
     OR OLD.model_revision IS DISTINCT FROM NEW.model_revision
     OR OLD.called_at IS DISTINCT FROM NEW.called_at
     OR OLD.estimated_cost IS DISTINCT FROM NEW.estimated_cost
     OR OLD.reasoning_domain_id IS DISTINCT FROM NEW.reasoning_domain_id
     OR OLD.call_kind IS DISTINCT FROM NEW.call_kind
     OR OLD.intent_sha256 IS DISTINCT FROM NEW.intent_sha256
     OR OLD.binding_id IS DISTINCT FROM NEW.binding_id
     OR OLD.binding_version IS DISTINCT FROM NEW.binding_version
     OR OLD.route_policy_id IS DISTINCT FROM NEW.route_policy_id
     OR OLD.route_policy_version IS DISTINCT FROM NEW.route_policy_version
     OR OLD.profile_id IS DISTINCT FROM NEW.profile_id
     OR OLD.profile_version IS DISTINCT FROM NEW.profile_version
     OR OLD.provider_account_id IS DISTINCT FROM NEW.provider_account_id
     OR OLD.provider_endpoint_id IS DISTINCT FROM NEW.provider_endpoint_id
     OR OLD.egress_processor_id IS DISTINCT FROM NEW.egress_processor_id
     OR OLD.credential_ref IS DISTINCT FROM NEW.credential_ref
     OR OLD.billing_account_id IS DISTINCT FROM NEW.billing_account_id
     OR OLD.billing_instrument_id IS DISTINCT FROM NEW.billing_instrument_id
     OR OLD.provider_health_observation_id IS DISTINCT FROM NEW.provider_health_observation_id
     OR OLD.account_health_observation_id IS DISTINCT FROM NEW.account_health_observation_id
     OR OLD.billing_responsibility IS DISTINCT FROM NEW.billing_responsibility
     OR OLD.admitted_at IS DISTINCT FROM NEW.admitted_at THEN
    RAISE EXCEPTION 'ops.model_call_ledger identity/reservation columns are immutable after INSERT (§19.1)'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.status <> 'RESERVED' AND NEW.status IS DISTINCT FROM OLD.status THEN
    RAISE EXCEPTION 'ops.model_call_ledger already finalized — status cannot change again (§19.1)'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (OLD.input_tokens IS NOT NULL AND OLD.input_tokens IS DISTINCT FROM NEW.input_tokens)
  OR (OLD.output_tokens IS NOT NULL AND OLD.output_tokens IS DISTINCT FROM NEW.output_tokens)
  OR (OLD.provider_cache_read_tokens IS NOT NULL AND OLD.provider_cache_read_tokens IS DISTINCT FROM NEW.provider_cache_read_tokens)
  OR (OLD.provider_cache_write_tokens IS NOT NULL AND OLD.provider_cache_write_tokens IS DISTINCT FROM NEW.provider_cache_write_tokens)
  OR (OLD.billable_tokens IS NOT NULL AND OLD.billable_tokens IS DISTINCT FROM NEW.billable_tokens)
  OR (OLD.candidate_count IS NOT NULL AND OLD.candidate_count IS DISTINCT FROM NEW.candidate_count)
  OR (OLD.candidate_tokens IS NOT NULL AND OLD.candidate_tokens IS DISTINCT FROM NEW.candidate_tokens)
  OR (OLD.cache_hit IS NOT NULL AND OLD.cache_hit IS DISTINCT FROM NEW.cache_hit)
  OR (OLD.latency_ms IS NOT NULL AND OLD.latency_ms IS DISTINCT FROM NEW.latency_ms)
  OR (OLD.actual_cost IS NOT NULL AND OLD.actual_cost IS DISTINCT FROM NEW.actual_cost)
  OR (OLD.error_class IS NOT NULL AND OLD.error_class IS DISTINCT FROM NEW.error_class)
  OR (OLD.provider_request_id IS NOT NULL AND OLD.provider_request_id IS DISTINCT FROM NEW.provider_request_id) THEN
    RAISE EXCEPTION 'ops.model_call_ledger outcome columns can only be set once, from NULL (§19.1)'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.purpose = 'CONTRIBUTION_DEIDENTIFY' AND NEW.actual_cost IS NOT NULL THEN
    RAISE EXCEPTION 'USER-paid reasoning calls never record platform actual cost'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION ops.reasoning_model_call_validate()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF NEW.purpose IN ('PRIVATE_DISTILL_TEXT', 'PRIVATE_DISTILL_VISION', 'PRIVATE_CONSOLIDATE') THEN
    -- ADR-0060 D-I: the all-NULL form of the CHECK's private arm is for rows that predate 0206 only.
    IF num_nonnulls(
         NEW.reasoning_domain_id, NEW.binding_id, NEW.binding_version, NEW.route_policy_id,
         NEW.route_policy_version, NEW.profile_id, NEW.profile_version, NEW.provider_account_id,
         NEW.provider_endpoint_id, NEW.egress_processor_id, NEW.credential_ref,
         NEW.provider_health_observation_id, NEW.account_health_observation_id, NEW.admitted_at
       ) <> 14 THEN
      RAISE EXCEPTION 'private reasoning model call must carry its admitted route'
        USING ERRCODE = '23514';
    END IF;
    IF NEW.status <> 'RESERVED'
       OR num_nonnulls(
            NEW.input_tokens, NEW.output_tokens, NEW.billable_tokens, NEW.candidate_count,
            NEW.candidate_tokens, NEW.cache_hit, NEW.latency_ms, NEW.actual_cost,
            NEW.error_class, NEW.provider_request_id, NEW.provider_cache_read_tokens,
            NEW.provider_cache_write_tokens
          ) <> 0
       OR NEW.admitted_at > clock_timestamp() THEN
      RAISE EXCEPTION 'reasoning model call must begin as an unfinalized USER-paid reservation'
        USING ERRCODE = '23514';
    END IF;
    -- §11.2.5 / ADR-0060 D-I: identity equals the current admission; the health ids are recorded and
    -- must have admitted this route at admitted_at, but a newer observation does not refuse the row.
    IF NOT EXISTS (
      SELECT 1
        FROM control.resolve_user_reasoning_admission(
          NEW.binding_id, NEW.binding_version, NEW.reasoning_domain_id, NEW.purpose
        ) admission
       WHERE admission.tenant_id = NEW.tenant_id
         AND admission.binding_id = NEW.binding_id
         AND admission.binding_version = NEW.binding_version
         AND admission.reasoning_domain_id = NEW.reasoning_domain_id
         AND admission.route_policy_id = NEW.route_policy_id
         AND admission.route_policy_version = NEW.route_policy_version
         AND admission.profile_id = NEW.profile_id
         AND admission.profile_version = NEW.profile_version
         AND admission.provider_account_id = NEW.provider_account_id
         AND admission.processor_id = NEW.provider
         AND admission.provider_model_id = NEW.model
         AND admission.model_revision IS NOT DISTINCT FROM NEW.model_revision
         AND admission.provider_endpoint_id = NEW.provider_endpoint_id
         AND admission.egress_processor_id = NEW.egress_processor_id
         AND admission.credential_ref = NEW.credential_ref
         AND admission.billing_account_id IS NOT DISTINCT FROM NEW.billing_account_id
         AND admission.billing_instrument_id IS NOT DISTINCT FROM NEW.billing_instrument_id
         AND NEW.billing_responsibility = 'USER'
    ) OR NOT EXISTS (
      SELECT 1
        FROM ops.reasoning_provider_health_observations provider_health
        JOIN ops.reasoning_account_health_observations account_health
          ON account_health.tenant_id = provider_health.tenant_id
         AND account_health.observation_id = NEW.account_health_observation_id
       WHERE provider_health.tenant_id = NEW.tenant_id
         AND provider_health.observation_id = NEW.provider_health_observation_id
         AND provider_health.processor_id = NEW.provider
         AND provider_health.provider_model_id = NEW.model
         AND provider_health.model_revision IS NOT DISTINCT FROM NEW.model_revision
         AND provider_health.provider_endpoint_id = NEW.provider_endpoint_id
         AND provider_health.verdict = 'HEALTHY'
         AND provider_health.observed_at <= NEW.admitted_at
         AND NEW.admitted_at < provider_health.valid_until
         AND account_health.provider_account_id = NEW.provider_account_id
         AND account_health.credential_ref = NEW.credential_ref
         AND account_health.billing_account_id IS NOT DISTINCT FROM NEW.billing_account_id
         AND account_health.billing_instrument_id IS NOT DISTINCT FROM NEW.billing_instrument_id
         AND account_health.account_verdict = 'HEALTHY'
         AND account_health.credential_verdict = 'VALID'
         AND account_health.billing_account_verdict IS NOT DISTINCT FROM
           CASE WHEN NEW.billing_account_id IS NULL THEN NULL ELSE 'ENABLED' END
         AND account_health.billing_instrument_verdict IS NOT DISTINCT FROM
           CASE WHEN NEW.billing_instrument_id IS NULL THEN NULL ELSE 'ENABLED' END
         AND account_health.observed_at <= NEW.admitted_at
         AND NEW.admitted_at < account_health.valid_until
    ) THEN
      RAISE EXCEPTION 'reasoning model call snapshot must equal one current exact admission'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.purpose IS DISTINCT FROM 'CONTRIBUTION_DEIDENTIFY' THEN
    RETURN NEW;
  END IF;
  IF NEW.status <> 'RESERVED'
     OR num_nonnulls(
          NEW.input_tokens, NEW.output_tokens, NEW.billable_tokens, NEW.candidate_count,
          NEW.candidate_tokens, NEW.cache_hit, NEW.latency_ms, NEW.actual_cost,
          NEW.error_class, NEW.provider_request_id, NEW.provider_cache_read_tokens,
          NEW.provider_cache_write_tokens
        ) <> 0
     OR NEW.admitted_at > clock_timestamp() THEN
    RAISE EXCEPTION 'reasoning model call must begin as an unfinalized USER-paid reservation'
      USING ERRCODE = '23514';
  END IF;
  IF NOT EXISTS (
    SELECT 1
      FROM control.resolve_user_reasoning_admission(
        NEW.binding_id,
        NEW.binding_version,
        NEW.reasoning_domain_id,
        'CONTRIBUTION_DEIDENTIFY'
      ) admission
      JOIN ops.reasoning_provider_health_observations provider_health
        ON provider_health.tenant_id = admission.tenant_id
       AND provider_health.observation_id = admission.provider_health_observation_id
      JOIN ops.reasoning_account_health_observations account_health
        ON account_health.tenant_id = admission.tenant_id
       AND account_health.observation_id = admission.account_health_observation_id
     WHERE admission.tenant_id = NEW.tenant_id
       AND admission.binding_id = NEW.binding_id
       AND admission.binding_version = NEW.binding_version
       AND admission.reasoning_domain_id = NEW.reasoning_domain_id
       AND admission.route_policy_id = NEW.route_policy_id
       AND admission.route_policy_version = NEW.route_policy_version
       AND admission.profile_id = NEW.profile_id
       AND admission.profile_version = NEW.profile_version
       AND admission.provider_account_id = NEW.provider_account_id
       AND admission.processor_id = NEW.provider
       AND admission.provider_model_id = NEW.model
       AND admission.model_revision IS NOT DISTINCT FROM NEW.model_revision
       AND admission.provider_endpoint_id = NEW.provider_endpoint_id
       AND admission.egress_processor_id = NEW.egress_processor_id
       AND admission.credential_ref = NEW.credential_ref
       AND admission.billing_account_id IS NOT DISTINCT FROM NEW.billing_account_id
       AND admission.billing_instrument_id IS NOT DISTINCT FROM NEW.billing_instrument_id
       AND admission.provider_health_observation_id = NEW.provider_health_observation_id
       AND admission.account_health_observation_id = NEW.account_health_observation_id
       AND NEW.billing_responsibility = 'USER'
       AND provider_health.observed_at <= NEW.admitted_at
       AND NEW.admitted_at < provider_health.valid_until
       AND provider_health.verdict = 'HEALTHY'
       AND account_health.observed_at <= NEW.admitted_at
       AND NEW.admitted_at < account_health.valid_until
       AND account_health.account_verdict = 'HEALTHY'
       AND account_health.credential_verdict = 'VALID'
       AND account_health.billing_account_verdict IS NOT DISTINCT FROM
         CASE WHEN NEW.billing_account_id IS NULL THEN NULL ELSE 'ENABLED' END
       AND account_health.billing_instrument_verdict IS NOT DISTINCT FROM
         CASE WHEN NEW.billing_instrument_id IS NULL THEN NULL ELSE 'ENABLED' END
  ) THEN
    RAISE EXCEPTION 'reasoning model call snapshot must equal one current exact admission'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

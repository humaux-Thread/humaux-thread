-- §71.1 / M04-1 (card M04-1; §46 forward-fix, EXPAND_CONTRACT, number 0262): the plan catalogue. A plan is data, not a
-- Rust branch: `control.plans` names a sellable plan and `control.plan_versions` pins one price, one entitlement template
-- and one lease block per version, so a subscription that pins a version keeps its terms (Baseline "Plan Versioning /
-- Grandfathering"). No subscription, payment, lease or journal table is added here.
--
-- Both tables are global (no tenant_id, no RLS) and keep the control-domain default grants (SELECT for the workers and
-- role_maintenance, nothing else): the catalogue is not a secret and no runtime role may write it. The only writer is
-- the owner door control.publish_plan_version (SECURITY DEFINER, search_path pg_catalog, EXECUTE role_maintenance
-- only), which inserts a version or verifies that the stored one is the one asked for. A version's price, currency,
-- interval, template and lease block never change after insert (trigger plan_versions_pin); only the one-way publish
-- (valid_from NULL -> a timestamp), the one-way retire (retired_at) and the provider product mapping may move.
--
-- valid_from IS NULL is a draft: a version no one is offered yet. The closed sets (currency, interval, template keys,
-- provider modes) are CHECK literals compared with crates/domain/src/plan.rs by contract test (§78.2).

CREATE TABLE control.plans (
  plan_id    uuid        PRIMARY KEY DEFAULT uuidv7(),
  plan_key   text        NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT plans_plan_key_unique UNIQUE (plan_key),
  CONSTRAINT plans_plan_key_shape CHECK (plan_key ~ '^[a-z][a-z0-9_]{0,31}$')
);

COMMENT ON TABLE control.plans IS
  'M04 D2: a sellable plan, named by a lowercase key; nothing branches on the key (Baseline 71.1). Written only by '
  'control.publish_plan_version.';

-- ponytail: the template's value shapes are validated by domain::plan before the door is called and by the quota issuer
-- when a window is cut; the database pins only the key set. Add a shape CHECK when a second writer of the door appears.
CREATE TABLE control.plan_versions (
  plan_version_id      uuid        PRIMARY KEY DEFAULT uuidv7(),
  plan_id              uuid        NOT NULL REFERENCES control.plans (plan_id),
  version              integer     NOT NULL,
  price_cents          bigint      NOT NULL,
  currency             text        NOT NULL DEFAULT 'USD',
  billing_interval     text        NOT NULL,
  entitlement_template jsonb       NOT NULL,
  lease_block          integer     NOT NULL,
  provider_product_ref jsonb       NOT NULL DEFAULT '{}'::jsonb,
  valid_from           timestamptz,
  retired_at           timestamptz,
  created_at           timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT plan_versions_plan_version_unique UNIQUE (plan_id, version),
  CONSTRAINT plan_versions_version_positive CHECK (version >= 1),
  CONSTRAINT plan_versions_price_nonnegative CHECK (price_cents >= 0),
  CONSTRAINT plan_versions_currency_v1_check CHECK (currency IN ('USD')),
  CONSTRAINT plan_versions_interval_v1_check CHECK (billing_interval IN ('month', 'year')),
  CONSTRAINT plan_versions_lease_block_positive CHECK (lease_block >= 1),
  -- The template is an object whose keys all belong to the closed set; `object - keys` leaves nothing exactly then.
  CONSTRAINT plan_versions_template_keys_v1_check CHECK (
    CASE WHEN jsonb_typeof(entitlement_template) = 'object'
         THEN (entitlement_template - ARRAY[
                 'mcp.billable_operations.per_period', 'mcp.billable_operations.credit',
                 'mcp.billable_operations.emergency', 'storage.retained_bytes',
                 'feature.cloud_intelligence', 'feature.byok']::text[]) = '{}'::jsonb
         ELSE false END),
  -- The provider mapping is an object keyed by billing-provider mode.
  CONSTRAINT plan_versions_provider_modes_v1_check CHECK (
    CASE WHEN jsonb_typeof(provider_product_ref) = 'object'
         THEN (provider_product_ref - ARRAY['fake', 'test', 'live']::text[]) = '{}'::jsonb
         ELSE false END),
  CONSTRAINT plan_versions_lifecycle CHECK (
    retired_at IS NULL OR (valid_from IS NOT NULL AND retired_at > valid_from))
);

COMMENT ON TABLE control.plan_versions IS
  'M04 D2: one immutable commercial version of a plan (price, currency, interval, entitlement template, lease block). '
  'valid_from NULL is a draft. A subscription pins plan_version_id (grandfathering). Written only by '
  'control.publish_plan_version; trigger plan_versions_pin refuses every other change.';
COMMENT ON COLUMN control.plan_versions.entitlement_template IS
  'M04 D3: feature key -> value, keys from the closed set above (crates/domain/src/plan.rs EntitlementKey). The '
  'entitlement projector turns the PLAN grant of a subscription into the snapshot from this object.';
COMMENT ON COLUMN control.plan_versions.provider_product_ref IS
  'M04 D8: billing-provider product reference per mode (fake, test, live). Mapping only: it carries no price or limit.';

-- Invoker rights, like 0245's snapshot trigger: it only inspects OLD and NEW, firing needs no EXECUTE.
CREATE FUNCTION control.plan_versions_pin() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'a plan version is never removed: retire it' USING ERRCODE = '23514';
  END IF;
  IF ROW(NEW.plan_version_id, NEW.plan_id, NEW.version, NEW.price_cents, NEW.currency, NEW.billing_interval,
         NEW.entitlement_template, NEW.lease_block)
     IS DISTINCT FROM
     ROW(OLD.plan_version_id, OLD.plan_id, OLD.version, OLD.price_cents, OLD.currency, OLD.billing_interval,
         OLD.entitlement_template, OLD.lease_block) THEN
    RAISE EXCEPTION 'a pinned plan version never changes: publish a new version number' USING ERRCODE = '23514';
  END IF;
  IF OLD.valid_from IS NOT NULL AND NEW.valid_from IS DISTINCT FROM OLD.valid_from THEN
    RAISE EXCEPTION 'valid_from is set once' USING ERRCODE = '23514';
  END IF;
  IF OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at THEN
    RAISE EXCEPTION 'retired_at is set once' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
ALTER FUNCTION control.plan_versions_pin() OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION control.plan_versions_pin() FROM PUBLIC;
CREATE TRIGGER plan_versions_pin BEFORE UPDATE OR DELETE ON control.plan_versions
FOR EACH ROW EXECUTE FUNCTION control.plan_versions_pin();

-- The one writer. A version that does not exist yet is inserted (a draft unless p_published); one that exists must carry
-- exactly the price, currency, interval, template and lease block asked for, else 23505 ("plan version content
-- conflict"): a pinned version is never edited, a new number is published instead. What a repeat call may still do is
-- publish a draft (never the reverse) and replace the provider mapping. Returns the version and whether this call
-- created it.
CREATE FUNCTION control.publish_plan_version(
  p_plan_key text,
  p_version integer,
  p_price_cents bigint,
  p_currency text,
  p_billing_interval text,
  p_entitlement_template jsonb,
  p_lease_block integer,
  p_provider_product_ref jsonb,
  p_published boolean
) RETURNS TABLE (out_plan_version_id uuid, out_created boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_plan_id uuid;
  v_new_id uuid;
  v_row control.plan_versions;
BEGIN
  IF p_plan_key IS NULL OR p_version IS NULL OR p_price_cents IS NULL OR p_currency IS NULL
     OR p_billing_interval IS NULL OR p_entitlement_template IS NULL OR p_lease_block IS NULL
     OR p_provider_product_ref IS NULL OR p_published IS NULL THEN
    RAISE EXCEPTION 'invalid plan version request' USING ERRCODE = '22023';
  END IF;
  -- One writer per (plan, version): the read-compare-write below runs under this lock.
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('plan-version:' || p_plan_key || ':' || p_version::text, 0));

  INSERT INTO control.plans (plan_key) VALUES (p_plan_key) ON CONFLICT (plan_key) DO NOTHING;
  SELECT p.plan_id INTO v_plan_id FROM control.plans p WHERE p.plan_key = p_plan_key;

  INSERT INTO control.plan_versions AS v
    (plan_id, version, price_cents, currency, billing_interval, entitlement_template, lease_block,
     provider_product_ref, valid_from)
  VALUES
    (v_plan_id, p_version, p_price_cents, p_currency, p_billing_interval, p_entitlement_template, p_lease_block,
     p_provider_product_ref, CASE WHEN p_published THEN pg_catalog.now() END)
  ON CONFLICT (plan_id, version) DO NOTHING
  RETURNING v.plan_version_id INTO v_new_id;
  IF v_new_id IS NOT NULL THEN
    RETURN QUERY SELECT v_new_id, true;
    RETURN;
  END IF;

  SELECT * INTO v_row FROM control.plan_versions v WHERE v.plan_id = v_plan_id AND v.version = p_version FOR UPDATE;
  IF ROW(v_row.price_cents, v_row.currency, v_row.billing_interval, v_row.entitlement_template, v_row.lease_block)
     IS DISTINCT FROM
     ROW(p_price_cents, p_currency, p_billing_interval, p_entitlement_template, p_lease_block) THEN
    RAISE EXCEPTION 'plan version content conflict'
      USING ERRCODE = '23505', DETAIL = 'a pinned version never changes; publish a new version number';
  END IF;
  IF v_row.valid_from IS NOT NULL AND NOT p_published THEN
    RAISE EXCEPTION 'plan version content conflict'
      USING ERRCODE = '23505', DETAIL = 'a published version is never a draft again';
  END IF;
  UPDATE control.plan_versions v
     SET valid_from = CASE WHEN p_published THEN coalesce(v.valid_from, pg_catalog.now()) END,
         provider_product_ref = p_provider_product_ref
   WHERE v.plan_version_id = v_row.plan_version_id;
  RETURN QUERY SELECT v_row.plan_version_id, false;
END;
$$;

ALTER TABLE control.plans OWNER TO role_migration_owner;
ALTER TABLE control.plan_versions OWNER TO role_migration_owner;
ALTER FUNCTION control.publish_plan_version(text, integer, bigint, text, text, jsonb, integer, jsonb, boolean)
  OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION control.publish_plan_version(text, integer, bigint, text, text, jsonb, integer, jsonb, boolean)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.publish_plan_version(text, integer, bigint, text, text, jsonb, integer, jsonb, boolean)
  TO role_maintenance;

COMMENT ON FUNCTION control.publish_plan_version(text, integer, bigint, text, text, jsonb, integer, jsonb, boolean) IS
  'M04 D2: the only writer of control.plans and control.plan_versions. Inserts a version or verifies the stored one is the '
  'one asked for (23505 on any difference); a repeat call may publish a draft and replace the provider mapping. Owner '
  'definer, EXECUTE role_maintenance only.';

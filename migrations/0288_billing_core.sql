-- §71.2 / §71.3 / M04-8 (card M04-8; §46 forward-fix, EXPAND_CONTRACT, number 0288): the billing core schema. Five new
-- tables and nothing else: no door, no existing table or grant is touched, and nothing here talks to a provider.
--
--   control.billing_customers     one provider customer per tenant (M04 D1: account = tenant, no seats)
--   control.subscriptions         the local projection of the provider's subscription, one live row per tenant
--   control.subscription_events   append-only applied state changes
--   control.billing_payments      append-only provider transactions (charge, refund, chargeback)
--   control.billing_inbox         the webhook intake of §71.3, global: the tenant is unknown until the processor pairs it
--
-- Access. 0011's control-schema default grants SELECT on every NEW control table to role_gateway and to every worker, and
-- to role_maintenance (0260 closed the same hole for the credential tables), so all five tables start with a REVOKE ALL
-- from PUBLIC and from every non-owner role (the 0267 pattern for control.entitlement_grants). Then exactly one grant:
-- INSERT on control.billing_inbox to role_gateway, the consumer of contract C4 (the webhook route inserts the verified raw
-- event and answers 2xx). No runtime role reads the subscription projection or the payments (§76: entitlements come from
-- the snapshot, never from raw billing tables), and the writers of the four tenant tables arrive as owner definer doors
-- with the processor (M04-11). The four tenant tables are RLS + FORCE with the tenant policy of control.entitlement_grants.
--
-- The closed sets (provider, subscription state, payment kind, currency, inbox status) are CHECK literals compared with
-- crates/domain/src/billing.rs and crates/domain/src/plan.rs by contract test (§78.2, G-M04-14). Provider is the closed set
-- of one: Creem only (M04 D7); the fake and test modes are still Creem-shaped.

CREATE TABLE control.billing_customers (
  tenant_id             uuid        PRIMARY KEY REFERENCES control.tenants (tenant_id),
  provider              text        NOT NULL,
  provider_customer_ref text        NOT NULL,
  created_at            timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT billing_customers_provider_v1_check CHECK (provider IN ('creem')),
  CONSTRAINT billing_customers_provider_ref_unique UNIQUE (provider, provider_customer_ref)
);

COMMENT ON TABLE control.billing_customers IS
  'M04 D1: the provider customer of a tenant, 1:1 (the tenant is the account, there are no seats). Written only by an owner '
  'definer door of the billing processor (M04-11); no runtime role reads it.';

-- No cancel_at_period_end column: CANCEL_AT_PERIOD_END is a state, and two columns must not carry one fact.
CREATE TABLE control.subscriptions (
  subscription_id           uuid        PRIMARY KEY DEFAULT uuidv7(),
  tenant_id                 uuid        NOT NULL REFERENCES control.tenants (tenant_id),
  provider                  text        NOT NULL,
  provider_subscription_ref text        NOT NULL,
  plan_version_id           uuid        NOT NULL REFERENCES control.plan_versions (plan_version_id),
  state                     text        NOT NULL,
  current_period_start      timestamptz NOT NULL,
  current_period_end        timestamptz NOT NULL,
  created_at                timestamptz NOT NULL DEFAULT now(),
  updated_at                timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT subscriptions_provider_v1_check CHECK (provider IN ('creem')),
  CONSTRAINT subscriptions_state_v1_check CHECK (
    state IN ('INCOMPLETE', 'TRIALING', 'ACTIVE', 'PAST_DUE', 'GRACE', 'PAUSED', 'CANCEL_AT_PERIOD_END', 'CANCELED')),
  CONSTRAINT subscriptions_period_check CHECK (current_period_end > current_period_start),
  CONSTRAINT subscriptions_provider_ref_unique UNIQUE (provider, provider_subscription_ref),
  -- The target of subscription_events' composite foreign key, so an event can never name another tenant's subscription.
  CONSTRAINT subscriptions_tenant_subscription_unique UNIQUE (tenant_id, subscription_id)
);

-- One live subscription per account (M04 D1): any state but CANCELED occupies the tenant's slot.
CREATE UNIQUE INDEX subscriptions_one_live_per_tenant ON control.subscriptions (tenant_id) WHERE state <> 'CANCELED';

COMMENT ON TABLE control.subscriptions IS
  'M04 D7: the local projection of the provider subscription (Baseline 71.2 states), pinned to a plan version '
  '(grandfathering). Written only by the billing processor''s owner door (M04-11) from the authoritative fetch, never by '
  'a webhook handler (71.3); no runtime role reads it (76).';
COMMENT ON COLUMN control.subscriptions.state IS
  'Baseline 71.2: INCOMPLETE, TRIALING, ACTIVE, PAST_DUE, GRACE, PAUSED, CANCEL_AT_PERIOD_END, CANCELED '
  '(crates/domain/src/billing.rs SubscriptionState). CANCEL_AT_PERIOD_END is a state, so there is no boolean beside it.';

-- ponytail: no foreign key from source_provider / source_event_id to control.billing_inbox, because the raw intake may be
-- purged after processing while an applied fact must outlive it; add the key if inbox rows are kept for the life of the event.
CREATE TABLE control.subscription_events (
  subscription_event_id uuid        PRIMARY KEY DEFAULT uuidv7(),
  tenant_id             uuid        NOT NULL,
  subscription_id       uuid        NOT NULL,
  from_state            text,
  to_state              text        NOT NULL,
  source_provider       text,
  source_event_id       text,
  observed_at           timestamptz NOT NULL,
  applied_at            timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT subscription_events_subscription_fk FOREIGN KEY (tenant_id, subscription_id)
    REFERENCES control.subscriptions (tenant_id, subscription_id),
  CONSTRAINT subscription_events_from_state_v1_check CHECK (
    from_state IN ('INCOMPLETE', 'TRIALING', 'ACTIVE', 'PAST_DUE', 'GRACE', 'PAUSED', 'CANCEL_AT_PERIOD_END', 'CANCELED')),
  CONSTRAINT subscription_events_to_state_v1_check CHECK (
    to_state IN ('INCOMPLETE', 'TRIALING', 'ACTIVE', 'PAST_DUE', 'GRACE', 'PAUSED', 'CANCEL_AT_PERIOD_END', 'CANCELED')),
  CONSTRAINT subscription_events_source_provider_v1_check CHECK (source_provider IN ('creem')),
  -- The inbox key it came from: both parts or neither (a state change the reconciliation made has no inbox event).
  CONSTRAINT subscription_events_source_pair_check CHECK ((source_provider IS NULL) = (source_event_id IS NULL))
);

COMMENT ON TABLE control.subscription_events IS
  'M04 D7: append-only applied facts, one row per state change of a subscription (from_state NULL on the first). '
  'source_provider + source_event_id name the inbox event it came from, NULL when reconciliation applied it. '
  'control.subscription_events_reject_mutation refuses UPDATE and DELETE.';

CREATE TABLE control.billing_payments (
  payment_id       uuid        PRIMARY KEY DEFAULT uuidv7(),
  tenant_id        uuid        NOT NULL REFERENCES control.tenants (tenant_id),
  provider         text        NOT NULL,
  provider_txn_ref text        NOT NULL,
  kind             text        NOT NULL,
  amount_cents     bigint      NOT NULL,
  currency         text        NOT NULL,
  period_start     timestamptz NOT NULL,
  period_end       timestamptz NOT NULL,
  occurred_at      timestamptz NOT NULL,
  recorded_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT billing_payments_provider_v1_check CHECK (provider IN ('creem')),
  CONSTRAINT billing_payments_kind_v1_check CHECK (kind IN ('CHARGE', 'REFUND', 'CHARGEBACK')),
  CONSTRAINT billing_payments_amount_nonnegative CHECK (amount_cents >= 0),
  -- The currency set of control.plan_versions (0262): a payment is stated in a currency a plan can be priced in.
  CONSTRAINT billing_payments_currency_v1_check CHECK (currency IN ('USD')),
  CONSTRAINT billing_payments_txn_unique UNIQUE (provider, provider_txn_ref, kind)
);

COMMENT ON TABLE control.billing_payments IS
  'M04 D7: append-only provider transactions. A refund or chargeback of the current period is the fact that downgrades '
  'immediately (owner answer Q4); the amount is unsigned and the kind says the direction. '
  'control.billing_payments_reject_mutation refuses UPDATE and DELETE.';

-- The §71.3 DDL verbatim, plus the processing status and the provider closed set.
-- ponytail: error_class stays free text: its writer and its vocabulary are the processor's (M04-11); close it with a CHECK
-- in the migration that lands the processor.
CREATE TABLE control.billing_inbox (
    provider text NOT NULL,
    event_id text NOT NULL,
    event_type text NOT NULL,
    api_version text,
    object_id text,
    payload jsonb NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    processed_at timestamptz,
    status text NOT NULL DEFAULT 'RECEIVED',
    error_class text,
    PRIMARY KEY (provider, event_id),
    CONSTRAINT billing_inbox_provider_v1_check CHECK (provider IN ('creem')),
    CONSTRAINT billing_inbox_status_v1_check CHECK (status IN ('RECEIVED', 'PROCESSED', 'FAILED'))
);

COMMENT ON TABLE control.billing_inbox IS
  'Baseline 71.3: the webhook intake. The primary key (provider, event_id) is the duplicate guard, so a redelivery stores '
  'nothing. Global (no tenant_id): the tenant is unknown until the processor pairs the event (M04-11). role_gateway '
  'holds INSERT and nothing else (contract C4); the processor reads and settles rows as an owner definer.';

-- Append-only, also against the owner (the 0032 credit_ledger_reject_mutation pattern): the owner role would otherwise
-- keep its implicit UPDATE and DELETE on its own tables.
CREATE FUNCTION control.subscription_events_reject_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION 'control.subscription_events is append-only (71.3) - % not permitted', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$;
CREATE TRIGGER subscription_events_reject_mutation BEFORE UPDATE OR DELETE ON control.subscription_events
FOR EACH ROW EXECUTE FUNCTION control.subscription_events_reject_mutation();

CREATE FUNCTION control.billing_payments_reject_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION 'control.billing_payments is append-only (71.3) - % not permitted', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$;
CREATE TRIGGER billing_payments_reject_mutation BEFORE UPDATE OR DELETE ON control.billing_payments
FOR EACH ROW EXECUTE FUNCTION control.billing_payments_reject_mutation();

-- A FOR EACH ROW trigger never fires on TRUNCATE (the 0101 credit_ledger defect), and no foreign key points at either
-- table, so a plain TRUNCATE would empty them. Both functions RAISE without touching OLD/NEW, so they serve the
-- statement-level guard unchanged.
CREATE TRIGGER subscription_events_reject_truncate BEFORE TRUNCATE ON control.subscription_events
FOR EACH STATEMENT EXECUTE FUNCTION control.subscription_events_reject_mutation();
CREATE TRIGGER billing_payments_reject_truncate BEFORE TRUNCATE ON control.billing_payments
FOR EACH STATEMENT EXECUTE FUNCTION control.billing_payments_reject_mutation();

ALTER TABLE control.billing_customers OWNER TO role_migration_owner;
ALTER TABLE control.subscriptions OWNER TO role_migration_owner;
ALTER TABLE control.subscription_events OWNER TO role_migration_owner;
ALTER TABLE control.billing_payments OWNER TO role_migration_owner;
ALTER TABLE control.billing_inbox OWNER TO role_migration_owner;
ALTER FUNCTION control.subscription_events_reject_mutation() OWNER TO role_migration_owner;
ALTER FUNCTION control.billing_payments_reject_mutation() OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION control.subscription_events_reject_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION control.billing_payments_reject_mutation() FROM PUBLIC;

-- RLS + FORCE on the four tenant tables, the policy shape of control.entitlement_grants (0033).
ALTER TABLE control.billing_customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE control.billing_customers FORCE ROW LEVEL SECURITY;
CREATE POLICY billing_customers_tenant_isolation ON control.billing_customers
USING (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid)
WITH CHECK (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid);

ALTER TABLE control.subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE control.subscriptions FORCE ROW LEVEL SECURITY;
CREATE POLICY subscriptions_tenant_isolation ON control.subscriptions
USING (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid)
WITH CHECK (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid);

ALTER TABLE control.subscription_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE control.subscription_events FORCE ROW LEVEL SECURITY;
CREATE POLICY subscription_events_tenant_isolation ON control.subscription_events
USING (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid)
WITH CHECK (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid);

ALTER TABLE control.billing_payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE control.billing_payments FORCE ROW LEVEL SECURITY;
CREATE POLICY billing_payments_tenant_isolation ON control.billing_payments
USING (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid)
WITH CHECK (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid);

REVOKE ALL ON TABLE
  control.billing_customers,
  control.subscriptions,
  control.subscription_events,
  control.billing_payments,
  control.billing_inbox
FROM
  PUBLIC,
  role_gateway,
  role_private_worker,
  role_consolidation_worker,
  role_public_worker,
  role_retrieval_worker,
  role_batch_issuer,
  role_admin,
  role_maintenance,
  role_health_reader;

-- The one grant: the webhook route (contract C4) inserts the verified raw event. INSERT only: billing_repo::inbox_insert
-- writes ON CONFLICT DO NOTHING without a conflict target and without RETURNING, so it never needs SELECT.
GRANT INSERT ON TABLE control.billing_inbox TO role_gateway;

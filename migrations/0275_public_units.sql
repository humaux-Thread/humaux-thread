-- §12.6 / ADR-0089 D-B / ADR-0090 D-B: additive phase-one unit revisions, M20-7.
CREATE TABLE public.units (
  unit_id uuid PRIMARY KEY DEFAULT uuidv7(),
  unit_type text NOT NULL CONSTRAINT units_type_check
    CHECK (unit_type IN ('FIX','DECISION','RESEARCH','USAGE','CHECKLIST','FAILURE_CASE')),
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.syntheses ADD COLUMN unit_id uuid REFERENCES public.units(unit_id);
CREATE TABLE public.unit_fields (
  revision_id uuid NOT NULL REFERENCES public.syntheses(synthesis_id),
  field_key text NOT NULL,
  state text NOT NULL CONSTRAINT unit_fields_state_check CHECK (state IN ('KNOWN','UNKNOWN','NOT_APPLICABLE')),
  value jsonb,
  reason text,
  assist text NOT NULL CONSTRAINT unit_fields_assist_check CHECK (assist IN ('RULE','MODEL','CONTRIBUTOR')),
  PRIMARY KEY (revision_id, field_key),
  CONSTRAINT unit_fields_value_check CHECK ((state = 'KNOWN') = (value IS NOT NULL)),
  CONSTRAINT unit_fields_result_assist_check CHECK (field_key <> 'result' OR assist <> 'MODEL'),
  CONSTRAINT unit_fields_result_check CHECK (field_key <> 'result' OR
    (state = 'KNOWN' AND value IN ('"UNKNOWN"'::jsonb,'"SUCCESS"'::jsonb,'"PARTIAL"'::jsonb,'"FAILED"'::jsonb)))
);
CREATE TABLE public.unit_conditions (
  revision_id uuid NOT NULL REFERENCES public.syntheses(synthesis_id),
  entity_id uuid NOT NULL,
  version_range text,
  platform text,
  constraint_key text NOT NULL,
  value jsonb NOT NULL,
  PRIMARY KEY (revision_id, entity_id, constraint_key)
);
-- §6.2.2: unreleased drafts have no serving-role read grant; M20-12 owns serving.
REVOKE ALL ON public.units, public.unit_fields, public.unit_conditions FROM PUBLIC,
  role_gateway, role_private_worker, role_consolidation_worker, role_public_worker,
  role_retrieval_worker, role_batch_issuer, role_maintenance, role_admin, role_health_reader;
ALTER TABLE public.units OWNER TO role_migration_owner;
ALTER TABLE public.unit_fields OWNER TO role_migration_owner;
ALTER TABLE public.unit_conditions OWNER TO role_migration_owner;
GRANT SELECT, INSERT, UPDATE ON public.units, public.unit_fields, public.unit_conditions TO role_public_worker;

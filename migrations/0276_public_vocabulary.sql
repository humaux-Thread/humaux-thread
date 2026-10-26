-- §12.3 / ADR-0089 D-E: public controlled vocabulary; no private identities or serving grants.
CREATE TABLE public.concepts (
  concept_id text PRIMARY KEY CHECK (concept_id ~ '^[a-z][a-z0-9]*([-_][a-z0-9]+)*$'),
  facet text NOT NULL CONSTRAINT concepts_facet_check CHECK (facet IN ('domain','task','project_type','industry','knowledge_type','content_language')),
  status text NOT NULL CONSTRAINT concepts_status_check CHECK (status IN ('ACTIVE','DEPRECATED')),
  replaced_by text REFERENCES public.concepts(concept_id) DEFERRABLE INITIALLY DEFERRED,
  definition text NOT NULL CHECK (length(btrim(definition)) > 0),
  UNIQUE (concept_id,facet),
  CHECK ((status='DEPRECATED' AND replaced_by IS NOT NULL AND replaced_by<>concept_id)
      OR (status='ACTIVE' AND replaced_by IS NULL))
);
CREATE TABLE public.concept_labels (
  concept_id text NOT NULL,
  -- §12.3: composite FK prevents helper facet drift, including direct worker writes.
  facet text NOT NULL,
  lang text NOT NULL CHECK (length(btrim(lang)) > 0),
  kind text NOT NULL CONSTRAINT concept_labels_kind_check CHECK (kind IN ('PREF','ALT')),
  label text NOT NULL CHECK (length(btrim(label)) > 0),
  PRIMARY KEY (concept_id,lang,kind,label),
  FOREIGN KEY (concept_id,facet) REFERENCES public.concepts(concept_id,facet)
);
CREATE UNIQUE INDEX concept_labels_one_pref ON public.concept_labels(concept_id,lang) WHERE kind='PREF';
CREATE UNIQUE INDEX concept_labels_facet_unique ON public.concept_labels(facet,lang,lower(label));
CREATE TABLE public.concept_relations (
  from_id text NOT NULL REFERENCES public.concepts(concept_id),
  to_id text NOT NULL REFERENCES public.concepts(concept_id),
  kind text NOT NULL CONSTRAINT concept_relations_kind_check CHECK (kind IN ('BROADER','RELATED','CLOSE_MATCH','EXACT_MATCH')),
  PRIMARY KEY (from_id,to_id,kind),
  CHECK (from_id<>to_id)
);
ALTER TABLE public.concepts OWNER TO role_migration_owner;
ALTER TABLE public.concept_labels OWNER TO role_migration_owner;
ALTER TABLE public.concept_relations OWNER TO role_migration_owner;
REVOKE ALL ON public.concepts, public.concept_labels, public.concept_relations FROM PUBLIC,
  role_gateway, role_private_worker, role_consolidation_worker, role_public_worker,
  role_retrieval_worker, role_batch_issuer, role_maintenance, role_admin;
GRANT SELECT, INSERT, UPDATE ON public.concepts, public.concept_labels, public.concept_relations TO role_public_worker;
-- §12.3: BROADER facet/DAG and active replacement checks run in the loader AND G-M20-16.

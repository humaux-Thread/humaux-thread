-- ADR-0098 D1 / Baseline §8.2, §8.7 (card M06-1a; §46 forward-fix, EXPAND_CONTRACT): the source identity of an Evidence
-- an agent relayed from an email, chat, calendar item or conversation. M06-1a only records it; the dedupe that reads it
-- is M06-1b.
--
-- Invariants:
--   ① the key is (tenant, owner user, source kind, object-key digest, version). It carries no agent, no ingest time and
--     no project (ADR-0098 D1); the UNIQUE below is the backstop of 1b's advisory lock.
--   ② object_key_d16 / thread_key_d16 are the first 16 bytes of SHA-256 of the raw external key; no raw key or message id
--     is stored (a PII-free uniqueness index). source_version is '' when the caller sent none, so the key has no NULL.
--   ③ source_kind is the smallint of humaux_domain::source::IngestSourceKind (1..6); the Rust half is reconciled by
--     adapters::tests::evidence_sources (§78.2).
--   ④ FORCE RLS on tenant AND owner: owner_user_id = the humaux.user_id GUC. A user-less (nil-UUID) write cannot satisfy
--     WITH CHECK because no row is owned by the nil user (the writer refuses a headless sourced write first).
--   ⑤ one row per Evidence (PK tenant_id, evidence_id); the composite FK carries the tenant leg and cascades, so the row
--     leaves with its Evidence in the §37 plan. Nobody holds UPDATE or DELETE.
--
-- Locks: CREATE TABLE's FK takes SHARE ROW EXCLUSIVE on private.evidence_objects until COMMIT, which blocks Evidence
-- INSERTs for the rest of this migration's transaction; the table is new and empty, so the indexes build instantly.

CREATE TABLE private.evidence_sources (
  tenant_id       uuid     NOT NULL,
  owner_user_id   uuid     NOT NULL,
  source_kind     smallint NOT NULL CONSTRAINT evidence_sources_source_kind_check
    CHECK (source_kind IN (1, 2, 3, 4, 5, 6)),
  object_key_d16  bytea    NOT NULL CONSTRAINT evidence_sources_object_key_len CHECK (octet_length(object_key_d16) = 16),
  source_version  text     NOT NULL DEFAULT '' CONSTRAINT evidence_sources_version_len CHECK (char_length(source_version) <= 64),
  thread_key_d16  bytea    NULL CONSTRAINT evidence_sources_thread_key_len CHECK (octet_length(thread_key_d16) = 16),
  evidence_id     uuid     NOT NULL,
  payload_sha256  bytea    NOT NULL CONSTRAINT evidence_sources_payload_len CHECK (octet_length(payload_sha256) = 32),
  CONSTRAINT evidence_sources_pkey PRIMARY KEY (tenant_id, evidence_id),
  CONSTRAINT evidence_sources_identity_key
    UNIQUE (tenant_id, owner_user_id, source_kind, object_key_d16, source_version),
  CONSTRAINT evidence_sources_evidence_fkey FOREIGN KEY (tenant_id, evidence_id)
    REFERENCES private.evidence_objects (tenant_id, evidence_id) ON DELETE CASCADE
);

CREATE INDEX evidence_sources_thread_idx ON private.evidence_sources (tenant_id, owner_user_id, thread_key_d16)
  WHERE thread_key_d16 IS NOT NULL;

ALTER TABLE private.evidence_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.evidence_sources FORCE ROW LEVEL SECURITY;
CREATE POLICY evidence_sources_tenant_and_owner ON private.evidence_sources
  USING (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid
         AND owner_user_id = NULLIF(current_setting('humaux.user_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid
         AND owner_user_id = NULLIF(current_setting('humaux.user_id', true), '')::uuid);

-- Owner + NAMED §6.2.2 grants: the gateway writes (INSERT) and reads; maintenance reads; nobody holds UPDATE or DELETE.
ALTER TABLE private.evidence_sources OWNER TO role_migration_owner;
REVOKE ALL ON private.evidence_sources FROM PUBLIC, role_gateway, role_private_worker, role_consolidation_worker,
  role_public_worker, role_retrieval_worker, role_batch_issuer, role_maintenance, role_admin;
GRANT SELECT, INSERT ON private.evidence_sources TO role_gateway;
GRANT SELECT ON private.evidence_sources TO role_maintenance;

COMMENT ON TABLE private.evidence_sources IS
  'ADR-0098 D1: source identity of a relayed Evidence, key (tenant, owner user, source_kind, object_key_d16, source_version); 16-byte SHA-256 prefixes, never raw keys. Written with the Evidence by adapters::remember::remember_sourced_in_txn. M06-1a.';

-- §6.1.3 / ADR-0078 D-B (card M29 T02; §46 forward-fix, EXPAND_CONTRACT, first free number after 0246): the closed
-- SubjectKind set gains BUSINESS, BRAND, PRODUCT and WEBSITE. Expand only: private.subjects.kind keeps its single
-- text CHECK (0153), now a strict superset of the old one, so every existing row (PERSON / ORGANISATION) still passes
-- and no row is rewritten. humaux_domain::subject::SubjectKind carries the same six wire strings (§78.2 contract test:
-- adapters::tests::subject_registry_rls::subject_checks_match_domain_enums).
--
-- Deliberately NOT added (ADR-0078 D-B, Q2 ruling): CHANNEL_ACCOUNT and PRODUCT_LINE wait for experiment E-C; a
-- repository is never a subject (control.repositories). No subject_keys.key_kind is added (Q4 ruling).
--
-- Rollout order: migrate first, then deploy. A binary older than this change never writes a new kind (its
-- SubjectKind::parse refuses it as INVALID_INPUT), but it reads a new-kind row as INTERNAL, so do not roll binaries
-- back below this change once such a row exists.
--
-- Locks: DROP + ADD in one ALTER TABLE (no window without a kind CHECK); the ADD is NOT VALID, so the table scan
-- happens in VALIDATE CONSTRAINT under SHARE UPDATE EXCLUSIVE (the 0099 two-step).
ALTER TABLE private.subjects
  DROP CONSTRAINT subjects_kind_check,
  ADD CONSTRAINT subjects_kind_check
    CHECK (kind IN ('PERSON', 'ORGANISATION', 'BUSINESS', 'BRAND', 'PRODUCT', 'WEBSITE', 'CHANNEL_ACCOUNT')) NOT VALID;
ALTER TABLE private.subjects VALIDATE CONSTRAINT subjects_kind_check;

COMMENT ON TABLE private.subjects IS
  '§6.1.3 aboutness anchor: a Person, Organisation, Business, Brand, Product or Website a memory can be about. '
  'Tenant-scoped, closed SubjectKind (ADR-0078 D-B), self-FK merged_into for de-dup. ADR-0027, card 7.';

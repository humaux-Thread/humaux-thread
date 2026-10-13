-- §46 forward-fix (EXPAND_CONTRACT, first free number after 0238). ADR-0068 D-A (card 40d-1b-ii): the projection
-- worker plans a Memory as note chunks only when it is the output of an identity contract, so role_retrieval_worker
-- reads private.identity_note_materializations — in the same statement that resolves the ticket's Memories, never one
-- query per Memory.
--
-- SELECT only, to role_retrieval_worker only. The 0235 FORCE RLS policy is unchanged: the tenant GUC (which the worker
-- sets on every transaction) and the parent Evidence's visibility, which the worker already reads through 0140's arm
-- of private.evidence_objects. No row is written; nobody gains INSERT / UPDATE / DELETE.
--
-- Locks: a GRANT takes a brief lock on the table's catalog row; no data is touched.

GRANT SELECT ON private.identity_note_materializations TO role_retrieval_worker;

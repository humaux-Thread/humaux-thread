-- §46 forward-fix (EXPAND_CONTRACT, first free number after 0240). ADR-0068 D-E / D-I (card 40d-1c-ii): recall groups
-- its dense candidates by Memory exactly when the serving projection's note chunk policy names a profile, so
-- role_gateway reads projection.card_profile_policies — the same migration-written row the projection worker chunks by
-- and the ledger definer counts by. One switch: chunking and grouped recall cannot be enabled apart.
--
-- SELECT only, to role_gateway only. The table has no tenant column and no RLS (0238: global config, the
-- embedding_fingerprints precedent); nobody gains INSERT / UPDATE / DELETE — the row stays migration-written (§78.1).
--
-- Locks: a GRANT takes a brief lock on the table's catalog row; no data is touched.

GRANT SELECT ON projection.card_profile_policies TO role_gateway;

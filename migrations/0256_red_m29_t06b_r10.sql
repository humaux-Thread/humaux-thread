-- §80.1 red record only (branch red/m29-t06b-r10, never merged): an extra EXECUTE grantee on the relation-correction revocation definer.
GRANT EXECUTE ON FUNCTION private.revoke_attributions_on_relation_correction() TO role_admin;

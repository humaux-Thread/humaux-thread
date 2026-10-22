-- §46 EXPAND_CONTRACT (card M02-1; audit SEC-1; Baseline §6.2.1, §6.2.2, §73.5, §73.6, §74, §75.1). Eight control tables
-- hold the verifier of a credential. They were created by 0032 / 0035 / 0037 and took 0011's `control.*` domain default,
-- SELECT for every non-owner role, so a compromised private, consolidation, public or retrieval worker could read every
-- API-key HMAC, session token hash, one-time-code hash, Argon2id password hash, recovery-code hash and invitation token hash
-- (0040's header already names the session case). The audit kept SEC-1 at P2 because the tables were empty and no writer
-- existed; M02 puts writers on them (login, session, OAuth), so the read path is closed first.
--
--   control.api_keys                  key_hash (HMAC-SHA256 verifier, §73.5)
--   control.sessions                  token_hash (bearer verifier of the session cookie, §73.6)
--   control.email_challenges          code_hash (signup one-time code, §74.2)
--   control.password_reset_challenges code_hash (§74.4)
--   control.email_change_requests     code_hash (§74.5)
--   control.password_credentials      password_hash (Argon2id, §74.3)
--   control.recovery_codes            code_hash (§74)
--   control.team_invitations          token_hash (invitation bearer, §75.1)
--
-- Result: role_gateway and role_maintenance keep exactly the SELECT they hold today (no grant is added, widened or moved);
-- every other role, PUBLIC included, ends with nothing on these eight tables, table-level or column-level. No Rust code in
-- the workspace names any of them; the only SQL that reads or writes them is owner SECURITY DEFINER (0039, 0111, 0186, 0188,
-- 0202, 0203), which keeps working because the owner is untouched.
--
-- Not changed, on purpose:
--   * 0011's ALTER DEFAULT PRIVILEGES. The `control.*` domain default still holds for every other control table, so a NEW
--     table that holds a verifier inherits worker SELECT until its own migration revokes it and names it in
--     maintenance::rls_check (a cell for role_gateway and role_maintenance, §6.2.2). M02-8 does that for the OAuth tables.
--   * control.credentials (openbao_ref is a locator, never secret bytes, 0003), control.webauthn_credentials (public key),
--     control.authenticators, control.identity_connections, control.user_emails, control.auth_events and
--     control.referral_codes: none holds a verifier.
--   * role_maintenance's SELECT. The onboarding doors run with owner rights, so it may not need the table grant at all;
--     narrowing it is a separate decision, not part of closing the worker read path.
--
-- No DML, no table, policy, trigger or function altered. Locks: none beyond the pg_class ACL rows of the eight tables.

REVOKE ALL ON TABLE
  control.api_keys,
  control.sessions,
  control.email_challenges,
  control.password_reset_challenges,
  control.email_change_requests,
  control.password_credentials,
  control.recovery_codes,
  control.team_invitations
FROM
  PUBLIC,
  role_private_worker,
  role_consolidation_worker,
  role_public_worker,
  role_retrieval_worker,
  role_batch_issuer,
  role_admin;

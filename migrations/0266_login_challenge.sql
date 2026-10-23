-- §46 forward-fix (EXPAND_CONTRACT, M02-5): the passwordless login challenge (M02 D2, §74.2). No new table:
--   control.email_challenges  gains purpose text ('SIGNUP' | 'LOGIN'), default 'SIGNUP' so the existing signup rows keep
--                             their meaning; a login code is one row of the same shape (keyed hash, attempts, expiry,
--                             consumed_at) and shares 0260's grants (SELECT for role_gateway and role_maintenance only).
--   control.auth_events       event_type CHECK gains LOGIN_CODE_SENT.
--
-- Nothing in the application can write either table: role_gateway holds SELECT only (0011 domain default, 0260). Three
-- owner SECURITY DEFINER doors are the whole write path, EXECUTE role_gateway only, PUBLIC and every other role refused:
--   control.login_challenge_issue   look up the mailbox, apply the resend cooldown, supersede earlier LOGIN codes, store
--                                   the new keyed hash, record LOGIN_CODE_SENT. Returns no row for an unknown or
--                                   non-loginable mailbox, so the caller can answer both cases identically.
--   control.login_challenge_claim   the latest LOGIN row of a mailbox: id and stored hash only, read-only. The code
--                                   compare happens in Rust (constant time), never in SQL.
--   control.login_challenge_settle  one conditional UPDATE: counts the attempt and consumes the row on a match, only
--                                   while consumed_at IS NULL, unexpired and attempts < max_attempts. Two concurrent
--                                   verifies of the same code serialize on the row; the loser re-evaluates the predicate
--                                   after the winner commits and updates nothing. Records LOGIN_SUCCESS or LOGIN_FAILURE.
--
-- Trust assumption: the compare is done by the caller (constant time, keyed hash), so settle takes the match result as an
-- argument. Only role_gateway may call it and it must first learn a challenge id from claim; a compromised gateway could
-- therefore settle a challenge as matched, which it could equally do by minting a session itself (§73.6).
--
-- TTL, attempt cap and cooldown are arguments, never literals: the caller passes the §78.1 policy values.
-- The code or its hash never reaches auth_events.metadata (§77).

ALTER TABLE control.email_challenges
  ADD COLUMN purpose text NOT NULL DEFAULT 'SIGNUP' CHECK (purpose IN ('SIGNUP', 'LOGIN'));

COMMENT ON COLUMN control.email_challenges.purpose IS
  'M02-5: which flow issued the code. SIGNUP (§74.2) or LOGIN (passwordless sign-in, M02 D2); closed set, mirrored by adapters::login_repo / application::login::ChallengePurpose (§78.2).';

ALTER TABLE control.auth_events DROP CONSTRAINT auth_events_event_type_check;
ALTER TABLE control.auth_events ADD CONSTRAINT auth_events_event_type_check CHECK (event_type IN (
  'SIGNUP_STARTED', 'EMAIL_CHALLENGE_SENT', 'EMAIL_VERIFIED', 'ACCOUNT_ACTIVATED',
  'LOGIN_SUCCESS', 'LOGIN_FAILURE',
  'PASSWORD_RESET_REQUESTED', 'PASSWORD_RESET_COMPLETED',
  'EMAIL_CHANGE_REQUESTED', 'EMAIL_CHANGE_COMPLETED',
  'LOGIN_CODE_SENT'));

CREATE FUNCTION control.login_challenge_issue(
  p_canonical_email text,
  p_code_hash text,
  p_ttl_seconds integer,
  p_max_attempts integer,
  p_cooldown_seconds integer
)
RETURNS TABLE (out_challenge_id uuid, out_user_id uuid, out_issued boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_user_id uuid;
  v_email_id uuid;
  v_challenge_id uuid;
BEGIN
  IF p_ttl_seconds <= 0 OR p_max_attempts <= 0 OR p_cooldown_seconds < 0 THEN
    RAISE EXCEPTION 'login challenge policy out of range' USING ERRCODE = '22023';
  END IF;

  SELECT e.user_email_id, e.user_id INTO v_email_id, v_user_id
    FROM control.user_emails e
    JOIN control.users u ON u.user_id = e.user_id
   WHERE e.canonical_email = p_canonical_email
     AND u.state IN ('PENDING_VERIFICATION', 'ACTIVE');
  IF NOT FOUND THEN
    RETURN;
  END IF;

  -- One issue per mailbox at a time, so the cooldown check and the insert cannot interleave.
  PERFORM pg_advisory_xact_lock(hashtextextended('login_challenge:' || p_canonical_email, 0));

  IF EXISTS (
    SELECT 1 FROM control.email_challenges c
     WHERE c.user_email_id = v_email_id AND c.purpose = 'LOGIN'
       AND c.created_at > now() - make_interval(secs => p_cooldown_seconds)
  ) THEN
    RETURN QUERY SELECT NULL::uuid, v_user_id, false;
    RETURN;
  END IF;

  -- Only the newest code is valid: earlier unconsumed LOGIN codes are retired.
  UPDATE control.email_challenges c SET consumed_at = now()
   WHERE c.user_email_id = v_email_id AND c.purpose = 'LOGIN' AND c.consumed_at IS NULL;

  INSERT INTO control.email_challenges (user_id, user_email_id, code_hash, max_attempts, expires_at, purpose)
  VALUES (v_user_id, v_email_id, p_code_hash, p_max_attempts, now() + make_interval(secs => p_ttl_seconds), 'LOGIN')
  RETURNING challenge_id INTO v_challenge_id;

  INSERT INTO control.auth_events (user_id, event_type) VALUES (v_user_id, 'LOGIN_CODE_SENT');

  RETURN QUERY SELECT v_challenge_id, v_user_id, true;
END;
$$;

CREATE FUNCTION control.login_challenge_claim(p_canonical_email text)
RETURNS TABLE (out_challenge_id uuid, out_code_hash text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT c.challenge_id, c.code_hash
    FROM control.user_emails e
    JOIN control.email_challenges c ON c.user_email_id = e.user_email_id
   WHERE e.canonical_email = p_canonical_email AND c.purpose = 'LOGIN'
   ORDER BY c.created_at DESC
   LIMIT 1;
$$;

CREATE FUNCTION control.login_challenge_settle(p_challenge_id uuid, p_code_matched boolean)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_user_id uuid;
BEGIN
  UPDATE control.email_challenges c
     SET attempts = c.attempts + 1,
         consumed_at = CASE WHEN p_code_matched THEN now() ELSE NULL END
   WHERE c.challenge_id = p_challenge_id
     AND c.purpose = 'LOGIN'
     AND c.consumed_at IS NULL
     AND c.expires_at > now()
     AND c.attempts < c.max_attempts
  RETURNING c.user_id INTO v_user_id;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  INSERT INTO control.auth_events (user_id, event_type)
  VALUES (v_user_id, CASE WHEN p_code_matched THEN 'LOGIN_SUCCESS' ELSE 'LOGIN_FAILURE' END);
  RETURN CASE WHEN p_code_matched THEN v_user_id ELSE NULL END;
END;
$$;

ALTER FUNCTION control.login_challenge_issue(text, text, integer, integer, integer) OWNER TO role_migration_owner;
ALTER FUNCTION control.login_challenge_claim(text) OWNER TO role_migration_owner;
ALTER FUNCTION control.login_challenge_settle(uuid, boolean) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION control.login_challenge_issue(text, text, integer, integer, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.login_challenge_claim(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.login_challenge_settle(uuid, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.login_challenge_issue(text, text, integer, integer, integer) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.login_challenge_claim(text) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.login_challenge_settle(uuid, boolean) TO role_gateway;

COMMENT ON FUNCTION control.login_challenge_issue(text, text, integer, integer, integer) IS
  'M02-5 / §74.2: stores a keyed code hash for a loginable mailbox (cooldown, supersede, LOGIN_CODE_SENT). No row = unknown mailbox.';
COMMENT ON FUNCTION control.login_challenge_claim(text) IS
  'M02-5: latest LOGIN challenge id and stored keyed hash of a mailbox; the compare is done by the caller in constant time.';
COMMENT ON FUNCTION control.login_challenge_settle(uuid, boolean) IS
  'M02-5 / §74.2: the single consume-or-count UPDATE; the user id only when a matching code consumed a live row in this statement, else NULL.';

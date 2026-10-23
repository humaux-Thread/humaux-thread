-- §46 forward-fix (EXPAND_CONTRACT, M02-4): the §74.6 email door. ops.email_outbox gains
--   idempotency_key  text UNIQUE, nullable (NULL = caller wants no replay protection; many NULLs allowed),
--   priority         smallint, 0 AUTH > 1 SECURITY > 2 REMINDER > 3 DIGEST, default 3 so an un-annotated row can never
--                    starve a login code,
-- and the closed state / event sets gain SUBMISSION_UNKNOWN: the provider connection was lost after DATA, so whether
-- the message left is unknowable. The claim query only ever selects QUEUED, so such a row is never auto-resent.
--
-- No new table and no grant changes: 0201's table-level INSERT (role_gateway) and SELECT, UPDATE (role_private_worker)
-- cover the new columns, so no rls_check cell moves.

ALTER TABLE ops.email_outbox
  ADD COLUMN idempotency_key text,
  ADD COLUMN priority smallint NOT NULL DEFAULT 3;

ALTER TABLE ops.email_outbox
  ADD CONSTRAINT email_outbox_idempotency_key_key UNIQUE (idempotency_key),
  ADD CONSTRAINT email_outbox_priority_check CHECK (priority IN (0, 1, 2, 3));

ALTER TABLE ops.email_outbox DROP CONSTRAINT email_outbox_state_check;
ALTER TABLE ops.email_outbox ADD CONSTRAINT email_outbox_state_check CHECK (state IN (
  'QUEUED', 'SENT', 'DELIVERED', 'BOUNCED', 'COMPLAINED', 'SUPPRESSED', 'FAILED', 'SUBMISSION_UNKNOWN'));

ALTER TABLE ops.email_delivery_events DROP CONSTRAINT email_delivery_events_event_type_check;
ALTER TABLE ops.email_delivery_events ADD CONSTRAINT email_delivery_events_event_type_check CHECK (event_type IN (
  'SENT', 'DELIVERED', 'BOUNCED', 'COMPLAINED', 'SUPPRESSED', 'FAILED', 'SUBMISSION_UNKNOWN'));

-- The drain orders by (priority, created_at) and the per-minute send cap counts recent sent_at.
DROP INDEX ops.idx_email_outbox_queued;
CREATE INDEX idx_email_outbox_queued ON ops.email_outbox (priority, created_at) WHERE state = 'QUEUED';
CREATE INDEX idx_email_outbox_sent_at ON ops.email_outbox (sent_at) WHERE sent_at IS NOT NULL;

COMMENT ON COLUMN ops.email_outbox.idempotency_key IS
  '§74.6 / M02-4: one row per key; a replayed enqueue inserts nothing (ON CONFLICT DO NOTHING).';
COMMENT ON COLUMN ops.email_outbox.priority IS
  'M02-4 storm guard: 0 AUTH, 1 SECURITY, 2 REMINDER, 3 DIGEST; the drain takes the lowest value first.';

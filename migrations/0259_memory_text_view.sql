-- §46 EXPAND_CONTRACT (card M07-2 / ADR-0085 D-A; Baseline §8.5, §8.2; module design M07 D1). private.memory_text_v:
-- the one place a Memory's canonical text is resolved, as (tenant_id, memory_id, title, body).
--
--   * An identity note (a row in private.identity_note_materializations, ADR-0067 D-B) has its body in its Evidence's
--     raw payload (private.events.payload, a JSON string, §8.2): `ev.payload #>> '{}'` is that string, unescaped, byte for
--     byte. A payload that is not a JSON string yields NULL, never a JSON text spelled as if it were the body.
--   * Every other Memory has its body in `content ->> 'key_claim'` (distilled, confirmed and corrected Memories, ADR-0016).
--   * title is `content ->> 'title'` for both. The derived-title fallback for a stripped title is card M07-3's, together
--     with the writer change; this view only reads what the row holds.
--
-- Until card M07-3 the writer still stores `key_claim` on an identity note, equal to its payload text, so both branches
-- agree for every row that exists. The identity branch does NOT fall back to `key_claim` when the Evidence is unreadable
-- or its payload is not a JSON string: it reads NULL. The one way to reach the `key_claim` branch with an identity note is
-- RLS hiding its contract row, which cannot happen while a Memory carries its Evidence's visibility (ADR-0016 D4); M07-3
-- strips `key_claim`, after which that case reads NULL too.
--
-- security_invoker: a reader gets exactly the RLS and privileges of memory_records, identity_note_materializations and
-- events under its own role (the 0255 view's rule). A Memory the caller cannot read is absent, not NULL.
-- Grants: SELECT to role_gateway (memory.get / grep / enumerate readers) and role_private_worker, the two runtime roles
-- that already read all four tables the view joins; nothing else, no INSERT/UPDATE/DELETE. The projection worker runs as
-- role_retrieval_worker, which has no SELECT on private.events; granting it the view and the table is card M10-6's
-- decision (ADR-0085 D-B), not this card's.
--
-- No DML, no table or policy altered. Locks: none beyond the catalog rows of one new view.
-- ponytail: events has no tenant_id, so the tenant leg runs through evidence_objects. The events lookup is by event_id
-- alone (the partition key recorded_at is not on the contract), so it probes each monthly leaf's primary key; add
-- recorded_at to the contract if a page of 200 notes ever shows it.

CREATE VIEW private.memory_text_v WITH (security_invoker = true) AS
  SELECT m.tenant_id,
         m.memory_id,
         m.content ->> 'title' AS title,
         CASE WHEN n.output_memory_id IS NOT NULL
              THEN CASE WHEN jsonb_typeof(ev.payload) = 'string' THEN ev.payload #>> '{}' END
              ELSE m.content ->> 'key_claim'
         END AS body
    FROM private.memory_records m
    LEFT JOIN private.identity_note_materializations n
      ON n.tenant_id = m.tenant_id AND n.output_memory_id = m.memory_id
    LEFT JOIN private.evidence_objects eo
      ON eo.tenant_id = n.tenant_id AND eo.evidence_id = n.evidence_id
    LEFT JOIN private.events ev
      ON ev.event_id = eo.evidence_id;

ALTER VIEW private.memory_text_v OWNER TO role_migration_owner;
REVOKE ALL ON private.memory_text_v
  FROM PUBLIC, role_gateway, role_private_worker, role_consolidation_worker, role_public_worker,
       role_retrieval_worker, role_batch_issuer, role_maintenance, role_admin;
GRANT SELECT ON private.memory_text_v TO role_gateway, role_private_worker;

COMMENT ON VIEW private.memory_text_v IS
  'ADR-0085 D-A (M07 D1): the one place a Memory''s title and body are resolved. An identity note''s body is its Evidence payload string (events.payload); any other Memory''s is content->>''key_claim''. security_invoker. Rust readers select from it (memory_repo::memory_texts_in_txn), SQL readers join it. M07-2.';

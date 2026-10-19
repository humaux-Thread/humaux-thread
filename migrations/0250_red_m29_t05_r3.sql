-- §80.1 red record only (branch red/m29-t05-r3, never merged): G-M29-3 fault, the PK no longer guards revision.
ALTER TABLE private.project_task_relations
  DROP CONSTRAINT project_task_relations_pkey,
  ADD CONSTRAINT project_task_relations_pkey PRIMARY KEY (tenant_id, relation_id, revision, recorded_at);

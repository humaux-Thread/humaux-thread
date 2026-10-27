-- §67.2 / §72.3 / ADR-0100: rate authority is the bounded gateway limiter.
-- M03-3: the manifest fences remaining function/view callers before any DROP.
-- RESTRICT preserves unexpected dependencies; no CASCADE may widen this retirement.
SET ROLE role_migration_owner;
DROP FUNCTION control.purge_idle_rate_buckets(interval, integer) RESTRICT;
DROP TABLE control.rate_buckets RESTRICT;
RESET ROLE;

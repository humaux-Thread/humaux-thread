-- §62 / §48.2 / M08 D7: re-harden every live RLS policy that casts a `humaux.*` GUC straight to uuid.
--
-- Why: 0031 wrapped every tenant GUC read in NULLIF(.., ''): once a `SET LOCAL` / `set_config(.., true)` has targeted
-- a placeholder GUC, the same backend reads it back as '' after that transaction ends, and `''::uuid` raises 22P02
-- instead of the predicate filtering to zero rows. Later CREATE / ALTER POLICY statements (0058 .. 0242) wrote the
-- plain cast again, on humaux.tenant_id and on humaux.user_id / workspace_id / principal_id, so the next transaction
-- on a pooled connection that skips the GUC setup errors on private.memory_records / evidence_objects / ... where
-- M08 D7 requires zero rows. NULLIF changes no successful read: it is the identity for every value but '', and on ''
-- the plain cast raised, so the rewrite only turns that error into a fail-closed NULL comparison.
--
-- Why a catalog loop, not explicit ALTER POLICY statements: the set to fix is whatever the catalog holds after 0245
-- (policies cloned onto partition leaves by control.partition_adopt_leaf, re-pointed by ALTER POLICY, written in
-- several source spellings), not what a grep over migration text finds. The loop is complete because
-- pg_policies.qual / with_check are pg_get_expr deparses, and the deparser has one spelling for this shape: a call
-- with a literal GUC name is `current_setting('<name>'::text[, <bool>])` (the `::text` disambiguates the overload)
-- and a cast of it is `(<call>)::uuid` (non-pretty deparse always parenthesizes the operand). `plain` below is
-- exactly that spelling; the NULLIF form puts `, ''::text)` between the call and the cast, so it never matches. Every
-- policy of every relation is scanned, partition leaves and tables without a tenant_id column included (a link
-- table's EXISTS casts the same GUC). The postcheck and `rls-check` RLS 四项 run the same pattern over the catalog.
--
-- Byte identity: only the matched cast is rewritten (regexp_replace on the deparse), ALTER POLICY keeps cmd, roles
-- and PERMISSIVE/RESTRICTIVE (0031's DROP/CREATE did not), and after each ALTER the loop re-reads the deparse and
-- aborts the migration if it differs from the rewritten text in any byte. Each hardened policy is named in a NOTICE.
DO $$
DECLARE
  plain constant text := $p$\(current_setting\(('humaux\.[^']*'::text(, (true|false))?)\)\)::uuid$p$;
  hardened constant text := $p$(NULLIF(current_setting(\1), ''::text))::uuid$p$;
  pol record;
  live record;
  new_qual text;
  new_check text;
BEGIN
  FOR pol IN
    SELECT schemaname, tablename, policyname, qual, with_check
      FROM pg_policies
     WHERE qual ~ plain OR with_check ~ plain
     ORDER BY schemaname, tablename, policyname
  LOOP
    new_qual := regexp_replace(pol.qual, plain, hardened, 'g');
    new_check := regexp_replace(pol.with_check, plain, hardened, 'g');
    IF pol.qual ~ plain THEN
      EXECUTE format('ALTER POLICY %I ON %I.%I USING (%s)',
                     pol.policyname, pol.schemaname, pol.tablename, new_qual);
    END IF;
    IF pol.with_check ~ plain THEN
      EXECUTE format('ALTER POLICY %I ON %I.%I WITH CHECK (%s)',
                     pol.policyname, pol.schemaname, pol.tablename, new_check);
    END IF;
    SELECT qual, with_check INTO live
      FROM pg_policies
     WHERE schemaname = pol.schemaname AND tablename = pol.tablename AND policyname = pol.policyname;
    IF live.qual IS DISTINCT FROM new_qual OR live.with_check IS DISTINCT FROM new_check THEN
      RAISE EXCEPTION '0246: %.%.% deparse differs from the NULLIF rewrite beyond the cast: qual % / with_check %',
        pol.schemaname, pol.tablename, pol.policyname, live.qual, live.with_check;
    END IF;
    RAISE NOTICE '0246 hardened %.%.%', pol.schemaname, pol.tablename, pol.policyname;
  END LOOP;
END $$;

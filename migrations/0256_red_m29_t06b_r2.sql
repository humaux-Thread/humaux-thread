-- §80.1 red record only (branch red/m29-t06b-r2, never merged): an A3' second site: another trigger on memory_records executing the A3' function.
CREATE TRIGGER memory_projects_on_supersede_again AFTER UPDATE OF superseded_by ON private.memory_records
  FOR EACH ROW WHEN (NEW.superseded_by IS NOT NULL AND NEW.superseded_by IS DISTINCT FROM OLD.superseded_by)
  EXECUTE FUNCTION private.memory_projects_on_supersede();

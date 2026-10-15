-- RED RECORD ONLY (M08-3 inject-red b2): removes the RLS layer from coord.tasks. Never merge.
ALTER TABLE coord.tasks NO FORCE ROW LEVEL SECURITY;
ALTER TABLE coord.tasks DISABLE ROW LEVEL SECURITY;

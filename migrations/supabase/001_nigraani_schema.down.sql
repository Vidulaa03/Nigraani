-- NIGRAANI: reverse 001_nigraani_schema.up.sql (and 003 policies).
-- Status: DRAFT FOR REVIEW. Not applied anywhere.
--
-- DESTRUCTIVE: drops the migrated tables and every row in them. demo.db is the
-- source of truth until cutover, so recovery is: run this, re-run 001 up, then
-- re-run scripts/migrate_sqlite_to_postgres.py --execute.
-- After cutover, take a fresh export first; rows written by the app to
-- Supabase after cutover exist nowhere else.

begin;

-- Order matters: orders references users.
drop table if exists public.decisions;
drop table if exists public.detections;
drop table if exists public.security_events;
drop table if exists public.orders;
drop table if exists public.users;

-- The nigraani_app role (if created per 003) is left in place on purpose:
-- dropping a login role is a separate, deliberate decision.

commit;

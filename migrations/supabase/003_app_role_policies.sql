-- NIGRAANI: least-privilege backend role and RLS policies.
-- Status: DRAFT FOR REVIEW. Not applied anywhere.
--
-- Prerequisite (done by you, outside version control): create the login role
-- with a password from your secret store, e.g. in the SQL editor:
--     create role nigraani_app login password '<from secret manager>';
-- Never commit that statement with a real password. This file refuses to run
-- if the role does not exist.
--
-- Why a dedicated role instead of postgres/service_role: both bypass RLS
-- (table owner / BYPASSRLS), so the policies below would never apply and a
-- leaked backend URL would grant full admin. nigraani_app gets exactly what
-- backend/database.py does today:
--   users, orders     SELECT                (seed rows come from the migration)
--   security_events   SELECT, INSERT, UPDATE (insert_event is an upsert)
--   detections        SELECT, INSERT         (append-only audit trail)
--   decisions         SELECT, INSERT         (append-only audit trail)
-- No DELETE anywhere, and no UPDATE on detections/decisions.

begin;

do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'nigraani_app') then
        raise exception 'Role nigraani_app does not exist; create it first (see header).';
    end if;
    if exists (select 1 from pg_roles where rolname = 'nigraani_app' and (rolsuper or rolbypassrls)) then
        raise exception 'nigraani_app must not be superuser or BYPASSRLS.';
    end if;
end
$$;

grant usage on schema public to nigraani_app;

grant select on public.users, public.orders to nigraani_app;
grant select, insert, update on public.security_events to nigraani_app;
grant select, insert on public.detections, public.decisions to nigraani_app;
grant usage on sequence
    public.detections_detection_id_seq,
    public.decisions_decision_id_seq
to nigraani_app;

create policy users_backend_read on public.users
    for select to nigraani_app using (true);
create policy orders_backend_read on public.orders
    for select to nigraani_app using (true);

create policy security_events_backend_read on public.security_events
    for select to nigraani_app using (true);
create policy security_events_backend_insert on public.security_events
    for insert to nigraani_app with check (true);
create policy security_events_backend_update on public.security_events
    for update to nigraani_app using (true) with check (true);

create policy detections_backend_read on public.detections
    for select to nigraani_app using (true);
create policy detections_backend_insert on public.detections
    for insert to nigraani_app with check (true);

create policy decisions_backend_read on public.decisions
    for select to nigraani_app using (true);
create policy decisions_backend_insert on public.decisions
    for insert to nigraani_app with check (true);

commit;

-- Rollback for this file only:
-- begin;
-- drop policy users_backend_read on public.users;
-- drop policy orders_backend_read on public.orders;
-- drop policy security_events_backend_read on public.security_events;
-- drop policy security_events_backend_insert on public.security_events;
-- drop policy security_events_backend_update on public.security_events;
-- drop policy detections_backend_read on public.detections;
-- drop policy detections_backend_insert on public.detections;
-- drop policy decisions_backend_read on public.decisions;
-- drop policy decisions_backend_insert on public.decisions;
-- revoke all on public.users, public.orders, public.security_events,
--     public.detections, public.decisions from nigraani_app;
-- revoke all on sequence public.detections_detection_id_seq,
--     public.decisions_decision_id_seq from nigraani_app;
-- commit;

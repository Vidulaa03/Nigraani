-- NIGRAANI: read-only post-load checks. Safe to run any time (SELECT only).
-- Expected values are from demo.db as inspected on 2026-10-10; the transfer
-- script recomputes them from the live SQLite file and compares automatically.

-- 1. Row counts (expected: users 5, orders 40, security_events 31,
--    detections 369, decisions 369).
select 'users' as table_name, count(*) from public.users
union all select 'orders', count(*) from public.orders
union all select 'security_events', count(*) from public.security_events
union all select 'detections', count(*) from public.detections
union all select 'decisions', count(*) from public.decisions;

-- 2. ID ranges (expected: detections 1..369, decisions 1..369,
--    orders 501..1408, security_events 999..1791570080979185).
select 'detections' as t, min(detection_id), max(detection_id) from public.detections
union all select 'decisions', min(decision_id), max(decision_id) from public.decisions
union all select 'orders', min(order_id), max(order_id) from public.orders
union all select 'security_events', min(event_id), max(event_id) from public.security_events;

-- 3. Identity sequences must be past the migrated IDs (next insert > 369).
select 'detections' as t, last_value, is_called from public.detections_detection_id_seq
union all select 'decisions', last_value, is_called from public.decisions_decision_id_seq;

-- 4. Relationships. Expected: 0 orphan orders. Telemetry orphans are
--    informational (no FK by design; demo.db has 4 resource_id orphans).
select 'orders.owner_id -> users' as check_name, count(*) as orphans
from public.orders o left join public.users u on u.user_id = o.owner_id
where u.user_id is null
union all
select 'security_events.resource_id -> orders (info)', count(*)
from public.security_events e
where e.resource_id is not null
  and not exists (select 1 from public.orders o where o.order_id = e.resource_id)
union all
select 'detections.event_ids -> security_events', count(*)
from public.detections d, jsonb_array_elements(d.event_ids) as ref(id)
where not exists (
    select 1 from public.security_events e where e.event_id = (ref.id)::bigint
);

-- 5. Duplicates. analysis_key duplicates must be 0 (enforced by index).
--    Legacy duplicate groups are expected (pre-dedup rows, analysis_key NULL);
--    the dashboard collapses them in _unique_detections/_unique_decisions.
select 'detections analysis_key dupes' as check_name, count(*) from (
    select analysis_key from public.detections
    where analysis_key is not null group by 1 having count(*) > 1) x
union all
select 'decisions analysis_key dupes', count(*) from (
    select analysis_key from public.decisions
    where analysis_key is not null group by 1 having count(*) > 1) x
union all
select 'detections legacy groups (expected 4 distinct of 369 rows)', count(*) from (
    select distinct detector, attack_type, ip, user_id, event_ids from public.detections) x;

-- 6. Security posture: RLS on, no Data API grants.
select c.relname, c.relrowsecurity as rls_enabled
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public'
  and c.relname in ('users', 'orders', 'security_events', 'detections', 'decisions');

select grantee, table_name, privilege_type
from information_schema.role_table_grants
where table_schema = 'public'
  and grantee in ('anon', 'authenticated')
  and table_name in ('users', 'orders', 'security_events', 'detections', 'decisions');
-- Expected: zero rows.

-- Moto Nzuri Field Ops v3.7.0: representative shop visit history and follow-ups.
-- Run in Supabase SQL Editor after the v3.6.0 migrations.

create table if not exists public.representative_shop_visits (
  id uuid primary key default gen_random_uuid(),
  submission_id uuid references public.agent_representative_submissions(id) on delete set null,
  representative_id uuid not null references public.agent_representative_profiles(user_id) on delete cascade,
  representative_email text not null,
  action text not null check (action in ('created','updated')),
  shop_name text not null check (length(trim(shop_name)) between 2 and 120),
  location text not null check (length(trim(location)) between 2 and 120),
  kp_number text,
  master_seed_no text,
  is_selling boolean not null default false,
  is_branded boolean not null default false,
  has_network boolean not null default false,
  has_paybill boolean not null default false,
  latitude double precision check (latitude is null or latitude between -90 and 90),
  longitude double precision check (longitude is null or longitude between -180 and 180),
  visit_notes text,
  visited_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);
create index if not exists idx_rep_visits_rep_date on public.representative_shop_visits(representative_id, visited_at desc);
create index if not exists idx_rep_visits_submission on public.representative_shop_visits(submission_id, visited_at desc);
create index if not exists idx_rep_visits_shop on public.representative_shop_visits(lower(shop_name), lower(location));
alter table public.representative_shop_visits enable row level security;
drop policy if exists admin_read_representative_shop_visits on public.representative_shop_visits;
create policy admin_read_representative_shop_visits on public.representative_shop_visits for select to authenticated using (public.is_admin());
drop policy if exists representative_read_own_shop_visits on public.representative_shop_visits;
create policy representative_read_own_shop_visits on public.representative_shop_visits for select to authenticated using (representative_id = auth.uid());

create table if not exists public.representative_shop_followups (
  id uuid primary key default gen_random_uuid(),
  representative_id uuid not null references public.agent_representative_profiles(user_id) on delete cascade,
  representative_email text not null,
  submission_id uuid references public.agent_representative_submissions(id) on delete set null,
  master_seed_no text,
  shop_name text not null check (length(trim(shop_name)) between 2 and 120),
  location text not null check (length(trim(location)) between 2 and 120),
  followup_type text not null check (followup_type in ('Revisit shop','Machine not selling','Machine needed','Network issue','Payment / Paybill issue','Shop information verification','Customer complaint','Other')),
  priority text not null default 'Normal' check (priority in ('Low','Normal','High','Urgent')),
  status text not null default 'Open' check (status in ('Open','In Progress','Completed','Cancelled')),
  notes text,
  resolution_notes text,
  due_date date,
  completed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists idx_rep_followups_rep_status_due on public.representative_shop_followups(representative_id, status, due_date);
create index if not exists idx_rep_followups_submission on public.representative_shop_followups(submission_id, created_at desc);
create index if not exists idx_rep_followups_shop on public.representative_shop_followups(lower(shop_name), lower(location));
alter table public.representative_shop_followups enable row level security;
drop policy if exists admin_read_representative_shop_followups on public.representative_shop_followups;
create policy admin_read_representative_shop_followups on public.representative_shop_followups for select to authenticated using (public.is_admin());
drop policy if exists representative_read_own_shop_followups on public.representative_shop_followups;
create policy representative_read_own_shop_followups on public.representative_shop_followups for select to authenticated using (representative_id = auth.uid());


-- Backfill historical create/update entries already stored in the v3.6 edit history.
-- This preserves earlier recorded changes when upgrading an existing installation.
insert into public.representative_shop_visits (
  submission_id, representative_id, representative_email, action, shop_name, location,
  kp_number, master_seed_no, is_selling, is_branded, has_network, has_paybill,
  latitude, longitude, visit_notes, visited_at
)
select
  h.submission_id,
  h.representative_id,
  coalesce(s.representative_email, p.email, 'unknown'),
  case when h.action = 'created' then 'created' else 'updated' end,
  coalesce(h.new_values->>'shop_name', s.shop_name),
  coalesce(h.new_values->>'location', s.location),
  nullif(h.new_values->>'kp_number',''),
  nullif(h.new_values->>'master_seed_no',''),
  coalesce((h.new_values->>'is_selling')::boolean, false),
  coalesce((h.new_values->>'is_branded')::boolean, false),
  coalesce((h.new_values->>'has_network')::boolean, false),
  coalesce((h.new_values->>'has_paybill')::boolean, false),
  nullif(h.new_values->>'latitude','')::double precision,
  nullif(h.new_values->>'longitude','')::double precision,
  case when h.action = 'created' then 'Backfilled from initial submission history' else 'Backfilled from shop edit history' end,
  h.edited_at
from public.representative_shop_edit_history h
join public.agent_representative_submissions s on s.id = h.submission_id
left join public.agent_representative_profiles p on p.user_id = h.representative_id
where h.representative_id is not null
  and coalesce(h.new_values->>'shop_name', s.shop_name) is not null
  and not exists (
    select 1 from public.representative_shop_visits v
    where v.submission_id = h.submission_id and v.visited_at = h.edited_at
  );

-- Moto Nzuri Field Ops v3.3: agent representative accounts and shop submissions.
-- Run this in Supabase SQL Editor after the existing schema.sql / driver_fleet_migration.sql.

create table if not exists public.agent_representative_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  email text unique not null,
  full_name text not null check (length(trim(full_name)) between 2 and 120),
  phone text,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.agent_representative_submissions (
  id uuid primary key default gen_random_uuid(),
  representative_id uuid references public.agent_representative_profiles(user_id) on delete set null,
  representative_email text not null,
  shop_name text not null check (length(trim(shop_name)) between 2 and 120),
  agent_name text not null check (length(trim(agent_name)) between 2 and 120),
  latitude double precision not null check (latitude between -90 and 90),
  longitude double precision not null check (longitude between -180 and 180),
  mpesa_number text not null check (length(trim(mpesa_number)) between 9 and 15),
  created_at timestamptz not null default now()
);

create index if not exists idx_rep_submissions_created on public.agent_representative_submissions(created_at desc);
create index if not exists idx_rep_submissions_rep on public.agent_representative_submissions(representative_id, created_at desc);
create index if not exists idx_rep_submissions_shop on public.agent_representative_submissions(lower(shop_name));

alter table public.agent_representative_profiles enable row level security;
alter table public.agent_representative_submissions enable row level security;

drop policy if exists admin_read_representative_profiles on public.agent_representative_profiles;
create policy admin_read_representative_profiles on public.agent_representative_profiles
  for select to authenticated using (public.is_admin());
drop policy if exists representative_own_profile on public.agent_representative_profiles;
create policy representative_own_profile on public.agent_representative_profiles
  for select to authenticated using (user_id = auth.uid() and active);
drop policy if exists admin_read_representative_submissions on public.agent_representative_submissions;
create policy admin_read_representative_submissions on public.agent_representative_submissions
  for select to authenticated using (public.is_admin());
drop policy if exists representative_read_own_submissions on public.agent_representative_submissions;
create policy representative_read_own_submissions on public.agent_representative_submissions
  for select to authenticated using (representative_id = auth.uid());

-- API writes use the server-side Supabase secret key; it must never be exposed in browser code.

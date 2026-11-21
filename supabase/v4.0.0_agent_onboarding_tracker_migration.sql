-- Moto Nzuri Field Ops v4.0.0: shared agent onboarding tracker
create extension if not exists pgcrypto;
create table if not exists public.agent_onboarding_tracker (
  id uuid primary key default gen_random_uuid(),
  date_onboarded date not null,
  agent_id text,
  agent_name text not null,
  shop_name text not null,
  location text not null,
  agent_phone_number text not null,
  latitude numeric(10,7),
  longitude numeric(10,7),
  projected_number_of_canisters numeric(12,2),
  actual_canisters_required numeric(12,2),
  display_delivered text not null default 'Not recorded',
  onboarding_status text not null default 'Pending',
  created_by uuid not null references auth.users(id) on delete restrict,
  created_by_email text,
  created_by_role text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint agent_onboarding_latitude_range check (latitude is null or latitude between -90 and 90),
  constraint agent_onboarding_longitude_range check (longitude is null or longitude between -180 and 180),
  constraint agent_onboarding_projected_nonnegative check (projected_number_of_canisters is null or projected_number_of_canisters >= 0),
  constraint agent_onboarding_actual_nonnegative check (actual_canisters_required is null or actual_canisters_required >= 0)
);
create index if not exists agent_onboarding_date_idx on public.agent_onboarding_tracker(date_onboarded desc);
create index if not exists agent_onboarding_shop_idx on public.agent_onboarding_tracker(lower(shop_name));
create index if not exists agent_onboarding_agent_idx on public.agent_onboarding_tracker(agent_id);
alter table public.agent_onboarding_tracker enable row level security;
-- All application access is mediated by the server using the Supabase service role
-- after validating an active portal account. No direct client policies are granted.
comment on table public.agent_onboarding_tracker is 'Shared agent onboarding tracker visible in all authenticated Moto Nzuri portals.';

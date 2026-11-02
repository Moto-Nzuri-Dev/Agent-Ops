-- Moto Nzuri Field Ops v3.9.0: dedicated Customer Care portal and shop onboarding.
create extension if not exists pgcrypto;

create table if not exists public.customer_care_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  email text unique not null,
  full_name text not null check (length(trim(full_name)) between 2 and 120),
  phone text,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.customer_care_profiles enable row level security;
drop policy if exists admin_read_customer_care_profiles on public.customer_care_profiles;
create policy admin_read_customer_care_profiles on public.customer_care_profiles for select to authenticated using (public.is_admin());
drop policy if exists customer_care_own_profile on public.customer_care_profiles;
create policy customer_care_own_profile on public.customer_care_profiles for select to authenticated using (user_id = auth.uid() and active);

create table if not exists public.csr_shop_onboarding (
  id uuid primary key default gen_random_uuid(),
  shop_name text not null check (length(trim(shop_name)) between 2 and 160),
  physical_address text not null check (length(trim(physical_address)) between 2 and 240),
  agent_full_name text not null check (length(trim(agent_full_name)) between 2 and 160),
  personal_phone_number text,
  alternative_number text,
  national_id text,
  kra_pin text,
  gps_latitude double precision check (gps_latitude is null or gps_latitude between -90 and 90),
  gps_longitude double precision check (gps_longitude is null or gps_longitude between -180 and 180),
  landmark text,
  kp_number text not null,
  machine_at_outlet text not null check (machine_at_outlet in ('Yes','No')),
  agent_commission numeric(10,2) not null default 10 check (agent_commission >= 0),
  entry_date date,
  mn_atr_number text,
  source text not null default 'customer-care',
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.csr_shop_onboarding enable row level security;
create index if not exists csr_shop_onboarding_name_idx on public.csr_shop_onboarding(lower(trim(shop_name)));
create index if not exists csr_shop_onboarding_kp_idx on public.csr_shop_onboarding(lower(trim(kp_number)));
create index if not exists csr_shop_onboarding_created_idx on public.csr_shop_onboarding(created_at desc);
create index if not exists csr_shop_onboarding_search_idx on public.csr_shop_onboarding using gin(to_tsvector('simple', coalesce(shop_name,'') || ' ' || coalesce(physical_address,'') || ' ' || coalesce(agent_full_name,'') || ' ' || coalesce(kp_number,'') || ' ' || coalesce(mn_atr_number,'')));

alter table public.customer_care_tickets add column if not exists csr_profile_id uuid references public.customer_care_profiles(user_id) on delete set null;
create index if not exists customer_care_tickets_updated_idx on public.customer_care_tickets(updated_at desc);

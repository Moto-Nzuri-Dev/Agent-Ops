create extension if not exists pgcrypto;

create or replace function public.current_sim_role()
returns text language sql stable as $$
  select coalesce(auth.jwt()->'app_metadata'->>'role',
                  auth.jwt()->'user_metadata'->>'role','viewer');
$$;

create table if not exists public.sim_cards (
 id uuid primary key default gen_random_uuid(),
 phone_number text not null,
 phone_normalized text generated always as (regexp_replace(phone_number,'[^0-9+]','','g')) stored,
 imsi text not null,
 imsi_normalized text generated always as (regexp_replace(imsi,'\s','','g')) stored,
 iccid text not null,
 iccid_normalized text generated always as (regexp_replace(iccid,'\s','','g')) stored,
 network_provider text not null default 'Safaricom',
 kp_number text, mn_number text, shop_name text, location text,
 activation_date date,
 status text not null default 'active' check(status in ('active','inactive','suspended','retired')),
 notes text,
 created_by uuid, created_by_email text, updated_by uuid,
 created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
 constraint sim_phone_unique unique(phone_normalized),
 constraint sim_imsi_unique unique(imsi_normalized),
 constraint sim_iccid_unique unique(iccid_normalized),
 constraint sim_phone_format check(phone_normalized ~ '^\+?[0-9]{9,15}$'),
 constraint sim_imsi_format check(imsi_normalized ~ '^[0-9]{14,16}$'),
 constraint sim_iccid_format check(iccid_normalized ~ '^[0-9]{18,22}$')
);
create table if not exists public.sim_recharges (
 id uuid primary key default gen_random_uuid(),
 sim_id uuid not null references public.sim_cards(id) on delete restrict,
 recharge_month date not null,
 amount_kes numeric(12,2) not null check(amount_kes>=0),
 recharged_at timestamptz not null default now(),
 transaction_reference text, notes text, recorded_by uuid, recorded_by_email text,
 created_at timestamptz not null default now(),
 constraint sim_month_unique unique(sim_id,recharge_month),
 constraint recharge_month_first check(extract(day from recharge_month)=1)
);
create table if not exists public.sim_audit_logs (
 id bigint generated always as identity primary key,
 sim_id uuid references public.sim_cards(id) on delete set null,
 action text not null, actor_id uuid, actor_email text,
 details jsonb not null default '{}'::jsonb, created_at timestamptz not null default now()
);
create index if not exists sim_cards_kp_idx on public.sim_cards(kp_number);
create index if not exists sim_cards_status_idx on public.sim_cards(status);
create index if not exists sim_recharges_month_idx on public.sim_recharges(recharge_month);
create or replace function public.sim_set_updated_at()
returns trigger language plpgsql as $$ begin new.updated_at=now(); return new; end; $$;
drop trigger if exists sim_cards_updated_at on public.sim_cards;
create trigger sim_cards_updated_at before update on public.sim_cards
for each row execute function public.sim_set_updated_at();

alter table public.sim_cards enable row level security;
alter table public.sim_recharges enable row level security;
alter table public.sim_audit_logs enable row level security;
drop policy if exists sim_cards_read on public.sim_cards;
create policy sim_cards_read on public.sim_cards for select to authenticated
using(public.current_sim_role() in ('admin','it_support','customer_service','viewer'));
drop policy if exists sim_cards_write on public.sim_cards;
create policy sim_cards_write on public.sim_cards for all to authenticated
using(public.current_sim_role() in ('admin','it_support','customer_service'))
with check(public.current_sim_role() in ('admin','it_support','customer_service'));
drop policy if exists sim_recharges_read on public.sim_recharges;
create policy sim_recharges_read on public.sim_recharges for select to authenticated
using(public.current_sim_role() in ('admin','it_support','customer_service','viewer'));
drop policy if exists sim_recharges_write on public.sim_recharges;
create policy sim_recharges_write on public.sim_recharges for all to authenticated
using(public.current_sim_role() in ('admin','it_support','customer_service'))
with check(public.current_sim_role() in ('admin','it_support','customer_service'));
drop policy if exists sim_audit_read on public.sim_audit_logs;
create policy sim_audit_read on public.sim_audit_logs for select to authenticated
using(public.current_sim_role()='admin');
drop policy if exists sim_audit_insert on public.sim_audit_logs;
create policy sim_audit_insert on public.sim_audit_logs for insert to authenticated
with check(public.current_sim_role() in ('admin','it_support','customer_service'));
grant select,insert,update on public.sim_cards,public.sim_recharges to authenticated;
grant select,insert on public.sim_audit_logs to authenticated;

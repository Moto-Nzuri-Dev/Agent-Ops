-- Moto Nzuri Field Ops v3.8.0 Phase 2: issue reporting, verification, notifications and performance.
-- Run after the v3.7.0 visit-history/follow-ups migration and existing customer-care migrations.

alter table public.representative_shop_followups
  add column if not exists verification_status text not null default 'Pending',
  add column if not exists verification_notes text,
  add column if not exists verified_by uuid references auth.users(id) on delete set null,
  add column if not exists verified_at timestamptz;

do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'representative_shop_followups_verification_status_check') then
    alter table public.representative_shop_followups add constraint representative_shop_followups_verification_status_check
      check (verification_status in ('Pending','Approved','Rejected','Not required'));
  end if;
end $$;
create index if not exists idx_rep_followups_verification on public.representative_shop_followups(verification_status, due_date);

create table if not exists public.ops_notifications (
  id uuid primary key default gen_random_uuid(),
  recipient_id uuid not null references auth.users(id) on delete cascade,
  title text not null check (length(trim(title)) between 1 and 160),
  body text not null default '',
  related_type text check (related_type is null or related_type in ('ticket','followup','visit','system')),
  related_id uuid,
  read_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists idx_ops_notifications_recipient_created on public.ops_notifications(recipient_id, created_at desc);
create index if not exists idx_ops_notifications_unread on public.ops_notifications(recipient_id, read_at) where read_at is null;
alter table public.ops_notifications enable row level security;
drop policy if exists ops_notifications_read_own on public.ops_notifications;
create policy ops_notifications_read_own on public.ops_notifications for select to authenticated using (recipient_id = auth.uid());
-- Writes occur only through server routes using the server-only Supabase secret key.


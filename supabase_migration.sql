-- UVI Alert: PIN-gated reminder tool
-- Tables are RLS-enabled with zero policies (default deny for anon/authenticated).
-- All access goes through SECURITY DEFINER RPCs that check the PIN on every call.

create extension if not exists pgcrypto schema extensions;

create table if not exists public.ua_admin_secret (
  id int primary key default 1,
  pin_hash text not null,
  constraint ua_admin_secret_single_row check (id = 1)
);
alter table public.ua_admin_secret enable row level security;
revoke all on public.ua_admin_secret from anon, authenticated;

create table if not exists public.ua_entries (
  id bigserial primary key,
  reminder_date date not null,
  name text not null,
  address text,
  contact_no text not null,
  note text,
  status text not null default 'pending' check (status in ('pending','done')),
  created_at timestamptz not null default now()
);
alter table public.ua_entries enable row level security;
revoke all on public.ua_entries from anon, authenticated;
revoke all on public.ua_entries_id_seq from anon, authenticated;

-- Seed the PIN (hashed). Safe to re-run: updates the hash if the row exists.
insert into public.ua_admin_secret (id, pin_hash)
values (1, extensions.crypt('9712', extensions.gen_salt('bf')))
on conflict (id) do update set pin_hash = excluded.pin_hash;

create or replace function public.ua_verify_pin(p_pin text)
returns boolean
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  return exists (
    select 1 from public.ua_admin_secret
    where id = 1 and pin_hash = extensions.crypt(p_pin, pin_hash)
  );
end;
$$;

create or replace function public.ua_list_entries(p_pin text)
returns setof public.ua_entries
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  if not public.ua_verify_pin(p_pin) then
    raise exception 'invalid pin';
  end if;
  return query select * from public.ua_entries order by reminder_date asc, created_at asc;
end;
$$;

create or replace function public.ua_add_entry(
  p_pin text, p_date date, p_name text, p_address text, p_contact text, p_note text
)
returns public.ua_entries
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_row public.ua_entries;
begin
  if not public.ua_verify_pin(p_pin) then
    raise exception 'invalid pin';
  end if;
  insert into public.ua_entries (reminder_date, name, address, contact_no, note)
  values (p_date, p_name, p_address, p_contact, p_note)
  returning * into v_row;
  return v_row;
end;
$$;

create or replace function public.ua_set_status(p_pin text, p_id bigint, p_status text)
returns void
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  if not public.ua_verify_pin(p_pin) then
    raise exception 'invalid pin';
  end if;
  if p_status not in ('pending','done') then
    raise exception 'invalid status';
  end if;
  update public.ua_entries set status = p_status where id = p_id;
end;
$$;

create or replace function public.ua_delete_entry(p_pin text, p_id bigint)
returns void
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  if not public.ua_verify_pin(p_pin) then
    raise exception 'invalid pin';
  end if;
  delete from public.ua_entries where id = p_id;
end;
$$;

revoke all on function public.ua_verify_pin(text) from public;
revoke all on function public.ua_list_entries(text) from public;
revoke all on function public.ua_add_entry(text, date, text, text, text, text) from public;
revoke all on function public.ua_set_status(text, bigint, text) from public;
revoke all on function public.ua_delete_entry(text, bigint) from public;

grant execute on function public.ua_verify_pin(text) to anon, authenticated;
grant execute on function public.ua_list_entries(text) to anon, authenticated;
grant execute on function public.ua_add_entry(text, date, text, text, text, text) to anon, authenticated;
grant execute on function public.ua_set_status(text, bigint, text) to anon, authenticated;
grant execute on function public.ua_delete_entry(text, bigint) to anon, authenticated;

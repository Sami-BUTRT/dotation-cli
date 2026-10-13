-- Fixture dotation : « orders » n'a pas de RLS. Ne pas corriger.
create table public.profiles (
  id uuid primary key,
  name text
);
alter table public.profiles enable row level security;

create table if not exists orders (
  id bigint generated always as identity primary key,
  user_id uuid,
  total numeric
);

-- Hors schéma public : non concerné.
create table private.audit (id bigint primary key);

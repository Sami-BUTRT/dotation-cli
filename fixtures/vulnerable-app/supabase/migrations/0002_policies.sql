-- Fixture dotation : cas volontairement dangereux. Ne pas corriger.
alter table public.profiles enable row level security;
create policy "everyone"
  on public.profiles
  for select
  using (true);

create function public.bump_counter()
returns void
language sql
security definer
as $$ update public.profiles set name = name; $$;

insert into storage.buckets (id, name, public)
values ('uploads', 'uploads', true);

create view public.all_profiles as select * from public.profiles;

create policy "anyone_writes" on public.profiles for insert with check (true);

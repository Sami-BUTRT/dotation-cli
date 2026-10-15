create policy "own rows" on public.profiles for select to authenticated using (auth.uid() = id);
create policy "server only" on public.profiles for all to service_role using (true) with check (true);

create function public.bump_counter()
returns void
language sql
security definer
set search_path = ''
as $$ update public.profiles set name = name where id = auth.uid(); $$;

insert into storage.buckets (id, name, public)
values ('uploads', 'uploads', false);

create view public.my_profiles with (security_invoker = true) as select * from public.profiles;

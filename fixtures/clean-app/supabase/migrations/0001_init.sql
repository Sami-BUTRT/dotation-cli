create table public.profiles (
  id uuid primary key references auth.users,
  name text
);
alter table public.profiles enable row level security;
create policy "own profile" on public.profiles for all using (auth.uid() = id);

create table orders (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users,
  total numeric
);
alter table orders enable row level security;
create policy "own orders" on orders for select using (auth.uid() = user_id);

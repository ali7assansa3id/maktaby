-- نظام إدارة مكتب المحاماة — Supabase PostgreSQL
-- نفّذ الملف كاملًا في SQL Editor بمشروع Supabase جديد.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  role text not null default 'lawyer' check (role in ('admin','lawyer','assistant','viewer')),
  created_at timestamptz not null default now()
);
create table if not exists public.clients (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  phone text,
  email text,
  address text,
  notes text,
  created_by uuid not null default auth.uid() references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table if not exists public.cases (
  id uuid primary key default gen_random_uuid(),
  case_number text not null,
  court text,
  case_type text,
  client_id uuid references public.clients(id) on delete set null,
  plaintiff text,
  defendant text,
  status text not null default 'منظورة',
  next_session date,
  last_decision text,
  notes text,
  created_by uuid not null default auth.uid() references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table if not exists public.hearings (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references public.cases(id) on delete cascade,
  hearing_date date not null,
  courtroom text,
  decision text,
  created_by uuid not null default auth.uid() references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table if not exists public.notices (
  id uuid primary key default gen_random_uuid(),
  case_id uuid references public.cases(id) on delete set null,
  recipient text not null,
  bailiff_number text,
  bailiff_office text,
  delivery_date date,
  status text not null default 'قيد الإعلان',
  notes text,
  created_by uuid not null default auth.uid() references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table if not exists public.tasks (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  case_id uuid references public.cases(id) on delete set null,
  assigned_to text,
  due_date date,
  status text not null default 'مفتوحة',
  details text,
  created_by uuid not null default auth.uid() references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- إنشاء ملف شخصي تلقائي لكل مستخدم جديد؛ الصلاحية الافتراضية ليست admin.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  insert into public.profiles (id,email,role)
  values (new.id,new.email,'lawyer')
  on conflict (id) do update set email=excluded.email;
  return new;
end;
$$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute procedure public.handle_new_user();

-- منع المستخدم من تغيير دوره بنفسه عبر تحديث صفه.
create or replace function public.prevent_profile_role_change()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  if auth.uid() = old.id and new.role is distinct from old.role then
    raise exception 'Changing your own role is not allowed';
  end if;
  return new;
end;
$$;
drop trigger if exists protect_profile_role on public.profiles;
create trigger protect_profile_role before update on public.profiles
for each row execute procedure public.prevent_profile_role_change();

alter table public.profiles enable row level security;
alter table public.clients enable row level security;
alter table public.cases enable row level security;
alter table public.hearings enable row level security;
alter table public.notices enable row level security;
alter table public.tasks enable row level security;

-- نموذج مبدئي: كل مستخدم مصادق عليه داخل المشروع يستطيع قراءة وتعديل بيانات المكتب المشتركة.
-- لا تستخدم هذا النموذج إذا كان لكل عميل/فريق عزل بيانات مستقل مطلوب.
drop policy if exists "profiles read authenticated" on public.profiles;
create policy "profiles read authenticated" on public.profiles for select to authenticated using (true);
drop policy if exists "users update own profile non-role" on public.profiles;
create policy "users update own profile non-role" on public.profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

do $$
declare t text;
begin
 foreach t in array array['clients','cases','hearings','notices','tasks'] loop
   execute format('drop policy if exists %I on public.%I', t||'_all_authenticated', t);
   execute format('create policy %I on public.%I for all to authenticated using (true) with check (true)', t||'_all_authenticated', t);
 end loop;
end $$;

grant usage on schema public to authenticated;
grant select, insert, update, delete on public.clients, public.cases, public.hearings, public.notices, public.tasks to authenticated;
grant select, update on public.profiles to authenticated;

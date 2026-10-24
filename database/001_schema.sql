-- TrustVault initial schema. Apply in Supabase SQL Editor to a NEW project.
-- Backend access uses the server-only service role key; never expose it to browsers.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null unique,
  full_name text not null default '',
  role text not null check (role in ('administrator', 'document_owner', 'viewer')),
  created_at timestamptz not null default now()
);

create table if not exists public.documents (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references public.profiles(id) on delete restrict,
  title text not null check (char_length(title) between 1 and 160),
  category text not null default 'General' check (char_length(category) <= 80),
  original_name text not null check (char_length(original_name) between 1 and 160),
  storage_path text not null unique,
  content_type text not null check (content_type in ('application/pdf', 'image/png', 'image/jpeg')),
  size_bytes bigint not null check (size_bytes > 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.document_permissions (
  document_id uuid not null references public.documents(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  can_read boolean not null default false,
  can_edit boolean not null default false,
  created_by uuid not null references public.profiles(id) on delete restrict,
  created_at timestamptz not null default now(),
  primary key (document_id, user_id),
  constraint permission_must_allow_something check (can_read or can_edit)
);

create table if not exists public.audit_events (
  id bigint generated always as identity primary key,
  actor_id uuid null,
  actor_role text not null,
  document_id uuid null,
  action text not null check (char_length(action) between 1 and 80),
  outcome text not null check (outcome in ('attempt', 'success', 'denied', 'failure')),
  ip_address inet null,
  user_agent text not null default '',
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists documents_owner_created_idx on public.documents(owner_id, created_at desc);
create index if not exists documents_category_idx on public.documents(category);
create index if not exists document_permissions_user_idx on public.document_permissions(user_id, document_id);
create index if not exists audit_events_created_idx on public.audit_events(created_at desc);
create index if not exists audit_events_document_idx on public.audit_events(document_id, created_at desc);

create or replace function public.set_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists documents_set_updated_at on public.documents;
create trigger documents_set_updated_at before update on public.documents
for each row execute function public.set_updated_at();

-- Prevent UPDATE/DELETE through the application database connection. Database owners
-- can still change schema objects, so describe this as tamper-resistant, not absolute immutability.
create or replace function public.reject_audit_mutation()
returns trigger language plpgsql as $$
begin
  raise exception 'audit_events is append-only';
end;
$$;

drop trigger if exists audit_events_no_update on public.audit_events;
create trigger audit_events_no_update before update or delete on public.audit_events
for each row execute function public.reject_audit_mutation();

-- Enable RLS and intentionally define no browser-user policies. All application data
-- access goes through the Express backend. The service-role key is server-only.
alter table public.profiles enable row level security;
alter table public.documents enable row level security;
alter table public.document_permissions enable row level security;
alter table public.audit_events enable row level security;

-- Setup notes:
-- 1) Create accounts in Supabase Authentication.
-- 2) Add one public.profiles row for each account using its auth.users UUID, email,
--    full_name, and role. Never allow a user to choose their own role.
-- 3) Create a PRIVATE Storage bucket named trustvault-private (or configure
--    SUPABASE_BUCKET to match). Set file size limit to match MAX_UPLOAD_MB.

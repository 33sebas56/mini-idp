create extension if not exists pgcrypto;

create table app_users (
    id uuid primary key default gen_random_uuid(),
    email varchar(320) not null unique,
    password_hash varchar(255) not null,
    email_verified boolean not null default false,
    enabled boolean not null default true,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table oauth_clients (
    id uuid primary key default gen_random_uuid(),
    client_id varchar(120) not null unique,
    client_secret_hash varchar(255) not null,
    name varchar(160) not null,
    redirect_uri varchar(500) not null,
    allowed_scopes varchar(500) not null,
    enabled boolean not null default true,
    created_at timestamptz not null default now()
);

create table audit_logs (
    id uuid primary key default gen_random_uuid(),
    actor_user_id uuid null references app_users(id),
    event_type varchar(120) not null,
    ip_address varchar(80),
    user_agent varchar(500),
    details text,
    created_at timestamptz not null default now()
);
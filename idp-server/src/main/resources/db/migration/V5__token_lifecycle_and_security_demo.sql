create table refresh_tokens (
    id uuid primary key default gen_random_uuid(),
    token_hash varchar(64) not null unique,
    user_id uuid not null references app_users(id) on delete cascade,
    client_id varchar(120) not null,
    scope varchar(500) not null,
    expires_at timestamptz not null,
    revoked_at timestamptz null,
    replaced_by_token_hash varchar(64) null,
    created_at timestamptz not null default now()
);

create index idx_refresh_tokens_user_id
    on refresh_tokens(user_id);

create index idx_refresh_tokens_client_id
    on refresh_tokens(client_id);

create table revoked_access_tokens (
    id uuid primary key default gen_random_uuid(),
    jti varchar(120) not null unique,
    expires_at timestamptz not null,
    revoked_at timestamptz not null default now()
);

create index idx_revoked_access_tokens_expires_at
    on revoked_access_tokens(expires_at);
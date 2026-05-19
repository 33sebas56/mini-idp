create table oauth_authorization_requests (
    id uuid primary key default gen_random_uuid(),
    client_id varchar(120) not null,
    redirect_uri varchar(500) not null,
    state varchar(500),
    scope varchar(500) not null,
    expires_at timestamptz not null,
    consumed_at timestamptz null,
    created_at timestamptz not null default now()
);

create index idx_oauth_authorization_requests_client_id
    on oauth_authorization_requests(client_id);

create table authorization_codes (
    id uuid primary key default gen_random_uuid(),
    code_hash varchar(64) not null unique,
    user_id uuid not null references app_users(id) on delete cascade,
    client_id varchar(120) not null,
    redirect_uri varchar(500) not null,
    scope varchar(500) not null,
    expires_at timestamptz not null,
    used_at timestamptz null,
    created_at timestamptz not null default now()
);

create index idx_authorization_codes_user_id
    on authorization_codes(user_id);

create index idx_authorization_codes_client_id
    on authorization_codes(client_id);
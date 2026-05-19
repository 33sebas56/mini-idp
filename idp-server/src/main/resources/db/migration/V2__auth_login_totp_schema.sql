create table email_verification_tokens (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references app_users(id) on delete cascade,
    token_hash varchar(64) not null unique,
    expires_at timestamptz not null,
    used_at timestamptz null,
    created_at timestamptz not null default now()
);

create index idx_email_verification_tokens_user_id
    on email_verification_tokens(user_id);

create table login_challenges (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references app_users(id) on delete cascade,
    challenge_hash varchar(64) not null unique,
    purpose varchar(50) not null,
    expires_at timestamptz not null,
    consumed_at timestamptz null,
    created_at timestamptz not null default now()
);

create index idx_login_challenges_user_id
    on login_challenges(user_id);

create table totp_credentials (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null unique references app_users(id) on delete cascade,
    secret_encrypted text not null,
    enabled boolean not null default false,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
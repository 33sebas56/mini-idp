create table signing_keys (
    id uuid primary key default gen_random_uuid(),
    kid varchar(120) not null unique,
    private_jwk_encrypted text not null,
    public_jwk text not null,
    active boolean not null default true,
    created_at timestamptz not null default now(),
    expires_at timestamptz null
);

create index idx_signing_keys_active
    on signing_keys(active);
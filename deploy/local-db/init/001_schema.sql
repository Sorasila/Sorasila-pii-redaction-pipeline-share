-- Local PII manifest store. The same schema can later be applied to Supabase, which also serves Postgres through PostgREST.
create schema if not exists api;

create table api.pii_manifests (
    delivery_id         uuid primary key,
    document_id         uuid not null,
    kid                 text not null,
    manifest_jwe        text not null,
    metadata            text not null,
    redacted_md_sha256  text not null check (redacted_md_sha256 ~ '^[0-9a-f]{64}$'),
    stored_at           timestamptz not null default now(),
    expires_at          timestamptz
);

comment on column api.pii_manifests.manifest_jwe is
    'Exact JWE JSON of the pii_manifest part. Plaintext test envelopes only on this local store.';
comment on column api.pii_manifests.expires_at is
    'NULL keeps the row: no deletion during the test phase.';

create index pii_manifests_document_id_idx on api.pii_manifests (document_id);

-- Insert-only role for the service: it cannot read, update or delete rows.
create role pii_writer nologin;
grant usage on schema api to pii_writer;
grant insert on api.pii_manifests to pii_writer;
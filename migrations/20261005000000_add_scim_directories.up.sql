/* auth_migration: 20261005000000 */
-- Replaced by the generic directory schema below before anything wrote to them.
drop table if exists {{ index .Options "Namespace" }}.scim_users;

/* auth_migration: 20261005000000 */
drop table if exists {{ index .Options "Namespace" }}.scim_tokens;

/* auth_migration: 20261005000000 */
-- A SCIM directory is the tenant boundary for provisioning. It belongs to one
-- SSO provider today; the column is nullable so a directory can later stand on
-- its own without altering this table.
create table if not exists {{ index .Options "Namespace" }}.scim_directories (
    id uuid not null,
    sso_provider_id uuid references {{ index .Options "Namespace" }}.sso_providers (id) on delete cascade,
    enabled boolean not null default false,
    settings jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint scim_directories_pkey primary key (id),
    constraint scim_directories_sso_provider_id_key unique (sso_provider_id)
);

/* auth_migration: 20261005000000 */
-- Bearer tokens for one directory. Only the SHA-256 digest of the token is
-- stored; a token carries 160 bits, so the digest needs no salt.
create table if not exists {{ index .Options "Namespace" }}.scim_tokens (
    id uuid not null,
    directory_id uuid not null references {{ index .Options "Namespace" }}.scim_directories (id) on delete cascade,
    token_hash bytea not null,
    prefix text not null,
    description text,
    created_at timestamptz not null default now(),
    expires_at timestamptz,
    revoked_at timestamptz,
    last_used_at timestamptz,
    constraint scim_tokens_pkey primary key (id),
    constraint scim_tokens_token_hash_key unique (token_hash),
    constraint scim_tokens_token_hash_length check (octet_length(token_hash) = 32)
);

/* auth_migration: 20261005000000 */
create index if not exists scim_tokens_directory_id_idx
    on {{ index .Options "Namespace" }}.scim_tokens (directory_id);

/* auth_migration: 20261005000000 */
-- Every provisioned resource, of every resource type, as its SCIM document.
-- The schema knows nothing about resource types or their attributes, so new
-- types, attributes and extensions never need a migration.
create table if not exists {{ index .Options "Namespace" }}.scim_resources (
    id uuid not null,
    directory_id uuid not null references {{ index .Options "Namespace" }}.scim_directories (id) on delete cascade,
    resource_type text not null,
    user_id uuid references {{ index .Options "Namespace" }}.users (id) on delete cascade,
    version bigint not null default 1,
    resource jsonb not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    deleted_at timestamptz,
    constraint scim_resources_pkey primary key (id),
    constraint scim_resources_directory_id_id_key unique (directory_id, id)
);

/* auth_migration: 20261005000000 */
create index if not exists scim_resources_directory_type_id_idx
    on {{ index .Options "Namespace" }}.scim_resources (directory_id, resource_type, id)
    where deleted_at is null;

/* auth_migration: 20261005000000 */
-- One live resource per account in a directory; tombstones keep the link.
create unique index if not exists scim_resources_directory_user_id_key
    on {{ index .Options "Namespace" }}.scim_resources (directory_id, user_id)
    where deleted_at is null and user_id is not null;

/* auth_migration: 20261005000000 */
create index if not exists scim_resources_user_id_idx
    on {{ index .Options "Namespace" }}.scim_resources (user_id);

/* auth_migration: 20261005000000 */
-- Normalised attribute values that must be unique or found quickly. Which
-- attributes are keyed is decided by the application, not by this schema.
create table if not exists {{ index .Options "Namespace" }}.scim_resource_keys (
    directory_id uuid not null,
    resource_type text not null,
    attribute text not null,
    value text collate "C" not null,
    resource_id uuid not null,
    is_unique boolean not null,
    constraint scim_resource_keys_pkey primary key (directory_id, resource_type, attribute, value, resource_id),
    constraint scim_resource_keys_resource_fkey foreign key (directory_id, resource_id)
        references {{ index .Options "Namespace" }}.scim_resources (directory_id, id) on delete cascade
);

/* auth_migration: 20261005000000 */
create unique index if not exists scim_resource_keys_unique_key
    on {{ index .Options "Namespace" }}.scim_resource_keys (directory_id, resource_type, attribute, value)
    where is_unique;

/* auth_migration: 20261005000000 */
create index if not exists scim_resource_keys_resource_id_idx
    on {{ index .Options "Namespace" }}.scim_resource_keys (resource_id);

/* auth_migration: 20261005000000 */
-- Directed references from one resource to another within a directory, named
-- by the referencing attribute.
create table if not exists {{ index .Options "Namespace" }}.scim_resource_references (
    directory_id uuid not null,
    source_id uuid not null,
    attribute text not null,
    target_id uuid not null,
    created_at timestamptz not null default now(),
    constraint scim_resource_references_pkey primary key (source_id, attribute, target_id),
    constraint scim_resource_references_not_self check (source_id <> target_id),
    constraint scim_resource_references_source_fkey foreign key (directory_id, source_id)
        references {{ index .Options "Namespace" }}.scim_resources (directory_id, id) on delete cascade,
    constraint scim_resource_references_target_fkey foreign key (directory_id, target_id)
        references {{ index .Options "Namespace" }}.scim_resources (directory_id, id) on delete cascade
);

/* auth_migration: 20261005000000 */
create index if not exists scim_resource_references_target_idx
    on {{ index .Options "Namespace" }}.scim_resource_references (target_id, attribute);

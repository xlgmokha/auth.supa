/* auth_migration: 20261005000000 */
create table if not exists {{ index .Options "Namespace" }}.scim_resources (
    id uuid not null,
    sso_provider_id uuid not null references {{ index .Options "Namespace" }}.sso_providers (id) on delete cascade,
    resource_type text not null,
    resource jsonb not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    deleted_at timestamptz,
    constraint scim_resources_pkey primary key (id)
);

/* auth_migration: 20261005000000 */
create unique index if not exists scim_resources_user_name_key
    on {{ index .Options "Namespace" }}.scim_resources (sso_provider_id, (lower(resource->>'userName')) collate "C")
    where resource_type = 'User' and deleted_at is null;

/* auth_migration: 20261005000000 */
create unique index if not exists scim_resources_external_id_key
    on {{ index .Options "Namespace" }}.scim_resources (sso_provider_id, resource_type, (resource->>'externalId') collate "C")
    where resource->>'externalId' is not null and deleted_at is null;

/* auth_migration: 20261005000000 */
create index if not exists scim_resources_display_name_idx
    on {{ index .Options "Namespace" }}.scim_resources (sso_provider_id, (lower(resource->>'displayName')) collate "C", id)
    where resource_type = 'Group' and deleted_at is null;

/* auth_migration: 20261005000000 */
create index if not exists scim_resources_id_idx
    on {{ index .Options "Namespace" }}.scim_resources (sso_provider_id, resource_type, id)
    where deleted_at is null;

/* auth_migration: 20261005000000 */
create index if not exists scim_resources_created_at_idx
    on {{ index .Options "Namespace" }}.scim_resources (sso_provider_id, resource_type, created_at, id)
    where deleted_at is null;

/* auth_migration: 20261005000000 */
create index if not exists scim_resources_updated_at_idx
    on {{ index .Options "Namespace" }}.scim_resources (sso_provider_id, resource_type, updated_at, id)
    where deleted_at is null;

/* auth_migration: 20261005000000 */
create index if not exists scim_resources_inactive_idx
    on {{ index .Options "Namespace" }}.scim_resources (sso_provider_id, id)
    where resource_type = 'User' and deleted_at is null and not coalesce((resource->>'active')::boolean, true);

/* auth_migration: 20261005000000 */
create index if not exists scim_resources_resource_idx
    on {{ index .Options "Namespace" }}.scim_resources using gin ((lower(resource::text)::jsonb) jsonb_path_ops)
    where deleted_at is null;

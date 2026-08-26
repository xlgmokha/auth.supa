-- SCIM Groups; RFC 7643 Group
create table if not exists {{ index .Options "Namespace" }}.scim_groups (
    id uuid not null default gen_random_uuid(),
    sso_provider_id uuid not null references {{ index .Options "Namespace" }}.sso_providers (id) on delete cascade,
    resource jsonb not null,
    display_name text not null generated always as (resource->>'displayName') stored,
    external_id text generated always as (resource->>'externalId') stored,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint scim_groups_pkey primary key (id),
    constraint scim_groups_id_provider_key unique (id, sso_provider_id)
);

-- displayName is unique within a provider, case-folded.
create unique index if not exists scim_groups_display_name_key
    on {{ index .Options "Namespace" }}.scim_groups (sso_provider_id, lower(display_name));

-- externalId is the IdP's key for the group; unique within a provider when set.
create unique index if not exists scim_groups_external_id_key
    on {{ index .Options "Namespace" }}.scim_groups (sso_provider_id, external_id)
    where external_id is not null;

-- Group membership. The composite key prevents duplicate (group, user) rows.
create table if not exists {{ index .Options "Namespace" }}.scim_group_members (
    scim_group_id uuid not null,
    scim_user_id uuid not null,
    sso_provider_id uuid not null,
    constraint scim_group_members_pkey primary key (scim_group_id, scim_user_id),
    constraint scim_group_members_group_fkey
        foreign key (scim_group_id, sso_provider_id)
        references {{ index .Options "Namespace" }}.scim_groups (id, sso_provider_id) on delete cascade,
    constraint scim_group_members_user_fkey
        foreign key (scim_user_id, sso_provider_id)
        references {{ index .Options "Namespace" }}.scim_users (id, sso_provider_id) on delete cascade
);

alter table {{ index .Options "Namespace" }}.scim_groups enable row level security;
alter table {{ index .Options "Namespace" }}.scim_group_members enable row level security;
grant select on {{ index .Options "Namespace" }}.scim_groups to postgres with grant option;
grant select on {{ index .Options "Namespace" }}.scim_group_members to postgres with grant option;

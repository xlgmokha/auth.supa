package models

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

type SCIMGroup struct {
	ID            uuid.UUID  `db:"id"`
	SSOProviderID uuid.UUID  `db:"sso_provider_id"`
	ResourceType  string     `db:"resource_type"`
	Resource      []byte     `db:"resource"`
	CreatedAt     time.Time  `db:"created_at"`
	UpdatedAt     time.Time  `db:"updated_at"`
	DeletedAt     *time.Time `db:"deleted_at"`
}

func (SCIMGroup) TableName() string {
	return "scim_resources"
}

type SCIMGroupMember struct {
	GroupID    uuid.UUID `db:"group_id"`
	SCIMUserID uuid.UUID `db:"scim_user_id"`
}

func (SCIMGroupMember) TableName() string {
	return "scim_group_members"
}

type SCIMGroupMembership struct {
	GroupID    uuid.UUID `db:"group_id"`
	SCIMUserID uuid.UUID `db:"scim_user_id"`
	Display    string    `db:"display"`
}

type SCIMGroupMemberChange struct {
	Added   []uuid.UUID
	Removed []uuid.UUID
	Members []uuid.UUID
}

func (c SCIMGroupMemberChange) Changed() bool {
	return len(c.Added)+len(c.Removed) > 0
}

var scimGroupsTable = scimTable{
	tableName:      SCIMGroup{}.TableName(),
	resourceType:   "Group",
	label:          "SCIM group",
	columns:        "id, sso_provider_id, resource_type, resource, created_at, updated_at, deleted_at",
	nameColumn:     "lower(resource->>'displayName')",
	externalColumn: "(resource->>'externalId')",
	stored:         "(resource - 'members')",
	written:        "?::jsonb || jsonb_build_object('members', coalesce(resource->'members', '[]'::jsonb))",
	scope:          "sso_provider_id = ? AND resource_type = 'Group' AND deleted_at IS NULL",
	conflict:       ErrSCIMGroupConflict,
}

func CreateSCIMGroup(tx *storage.Connection, providerID uuid.UUID, resource []byte) (*SCIMGroup, error) {
	return createSCIMRow[SCIMGroup](tx, scimGroupsTable, providerID, resource)
}

func FindSCIMGroup(tx *storage.Connection, providerID, id uuid.UUID) (*SCIMGroup, error) {
	return findSCIMRow[SCIMGroup](tx, scimGroupsTable, SCIMTarget{ProviderID: providerID, ID: id})
}

func FindSCIMGroups(tx *storage.Connection, providerID uuid.UUID, query SCIMQuery) ([]SCIMGroup, int, error) {
	return findSCIMPage[SCIMGroup](tx, scimGroupsTable, providerID, query)
}

func ReplaceSCIMGroupIfChanged(tx *storage.Connection, target SCIMTarget, resource []byte) (*SCIMGroup, bool, error) {
	return replaceSCIMRowIfChanged[SCIMGroup](tx, scimGroupsTable, target, resource)
}

func LockUnchangedSCIMGroup(tx *storage.Connection, providerID, id uuid.UUID, resource []byte) (*SCIMGroup, error) {
	return findUnchangedSCIMRow[SCIMGroup](tx, scimGroupsTable, SCIMTarget{ProviderID: providerID, ID: id}, resource)
}

func DeleteSCIMGroup(tx *storage.Connection, target SCIMTarget) (*SCIMGroup, error) {
	return writeSCIMRow[SCIMGroup](tx, scimGroupsTable, target, scimWrite{verb: "deleting", sql: "DELETE FROM %q"})
}

func FindSCIMMembershipsByGroup(tx *storage.Connection, providerID uuid.UUID, groupIDs []uuid.UUID) ([]SCIMGroupMembership, error) {
	members := []SCIMGroupMembership{}
	if len(groupIDs) == 0 {
		return members, nil
	}
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT g.id AS group_id, u.id AS scim_user_id FROM %q g CROSS JOIN LATERAL jsonb_array_elements(coalesce(g.resource->'members', '[]'::jsonb)) m JOIN %q u ON u.id = (m->>'value')::uuid WHERE g.id = ANY(?::uuid[]) AND u.sso_provider_id = ? AND u.deleted_at IS NULL ORDER BY g.id, u.id", scimGroupsTable.tableName, scimUsersTable.tableName),
		groupIDs, providerID,
	).All(&members); err != nil {
		return nil, errors.Wrap(err, "error finding SCIM group members")
	}
	return members, nil
}

func FindSCIMMembershipsByUser(tx *storage.Connection, providerID uuid.UUID, scimUserIDs []uuid.UUID) ([]SCIMGroupMembership, error) {
	memberships := []SCIMGroupMembership{}
	if len(scimUserIDs) == 0 {
		return memberships, nil
	}
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT g.id AS group_id, (m->>'value')::uuid AS scim_user_id, g.resource->>'displayName' AS display FROM %q g CROSS JOIN LATERAL jsonb_array_elements(coalesce(g.resource->'members', '[]'::jsonb)) m WHERE m->>'value' = ANY(?::text[]) AND g.sso_provider_id = ? AND g.resource_type = 'Group' AND g.deleted_at IS NULL ORDER BY scim_user_id, lower(g.resource->>'displayName') COLLATE \"C\", g.id", scimGroupsTable.tableName),
		uuidStrings(scimUserIDs), providerID,
	).All(&memberships); err != nil {
		return nil, errors.Wrap(err, "error finding SCIM groups for users")
	}
	return memberships, nil
}

func ReplaceSCIMGroupMembers(tx *storage.Connection, group *SCIMGroup, scimUserIDs []uuid.UUID) (*SCIMGroup, SCIMGroupMemberChange, error) {
	stored := &SCIMGroup{}
	if err := tx.RawQuery(fmt.Sprintf("SELECT %s FROM %q WHERE id = ?", scimGroupsTable.columns, scimGroupsTable.tableName), group.ID).First(stored); err != nil {
		return nil, SCIMGroupMemberChange{}, scimGroupsTable.wrapError(err, "finding")
	}
	current, err := scimGroupMemberIDs(stored)
	if err != nil {
		return nil, SCIMGroupMemberChange{}, err
	}
	return ReplaceSCIMGroupMembersFrom(tx, group, current, scimUserIDs)
}

func ReplaceSCIMGroupMembersFrom(tx *storage.Connection, group *SCIMGroup, current, scimUserIDs []uuid.UUID) (*SCIMGroup, SCIMGroupMemberChange, error) {
	members := sortedUniqueUUIDs(scimUserIDs)
	change := SCIMGroupMemberChange{Members: members, Added: differenceUUIDs(members, current), Removed: differenceUUIDs(current, members)}
	if !change.Changed() {
		return group, change, nil
	}
	if len(change.Added) > 0 {
		if err := requireLiveSCIMUsers(tx, group.SSOProviderID, change.Added); err != nil {
			return nil, change, err
		}
	}
	updated := &SCIMGroup{}
	if err := tx.RawQuery(
		fmt.Sprintf(`UPDATE %q SET resource = jsonb_set(resource, '{members}', (
  SELECT coalesce(jsonb_agg(jsonb_build_object('value', value, 'type', 'User') ORDER BY value), '[]'::jsonb) FROM (
    SELECT m->>'value' AS value FROM jsonb_array_elements(coalesce(resource->'members', '[]'::jsonb)) m WHERE m->>'value' <> ALL(?::text[])
    UNION SELECT unnest(?::text[])
  ) members)), updated_at = clock_timestamp() WHERE id = ? RETURNING %s`, scimGroupsTable.tableName, scimGroupsTable.columns),
		uuidStrings(change.Removed), uuidStrings(change.Added), group.ID,
	).First(updated); err != nil {
		return nil, change, errors.Wrap(err, "error updating SCIM group members")
	}
	members, err := scimGroupMemberIDs(updated)
	change.Members = members
	return updated, change, err
}

func RemoveSCIMUserFromGroups(tx *storage.Connection, scimUserID uuid.UUID) error {
	return errors.Wrap(tx.RawQuery(
		fmt.Sprintf(`UPDATE %q SET resource = jsonb_set(resource, '{members}', (SELECT coalesce(jsonb_agg(m ORDER BY m->>'value'), '[]'::jsonb) FROM jsonb_array_elements(resource->'members') m WHERE m->>'value' <> ?)) WHERE resource_type = 'Group' AND resource->'members' @> jsonb_build_array(jsonb_build_object('value', ?::text))`, scimGroupsTable.tableName),
		scimUserID.String(), scimUserID.String(),
	).Exec(), "error removing SCIM user from groups")
}

func scimGroupMemberIDs(group *SCIMGroup) ([]uuid.UUID, error) {
	var resource struct {
		Members []struct {
			Value uuid.UUID `json:"value"`
		} `json:"members"`
	}
	if err := json.Unmarshal(group.Resource, &resource); err != nil {
		return nil, errors.Wrap(err, "error decoding SCIM group members")
	}
	ids := make([]uuid.UUID, len(resource.Members))
	for i, member := range resource.Members {
		ids[i] = member.Value
	}
	return sortedUniqueUUIDs(ids), nil
}

func uuidStrings(ids []uuid.UUID) []string {
	values := make([]string, len(ids))
	for i, id := range ids {
		values[i] = id.String()
	}
	return values
}

func requireLiveSCIMUsers(tx *storage.Connection, providerID uuid.UUID, ids []uuid.UUID) error {
	live, err := tx.Q().Where("id = ANY(?::uuid[]) AND sso_provider_id = ? AND deleted_at IS NULL", ids, providerID).Count(&SCIMUser{})
	if err != nil {
		return errors.Wrap(err, "error finding SCIM group members")
	}
	if live != len(ids) {
		return ErrSCIMGroupMemberNotFound
	}
	return nil
}

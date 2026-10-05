package models

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

type SCIMUser struct {
	ID            uuid.UUID  `db:"id"`
	SSOProviderID uuid.UUID  `db:"sso_provider_id"`
	Resource      []byte     `db:"resource"`
	UserName      string     `db:"user_name"`
	ExternalID    *string    `db:"external_id"`
	Active        bool       `db:"active"`
	CreatedAt     time.Time  `db:"created_at"`
	UpdatedAt     time.Time  `db:"updated_at"`
	DeletedAt     *time.Time `db:"deleted_at"`
}

func (SCIMUser) TableName() string {
	return "scim_users"
}

var scimUsersTable = scimTable{
	tableName:      SCIMUser{}.TableName(),
	label:          "SCIM user",
	columns:        "id, sso_provider_id, resource, user_name, external_id, active, created_at, updated_at, deleted_at",
	nameColumn:     "user_name",
	externalColumn: "external_id",
	stored:         "resource",
	written:        "?::jsonb",
	scope:          "sso_provider_id = ? AND deleted_at IS NULL",
	conflict:       ErrSCIMUserConflict,
}

func CreateSCIMUser(tx *storage.Connection, providerID uuid.UUID, resource []byte) (*SCIMUser, error) {
	return createSCIMRow[SCIMUser](tx, scimUsersTable, providerID, resource)
}

func FindSCIMUser(tx *storage.Connection, providerID, id uuid.UUID) (*SCIMUser, error) {
	return findSCIMRow[SCIMUser](tx, scimUsersTable, SCIMTarget{ProviderID: providerID, ID: id})
}

func ReplaceSCIMUserIfChanged(tx *storage.Connection, target SCIMTarget, resource []byte) (*SCIMUser, bool, error) {
	return replaceSCIMRowIfChanged[SCIMUser](tx, scimUsersTable, target, resource)
}

func FindSCIMUsers(tx *storage.Connection, providerID uuid.UUID, query SCIMQuery) ([]SCIMUser, int, error) {
	return findSCIMPage[SCIMUser](tx, scimUsersTable, providerID, query)
}

func ReplaceSCIMUser(tx *storage.Connection, target SCIMTarget, resource []byte) (*SCIMUser, error) {
	return replaceSCIMRow[SCIMUser](tx, scimUsersTable, target, resource)
}

func DeleteSCIMUser(tx *storage.Connection, target SCIMTarget) (*SCIMUser, error) {
	return writeSCIMRow[SCIMUser](tx, scimUsersTable, target, scimWrite{verb: "deleting", sql: "UPDATE %q SET deleted_at = now(), updated_at = clock_timestamp()"})
}

const scimUserLink = "s.sso_provider_id = CASE WHEN i.provider ~ '^sso:[0-9a-fA-F-]{36}$' THEN substr(i.provider, 5)::uuid END AND s.user_name = lower(i.provider_id) AND i.user_id = ?"

func FindSCIMLinkedUser(tx *storage.Connection, row *SCIMUser) (*User, error) {
	identity := &Identity{}
	if err := tx.Q().Where("provider = ? AND lower(provider_id) = ?", "sso:"+row.SSOProviderID.String(), row.UserName).First(identity); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, nil
		}
		return nil, errors.Wrap(err, "error finding SCIM user identity")
	}
	return FindUserByID(tx, identity.UserID)
}

func SoftDeleteSCIMUsersByUserID(tx *storage.Connection, userID uuid.UUID) ([]SCIMUser, error) {
	rows := []SCIMUser{}
	if err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q s SET deleted_at = now(), updated_at = clock_timestamp() FROM %q i WHERE %s AND s.deleted_at IS NULL RETURNING s.%s", scimUsersTable.tableName, Identity{}.TableName(), scimUserLink, strings.ReplaceAll(scimUsersTable.columns, ", ", ", s.")),
		userID,
	).All(&rows); err != nil {
		return nil, errors.Wrap(err, "error deleting SCIM users by user id")
	}
	return rows, nil
}

func IsSCIMManaged(tx *storage.Connection, providerID, userID uuid.UUID) (bool, error) {
	result := struct {
		Managed bool `db:"managed"`
	}{}
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT EXISTS (SELECT 1 FROM %q s, %q i WHERE %s AND s.sso_provider_id = ? AND s.deleted_at IS NULL) AS managed", scimUsersTable.tableName, Identity{}.TableName(), scimUserLink),
		userID, providerID,
	).First(&result); err != nil {
		return false, errors.Wrap(err, "error finding SCIM user")
	}
	return result.Managed, nil
}

func IsSCIMUserDeprovisionedByProvider(tx *storage.Connection, providerID, userID uuid.UUID) (bool, error) {
	return isSCIMUserDeprovisioned(tx, " AND s.sso_provider_id = ?", userID, providerID)
}

func IsSCIMUserDeprovisioned(tx *storage.Connection, userID uuid.UUID) (bool, error) {
	return isSCIMUserDeprovisioned(tx, "", userID)
}

func isSCIMUserDeprovisioned(tx *storage.Connection, where string, args ...any) (bool, error) {
	result := struct {
		Deprovisioned bool `db:"deprovisioned"`
	}{}
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT coalesce(bool_and(s.deleted_at IS NOT NULL OR NOT s.active), false) AS deprovisioned FROM %q s, %q i WHERE %s%s", scimUsersTable.tableName, Identity{}.TableName(), scimUserLink, where),
		args...,
	).First(&result); err != nil {
		return false, errors.Wrap(err, "error finding SCIM user")
	}
	return result.Deprovisioned, nil
}

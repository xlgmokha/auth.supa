package models

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

type SCIMResource struct {
	ID            uuid.UUID       `db:"id"`
	SSOProviderID uuid.UUID       `db:"sso_provider_id"`
	ResourceType  string          `db:"resource_type"`
	Resource      json.RawMessage `db:"resource"`
	CreatedAt     time.Time       `db:"created_at"`
	UpdatedAt     time.Time       `db:"updated_at"`
	DeletedAt     *time.Time      `db:"deleted_at"`
}

func (SCIMResource) TableName() string {
	return "scim_resources"
}

func SCIMResources(tx *storage.Connection, providerID uuid.UUID, resourceType string) *pop.Query {
	return tx.Q().
		Where("sso_provider_id = ?", providerID).
		Where("resource_type = ?", resourceType).
		Where("deleted_at IS NULL")
}

func FindSCIMResource(tx *storage.Connection, providerID uuid.UUID, resourceType string, id uuid.UUID) (*SCIMResource, error) {
	resource := &SCIMResource{}
	if err := SCIMResources(tx, providerID, resourceType).Where("id = ?", id).First(resource); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, SCIMNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding SCIM resource")
	}
	return resource, nil
}

func CreateSCIMResource(tx *storage.Connection, providerID uuid.UUID, resourceType, document string) (*SCIMResource, error) {
	resource := &SCIMResource{}
	err := tx.RawQuery(
		fmt.Sprintf("INSERT INTO %q (id, sso_provider_id, resource_type, resource) VALUES (?, ?, ?, ?::jsonb) RETURNING *", resource.TableName()),
		uuid.Must(uuid.NewV4()), providerID, resourceType, document,
	).First(resource)
	return resource, err
}

func UpdateSCIMResource(tx *storage.Connection, providerID uuid.UUID, resourceType string, id uuid.UUID, document string, version *time.Time) (*SCIMResource, error) {
	resource := &SCIMResource{}
	if err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET resource = ?::jsonb, updated_at = now() WHERE id = ? AND sso_provider_id = ? AND resource_type = ? AND deleted_at IS NULL AND updated_at = COALESCE(?, updated_at) RETURNING *", resource.TableName()),
		document, id, providerID, resourceType, version,
	).First(resource); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, SCIMNotFoundError{}
		}
		return nil, err
	}
	return resource, nil
}

func DeleteSCIMResource(tx *storage.Connection, providerID uuid.UUID, resourceType string, id uuid.UUID, version *time.Time) error {
	count, err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET deleted_at = now() WHERE id = ? AND sso_provider_id = ? AND resource_type = ? AND deleted_at IS NULL AND updated_at = COALESCE(?, updated_at)", SCIMResource{}.TableName()),
		id, providerID, resourceType, version,
	).ExecWithCount()
	if err != nil {
		return errors.Wrap(err, "error deleting SCIM resource")
	}
	if count == 0 {
		return SCIMNotFoundError{}
	}
	return nil
}

package models

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgerrcode"
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

type SCIMScope struct {
	ProviderID   uuid.UUID
	ResourceType string
}

func (s SCIMScope) Query(tx *storage.Connection) *pop.Query {
	return tx.Q().
		Where("sso_provider_id = ?", s.ProviderID).
		Where("resource_type = ?", s.ResourceType).
		Where("deleted_at IS NULL")
}

func (s SCIMScope) Find(tx *storage.Connection, id uuid.UUID) (*SCIMResource, error) {
	resource := &SCIMResource{}
	if err := s.Query(tx).Where("id = ?", id).First(resource); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, SCIMNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding SCIM resource")
	}
	return resource, nil
}

func (s SCIMScope) Create(tx *storage.Connection, document string) (*SCIMResource, error) {
	resource := &SCIMResource{}
	err := tx.RawQuery(
		fmt.Sprintf("INSERT INTO %q (id, sso_provider_id, resource_type, resource) VALUES (?, ?, ?, ?::jsonb) RETURNING *", resource.TableName()),
		uuid.Must(uuid.NewV4()), s.ProviderID, s.ResourceType, document,
	).First(resource)
	return resource, scimUniqueness(err)
}

func (s SCIMScope) Update(tx *storage.Connection, id uuid.UUID, document string, version *time.Time) (*SCIMResource, error) {
	resource := &SCIMResource{}
	if err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET resource = ?::jsonb, updated_at = now() WHERE id = ? AND sso_provider_id = ? AND resource_type = ? AND deleted_at IS NULL AND updated_at = COALESCE(?, updated_at) RETURNING *", resource.TableName()),
		document, id, s.ProviderID, s.ResourceType, version,
	).First(resource); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, SCIMNotFoundError{}
		}
		return nil, scimUniqueness(err)
	}
	return resource, nil
}

func (s SCIMScope) Delete(tx *storage.Connection, id uuid.UUID, version *time.Time) error {
	count, err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET deleted_at = now() WHERE id = ? AND sso_provider_id = ? AND resource_type = ? AND deleted_at IS NULL AND updated_at = COALESCE(?, updated_at)", SCIMResource{}.TableName()),
		id, s.ProviderID, s.ResourceType, version,
	).ExecWithCount()
	if err != nil {
		return errors.Wrap(err, "error deleting SCIM resource")
	}
	if count == 0 {
		return SCIMNotFoundError{}
	}
	return nil
}

func scimUniqueness(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
		return SCIMUniquenessError{}
	}
	return err
}

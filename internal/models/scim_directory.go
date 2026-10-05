package models

import (
	"database/sql"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

// SCIMDirectory is the tenant boundary for SCIM provisioning: its tokens
// authenticate requests and every provisioned resource belongs to it.
type SCIMDirectory struct {
	ID            uuid.UUID  `db:"id" json:"id"`
	SSOProviderID *uuid.UUID `db:"sso_provider_id" json:"sso_provider_id,omitempty"`
	Enabled       bool       `db:"enabled" json:"enabled"`
	Settings      JSONMap    `db:"settings" json:"-"`
	CreatedAt     time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt     time.Time  `db:"updated_at" json:"updated_at"`
}

func (SCIMDirectory) TableName() string {
	return "scim_directories"
}

// SCIMDirectoryNotFoundError is returned when an SSO provider has no SCIM
// directory yet.
type SCIMDirectoryNotFoundError struct{}

func (e SCIMDirectoryNotFoundError) Error() string {
	return "SCIM directory not found"
}

func (e SCIMDirectoryNotFoundError) Is(target error) bool {
	return target == errNotFound
}

// FindSCIMDirectoryBySSOProviderID returns the directory that provisions into
// the SSO provider.
func FindSCIMDirectoryBySSOProviderID(tx *storage.Connection, ssoProviderID uuid.UUID) (*SCIMDirectory, error) {
	var directory SCIMDirectory
	if err := tx.Q().Where("sso_provider_id = ?", ssoProviderID).First(&directory); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, SCIMDirectoryNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding SCIM directory")
	}
	return &directory, nil
}

// EnsureSCIMDirectory returns the SSO provider's directory, creating a
// disabled one if it has none, and locks it for the rest of the transaction.
func EnsureSCIMDirectory(tx *storage.Connection, ssoProviderID uuid.UUID) (*SCIMDirectory, error) {
	if err := tx.RawQuery(
		"insert into scim_directories (id, sso_provider_id) values (?, ?) on conflict (sso_provider_id) do nothing",
		uuid.Must(uuid.NewV7()), ssoProviderID,
	).Exec(); err != nil {
		return nil, errors.Wrap(err, "error creating SCIM directory")
	}

	var directory SCIMDirectory
	if err := tx.RawQuery(
		"select * from scim_directories where sso_provider_id = ? for update", ssoProviderID,
	).First(&directory); err != nil {
		return nil, errors.Wrap(err, "error locking SCIM directory")
	}
	return &directory, nil
}

// SetEnabled turns provisioning on or off, reporting whether the state changed.
// Tokens are never touched.
func (d *SCIMDirectory) SetEnabled(tx *storage.Connection, enabled bool) (bool, error) {
	if d.Enabled == enabled {
		return false, nil
	}
	if err := tx.RawQuery(
		"update scim_directories set enabled = ?, updated_at = now() where id = ? returning *", enabled, d.ID,
	).First(d); err != nil {
		return false, errors.Wrap(err, "error updating SCIM directory")
	}
	return true, nil
}

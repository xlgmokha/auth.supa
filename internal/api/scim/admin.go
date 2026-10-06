package scim

import (
	"database/sql"
	"errors"
	"time"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func SetEnabled(tx *storage.Connection, providerID uuid.UUID, enabled bool) error {
	set := models.DisableSCIM
	if enabled {
		set = models.EnableSCIM
	}
	changed, err := set(tx, providerID)
	if err != nil || !changed {
		return err
	}
	return nil
}

func CreateToken(tx *storage.Connection, provider *models.SSOProvider, expiresAt *time.Time) (*models.SCIMToken, string, error) {
	token, plaintext, err := models.CreateSCIMToken(tx, provider, expiresAt)
	if err != nil {
		return nil, "", err
	}
	return token, plaintext, nil
}

func RevokeToken(tx *storage.Connection, providerID uuid.UUID, tokenID string) (*models.SCIMToken, error) {
	token, revoked, err := revokeToken(tx, providerID, tokenID)
	if err != nil || !revoked {
		return token, err
	}
	return token, nil
}

func revokeToken(tx *storage.Connection, providerID uuid.UUID, tokenID string) (*models.SCIMToken, bool, error) {
	id, err := uuid.FromString(tokenID)
	if err != nil {
		return nil, false, models.SCIMNotFoundError{}
	}
	token, err := models.FindSCIMToken(tx, providerID, id)
	if err != nil || token.IsRevoked() {
		return token, false, err
	}
	if err := token.Revoke(tx); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			token, err = models.FindSCIMToken(tx, providerID, id)
			return token, false, err
		}
		return nil, false, err
	}
	return token, true, nil
}

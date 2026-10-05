package scim

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func SetEnabled(config *conf.GlobalConfiguration, tx *storage.Connection, r *http.Request, actor *models.User, providerID uuid.UUID, enabled bool) error {
	set, action := models.DisableSCIM, models.SCIMDisabledAction
	if enabled {
		set, action = models.EnableSCIM, models.SCIMEnabledAction
	}
	changed, err := set(tx, providerID)
	if err != nil || !changed {
		return err
	}
	return audit(config, tx, r, auditEvent{
		Actor:      actor,
		Action:     action,
		ProviderID: providerID,
		Traits:     map[string]any{},
	})
}

func CreateToken(config *conf.GlobalConfiguration, tx *storage.Connection, r *http.Request, actor *models.User, provider *models.SSOProvider, expiresAt *time.Time) (*models.SCIMToken, string, error) {
	token, plaintext, err := models.CreateSCIMToken(tx, provider, expiresAt)
	if err != nil {
		return nil, "", err
	}
	if err := audit(config, tx, r, tokenEvent(actor, models.SCIMTokenCreatedAction, token)); err != nil {
		return nil, "", err
	}
	return token, plaintext, nil
}

func RevokeToken(config *conf.GlobalConfiguration, tx *storage.Connection, r *http.Request, actor *models.User, providerID uuid.UUID, tokenID string) (*models.SCIMToken, error) {
	token, revoked, err := revokeToken(tx, providerID, tokenID)
	if err != nil || !revoked {
		return token, err
	}
	return token, audit(config, tx, r, tokenEvent(actor, models.SCIMTokenRevokedAction, token))
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

func tokenEvent(actor *models.User, action models.AuditAction, token *models.SCIMToken) auditEvent {
	return auditEvent{
		Actor:      actor,
		Action:     action,
		ProviderID: token.SSOProviderID,
		Traits:     map[string]any{"token_id": token.ID, "token_prefix": token.Prefix, "expires_at": token.ExpiresAt},
	}
}

func Deprovision(config *conf.GlobalConfiguration, tx *storage.Connection, r *http.Request, actor *models.User, provider *models.SSOProvider) error {
	if !config.SSO.SCIM.Enabled {
		return nil
	}
	enabled, err := models.IsSCIMEnabled(tx, provider.ID)
	if err != nil || !enabled {
		return err
	}
	tokens, err := models.FindActiveSCIMTokensBySSOProvider(tx, provider.ID)
	if err != nil {
		return err
	}
	prefixes := make([]string, len(tokens))
	for i, token := range tokens {
		prefixes[i] = token.Prefix
	}
	return audit(config, tx, r, auditEvent{
		Actor:      actor,
		Action:     models.SCIMDisabledAction,
		ProviderID: provider.ID,
		Traits:     map[string]any{"token_prefixes": prefixes},
	})
}

func DeleteUsers(config *conf.GlobalConfiguration, tx *storage.Connection, r *http.Request, actor *models.User, userID uuid.UUID) error {
	rows, err := models.SoftDeleteSCIMUsersByUserID(tx, userID)
	if err != nil {
		return err
	}
	for i := range rows {
		if err := models.RemoveSCIMMemberFromGroups(tx, rows[i].ID); err != nil {
			return err
		}
		event := auditEvent{Actor: actor, Action: models.SCIMUserDeletedAction, ProviderID: rows[i].SSOProviderID, Traits: userTraits(&rows[i], &userID)}
		if err := audit(config, tx, r, event); err != nil {
			return err
		}
	}
	return nil
}

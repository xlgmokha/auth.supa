package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/scim"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

// SCIMSettingsParams turns SCIM provisioning on or off for an SSO provider.
type SCIMSettingsParams struct {
	Enabled *bool `json:"enabled"`
}

// SCIMTokenParams describes a bearer token to create.
type SCIMTokenParams struct {
	Description *string    `json:"description"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

// SCIMStatus is the SCIM state of an SSO provider. Token plaintext is never
// part of it.
type SCIMStatus struct {
	Enabled bool                `json:"enabled"`
	BaseURL string              `json:"base_url"`
	Tokens  []*models.SCIMToken `json:"tokens"`
}

// SCIMTokenResponse is a newly created token, the only response that ever
// carries its plaintext.
type SCIMTokenResponse struct {
	*models.SCIMToken
	Token   string `json:"token"`
	BaseURL string `json:"base_url"`
}

// adminSCIMGet returns whether SCIM is enabled for the SSO provider, its base
// URL and its active tokens.
func (a *API) adminSCIMGet(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	provider := getSSOProvider(ctx)
	db := a.db.WithContext(ctx)
	directory, err := models.FindSCIMDirectoryBySSOProviderID(db, provider.ID)
	switch {
	case models.IsNotFoundError(err):
		directory = nil
	case err != nil:
		return apierrors.NewInternalServerError("Database error finding SCIM directory").WithInternalError(err)
	}
	status, err := a.scimStatus(db, provider, directory)
	if err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, status)
}

// adminSCIMUpdate turns SCIM on or off for the SSO provider. Its tokens are
// never touched, so re-enabling restores service with them.
func (a *API) adminSCIMUpdate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	provider := getSSOProvider(ctx)
	params := &SCIMSettingsParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}
	if params.Enabled == nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "enabled must be true or false")
	}

	var status *SCIMStatus
	err := a.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		directory, err := models.EnsureSCIMDirectory(tx, provider.ID)
		if err != nil {
			return err
		}
		changed, err := directory.SetEnabled(tx, *params.Enabled)
		if err != nil {
			return err
		}
		if changed {
			action := models.SCIMDisabledAction
			if *params.Enabled {
				action = models.SCIMEnabledAction
			}
			if err := a.auditSCIM(r, tx, action, provider, nil); err != nil {
				return err
			}
		}
		status, err = a.scimStatus(tx, provider, directory)
		return err
	})
	if err != nil {
		return apierrors.NewInternalServerError("Database error updating SCIM").WithInternalError(err)
	}
	return sendJSON(w, http.StatusOK, status)
}

// adminSCIMTokenCreate creates a bearer token. Its plaintext is returned now
// and never again.
func (a *API) adminSCIMTokenCreate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	provider := getSSOProvider(ctx)
	params := &SCIMTokenParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}
	if params.ExpiresAt != nil && !params.ExpiresAt.After(a.Now()) {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "expires_at must be in the future")
	}

	var response *SCIMTokenResponse
	err := a.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		directory, err := models.EnsureSCIMDirectory(tx, provider.ID)
		if err != nil {
			return err
		}
		token, plaintext, err := models.NewSCIMToken(tx, directory.ID, params.Description, params.ExpiresAt)
		if err != nil {
			return err
		}
		if err := a.auditSCIM(r, tx, models.SCIMTokenCreatedAction, provider, token); err != nil {
			return err
		}
		response = &SCIMTokenResponse{SCIMToken: token, Token: plaintext, BaseURL: scim.BaseURL(a.config)}
		return nil
	})
	if err != nil {
		return apierrors.NewInternalServerError("Database error creating SCIM token").WithInternalError(err)
	}
	return sendJSON(w, http.StatusCreated, response)
}

// adminSCIMTokenRevoke revokes a bearer token by id. Revoking a revoked token
// returns it unchanged.
func (a *API) adminSCIMTokenRevoke(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	provider := getSSOProvider(ctx)
	notFound := apierrors.NewNotFoundError(apierrors.ErrorCodeSCIMTokenNotFound, "SCIM token not found")
	id, err := uuid.FromString(chi.URLParam(r, "token_id"))
	if err != nil {
		return notFound
	}

	var token *models.SCIMToken
	err = a.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		directory, err := models.FindSCIMDirectoryBySSOProviderID(tx, provider.ID)
		if err != nil {
			return err
		}
		if token, err = models.FindSCIMToken(tx, directory.ID, id); err != nil {
			return err
		}
		revoked, err := token.Revoke(tx)
		if err != nil || !revoked {
			return err
		}
		return a.auditSCIM(r, tx, models.SCIMTokenRevokedAction, provider, token)
	})
	switch {
	case models.IsNotFoundError(err):
		return notFound
	case err != nil:
		return apierrors.NewInternalServerError("Database error revoking SCIM token").WithInternalError(err)
	}
	return sendJSON(w, http.StatusOK, token)
}

// scimStatus reports the provider's SCIM state; directory is nil for a
// provider that never had one. Routes are only served while SCIM is enabled
// for the project.
func (a *API) scimStatus(tx *storage.Connection, provider *models.SSOProvider, directory *models.SCIMDirectory) (*SCIMStatus, error) {
	status := &SCIMStatus{BaseURL: scim.BaseURL(a.config), Tokens: []*models.SCIMToken{}}
	if directory == nil {
		return status, nil
	}
	status.Enabled = provider.IsEnabled() && directory.Enabled
	var err error
	if status.Tokens, err = models.FindActiveSCIMTokens(tx, directory.ID); err != nil {
		return nil, apierrors.NewInternalServerError("Database error listing SCIM tokens").WithInternalError(err)
	}
	return status, nil
}

func (a *API) auditSCIM(r *http.Request, tx *storage.Connection, action models.AuditAction, provider *models.SSOProvider, token *models.SCIMToken) error {
	traits := map[string]interface{}{"sso_provider_id": provider.ID}
	if token != nil {
		traits["token_id"] = token.ID
		traits["prefix"] = token.Prefix
	}
	return models.NewAuditLogEntry(a.config.AuditLog, r, tx, getAdminUser(r.Context()), action, utilities.GetIPAddress(r), traits)
}

package api

import (
	"database/sql"
	"errors"
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

type AdminSCIMTokenCreateParams struct {
	ExpiresAt *time.Time `json:"expires_at"`
}

type AdminSCIMTokenCreateResponse struct {
	BaseURL string `json:"base_url"`
	Token   string `json:"token"`
	*models.SCIMToken
}

type AdminSCIMTokenListResponse struct {
	Tokens []models.SCIMToken `json:"tokens"`
}

type AdminSCIMStatusResponse struct {
	Enabled bool               `json:"enabled"`
	BaseURL string             `json:"base_url"`
	Tokens  []models.SCIMToken `json:"tokens"`
}

func (a *API) adminSCIMGet(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	return a.sendSCIMStatus(w, a.db.WithContext(ctx), getSSOProvider(ctx))
}

func (a *API) adminSCIMEnable(w http.ResponseWriter, r *http.Request) error {
	return a.setSCIM(w, r, true)
}

func (a *API) adminSCIMDisable(w http.ResponseWriter, r *http.Request) error {
	return a.setSCIM(w, r, false)
}

func (a *API) setSCIM(w http.ResponseWriter, r *http.Request, enabled bool) error {
	set, action, verb := models.DisableSCIM, models.SCIMDisabledAction, "disabling"
	if enabled {
		set, action, verb = models.EnableSCIM, models.SCIMEnabledAction, "enabling"
	}
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	if err := db.Transaction(func(tx *storage.Connection) error {
		changed, err := set(tx, provider.ID)
		if err != nil || !changed {
			return err
		}
		return scim.Audit(a.config, tx, r, scim.AuditEvent{
			Actor:      getAdminUser(ctx),
			Action:     action,
			ProviderID: provider.ID,
			Traits:     map[string]any{},
		})
	}); err != nil {
		return apierrors.NewInternalServerError("Error %s SCIM", verb).WithInternalError(err)
	}

	return a.sendSCIMStatus(w, db, provider)
}

func (a *API) adminSCIMTokensCreate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	params := &AdminSCIMTokenCreateParams{}
	if body, err := utilities.GetBodyBytes(r); err != nil || len(body) > 0 {
		if err := retrieveRequestParams(r, params); err != nil {
			return err
		}
	}

	var token *models.SCIMToken
	var plaintext string
	err := db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if token, plaintext, terr = models.CreateSCIMToken(tx, provider, params.ExpiresAt); terr != nil {
			return terr
		}
		return scim.Audit(a.config, tx, r, scimTokenEvent(r, models.SCIMTokenCreatedAction, token))
	})
	if err != nil {
		if errors.Is(err, models.ErrSCIMTokenExpiry) {
			return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "expires_at must be in the future")
		}
		return apierrors.NewInternalServerError("Error creating SCIM token").WithInternalError(err)
	}

	return sendJSON(w, http.StatusCreated, &AdminSCIMTokenCreateResponse{
		BaseURL:   scim.BaseURL(a.config),
		Token:     plaintext,
		SCIMToken: token,
	})
}

func (a *API) adminSCIMTokensList(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	provider := getSSOProvider(ctx)

	tokens, err := models.FindSCIMTokensBySSOProvider(a.db.WithContext(ctx), provider.ID)
	if err != nil {
		return apierrors.NewInternalServerError("Error listing SCIM tokens").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, &AdminSCIMTokenListResponse{Tokens: tokens})
}

func (a *API) adminSCIMTokensRevoke(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	var token *models.SCIMToken
	err := db.Transaction(func(tx *storage.Connection) error {
		var revoked bool
		var terr error
		if token, revoked, terr = revokeSCIMToken(tx, provider.ID, chi.URLParam(r, "token_id")); terr != nil || !revoked {
			return terr
		}
		return scim.Audit(a.config, tx, r, scimTokenEvent(r, models.SCIMTokenRevokedAction, token))
	})
	if err != nil {
		if models.IsNotFoundError(err) {
			return apierrors.NewNotFoundError(apierrors.ErrorCodeSCIMTokenNotFound, "SCIM token not found")
		}
		return apierrors.NewInternalServerError("Error revoking SCIM token").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, token)
}

func revokeSCIMToken(tx *storage.Connection, providerID uuid.UUID, tokenID string) (*models.SCIMToken, bool, error) {
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

func scimTokenEvent(r *http.Request, action models.AuditAction, token *models.SCIMToken) scim.AuditEvent {
	return scim.AuditEvent{
		Actor:      getAdminUser(r.Context()),
		Action:     action,
		ProviderID: token.SSOProviderID,
		Traits:     map[string]any{"token_id": token.ID, "token_prefix": token.Prefix, "expires_at": token.ExpiresAt},
	}
}

func (a *API) sendSCIMStatus(w http.ResponseWriter, db *storage.Connection, provider *models.SSOProvider) error {
	tokens, err := models.FindActiveSCIMTokensBySSOProvider(db, provider.ID)
	if err != nil {
		return apierrors.NewInternalServerError("Error finding SCIM tokens").WithInternalError(err)
	}
	enabled := false
	if provider.IsEnabled() {
		if enabled, err = models.IsSCIMEnabled(db, provider.ID); err != nil {
			return apierrors.NewInternalServerError("Error finding SCIM settings").WithInternalError(err)
		}
	}

	return sendJSON(w, http.StatusOK, &AdminSCIMStatusResponse{
		Enabled: enabled,
		BaseURL: scim.BaseURL(a.config),
		Tokens:  tokens,
	})
}

func (a *API) deprovisionSCIM(tx *storage.Connection, r *http.Request, provider *models.SSOProvider) error {
	if !a.config.SSO.SCIM.Enabled {
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
	return scim.Audit(a.config, tx, r, scim.AuditEvent{
		Actor:      getAdminUser(r.Context()),
		Action:     models.SCIMDisabledAction,
		ProviderID: provider.ID,
		Traits:     map[string]any{"token_prefixes": prefixes},
	})
}

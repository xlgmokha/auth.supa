package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/api/scim"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

type scimUserSync struct {
	api *API
}

func (s *scimUserSync) BeforeUserProvisioned(r *http.Request, db *storage.Connection, providerID uuid.UUID, profile scim.Profile) error {
	if !s.api.hooksMgr.Enabled(v0hooks.BeforeUserCreated) {
		return nil
	}
	providerType := scim.ProviderType(providerID)
	decision, err := s.decideAccountLinking(db, providerType, profile)
	if err != nil || decision.Decision != models.CreateAccount {
		return scim.Error(err)
	}
	candidate, err := s.newUser(providerType, decision, profile)
	if err != nil {
		return scim.Error(err)
	}
	err = s.api.triggerBeforeUserCreated(r, db, candidate)
	var httpErr *apierrors.HTTPError
	if errors.As(err, &httpErr) && httpErr.HTTPStatus < http.StatusInternalServerError {
		return scim.ErrStatus(httpErr.HTTPStatus, httpErr.Message)
	}
	return scim.Error(err)
}

func (s *scimUserSync) UserProvisioned(tx *storage.Connection, row *models.SCIMUser, profile scim.Profile) (*models.User, error) {
	providerType := scim.ProviderType(row.SSOProviderID)
	decision, err := s.decideAccountLinking(tx, providerType, profile)
	if err != nil {
		return nil, err
	}
	var linked, created *models.User
	switch decision.Decision {
	case models.CreateAccount:
		candidate, err := s.newUser(providerType, decision, profile)
		if err != nil {
			return nil, err
		}
		if created, err = s.api.signupNewUser(tx, candidate); err != nil {
			return nil, err
		}
		if _, err := s.api.createNewIdentity(tx, created, providerType, profile.IdentityData()); err != nil {
			return nil, err
		}
		linked = created
	case models.AccountExists, models.LinkAccount:
		linked = decision.User
		if !linked.IsSSOUser {
			return nil, scim.ErrUniqueness("user is not an SSO user")
		}
		if decision.Decision == models.LinkAccount {
			if _, err := s.api.createNewIdentity(tx, linked, providerType, profile.IdentityData()); err != nil {
				return nil, err
			}
			if err := linked.UpdateAppMetaDataProviders(tx); err != nil {
				return nil, err
			}
		}
	case models.MultipleAccounts:
		return nil, scim.ErrUniqueness("multiple users share this email in the SSO provider")
	default:
		return nil, apierrors.NewInternalServerError("Unknown automatic linking decision: %v", decision.Decision)
	}
	if !row.Active() {
		return created, models.Logout(tx, linked.ID)
	}
	return created, nil
}

func (s *scimUserSync) UserUpdated(tx *storage.Connection, r *http.Request, update scim.UserUpdate) error {
	linked, err := models.FindSCIMLinkedUser(tx, update.Old)
	if err != nil || linked == nil {
		return err
	}
	if err := renameSCIMIdentity(tx, r, linked, update); err != nil {
		return err
	}
	if err := changeSCIMEmail(tx, linked, update); err != nil {
		return err
	}
	if update.Old.Active() && !update.Row.Active() {
		return models.Logout(tx, linked.ID)
	}
	return nil
}

func renameSCIMIdentity(tx *storage.Connection, r *http.Request, linked *models.User, update scim.UserUpdate) error {
	var stored struct {
		UserName string `json:"userName"`
	}
	if err := json.Unmarshal(update.Old.Resource, &stored); err != nil {
		return err
	}
	profile := update.Profile
	if stored.UserName == profile.UserName {
		return nil
	}
	data := map[string]any{scim.ClaimSub: profile.UserName}
	if profile.Email != "" {
		data[scim.ClaimEmail] = profile.Email
	}
	err := models.RenameSCIMIdentity(tx, models.SCIMIdentityRename{
		UserID:   linked.ID,
		Provider: scim.ProviderType(update.Row.SSOProviderID),
		From:     stored.UserName,
		To:       profile.UserName,
		Data:     data,
	})
	if models.IsNotFoundError(err) {
		observability.GetLogEntry(r).Entry.WithField("user_id", linked.ID).WithField("sso_provider_id", update.Row.SSOProviderID).Warn("scim: identity not found, rename skipped")
		return nil
	}
	return err
}

func changeSCIMEmail(tx *storage.Connection, linked *models.User, update scim.UserUpdate) error {
	email := update.Profile.Email
	if email == "" || strings.EqualFold(email, linked.GetEmail()) {
		return nil
	}
	if err := models.ChangeSCIMIdentityEmail(tx, models.SCIMIdentityEmailChange{
		UserID:   linked.ID,
		Provider: scim.ProviderType(update.Row.SSOProviderID),
		Subject:  update.Profile.UserName,
		Email:    email,
	}); err != nil {
		return err
	}
	if err := linked.SetEmail(tx, strings.ToLower(email)); err != nil {
		return err
	}
	if err := linked.ClearAllPendingTokens(tx); err != nil {
		return err
	}
	return linked.UpdateUserMetaData(tx, map[string]any{scim.ClaimEmail: email})
}

func (s *scimUserSync) UserDeleted(tx *storage.Connection, row *models.SCIMUser) error {
	linked, err := models.FindSCIMLinkedUser(tx, row)
	if err != nil || linked == nil {
		return err
	}
	return models.Logout(tx, linked.ID)
}

func (s *scimUserSync) AfterUserProvisioned(r *http.Request, db *storage.Connection, created *models.User) {
	if created == nil {
		return
	}
	if err := s.api.triggerAfterUserCreated(r, db, created); err != nil {
		observability.GetLogEntry(r).Entry.WithError(err).WithField("user_id", created.ID).Error("scim: after user created hook failed")
	}
}

func (s *scimUserSync) decideAccountLinking(conn *storage.Connection, providerType string, profile scim.Profile) (models.AccountLinkingResult, error) {
	emails := []provider.Email{{Email: profile.Email, Verified: true, Primary: true}}
	return models.DetermineAccountLinking(conn, s.api.config, emails, s.api.config.JWT.Aud, providerType, profile.UserName)
}

func (s *scimUserSync) newUser(providerType string, decision models.AccountLinkingResult, profile scim.Profile) (*models.User, error) {
	params := &SignupParams{
		Provider: providerType,
		Email:    decision.CandidateEmail.Email,
		Aud:      s.api.config.JWT.Aud,
		Data:     profile.IdentityData(),
	}
	candidate, err := params.ToUserModel(true)
	if err != nil {
		return nil, err
	}
	now := s.api.Now()
	candidate.EmailConfirmedAt = &now
	return candidate, nil
}

package api

import (
	"errors"
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func (s *scimUserRepository) provisionAuthUser(tx *storage.Connection, row *models.SCIMUser, user *core.User) (*models.User, error) {
	providerType := scimProviderType(row.SSOProviderID)
	decision, err := s.decideAccountLinking(tx, providerType, user)
	if err != nil {
		return nil, err
	}
	var linked, created *models.User
	switch decision.Decision {
	case models.CreateAccount:
		candidate, err := s.newUser(providerType, decision, user)
		if err != nil {
			return nil, err
		}
		if created, err = s.api.signupNewUser(tx, candidate); err != nil {
			return nil, err
		}
		if _, err := s.api.createNewIdentity(tx, created, providerType, scimIdentityData(user)); err != nil {
			return nil, err
		}
		linked = created
	case models.AccountExists, models.LinkAccount:
		linked = decision.User
		if !linked.IsSSOUser {
			return nil, scimerrors.ErrUniqueness("user is not an SSO user")
		}
		if decision.Decision == models.LinkAccount {
			if _, err := s.api.createNewIdentity(tx, linked, providerType, scimIdentityData(user)); err != nil {
				return nil, err
			}
			if err := linked.UpdateAppMetaDataProviders(tx); err != nil {
				return nil, err
			}
		}
	case models.MultipleAccounts:
		return nil, scimerrors.ErrUniqueness("multiple users share this email in the SSO provider")
	default:
		return nil, apierrors.NewInternalServerError("Unknown automatic linking decision: %v", decision.Decision)
	}
	if created != nil {
		err = models.LinkNewSCIMUser(tx, row, linked.ID)
	} else {
		err = models.LinkSCIMUser(tx, row, linked.ID)
	}
	if err == nil && !row.Active {
		err = models.Logout(tx, linked.ID)
	}
	return created, err
}

func (s *scimUserRepository) beforeProvision(r *http.Request, db *storage.Connection, providerID uuid.UUID, user *core.User) error {
	if scimUserEmail(user) == "" {
		return scimerrors.ErrInvalidValue(`"emails" or an email address "userName" is required`)
	}
	if !s.api.hooksMgr.Enabled(v0hooks.BeforeUserCreated) {
		return nil
	}
	providerType := scimProviderType(providerID)
	decision, err := s.decideAccountLinking(db, providerType, user)
	if err != nil || decision.Decision != models.CreateAccount {
		return scimError(err)
	}
	candidate, err := s.newUser(providerType, decision, user)
	if err != nil {
		return scimError(err)
	}
	err = s.api.triggerBeforeUserCreated(r, db, candidate)
	var httpErr *apierrors.HTTPError
	if errors.As(err, &httpErr) && httpErr.HTTPStatus < http.StatusInternalServerError {
		return scimerrors.NewError(httpErr.HTTPStatus, "", httpErr.Message)
	}
	return scimError(err)
}

func (s *scimUserRepository) decideAccountLinking(conn *storage.Connection, providerType string, user *core.User) (models.AccountLinkingResult, error) {
	emails := []provider.Email{{Email: scimUserEmail(user), Verified: true, Primary: true}}
	return models.DetermineAccountLinking(conn, s.api.config, emails, s.api.config.JWT.Aud, providerType, user.UserName)
}

func (s *scimUserRepository) newUser(providerType string, decision models.AccountLinkingResult, user *core.User) (*models.User, error) {
	params := &SignupParams{
		Provider: providerType,
		Email:    decision.CandidateEmail.Email,
		Aud:      s.api.config.JWT.Aud,
		Data:     scimIdentityData(user),
	}
	candidate, err := params.ToUserModel(true)
	if err != nil {
		return nil, err
	}
	now := s.api.Now()
	candidate.EmailConfirmedAt = &now
	return candidate, nil
}

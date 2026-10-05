package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

type scimUserEvents interface {
	BeforeUserProvisioned(r *http.Request, db *storage.Connection, providerID uuid.UUID, user *core.User) error
	UserProvisioned(tx *storage.Connection, row *models.SCIMUser, user *core.User) (*models.User, error)
	UserUpdated(tx *storage.Connection, r *http.Request, update scimUserUpdate) error
	UserDeleted(tx *storage.Connection, row *models.SCIMUser) error
	AfterUserProvisioned(r *http.Request, db *storage.Connection, created *models.User)
}

type scimUserUpdate struct {
	old  *models.SCIMUser
	row  *models.SCIMUser
	user *core.User
}

type scimUserSync struct {
	api *API
}

func (s *scimUserSync) BeforeUserProvisioned(r *http.Request, db *storage.Connection, providerID uuid.UUID, user *core.User) error {
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

func (s *scimUserSync) UserProvisioned(tx *storage.Connection, row *models.SCIMUser, user *core.User) (*models.User, error) {
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
	if !row.Active() {
		return created, models.Logout(tx, linked.ID)
	}
	return created, nil
}

func (s *scimUserSync) UserUpdated(tx *storage.Connection, r *http.Request, update scimUserUpdate) error {
	old, row, user := update.old, update.row, update.user
	linked, err := models.FindSCIMLinkedUser(tx, old)
	if err != nil || linked == nil {
		return err
	}
	var stored struct {
		UserName string `json:"userName"`
	}
	if err := json.Unmarshal(old.Resource, &stored); err != nil {
		return err
	}
	providerType := scimProviderType(row.SSOProviderID)
	email := scimUserEmail(user)
	if stored.UserName != user.UserName {
		data := map[string]any{scimClaimSub: user.UserName}
		if email != "" {
			data[scimClaimEmail] = email
		}
		err := models.RenameSCIMIdentity(tx, models.SCIMIdentityRename{
			UserID:   linked.ID,
			Provider: providerType,
			From:     stored.UserName,
			To:       user.UserName,
			Data:     data,
		})
		if models.IsNotFoundError(err) {
			observability.GetLogEntry(r).Entry.WithField("user_id", linked.ID).WithField("sso_provider_id", row.SSOProviderID).Warn("scim: identity not found, rename skipped")
		} else if err != nil {
			return err
		}
	}
	if email != "" && !strings.EqualFold(email, linked.GetEmail()) {
		if err := models.ChangeSCIMIdentityEmail(tx, models.SCIMIdentityEmailChange{
			UserID:   linked.ID,
			Provider: providerType,
			Subject:  user.UserName,
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
		if err := linked.UpdateUserMetaData(tx, map[string]any{scimClaimEmail: email}); err != nil {
			return err
		}
	}
	if old.Active() && !row.Active() {
		return models.Logout(tx, linked.ID)
	}
	return nil
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

func (s *scimUserSync) decideAccountLinking(conn *storage.Connection, providerType string, user *core.User) (models.AccountLinkingResult, error) {
	emails := []provider.Email{{Email: scimUserEmail(user), Verified: true, Primary: true}}
	return models.DetermineAccountLinking(conn, s.api.config, emails, s.api.config.JWT.Aud, providerType, user.UserName)
}

func (s *scimUserSync) newUser(providerType string, decision models.AccountLinkingResult, user *core.User) (*models.User, error) {
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

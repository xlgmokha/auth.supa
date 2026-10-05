package scim

import (
	"net/mail"
	"strings"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// userHooks keeps each SCIM User linked to the auth.users account it
// provisions, and that account in step with the User's lifecycle.
type userHooks struct {
	config *conf.GlobalConfiguration
}

// afterCreate links the User to an account. An account the SSO provider
// already signed in, or a User deleted earlier, is reused; otherwise an SSO
// account is created with the same identity a SAML sign-in would resolve.
func (h userHooks) afterCreate(tx *storage.Connection, tenant *Tenant, row *models.SCIMResource) error {
	document := core.Object(row.Resource)
	userName, _ := document.Get("userName").(string)
	provider := "sso:" + tenant.SSOProviderID.String()

	identity, err := models.FindIdentityByIdAndProvider(tx, userName, provider)
	switch {
	case err == nil:
		return row.SetUserID(tx, identity.UserID)
	case !models.IsNotFoundError(err):
		return err
	}

	email := emailOf(document)
	user, err := models.NewUser("", email, "", h.config.JWT.Aud, nil)
	if err != nil {
		return err
	}
	user.IsSSOUser = true
	if err := tx.Create(user); err != nil {
		return err
	}
	if err := user.SetRole(tx, h.config.JWT.DefaultGroupName); err != nil {
		return err
	}
	if email != "" {
		if err := user.Confirm(tx); err != nil {
			return err
		}
	}
	identityData := map[string]interface{}{"sub": userName}
	if email != "" {
		identityData["email"] = email
		identityData["email_verified"] = true
	}
	identity, err = models.NewIdentity(user, provider, identityData)
	if err != nil {
		return err
	}
	if err := tx.Create(identity); err != nil {
		return err
	}
	return row.SetUserID(tx, user.ID)
}

// afterUpdate keeps the account's email in step with the User, and revokes
// every session and refresh token when the User is deactivated.
// Reactivating restores nothing: the user signs in again.
func (h userHooks) afterUpdate(tx *storage.Connection, tenant *Tenant, before, after *models.SCIMResource) error {
	if after.UserID == nil {
		return nil
	}
	user, err := models.FindUserByID(tx, *after.UserID)
	if err != nil {
		return err
	}
	if email := emailOf(core.Object(after.Resource)); email != "" && !strings.EqualFold(email, user.GetEmail()) {
		if err := user.SetEmail(tx, strings.ToLower(email)); err != nil {
			return err
		}
		identities, err := models.FindIdentitiesByUserID(tx, user.ID)
		if err != nil {
			return err
		}
		provider := "sso:" + tenant.SSOProviderID.String()
		for _, identity := range identities {
			if identity.Provider != provider {
				continue
			}
			if err := identity.UpdateIdentityData(tx, map[string]interface{}{"email": strings.ToLower(email)}); err != nil {
				return err
			}
		}
	}
	if isActive(before) && !isActive(after) {
		return models.Logout(tx, user.ID)
	}
	return nil
}

// afterDelete revokes every session and refresh token of the account. The
// account itself is kept.
func (h userHooks) afterDelete(tx *storage.Connection, tenant *Tenant, row *models.SCIMResource) error {
	if row.UserID == nil {
		return nil
	}
	return models.Logout(tx, *row.UserID)
}

// isActive reads the User's active attribute, which defaults to true.
func isActive(row *models.SCIMResource) bool {
	active, ok := core.Object(row.Resource).Get("active").(bool)
	return !ok || active
}

// emailOf is the account email for a User: its primary email, else its first
// email, else its userName when that is an email address.
func emailOf(document core.Object) string {
	elements, _ := document.Get("emails").([]any)
	first := ""
	for _, element := range elements {
		object, ok := element.(map[string]any)
		if !ok {
			continue
		}
		value, _ := core.Object(object).Get("value").(string)
		if primary, _ := core.Object(object).Get("primary").(bool); primary && value != "" {
			return value
		}
		if first == "" {
			first = value
		}
	}
	if first != "" {
		return first
	}
	userName, _ := document.Get("userName").(string)
	if address, err := mail.ParseAddress(userName); err == nil && address.Address == userName {
		return userName
	}
	return ""
}

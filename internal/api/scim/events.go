package scim

import (
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type UserEvents interface {
	BeforeUserProvisioned(r *http.Request, db *storage.Connection, providerID uuid.UUID, profile Profile) error
	UserProvisioned(tx *storage.Connection, row *models.SCIMUser, profile Profile) (*models.User, error)
	UserUpdated(tx *storage.Connection, r *http.Request, update UserUpdate) error
	UserDeleted(tx *storage.Connection, row *models.SCIMUser) error
	AfterUserProvisioned(r *http.Request, db *storage.Connection, created *models.User)
}

type UserUpdate struct {
	Old     *models.SCIMUser
	Row     *models.SCIMUser
	Profile Profile
}

type Profile struct {
	UserName string
	Email    string
}

func newProfile(user *core.User) Profile {
	return Profile{UserName: user.UserName, Email: userEmail(user)}
}

func (p Profile) IdentityData() map[string]any {
	return map[string]any{
		ClaimSub:               p.UserName,
		ClaimEmail:             p.Email,
		scimClaimEmailVerified: true,
	}
}

package scim

import (
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type UserEvents interface {
	BeforeUserProvisioned(r *http.Request, db *storage.Connection, providerID uuid.UUID, user *core.User) error
	UserProvisioned(tx *storage.Connection, row *models.SCIMUser, user *core.User) (*models.User, error)
	UserUpdated(tx *storage.Connection, r *http.Request, update UserUpdate) error
	UserDeleted(tx *storage.Connection, row *models.SCIMUser) error
	AfterUserProvisioned(r *http.Request, db *storage.Connection, created *models.User)
}

type UserUpdate struct {
	Old  *models.SCIMUser
	Row  *models.SCIMUser
	User *core.User
}

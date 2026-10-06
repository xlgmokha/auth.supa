package scim

import (
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

type auditEvent struct {
	Actor      *models.User
	Action     models.AuditAction
	ProviderID uuid.UUID
	Traits     map[string]any
}

func audit(config *conf.GlobalConfiguration, tx *storage.Connection, r *http.Request, event auditEvent) error {
	event.Traits["sso_provider_id"] = event.ProviderID
	event.Traits["outcome"] = "success"
	return models.NewAuditLogEntry(config.AuditLog, r, tx, event.Actor, event.Action, utilities.GetIPAddress(r), event.Traits)
}

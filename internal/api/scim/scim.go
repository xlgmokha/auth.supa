package scim

import (
	"context"
	"net/http"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/ctxkey"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

var tokenKey = ctxkey.New[*models.SCIMToken]("scim_token")

func BaseURL(config *conf.GlobalConfiguration) string {
	return strings.TrimRight(config.API.ExternalURL, "/") + BasePath
}

func SendTooManyRequests(w http.ResponseWriter) error {
	return protocol.SendError(w, scimerrors.NewError(http.StatusTooManyRequests, "", "Request rate limit reached"))
}

type auditEvent struct {
	Actor      *models.User
	Action     models.AuditAction
	ProviderID uuid.UUID
	Traits     map[string]any
}

func audit(config *conf.GlobalConfiguration, tx *storage.Connection, r *http.Request, event auditEvent) error {
	event.Traits["sso_provider_id"] = event.ProviderID
	return models.NewAuditLogEntry(config.AuditLog, r, tx, event.Actor, event.Action, utilities.GetIPAddress(r), event.Traits)
}

func newTokenValidator(db *storage.Connection) server.TokenValidator {
	return func(ctx context.Context, candidate string) (context.Context, error) {
		token, err := models.AuthenticateSCIMToken(db.WithContext(ctx), candidate)
		if models.IsNotFoundError(err) {
			return ctx, server.ErrInvalidToken
		}
		if err != nil {
			return ctx, err
		}
		return tokenKey.WithValue(ctx, token), nil
	}
}

func newAuthenticate(db *storage.Connection) func(http.Handler) http.Handler {
	return server.RequireBearerToken(newTokenValidator(db))
}

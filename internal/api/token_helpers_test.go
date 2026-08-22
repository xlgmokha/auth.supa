package api

import (
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/tokens"
)

// generateAccessToken is a test-only shorthand for tokenService.GenerateAccessToken.
func (a *API) generateAccessToken(r *http.Request, tx *storage.Connection, user *models.User, sessionId *uuid.UUID, authenticationMethod models.AuthenticationMethod) (string, int64, error) {
	return a.tokenService.GenerateAccessToken(r, tx, tokens.GenerateAccessTokenParams{
		User:                 user,
		SessionID:            sessionId,
		AuthenticationMethod: authenticationMethod,
	})
}

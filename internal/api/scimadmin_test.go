package api

import (
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/storage"
)

func (ts *SCIMTestSuite) TestAdminSCIMStatus() {
	w := ts.admin(http.MethodPost, "/admin/sso/providers", map[string]any{
		"type":         "saml",
		"metadata_xml": validSAMLIDPMetadata("https://idp.example.com/new"),
	})
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	providerID := decodeJSON(ts.T(), w)["id"].(string)

	// A provider that never enabled SCIM has no directory yet.
	w = ts.admin(http.MethodGet, "/admin/sso/providers/"+providerID+"/scim", nil)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.JSONEq(ts.T(), `{"enabled":false,"base_url":"http://localhost:9999/scim/v2","tokens":[]}`, w.Body.String())

	w = ts.admin(http.MethodGet, ts.scimAdminPath(ts.A.ID, ""), nil)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	status := decodeJSON(ts.T(), w)
	require.Equal(ts.T(), true, status["enabled"])
	require.Len(ts.T(), status["tokens"], 1)
	token := status["tokens"].([]any)[0].(map[string]any)
	require.Equal(ts.T(), ts.A.Token[:12], token["prefix"])
	require.NotContains(ts.T(), token, "token")
	require.NotContains(ts.T(), w.Body.String(), ts.A.Token, "the plaintext is never returned again")
	for _, field := range []string{"id", "description", "created_at", "expires_at", "revoked_at", "last_used_at"} {
		require.Contains(ts.T(), token, field)
	}

	// A disabled SSO provider reports SCIM as disabled.
	require.NoError(ts.T(), ts.API.db.RawQuery("update sso_providers set disabled = true where id = ?", ts.A.ID).Exec())
	require.Equal(ts.T(), false, decodeJSON(ts.T(), ts.admin(http.MethodGet, ts.scimAdminPath(ts.A.ID, ""), nil))["enabled"])

	// An unknown provider is not found, by id or resource id.
	unknown := ts.admin(http.MethodGet, "/admin/sso/providers/"+uuid.Must(uuid.NewV4()).String()+"/scim", nil)
	require.Equal(ts.T(), http.StatusNotFound, unknown.Code)
	require.Equal(ts.T(), "sso_provider_not_found", decodeJSON(ts.T(), unknown)["error_code"])
}

func (ts *SCIMTestSuite) TestAdminSCIMEnableDisable() {
	path := ts.scimAdminPath(ts.A.ID, "")

	// Enabling an enabled provider is a no-op.
	w := ts.admin(http.MethodPut, path, map[string]any{"enabled": true})
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Len(ts.T(), ts.auditEntries("scim_enabled"), 2, "one per provider set up, none for the no-op")

	// Disabling stops every SCIM request except discovery, and touches no token.
	w = ts.admin(http.MethodPut, path, map[string]any{"enabled": false})
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	status := decodeJSON(ts.T(), w)
	require.Equal(ts.T(), false, status["enabled"])
	require.Len(ts.T(), status["tokens"], 1)
	ts.requireSCIMError(ts.scim(ts.A, http.MethodGet, "/Users", nil), http.StatusForbidden, "")
	require.Equal(ts.T(), http.StatusOK, ts.scim(ts.A, http.MethodGet, "/ServiceProviderConfig", nil).Code)
	require.Equal(ts.T(), http.StatusOK, ts.scim(ts.B, http.MethodGet, "/Users", nil).Code)

	w = ts.admin(http.MethodPut, path, map[string]any{"enabled": false})
	require.Equal(ts.T(), http.StatusOK, w.Code)
	disabled := ts.auditEntries("scim_disabled")
	require.Len(ts.T(), disabled, 1)
	require.Equal(ts.T(), "supabase_admin", disabled[0]["actor_username"])
	require.Equal(ts.T(), ts.A.ID.String(), disabled[0]["traits"].(map[string]any)["sso_provider_id"])

	// Re-enabling restores service with the existing token.
	w = ts.admin(http.MethodPut, path, map[string]any{"enabled": true})
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.Equal(ts.T(), http.StatusOK, ts.scim(ts.A, http.MethodGet, "/Users", nil).Code)
	require.Len(ts.T(), ts.auditEntries("scim_enabled"), 3)

	for _, body := range []any{map[string]any{}, map[string]any{"enabled": "yes"}, "not json"} {
		w = ts.admin(http.MethodPut, path, body)
		require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())
	}
}

func (ts *SCIMTestSuite) TestAdminSCIMTokens() {
	path := ts.scimAdminPath(ts.A.ID, "/tokens")
	expiresAt := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)

	w := ts.admin(http.MethodPost, path, map[string]any{"description": "Okta production", "expires_at": expiresAt})
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	created := decodeJSON(ts.T(), w)
	plaintext := created["token"].(string)
	require.Regexp(ts.T(), regexp.MustCompile(`^scim_[0-9a-f]{40}$`), plaintext)
	require.Equal(ts.T(), plaintext[:12], created["prefix"])
	require.Equal(ts.T(), "Okta production", created["description"])
	require.Equal(ts.T(), "http://localhost:9999/scim/v2", created["base_url"])
	require.Equal(ts.T(), expiresAt.Format(time.RFC3339), created["expires_at"])
	require.Nil(ts.T(), created["revoked_at"])

	// Only the digest is stored.
	var stored int
	require.NoError(ts.T(), ts.API.db.RawQuery("select count(*) from scim_tokens where token_hash = sha256(convert_to(?, 'UTF8'))", plaintext).First(&stored))
	require.Equal(ts.T(), 1, stored)

	// Several tokens are active at once, so rotation can overlap.
	second := scimProvider{ID: ts.A.ID, Token: plaintext}
	require.Equal(ts.T(), http.StatusOK, ts.scim(ts.A, http.MethodGet, "/Users", nil).Code)
	require.Equal(ts.T(), http.StatusOK, ts.scim(second, http.MethodGet, "/Users", nil).Code)
	require.Len(ts.T(), decodeJSON(ts.T(), ts.admin(http.MethodGet, ts.scimAdminPath(ts.A.ID, ""), nil))["tokens"], 2)

	w = ts.admin(http.MethodPost, path, map[string]any{"expires_at": time.Now().Add(-time.Minute)})
	require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())

	// Revoking is by id, takes effect immediately, and is idempotent.
	id := created["id"].(string)
	w = ts.admin(http.MethodDelete, path+"/"+id, nil)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	revoked := decodeJSON(ts.T(), w)
	require.NotNil(ts.T(), revoked["revoked_at"])
	require.NotContains(ts.T(), revoked, "token")
	ts.requireSCIMError(ts.scim(second, http.MethodGet, "/Users", nil), http.StatusUnauthorized, "")
	require.Equal(ts.T(), http.StatusOK, ts.scim(ts.A, http.MethodGet, "/Users", nil).Code)

	again := ts.admin(http.MethodDelete, path+"/"+id, nil)
	require.Equal(ts.T(), http.StatusOK, again.Code)
	require.Equal(ts.T(), revoked["revoked_at"], decodeJSON(ts.T(), again)["revoked_at"])
	revokes := ts.auditEntries("scim_token_revoked")
	require.Len(ts.T(), revokes, 1)
	require.Equal(ts.T(), plaintext[:12], revokes[0]["traits"].(map[string]any)["prefix"])
	require.Len(ts.T(), decodeJSON(ts.T(), ts.admin(http.MethodGet, ts.scimAdminPath(ts.A.ID, ""), nil))["tokens"], 1)

	// Another provider's token, an unknown id and a malformed id are not found.
	var otherID string
	require.NoError(ts.T(), ts.API.db.RawQuery(`select t.id from scim_tokens t join scim_directories d on d.id = t.directory_id where d.sso_provider_id = ?`, ts.B.ID).First(&otherID))
	for _, tokenID := range []string{otherID, uuid.Must(uuid.NewV4()).String(), "scim_0000000"} {
		w = ts.admin(http.MethodDelete, path+"/"+tokenID, nil)
		require.Equal(ts.T(), http.StatusNotFound, w.Code, tokenID)
		require.Equal(ts.T(), "scim_token_not_found", decodeJSON(ts.T(), w)["error_code"])
	}
	require.Equal(ts.T(), http.StatusOK, ts.scim(ts.B, http.MethodGet, "/Users", nil).Code)

	// Tokens can be created before SCIM is enabled.
	w = ts.admin(http.MethodPost, "/admin/sso/providers", map[string]any{"type": "saml", "metadata_xml": validSAMLIDPMetadata("https://idp.example.com/later")})
	require.Equal(ts.T(), http.StatusCreated, w.Code)
	later := uuid.FromStringOrNil(decodeJSON(ts.T(), w)["id"].(string))
	early := scimProvider{ID: later, Token: ts.createSCIMToken(later, nil)}
	ts.requireSCIMError(ts.scim(early, http.MethodGet, "/Users", nil), http.StatusForbidden, "")

	require.Len(ts.T(), ts.auditEntries("scim_token_created"), 4)
}

func TestSCIMRateLimits(t *testing.T) {
	api, config, err := setupAPIForTestWithCallback(func(config *conf.GlobalConfiguration, conn *storage.Connection) {
		if config != nil {
			config.SSO.SCIM.Enabled = true
			config.SSO.SCIM.RateLimitDirectory = 3
			config.SSO.SCIM.RateLimitIP = 2
		}
	})
	require.NoError(t, err)
	defer api.db.Close()
	if !config.SAML.Enabled {
		t.Skip("SAML is disabled")
	}

	ts := &SCIMTestSuite{API: api, Config: config}
	ts.SetT(t)
	ts.SetupTest()

	// One directory exhausting its budget leaves another unaffected, though
	// both arrive from the same address.
	codes := []int{}
	for range 5 {
		codes = append(codes, ts.scim(ts.A, http.MethodGet, "/Users", nil).Code)
	}
	require.Equal(t, []int{200, 200, 200, 429, 429}, codes)
	ts.requireSCIMError(ts.scim(ts.A, http.MethodGet, "/Users", nil), http.StatusTooManyRequests, "")
	require.Equal(t, http.StatusOK, ts.scim(ts.B, http.MethodGet, "/Users", nil).Code)

	// Requests whose token resolves to no directory are bounded by address.
	codes = []int{}
	for range 4 {
		codes = append(codes, ts.request(http.MethodGet, "/scim/v2/Users", "Bearer scim_bogus", nil, []string{"My-Custom-Header", "203.0.113.9"}).Code)
	}
	require.Equal(t, []int{401, 401, 429, 429}, codes)
	require.Equal(t, http.StatusUnauthorized, ts.request(http.MethodGet, "/scim/v2/Users", "Bearer scim_bogus", nil, []string{"My-Custom-Header", "203.0.113.10"}).Code)
}

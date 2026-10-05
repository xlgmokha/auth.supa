package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

const (
	scimMediaType  = "application/scim+json"
	scimErrorURN   = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimPatchOpURN = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	scimUserURN    = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupURN   = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimEntURN     = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
)

// scimProvider is an SSO provider with SCIM enabled and one bearer token.
type scimProvider struct {
	ID    uuid.UUID
	Token string
}

type SCIMTestSuite struct {
	suite.Suite
	API      *API
	Config   *conf.GlobalConfiguration
	AdminJWT string

	A scimProvider
	B scimProvider
}

func TestSCIM(t *testing.T) {
	api, config, err := setupAPIForTestWithCallback(func(config *conf.GlobalConfiguration, conn *storage.Connection) {
		if config != nil {
			config.SSO.SCIM.Enabled = true
			config.SSO.SCIM.RateLimitDirectory = 1_000_000
			config.SSO.SCIM.RateLimitIP = 1_000_000
		}
	})
	require.NoError(t, err)
	defer api.db.Close()

	if config.SAML.Enabled {
		suite.Run(t, &SCIMTestSuite{API: api, Config: config})
	}
}

func (ts *SCIMTestSuite) SetupTest() {
	require.NoError(ts.T(), models.TruncateAll(ts.API.db))

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &AccessTokenClaims{Role: "supabase_admin"}).SignedString([]byte(ts.Config.JWT.Secret))
	require.NoError(ts.T(), err)
	ts.AdminJWT = token

	ts.A = ts.newSCIMProvider("A")
	ts.B = ts.newSCIMProvider("B")
}

// newSCIMProvider creates a SAML provider through the Admin API, enables SCIM
// on it and creates a token.
func (ts *SCIMTestSuite) newSCIMProvider(name string) scimProvider {
	w := ts.admin(http.MethodPost, "/admin/sso/providers", map[string]any{
		"type":         "saml",
		"metadata_xml": validSAMLIDPMetadata("https://idp.example.com/" + name),
	})
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	var provider struct {
		ID uuid.UUID `json:"id"`
	}
	require.NoError(ts.T(), json.Unmarshal(w.Body.Bytes(), &provider))

	w = ts.admin(http.MethodPut, ts.scimAdminPath(provider.ID, ""), map[string]any{"enabled": true})
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

	return scimProvider{ID: provider.ID, Token: ts.createSCIMToken(provider.ID, nil)}
}

func (ts *SCIMTestSuite) createSCIMToken(providerID uuid.UUID, body map[string]any) string {
	if body == nil {
		body = map[string]any{}
	}
	w := ts.admin(http.MethodPost, ts.scimAdminPath(providerID, "/tokens"), body)
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	var created struct {
		Token string `json:"token"`
	}
	require.NoError(ts.T(), json.Unmarshal(w.Body.Bytes(), &created))
	return created.Token
}

func (ts *SCIMTestSuite) scimAdminPath(providerID uuid.UUID, suffix string) string {
	return "/admin/sso/providers/" + providerID.String() + "/scim" + suffix
}

func (ts *SCIMTestSuite) admin(method, path string, body any) *httptest.ResponseRecorder {
	return ts.request(method, path, "Bearer "+ts.AdminJWT, body, nil)
}

func (ts *SCIMTestSuite) scim(p scimProvider, method, path string, body any, headers ...string) *httptest.ResponseRecorder {
	return ts.request(method, "/scim/v2"+path, "Bearer "+p.Token, body, headers)
}

func (ts *SCIMTestSuite) request(method, path, authorization string, body any, headers []string) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	switch b := body.(type) {
	case nil:
		reader = bytes.NewReader(nil)
	case string:
		reader = bytes.NewReader([]byte(b))
	default:
		raw, err := json.Marshal(b)
		require.NoError(ts.T(), err)
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, "http://localhost"+path, reader)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	req.Header.Set("Content-Type", scimMediaType)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	return w
}

func decodeJSON(t require.TestingT, w *httptest.ResponseRecorder) map[string]any {
	var out map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out), w.Body.String())
	return out
}

func (ts *SCIMTestSuite) requireSCIMError(w *httptest.ResponseRecorder, status int, scimType string) {
	ts.T().Helper()
	require.Equal(ts.T(), status, w.Code, w.Body.String())
	require.Equal(ts.T(), scimMediaType, w.Header().Get("Content-Type"))
	body := decodeJSON(ts.T(), w)
	require.Equal(ts.T(), []any{scimErrorURN}, body["schemas"])
	require.Equal(ts.T(), fmt.Sprint(status), body["status"])
	if scimType != "" {
		require.Equal(ts.T(), scimType, body["scimType"])
	}
}

func scimUser(userName string, extra map[string]any) map[string]any {
	user := map[string]any{
		"schemas":  []string{scimUserURN},
		"userName": userName,
		"name":     map[string]any{"givenName": "Given", "familyName": "Family"},
		"emails":   []map[string]any{{"value": userName, "type": "work", "primary": true}},
		"active":   true,
	}
	for k, v := range extra {
		user[k] = v
	}
	return user
}

func (ts *SCIMTestSuite) createUser(p scimProvider, userName string, extra map[string]any) map[string]any {
	ts.T().Helper()
	w := ts.scim(p, http.MethodPost, "/Users", scimUser(userName, extra))
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	return decodeJSON(ts.T(), w)
}

func (ts *SCIMTestSuite) createGroup(p scimProvider, displayName string, members ...string) map[string]any {
	ts.T().Helper()
	elements := []map[string]any{}
	for _, member := range members {
		elements = append(elements, map[string]any{"value": member})
	}
	w := ts.scim(p, http.MethodPost, "/Groups", map[string]any{
		"schemas":     []string{scimGroupURN},
		"displayName": displayName,
		"members":     elements,
	})
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	return decodeJSON(ts.T(), w)
}

func (ts *SCIMTestSuite) list(p scimProvider, path string, query url.Values) map[string]any {
	ts.T().Helper()
	w := ts.scim(p, http.MethodGet, path+"?"+query.Encode(), nil)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	return decodeJSON(ts.T(), w)
}

func resourceValues(list map[string]any, attribute string) []string {
	out := []string{}
	resources, _ := list["Resources"].([]any)
	for _, resource := range resources {
		value, _ := resource.(map[string]any)[attribute].(string)
		out = append(out, value)
	}
	return out
}

func patchOp(operations ...map[string]any) map[string]any {
	return map[string]any{"schemas": []string{scimPatchOpURN}, "Operations": operations}
}

func (ts *SCIMTestSuite) userAccount(scimID string) *models.User {
	ts.T().Helper()
	var resource models.SCIMResource
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", scimID).First(&resource))
	require.NotNil(ts.T(), resource.UserID)
	user, err := models.FindUserByID(ts.API.db, *resource.UserID)
	require.NoError(ts.T(), err)
	return user
}

func (ts *SCIMTestSuite) newSession(user *models.User) {
	ts.T().Helper()
	_, err := models.GrantAuthenticatedUser(ts.API.db, user, models.GrantParams{})
	require.NoError(ts.T(), err)
}

func (ts *SCIMTestSuite) sessionCount(user *models.User) (sessions, refreshTokens int) {
	ts.T().Helper()
	sessions, err := ts.API.db.Q().Where("user_id = ?", user.ID).Count(&models.Session{})
	require.NoError(ts.T(), err)
	refreshTokens, err = ts.API.db.Q().Where("user_id = ? and revoked = false", user.ID.String()).Count(&models.RefreshToken{})
	require.NoError(ts.T(), err)
	return sessions, refreshTokens
}

func (ts *SCIMTestSuite) auditEntries(action string) []map[string]any {
	ts.T().Helper()
	entries := []models.AuditLogEntry{}
	require.NoError(ts.T(), ts.API.db.RawQuery("select * from audit_log_entries where payload->>'action' = ? order by created_at", action).All(&entries))
	out := []map[string]any{}
	for _, entry := range entries {
		out = append(out, entry.Payload)
	}
	return out
}

func (ts *SCIMTestSuite) TestDiscovery() {
	w := ts.request(http.MethodGet, "/scim/v2/ServiceProviderConfig", "", nil, nil)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	spc := decodeJSON(ts.T(), w)
	require.Equal(ts.T(), map[string]any{"supported": true, "maxResults": float64(100)}, spc["filter"])
	require.Equal(ts.T(), map[string]any{"supported": true}, spc["patch"])
	require.Equal(ts.T(), map[string]any{"supported": true}, spc["sort"])
	require.Equal(ts.T(), map[string]any{"supported": true}, spc["etag"])
	require.Equal(ts.T(), false, spc["bulk"].(map[string]any)["supported"])
	require.Equal(ts.T(), "oauthbearertoken", spc["authenticationSchemes"].([]any)[0].(map[string]any)["type"])
	require.Equal(ts.T(), "http://localhost:9999/scim/v2/ServiceProviderConfig", spc["meta"].(map[string]any)["location"])

	types := decodeJSON(ts.T(), ts.scim(ts.A, http.MethodGet, "/ResourceTypes", nil))
	require.Equal(ts.T(), float64(2), types["totalResults"])
	require.ElementsMatch(ts.T(), []string{"User", "Group"}, resourceValues(types, "name"))

	w = ts.scim(ts.A, http.MethodGet, "/ResourceTypes/User", nil)
	require.Equal(ts.T(), http.StatusOK, w.Code)
	user := decodeJSON(ts.T(), w)
	require.Equal(ts.T(), "/Users", user["endpoint"])
	require.Equal(ts.T(), scimUserURN, user["schema"])
	require.Equal(ts.T(), scimEntURN, user["schemaExtensions"].([]any)[0].(map[string]any)["schema"])

	schemas := decodeJSON(ts.T(), ts.scim(ts.A, http.MethodGet, "/Schemas", nil))
	require.ElementsMatch(ts.T(), []string{scimUserURN, scimEntURN, scimGroupURN}, resourceValues(schemas, "id"))

	ts.requireSCIMError(ts.scim(ts.A, http.MethodGet, "/Schemas?filter="+url.QueryEscape(`id eq "x"`), nil), http.StatusForbidden, "")
	ts.requireSCIMError(ts.scim(ts.A, http.MethodGet, "/Unknown", nil), http.StatusNotFound, "")
	ts.requireSCIMError(ts.scim(ts.A, http.MethodPost, "/Bulk", nil), http.StatusNotImplemented, "")
}

func (ts *SCIMTestSuite) TestAuthentication() {
	user := ts.createUser(ts.A, "alice@example.com", nil)
	path := "/scim/v2/Users/" + user["id"].(string)

	cases := map[string]string{
		"missing":       "",
		"basic":         "Basic YWRtaW46YWRtaW4=",
		"unknown":       "Bearer scim_0000000000000000000000000000000000000000",
		"malformed":     "Bearer not-a-token",
		"admin JWT":     "Bearer " + ts.AdminJWT,
		"service token": "Bearer " + ts.Config.JWT.Secret,
	}
	for name, authorization := range cases {
		w := ts.request(http.MethodGet, path, authorization, nil, nil)
		require.Equal(ts.T(), http.StatusUnauthorized, w.Code, name)
		require.Contains(ts.T(), w.Body.String(), scimErrorURN, name)
	}

	// A client-supplied provider is ignored: the token alone picks the directory.
	w := ts.request(http.MethodGet, path, "Bearer "+ts.B.Token, nil, []string{"X-SSO-Provider-ID", ts.A.ID.String()})
	ts.requireSCIMError(w, http.StatusNotFound, "")

	// An expired token is refused.
	expired := ts.createSCIMToken(ts.A.ID, map[string]any{"expires_at": time.Now().Add(time.Hour)})
	require.NoError(ts.T(), ts.API.db.RawQuery("update scim_tokens set expires_at = now() - interval '1 second', created_at = now() - interval '1 hour' where token_hash = ?", models.HashSCIMToken(expired)).Exec())
	w = ts.request(http.MethodGet, path, "Bearer "+expired, nil, nil)
	ts.requireSCIMError(w, http.StatusUnauthorized, "")
	require.Contains(ts.T(), w.Header().Get("WWW-Authenticate"), "invalid_token")

	// A token records its last use.
	var lastUsed *time.Time
	require.NoError(ts.T(), ts.API.db.RawQuery("select last_used_at from scim_tokens where token_hash = ?", models.HashSCIMToken(ts.A.Token)).First(&lastUsed))
	require.NotNil(ts.T(), lastUsed)
}

func (ts *SCIMTestSuite) TestDisabledProviderRefusesRequests() {
	user := ts.createUser(ts.A, "alice@example.com", nil)
	require.NoError(ts.T(), ts.API.db.RawQuery("update sso_providers set disabled = true where id = ?", ts.A.ID).Exec())

	ts.requireSCIMError(ts.scim(ts.A, http.MethodGet, "/Users/"+user["id"].(string), nil), http.StatusForbidden, "")
	require.Equal(ts.T(), http.StatusOK, ts.scim(ts.A, http.MethodGet, "/ServiceProviderConfig", nil).Code)
	require.Equal(ts.T(), http.StatusOK, ts.scim(ts.B, http.MethodGet, "/Users", nil).Code)
}

func (ts *SCIMTestSuite) TestCreateUser() {
	w := ts.scim(ts.A, http.MethodPost, "/Users", scimUser("Alice@Example.com", map[string]any{
		"externalId": "00u1",
		"password":   "Okta-generated-secret",
		scimEntURN:   map[string]any{"employeeNumber": "42"},
	}))
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	created := decodeJSON(ts.T(), w)
	id := created["id"].(string)
	location := "http://localhost:9999/scim/v2/Users/" + id

	require.Equal(ts.T(), location, w.Header().Get("Location"))
	require.Equal(ts.T(), `W/"1"`, w.Header().Get("ETag"))
	require.Equal(ts.T(), "Alice@Example.com", created["userName"])
	require.Equal(ts.T(), "00u1", created["externalId"])
	require.Equal(ts.T(), true, created["active"])
	require.NotContains(ts.T(), created, "password")
	require.Equal(ts.T(), []any{scimUserURN, scimEntURN}, created["schemas"])
	meta := created["meta"].(map[string]any)
	require.Equal(ts.T(), "User", meta["resourceType"])
	require.Equal(ts.T(), location, meta["location"])
	require.Equal(ts.T(), `W/"1"`, meta["version"])

	// The account it provisions is an SSO user with a confirmed email and the
	// identity a SAML sign-in by the same subject resolves to.
	user := ts.userAccount(id)
	require.True(ts.T(), user.IsSSOUser)
	require.Equal(ts.T(), "alice@example.com", user.GetEmail())
	require.NotNil(ts.T(), user.EmailConfirmedAt)
	identity, err := models.FindIdentityByIdAndProvider(ts.API.db, "Alice@Example.com", "sso:"+ts.A.ID.String())
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), user.ID, identity.UserID)

	// The generated password is never stored.
	var stored models.SCIMResource
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", id).First(&stored))
	require.NotContains(ts.T(), stored.Resource, "password")

	got := decodeJSON(ts.T(), ts.scim(ts.A, http.MethodGet, "/Users/"+id, nil))
	require.Equal(ts.T(), created, got)

	entries := ts.auditEntries("scim_user_created")
	require.Len(ts.T(), entries, 1)
	traits := entries[0]["traits"].(map[string]any)
	require.Equal(ts.T(), ts.A.ID.String(), traits["sso_provider_id"])
	require.Equal(ts.T(), id, traits["resource_id"])
	require.Equal(ts.T(), user.ID.String(), traits["user_id"])
	require.Equal(ts.T(), "success", traits["outcome"])
	require.Equal(ts.T(), ts.A.ID.String(), entries[0]["actor_id"])
	require.Equal(ts.T(), "scim:"+ts.A.Token[:12], entries[0]["actor_username"])
	require.Equal(ts.T(), "scim", entries[0]["log_type"])
}

func (ts *SCIMTestSuite) TestCreateUserUniqueness() {
	ts.createUser(ts.A, "alice@example.com", map[string]any{"externalId": "ext-1"})

	ts.requireSCIMError(ts.scim(ts.A, http.MethodPost, "/Users", scimUser("ALICE@example.com", nil)), http.StatusConflict, "uniqueness")
	ts.requireSCIMError(ts.scim(ts.A, http.MethodPost, "/Users", scimUser("bob@example.com", map[string]any{"externalId": "ext-1"})), http.StatusConflict, "uniqueness")
	require.Len(ts.T(), ts.auditEntries("scim_user_created"), 1, "a failed create records no event")

	// Another provider's directory is independent.
	ts.createUser(ts.B, "alice@example.com", map[string]any{"externalId": "ext-1"})
}

func (ts *SCIMTestSuite) TestConcurrentCreateRace() {
	const racers = 8
	codes := make([]int, racers)
	var wg sync.WaitGroup
	for i := range racers {
		wg.Go(func() {
			codes[i] = ts.scim(ts.A, http.MethodPost, "/Users", scimUser("race@example.com", nil)).Code
		})
	}
	wg.Wait()

	created := 0
	for _, code := range codes {
		switch code {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
		default:
			ts.T().Fatalf("unexpected status %d", code)
		}
	}
	require.Equal(ts.T(), 1, created, "%v", codes)
	list := ts.list(ts.A, "/Users", url.Values{"filter": {`userName eq "race@example.com"`}})
	require.Equal(ts.T(), float64(1), list["totalResults"])
}

func (ts *SCIMTestSuite) TestListUsers() {
	for i := range 5 {
		ts.createUser(ts.A, fmt.Sprintf("user%d@example.com", i), nil)
	}
	ts.createUser(ts.B, "other@example.com", nil)

	list := ts.list(ts.A, "/Users", url.Values{})
	require.Equal(ts.T(), []any{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, list["schemas"])
	require.Equal(ts.T(), float64(5), list["totalResults"])
	require.Equal(ts.T(), float64(1), list["startIndex"])
	require.Equal(ts.T(), float64(5), list["itemsPerPage"])

	page := ts.list(ts.A, "/Users", url.Values{"startIndex": {"2"}, "count": {"2"}, "sortBy": {"userName"}})
	require.Equal(ts.T(), float64(5), page["totalResults"])
	require.Equal(ts.T(), float64(2), page["itemsPerPage"])
	require.Equal(ts.T(), []string{"user1@example.com", "user2@example.com"}, resourceValues(page, "userName"))

	past := ts.list(ts.A, "/Users", url.Values{"startIndex": {"10"}})
	require.Equal(ts.T(), float64(5), past["totalResults"])
	require.Equal(ts.T(), float64(0), past["itemsPerPage"])

	totals := ts.list(ts.A, "/Users", url.Values{"count": {"0"}})
	require.Equal(ts.T(), float64(5), totals["totalResults"])
	require.Empty(ts.T(), totals["Resources"])

	capped := ts.list(ts.A, "/Users", url.Values{"count": {"1000"}})
	require.Equal(ts.T(), float64(5), capped["itemsPerPage"])

	filtered := ts.list(ts.A, "/Users", url.Values{"filter": {`userName eq "USER3@example.com"`}})
	require.Equal(ts.T(), []string{"user3@example.com"}, resourceValues(filtered, "userName"))
	none := ts.list(ts.A, "/Users", url.Values{"filter": {`userName eq "other@example.com"`}})
	require.Equal(ts.T(), float64(0), none["totalResults"])

	ts.requireSCIMError(ts.scim(ts.A, http.MethodGet, "/Users?filter="+url.QueryEscape(`nope eq "x"`), nil), http.StatusBadRequest, "invalidFilter")
	ts.requireSCIMError(ts.scim(ts.A, http.MethodGet, "/Users?filter="+url.QueryEscape(`userName xx "x"`), nil), http.StatusBadRequest, "invalidFilter")
	ts.requireSCIMError(ts.scim(ts.A, http.MethodGet, "/Users?sortBy=nope", nil), http.StatusBadRequest, "invalidValue")
	ts.requireSCIMError(ts.scim(ts.A, http.MethodGet, "/Users?sortBy=groups", nil), http.StatusBadRequest, "invalidValue")
}

func (ts *SCIMTestSuite) TestSortIsTotalAndCollationIndependent() {
	for _, name := range []string{"b@example.com", "B2@example.com", "a@example.com", "_x@example.com", "Ä@example.com"} {
		ts.createUser(ts.A, name, nil)
	}
	asc := resourceValues(ts.list(ts.A, "/Users", url.Values{"sortBy": {"userName"}}), "userName")
	// Case-folded, then compared byte by byte: "b2@" sorts before "b@".
	require.Equal(ts.T(), []string{"_x@example.com", "a@example.com", "B2@example.com", "b@example.com", "Ä@example.com"}, asc)
	desc := resourceValues(ts.list(ts.A, "/Users", url.Values{"sortBy": {"userName"}, "sortOrder": {"descending"}}), "userName")
	require.Equal(ts.T(), []string{"Ä@example.com", "b@example.com", "B2@example.com", "a@example.com", "_x@example.com"}, desc)

	// Paging a sort with ties never repeats or skips a row.
	seen := map[string]bool{}
	for start := 1; start <= 5; start++ {
		page := ts.list(ts.A, "/Users", url.Values{"sortBy": {"meta.resourceType"}, "startIndex": {fmt.Sprint(start)}, "count": {"1"}})
		for _, id := range resourceValues(page, "id") {
			require.False(ts.T(), seen[id])
			seen[id] = true
		}
	}
	require.Len(ts.T(), seen, 5)
}

func (ts *SCIMTestSuite) TestAttributesProjection() {
	user := ts.createUser(ts.A, "alice@example.com", nil)
	id := user["id"].(string)

	only := decodeJSON(ts.T(), ts.scim(ts.A, http.MethodGet, "/Users/"+id+"?attributes=userName", nil))
	require.Equal(ts.T(), map[string]any{"id": id, "schemas": []any{scimUserURN}, "userName": "alice@example.com"}, only)

	withMeta := decodeJSON(ts.T(), ts.scim(ts.A, http.MethodGet, "/Users/"+id+"?attributes=userName,meta", nil))
	require.Contains(ts.T(), withMeta, "meta")

	excluded := decodeJSON(ts.T(), ts.scim(ts.A, http.MethodGet, "/Users/"+id+"?excludedAttributes=emails,name", nil))
	require.NotContains(ts.T(), excluded, "emails")
	require.NotContains(ts.T(), excluded, "name")
	require.Contains(ts.T(), excluded, "userName")

	list := ts.list(ts.A, "/Users", url.Values{"attributes": {"userName"}})
	require.Equal(ts.T(), map[string]any{"id": id, "schemas": []any{scimUserURN}, "userName": "alice@example.com"}, list["Resources"].([]any)[0])

	ts.requireSCIMError(ts.scim(ts.A, http.MethodGet, "/Users/"+id+"?attributes=userName&excludedAttributes=emails", nil), http.StatusBadRequest, "invalidValue")
	ts.requireSCIMError(ts.scim(ts.A, http.MethodGet, "/Users?attributes=userName&excludedAttributes=emails", nil), http.StatusBadRequest, "invalidValue")
}

func (ts *SCIMTestSuite) TestReplaceAndPatchUser() {
	user := ts.createUser(ts.A, "alice@example.com", map[string]any{"externalId": "e1"})
	id := user["id"].(string)

	// Okta updates with a full PUT.
	replacement := scimUser("alice@example.com", map[string]any{
		"externalId": "e1",
		"name":       map[string]any{"givenName": "Alicia", "familyName": "Smith"},
		"emails":     []map[string]any{{"value": "alicia@example.com", "primary": true}},
	})
	w := ts.scim(ts.A, http.MethodPut, "/Users/"+id, replacement)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	replaced := decodeJSON(ts.T(), w)
	require.Equal(ts.T(), "Alicia", replaced["name"].(map[string]any)["givenName"])
	require.Equal(ts.T(), `W/"2"`, w.Header().Get("ETag"))
	require.Equal(ts.T(), "alicia@example.com", ts.userAccount(id).GetEmail())

	// The spec leads with PATCH, including Okta's pathless replace.
	w = ts.scim(ts.A, http.MethodPatch, "/Users/"+id, patchOp(
		map[string]any{"op": "replace", "value": map[string]any{"displayName": "Ali"}},
		map[string]any{"op": "replace", "path": "name.familyName", "value": "Jones"},
	))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	patched := decodeJSON(ts.T(), w)
	require.Equal(ts.T(), "Ali", patched["displayName"])
	require.Equal(ts.T(), "Jones", patched["name"].(map[string]any)["familyName"])

	// Stale versions are refused.
	ts.requireSCIMError(ts.scim(ts.A, http.MethodPut, "/Users/"+id, replacement, "If-Match", `W/"1"`), http.StatusPreconditionFailed, "")
	w = ts.scim(ts.A, http.MethodPut, "/Users/"+id, replacement, "If-Match", `W/"3"`)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

	// Changing the userName to one in use is a conflict.
	ts.createUser(ts.A, "bob@example.com", nil)
	ts.requireSCIMError(ts.scim(ts.A, http.MethodPatch, "/Users/"+id, patchOp(map[string]any{"op": "replace", "path": "userName", "value": "BOB@example.com"})), http.StatusConflict, "uniqueness")

	require.Len(ts.T(), ts.auditEntries("scim_user_updated"), 3)
}

func (ts *SCIMTestSuite) TestDeactivateAndReactivateUser() {
	user := ts.createUser(ts.A, "alice@example.com", nil)
	id := user["id"].(string)
	account := ts.userAccount(id)
	ts.newSession(account)
	ts.newSession(account)
	sessions, refreshTokens := ts.sessionCount(account)
	require.Equal(ts.T(), 2, sessions)
	require.Equal(ts.T(), 2, refreshTokens)

	w := ts.scim(ts.A, http.MethodPatch, "/Users/"+id, patchOp(map[string]any{"op": "replace", "value": map[string]any{"active": false}}))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), false, decodeJSON(ts.T(), w)["active"])
	sessions, refreshTokens = ts.sessionCount(account)
	require.Zero(ts.T(), sessions)
	require.Zero(ts.T(), refreshTokens)

	// Deactivated users are still listed.
	list := ts.list(ts.A, "/Users", url.Values{"filter": {"active eq false"}})
	require.Equal(ts.T(), []string{id}, resourceValues(list, "id"))

	ts.newSession(account)
	w = ts.scim(ts.A, http.MethodPatch, "/Users/"+id, patchOp(map[string]any{"op": "replace", "path": "active", "value": true}))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), true, decodeJSON(ts.T(), w)["active"])
	sessions, _ = ts.sessionCount(account)
	require.Equal(ts.T(), 1, sessions, "reactivating neither restores nor revokes sessions")
}

func (ts *SCIMTestSuite) TestDeleteUser() {
	user := ts.createUser(ts.A, "alice@example.com", map[string]any{"externalId": "e1"})
	id := user["id"].(string)
	account := ts.userAccount(id)
	ts.newSession(account)

	ts.requireSCIMError(ts.scim(ts.A, http.MethodDelete, "/Users/"+id, nil, "If-Match", `W/"9"`), http.StatusPreconditionFailed, "")
	w := ts.scim(ts.A, http.MethodDelete, "/Users/"+id, nil)
	require.Equal(ts.T(), http.StatusNoContent, w.Code, w.Body.String())

	sessions, refreshTokens := ts.sessionCount(account)
	require.Zero(ts.T(), sessions)
	require.Zero(ts.T(), refreshTokens)

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		var body any
		switch method {
		case http.MethodPut:
			body = scimUser("alice@example.com", nil)
		case http.MethodPatch:
			body = patchOp(map[string]any{"op": "replace", "path": "displayName", "value": "x"})
		}
		ts.requireSCIMError(ts.scim(ts.A, method, "/Users/"+id, body), http.StatusNotFound, "")
	}
	require.Equal(ts.T(), float64(0), ts.list(ts.A, "/Users", url.Values{})["totalResults"])
	require.Equal(ts.T(), float64(0), ts.list(ts.A, "/Users", url.Values{"filter": {`externalId eq "e1"`}})["totalResults"])

	// The tombstone stays for support, and the account is kept.
	var tombstone models.SCIMResource
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", id).First(&tombstone))
	require.NotNil(ts.T(), tombstone.DeletedAt)
	_, err := models.FindUserByID(ts.API.db, account.ID)
	require.NoError(ts.T(), err)

	// Re-provisioning gets a new SCIM id linked to the same account.
	again := ts.createUser(ts.A, "alice@example.com", map[string]any{"externalId": "e1"})
	require.NotEqual(ts.T(), id, again["id"])
	require.Equal(ts.T(), account.ID, ts.userAccount(again["id"].(string)).ID)

	require.Len(ts.T(), ts.auditEntries("scim_user_deleted"), 1)
}

func (ts *SCIMTestSuite) TestTenantIsolation() {
	user := ts.createUser(ts.B, "shared@example.com", nil)
	group := ts.createGroup(ts.B, "Doctors", user["id"].(string))
	mine := ts.createUser(ts.A, "shared@example.com", nil)
	require.NotEqual(ts.T(), user["id"], mine["id"])
	require.NotEqual(ts.T(), ts.userAccount(user["id"].(string)).ID, ts.userAccount(mine["id"].(string)).ID)

	for _, resource := range []struct{ path, kind string }{
		{"/Users/" + user["id"].(string), "User"},
		{"/Groups/" + group["id"].(string), "Group"},
	} {
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			var body any
			switch {
			case method == http.MethodPut && resource.kind == "User":
				body = scimUser("shared@example.com", nil)
			case method == http.MethodPut:
				body = map[string]any{"schemas": []string{scimGroupURN}, "displayName": "x"}
			case method == http.MethodPatch:
				body = patchOp(map[string]any{"op": "add", "path": "members", "value": []map[string]any{{"value": mine["id"]}}})
			}
			ts.requireSCIMError(ts.scim(ts.A, method, resource.path, body), http.StatusNotFound, "")
		}
	}

	require.Equal(ts.T(), []string{mine["id"].(string)}, resourceValues(ts.list(ts.A, "/Users", url.Values{"filter": {`userName eq "shared@example.com"`}}), "id"))
	require.Equal(ts.T(), float64(0), ts.list(ts.A, "/Groups", url.Values{"filter": {`displayName eq "Doctors"`}})["totalResults"])

	// A member id from another directory is refused.
	w := ts.scim(ts.A, http.MethodPost, "/Groups", map[string]any{
		"schemas": []string{scimGroupURN}, "displayName": "Nurses",
		"members": []map[string]any{{"value": user["id"]}},
	})
	ts.requireSCIMError(w, http.StatusBadRequest, "invalidValue")

	// B's resources are unchanged.
	got := decodeJSON(ts.T(), ts.scim(ts.B, http.MethodGet, "/Groups/"+group["id"].(string), nil))
	require.Len(ts.T(), got["members"], 1)
}

func (ts *SCIMTestSuite) TestRequestsFromAnotherHostAreRefusedLikeOtherRoutes() {
	w := ts.request(http.MethodGet, "/scim/v2/Users", "Bearer "+ts.A.Token, nil, nil)
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.True(ts.T(), strings.HasPrefix(w.Header().Get("Content-Type"), scimMediaType))
}

func TestSCIMDisabled(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)
	defer api.db.Close()
	adminJWT, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &AccessTokenClaims{Role: "supabase_admin"}).SignedString([]byte(config.JWT.Secret))
	require.NoError(t, err)

	for _, path := range []string{"/scim/v2/ServiceProviderConfig", "/scim/v2/Users"} {
		req := httptest.NewRequest(http.MethodGet, "http://localhost"+path, nil)
		w := httptest.NewRecorder()
		api.handler.ServeHTTP(w, req)
		require.Equal(t, http.StatusNotFound, w.Code, path)
		require.JSONEq(t, `{"code":404,"error_code":"feature_disabled","msg":"SCIM is disabled"}`, w.Body.String())
	}

	// The Admin API is hidden too, for providers that exist.
	provider := &models.SSOProvider{ID: uuid.Must(uuid.NewV4())}
	require.NoError(t, api.db.Create(provider))
	defer func() { require.NoError(t, models.TruncateAll(api.db)) }()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/admin/sso/providers/"+provider.ID.String()+"/scim", nil)
	req.Header.Set("Authorization", "Bearer "+adminJWT)
	w := httptest.NewRecorder()
	api.handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
	require.JSONEq(t, `{"code":404,"error_code":"feature_disabled","msg":"SCIM is disabled"}`, w.Body.String())
}

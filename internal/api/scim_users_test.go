package api

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/supabase/auth/internal/api/scim"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/models"
)

const oktaUser = `{
	"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
	"userName": "Alice@Example.com",
	"name": {"givenName": "Alice", "familyName": "Smith"},
	"emails": [{"primary": true, "value": "alice@example.com", "type": "work"}],
	"displayName": "Alice Smith",
	"locale": "en-US",
	"externalId": "00u1abcd",
	"groups": [],
	"password": "hunter2hunter2",
	"active": true
}`

func (ts *SCIMTestSuite) create(token, body string) string {
	return ts.expectAs(token, http.StatusCreated, http.MethodPost, "/Users", body)["id"].(string)
}

func (ts *SCIMTestSuite) list(token, filter string) map[string]any {
	return ts.get(token, "/Users?"+url.Values{"filter": {filter}, "startIndex": {"1"}, "count": {"100"}}.Encode())
}

func (ts *SCIMTestSuite) get(token, path string) map[string]any {
	return ts.expectAs(token, http.StatusOK, http.MethodGet, path, "")
}

func (ts *SCIMTestSuite) repository() (context.Context, server.Repository[*core.User]) {
	ctx, err := scim.NewTokenValidator(ts.API.db)(context.Background(), ts.TokenA)
	require.NoError(ts.T(), err)
	ctx = scim.RequestKey.WithValue(ctx, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", nil))
	return ctx, scim.NewUserRepository(ts.API.db, ts.API.config, &scimUserSync{api: ts.API})
}

func (ts *SCIMTestSuite) storedUser(id string) models.SCIMUser {
	var stored models.SCIMUser
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", id).First(&stored))
	return stored
}

func (ts *SCIMTestSuite) requireSCIMStatus(err error, code int, msg ...any) {
	var scimErr *scimerrors.Error
	require.ErrorAs(ts.T(), err, &scimErr, msg...)
	require.Equal(ts.T(), code, scimErr.StatusCode(), msg...)
}

func pluck(items any, field string) []string {
	values := []string{}
	for _, item := range items.([]any) {
		values = append(values, item.(map[string]any)[field].(string))
	}
	return values
}

func (ts *SCIMTestSuite) TestOktaLifecycle() {
	require.EqualValues(ts.T(), 0, ts.list(ts.TokenA, `userName eq "alice@example.com"`)["totalResults"])

	w, created := ts.do(ts.TokenA, http.MethodPost, "/Users", oktaUser)
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	id := created["id"].(string)
	location := "http://localhost:9999/scim/v2/Users/" + id
	require.Equal(ts.T(), location, w.Header().Get("Location"))
	require.Equal(ts.T(), location, created["meta"].(map[string]any)["location"])
	require.Equal(ts.T(), "Alice@Example.com", created["userName"])
	require.Equal(ts.T(), "00u1abcd", created["externalId"])
	require.Equal(ts.T(), "Alice Smith", created["displayName"])
	require.NotContains(ts.T(), w.Body.String(), "hunter2")

	stored := ts.storedUser(id)
	require.Equal(ts.T(), ts.A.ID, stored.SSOProviderID)
	require.Equal(ts.T(), "alice@example.com", stored.UserName())
	require.NotContains(ts.T(), string(stored.Resource), "hunter2")
	require.NotContains(ts.T(), string(stored.Resource), `"id"`)

	for _, filter := range []string{`userName eq "alice@example.com"`, `userName eq "ALICE@EXAMPLE.COM"`, `externalId eq "00u1abcd"`, `userName eq "alice@example.com" and externalId eq "00u1abcd"`} {
		found := ts.list(ts.TokenA, filter)
		require.EqualValues(ts.T(), 1, found["totalResults"], filter)
		require.Equal(ts.T(), id, found["Resources"].([]any)[0].(map[string]any)["id"], filter)
	}
	require.EqualValues(ts.T(), 0, ts.list(ts.TokenA, `externalId eq "00U1ABCD"`)["totalResults"])
	require.EqualValues(ts.T(), 0, ts.list(ts.TokenA, `userName eq "alice@example.com" and externalId eq "00U1ABCD"`)["totalResults"])

	require.Equal(ts.T(), "Alice", ts.get(ts.TokenA, "/Users/"+id)["name"].(map[string]any)["givenName"])

	w, replaced := ts.do(ts.TokenA, http.MethodPut, "/Users/"+id, oktaUserWith("givenName", "Alicia"))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), "Alicia", replaced["name"].(map[string]any)["givenName"])
	require.Equal(ts.T(), created["meta"].(map[string]any)["created"], replaced["meta"].(map[string]any)["created"])

	w, patched := ts.do(ts.TokenA, http.MethodPatch, "/Users/"+id, patchOp(`{"op": "replace", "value": {"active": false}}`))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), false, patched["active"])
	require.False(ts.T(), ts.storedUser(id).Active())

	ts.expectAs(ts.TokenA, http.StatusNoContent, http.MethodDelete, "/Users/"+id, "")

	for _, tc := range []struct{ method, body string }{
		{http.MethodGet, ""},
		{http.MethodPut, oktaUser},
		{http.MethodPatch, patchOp(`{"op":"replace","value":{"active":true}}`)},
		{http.MethodDelete, ""},
	} {
		ts.expectAs(ts.TokenA, http.StatusNotFound, tc.method, "/Users/"+id, tc.body)
	}
	for _, filter := range []string{"", `userName eq "alice@example.com"`, `externalId eq "00u1abcd"`} {
		require.EqualValues(ts.T(), 0, ts.list(ts.TokenA, filter)["totalResults"], filter)
	}

	require.NotEqual(ts.T(), id, ts.create(ts.TokenA, oktaUser))
	require.NotNil(ts.T(), ts.storedUser(id).DeletedAt)
}

func (ts *SCIMTestSuite) TestOktaContentTypesAndReactivate() {
	for i, contentType := range []string{"application/scim+json; charset=utf-8", "application/json", "application/json; charset=utf-8"} {
		name := string(rune('a'+i)) + "@example.com"
		w, created := ts.doAs(contentType, ts.TokenA, http.MethodPost, "/Users", userWith(name, name))
		require.Equal(ts.T(), http.StatusCreated, w.Code, contentType+" "+w.Body.String())
		id := created["id"].(string)

		for _, active := range []bool{false, true} {
			w, patched := ts.doAs(contentType, ts.TokenA, http.MethodPatch, "/Users/"+id, patchOp(`{"op": "replace", "value": {"active": `+strconv.FormatBool(active)+`}}`))
			require.Equal(ts.T(), http.StatusOK, w.Code, contentType+" "+w.Body.String())
			require.Equal(ts.T(), active, patched["active"], contentType)
		}
	}
}

func (ts *SCIMTestSuite) TestUnsupportedEndpointsReturnNotImplemented() {
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/Me"},
		{http.MethodPost, "/Bulk"},
		{http.MethodPost, "/.search"},
		{http.MethodPost, "/Users/.search"},
		{http.MethodPost, "/Groups/.search"},
	} {
		w, _ := ts.do(ts.TokenA, tc.method, tc.path, "{}")
		require.Equal(ts.T(), http.StatusNotImplemented, w.Code, tc.path)
		require.Equal(ts.T(), protocol.MediaType, w.Header().Get("Content-Type"), tc.path)
		require.Contains(ts.T(), w.Body.String(), protocol.SchemaError, tc.path)
	}
}

func (ts *SCIMTestSuite) TestUniquenessWithinProvider() {
	ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))

	for _, body := range []string{userWith("ALICE@example.com", "a-2"), userWith("bob@example.com", "a-1")} {
		w, response := ts.do(ts.TokenA, http.MethodPost, "/Users", body)
		require.Equal(ts.T(), http.StatusConflict, w.Code, w.Body.String())
		require.Equal(ts.T(), "uniqueness", response["scimType"])
	}

	ts.create(ts.TokenB, userWith("alice@example.com", "a-1"))
}

func (ts *SCIMTestSuite) TestUniqueIndexIsTheBackstop() {
	ctx, users := ts.repository()

	_, err := users.Create(ctx, &core.User{UserName: "alice@example.com", Emails: emails("alice@example.com")})
	require.NoError(ts.T(), err)

	_, err = users.Create(ctx, &core.User{UserName: "Alice@Example.com", Emails: emails("alice@example.com")})
	ts.requireSCIMStatus(err, http.StatusConflict)
}

func (ts *SCIMTestSuite) scimAuditEntries() []models.AuditLogEntry {
	return queryAuditEntries(ts.T(), ts.API.db, "payload->>'log_type' = ?", "scim")
}

func (ts *SCIMTestSuite) auditDuring(fn func()) []models.AuditLogEntry {
	before := len(ts.scimAuditEntries())
	fn()
	return ts.scimAuditEntries()[before:]
}

func (ts *SCIMTestSuite) TestAuditLog() {
	id := ts.create(ts.TokenA, oktaUser)

	ts.expectAs(ts.TokenA, http.StatusConflict, http.MethodPost, "/Users", oktaUser)

	for _, operation := range []string{
		`{"op":"replace","path":"displayName","value":"Alice S."}`,
		`{"op":"replace","path":"active","value":false}`,
		`{"op":"replace","path":"active","value":true}`,
	} {
		ts.expectAs(ts.TokenA, http.StatusOK, http.MethodPatch, "/Users/"+id, patchOp(operation))
	}

	ts.expectAs(ts.TokenA, http.StatusNoContent, http.MethodDelete, "/Users/"+id, "")

	entries := ts.scimAuditEntries()
	for _, entry := range entries {
		ts.requireSCIMAudit(entry, map[string]any{"scim_user_id": id, "user_id": ts.linkedUser(id).ID.String()})
	}
	created, updated, deleted := string(models.SCIMUserCreatedAction), string(models.SCIMUserUpdatedAction), string(models.SCIMUserDeletedAction)
	require.Equal(ts.T(), []string{created, updated, updated, updated, deleted}, actionsOf(entries))
}

func (ts *SCIMTestSuite) requireSCIMAudit(entry models.AuditLogEntry, traits map[string]any) {
	require.Equal(ts.T(), uuid.Nil.String(), entry.Payload["actor_id"])
	require.Equal(ts.T(), "scim:"+ts.TokenA[:12], entry.Payload["actor_username"])
	got := entry.Payload["traits"].(map[string]any)
	require.Equal(ts.T(), ts.A.ID.String(), got["sso_provider_id"])
	require.Equal(ts.T(), "success", got["outcome"])
	for key, want := range traits {
		require.Equal(ts.T(), want, got[key], key)
	}
}

func (ts *SCIMTestSuite) TestRolesRoundTrip() {
	id := ts.create(ts.TokenA, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice@example.com","emails":[{"primary":true,"value":"alice@example.com"}],"roles":[{"value":"admin","primary":true},{"value":"billing"}]}`)

	require.Equal(ts.T(), []string{"admin", "billing"}, pluck(ts.get(ts.TokenA, "/Users/"+id)["roles"], "value"))
}

func (ts *SCIMTestSuite) TestSort() {
	ids := map[string]string{}
	for _, name := range []string{"carol@example.com", "Alice@example.com", "bob@example.com"} {
		ids[name] = ts.create(ts.TokenA, userWith(name, name))
	}
	ts.create(ts.TokenB, userWith("aaron@example.com", "b"))

	sorted := func(params url.Values) []string {
		return pluck(ts.get(ts.TokenA, "/Users?"+params.Encode())["Resources"], "userName")
	}

	require.Equal(ts.T(), []string{"Alice@example.com", "bob@example.com", "carol@example.com"}, sorted(url.Values{"sortBy": {"userName"}}))
	require.Equal(ts.T(), []string{"carol@example.com", "bob@example.com", "Alice@example.com"}, sorted(url.Values{"sortBy": {"userName"}, "sortOrder": {"descending"}}))
	require.Equal(ts.T(), []string{"carol@example.com", "Alice@example.com", "bob@example.com"}, sorted(url.Values{"sortBy": {"meta.created"}}))
	require.Equal(ts.T(), []string{"carol@example.com", "Alice@example.com", "bob@example.com"}, sorted(url.Values{"sortOrder": {"descending"}}))
	require.Equal(ts.T(), []string{"Alice@example.com"}, sorted(url.Values{"sortBy": {"userName"}, "count": {"1"}}))
	require.Equal(ts.T(), []string{"bob@example.com"}, sorted(url.Values{"sortBy": {"userName"}, "startIndex": {"2"}, "count": {"1"}}))

	_, body := ts.do(ts.TokenA, http.MethodPatch, "/Users/"+ids["carol@example.com"], patchOp(`{"op":"replace","path":"title","value":"Lead"}`))
	require.Equal(ts.T(), "Lead", body["title"])
	require.Equal(ts.T(), "carol@example.com", sorted(url.Values{"sortBy": {"meta.lastModified"}, "sortOrder": {"descending"}})[0])

	require.Equal(ts.T(), slices.Sorted(maps.Values(ids)), pluck(ts.get(ts.TokenA, "/Users?sortBy=id")["Resources"], "id"))

	for _, sortBy := range []string{"displayName", "emails.value", "password"} {
		w, body := ts.do(ts.TokenA, http.MethodGet, "/Users?"+url.Values{"sortBy": {sortBy}}.Encode(), "")
		require.Equal(ts.T(), http.StatusBadRequest, w.Code, sortBy)
		require.Equal(ts.T(), string(scimerrors.InvalidValue), body["scimType"], sortBy)
	}
}

func (ts *SCIMTestSuite) TestAttributeProjection() {
	id := ts.create(ts.TokenA, oktaUser)

	for _, path := range []string{"/Users/" + id, "/Users"} {
		project := func(query string) map[string]any {
			body := ts.get(ts.TokenA, path+"?"+query)
			if path == "/Users" {
				return body["Resources"].([]any)[0].(map[string]any)
			}
			return body
		}
		user := project("attributes=userName")
		require.Equal(ts.T(), id, user["id"])
		require.NotNil(ts.T(), user["schemas"])
		require.NotContains(ts.T(), user, "meta")
		excluded := project("excludedAttributes=displayName,emails")
		require.Contains(ts.T(), excluded, "name")
		for _, user := range []map[string]any{user, excluded} {
			require.Equal(ts.T(), "Alice@Example.com", user["userName"])
			require.NotContains(ts.T(), user, "displayName")
			require.NotContains(ts.T(), user, "emails")
		}

		w, body := ts.do(ts.TokenA, http.MethodGet, path+"?attributes=userName&excludedAttributes=emails", "")
		require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())
		require.Equal(ts.T(), string(scimerrors.InvalidValue), body["scimType"])
	}
}

func (ts *SCIMTestSuite) TestWriteResponseProjection() {
	w, created := ts.do(ts.TokenA, http.MethodPost, "/Users?attributes=userName", userWith("alice@example.com", "a-1"))
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	id := created["id"].(string)
	require.ElementsMatch(ts.T(), []string{"id", "schemas", "userName"}, slices.Collect(maps.Keys(created)))

	w, got := ts.do(ts.TokenA, http.MethodPut, "/Users/"+id+"?excludedAttributes=emails", userWith("alice@example.com", "a-2"))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.NotContains(ts.T(), got, "emails")
	require.Equal(ts.T(), "a-2", got["externalId"])

	w, got = ts.do(ts.TokenA, http.MethodPatch, "/Users/"+id+"?excludedAttributes=emails", patchOp(`{"op":"replace","path":"externalId","value":"a-3"}`))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.NotContains(ts.T(), got, "emails")
	require.Equal(ts.T(), "a-3", got["externalId"])

	group := ts.createGroup(ts.TokenA, groupWith("Engineering", ""))
	w, got = ts.do(ts.TokenA, http.MethodPatch, "/Groups/"+group+"?attributes=displayName", patchOp(`{"op":"add","path":"members","value":[{"value":"`+id+`"}]}`))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.ElementsMatch(ts.T(), []string{"id", "schemas", "displayName"}, slices.Collect(maps.Keys(got)))

	require.Equal(ts.T(), []string{id}, memberValues(ts.get(ts.TokenA, "/Groups/"+group)))
}

func (ts *SCIMTestSuite) TestETagAndIfMatch() {
	for _, tc := range []struct{ path, body, patch string }{
		{"/Users", oktaUser, patchOp(`{"op":"replace","path":"displayName","value":"Alice S."}`)},
		{"/Groups", groupWith("Engineering", "g-1"), patchOp(`{"op":"replace","path":"displayName","value":"Platform"}`)},
	} {
		w, created := ts.do(ts.TokenA, http.MethodPost, tc.path, tc.body)
		require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
		path := tc.path + "/" + created["id"].(string)
		stale := w.Header().Get("ETag")
		require.Equal(ts.T(), created["meta"].(map[string]any)["version"], stale, path)
		require.Equal(ts.T(), stale, ts.etag(path))

		w, _ = ts.doAs(protocol.MediaType, ts.TokenA, http.MethodPatch, path, tc.patch, "If-Match", stale)
		require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
		current := w.Header().Get("ETag")
		require.NotEqual(ts.T(), stale, current, path)

		for _, version := range []string{stale, `W/"garbage"`} {
			for method, body := range map[string]string{http.MethodPut: tc.body, http.MethodPatch: tc.patch, http.MethodDelete: ""} {
				w, _ := ts.doAs(protocol.MediaType, ts.TokenA, method, path, body, "If-Match", version)
				require.Equal(ts.T(), http.StatusPreconditionFailed, w.Code, method+" "+path+" "+w.Body.String())
			}
		}
		require.Equal(ts.T(), current, ts.etag(path))

		w, _ = ts.doAs(protocol.MediaType, ts.TokenA, http.MethodPut, tc.path+"/"+uuid.Must(uuid.NewV4()).String(), tc.body, "If-Match", current)
		require.Equal(ts.T(), http.StatusNotFound, w.Code, w.Body.String())

		w, _ = ts.doAs(protocol.MediaType, ts.TokenA, http.MethodPut, path, tc.body, "If-Match", current)
		require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
		w, _ = ts.doAs(protocol.MediaType, ts.TokenA, http.MethodDelete, path, "", "If-Match", w.Header().Get("ETag"))
		require.Equal(ts.T(), http.StatusNoContent, w.Code, w.Body.String())
	}
}

func (ts *SCIMTestSuite) TestPatchAttributesOutsideTheMinimalSchema() {
	id := ts.create(ts.TokenA, oktaUser)

	patch := patchOp(`{"op":"replace","path":"title","value":"Engineer"}`, `{"op":"add","path":"phoneNumbers","value":[{"value":"555-0100","type":"work"}]}`, `{"op":"replace","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department","value":"Auth"}`)
	w, patched := ts.do(ts.TokenA, http.MethodPatch, "/Users/"+id, patch)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), "Engineer", patched["title"])

	read := ts.get(ts.TokenA, "/Users/"+id)
	require.Equal(ts.T(), "Engineer", read["title"])
	require.Equal(ts.T(), "555-0100", read["phoneNumbers"].([]any)[0].(map[string]any)["value"])
	require.Equal(ts.T(), "Auth", read[string(core.SchemaEnterpriseUser)].(map[string]any)["department"])
	require.ElementsMatch(ts.T(), []any{string(core.SchemaUser), string(core.SchemaEnterpriseUser)}, read["schemas"])
}

func (ts *SCIMTestSuite) TestActiveDefaultsToTrue() {
	w, created := ts.do(ts.TokenA, http.MethodPost, "/Users", userWith("alice@example.com", "a-1"))
	require.Equal(ts.T(), http.StatusCreated, w.Code)
	require.Equal(ts.T(), true, created["active"])

	w, replaced := ts.do(ts.TokenA, http.MethodPut, "/Users/"+created["id"].(string), userWith("alice@example.com", "a-1"))
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.Equal(ts.T(), true, replaced["active"])
}

func (ts *SCIMTestSuite) TestPagination() {
	for _, name := range []string{"a", "b", "c"} {
		ts.create(ts.TokenA, userWith(name+"@example.com", name))
	}

	for query, size := range map[string]int{"startIndex=2&count=1": 1, "count=0": 0, "startIndex=10&count=5": 0, "startIndex=2&count=5": 2} {
		page := ts.get(ts.TokenA, "/Users?"+query)
		require.EqualValues(ts.T(), 3, page["totalResults"], query)
		require.Len(ts.T(), page["Resources"], size, query)
		if size == 1 {
			require.EqualValues(ts.T(), 2, page["startIndex"])
			require.Equal(ts.T(), []string{"b@example.com"}, pluck(page["Resources"], "userName"))
		}
	}
}

func (ts *SCIMTestSuite) TestPageSizeCap() {
	for i := range 101 {
		_, err := models.CreateSCIMUser(ts.API.db, ts.A.ID, []byte(`{"userName":"user`+strconv.Itoa(i)+`@example.com"}`))
		require.NoError(ts.T(), err)
	}

	for _, query := range []string{"", "?count=200"} {
		page := ts.get(ts.TokenA, "/Users"+query)
		require.Equal(ts.T(), []any{string(protocol.SchemaListResponse)}, page["schemas"], query)
		require.EqualValues(ts.T(), 101, page["totalResults"], query)
		require.EqualValues(ts.T(), 1, page["startIndex"], query)
		require.EqualValues(ts.T(), 100, page["itemsPerPage"], query)
		require.Len(ts.T(), page["Resources"], 100, query)
	}
}

func (ts *SCIMTestSuite) TestSortTieBreaksOnID() {
	ids := []string{
		ts.create(ts.TokenA, userWith("alice@example.com", "a-1")),
		ts.create(ts.TokenA, userWith("bob@example.com", "b-1")),
		ts.create(ts.TokenA, userWith("carol@example.com", "c-1")),
	}
	require.NoError(ts.T(), ts.API.db.RawQuery(
		"UPDATE "+(&models.SCIMUser{}).TableName()+" SET created_at = '2026-01-01T00:00:00Z', updated_at = '2026-01-01T00:00:00Z' WHERE sso_provider_id = ?", ts.A.ID,
	).Exec())
	slices.Sort(ids)
	descending := slices.Clone(ids)
	slices.Reverse(descending)

	for _, sortBy := range []string{"meta.created", "meta.lastModified"} {
		for order, want := range map[string][]string{"ascending": ids, "descending": descending} {
			got := []string{}
			for startIndex := 1; startIndex <= len(ids); startIndex++ {
				params := url.Values{"sortBy": {sortBy}, "sortOrder": {order}, "startIndex": {strconv.Itoa(startIndex)}, "count": {"1"}}
				got = append(got, pluck(ts.get(ts.TokenA, "/Users?"+params.Encode())["Resources"], "id")...)
			}
			require.Equal(ts.T(), want, got, sortBy+" "+order)
		}
	}
}

func (ts *SCIMTestSuite) TestFilterAnyAttribute() {
	enterprise := `"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"Tour Operations"}`
	bjensen := ts.create(ts.TokenA, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"bjensen@example.com","name":{"givenName":"Barbara","familyName":"Jensen"},"title":"Tour Guide","emails":[{"value":"bjensen@example.com","type":"work","primary":true},{"value":"barbara@example.com","type":"home"}],`+enterprise+`}`)
	jsmith := ts.create(ts.TokenA, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"jsmith@example.com","name":{"givenName":"John","familyName":"Smith"},"title":"Tour Guide","emails":[{"value":"jsmith@example.com","type":"work","primary":true}]}`)
	ts.create(ts.TokenB, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"bjensen@example.com","name":{"givenName":"Barbara"},"emails":[{"value":"bjensen@example.com"}]}`)

	for filter, want := range map[string][]string{
		`name.givenName eq "barbara"`:                                                                {bjensen},
		`emails eq "BARBARA@example.com"`:                                                            {bjensen},
		`emails.value eq "jsmith@example.com"`:                                                       {jsmith},
		`emails[type eq "work" and value eq "bjensen@example.com"]`:                                  {bjensen},
		`emails[type eq "home" and value eq "bjensen@example.com"]`:                                  {},
		`emails[type eq "home" or value eq "jsmith@example.com"]`:                                    {bjensen, jsmith},
		`title eq "tour guide" and name.familyName eq "Smith"`:                                       {jsmith},
		`userName eq "bjensen@example.com" or name.givenName eq "John"`:                              {bjensen, jsmith},
		`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "tour operations"`: {bjensen},
		`active eq true and title eq "tour guide"`:                                                   {bjensen, jsmith},
		`active eq false`: {},
	} {
		require.ElementsMatch(ts.T(), want, pluck(ts.list(ts.TokenA, filter)["Resources"], "id"), filter)
	}
}

func (ts *SCIMTestSuite) TestFilterOperators() {
	const core = `"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"]`
	bjensen := ts.create(ts.TokenA, `{`+core+`,"userName":"bjensen@example.com","externalId":"00uB","nickName":"b_j","title":"Tour Guide","profileUrl":"https://example.com/Bjensen","name":{"familyName":"Jensen"},"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"Tour Operations"}}`)
	jsmith := ts.create(ts.TokenA, `{`+core+`,"userName":"jsmith@example.com","externalId":"00uJ","nickName":"bxj","title":"Tour Guide","name":{"familyName":"Smith"}}`)
	mmiller := ts.create(ts.TokenA, `{`+core+`,"userName":"mmiller@example.com","nickName":""}`)
	ts.create(ts.TokenB, `{`+core+`,"userName":"bjensen@example.com","externalId":"00uB","title":"Tour Guide"}`)
	created := ts.get(ts.TokenA, "/Users/"+jsmith)["meta"].(map[string]any)["created"].(string)

	for filter, want := range map[string][]string{
		`userName co "JENSEN"`:                        {bjensen},
		`userName sw "j"`:                             {jsmith},
		`userName ew "@EXAMPLE.COM"`:                  {bjensen, jsmith, mmiller},
		`userName gt "c"`:                             {jsmith, mmiller},
		`userName le "jsmith@example.com"`:            {bjensen, jsmith},
		`userName ne "BJENSEN@example.com"`:           {jsmith, mmiller},
		`externalId eq "00ub"`:                        {},
		`externalId co "B"`:                           {bjensen},
		`externalId lt "00uC"`:                        {bjensen},
		`externalId ne "00uB"`:                        {jsmith, mmiller},
		`externalId pr`:                               {bjensen, jsmith},
		`profileUrl eq "https://example.com/Bjensen"`: {bjensen},
		`profileUrl eq "https://example.com/bjensen"`: {},
		`profileUrl sw "https://example.com/B"`:       {bjensen},
		`nickName co "_"`:                             {bjensen},
		`nickName sw "b%"`:                            {},
		`nickName pr`:                                 {bjensen, jsmith},
		`title ne "tour guide"`:                       {mmiller},
		`title ge "TOUR GUIDE"`:                       {bjensen, jsmith},
		`title pr`:                                    {bjensen, jsmith},
		`not (title pr)`:                              {mmiller},
		`not (title eq "tour guide")`:                 {mmiller},
		`not (title co "guide" or userName sw "m")`:   {},
		`name pr`:                    {bjensen, jsmith},
		`name.familyName sw "jen"`:   {bjensen},
		`name.familyName ne "smith"`: {bjensen, mmiller},
		`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department co "operations"`: {bjensen},
		`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department pr`:              {bjensen},
		`active ne false`:                             {bjensen, jsmith, mmiller},
		`active pr`:                                   {bjensen, jsmith, mmiller},
		`not (title co "guide")`:                      {mmiller},
		`not (externalId sw "00u")`:                   {mmiller},
		`not (name.familyName gt "a")`:                {mmiller},
		`id eq "` + bjensen + `"`:                     {bjensen},
		`id ne "` + bjensen + `"`:                     {jsmith, mmiller},
		`id eq "not-a-uuid"`:                          {},
		`id pr`:                                       {bjensen, jsmith, mmiller},
		`meta.created eq "` + created + `"`:           {jsmith},
		`meta.created gt "` + created + `"`:           {mmiller},
		`meta.created le "` + created + `"`:           {bjensen, jsmith},
		`meta.lastModified lt "2000-01-01T00:00:00Z"`: {},
		`meta.lastModified pr`:                        {bjensen, jsmith, mmiller},
		`(title pr and not (userName sw "b")) or externalId eq "00uB"`: {bjensen, jsmith},
		`title pr and (name.familyName eq "smith" or nickName co "_")`: {bjensen, jsmith},
	} {
		require.ElementsMatch(ts.T(), want, pluck(ts.list(ts.TokenA, filter)["Resources"], "id"), filter)
	}
}

func (ts *SCIMTestSuite) TestUnsupportedFilters() {
	for path, filters := range map[string][]string{
		"/Users": {
			`userName eq null`,
			`groups.value eq "00000000-0000-0000-0000-000000000000"`,
			`emails co "example.com"`,
			`emails.value sw "a"`,
			`emails[value co "a"]`,
			`emails[not (type eq "work")]`,
			`emails pr`,
			`photos.value eq "https://example.com/a.jpg"`,
			`meta.version eq "W/\"1\""`,
			`emails[type eq "work" and type eq "home"]`,
			`emails[type eq "work" and (value eq "a" or value eq "b")]`,
		},
		"/Groups": {
			`members.value eq "00000000-0000-0000-0000-000000000000"`,
			`members[value eq "00000000-0000-0000-0000-000000000000"]`,
			`members pr`,
			`not (members.value eq "00000000-0000-0000-0000-000000000000")`,
		},
	} {
		for _, filter := range filters {
			w, body := ts.do(ts.TokenA, http.MethodGet, path+"?"+url.Values{"filter": {filter}}.Encode(), "")
			require.Equal(ts.T(), http.StatusBadRequest, w.Code, filter)
			require.Equal(ts.T(), "invalidFilter", body["scimType"], filter)
		}
	}
}

func (ts *SCIMTestSuite) TestUnknownID() {
	for _, id := range []string{"not-a-uuid", "00000000-0000-0000-0000-000000000000"} {
		ts.expectAs(ts.TokenA, http.StatusNotFound, http.MethodGet, "/Users/"+id, "")
	}
}

func (ts *SCIMTestSuite) TestRequiresSSOProviderOnContext() {
	users := scim.NewUserRepository(ts.API.db, ts.API.config, &scimUserSync{api: ts.API})

	_, _, err := users.List(context.Background(), &protocol.SearchRequest{Count: 10})
	require.Error(ts.T(), err)
	_, err = users.Read(context.Background(), "00000000-0000-0000-0000-000000000000")
	require.Error(ts.T(), err)
}

func (ts *SCIMTestSuite) TestPrimaryEmailRequiredToProvision() {
	w, body := ts.do(ts.TokenA, http.MethodPost, "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"not-an-email"}`)
	require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())
	require.Contains(ts.T(), body["detail"], "is required")
}

func (ts *SCIMTestSuite) TestPrimaryEmail() {
	for userName, tc := range map[string]struct{ emails, want string }{
		"dana@example.com": {`[{"value":"work@example.com"},{"value":"home@example.com","primary":true}]`, "home@example.com"},
		"erin@example.com": {`[{"value":"work@example.com"},{"value":"home@example.com"}]`, "work@example.com"},
	} {
		id := ts.create(ts.TokenA, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"`+userName+`","emails":`+tc.emails+`}`)
		require.Equal(ts.T(), tc.want, ts.linkedUser(id).GetEmail(), userName)
	}
}

func (ts *SCIMTestSuite) TestUsersGroupsAttribute() {
	alice := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	bob := ts.create(ts.TokenA, userWith("bob@example.com", "b-1"))
	ops := ts.createGroup(ts.TokenA, groupWith("Ops", "g-2", alice))
	eng := ts.createGroup(ts.TokenA, groupWith("Engineering", "g-1", alice))

	got := ts.get(ts.TokenA, "/Users/"+alice)
	require.Equal(ts.T(), []any{
		map[string]any{"value": eng, "$ref": "http://localhost:9999/scim/v2/Groups/" + eng, "display": "Engineering", "type": "direct"},
		map[string]any{"value": ops, "$ref": "http://localhost:9999/scim/v2/Groups/" + ops, "display": "Ops", "type": "direct"},
	}, got["groups"])

	require.NotContains(ts.T(), ts.get(ts.TokenA, "/Users/"+bob), "groups")
	require.Len(ts.T(), ts.list(ts.TokenA, `userName eq "alice@example.com"`)["Resources"].([]any)[0].(map[string]any)["groups"], 2)

	claimed := `[{"value":"` + ops + `","display":"Forged"}]`
	w, created := ts.do(ts.TokenA, http.MethodPost, "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"carol@example.com","emails":[{"primary":true,"value":"carol@example.com"}],"groups":`+claimed+`}`)
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	require.NotContains(ts.T(), created, "groups")
	require.NotContains(ts.T(), string(ts.storedUser(created["id"].(string)).Resource), "groups")

	w, replaced := ts.do(ts.TokenA, http.MethodPut, "/Users/"+bob, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"bob@example.com","groups":`+claimed+`}`)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.NotContains(ts.T(), replaced, "groups")
	require.NotContains(ts.T(), string(ts.storedUser(bob).Resource), "groups")

	w, patched := ts.do(ts.TokenA, http.MethodPatch, "/Users/"+alice, patchOp(`{"op":"replace","path":"displayName","value":"Alice"}`))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Len(ts.T(), patched["groups"], 2)
	require.NotContains(ts.T(), string(ts.storedUser(alice).Resource), "groups")

	ts.expectAs(ts.TokenA, http.StatusNoContent, http.MethodDelete, "/Groups/"+ops, "")
	require.Equal(ts.T(), []string{eng}, pluck(ts.get(ts.TokenA, "/Users/"+alice)["groups"], "value"))
}

func userWith(userName, externalID string) string {
	return `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + userName + `","externalId":"` + externalID + `","emails":[{"primary":true,"value":"` + userName + `"}]}`
}

func emails(value string) []core.Email {
	return []core.Email{{Value: value, Primary: new(true)}}
}

func oktaUserWith(field string, value any) string {
	return withField(oktaUser, field, value)
}

func withField(body, field string, value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	match := regexp.MustCompile(`"` + regexp.QuoteMeta(field) + `": ("[^"]*"|true|false)`).FindStringIndex(body)
	if match == nil {
		panic("no " + field + " in body")
	}
	return body[:match[0]] + `"` + field + `": ` + string(encoded) + body[match[1]:]
}

func patchOp(ops ...string) string {
	return `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[` + strings.Join(ops, ",") + `]}`
}

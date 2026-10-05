package api

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
)

func memberIDs(resource map[string]any) []string {
	ids := []string{}
	members, _ := resource["members"].([]any)
	for _, member := range members {
		ids = append(ids, member.(map[string]any)["value"].(string))
	}
	return ids
}

func groupsOf(resource map[string]any) map[string]string {
	out := map[string]string{}
	groups, _ := resource["groups"].([]any)
	for _, group := range groups {
		g := group.(map[string]any)
		out[g["display"].(string)] = g["type"].(string)
	}
	return out
}

func (ts *SCIMTestSuite) get(p scimProvider, path string) map[string]any {
	ts.T().Helper()
	w := ts.scim(p, http.MethodGet, path, nil)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	return decodeJSON(ts.T(), w)
}

func addMembers(ids ...string) map[string]any {
	values := []map[string]any{}
	for _, id := range ids {
		values = append(values, map[string]any{"value": id})
	}
	return map[string]any{"op": "add", "path": "members", "value": values}
}

func removeMember(id string) map[string]any {
	return map[string]any{"op": "remove", "path": fmt.Sprintf(`members[value eq "%s"]`, id)}
}

func (ts *SCIMTestSuite) TestGroupCRUD() {
	alice := ts.createUser(ts.A, "alice@example.com", nil)
	aliceID := alice["id"].(string)

	w := ts.scim(ts.A, http.MethodPost, "/Groups", map[string]any{
		"schemas":     []string{scimGroupURN},
		"displayName": "Doctors",
		"externalId":  "g-1",
		"members":     []map[string]any{{"value": aliceID, "type": "Group"}},
	})
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	group := decodeJSON(ts.T(), w)
	groupID := group["id"].(string)
	require.Equal(ts.T(), "http://localhost:9999/scim/v2/Groups/"+groupID, w.Header().Get("Location"))
	require.Equal(ts.T(), []any{map[string]any{
		"value": aliceID,
		"$ref":  "http://localhost:9999/scim/v2/Users/" + aliceID,
		"type":  "User",
	}}, group["members"], "the member type comes from the directory, not the client")

	require.Equal(ts.T(), map[string]string{"Doctors": "direct"}, groupsOf(ts.get(ts.A, "/Users/"+aliceID)))

	// Groups list, page and filter like Users do.
	ts.createGroup(ts.A, "Nurses")
	require.Equal(ts.T(), float64(2), ts.list(ts.A, "/Groups", url.Values{})["totalResults"])
	require.Equal(ts.T(), []string{groupID}, resourceValues(ts.list(ts.A, "/Groups", url.Values{"filter": {`displayName eq "doctors"`}}), "id"))
	require.Equal(ts.T(), []string{groupID}, resourceValues(ts.list(ts.A, "/Groups", url.Values{"filter": {`externalId eq "g-1"`}}), "id"))
	require.Equal(ts.T(), []string{groupID}, resourceValues(ts.list(ts.A, "/Groups", url.Values{"filter": {`members.value eq "` + aliceID + `"`}}), "id"))
	require.Equal(ts.T(), []string{groupID}, resourceValues(ts.list(ts.A, "/Groups", url.Values{"filter": {`members[type eq "User"]`}}), "id"))
	require.Equal(ts.T(), []string{"Nurses"}, resourceValues(ts.list(ts.A, "/Groups", url.Values{"filter": {"not (members pr)"}}), "displayName"))
	require.Equal(ts.T(), []string{"Doctors", "Nurses"}, resourceValues(ts.list(ts.A, "/Groups", url.Values{"sortBy": {"displayName"}, "count": {"2"}}), "displayName"))
	require.Equal(ts.T(), []string{aliceID}, resourceValues(ts.list(ts.A, "/Users", url.Values{"filter": {`groups.value eq "` + groupID + `"`}}), "id"))
	require.Equal(ts.T(), []string{aliceID}, resourceValues(ts.list(ts.A, "/Users", url.Values{"filter": {`groups[display eq "DOCTORS"]`}}), "id"))

	// excludedAttributes=members skips loading members entirely.
	excluded := ts.get(ts.A, "/Groups/"+groupID+"?excludedAttributes=members")
	require.NotContains(ts.T(), excluded, "members")

	// A full replace rewrites membership.
	bob := ts.createUser(ts.A, "bob@example.com", nil)
	w = ts.scim(ts.A, http.MethodPut, "/Groups/"+groupID, map[string]any{
		"schemas":     []string{scimGroupURN},
		"displayName": "Physicians",
		"externalId":  "g-1",
		"members":     []map[string]any{{"value": bob["id"]}},
	})
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	replaced := decodeJSON(ts.T(), w)
	require.Equal(ts.T(), "Physicians", replaced["displayName"])
	require.Equal(ts.T(), []string{bob["id"].(string)}, memberIDs(replaced))
	require.Empty(ts.T(), groupsOf(ts.get(ts.A, "/Users/"+aliceID)))

	// Okta reconciles the group with a pathless replace before syncing members.
	w = ts.scim(ts.A, http.MethodPatch, "/Groups/"+groupID, patchOp(map[string]any{"op": "replace", "value": map[string]any{"id": groupID, "displayName": "Doctors"}}))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), "Doctors", decodeJSON(ts.T(), w)["displayName"])

	w = ts.scim(ts.A, http.MethodDelete, "/Groups/"+groupID, nil)
	require.Equal(ts.T(), http.StatusNoContent, w.Code, w.Body.String())
	ts.requireSCIMError(ts.scim(ts.A, http.MethodGet, "/Groups/"+groupID, nil), http.StatusNotFound, "")
	require.Empty(ts.T(), groupsOf(ts.get(ts.A, "/Users/"+bob["id"].(string))))

	require.Len(ts.T(), ts.auditEntries("scim_group_created"), 2)
	require.Len(ts.T(), ts.auditEntries("scim_group_updated"), 2)
	require.Len(ts.T(), ts.auditEntries("scim_group_deleted"), 1)
	require.Len(ts.T(), ts.auditEntries("scim_group_member_added"), 2)
	require.Len(ts.T(), ts.auditEntries("scim_group_member_removed"), 1)
}

func (ts *SCIMTestSuite) TestGroupMembershipPatch() {
	alice := ts.createUser(ts.A, "alice@example.com", nil)["id"].(string)
	bob := ts.createUser(ts.A, "bob@example.com", nil)["id"].(string)
	group := ts.createGroup(ts.A, "Doctors")
	path := "/Groups/" + group["id"].(string)

	w := ts.scim(ts.A, http.MethodPatch, path, patchOp(addMembers(alice, bob)))
	require.Equal(ts.T(), http.StatusNoContent, w.Code, w.Body.String())
	require.Equal(ts.T(), `W/"2"`, w.Header().Get("ETag"))
	require.ElementsMatch(ts.T(), []string{alice, bob}, memberIDs(ts.get(ts.A, path)))

	// Adding an existing member and removing an absent one are no-ops.
	w = ts.scim(ts.A, http.MethodPatch, path, patchOp(addMembers(alice)))
	require.Equal(ts.T(), http.StatusNoContent, w.Code, w.Body.String())
	require.Equal(ts.T(), `W/"2"`, w.Header().Get("ETag"), "a no-op does not change the version")
	absent := uuid.Must(uuid.NewV4()).String()
	w = ts.scim(ts.A, http.MethodPatch, path, patchOp(removeMember(absent)))
	require.Equal(ts.T(), http.StatusNoContent, w.Code, w.Body.String())

	w = ts.scim(ts.A, http.MethodPatch, path, patchOp(removeMember(alice)))
	require.Equal(ts.T(), http.StatusNoContent, w.Code, w.Body.String())
	require.Equal(ts.T(), []string{bob}, memberIDs(ts.get(ts.A, path)))
	require.Len(ts.T(), ts.auditEntries("scim_group_member_added"), 2)
	require.Len(ts.T(), ts.auditEntries("scim_group_member_removed"), 1)

	// Stale versions are refused on the delta path too.
	ts.requireSCIMError(ts.scim(ts.A, http.MethodPatch, path, patchOp(addMembers(alice)), "If-Match", `W/"1"`), http.StatusPreconditionFailed, "")

	// A remove that carries a value is refused, per RFC 7644 Section 3.5.2.2.
	w = ts.scim(ts.A, http.MethodPatch, path, patchOp(map[string]any{"op": "remove", "path": "members", "value": []map[string]any{{"value": bob}}}))
	ts.requireSCIMError(w, http.StatusBadRequest, "invalidSyntax")

	// Members must be resources of this directory.
	foreign := ts.createUser(ts.B, "eve@example.com", nil)["id"].(string)
	ts.requireSCIMError(ts.scim(ts.A, http.MethodPatch, path, patchOp(addMembers(foreign))), http.StatusBadRequest, "invalidValue")
	ts.requireSCIMError(ts.scim(ts.A, http.MethodPatch, path, patchOp(addMembers("not-an-id"))), http.StatusBadRequest, "invalidValue")

	// Mixed operations go through the full PATCH path and keep the same rules.
	w = ts.scim(ts.A, http.MethodPatch, path, patchOp(
		map[string]any{"op": "replace", "path": "displayName", "value": "Physicians"},
		addMembers(alice),
	))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.ElementsMatch(ts.T(), []string{alice, bob}, memberIDs(decodeJSON(ts.T(), w)))

	// A reference-only PATCH asking for attributes gets the resource back.
	w = ts.scim(ts.A, http.MethodPatch, path+"?attributes=members", patchOp(removeMember(alice)))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), []string{bob}, memberIDs(decodeJSON(ts.T(), w)))
}

func (ts *SCIMTestSuite) TestMembershipAndLifecycleAreIndependent() {
	alice := ts.createUser(ts.A, "alice@example.com", nil)["id"].(string)
	group := ts.createGroup(ts.A, "Doctors", alice)
	path := "/Groups/" + group["id"].(string)

	w := ts.scim(ts.A, http.MethodPatch, "/Users/"+alice, patchOp(map[string]any{"op": "replace", "path": "active", "value": false}))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), []string{alice}, memberIDs(ts.get(ts.A, path)), "deactivating keeps membership")

	w = ts.scim(ts.A, http.MethodPatch, path, patchOp(removeMember(alice)))
	require.Equal(ts.T(), http.StatusNoContent, w.Code)
	w = ts.scim(ts.A, http.MethodPatch, "/Users/"+alice, patchOp(map[string]any{"op": "replace", "path": "active", "value": true}))
	require.Equal(ts.T(), http.StatusOK, w.Code)
	w = ts.scim(ts.A, http.MethodPatch, path, patchOp(addMembers(alice)))
	require.Equal(ts.T(), http.StatusNoContent, w.Code)
	w = ts.scim(ts.A, http.MethodPatch, path, patchOp(removeMember(alice)))
	require.Equal(ts.T(), http.StatusNoContent, w.Code)
	require.Equal(ts.T(), true, ts.get(ts.A, "/Users/"+alice)["active"], "leaving every group keeps the user active")

	// Deleting a user removes it from its groups.
	w = ts.scim(ts.A, http.MethodPatch, path, patchOp(addMembers(alice)))
	require.Equal(ts.T(), http.StatusNoContent, w.Code)
	require.Equal(ts.T(), http.StatusNoContent, ts.scim(ts.A, http.MethodDelete, "/Users/"+alice, nil).Code)
	require.Empty(ts.T(), memberIDs(ts.get(ts.A, path)))
	require.Zero(ts.T(), ts.referencesTo(alice))
	removed := ts.auditEntries("scim_group_member_removed")
	require.Equal(ts.T(), alice, removed[len(removed)-1]["traits"].(map[string]any)["member_id"])
}

func (ts *SCIMTestSuite) referencesTo(id string) int {
	ts.T().Helper()
	var count int
	require.NoError(ts.T(), ts.API.db.RawQuery("select count(*) from scim_resource_references where target_id = ?", id).First(&count))
	return count
}

func (ts *SCIMTestSuite) TestNestedGroups() {
	alice := ts.createUser(ts.A, "alice@example.com", nil)["id"].(string)
	staff := ts.createGroup(ts.A, "Staff")["id"].(string)
	clinical := ts.createGroup(ts.A, "Clinical", alice)["id"].(string)
	doctors := ts.createGroup(ts.A, "Doctors", alice)["id"].(string)

	require.Equal(ts.T(), http.StatusNoContent, ts.scim(ts.A, http.MethodPatch, "/Groups/"+staff, patchOp(addMembers(clinical))).Code)
	require.Equal(ts.T(), http.StatusNoContent, ts.scim(ts.A, http.MethodPatch, "/Groups/"+clinical, patchOp(addMembers(doctors))).Code)

	members := ts.get(ts.A, "/Groups/"+staff)["members"].([]any)
	require.Equal(ts.T(), "Group", members[0].(map[string]any)["type"])
	require.Equal(ts.T(), "http://localhost:9999/scim/v2/Groups/"+clinical, members[0].(map[string]any)["$ref"])

	// Membership through a nested group is indirect; a direct one wins.
	require.Equal(ts.T(), map[string]string{"Clinical": "direct", "Doctors": "direct", "Staff": "indirect"}, groupsOf(ts.get(ts.A, "/Users/"+alice)))

	// No group may contain itself, directly or through others.
	for _, attempt := range []struct{ group, member string }{
		{doctors, doctors},
		{doctors, staff},
		{clinical, staff},
	} {
		ts.requireSCIMError(ts.scim(ts.A, http.MethodPatch, "/Groups/"+attempt.group, patchOp(addMembers(attempt.member))), http.StatusBadRequest, "invalidValue")
	}
	w := ts.scim(ts.A, http.MethodPut, "/Groups/"+doctors, map[string]any{
		"schemas": []string{scimGroupURN}, "displayName": "Doctors",
		"members": []map[string]any{{"value": staff}},
	})
	ts.requireSCIMError(w, http.StatusBadRequest, "invalidValue")

	// Deleting a group detaches it from its parents and children.
	require.Equal(ts.T(), http.StatusNoContent, ts.scim(ts.A, http.MethodDelete, "/Groups/"+clinical, nil).Code)
	require.Empty(ts.T(), memberIDs(ts.get(ts.A, "/Groups/"+staff)))
	require.Equal(ts.T(), map[string]string{"Doctors": "direct"}, groupsOf(ts.get(ts.A, "/Users/"+alice)))
}

func (ts *SCIMTestSuite) TestConcurrentNestingCannotFormACycle() {
	one := ts.createGroup(ts.A, "One")["id"].(string)
	two := ts.createGroup(ts.A, "Two")["id"].(string)

	codes := make([]int, 2)
	var wg sync.WaitGroup
	wg.Go(func() { codes[0] = ts.scim(ts.A, http.MethodPatch, "/Groups/"+one, patchOp(addMembers(two))).Code })
	wg.Go(func() { codes[1] = ts.scim(ts.A, http.MethodPatch, "/Groups/"+two, patchOp(addMembers(one))).Code })
	wg.Wait()

	require.ElementsMatch(ts.T(), []int{http.StatusNoContent, http.StatusBadRequest}, codes)
}

func (ts *SCIMTestSuite) TestConcurrentDeleteAndAddLeaveNoDanglingMember() {
	for i := range 5 {
		user := ts.createUser(ts.A, fmt.Sprintf("u%d@example.com", i), nil)["id"].(string)
		group := ts.createGroup(ts.A, fmt.Sprintf("G%d", i))["id"].(string)

		var wg sync.WaitGroup
		wg.Go(func() { ts.scim(ts.A, http.MethodPatch, "/Groups/"+group, patchOp(addMembers(user))) })
		wg.Go(func() { ts.scim(ts.A, http.MethodDelete, "/Users/"+user, nil) })
		wg.Wait()

		require.Empty(ts.T(), memberIDs(ts.get(ts.A, "/Groups/"+group)))
		require.Zero(ts.T(), ts.referencesTo(user))
	}
}

func (ts *SCIMTestSuite) TestLargeGroup() {
	group := ts.createGroup(ts.A, "Everyone")["id"].(string)
	var directoryID string
	require.NoError(ts.T(), ts.API.db.RawQuery("select directory_id from scim_resources where id = ?", group).First(&directoryID))

	// Seed members directly; provisioning each through the API is not the point.
	const size = 5000
	require.NoError(ts.T(), ts.API.db.RawQuery(`
		with users as (
			insert into scim_resources (id, directory_id, resource_type, resource)
			select gen_random_uuid(), ?, 'User', jsonb_build_object('userName', 'bulk' || n || '@example.com')
			from generate_series(1, ?) n returning id
		)
		insert into scim_resource_references (directory_id, source_id, attribute, target_id)
		select ?, ?, 'members', id from users`, directoryID, size, directoryID, group).Exec())
	// Refresh planner statistics as autovacuum would after a bulk load.
	require.NoError(ts.T(), ts.API.db.RawQuery("analyze scim_resources, scim_resource_references").Exec())

	alice := ts.createUser(ts.A, "alice@example.com", nil)["id"].(string)
	require.Equal(ts.T(), http.StatusNoContent, ts.scim(ts.A, http.MethodPatch, "/Groups/"+group, patchOp(addMembers(alice))).Code)
	require.Equal(ts.T(), http.StatusNoContent, ts.scim(ts.A, http.MethodPatch, "/Groups/"+group, patchOp(removeMember(alice))).Code)

	require.Len(ts.T(), ts.get(ts.A, "/Groups/"+group)["members"], size)
	require.Equal(ts.T(), float64(size), ts.list(ts.A, "/Users", url.Values{"count": {"0"}, "filter": {`groups.value eq "` + group + `"`}})["totalResults"])
}

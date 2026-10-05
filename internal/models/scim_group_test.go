package models

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/storage"
)

type SCIMGroupTestSuite struct {
	suite.Suite
	db       *storage.Connection
	provider *SSOProvider
}

func TestSCIMGroup(t *testing.T) {
	ts := &SCIMGroupTestSuite{db: setupSCIMTestDB(t)}
	defer func() { require.NoError(t, ts.db.Close()) }()
	suite.Run(t, ts)
}

func (ts *SCIMGroupTestSuite) SetupTest() {
	require.NoError(ts.T(), TruncateAll(ts.db))
	ts.provider = ts.createProvider()
}

func (ts *SCIMGroupTestSuite) TestCreate() {
	group, err := CreateSCIMGroup(ts.db, ts.provider.ID, []byte(`{"displayName":"Engineering","externalId":"ext-1"}`))
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), ts.provider.ID, group.SSOProviderID)
	require.Equal(ts.T(), "Group", group.ResourceType)
	require.Equal(ts.T(), "ext-1", ts.attribute(group, "externalId"))
	require.JSONEq(ts.T(), `{"displayName":"Engineering","externalId":"ext-1"}`, string(group.Resource))
	require.False(ts.T(), group.CreatedAt.IsZero())

}

func (ts *SCIMGroupTestSuite) TestReplaceChecksVersion() {
	group := ts.createGroup(ts.provider.ID, "Engineering")

	replaced, changed, err := ReplaceSCIMGroupIfChanged(ts.db, SCIMTarget{ProviderID: ts.provider.ID, ID: group.ID, UpdatedAt: &group.UpdatedAt}, []byte(`{"displayName":"Platform"}`))
	require.NoError(ts.T(), err)
	require.True(ts.T(), changed)
	require.Equal(ts.T(), "Platform", ts.attribute(replaced, "displayName"))

	_, _, err = ReplaceSCIMGroupIfChanged(ts.db, SCIMTarget{ProviderID: ts.provider.ID, ID: group.ID, UpdatedAt: &group.UpdatedAt}, []byte(`{"displayName":"Stale"}`))
	require.ErrorIs(ts.T(), err, ErrSCIMStale)

	other := ts.createProvider().ID
	for _, version := range []*time.Time{nil, &replaced.UpdatedAt} {
		_, _, err = ReplaceSCIMGroupIfChanged(ts.db, SCIMTarget{ProviderID: other, ID: group.ID, UpdatedAt: version}, []byte(`{"displayName":"Other"}`))
		require.ErrorIs(ts.T(), err, SCIMNotFoundError{})
	}
}

func (ts *SCIMGroupTestSuite) TestEachWriteInATransactionGetsANewVersion() {
	group := ts.createGroup(ts.provider.ID, "Engineering")
	alice := ts.createUser(ts.provider.ID, "alice")

	require.NoError(ts.T(), ts.db.Transaction(func(tx *storage.Connection) error {
		replaced, changed, err := ReplaceSCIMGroupIfChanged(tx, SCIMTarget{ProviderID: ts.provider.ID, ID: group.ID}, []byte(`{"displayName":"Platform"}`))
		require.NoError(ts.T(), err)
		require.True(ts.T(), changed)
		touched, _, err := ReplaceSCIMGroupMembers(tx, replaced, []uuid.UUID{alice.ID})
		require.NoError(ts.T(), err)
		require.True(ts.T(), touched.UpdatedAt.After(replaced.UpdatedAt))
		return nil
	}))
}

func (ts *SCIMGroupTestSuite) TestDeleteRemovesMembers() {
	group := ts.createGroup(ts.provider.ID, "Engineering")
	ts.addMembers(group, ts.createUser(ts.provider.ID, "alice").ID)

	_, err := DeleteSCIMGroup(ts.db, SCIMTarget{ProviderID: ts.provider.ID, ID: group.ID})
	require.NoError(ts.T(), err)

	_, err = FindSCIMGroup(ts.db, ts.provider.ID, group.ID)
	require.ErrorIs(ts.T(), err, SCIMNotFoundError{})

	for _, version := range []*time.Time{nil, &group.UpdatedAt} {
		_, err = DeleteSCIMGroup(ts.db, SCIMTarget{ProviderID: ts.provider.ID, ID: group.ID, UpdatedAt: version})
		require.ErrorIs(ts.T(), err, SCIMNotFoundError{})
	}
}

func (ts *SCIMGroupTestSuite) TestReplaceMembersDiffs() {
	group := ts.createGroup(ts.provider.ID, "Engineering")
	alice := ts.createUser(ts.provider.ID, "Alice")
	bob := ts.createUser(ts.provider.ID, "bob")
	carol := ts.createUser(ts.provider.ID, "carol")

	_, change, err := ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{alice.ID, bob.ID, alice.ID})
	require.NoError(ts.T(), err)
	require.ElementsMatch(ts.T(), []uuid.UUID{alice.ID, bob.ID}, change.Added)
	require.Empty(ts.T(), change.Removed)

	_, change, err = ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{bob.ID, carol.ID})
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), []uuid.UUID{carol.ID}, change.Added)
	require.Equal(ts.T(), []uuid.UUID{alice.ID}, change.Removed)
	require.ElementsMatch(ts.T(), []uuid.UUID{bob.ID, carol.ID}, ts.members(group))

	_, change, err = ReplaceSCIMGroupMembers(ts.db, group, nil)
	require.NoError(ts.T(), err)
	require.Empty(ts.T(), change.Added)
	require.ElementsMatch(ts.T(), []uuid.UUID{bob.ID, carol.ID}, change.Removed)
}

func (ts *SCIMGroupTestSuite) TestReplaceMembersRejectsUnknownUsers() {
	group := ts.createGroup(ts.provider.ID, "Engineering")
	alice := ts.createUser(ts.provider.ID, "alice")
	bob := ts.createUser(ts.provider.ID, "bob")
	_, err := DeleteSCIMUser(ts.db, SCIMTarget{ProviderID: ts.provider.ID, ID: bob.ID})
	require.NoError(ts.T(), err)
	mallory := ts.createUser(ts.createProvider().ID, "mallory")

	for _, id := range []uuid.UUID{mallory.ID, bob.ID, uuid.Must(uuid.NewV4())} {
		_, _, err = ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{alice.ID, id})
		require.ErrorIs(ts.T(), err, ErrSCIMGroupMemberNotFound)
		require.Empty(ts.T(), ts.members(group))
	}
}

func (ts *SCIMGroupTestSuite) TestReplaceMembersSkipsDeletedMembers() {
	group := ts.createGroup(ts.provider.ID, "Engineering")
	alice := ts.createUser(ts.provider.ID, "alice")
	bob := ts.createUser(ts.provider.ID, "bob")
	ts.addMembers(group, alice.ID)
	_, err := DeleteSCIMUser(ts.db, SCIMTarget{ProviderID: ts.provider.ID, ID: alice.ID})
	require.NoError(ts.T(), err)
	require.Empty(ts.T(), ts.members(group))

	_, err = DeleteSCIMUser(ts.db, SCIMTarget{ProviderID: ts.provider.ID, ID: alice.ID, UpdatedAt: &alice.UpdatedAt})
	require.ErrorIs(ts.T(), err, SCIMNotFoundError{})

	_, change, err := ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{alice.ID, bob.ID})
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), []uuid.UUID{bob.ID}, change.Added)
	require.Empty(ts.T(), change.Removed)

	_, _, err = ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{alice.ID, bob.ID, uuid.Nil})
	require.ErrorIs(ts.T(), err, ErrSCIMGroupMemberNotFound)
}

func (ts *SCIMGroupTestSuite) TestFindMembershipsByUser() {
	engineering := ts.createGroup(ts.provider.ID, "Engineering")
	admins := ts.createGroup(ts.provider.ID, "Admins")
	alice := ts.createUser(ts.provider.ID, "alice")
	bob := ts.createUser(ts.provider.ID, "bob")
	ts.addMembers(engineering, alice.ID, bob.ID)
	ts.addMembers(admins, alice.ID)

	groups, err := FindSCIMMembershipsByUser(ts.db, ts.provider.ID, []uuid.UUID{alice.ID, bob.ID})
	require.NoError(ts.T(), err)
	require.Len(ts.T(), groups, 3)

	byUser := map[uuid.UUID][]string{}
	for _, g := range groups {
		byUser[g.SCIMUserID] = append(byUser[g.SCIMUserID], g.Display)
	}
	require.Equal(ts.T(), []string{"Admins", "Engineering"}, byUser[alice.ID])
	require.Equal(ts.T(), []string{"Engineering"}, byUser[bob.ID])

	groups, err = FindSCIMMembershipsByUser(ts.db, ts.createProvider().ID, []uuid.UUID{alice.ID})
	require.NoError(ts.T(), err)
	require.Empty(ts.T(), groups)
}

func (ts *SCIMGroupTestSuite) createProvider() *SSOProvider {
	return createSCIMTestProvider(ts.T(), ts.db)
}

func (ts *SCIMGroupTestSuite) createGroup(providerID uuid.UUID, displayName string) *SCIMGroup {
	group, err := CreateSCIMGroup(ts.db, providerID, []byte(fmt.Sprintf(`{"displayName":%q}`, displayName)))
	require.NoError(ts.T(), err)
	return group
}

func (ts *SCIMGroupTestSuite) createUser(providerID uuid.UUID, userName string) *SCIMUser {
	user, err := CreateSCIMUser(ts.db, providerID, []byte(fmt.Sprintf(`{"userName":%q}`, userName)))
	require.NoError(ts.T(), err)
	return user
}

func (ts *SCIMGroupTestSuite) addMembers(group *SCIMGroup, ids ...uuid.UUID) {
	_, _, err := ReplaceSCIMGroupMembers(ts.db, group, ids)
	require.NoError(ts.T(), err)
}

func (ts *SCIMGroupTestSuite) members(group *SCIMGroup) []uuid.UUID {
	members, err := FindSCIMMembershipsByGroup(ts.db, ts.provider.ID, []uuid.UUID{group.ID})
	require.NoError(ts.T(), err)
	ids := make([]uuid.UUID, len(members))
	for i, m := range members {
		ids[i] = m.SCIMUserID
	}
	return ids
}

func (ts *SCIMGroupTestSuite) attribute(group *SCIMGroup, name string) any {
	var resource map[string]any
	require.NoError(ts.T(), json.Unmarshal(group.Resource, &resource))
	return resource[name]
}

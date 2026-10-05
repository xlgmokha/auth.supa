package models

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSCIMUserLinkedThroughIdentity(t *testing.T) {
	db := setupSCIMTestDB(t)
	provider := createSCIMTestProvider(t, db)
	user, err := NewUser("", "bjensen@example.com", "", "test", nil)
	require.NoError(t, err)
	require.NoError(t, db.Create(user))
	identity, err := NewIdentity(user, "sso:"+provider.ID.String(), map[string]any{"sub": "BJensen"})
	require.NoError(t, err)
	require.NoError(t, db.Create(identity))

	row, err := CreateSCIMUser(db, provider.ID, []byte(`{"userName":"bjensen"}`))
	require.NoError(t, err)
	linked, err := FindSCIMLinkedUser(db, row)
	require.NoError(t, err)
	require.Equal(t, user.ID, linked.ID)

	deprovisioned, err := IsSCIMUserDeprovisioned(db, user.ID)
	require.NoError(t, err)
	require.False(t, deprovisioned)

	_, err = DeleteSCIMUser(db, SCIMTarget{ProviderID: provider.ID, ID: row.ID})
	require.NoError(t, err)
	deprovisioned, err = IsSCIMUserDeprovisioned(db, user.ID)
	require.NoError(t, err)
	require.True(t, deprovisioned)

	_, err = CreateSCIMUser(db, provider.ID, []byte(`{"userName":"BJENSEN"}`))
	require.NoError(t, err)
	deprovisioned, err = IsSCIMUserDeprovisionedByProvider(db, provider.ID, user.ID)
	require.NoError(t, err)
	require.False(t, deprovisioned)

	other, err := CreateSCIMUser(db, provider.ID, []byte(`{"userName":"babs"}`))
	require.NoError(t, err)
	linked, err = FindSCIMLinkedUser(db, other)
	require.NoError(t, err)
	require.Nil(t, linked)
}

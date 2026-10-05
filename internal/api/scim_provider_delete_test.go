package api

import (
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/models"
)

func scimUser(name string) string {
	return userWith(name+"@example.com", name)
}

func (ts *SCIMTestSuite) deleteProvider(p *models.SSOProvider) {
	w := serveAdmin(ts.T(), ts.API, http.MethodDelete, "/admin/sso/providers/"+p.ID.String(), nil)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
}

func (ts *SCIMTestSuite) reloadUser(id uuid.UUID) *models.User {
	user, err := models.FindUserByID(ts.API.db, id)
	require.NoError(ts.T(), err)
	return user
}

func (ts *SCIMTestSuite) countRows(model any, where string, args ...any) int {
	count, err := ts.API.db.Q().Where(where, args...).Count(model)
	require.NoError(ts.T(), err)
	return count
}

func (ts *SCIMTestSuite) auditActions(action models.AuditAction) []models.AuditLogEntry {
	return queryAuditEntries(ts.T(), ts.API.db, "payload->>'action' = ?", string(action))
}

func (ts *SCIMTestSuite) TestProviderDeleteCascadesSCIMRows() {
	activeID := ts.create(ts.TokenA, scimUser("active"))
	active := ts.linkedUser(activeID)
	deactivatedID := ts.create(ts.TokenA, scimUser("deactivated"))
	deactivated := ts.linkedUser(deactivatedID)
	ts.setActive(deactivatedID, false)
	ts.createGroup(ts.TokenA, groupWith("A", "", activeID, deactivatedID))
	ts.create(ts.TokenB, scimUser("other"))
	groupEvents := ts.countRows(&models.AuditLogEntry{}, "payload->>'action' LIKE 'scim_group_%'")

	ts.deleteProvider(ts.A)

	require.Equal(ts.T(), groupEvents, ts.countRows(&models.AuditLogEntry{}, "payload->>'action' LIKE 'scim_group_%'"))
	require.False(ts.T(), ts.reloadUser(active.ID).IsBanned())
	require.False(ts.T(), ts.reloadUser(deactivated.ID).IsBanned())
	require.Zero(ts.T(), ts.countRows(&models.SCIMUser{}, "sso_provider_id = ? AND resource_type = 'User'", ts.A.ID))
	require.Zero(ts.T(), ts.countRows(&models.SCIMGroup{}, "sso_provider_id = ? AND resource_type = 'Group'", ts.A.ID))
	require.Zero(ts.T(), ts.countRows(&models.SCIMToken{}, "sso_provider_id = ?", ts.A.ID))
	require.Equal(ts.T(), 1, ts.countRows(&models.SCIMUser{}, "sso_provider_id = ? AND resource_type = 'User'", ts.B.ID))
	ts.expectAs(ts.TokenB, http.StatusOK, http.MethodGet, "/Users", "")
}

func (ts *SCIMTestSuite) TestProviderDeleteAudit() {
	for name, setup := range map[string]func() []any{
		"active token": func() []any { return []any{ts.TokenA[:12]} },
		"expired token": func() []any {
			require.NoError(ts.T(), ts.API.db.RawQuery(
				"UPDATE "+(&models.SCIMToken{}).TableName()+" SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' WHERE sso_provider_id = ?", ts.A.ID,
			).Exec())
			return []any{}
		},
		"SCIM disabled": func() []any {
			_, err := models.DisableSCIM(ts.API.db, ts.A.ID)
			require.NoError(ts.T(), err)
			return nil
		},
		"SCIM flag off": func() []any {
			ts.API.config.SSO.SCIM.Enabled = false
			return nil
		},
	} {
		ts.SetupTest()
		prefixes := setup()
		entries := ts.auditDuring(func() { ts.deleteProvider(ts.A) })
		ts.API.config.SSO.SCIM.Enabled = true
		if prefixes == nil {
			require.Empty(ts.T(), entries, name)
			continue
		}
		require.Equal(ts.T(), []string{string(models.SCIMDisabledAction)}, actionsOf(entries), name)
		traits := entries[0].Payload["traits"].(map[string]any)
		require.Equal(ts.T(), prefixes, traits["token_prefixes"], name)
		require.Equal(ts.T(), ts.A.ID.String(), traits["sso_provider_id"], name)
	}
}

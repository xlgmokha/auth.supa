// Package scim serves SCIM 2.0 (RFC 7643, RFC 7644) provisioning for SSO
// providers on top of github.com/supabase-community/scim-go. Every resource
// type is stored through one generic repository; only the definitions below
// know about Users and Groups.
package scim

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

const (
	// BasePath is where the SCIM server is mounted.
	BasePath = "/scim/v2"

	documentationURI = "https://supabase.com/docs/guides/auth/enterprise-sso/scim"
	maxResults       = 100
)

// Server is the SCIM service provider for every SSO provider's directory.
type Server struct {
	db      *storage.Connection
	config  *conf.GlobalConfiguration
	baseURL string
	limits  protocol.Limits
	types   map[string]*resourceType
	handler http.Handler
	now     func() time.Time
}

// NewServer builds the SCIM server.
func NewServer(config *conf.GlobalConfiguration, db *storage.Connection) *Server {
	s := &Server{
		db:      db,
		config:  config,
		baseURL: BaseURL(config),
		limits:  protocol.DefaultLimits,
		types:   map[string]*resourceType{},
		now:     time.Now,
	}

	userAttributes := core.UserAttributes()
	enterpriseAttributes := core.EnterpriseUserAttributes()
	groupAttributes := core.GroupAttributes()

	users := &resourceType{
		name:     "User",
		endpoint: "/Users",
		schemas: core.Schemas{
			core.NewSchema(core.SchemaUser).WithName("User").With(userAttributes...),
			core.NewSchema(core.SchemaEnterpriseUser).With(enterpriseAttributes...),
		},
		keys: []key{
			{attribute: "userName", unique: true},
			{attribute: "externalId", unique: true},
		},
		derived: []derived{{attribute: "groups", via: "members", display: "displayName"}},
		hooks:   userHooks{config: config},
	}
	groups := &resourceType{
		name:     "Group",
		endpoint: "/Groups",
		schemas: core.Schemas{
			core.NewSchema(core.SchemaGroup).WithName("Group").With(groupAttributes...),
		},
		keys: []key{
			{attribute: "displayName"},
			{attribute: "externalId", unique: true},
		},
		references: []reference{{
			attribute: "members",
			targets:   []string{"User", "Group"},
			added:     models.SCIMGroupMemberAddedAction,
			removed:   models.SCIMGroupMemberRemovedAction,
		}},
		hooks: noHooks{},
	}
	s.types[users.name] = users
	s.types[groups.name] = groups

	spc := core.NewServiceProviderConfig().Patching().Filtering(maxResults).Sorting().Versioning()
	spc.DocumentationURI = documentationURI

	s.handler = server.New(BasePath, spc,
		server.WithBaseURL(s.baseURL),
		server.ErrorHandler(logError),
		server.WithResource(
			server.NewResource[*core.User]("User", users.endpoint, core.SchemaUser, userAttributes...).
				WithDescription("User Account").
				WithExtension(core.SchemaEnterpriseUser, enterpriseAttributes...).
				WithRepository(&repository[*core.User]{server: s, kind: users}),
		),
		server.WithResource(
			server.NewResource[*core.Group]("Group", groups.endpoint, core.SchemaGroup, groupAttributes...).
				WithDescription("Group").
				WithRepository(&repository[*core.Group]{server: s, kind: groups}),
		),
		server.WithAuthentication(core.NewOAuthBearerToken().AsPrimary(), server.RequireBearerToken(s.authorize)),
	)
	return s
}

// BaseURL is the SCIM base URL an identity provider is configured with.
func BaseURL(config *conf.GlobalConfiguration) string {
	return strings.TrimRight(config.API.ExternalURL, "/") + BasePath
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPatch && s.patchReferences(w, r) {
		return
	}
	s.handler.ServeHTTP(w, r)
}

// authorize admits a request whose bearer token resolved to a usable
// credential, scoping it to that credential's directory. A token that is
// unknown, revoked or expired is invalid; a directory that is disabled, or
// whose SSO provider is, refuses every request.
func (s *Server) authorize(ctx context.Context, _ string) (context.Context, error) {
	credential := credentialFrom(ctx)
	now := s.now()
	if credential == nil || !credential.IsUsable(now) {
		return ctx, server.ErrInvalidToken
	}
	if credential.ProviderDisabled || !credential.DirectoryEnabled {
		return ctx, scimerrors.ErrForbidden("SCIM provisioning is disabled for this SSO provider")
	}
	if err := credential.Touch(s.db.WithContext(ctx), now); err != nil {
		logrus.WithError(err).Warn("could not record SCIM token use")
	}
	return withTenant(ctx, &Tenant{
		DirectoryID:   credential.DirectoryID,
		SSOProviderID: credential.SSOProviderID,
		TokenPrefix:   credential.Prefix,
		request:       requestFrom(ctx),
	}), nil
}

func logError(r *http.Request, err error) {
	observability.GetLogEntry(r).Entry.WithError(err).Error("SCIM request failed")
}

package scim

import (
	"net/http"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

const BasePath = "/scim/v2"

type Server struct {
	*server.Server
	cfg *core.ServiceProviderConfig
}

func NewServer(config *conf.GlobalConfiguration, db *storage.Connection) http.Handler {
	cfg := core.NewServiceProviderConfig().Filtering(protocol.DefaultLimits.MaxCount).Patching().Sorting()
	return &Server{
		cfg: cfg,
		Server: server.New(BasePath,
			cfg,
			server.WithBaseURL(BaseURL(config)),
			server.ErrorHandler(func(r *http.Request, err error) {
				observability.GetLogEntry(r).Entry.WithError(err).Error("scim: request failed")
			}),
			server.WithResource(server.
				NewResource[*core.User]("User", "/Users", core.SchemaUser, core.UserAttributes()...).
				WithExtension(core.SchemaEnterpriseUser, core.EnterpriseUserAttributes()...).
				WithRepository(NewRepository[*core.User](db, "User", BaseURL(config)+"/Users", core.Schemas{
					core.NewSchema(core.SchemaUser).With(core.UserAttributes()...),
					core.NewSchema(core.SchemaEnterpriseUser).With(core.EnterpriseUserAttributes()...),
				})),
			),
			server.WithResource(server.
				NewResource[*core.Group]("Group", "/Groups", core.SchemaGroup, core.GroupAttributes()...).
				WithRepository(NewRepository[*core.Group](db, "Group", BaseURL(config)+"/Groups", core.Schemas{
					core.NewSchema(core.SchemaGroup).With(core.GroupAttributes()...),
				})),
			),
			server.WithAuthentication(core.NewOAuthBearerToken().AsPrimary(), newAuthenticate(db)),
		),
	}
}

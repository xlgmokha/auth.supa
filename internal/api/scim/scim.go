package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/ctxkey"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

const (
	BasePath          = "/scim/v2"
	resourceTypeUser  = "User"
	resourceTypeGroup = "Group"

	ClaimSub           = "sub"
	ClaimEmail         = "email"
	claimEmailVerified = "email_verified"
)

var (
	RequestKey = ctxkey.New[*http.Request]("scim_request")
	tokenKey   = ctxkey.New[*models.SCIMToken]("scim_token")

	unstored = strings.Fields("id meta password groups members")

	commonSortKeys = map[string]models.SCIMSortKey{
		"id":                models.SCIMSortByID,
		"meta.created":      models.SCIMSortByCreatedAt,
		"meta.lastmodified": models.SCIMSortByUpdatedAt,
	}
)

func NewServer(db *storage.Connection, config *conf.GlobalConfiguration, events UserEvents, validate server.TokenValidator, limit func(http.Handler) http.Handler) *server.Server {
	authenticate := func(next http.Handler) http.Handler {
		return server.RequireBearerToken(validate)(limit(next))
	}
	return server.New(BasePath,
		core.NewServiceProviderConfig().Filtering(protocol.DefaultLimits.MaxCount).Patching().Sorting().Versioning(),
		server.WithBaseURL(BaseURL(config)),
		server.ErrorHandler(func(r *http.Request, err error) {
			observability.GetLogEntry(r).Entry.WithError(err).Error("scim: request failed")
		}),
		server.WithResource(server.NewResource[*core.User](resourceTypeUser, "/Users", core.SchemaUser, userSchemas.Base().Attributes...).
			WithExtension(core.SchemaEnterpriseUser, userSchemas.Extensions()[0].Attributes...).
			WithRepository(NewUserRepository(db, config, events))),
		server.WithResource(server.NewResource[*core.Group](resourceTypeGroup, "/Groups", core.SchemaGroup, groupSchemas.Base().Attributes...).
			WithRepository(&groupRepository{db: db, config: config})),
		server.WithAuthentication(core.NewOAuthBearerToken().AsPrimary(), authenticate),
	)
}

func NewTokenValidator(db *storage.Connection) server.TokenValidator {
	return func(ctx context.Context, candidate string) (context.Context, error) {
		token, err := models.AuthenticateSCIMToken(db.WithContext(ctx), candidate)
		if models.IsNotFoundError(err) {
			return ctx, server.ErrInvalidToken
		}
		if err != nil {
			return ctx, err
		}
		return tokenKey.WithValue(ctx, token), nil
	}
}

func LimitInvalidTokens(validate server.TokenValidator, limited func(*http.Request) bool) server.TokenValidator {
	return func(ctx context.Context, candidate string) (context.Context, error) {
		next, err := validate(ctx, candidate)
		if !errors.Is(err, server.ErrInvalidToken) {
			return next, err
		}
		if r := RequestKey.Value(ctx); r != nil && limited(r) {
			return ctx, errTooManyRequests()
		}
		return next, err
	}
}

func WithRequest(w http.ResponseWriter, req *http.Request) (context.Context, error) {
	ctx := RequestKey.WithValue(req.Context(), req)
	return groupSnapshotKey.WithValue(ctx, &groupSnapshot{}), nil
}

func BaseURL(config *conf.GlobalConfiguration) string {
	return strings.TrimRight(config.API.ExternalURL, "/") + BasePath
}

func toQuery(query *protocol.SearchRequest, schemas core.Schemas, name string) (models.SCIMQuery, error) {
	search := models.SCIMQuery{Offset: query.Offset(), Limit: query.Count}
	if query.Filter != "" {
		criteria, err := protocol.Filter(schemas, query.Filter, sqlFilter{schemas: schemas, name: name})
		if err != nil {
			return search, err
		}
		search.Filter = criteria
	}
	if query.SortBy == "" {
		return search, nil
	}
	parent, attribute, err := query.SortAttribute(schemas)
	if err != nil {
		return search, err
	}
	key := parent.Name
	if attribute != parent {
		key += "." + attribute.Name
	}
	lower := strings.ToLower(key)
	by, ok := commonSortKeys[lower]
	if !ok && lower == strings.ToLower(name) {
		by, ok = models.SCIMSortByName, true
	}
	if !ok {
		return search, scimerrors.ErrInvalidValue(fmt.Sprintf(`"sortBy" must be one of "id", %q, "meta.created" or "meta.lastModified"`, name))
	}
	search.Order = models.SCIMOrder{By: by, Descending: query.Descending()}
	return search, nil
}

func encode(resource core.Resource) ([]byte, error) {
	fields, err := core.NewObject(resource)
	if err != nil {
		return nil, err
	}
	for _, key := range unstored {
		fields.Remove(key)
	}
	return json.Marshal(fields)
}

func parseTarget(ctx context.Context, id, version string) (models.SCIMTarget, error) {
	providerID, err := ProviderID(ctx)
	if err != nil {
		return models.SCIMTarget{}, err
	}
	resourceID, err := uuid.FromString(id)
	if err != nil {
		return models.SCIMTarget{}, errNotFound()
	}
	target := models.SCIMTarget{ProviderID: providerID, ID: resourceID}
	if version == "" {
		return target, nil
	}
	micros, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(version, `W/"`), `"`), 10, 64)
	if err != nil {
		return models.SCIMTarget{}, errStale()
	}
	updatedAt := time.UnixMicro(micros)
	target.UpdatedAt = &updatedAt
	return target, nil
}

func ProviderID(ctx context.Context) (uuid.UUID, error) {
	token := tokenKey.Value(ctx)
	if token == nil || token.SSOProviderID == uuid.Nil {
		return uuid.Nil, errors.New("scim: request has no SSO provider")
	}
	return token.SSOProviderID, nil
}

func ProviderType(providerID uuid.UUID) string {
	return "sso:" + providerID.String()
}

func requestFrom(ctx context.Context) (*http.Request, error) {
	r := RequestKey.Value(ctx)
	if r == nil {
		return nil, apierrors.NewInternalServerError("SCIM request missing from context")
	}
	return r.WithContext(ctx), nil
}

func versionOf(updatedAt time.Time) string {
	return `W/"` + strconv.FormatInt(updatedAt.UnixMicro(), 10) + `"`
}

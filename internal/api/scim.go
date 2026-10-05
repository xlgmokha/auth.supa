package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/badoux/checkmail"
	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/ctxkey"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

const (
	scimBasePath          = "/scim/v2"
	scimResourceTypeUser  = "User"
	scimResourceTypeGroup = "Group"

	scimClaimSub           = "sub"
	scimClaimEmail         = "email"
	scimClaimEmailVerified = "email_verified"
)

var (
	scimRequestKey       = ctxkey.New[*http.Request]("scim_request")
	scimTokenKey         = ctxkey.New[*models.SCIMToken]("scim_token")
	scimGroupSnapshotKey = ctxkey.New[*scimGroupSnapshot]("scim_group_snapshot")

	scimUserSchemas = core.Schemas{
		core.NewSchema(core.SchemaUser).With(core.UserAttributes()...),
		core.NewSchema(core.SchemaEnterpriseUser).With(core.EnterpriseUserAttributes()...),
	}
	scimGroupSchemas = core.Schemas{core.NewSchema(core.SchemaGroup).With(core.GroupAttributes()...)}

	scimUnstored = strings.Fields("id meta password groups members")

	scimCommonSortKeys = map[string]models.SCIMSortKey{
		"id":                models.SCIMSortByID,
		"meta.created":      models.SCIMSortByCreatedAt,
		"meta.lastmodified": models.SCIMSortByUpdatedAt,
	}
)

type scimAuditEvent struct {
	actor      *models.User
	action     models.AuditAction
	providerID uuid.UUID
	traits     map[string]any
}

func (a *API) newSCIMServer(validate server.TokenValidator, limit func(http.Handler) http.Handler) *server.Server {
	authenticate := func(next http.Handler) http.Handler {
		return server.RequireBearerToken(validate)(limit(next))
	}
	return server.New(scimBasePath,
		core.NewServiceProviderConfig().Filtering(protocol.DefaultLimits.MaxCount).Patching().Sorting().Versioning(),
		server.WithBaseURL(scimBaseURL(a.config)),
		server.ErrorHandler(func(r *http.Request, err error) {
			observability.GetLogEntry(r).Entry.WithError(err).Error("scim: request failed")
		}),
		server.WithResource(server.NewResource[*core.User](scimResourceTypeUser, "/Users", core.SchemaUser, scimUserSchemas.Base().Attributes...).
			WithExtension(core.SchemaEnterpriseUser, scimUserSchemas.Extensions()[0].Attributes...).
			WithRepository(a.newSCIMUserRepository())),
		server.WithResource(server.NewResource[*core.Group](scimResourceTypeGroup, "/Groups", core.SchemaGroup, scimGroupSchemas.Base().Attributes...).
			WithRepository(&scimGroupRepository{db: a.db, config: a.config})),
		server.WithAuthentication(core.NewOAuthBearerToken().AsPrimary(), authenticate),
	)
}

func newSCIMTokenValidator(db *storage.Connection) server.TokenValidator {
	return func(ctx context.Context, candidate string) (context.Context, error) {
		token, err := models.AuthenticateSCIMToken(db.WithContext(ctx), candidate)
		if models.IsNotFoundError(err) {
			return ctx, server.ErrInvalidToken
		}
		if err != nil {
			return ctx, err
		}
		return scimTokenKey.WithValue(ctx, token), nil
	}
}

func (a *API) withSCIMRequest(w http.ResponseWriter, req *http.Request) (context.Context, error) {
	ctx := scimRequestKey.WithValue(req.Context(), req)
	return scimGroupSnapshotKey.WithValue(ctx, &scimGroupSnapshot{}), nil
}

func (a *API) newSCIMUserRepository() *scimUserRepository {
	return &scimUserRepository{db: a.db, config: a.config, events: &scimUserSync{api: a}}
}

func auditSCIM(config *conf.GlobalConfiguration, tx *storage.Connection, r *http.Request, event scimAuditEvent) error {
	event.traits["sso_provider_id"] = event.providerID
	event.traits["outcome"] = "success"
	return models.NewAuditLogEntry(config.AuditLog, r, tx, event.actor, event.action, utilities.GetIPAddress(r), event.traits)
}

func (a *API) deleteSCIMUsers(tx *storage.Connection, r *http.Request, actor *models.User, userID uuid.UUID) error {
	rows, err := models.SoftDeleteSCIMUsersByUserID(tx, userID)
	if err != nil {
		return err
	}
	for i := range rows {
		if err := models.RemoveSCIMUserFromGroups(tx, rows[i].ID); err != nil {
			return err
		}
		event := scimAuditEvent{actor: actor, action: models.SCIMUserDeletedAction, providerID: rows[i].SSOProviderID, traits: scimUserTraits(&rows[i], &userID)}
		if err := auditSCIM(a.config, tx, r, event); err != nil {
			return err
		}
	}
	return nil
}

func scimBaseURL(config *conf.GlobalConfiguration) string {
	return strings.TrimRight(config.API.ExternalURL, "/") + scimBasePath
}

func scimSearch(query *protocol.SearchRequest, schemas core.Schemas, name string) (models.SCIMQuery, error) {
	search := models.SCIMQuery{Offset: query.Offset(), Limit: query.Count}
	if query.Filter != "" {
		criteria, err := protocol.Filter(schemas, query.Filter, scimSQLFilter{schemas: schemas, name: name})
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
	by, ok := scimCommonSortKeys[lower]
	if !ok && lower == strings.ToLower(name) {
		by, ok = models.SCIMSortByName, true
	}
	if !ok {
		return search, scimerrors.ErrInvalidValue(fmt.Sprintf(`"sortBy" must be one of "id", %q, "meta.created" or "meta.lastModified"`, name))
	}
	search.Order = models.SCIMOrder{By: by, Descending: query.Descending()}
	return search, nil
}

func scimEncode(resource core.Resource) ([]byte, error) {
	fields, err := core.NewObject(resource)
	if err != nil {
		return nil, err
	}
	for _, key := range scimUnstored {
		fields.Remove(key)
	}
	return json.Marshal(fields)
}

func scimTarget(ctx context.Context, id, version string) (models.SCIMTarget, error) {
	providerID, err := scimProviderID(ctx)
	if err != nil {
		return models.SCIMTarget{}, err
	}
	resourceID, err := uuid.FromString(id)
	if err != nil {
		return models.SCIMTarget{}, errSCIMNotFound()
	}
	target := models.SCIMTarget{ProviderID: providerID, ID: resourceID}
	if version == "" {
		return target, nil
	}
	micros, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(version, `W/"`), `"`), 10, 64)
	if err != nil {
		return models.SCIMTarget{}, errSCIMStale()
	}
	updatedAt := time.UnixMicro(micros)
	target.UpdatedAt = &updatedAt
	return target, nil
}

func scimProviderID(ctx context.Context) (uuid.UUID, error) {
	token := scimTokenKey.Value(ctx)
	if token == nil || token.SSOProviderID == uuid.Nil {
		return uuid.Nil, errors.New("scim: request has no SSO provider")
	}
	return token.SSOProviderID, nil
}

func scimProviderType(providerID uuid.UUID) string {
	return "sso:" + providerID.String()
}

func scimRequest(ctx context.Context) (*http.Request, error) {
	r := scimRequestKey.Value(ctx)
	if r == nil {
		return nil, apierrors.NewInternalServerError("SCIM request missing from context")
	}
	return r.WithContext(ctx), nil
}

func scimVersion(updatedAt time.Time) string {
	return `W/"` + strconv.FormatInt(updatedAt.UnixMicro(), 10) + `"`
}

func scimActor(r *http.Request) *models.User {
	prefix := ""
	if token := scimTokenKey.Value(r.Context()); token != nil {
		prefix = token.Prefix
	}
	return &models.User{Email: storage.NullString("scim:" + prefix)}
}

type scimSQLFilter struct {
	schemas core.Schemas
	name    string
}

func (f scimSQLFilter) Compare(attribute *protocol.Attribute, op filter.Operator, value any) (models.SCIMFilter, error) {
	column := attribute.Parent == nil && attribute.Path.SubAttribute == ""
	switch {
	case op != filter.OpEquals || value == nil:
		return f.unsupported()
	case column && attribute.Definition.Name == f.name:
		return models.SCIMFilter{Attribute: models.SCIMAttributeName, Value: value}, nil
	case column && attribute.Definition.Name == "externalId":
		return models.SCIMFilter{Attribute: models.SCIMAttributeExternalID, Value: value}, nil
	case column && attribute.Definition.Name == "active":
		return models.SCIMFilter{Attribute: models.SCIMAttributeActive, Value: value}, nil
	}
	return f.match(attribute, value)
}

func (f scimSQLFilter) Present(*protocol.Attribute) (models.SCIMFilter, error) {
	return f.unsupported()
}

func (f scimSQLFilter) And(left, right models.SCIMFilter) (models.SCIMFilter, error) {
	return models.SCIMFilter{And: append(scimTerms(left, left.And), scimTerms(right, right.And)...)}, nil
}

func (f scimSQLFilter) Or(left, right models.SCIMFilter) (models.SCIMFilter, error) {
	return models.SCIMFilter{Or: append(scimTerms(left, left.Or), scimTerms(right, right.Or)...)}, nil
}

func (f scimSQLFilter) Not(models.SCIMFilter) (models.SCIMFilter, error) {
	return f.unsupported()
}

func (f scimSQLFilter) ValuePath(attribute *protocol.Attribute, valueFilter func() (models.SCIMFilter, error)) (models.SCIMFilter, error) {
	parent := attribute.Definition
	if slices.Contains(scimUnstored, parent.Name) {
		return f.unsupported()
	}
	inner, err := valueFilter()
	if err != nil {
		return inner, err
	}
	terms := scimTerms(inner, inner.Or)
	for i, term := range terms {
		element := map[string]any{}
		if !scimMerge(element, term) {
			return f.unsupported()
		}
		terms[i] = models.SCIMFilter{Match: f.wrap(attribute.Path, parent, element)}
	}
	if len(terms) == 1 {
		return terms[0], nil
	}
	return models.SCIMFilter{Or: terms}, nil
}

func (f scimSQLFilter) match(attribute *protocol.Attribute, value any) (models.SCIMFilter, error) {
	definition, path := attribute.Definition, attribute.Path
	if definition.CaseExact || definition.Type == core.TypeBinary || definition.Type == core.TypeDateTime {
		return f.unsupported()
	}
	term := map[string]any{definition.Name: value}
	if attribute.Parent != nil {
		return models.SCIMFilter{Match: term}, nil
	}
	parent, _ := f.schemas.Resolve(core.SchemaURI(path.URI), path.Name, "")
	if parent == nil || slices.Contains(scimUnstored, parent.Name) {
		return f.unsupported()
	}
	if parent != definition {
		return models.SCIMFilter{Match: f.wrap(path, parent, term)}, nil
	}
	return models.SCIMFilter{Match: f.extension(path, term)}, nil
}

func (f scimSQLFilter) wrap(path filter.AttrPath, parent *core.Attribute, term map[string]any) map[string]any {
	var nested any = term
	if parent.MultiValued {
		nested = []any{term}
	}
	return f.extension(path, map[string]any{parent.Name: nested})
}

func (f scimSQLFilter) extension(path filter.AttrPath, term map[string]any) map[string]any {
	schema := f.schemas.Lookup(core.SchemaURI(path.URI))
	if !f.schemas.IsExtension(schema) {
		return term
	}
	return map[string]any{string(schema.ID): term}
}

func (f scimSQLFilter) unsupported() (models.SCIMFilter, error) {
	return models.SCIMFilter{}, scimerrors.ErrInvalidFilter(`only "eq" filters joined by "and" or "or" are supported`)
}

func scimTerms(filter models.SCIMFilter, terms []models.SCIMFilter) []models.SCIMFilter {
	if len(terms) > 0 {
		return terms
	}
	return []models.SCIMFilter{filter}
}

func scimMerge(element map[string]any, term models.SCIMFilter) bool {
	if term.Match == nil {
		return len(term.And) > 0 && !slices.ContainsFunc(term.And, func(t models.SCIMFilter) bool { return !scimMerge(element, t) })
	}
	for key, value := range term.Match {
		if existing, ok := element[key]; ok && existing != value {
			return false
		}
		element[key] = value
	}
	return true
}

type scimGroupRepository struct {
	db     *storage.Connection
	config *conf.GlobalConfiguration
}

type scimGroupSnapshot struct {
	version string
	members []uuid.UUID
}

func (s *scimGroupRepository) List(ctx context.Context, query *protocol.SearchRequest) ([]*core.Group, int, error) {
	providerID, err := scimProviderID(ctx)
	if err != nil {
		return nil, 0, err
	}
	search, err := scimSearch(query, scimGroupSchemas, "displayName")
	if err != nil {
		return nil, 0, err
	}
	db := s.db.WithContext(ctx)
	rows, total, err := models.FindSCIMGroups(db, providerID, search)
	if err != nil {
		return nil, 0, err
	}
	members, err := s.members(db, providerID, rows, protocol.ProjectionFrom(ctx))
	if err != nil {
		return nil, 0, err
	}
	groups := make([]*core.Group, 0, len(rows))
	for _, row := range rows {
		group, err := s.compose(row, members[row.ID])
		if err != nil {
			return nil, 0, err
		}
		groups = append(groups, group)
	}
	return groups, total, nil
}

func (s *scimGroupRepository) Read(ctx context.Context, id string) (*core.Group, error) {
	target, err := scimTarget(ctx, id, "")
	if err != nil {
		return nil, err
	}
	db := s.db.WithContext(ctx)
	row, err := models.FindSCIMGroup(db, target.ProviderID, target.ID)
	if err != nil {
		return nil, scimError(err)
	}
	projection := protocol.ProjectionFrom(ctx)
	members, err := s.members(db, target.ProviderID, []models.SCIMGroup{*row}, projection)
	if err != nil {
		return nil, err
	}
	group, err := s.compose(*row, members[row.ID])
	if err != nil {
		return nil, err
	}
	if snapshot := scimGroupSnapshotKey.Value(ctx); snapshot != nil && projection.Returns("members") {
		snapshot.members, snapshot.version = members[row.ID], group.Meta.Version
	}
	return group, nil
}

func (s *scimGroupRepository) Create(ctx context.Context, group *core.Group) (*core.Group, error) {
	providerID, err := scimProviderID(ctx)
	if err != nil {
		return nil, err
	}
	return s.save(ctx, group, func(tx *storage.Connection, resource []byte) (*models.SCIMGroup, models.AuditAction, error) {
		row, err := models.CreateSCIMGroup(tx, providerID, resource)
		return row, models.SCIMGroupCreatedAction, err
	})
}

func (s *scimGroupRepository) Update(ctx context.Context, group *core.Group) (*core.Group, error) {
	target, err := scimTarget(ctx, group.ID, group.Meta.Version)
	if err != nil {
		return nil, err
	}
	merge := s.mergeable(ctx, group.Meta.Version)
	return s.save(ctx, group, func(tx *storage.Connection, resource []byte) (*models.SCIMGroup, models.AuditAction, error) {
		if merge {
			if row, err := models.LockUnchangedSCIMGroup(tx, target.ProviderID, target.ID, resource); err != nil || row != nil {
				return row, "", err
			}
		}
		row, changed, err := models.ReplaceSCIMGroupIfChanged(tx, target, resource)
		if err != nil || !changed {
			return row, "", err
		}
		return row, models.SCIMGroupUpdatedAction, nil
	})
}

func (s *scimGroupRepository) Delete(ctx context.Context, group *core.Group) error {
	target, err := scimTarget(ctx, group.ID, group.Meta.Version)
	if err != nil {
		return err
	}
	r, err := scimRequest(ctx)
	if err != nil {
		return err
	}
	return scimError(s.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		row, err := models.DeleteSCIMGroup(tx, target)
		if err != nil {
			return err
		}
		var resource struct {
			DisplayName string `json:"displayName"`
		}
		if err := json.Unmarshal(row.Resource, &resource); err != nil {
			return err
		}
		return auditSCIM(s.config, tx, r, scimGroupEvent(r, models.SCIMGroupDeletedAction, row, resource.DisplayName))
	}))
}

func (s *scimGroupRepository) save(ctx context.Context, group *core.Group, write func(*storage.Connection, []byte) (*models.SCIMGroup, models.AuditAction, error)) (*core.Group, error) {
	members := make([]uuid.UUID, 0, len(group.Members))
	for _, member := range group.Members {
		id, err := uuid.FromString(member.Value)
		if err != nil {
			return nil, errSCIMMemberNotFound()
		}
		members = append(members, id)
	}
	resource, err := scimEncode(&core.Group{Base: group.Base, DisplayName: group.DisplayName})
	if err != nil {
		return nil, err
	}
	r, err := scimRequest(ctx)
	if err != nil {
		return nil, err
	}
	version := group.Meta.Version
	snapshot := scimGroupSnapshotKey.Value(ctx)
	tracked := snapshot != nil && version != "" && snapshot.version == version
	var row *models.SCIMGroup
	var change models.SCIMGroupMemberChange
	err = s.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		var action models.AuditAction
		var terr error
		if row, action, terr = write(tx, resource); terr != nil {
			return terr
		}
		if tracked {
			row, change, terr = models.ReplaceSCIMGroupMembersFrom(tx, row, snapshot.members, members)
		} else {
			row, change, terr = models.ReplaceSCIMGroupMembers(tx, row, members)
		}
		if terr != nil {
			return terr
		}
		if action == "" && change.Changed() {
			action = models.SCIMGroupUpdatedAction
		}
		if action == "" {
			return nil
		}
		return auditSCIM(s.config, tx, r, scimGroupEvent(r, action, row, group.DisplayName))
	})
	if err != nil {
		return nil, scimError(err)
	}
	return s.compose(*row, change.Members)
}

func (s *scimGroupRepository) mergeable(ctx context.Context, version string) bool {
	r := scimRequestKey.Value(ctx)
	snapshot := scimGroupSnapshotKey.Value(ctx)
	blindPatch := r != nil && r.Method == http.MethodPatch && (r.Header.Get("If-Match") == "" || r.Header.Get("If-Match") == "*")
	sameVersion := snapshot != nil && version != "" && snapshot.version == version
	return blindPatch && sameVersion
}

func (s *scimGroupRepository) members(tx *storage.Connection, providerID uuid.UUID, rows []models.SCIMGroup, projection protocol.Projection) (map[uuid.UUID][]uuid.UUID, error) {
	members := map[uuid.UUID][]uuid.UUID{}
	if !projection.Returns("members") {
		return members, nil
	}
	ids := make([]uuid.UUID, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	memberships, err := models.FindSCIMMembershipsByGroup(tx, providerID, ids)
	if err != nil {
		return nil, err
	}
	for _, m := range memberships {
		members[m.GroupID] = append(members[m.GroupID], m.SCIMUserID)
	}
	return members, nil
}

func (s *scimGroupRepository) compose(row models.SCIMGroup, scimUserIDs []uuid.UUID) (*core.Group, error) {
	base := scimBaseURL(s.config)
	group := &core.Group{}
	if err := json.Unmarshal(row.Resource, group); err != nil {
		return nil, err
	}
	group.ID = row.ID.String()
	group.Meta = core.Meta{
		ResourceType: scimResourceTypeGroup,
		Created:      row.CreatedAt.UTC(),
		LastModified: row.UpdatedAt.UTC(),
		Location:     base + "/Groups/" + group.ID,
		Version:      scimVersion(row.UpdatedAt),
	}
	group.Schemas = []core.SchemaURI{core.SchemaGroup}
	group.Members = make([]core.Member, len(scimUserIDs))
	for i, scimUserID := range scimUserIDs {
		id := scimUserID.String()
		group.Members[i] = core.Member{Value: id, Ref: base + "/Users/" + id, Type: scimResourceTypeUser}
	}
	return group, nil
}

func scimGroupEvent(r *http.Request, action models.AuditAction, row *models.SCIMGroup, displayName string) scimAuditEvent {
	traits := map[string]any{"scim_group_id": row.ID, "display_name": displayName}
	return scimAuditEvent{actor: scimActor(r), action: action, providerID: row.SSOProviderID, traits: traits}
}

type scimUserRepository struct {
	db     *storage.Connection
	config *conf.GlobalConfiguration
	events scimUserEvents
}

func (s *scimUserRepository) List(ctx context.Context, query *protocol.SearchRequest) ([]*core.User, int, error) {
	providerID, err := scimProviderID(ctx)
	if err != nil {
		return nil, 0, err
	}
	search, err := scimSearch(query, scimUserSchemas, "userName")
	if err != nil {
		return nil, 0, err
	}
	db := s.db.WithContext(ctx)
	rows, total, err := models.FindSCIMUsers(db, providerID, search)
	if err != nil {
		return nil, 0, err
	}
	users, err := s.render(db, providerID, rows, protocol.ProjectionFrom(ctx))
	if err != nil {
		return nil, 0, err
	}
	return users, total, nil
}

func (s *scimUserRepository) Read(ctx context.Context, id string) (*core.User, error) {
	target, err := scimTarget(ctx, id, "")
	if err != nil {
		return nil, err
	}
	db := s.db.WithContext(ctx)
	row, err := models.FindSCIMUser(db, target.ProviderID, target.ID)
	if err != nil {
		return nil, scimError(err)
	}
	users, err := s.render(db, target.ProviderID, []models.SCIMUser{*row}, protocol.ProjectionFrom(ctx))
	if err != nil {
		return nil, err
	}
	return users[0], nil
}

func (s *scimUserRepository) Create(ctx context.Context, user *core.User) (*core.User, error) {
	providerID, err := scimProviderID(ctx)
	if err != nil {
		return nil, err
	}
	resource, err := scimUserResource(user)
	if err != nil {
		return nil, err
	}
	r, err := scimRequest(ctx)
	if err != nil {
		return nil, err
	}
	db := s.db.WithContext(ctx)
	if err := s.beforeProvision(r, db, providerID, user); err != nil {
		return nil, err
	}
	return s.save(db, r, providerID, func(tx *storage.Connection) (*models.SCIMUser, *models.User, models.AuditAction, error) {
		row, err := models.CreateSCIMUser(tx, providerID, resource)
		if err != nil {
			return nil, nil, "", err
		}
		created, err := s.events.UserProvisioned(tx, row, user)
		return row, created, models.SCIMUserCreatedAction, err
	})
}

func (s *scimUserRepository) Update(ctx context.Context, user *core.User) (*core.User, error) {
	target, err := scimTarget(ctx, user.ID, user.Meta.Version)
	if err != nil {
		return nil, err
	}
	resource, err := scimUserResource(user)
	if err != nil {
		return nil, err
	}
	r, err := scimRequest(ctx)
	if err != nil {
		return nil, err
	}
	db := s.db.WithContext(ctx)
	existing, err := models.FindSCIMUser(db, target.ProviderID, target.ID)
	if err != nil {
		return nil, scimError(err)
	}
	linked, err := models.FindSCIMLinkedUser(db, existing)
	if err != nil {
		return nil, scimError(err)
	}
	if linked == nil {
		if err := s.beforeProvision(r, db, target.ProviderID, user); err != nil {
			return nil, err
		}
	}
	return s.save(db, r, target.ProviderID, func(tx *storage.Connection) (*models.SCIMUser, *models.User, models.AuditAction, error) {
		if linked == nil {
			row, err := models.ReplaceSCIMUser(tx, target, resource)
			if err != nil {
				return nil, nil, "", err
			}
			created, err := s.events.UserProvisioned(tx, row, user)
			return row, created, models.SCIMUserUpdatedAction, err
		}
		row, changed, err := models.ReplaceSCIMUserIfChanged(tx, target, resource)
		if err != nil || !changed {
			return row, nil, "", err
		}
		return row, nil, models.SCIMUserUpdatedAction, s.events.UserUpdated(tx, r, scimUserUpdate{old: existing, row: row, user: user})
	})
}

func (s *scimUserRepository) Delete(ctx context.Context, user *core.User) error {
	target, err := scimTarget(ctx, user.ID, user.Meta.Version)
	if err != nil {
		return err
	}
	r, err := scimRequest(ctx)
	if err != nil {
		return err
	}
	return scimError(s.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		row, err := models.DeleteSCIMUser(tx, target)
		if err != nil {
			return err
		}
		if err := s.events.UserDeleted(tx, row); err != nil {
			return err
		}
		if err := models.RemoveSCIMUserFromGroups(tx, row.ID); err != nil {
			return err
		}
		event, err := scimUserEvent(tx, r, models.SCIMUserDeletedAction, row)
		if err != nil {
			return err
		}
		return auditSCIM(s.config, tx, r, event)
	}))
}

func (s *scimUserRepository) save(db *storage.Connection, r *http.Request, providerID uuid.UUID, write func(*storage.Connection) (*models.SCIMUser, *models.User, models.AuditAction, error)) (*core.User, error) {
	var saved *core.User
	var created *models.User
	err := db.Transaction(func(tx *storage.Connection) error {
		row, user, action, terr := write(tx)
		if terr != nil {
			return terr
		}
		created = user
		if action != "" {
			event, terr := scimUserEvent(tx, r, action, row)
			if terr != nil {
				return terr
			}
			if terr = auditSCIM(s.config, tx, r, event); terr != nil {
				return terr
			}
		}
		users, terr := s.render(tx, providerID, []models.SCIMUser{*row}, protocol.Projection{})
		if terr != nil {
			return terr
		}
		saved = users[0]
		return nil
	})
	if err != nil {
		return nil, scimError(err)
	}
	s.events.AfterUserProvisioned(r, db, created)
	return saved, nil
}

func (s *scimUserRepository) render(tx *storage.Connection, providerID uuid.UUID, rows []models.SCIMUser, projection protocol.Projection) ([]*core.User, error) {
	base := scimBaseURL(s.config)
	groups := map[uuid.UUID][]core.GroupMembership{}
	if projection.Returns("groups") {
		ids := make([]uuid.UUID, len(rows))
		for i, row := range rows {
			ids[i] = row.ID
		}
		memberships, err := models.FindSCIMMembershipsByUser(tx, providerID, ids)
		if err != nil {
			return nil, err
		}
		for _, m := range memberships {
			id := m.GroupID.String()
			groups[m.SCIMUserID] = append(groups[m.SCIMUserID], core.GroupMembership{
				Value:   id,
				Ref:     base + "/Groups/" + id,
				Display: m.Display,
				Type:    "direct",
			})
		}
	}
	users := make([]*core.User, 0, len(rows))
	for _, row := range rows {
		user := &core.User{}
		if err := json.Unmarshal(row.Resource, user); err != nil {
			return nil, err
		}
		user.ID = row.ID.String()
		user.Meta = core.Meta{
			ResourceType: scimResourceTypeUser,
			Created:      row.CreatedAt.UTC(),
			LastModified: row.UpdatedAt.UTC(),
			Location:     base + "/Users/" + user.ID,
			Version:      scimVersion(row.UpdatedAt),
		}
		active := row.Active()
		user.Active = &active
		user.Schemas = []core.SchemaURI{core.SchemaUser}
		if user.EnterpriseUser != nil {
			user.Schemas = append(user.Schemas, core.SchemaEnterpriseUser)
		}
		user.Groups = groups[row.ID]
		users = append(users, user)
	}
	return users, nil
}

func (s *scimUserRepository) beforeProvision(r *http.Request, db *storage.Connection, providerID uuid.UUID, user *core.User) error {
	if scimUserEmail(user) == "" {
		return scimerrors.ErrInvalidValue(`"emails" or an email address "userName" is required`)
	}
	return s.events.BeforeUserProvisioned(r, db, providerID, user)
}

func scimUserResource(user *core.User) ([]byte, error) {
	resource, err := scimEncode(user)
	if err != nil {
		return nil, err
	}
	if email := scimPrimaryEmail(user.Emails); email != "" && !isEmailAddress(email) {
		return nil, scimerrors.ErrInvalidValue(`"emails" value must be an email address`)
	}
	return resource, nil
}

func scimUserEmail(user *core.User) string {
	if email := scimPrimaryEmail(user.Emails); email != "" {
		return email
	}
	if isEmailAddress(user.UserName) {
		return user.UserName
	}
	return ""
}

func isEmailAddress(value string) bool {
	return len(value) <= 255 && checkmail.ValidateFormat(value) == nil
}

func scimPrimaryEmail(emails []core.Email) string {
	for _, email := range emails {
		if email.Primary != nil && *email.Primary {
			return email.Value
		}
	}
	if len(emails) > 0 {
		return emails[0].Value
	}
	return ""
}

func scimIdentityData(user *core.User) map[string]any {
	return map[string]any{
		scimClaimSub:           user.UserName,
		scimClaimEmail:         scimUserEmail(user),
		scimClaimEmailVerified: true,
	}
}

func scimUserEvent(tx *storage.Connection, r *http.Request, action models.AuditAction, row *models.SCIMUser) (scimAuditEvent, error) {
	linked, err := models.FindSCIMLinkedUser(tx, row)
	if err != nil {
		return scimAuditEvent{}, err
	}
	var userID *uuid.UUID
	if linked != nil {
		userID = &linked.ID
	}
	return scimAuditEvent{actor: scimActor(r), action: action, providerID: row.SSOProviderID, traits: scimUserTraits(row, userID)}, nil
}

func scimUserTraits(row *models.SCIMUser, userID *uuid.UUID) map[string]any {
	traits := map[string]any{
		"scim_user_id": row.ID,
		"user_name":    row.UserName(),
		"active":       row.Active(),
	}
	if userID != nil {
		traits["user_id"] = *userID
	}
	return traits
}

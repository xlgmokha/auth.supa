package scim

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
	BasePath          = "/scim/v2"
	resourceTypeUser  = "User"
	resourceTypeGroup = "Group"

	ClaimSub           = "sub"
	ClaimEmail         = "email"
	claimEmailVerified = "email_verified"
)

var (
	RequestKey       = ctxkey.New[*http.Request]("scim_request")
	tokenKey         = ctxkey.New[*models.SCIMToken]("scim_token")
	groupSnapshotKey = ctxkey.New[*groupSnapshot]("scim_group_snapshot")

	userSchemas = core.Schemas{
		core.NewSchema(core.SchemaUser).With(core.UserAttributes()...),
		core.NewSchema(core.SchemaEnterpriseUser).With(core.EnterpriseUserAttributes()...),
	}
	groupSchemas = core.Schemas{core.NewSchema(core.SchemaGroup).With(core.GroupAttributes()...)}

	unstored = strings.Fields("id meta password groups members")

	commonSortKeys = map[string]models.SCIMSortKey{
		"id":                models.SCIMSortByID,
		"meta.created":      models.SCIMSortByCreatedAt,
		"meta.lastmodified": models.SCIMSortByUpdatedAt,
	}
)

type auditEvent struct {
	Actor      *models.User
	Action     models.AuditAction
	ProviderID uuid.UUID
	Traits     map[string]any
}

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

func NewUserRepository(db *storage.Connection, config *conf.GlobalConfiguration, events UserEvents) *UserRepository {
	return &UserRepository{db: db, config: config, events: events}
}

func audit(config *conf.GlobalConfiguration, tx *storage.Connection, r *http.Request, event auditEvent) error {
	event.Traits["sso_provider_id"] = event.ProviderID
	event.Traits["outcome"] = "success"
	return models.NewAuditLogEntry(config.AuditLog, r, tx, event.Actor, event.Action, utilities.GetIPAddress(r), event.Traits)
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

func actorFrom(r *http.Request) *models.User {
	prefix := ""
	if token := tokenKey.Value(r.Context()); token != nil {
		prefix = token.Prefix
	}
	return &models.User{Email: storage.NullString("scim:" + prefix)}
}

type sqlFilter struct {
	schemas core.Schemas
	name    string
}

func (f sqlFilter) Compare(attribute *protocol.Attribute, op filter.Operator, value any) (models.SCIMFilter, error) {
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

func (f sqlFilter) Present(*protocol.Attribute) (models.SCIMFilter, error) {
	return f.unsupported()
}

func (f sqlFilter) And(left, right models.SCIMFilter) (models.SCIMFilter, error) {
	return models.SCIMFilter{And: append(termsOf(left, left.And), termsOf(right, right.And)...)}, nil
}

func (f sqlFilter) Or(left, right models.SCIMFilter) (models.SCIMFilter, error) {
	return models.SCIMFilter{Or: append(termsOf(left, left.Or), termsOf(right, right.Or)...)}, nil
}

func (f sqlFilter) Not(models.SCIMFilter) (models.SCIMFilter, error) {
	return f.unsupported()
}

func (f sqlFilter) ValuePath(attribute *protocol.Attribute, valueFilter func() (models.SCIMFilter, error)) (models.SCIMFilter, error) {
	parent := attribute.Definition
	if slices.Contains(unstored, parent.Name) {
		return f.unsupported()
	}
	inner, err := valueFilter()
	if err != nil {
		return inner, err
	}
	terms := termsOf(inner, inner.Or)
	for i, term := range terms {
		element := map[string]any{}
		if !mergeTerm(element, term) {
			return f.unsupported()
		}
		terms[i] = models.SCIMFilter{Match: f.wrap(attribute.Path, parent, element)}
	}
	if len(terms) == 1 {
		return terms[0], nil
	}
	return models.SCIMFilter{Or: terms}, nil
}

func (f sqlFilter) match(attribute *protocol.Attribute, value any) (models.SCIMFilter, error) {
	definition, path := attribute.Definition, attribute.Path
	if definition.CaseExact || definition.Type == core.TypeBinary || definition.Type == core.TypeDateTime {
		return f.unsupported()
	}
	term := map[string]any{definition.Name: value}
	if attribute.Parent != nil {
		return models.SCIMFilter{Match: term}, nil
	}
	parent, _ := f.schemas.Resolve(core.SchemaURI(path.URI), path.Name, "")
	if parent == nil || slices.Contains(unstored, parent.Name) {
		return f.unsupported()
	}
	if parent != definition {
		return models.SCIMFilter{Match: f.wrap(path, parent, term)}, nil
	}
	return models.SCIMFilter{Match: f.extension(path, term)}, nil
}

func (f sqlFilter) wrap(path filter.AttrPath, parent *core.Attribute, term map[string]any) map[string]any {
	var nested any = term
	if parent.MultiValued {
		nested = []any{term}
	}
	return f.extension(path, map[string]any{parent.Name: nested})
}

func (f sqlFilter) extension(path filter.AttrPath, term map[string]any) map[string]any {
	schema := f.schemas.Lookup(core.SchemaURI(path.URI))
	if !f.schemas.IsExtension(schema) {
		return term
	}
	return map[string]any{string(schema.ID): term}
}

func (f sqlFilter) unsupported() (models.SCIMFilter, error) {
	return models.SCIMFilter{}, scimerrors.ErrInvalidFilter(`only "eq" filters joined by "and" or "or" are supported`)
}

func termsOf(filter models.SCIMFilter, terms []models.SCIMFilter) []models.SCIMFilter {
	if len(terms) > 0 {
		return terms
	}
	return []models.SCIMFilter{filter}
}

func mergeTerm(element map[string]any, term models.SCIMFilter) bool {
	if term.Match == nil {
		return len(term.And) > 0 && !slices.ContainsFunc(term.And, func(t models.SCIMFilter) bool { return !mergeTerm(element, t) })
	}
	for key, value := range term.Match {
		if existing, ok := element[key]; ok && existing != value {
			return false
		}
		element[key] = value
	}
	return true
}

type groupRepository struct {
	db     *storage.Connection
	config *conf.GlobalConfiguration
}

type groupSnapshot struct {
	version string
	members []uuid.UUID
}

func (s *groupRepository) List(ctx context.Context, query *protocol.SearchRequest) ([]*core.Group, int, error) {
	providerID, err := ProviderID(ctx)
	if err != nil {
		return nil, 0, err
	}
	search, err := toQuery(query, groupSchemas, "displayName")
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

func (s *groupRepository) Read(ctx context.Context, id string) (*core.Group, error) {
	target, err := parseTarget(ctx, id, "")
	if err != nil {
		return nil, err
	}
	db := s.db.WithContext(ctx)
	row, err := models.FindSCIMGroup(db, target.ProviderID, target.ID)
	if err != nil {
		return nil, Error(err)
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
	if snapshot := groupSnapshotKey.Value(ctx); snapshot != nil && projection.Returns("members") {
		snapshot.members, snapshot.version = make([]uuid.UUID, len(members[row.ID])), group.Meta.Version
		for i, member := range members[row.ID] {
			snapshot.members[i] = member.SCIMUserID
		}
	}
	return group, nil
}

func (s *groupRepository) Create(ctx context.Context, group *core.Group) (*core.Group, error) {
	providerID, err := ProviderID(ctx)
	if err != nil {
		return nil, err
	}
	return s.save(ctx, group, func(tx *storage.Connection, resource []byte) (*models.SCIMGroup, models.AuditAction, error) {
		row, err := models.CreateSCIMGroup(tx, providerID, resource)
		return row, models.SCIMGroupCreatedAction, err
	})
}

func (s *groupRepository) Update(ctx context.Context, group *core.Group) (*core.Group, error) {
	target, err := parseTarget(ctx, group.ID, group.Meta.Version)
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

func (s *groupRepository) Delete(ctx context.Context, group *core.Group) error {
	target, err := parseTarget(ctx, group.ID, group.Meta.Version)
	if err != nil {
		return err
	}
	r, err := requestFrom(ctx)
	if err != nil {
		return err
	}
	return Error(s.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
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
		if err := models.RemoveSCIMMemberFromGroups(tx, row.ID); err != nil {
			return err
		}
		return audit(s.config, tx, r, groupEvent(r, models.SCIMGroupDeletedAction, row, resource.DisplayName))
	}))
}

func (s *groupRepository) save(ctx context.Context, group *core.Group, write func(*storage.Connection, []byte) (*models.SCIMGroup, models.AuditAction, error)) (*core.Group, error) {
	members := make([]uuid.UUID, 0, len(group.Members))
	for _, member := range group.Members {
		id, err := uuid.FromString(member.Value)
		if err != nil {
			return nil, errMemberNotFound()
		}
		members = append(members, id)
	}
	resource, err := encode(&core.Group{Base: group.Base, DisplayName: group.DisplayName})
	if err != nil {
		return nil, err
	}
	r, err := requestFrom(ctx)
	if err != nil {
		return nil, err
	}
	version := group.Meta.Version
	snapshot := groupSnapshotKey.Value(ctx)
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
		return audit(s.config, tx, r, groupEvent(r, action, row, group.DisplayName))
	})
	if err != nil {
		return nil, Error(err)
	}
	stored, err := row.Members()
	if err != nil {
		return nil, err
	}
	return s.compose(*row, stored)
}

func (s *groupRepository) mergeable(ctx context.Context, version string) bool {
	r := RequestKey.Value(ctx)
	snapshot := groupSnapshotKey.Value(ctx)
	blindPatch := r != nil && r.Method == http.MethodPatch && (r.Header.Get("If-Match") == "" || r.Header.Get("If-Match") == "*")
	sameVersion := snapshot != nil && version != "" && snapshot.version == version
	return blindPatch && sameVersion
}

func (s *groupRepository) members(tx *storage.Connection, providerID uuid.UUID, rows []models.SCIMGroup, projection protocol.Projection) (map[uuid.UUID][]models.SCIMGroupMembership, error) {
	members := map[uuid.UUID][]models.SCIMGroupMembership{}
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
		members[m.GroupID] = append(members[m.GroupID], m)
	}
	return members, nil
}

func (s *groupRepository) compose(row models.SCIMGroup, members []models.SCIMGroupMembership) (*core.Group, error) {
	base := BaseURL(s.config)
	group := &core.Group{}
	if err := json.Unmarshal(row.Resource, group); err != nil {
		return nil, err
	}
	group.ID = row.ID.String()
	group.Meta = core.Meta{
		ResourceType: resourceTypeGroup,
		Created:      row.CreatedAt.UTC(),
		LastModified: row.UpdatedAt.UTC(),
		Location:     base + "/Groups/" + group.ID,
		Version:      versionOf(row.UpdatedAt),
	}
	group.Schemas = []core.SchemaURI{core.SchemaGroup}
	group.Members = make([]core.Member, len(members))
	for i, member := range members {
		id := member.SCIMUserID.String()
		group.Members[i] = core.Member{Value: id, Ref: base + "/" + member.Type + "s/" + id, Type: core.ResourceTypeName(member.Type)}
	}
	return group, nil
}

func groupEvent(r *http.Request, action models.AuditAction, row *models.SCIMGroup, displayName string) auditEvent {
	traits := map[string]any{"scim_group_id": row.ID, "display_name": displayName}
	return auditEvent{Actor: actorFrom(r), Action: action, ProviderID: row.SSOProviderID, Traits: traits}
}

type UserRepository struct {
	db     *storage.Connection
	config *conf.GlobalConfiguration
	events UserEvents
}

func (s *UserRepository) List(ctx context.Context, query *protocol.SearchRequest) ([]*core.User, int, error) {
	providerID, err := ProviderID(ctx)
	if err != nil {
		return nil, 0, err
	}
	search, err := toQuery(query, userSchemas, "userName")
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

func (s *UserRepository) Read(ctx context.Context, id string) (*core.User, error) {
	target, err := parseTarget(ctx, id, "")
	if err != nil {
		return nil, err
	}
	db := s.db.WithContext(ctx)
	row, err := models.FindSCIMUser(db, target.ProviderID, target.ID)
	if err != nil {
		return nil, Error(err)
	}
	users, err := s.render(db, target.ProviderID, []models.SCIMUser{*row}, protocol.ProjectionFrom(ctx))
	if err != nil {
		return nil, err
	}
	return users[0], nil
}

func (s *UserRepository) Create(ctx context.Context, user *core.User) (*core.User, error) {
	providerID, err := ProviderID(ctx)
	if err != nil {
		return nil, err
	}
	resource, err := encodeUser(user)
	if err != nil {
		return nil, err
	}
	r, err := requestFrom(ctx)
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
		created, err := s.events.UserProvisioned(tx, row, newProfile(user))
		return row, created, models.SCIMUserCreatedAction, err
	})
}

func (s *UserRepository) Update(ctx context.Context, user *core.User) (*core.User, error) {
	target, err := parseTarget(ctx, user.ID, user.Meta.Version)
	if err != nil {
		return nil, err
	}
	resource, err := encodeUser(user)
	if err != nil {
		return nil, err
	}
	r, err := requestFrom(ctx)
	if err != nil {
		return nil, err
	}
	db := s.db.WithContext(ctx)
	existing, err := models.FindSCIMUser(db, target.ProviderID, target.ID)
	if err != nil {
		return nil, Error(err)
	}
	linked, err := models.FindSCIMLinkedUser(db, existing)
	if err != nil {
		return nil, Error(err)
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
			created, err := s.events.UserProvisioned(tx, row, newProfile(user))
			return row, created, models.SCIMUserUpdatedAction, err
		}
		row, changed, err := models.ReplaceSCIMUserIfChanged(tx, target, resource)
		if err != nil || !changed {
			return row, nil, "", err
		}
		return row, nil, models.SCIMUserUpdatedAction, s.events.UserUpdated(tx, r, UserUpdate{Old: existing, Row: row, Profile: newProfile(user)})
	})
}

func (s *UserRepository) Delete(ctx context.Context, user *core.User) error {
	target, err := parseTarget(ctx, user.ID, user.Meta.Version)
	if err != nil {
		return err
	}
	r, err := requestFrom(ctx)
	if err != nil {
		return err
	}
	return Error(s.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		row, err := models.DeleteSCIMUser(tx, target)
		if err != nil {
			return err
		}
		if err := s.events.UserDeleted(tx, row); err != nil {
			return err
		}
		if err := models.RemoveSCIMMemberFromGroups(tx, row.ID); err != nil {
			return err
		}
		event, err := userEvent(tx, r, models.SCIMUserDeletedAction, row)
		if err != nil {
			return err
		}
		return audit(s.config, tx, r, event)
	}))
}

func (s *UserRepository) save(db *storage.Connection, r *http.Request, providerID uuid.UUID, write func(*storage.Connection) (*models.SCIMUser, *models.User, models.AuditAction, error)) (*core.User, error) {
	var saved *core.User
	var created *models.User
	err := db.Transaction(func(tx *storage.Connection) error {
		row, user, action, terr := write(tx)
		if terr != nil {
			return terr
		}
		created = user
		if action != "" {
			event, terr := userEvent(tx, r, action, row)
			if terr != nil {
				return terr
			}
			if terr = audit(s.config, tx, r, event); terr != nil {
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
		return nil, Error(err)
	}
	s.events.AfterUserProvisioned(r, db, created)
	return saved, nil
}

func (s *UserRepository) render(tx *storage.Connection, providerID uuid.UUID, rows []models.SCIMUser, projection protocol.Projection) ([]*core.User, error) {
	base := BaseURL(s.config)
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
				Type:    m.Type,
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
			ResourceType: resourceTypeUser,
			Created:      row.CreatedAt.UTC(),
			LastModified: row.UpdatedAt.UTC(),
			Location:     base + "/Users/" + user.ID,
			Version:      versionOf(row.UpdatedAt),
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

func (s *UserRepository) beforeProvision(r *http.Request, db *storage.Connection, providerID uuid.UUID, user *core.User) error {
	if userEmail(user) == "" {
		return scimerrors.ErrInvalidValue(`"emails" or an email address "userName" is required`)
	}
	return s.events.BeforeUserProvisioned(r, db, providerID, newProfile(user))
}

func encodeUser(user *core.User) ([]byte, error) {
	resource, err := encode(user)
	if err != nil {
		return nil, err
	}
	if email := primaryEmail(user.Emails); email != "" && !isEmailAddress(email) {
		return nil, scimerrors.ErrInvalidValue(`"emails" value must be an email address`)
	}
	return resource, nil
}

func userEmail(user *core.User) string {
	if email := primaryEmail(user.Emails); email != "" {
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

func primaryEmail(emails []core.Email) string {
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

func userEvent(tx *storage.Connection, r *http.Request, action models.AuditAction, row *models.SCIMUser) (auditEvent, error) {
	linked, err := models.FindSCIMLinkedUser(tx, row)
	if err != nil {
		return auditEvent{}, err
	}
	var userID *uuid.UUID
	if linked != nil {
		userID = &linked.ID
	}
	return auditEvent{Actor: actorFrom(r), Action: action, ProviderID: row.SSOProviderID, Traits: userTraits(row, userID)}, nil
}

func userTraits(row *models.SCIMUser, userID *uuid.UUID) map[string]any {
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

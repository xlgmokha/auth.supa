package scim

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/api/scim/query"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

var columns = map[string]string{
	"id":                "id",
	"meta.created":      "created_at",
	"meta.lastModified": "updated_at",
}

type repository[T core.Resource] struct {
	db           *storage.Connection
	resourceType string
	endpoint     string
	schemas      core.Schemas
}

func NewRepository[T core.Resource](db *storage.Connection, resourceType, endpoint string, schemas core.Schemas) server.Repository[T] {
	return &repository[T]{
		db:           db,
		resourceType: resourceType,
		endpoint:     endpoint,
		schemas:      schemas,
	}
}

func (r *repository[T]) List(ctx context.Context, query *protocol.SearchRequest) ([]T, int, error) {
	q, err := r.filter(ctx, query.Filter)
	if err != nil {
		return nil, 0, err
	}
	if query.Count == 0 {
		total, err := q.Count(&models.SCIMResource{})
		return []T{}, total, err
	}
	rows, err := r.page(q, query)
	if err != nil {
		return nil, 0, err
	}
	items, err := r.decodeAll(rows)
	if err != nil {
		return nil, 0, err
	}
	return items, q.Paginator.TotalEntriesSize, nil
}

func (r *repository[T]) Read(ctx context.Context, id string) (T, error) {
	var zero T
	key, err := uuid.FromString(id)
	if err != nil {
		return zero, notFound()
	}
	scope, err := r.scope(ctx)
	if err != nil {
		return zero, err
	}
	row, err := scope.Find(r.db.WithContext(ctx), key)
	if models.IsNotFoundError(err) {
		return zero, notFound()
	}
	if err != nil {
		return zero, err
	}
	return r.decode(row)
}

func (r *repository[T]) Create(ctx context.Context, item T) (T, error) {
	var zero T
	scope, err := r.scope(ctx)
	if err != nil {
		return zero, err
	}
	document, err := encode(item)
	if err != nil {
		return zero, err
	}
	row, err := scope.Create(r.db.WithContext(ctx), document)
	if err != nil {
		return zero, uniqueness(err)
	}
	return r.decode(row)
}

func (r *repository[T]) Update(ctx context.Context, item T) (T, error) {
	var zero T
	scope, err := r.scope(ctx)
	if err != nil {
		return zero, err
	}
	document, err := encode(item)
	if err != nil {
		return zero, err
	}
	common := item.Common()
	row, err := scope.Update(r.db.WithContext(ctx), uuid.FromStringOrNil(common.ID), document, versionTime(common.Meta.Version))
	if models.IsNotFoundError(err) {
		return zero, r.missing(ctx, common.ID)
	}
	if err != nil {
		return zero, uniqueness(err)
	}
	return r.decode(row)
}

func (r *repository[T]) Delete(ctx context.Context, item T) error {
	scope, err := r.scope(ctx)
	if err != nil {
		return err
	}
	common := item.Common()
	err = scope.Delete(r.db.WithContext(ctx), uuid.FromStringOrNil(common.ID), versionTime(common.Meta.Version))
	if models.IsNotFoundError(err) {
		return r.missing(ctx, common.ID)
	}
	return err
}

func (r *repository[T]) scope(ctx context.Context) (models.SCIMScope, error) {
	token := tokenKey.Value(ctx)
	if token == nil {
		return models.SCIMScope{}, scimerrors.ErrInternal("missing SCIM token")
	}
	return models.SCIMScope{ProviderID: token.SSOProviderID, ResourceType: r.resourceType}, nil
}

func (r *repository[T]) missing(ctx context.Context, id string) error {
	if _, err := r.Read(ctx, id); err != nil {
		return err
	}
	return scimerrors.ErrPreconditionFailed("resource has changed on the server")
}

func (r *repository[T]) order(query *protocol.SearchRequest) (string, []any, error) {
	if query.SortBy == "" {
		return "created_at, id", nil, nil
	}
	parent, attribute, err := query.SortAttribute(r.schemas)
	if err != nil {
		return "", nil, err
	}
	direction := " ASC"
	if query.Descending() {
		direction = " DESC"
	}
	keys := []string{parent.Name}
	if parent != attribute {
		keys = append(keys, attribute.Name)
	}
	if column, ok := columns[strings.Join(keys, ".")]; ok {
		return column + direction + ", id", nil, nil
	}
	if parent.MultiValued {
		keys = []string{parent.Name, "0", attribute.Name}
	}
	for _, extension := range r.schemas.Extensions() {
		if extension.Attributes.Lookup(parent.Name) == parent {
			keys = append([]string{string(extension.ID)}, keys...)
		}
	}
	return `lower(resource #>> ?::text[]) COLLATE "C"` + direction + ", id", []any{textArray(keys)}, nil
}

func (r *repository[T]) decodeAll(rows []models.SCIMResource) ([]T, error) {
	items := make([]T, 0, len(rows))
	for _, row := range rows {
		item, err := r.decode(&row)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

func (r *repository[T]) decode(row *models.SCIMResource) (T, error) {
	var item T
	if err := json.Unmarshal(row.Resource, &item); err != nil {
		return item, err
	}
	common := item.Common()
	common.ID = row.ID.String()
	common.Meta = core.Meta{
		ResourceType: core.ResourceTypeName(r.resourceType),
		Created:      row.CreatedAt.UTC(),
		LastModified: row.UpdatedAt.UTC(),
		Location:     r.endpoint + "/" + common.ID,
		Version:      version(row.UpdatedAt),
	}
	return item, nil
}

func (r *repository[T]) filter(ctx context.Context, expression string) (*pop.Query, error) {
	scope, err := r.scope(ctx)
	if err != nil {
		return nil, err
	}
	q := scope.Query(r.db.WithContext(ctx))
	if expression == "" {
		return q, nil
	}
	builder, err := protocol.Filter(r.schemas, expression, query.NewEvaluator(r.schemas))
	if err != nil {
		return nil, err
	}
	return builder.Build(q), nil
}

func (r *repository[T]) page(q *pop.Query, query *protocol.SearchRequest) ([]models.SCIMResource, error) {
	order, args, err := r.order(query)
	if err != nil {
		return nil, err
	}
	q.Paginator = &pop.Paginator{PerPage: query.Count, Offset: query.Offset()}
	rows := []models.SCIMResource{}
	return rows, q.Order(order, args...).All(&rows)
}

func encode(item core.Resource) (string, error) {
	raw, err := json.Marshal(item)
	if err != nil {
		return "", err
	}
	document := map[string]any{}
	if err := json.Unmarshal(raw, &document); err != nil {
		return "", err
	}
	for _, key := range []string{"id", "meta", "password"} {
		delete(document, key)
	}
	raw, err = json.Marshal(document)
	return string(raw), err
}

func uniqueness(err error) error {
	if unique, ok := errors.AsType[models.SCIMUniquenessError](err); ok {
		return scimerrors.ErrUniqueness(strconv.Quote(unique.Attribute) + " must be unique")
	}
	return err
}

func notFound() error {
	return scimerrors.ErrNotFound("Not found")
}

func version(t time.Time) string {
	return `W/"` + strconv.FormatInt(t.UnixMicro(), 10) + `"`
}

func versionTime(version string) *time.Time {
	micros, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(version, `W/"`), `"`), 10, 64)
	if err != nil {
		return nil
	}
	t := time.UnixMicro(micros).UTC()
	return &t
}

func textArray(keys []string) string {
	quoted := make([]string, len(keys))
	for i, key := range keys {
		quoted[i] = strconv.Quote(key)
	}
	return "{" + strings.Join(quoted, ",") + "}"
}

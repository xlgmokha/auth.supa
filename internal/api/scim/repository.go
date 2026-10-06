package scim

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgerrcode"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/storage"
)

var uniqueAttributes = map[string]string{
	"scim_resources_user_name_key":   "userName",
	"scim_resources_external_id_key": "externalId",
}

var columns = map[string]string{
	"id":                "id",
	"meta.created":      "created_at",
	"meta.lastModified": "updated_at",
}

type scimResource struct {
	ID            uuid.UUID       `db:"id"`
	SSOProviderID uuid.UUID       `db:"sso_provider_id"`
	ResourceType  string          `db:"resource_type"`
	Resource      json.RawMessage `db:"resource"`
	CreatedAt     time.Time       `db:"created_at"`
	UpdatedAt     time.Time       `db:"updated_at"`
	DeletedAt     *time.Time      `db:"deleted_at"`
}

func (scimResource) TableName() string {
	return "scim_resources"
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
	q, err := r.scope(ctx)
	if err != nil {
		return nil, 0, err
	}
	if query.Filter != "" {
		builder, err := protocol.Filter(r.schemas, query.Filter, newEvaluator(r.schemas))
		if err != nil {
			return nil, 0, err
		}
		q = q.Scope(builder.Scope)
	}
	if query.Count == 0 {
		total, err := q.Count(&scimResource{})
		return []T{}, total, err
	}
	order, args, err := r.order(query)
	if err != nil {
		return nil, 0, err
	}
	q.Paginator = &pop.Paginator{PerPage: query.Count, Offset: query.Offset()}
	rows := []scimResource{}
	if err := q.Order(order, args...).All(&rows); err != nil {
		return nil, 0, err
	}
	items := make([]T, 0, len(rows))
	for _, row := range rows {
		item, err := r.decode(&row)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	return items, q.Paginator.TotalEntriesSize, nil
}

func (r *repository[T]) Read(ctx context.Context, id string) (T, error) {
	var zero T
	key, err := uuid.FromString(id)
	if err != nil {
		return zero, notFound()
	}
	q, err := r.scope(ctx)
	if err != nil {
		return zero, err
	}
	row := &scimResource{}
	if err := q.Where("id = ?", key).First(row); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return zero, notFound()
		}
		return zero, err
	}
	return r.decode(row)
}

func (r *repository[T]) Create(ctx context.Context, item T) (T, error) {
	var zero T
	providerID, err := r.providerID(ctx)
	if err != nil {
		return zero, err
	}
	document, err := encode(item)
	if err != nil {
		return zero, err
	}
	row := &scimResource{}
	if err := r.db.WithContext(ctx).RawQuery(
		fmt.Sprintf("INSERT INTO %q (id, sso_provider_id, resource_type, resource) VALUES (?, ?, ?, ?::jsonb) RETURNING *", row.TableName()),
		uuid.Must(uuid.NewV4()), providerID, r.resourceType, document,
	).First(row); err != nil {
		return zero, uniqueness(err)
	}
	return r.decode(row)
}

func (r *repository[T]) Update(ctx context.Context, item T) (T, error) {
	var zero T
	providerID, err := r.providerID(ctx)
	if err != nil {
		return zero, err
	}
	document, err := encode(item)
	if err != nil {
		return zero, err
	}
	row := &scimResource{}
	common := item.Common()
	if err := r.db.WithContext(ctx).RawQuery(
		fmt.Sprintf("UPDATE %q SET resource = ?::jsonb, updated_at = now() WHERE id = ? AND sso_provider_id = ? AND resource_type = ? AND deleted_at IS NULL AND updated_at = COALESCE(?, updated_at) RETURNING *", row.TableName()),
		document, common.ID, providerID, r.resourceType, versionTime(common.Meta.Version),
	).First(row); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return zero, r.missing(ctx, common.ID)
		}
		return zero, uniqueness(err)
	}
	return r.decode(row)
}

func (r *repository[T]) Delete(ctx context.Context, item T) error {
	providerID, err := r.providerID(ctx)
	if err != nil {
		return err
	}
	common := item.Common()
	count, err := r.db.WithContext(ctx).RawQuery(
		fmt.Sprintf("UPDATE %q SET deleted_at = now() WHERE id = ? AND sso_provider_id = ? AND resource_type = ? AND deleted_at IS NULL AND updated_at = COALESCE(?, updated_at)", scimResource{}.TableName()),
		common.ID, providerID, r.resourceType, versionTime(common.Meta.Version),
	).ExecWithCount()
	if err != nil {
		return err
	}
	if count == 0 {
		return r.missing(ctx, common.ID)
	}
	return nil
}

func (r *repository[T]) providerID(ctx context.Context) (uuid.UUID, error) {
	token := tokenKey.Value(ctx)
	if token == nil {
		return uuid.Nil, scimerrors.ErrInternal("missing SCIM token")
	}
	return token.SSOProviderID, nil
}

func (r *repository[T]) scope(ctx context.Context) (*pop.Query, error) {
	providerID, err := r.providerID(ctx)
	if err != nil {
		return nil, err
	}
	return r.db.WithContext(ctx).Q().
		Where("sso_provider_id = ?", providerID).
		Where("resource_type = ?", r.resourceType).
		Where("deleted_at IS NULL"), nil
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

func (r *repository[T]) decode(row *scimResource) (T, error) {
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
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
		return scimerrors.ErrUniqueness(strconv.Quote(uniqueAttributes[pgErr.ConstraintName]) + " must be unique")
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

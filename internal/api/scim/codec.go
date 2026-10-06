package scim

import (
	"encoding/json"
	"maps"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func (r *repository[T]) decodeOne(tx *storage.Connection, scope models.SCIMScope, row *models.SCIMResource) (T, error) {
	items, err := r.decodeAll(tx, scope, []models.SCIMResource{*row}, nil)
	if err != nil {
		var zero T
		return zero, err
	}
	return items[0], nil
}

func (r *repository[T]) decodeAll(tx *storage.Connection, scope models.SCIMScope, rows []models.SCIMResource, excluded []string) ([]T, error) {
	ids := make([]uuid.UUID, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	elements := map[uuid.UUID]map[string]any{}
	for _, ref := range r.references {
		if ref.excluded(excluded) {
			continue
		}
		loaded, err := ref.load(tx, scope, ids, r.locations)
		if err != nil {
			return nil, err
		}
		for id, list := range loaded {
			if elements[id] == nil {
				elements[id] = map[string]any{}
			}
			elements[id][ref.name()] = list
		}
	}
	items := make([]T, 0, len(rows))
	for _, row := range rows {
		item, err := r.decode(&row, elements[row.ID])
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

func (r *repository[T]) decode(row *models.SCIMResource, attributes map[string]any) (T, error) {
	var item T
	raw := []byte(row.Resource)
	if len(attributes) > 0 {
		document := map[string]any{}
		if err := json.Unmarshal(raw, &document); err != nil {
			return item, err
		}
		maps.Copy(document, attributes)
		var err error
		if raw, err = json.Marshal(document); err != nil {
			return item, err
		}
	}
	if err := json.Unmarshal(raw, &item); err != nil {
		return item, err
	}
	common := item.Common()
	common.ID = row.ID.String()
	common.Meta = core.Meta{
		ResourceType: core.ResourceTypeName(r.resourceType),
		Created:      row.CreatedAt.UTC(),
		LastModified: row.UpdatedAt.UTC(),
		Location:     r.locations[r.resourceType] + "/" + common.ID,
		Version:      version(row.UpdatedAt),
	}
	return item, nil
}

func (r *repository[T]) encode(item T) (string, map[string][]uuid.UUID, error) {
	raw, err := json.Marshal(item)
	if err != nil {
		return "", nil, err
	}
	document := map[string]any{}
	if err := json.Unmarshal(raw, &document); err != nil {
		return "", nil, err
	}
	for _, key := range []string{"id", "meta", "password"} {
		delete(document, key)
	}
	targets := map[string][]uuid.UUID{}
	for _, ref := range r.references {
		if targets[ref.name()], err = ref.extract(document); err != nil {
			return "", nil, err
		}
	}
	raw, err = json.Marshal(document)
	return string(raw), targets, err
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

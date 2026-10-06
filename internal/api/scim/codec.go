package scim

import (
	"encoding/json"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func (r *repository[T]) decodeOne(tx *storage.Connection, scope models.SCIMScope, row *models.SCIMResource) (T, error) {
	items, err := r.decodeAll(tx, scope, []models.SCIMResource{*row}, protocol.Projection{})
	if err != nil {
		var zero T
		return zero, err
	}
	return items[0], nil
}

func (r *repository[T]) decodeAll(tx *storage.Connection, scope models.SCIMScope, rows []models.SCIMResource, projection protocol.Projection) ([]T, error) {
	ids := make([]uuid.UUID, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	elements := map[uuid.UUID]map[string]any{}
	for _, ref := range r.references {
		if !projection.Returns(ref.name()) {
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
	if err := json.Unmarshal(row.Resource, &item); err != nil {
		return item, err
	}
	if len(attributes) > 0 {
		raw, err := json.Marshal(attributes)
		if err != nil {
			return item, err
		}
		if err := json.Unmarshal(raw, &item); err != nil {
			return item, err
		}
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
	document, err := core.NewObject(item)
	if err != nil {
		return "", nil, err
	}
	for _, key := range []string{"id", "meta", "password"} {
		document.Remove(key)
	}
	targets := map[string][]uuid.UUID{}
	for _, ref := range r.references {
		if targets[ref.name()], err = ref.extract(document); err != nil {
			return "", nil, err
		}
	}
	raw, err := json.Marshal(document)
	return string(raw), targets, err
}

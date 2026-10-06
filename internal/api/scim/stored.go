package scim

import (
	"slices"
	"strconv"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/api/scim/query"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type stored struct {
	named
	targets []string
}

func Stored(attribute string) Reference {
	return stored{named: named(attribute)}
}

func (ref stored) Columns() map[string]string {
	return map[string]string{query.ValueAttribute: "ref.target_id", "type": "lower(target.resource_type)"}
}

func (ref stored) Exists(inner string, args []any) (string, []any) {
	return "EXISTS (SELECT 1 FROM scim_resource_references ref JOIN scim_resources target ON target.id = ref.target_id AND target.deleted_at IS NULL WHERE ref.source_id = scim_resources.id AND ref.attribute = ? AND " + inner + ")", append([]any{ref.Name()}, args...)
}

func (ref stored) resolve(schemas core.Schemas) Reference {
	var attribute *core.Attribute
	ref.named, attribute = ref.canonical(schemas)
	for _, target := range attribute.SubAttribute("$ref").ReferenceTypes {
		ref.targets = append(ref.targets, string(target))
	}
	return ref
}

func (ref stored) extract(document core.Object) ([]uuid.UUID, error) {
	elements, _ := document.Get(ref.Name()).([]any)
	document.Remove(ref.Name())
	ids := make([]uuid.UUID, 0, len(elements))
	seen := make(map[uuid.UUID]bool, len(elements))
	for _, element := range elements {
		value, _ := element.(map[string]any)["value"].(string)
		id, err := uuid.FromString(value)
		if err != nil {
			return nil, scimerrors.ErrInvalidValue(strconv.Quote(value) + " is not a valid " + ref.Name() + " value")
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (ref stored) link(tx *storage.Connection, scope models.SCIMScope, source uuid.UUID, wanted []uuid.UUID) error {
	current, err := scope.FindReferences(tx, []uuid.UUID{source}, ref.Name())
	if err != nil {
		return err
	}
	add, remove := diff(current, wanted)
	if err := ref.acyclic(tx, scope, source, add); err != nil {
		return err
	}
	added, err := scope.AddReferences(tx, source, ref.Name(), ref.targets, add)
	if err != nil {
		return err
	}
	for _, id := range add {
		if !slices.Contains(added, id) {
			return scimerrors.ErrInvalidValue(strconv.Quote(id.String()) + " is not a valid " + ref.Name() + " value")
		}
	}
	return scope.RemoveReferences(tx, source, ref.Name(), remove)
}

func (ref stored) acyclic(tx *storage.Connection, scope models.SCIMScope, source uuid.UUID, targets []uuid.UUID) error {
	if len(targets) == 0 {
		return nil
	}
	ancestors, err := scope.FindAncestors(tx, []uuid.UUID{source}, ref.Name())
	if err != nil {
		return err
	}
	for _, target := range targets {
		if target == source || slices.ContainsFunc(ancestors, func(ancestor models.SCIMAncestor) bool { return ancestor.SourceID == target }) {
			return scimerrors.ErrInvalidValue(strconv.Quote(target.String()) + " would make " + ref.Name() + " cyclic")
		}
	}
	return nil
}

func (ref stored) load(tx *storage.Connection, scope models.SCIMScope, ids []uuid.UUID, locations map[string]string) (map[uuid.UUID][]any, error) {
	elements := map[uuid.UUID][]any{}
	references, err := scope.FindReferences(tx, ids, ref.Name())
	for _, reference := range references {
		elements[reference.SourceID] = append(elements[reference.SourceID], element(reference.TargetID, locations[reference.TargetType], reference.TargetType))
	}
	return elements, err
}

func diff(current []models.SCIMReference, wanted []uuid.UUID) (add, remove []uuid.UUID) {
	have := make(map[uuid.UUID]bool, len(current))
	for _, reference := range current {
		have[reference.TargetID] = true
	}
	for _, id := range wanted {
		if !have[id] {
			add = append(add, id)
		}
		delete(have, id)
	}
	for id := range have {
		remove = append(remove, id)
	}
	return add, remove
}

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

func (ref stored) resolve(schemas core.Schemas) Reference {
	var attribute *core.Attribute
	ref.named, attribute = ref.canonical(schemas)
	for _, target := range attribute.SubAttribute("$ref").ReferenceTypes {
		ref.targets = append(ref.targets, string(target))
	}
	return ref
}

func (ref stored) extract(document map[string]any) ([]uuid.UUID, error) {
	elements, _ := document[ref.name()].([]any)
	delete(document, ref.name())
	ids := make([]uuid.UUID, 0, len(elements))
	seen := make(map[uuid.UUID]bool, len(elements))
	for _, element := range elements {
		value, _ := element.(map[string]any)["value"].(string)
		id, err := uuid.FromString(value)
		if err != nil {
			return nil, scimerrors.ErrInvalidValue(strconv.Quote(value) + " is not a valid " + ref.name() + " value")
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (ref stored) link(tx *storage.Connection, scope models.SCIMScope, source uuid.UUID, wanted []uuid.UUID) error {
	current, err := scope.FindReferences(tx, []uuid.UUID{source}, ref.name())
	if err != nil {
		return err
	}
	add, remove := diff(current, wanted)
	if err := ref.admit(tx, scope, source, add); err != nil {
		return err
	}
	if err := scope.AddReferences(tx, source, ref.name(), add); err != nil {
		return err
	}
	return scope.RemoveReferences(tx, source, ref.name(), remove)
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

func (ref stored) admit(tx *storage.Connection, scope models.SCIMScope, source uuid.UUID, targets []uuid.UUID) error {
	types, err := scope.LockTargets(tx, targets)
	if err != nil {
		return err
	}
	nested := false
	for _, target := range targets {
		if !slices.Contains(ref.targets, types[target]) {
			return scimerrors.ErrInvalidValue(strconv.Quote(target.String()) + " is not a valid " + ref.name() + " value")
		}
		nested = nested || types[target] == scope.ResourceType
	}
	if !nested {
		return nil
	}
	return ref.acyclic(tx, scope, source, targets)
}

func (ref stored) acyclic(tx *storage.Connection, scope models.SCIMScope, source uuid.UUID, targets []uuid.UUID) error {
	if err := scope.LockHierarchy(tx); err != nil {
		return err
	}
	ancestors, err := scope.FindAncestorIDs(tx, source, ref.name())
	if err != nil {
		return err
	}
	ancestors = append(ancestors, source)
	for _, target := range targets {
		if slices.Contains(ancestors, target) {
			return scimerrors.ErrInvalidValue(strconv.Quote(target.String()) + " would make " + ref.name() + " cyclic")
		}
	}
	return nil
}

func (ref stored) load(tx *storage.Connection, scope models.SCIMScope, ids []uuid.UUID, locations map[string]string) (map[uuid.UUID][]any, error) {
	elements := map[uuid.UUID][]any{}
	references, err := scope.FindReferences(tx, ids, ref.name())
	for _, reference := range references {
		elements[reference.SourceID] = append(elements[reference.SourceID], map[string]any{
			"value": reference.TargetID.String(),
			"$ref":  locations[reference.TargetType] + "/" + reference.TargetID.String(),
			"type":  reference.TargetType,
		})
	}
	return elements, err
}

func (ref stored) query() query.Reference {
	return query.Stored(ref.name())
}

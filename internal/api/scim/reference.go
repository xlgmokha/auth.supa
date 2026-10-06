package scim

import (
	"slices"
	"strconv"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type Reference struct {
	attribute string
	targets   []string
}

func Stored(attribute string) Reference {
	return Reference{attribute: attribute}
}

func (ref Reference) resolve(schemas core.Schemas) Reference {
	attribute := schemas.Base().Attributes.Lookup(ref.attribute)
	ref.attribute = attribute.Name
	for _, target := range attribute.SubAttribute("$ref").ReferenceTypes {
		ref.targets = append(ref.targets, string(target))
	}
	return ref
}

func (ref Reference) extract(document map[string]any) ([]uuid.UUID, error) {
	elements, _ := document[ref.attribute].([]any)
	delete(document, ref.attribute)
	ids := make([]uuid.UUID, 0, len(elements))
	seen := make(map[uuid.UUID]bool, len(elements))
	for _, element := range elements {
		value, _ := element.(map[string]any)["value"].(string)
		id, err := uuid.FromString(value)
		if err != nil {
			return nil, scimerrors.ErrInvalidValue(strconv.Quote(value) + " is not a valid " + ref.attribute + " value")
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (ref Reference) link(tx *storage.Connection, scope models.SCIMScope, source uuid.UUID, wanted []uuid.UUID) error {
	current, err := scope.FindReferences(tx, []uuid.UUID{source}, ref.attribute)
	if err != nil {
		return err
	}
	have := make(map[uuid.UUID]bool, len(current))
	for _, reference := range current {
		have[reference.TargetID] = true
	}
	add := []uuid.UUID{}
	for _, id := range wanted {
		if !have[id] {
			add = append(add, id)
		}
		delete(have, id)
	}
	remove := make([]uuid.UUID, 0, len(have))
	for id := range have {
		remove = append(remove, id)
	}
	if err := ref.admit(tx, scope, add); err != nil {
		return err
	}
	if err := scope.AddReferences(tx, source, ref.attribute, add); err != nil {
		return err
	}
	return scope.RemoveReferences(tx, source, ref.attribute, remove)
}

func (ref Reference) admit(tx *storage.Connection, scope models.SCIMScope, targets []uuid.UUID) error {
	types, err := scope.LockTargets(tx, targets)
	if err != nil {
		return err
	}
	for _, target := range targets {
		if !slices.Contains(ref.targets, types[target]) {
			return scimerrors.ErrInvalidValue(strconv.Quote(target.String()) + " is not a valid " + ref.attribute + " value")
		}
	}
	return nil
}

func (ref Reference) excluded(attributes []string) bool {
	return slices.ContainsFunc(attributes, func(attribute string) bool {
		return strings.EqualFold(attribute, ref.attribute)
	})
}

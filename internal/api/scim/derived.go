package scim

import (
	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase/auth/internal/api/scim/query"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type derived struct {
	named
	source string
	via    string
}

func Derived(attribute, source, via string) Reference {
	return derived{named: named(attribute), source: source, via: via}
}

func (ref derived) resolve(schemas core.Schemas) Reference {
	ref.named, _ = ref.canonical(schemas)
	return ref
}

func (ref derived) extract(document map[string]any) ([]uuid.UUID, error) {
	delete(document, ref.name())
	return nil, nil
}

func (ref derived) link(*storage.Connection, models.SCIMScope, uuid.UUID, []uuid.UUID) error {
	return nil
}

func (ref derived) load(tx *storage.Connection, scope models.SCIMScope, ids []uuid.UUID, locations map[string]string) (map[uuid.UUID][]any, error) {
	elements := map[uuid.UUID][]any{}
	ancestors, err := scope.FindAncestors(tx, ids, ref.via)
	for _, ancestor := range ancestors {
		element := map[string]any{
			"value": ancestor.SourceID.String(),
			"$ref":  locations[ref.source] + "/" + ancestor.SourceID.String(),
			"type":  "indirect",
		}
		if ancestor.Depth == 1 {
			element["type"] = "direct"
		}
		if ancestor.Display != nil {
			element["display"] = *ancestor.Display
		}
		elements[ancestor.TargetID] = append(elements[ancestor.TargetID], element)
	}
	return elements, err
}

func (ref derived) query() query.Reference {
	return query.Derived(ref.name(), ref.via)
}

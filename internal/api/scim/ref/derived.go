package ref

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

func (ref derived) Columns() map[string]string {
	return map[string]string{query.ValueAttribute: "chain.source_id"}
}

func (ref derived) Exists(inner string, args []any) (string, []any) {
	return `scim_resources.id IN (WITH RECURSIVE down (id) AS (
		SELECT chain.target_id FROM scim_resource_references chain WHERE chain.attribute = ? AND ` + inner + `
		UNION
		SELECT ref.target_id FROM down JOIN scim_resource_references ref ON ref.source_id = down.id AND ref.attribute = ?
	) SELECT id FROM down)`, append(append([]any{ref.via}, args...), ref.via)
}

func (ref derived) Resolve(schemas core.Schemas) Reference {
	ref.named, _ = ref.canonical(schemas)
	return ref
}

func (ref derived) Extract(any) ([]uuid.UUID, error) {
	return nil, nil
}

func (ref derived) Link(*storage.Connection, models.SCIMScope, uuid.UUID, []uuid.UUID) error {
	return nil
}

func (ref derived) Load(tx *storage.Connection, scope models.SCIMScope, ids []uuid.UUID, locations map[string]string) (map[uuid.UUID][]any, error) {
	elements := map[uuid.UUID][]any{}
	ancestors, err := scope.FindAncestors(tx, ids, ref.via)
	for _, ancestor := range ancestors {
		kind := "indirect"
		if ancestor.Depth == 1 {
			kind = "direct"
		}
		entry := element(ancestor.SourceID, locations[ref.source], kind)
		if ancestor.Display != nil {
			entry["display"] = *ancestor.Display
		}
		elements[ancestor.TargetID] = append(elements[ancestor.TargetID], entry)
	}
	return elements, err
}

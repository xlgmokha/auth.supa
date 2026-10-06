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

func (ref derived) extract(document core.Object) ([]uuid.UUID, error) {
	document.Remove(ref.Name())
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

func (ref derived) Columns() map[string]string {
	return map[string]string{query.ValueAttribute: "chain.source_id"}
}

func (ref derived) Exists(inner string, args []any) (string, []any) {
	return `EXISTS (WITH RECURSIVE chain (source_id, depth) AS (
		SELECT source_id, 1 FROM scim_resource_references WHERE target_id = scim_resources.id AND attribute = ?
		UNION
		SELECT ref.source_id, chain.depth + 1 FROM chain JOIN scim_resource_references ref ON ref.target_id = chain.source_id AND ref.attribute = ? WHERE chain.depth < 64
	) SELECT 1 FROM chain WHERE ` + inner + ")", append([]any{ref.via, ref.via}, args...)
}

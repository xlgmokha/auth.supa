package scim

import (
	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase/auth/internal/api/scim/query"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type Reference interface {
	query.Reference
	resolve(schemas core.Schemas) Reference
	extract(attribute any) ([]uuid.UUID, error)
	link(tx *storage.Connection, scope models.SCIMScope, source uuid.UUID, wanted []uuid.UUID) error
	load(tx *storage.Connection, scope models.SCIMScope, ids []uuid.UUID, locations map[string]string) (map[uuid.UUID][]any, error)
}

type named string

func (n named) Name() string {
	return string(n)
}

func (n named) canonical(schemas core.Schemas) (named, *core.Attribute) {
	attribute := schemas.Base().Attributes.Lookup(string(n))
	return named(attribute.Name), attribute
}

func element(id uuid.UUID, endpoint, kind string) map[string]any {
	return map[string]any{
		query.ValueAttribute: id.String(),
		"$ref":               endpoint + "/" + id.String(),
		"type":               kind,
	}
}

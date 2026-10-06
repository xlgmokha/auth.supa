package query

import (
	"strconv"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

type Reference interface {
	name() string
	columns() (id, kind string)
	exists(inner string, args []any) (string, []any)
}

func match(ref Reference, definition *core.Attribute, op filter.Operator, value any) (clause, error) {
	text, _ := value.(string)
	if op != filter.OpEquals && op != filter.OpNotEquals {
		return nil, scimerrors.ErrInvalidFilter(strconv.Quote(ref.name()+"."+definition.Name) + " supports only eq and ne")
	}
	sign := map[filter.Operator]string{filter.OpEquals: " = ", filter.OpNotEquals: " <> "}[op]
	id, kind := ref.columns()
	switch definition.Name {
	case "value":
		target, err := uuid.FromString(text)
		if err != nil {
			return predicate{text: strconv.FormatBool(op == filter.OpNotEquals)}, nil
		}
		return predicate{id + sign + "?::uuid", []any{target.String()}}, nil
	case "type":
		return predicate{kind + sign + "?", []any{strings.ToLower(text)}}, nil
	}
	return nil, scimerrors.ErrInvalidFilter(strconv.Quote(ref.name()+"."+definition.Name) + " cannot be filtered")
}

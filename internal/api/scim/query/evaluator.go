package query

import (
	"strings"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/protocol"
)

type Evaluator struct {
	schemas core.Schemas
}

func NewEvaluator(schemas core.Schemas) protocol.Evaluator[Builder] {
	return Evaluator{schemas: schemas}
}

func (e Evaluator) Compare(attribute *protocol.Attribute, op filter.Operator, value any) (Builder, error) {
	return Builder{compare{e.path(attribute), op, value}}, nil
}

func (e Evaluator) Present(attribute *protocol.Attribute) (Builder, error) {
	return Builder{present{e.path(attribute)}}, nil
}

func (e Evaluator) And(l, r Builder) (Builder, error) {
	return Builder{and{l.expr, r.expr}}, nil
}

func (e Evaluator) Or(l, r Builder) (Builder, error) {
	return Builder{or{l.expr, r.expr}}, nil
}

func (e Evaluator) Not(operand Builder) (Builder, error) {
	return Builder{not{operand.expr}}, nil
}

func (e Evaluator) ValuePath(attribute *protocol.Attribute, valueFilter func() (Builder, error)) (Builder, error) {
	inner, err := valueFilter()
	if err != nil {
		return inner, err
	}
	return Builder{exists{e.path(attribute), inner.expr}}, nil
}

func (e Evaluator) path(attribute *protocol.Attribute) path {
	if attribute.Parent != nil {
		return path{"@", []string{attribute.Definition.Name}}
	}
	keys := []string{attribute.Definition.Name}
	if top, ok := e.schemas.Resolve(core.SchemaURI(attribute.Path.URI), attribute.Path.Name, ""); ok && top != attribute.Definition {
		keys = []string{top.Name, attribute.Definition.Name}
	}
	schema := e.schemas.Lookup(core.SchemaURI(attribute.Path.URI))
	if e.schemas.IsExtension(schema) {
		return path{"$", append([]string{string(schema.ID)}, keys...)}
	}
	if root, ok := variables[strings.Join(keys, ".")]; ok {
		return path{root: root}
	}
	return path{"$", keys}
}

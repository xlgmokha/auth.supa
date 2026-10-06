package query

import (
	"slices"
	"strconv"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

type Evaluator struct {
	schemas    core.Schemas
	references []string
}

func NewEvaluator(schemas core.Schemas, references ...string) protocol.Evaluator[Builder] {
	return Evaluator{schemas: schemas, references: references}
}

func (e Evaluator) Compare(attribute *protocol.Attribute, op filter.Operator, value any) (Builder, error) {
	name, ok := e.reference(attribute)
	if !ok {
		return Builder{jsonpath{compare{e.path(attribute), op, value}}}, nil
	}
	leaf, err := target(name, attribute.Definition, op, value)
	if err != nil {
		return Builder{}, err
	}
	return e.wrap(attribute, name, leaf), nil
}

func (e Evaluator) Present(attribute *protocol.Attribute) (Builder, error) {
	name, ok := e.reference(attribute)
	if !ok {
		return Builder{jsonpath{present{e.path(attribute)}}}, nil
	}
	return e.wrap(attribute, name, predicate{text: "TRUE"}), nil
}

func (e Evaluator) And(l, r Builder) (Builder, error) {
	if lpath, rpath, ok := jsonpaths(l, r); ok {
		return Builder{jsonpath{and{lpath.expr, rpath.expr}}}, nil
	}
	return Builder{junction{"AND", l.clause, r.clause}}, nil
}

func (e Evaluator) Or(l, r Builder) (Builder, error) {
	if lpath, rpath, ok := jsonpaths(l, r); ok {
		return Builder{jsonpath{or{lpath.expr, rpath.expr}}}, nil
	}
	return Builder{junction{"OR", l.clause, r.clause}}, nil
}

func (e Evaluator) Not(operand Builder) (Builder, error) {
	if path, ok := operand.clause.(jsonpath); ok {
		return Builder{jsonpath{not{path.expr}}}, nil
	}
	return Builder{negation{operand.clause}}, nil
}

func (e Evaluator) ValuePath(attribute *protocol.Attribute, valueFilter func() (Builder, error)) (Builder, error) {
	inner, err := valueFilter()
	if err != nil {
		return inner, err
	}
	if name, ok := e.reference(attribute); ok {
		return Builder{reference{name, inner.clause}}, nil
	}
	path, ok := inner.clause.(jsonpath)
	if !ok {
		return Builder{}, scimerrors.ErrInvalidFilter(scimerrors.InvalidFilter.Description())
	}
	return Builder{jsonpath{exists{e.path(attribute), path.expr}}}, nil
}

func (e Evaluator) wrap(attribute *protocol.Attribute, name string, leaf clause) Builder {
	if attribute.Parent != nil {
		return Builder{leaf}
	}
	return Builder{reference{name, leaf}}
}

func (e Evaluator) reference(attribute *protocol.Attribute) (string, bool) {
	top := attribute.Parent
	if top == nil {
		base := e.schemas.Base()
		if attribute.Path.URI != "" && core.SchemaURI(attribute.Path.URI) != base.ID {
			return "", false
		}
		top = base.Attributes.Lookup(attribute.Path.Name)
	}
	if top == nil {
		return "", false
	}
	return top.Name, slices.Contains(e.references, top.Name)
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

func target(name string, definition *core.Attribute, op filter.Operator, value any) (clause, error) {
	text, _ := value.(string)
	if op != filter.OpEquals && op != filter.OpNotEquals {
		return nil, scimerrors.ErrInvalidFilter(strconv.Quote(name+"."+definition.Name) + " supports only eq and ne")
	}
	sign := map[filter.Operator]string{filter.OpEquals: " = ", filter.OpNotEquals: " <> "}[op]
	switch definition.Name {
	case "value":
		id, err := uuid.FromString(text)
		if err != nil {
			return predicate{text: strconv.FormatBool(op == filter.OpNotEquals)}, nil
		}
		return predicate{"ref.target_id" + sign + "?::uuid", []any{id.String()}}, nil
	case "type":
		return predicate{"lower(target.resource_type)" + sign + "?", []any{strings.ToLower(text)}}, nil
	}
	return nil, scimerrors.ErrInvalidFilter(strconv.Quote(name+"."+definition.Name) + " cannot be filtered")
}

func jsonpaths(l, r Builder) (jsonpath, jsonpath, bool) {
	lpath, lok := l.clause.(jsonpath)
	rpath, rok := r.clause.(jsonpath)
	return lpath, rpath, lok && rok
}

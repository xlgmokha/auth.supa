package scim

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/protocol"
)

var variables = map[string]string{
	"id":                "$id",
	"meta.created":      "$created",
	"meta.lastModified": "$lastmodified",
}

var operators = map[filter.Operator]string{
	filter.OpEquals:            "==",
	filter.OpNotEquals:         "!=",
	filter.OpGreaterThan:       ">",
	filter.OpGreaterThanEquals: ">=",
	filter.OpLessThan:          "<",
	filter.OpLessThanEquals:    "<=",
}

type expr interface {
	String() string
	variables() bool
}

type path struct {
	root string
	keys []string
}

func (p path) String() string {
	var s strings.Builder
	s.WriteString(p.root)
	for _, key := range p.keys {
		s.WriteString("." + quote(strings.ToLower(key)))
	}
	if p.variables() && p.root != "$id" {
		s.WriteString(".datetime()")
	}
	return s.String()
}

func (p path) variables() bool {
	return p.root != "$" && p.root != "@"
}

type compare struct {
	path  path
	op    filter.Operator
	value any
}

func (c compare) String() string {
	switch c.op {
	case filter.OpStartsWith:
		return c.path.String() + " starts with " + literal(c.value)
	case filter.OpContains:
		return c.path.String() + " like_regex " + pattern(c.value, "")
	case filter.OpEndsWith:
		return c.path.String() + " like_regex " + pattern(c.value, "$")
	}
	return c.path.String() + " " + operators[c.op] + " " + literal(c.value)
}

func (c compare) variables() bool { return c.path.variables() }

type present struct{ path path }

func (p present) String() string {
	return "exists(" + p.path.String() + ` ? (@.type() != "null" && !(@.type() == "string" && @ == "")))`
}

func (p present) variables() bool { return p.path.variables() }

type and struct{ l, r expr }

func (a and) String() string  { return "(" + a.l.String() + " && " + a.r.String() + ")" }
func (a and) variables() bool { return a.l.variables() || a.r.variables() }

type or struct{ l, r expr }

func (o or) String() string  { return "(" + o.l.String() + " || " + o.r.String() + ")" }
func (o or) variables() bool { return o.l.variables() || o.r.variables() }

type not struct{ x expr }

func (n not) String() string  { return "!(" + n.x.String() + ")" }
func (n not) variables() bool { return n.x.variables() }

type exists struct {
	path  path
	inner expr
}

func (e exists) String() string {
	return "exists(" + e.path.String() + "[*] ? (" + e.inner.String() + "))"
}

func (e exists) variables() bool { return e.inner.variables() }

type queryBuilder struct {
	expr expr
}

func (b queryBuilder) Scope(q *pop.Query) *pop.Query {
	if b.expr.variables() {
		return q.Where("jsonb_path_match(lower(resource::text)::jsonb, ?::jsonpath, jsonb_build_object('id', id, 'created', created_at, 'lastmodified', updated_at))", b.expr.String())
	}
	return q.Where("lower(resource::text)::jsonb @@ ?::jsonpath", b.expr.String())
}

func (b queryBuilder) Build(q *pop.Query) *pop.Query {
	return q.Scope(b.Scope)
}

type queryEvaluator struct {
	schemas core.Schemas
}

func newEvaluator(schemas core.Schemas) protocol.Evaluator[queryBuilder] {
	return queryEvaluator{schemas: schemas}
}

func (e queryEvaluator) Compare(attribute *protocol.Attribute, op filter.Operator, value any) (queryBuilder, error) {
	return queryBuilder{compare{e.path(attribute), op, value}}, nil
}

func (e queryEvaluator) Present(attribute *protocol.Attribute) (queryBuilder, error) {
	return queryBuilder{present{e.path(attribute)}}, nil
}

func (e queryEvaluator) And(l, r queryBuilder) (queryBuilder, error) {
	return queryBuilder{and{l.expr, r.expr}}, nil
}

func (e queryEvaluator) Or(l, r queryBuilder) (queryBuilder, error) {
	return queryBuilder{or{l.expr, r.expr}}, nil
}

func (e queryEvaluator) Not(operand queryBuilder) (queryBuilder, error) {
	return queryBuilder{not{operand.expr}}, nil
}

func (e queryEvaluator) ValuePath(attribute *protocol.Attribute, valueFilter func() (queryBuilder, error)) (queryBuilder, error) {
	inner, err := valueFilter()
	if err != nil {
		return inner, err
	}
	return queryBuilder{exists{e.path(attribute), inner.expr}}, nil
}

func (e queryEvaluator) path(attribute *protocol.Attribute) path {
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

func literal(value any) string {
	switch v := value.(type) {
	case time.Time:
		return quote(v.UTC().Format("2006-01-02T15:04:05.999999-07:00")) + ".datetime()"
	case string:
		return quote(strings.ToLower(v))
	}
	raw, _ := json.Marshal(value)
	return string(raw)
}

func pattern(value any, suffix string) string {
	s, _ := value.(string)
	return quote(regexp.QuoteMeta(strings.ToLower(s)) + suffix)
}

func quote(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

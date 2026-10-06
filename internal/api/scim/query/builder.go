package query

import "github.com/gobuffalo/pop/v6"

type Builder struct {
	expr expr
}

func (b Builder) Scope(q *pop.Query) *pop.Query {
	if b.expr.variables() {
		return q.Where("jsonb_path_match(lower(resource::text)::jsonb, ?::jsonpath, jsonb_build_object('id', id, 'created', created_at, 'lastmodified', updated_at))", b.expr.String())
	}
	return q.Where("lower(resource::text)::jsonb @@ ?::jsonpath", b.expr.String())
}

func (b Builder) Build(q *pop.Query) *pop.Query {
	return q.Scope(b.Scope)
}

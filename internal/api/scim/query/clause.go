package query

type clause interface {
	sql() (string, []any)
}

type jsonpath struct{ expr expr }

func (j jsonpath) sql() (string, []any) {
	if j.expr.variables() {
		return "jsonb_path_match(lower(resource::text)::jsonb, ?::jsonpath, jsonb_build_object('id', id, 'created', created_at, 'lastmodified', updated_at))", []any{j.expr.String()}
	}
	return "lower(resource::text)::jsonb @@ ?::jsonpath", []any{j.expr.String()}
}

type junction struct {
	op   string
	l, r clause
}

func (j junction) sql() (string, []any) {
	l, largs := j.l.sql()
	r, rargs := j.r.sql()
	return "(" + l + " " + j.op + " " + r + ")", append(largs, rargs...)
}

type negation struct{ x clause }

func (n negation) sql() (string, []any) {
	x, args := n.x.sql()
	return "NOT (" + x + ")", args
}

type predicate struct {
	text string
	args []any
}

func (p predicate) sql() (string, []any) { return p.text, p.args }

type reference struct {
	ref   Reference
	inner clause
}

func (r reference) sql() (string, []any) {
	inner, args := r.inner.sql()
	return r.ref.exists(inner, args)
}

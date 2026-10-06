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

type Reference struct {
	Attribute string
	Via       string
}

type reference struct {
	Reference
	inner clause
}

func (r reference) sql() (string, []any) {
	inner, args := r.inner.sql()
	if r.Via == "" {
		return "EXISTS (SELECT 1 FROM scim_resource_references ref JOIN scim_resources target ON target.id = ref.target_id WHERE ref.source_id = scim_resources.id AND ref.attribute = ? AND " + inner + ")", append([]any{r.Attribute}, args...)
	}
	return `EXISTS (WITH RECURSIVE chain (source_id, depth) AS (
		SELECT source_id, 1 FROM scim_resource_references WHERE target_id = scim_resources.id AND attribute = ?
		UNION
		SELECT ref.source_id, chain.depth + 1 FROM chain JOIN scim_resource_references ref ON ref.target_id = chain.source_id AND ref.attribute = ? WHERE chain.depth < 64
	) SELECT 1 FROM chain WHERE ` + inner + ")", append([]any{r.Via, r.Via}, args...)
}

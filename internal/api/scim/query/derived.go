package query

type derived struct {
	attribute string
	via       string
}

func Derived(attribute, via string) Reference {
	return derived{attribute, via}
}

func (d derived) name() string { return d.attribute }

func (d derived) columns() (string, string) {
	return "chain.source_id", "(CASE WHEN chain.depth = 1 THEN 'direct' ELSE 'indirect' END)"
}

func (d derived) exists(inner string, args []any) (string, []any) {
	return `EXISTS (WITH RECURSIVE chain (source_id, depth) AS (
		SELECT source_id, 1 FROM scim_resource_references WHERE target_id = scim_resources.id AND attribute = ?
		UNION
		SELECT ref.source_id, chain.depth + 1 FROM chain JOIN scim_resource_references ref ON ref.target_id = chain.source_id AND ref.attribute = ? WHERE chain.depth < 64
	) SELECT 1 FROM chain WHERE ` + inner + ")", append([]any{d.via, d.via}, args...)
}

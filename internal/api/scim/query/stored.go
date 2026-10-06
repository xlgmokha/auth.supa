package query

type stored struct {
	attribute string
}

func Stored(attribute string) Reference {
	return stored{attribute}
}

func (s stored) name() string { return s.attribute }

func (s stored) columns() map[string]string {
	return map[string]string{valueAttribute: "ref.target_id", "type": "lower(target.resource_type)"}
}

func (s stored) exists(inner string, args []any) (string, []any) {
	return "EXISTS (SELECT 1 FROM scim_resource_references ref JOIN scim_resources target ON target.id = ref.target_id WHERE ref.source_id = scim_resources.id AND ref.attribute = ? AND " + inner + ")", append([]any{s.attribute}, args...)
}

package scim

import (
	"strconv"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

// fragment is SQL over the scim_resources alias r whose "?" placeholders are
// bound, in order, to args. The jsonb "?" operator is never used, because
// every "?" is rebound as a placeholder.
type fragment struct {
	sql  string
	args []any
}

// sqlf substitutes each "%s" in format with the next part, keeping the
// parts' arguments in placeholder order.
func sqlf(format string, parts ...fragment) fragment {
	out := fragment{}
	pieces := strings.Split(format, "%s")
	var b strings.Builder
	for i, piece := range pieces {
		b.WriteString(piece)
		if i < len(parts) {
			b.WriteString(parts[i].sql)
			out.args = append(out.args, parts[i].args...)
		}
	}
	out.sql = b.String()
	return out
}

func bind(value any) fragment {
	return fragment{sql: "?", args: []any{value}}
}

func raw(sql string) fragment {
	return fragment{sql: sql}
}

// scope is the element a value filter or multi-valued comparison ranges over.
type scope struct {
	alias     string
	reference *reference
	derived   *derived
}

// related reports whether the elements in scope are other resources, rather
// than elements of the document.
func (s *scope) related() bool {
	return s.reference != nil || s.derived != nil
}

// evaluator translates a SCIM filter, RFC 7644 Section 3.4.2.2, into SQL. The
// filter has already been validated against the schema, so attribute types,
// operators and literal types are known to be compatible.
type evaluator struct {
	kind    *resourceType
	tenant  *Tenant
	scope   *scope
	aliases int
}

func newEvaluator(kind *resourceType, tenant *Tenant) *evaluator {
	return &evaluator{kind: kind, tenant: tenant}
}

func (e *evaluator) Compare(attribute *protocol.Attribute, op filter.Operator, value any) (fragment, error) {
	if value == nil {
		// RFC 7644 Section 3.4.2.2: comparing with null tests for presence.
		assigned, err := e.Present(attribute)
		switch {
		case err != nil:
			return fragment{}, err
		case op == filter.OpEquals:
			return e.Not(assigned)
		case op == filter.OpNotEquals:
			return assigned, nil
		}
		return fragment{}, invalidFilter()
	}
	return e.predicate(attribute, func(target fragment, definition *core.Attribute) (fragment, error) {
		return compare(target, definition, op, value)
	}, op, value)
}

// Present is true when the attribute has a value other than null, "", [] or
// {}; for a multi-valued attribute, when any element has one.
func (e *evaluator) Present(attribute *protocol.Attribute) (fragment, error) {
	definition := attribute.Definition
	if e.scope != nil {
		target, err := e.scopedJSON(definition)
		if err != nil {
			return fragment{}, err
		}
		return assigned(target), nil
	}
	if column, ok := commonColumn(attribute); ok {
		if column.sql == "" {
			return fragment{}, invalidFilter()
		}
		return sqlf("(%s) is not null", column), nil
	}
	top := e.topLevel(attribute.Path)
	if top == nil {
		return fragment{}, invalidFilter()
	}
	if top.MultiValued {
		return e.within(attribute.Path, top, func() (fragment, error) {
			return e.Present(attribute)
		})
	}
	return assigned(e.json(attribute.Path, top, definition)), nil
}

func (e *evaluator) And(left, right fragment) (fragment, error) {
	return sqlf("(%s) and (%s)", left, right), nil
}

func (e *evaluator) Or(left, right fragment) (fragment, error) {
	return sqlf("(%s) or (%s)", left, right), nil
}

func (e *evaluator) Not(operand fragment) (fragment, error) {
	return sqlf("not coalesce((%s), false)", operand), nil
}

func (e *evaluator) ValuePath(attribute *protocol.Attribute, valueFilter func() (fragment, error)) (fragment, error) {
	top := e.topLevel(attribute.Path)
	if top == nil || !top.MultiValued {
		return fragment{}, invalidFilter()
	}
	return e.within(attribute.Path, top, valueFilter)
}

// predicate builds the condition for one attribute: for single-valued
// attributes directly, and for multi-valued attributes as "any element
// matches", per RFC 7644 Section 3.4.2.2.
func (e *evaluator) predicate(attribute *protocol.Attribute, test func(target fragment, definition *core.Attribute) (fragment, error), op filter.Operator, value any) (fragment, error) {
	definition := attribute.Definition
	if e.scope != nil {
		if referenced, ok := e.referencedID(definition, op, value); ok {
			return referenced, nil
		}
		target, err := e.scoped(definition)
		if err != nil {
			return fragment{}, err
		}
		return test(target, definition)
	}

	if column, ok := commonColumn(attribute); ok {
		if column.sql == "" {
			return fragment{}, invalidFilter()
		}
		return test(column, definition)
	}

	top := e.topLevel(attribute.Path)
	if top == nil {
		return fragment{}, invalidFilter()
	}
	if top.MultiValued {
		// Filters on a multi-valued attribute range over its elements; a
		// complex one without a sub-attribute compares "value".
		return e.within(attribute.Path, top, func() (fragment, error) {
			return e.predicate(attribute, test, op, value)
		})
	}
	if k := e.kind.key(top.Name); k != nil && attribute.Path.SubAttribute == "" && attribute.Path.URI == "" {
		if indexed, ok := e.keyed(k, definition, op, value); ok {
			return indexed, nil
		}
	}
	return test(e.document(attribute.Path, top, definition), definition)
}

// within evaluates inner with the elements of the multi-valued attribute top
// in scope, and returns it as a condition on the resource: that any element
// matches.
func (e *evaluator) within(path filter.AttrPath, top *core.Attribute, inner func() (fragment, error)) (fragment, error) {
	e.aliases++
	s := &scope{alias: "e" + strconv.Itoa(e.aliases), reference: e.kind.reference(top.Name), derived: e.kind.derivedAttribute(top.Name)}

	previous := e.scope
	e.scope = s
	condition, err := inner()
	e.scope = previous
	if err != nil {
		return fragment{}, err
	}

	switch {
	case s.reference != nil:
		return sqlf(`exists (select 1 from scim_resource_references `+s.alias+`r
			join scim_resources `+s.alias+` on `+s.alias+`.id = `+s.alias+`r.target_id
			where `+s.alias+`r.source_id = r.id and `+s.alias+`r.attribute = %s and (%s))`,
			bind(s.reference.attribute), condition), nil
	case s.derived != nil:
		return sqlf(`exists (select 1 from scim_resource_references `+s.alias+`r
			join scim_resources `+s.alias+` on `+s.alias+`.id = `+s.alias+`r.source_id
			where `+s.alias+`r.target_id = r.id and `+s.alias+`r.attribute = %s and (%s))`,
			bind(s.derived.via), condition), nil
	}
	source := e.document(filter.AttrPath{URI: path.URI, Name: path.Name}, top, top)
	return sqlf("exists (select 1 from jsonb_path_query(%s, '$[*]') as "+s.alias+"(v) where %s)", source, condition), nil
}

// referencedID answers "value eq <id>" on a reference by comparing ids as
// uuids, so the lookup is driven by the primary key of the referenced
// resource rather than by scanning references.
func (e *evaluator) referencedID(definition *core.Attribute, op filter.Operator, value any) (fragment, bool) {
	if !e.scope.related() {
		return fragment{}, false
	}
	if op != filter.OpEquals || !strings.EqualFold(definition.Name, "value") {
		return fragment{}, false
	}
	s, ok := value.(string)
	if !ok {
		return fragment{}, false
	}
	id, err := uuid.FromString(s)
	if err != nil {
		return raw("false"), true
	}
	return sqlf(e.scope.alias+".id = %s::uuid", bind(id.String())), true
}

// scoped returns the typed value of a sub-attribute of the element in scope,
// or of the element itself for a multi-valued attribute of simple values.
func (e *evaluator) scoped(definition *core.Attribute) (fragment, error) {
	if !e.scope.related() && definition.Type == core.TypeComplex {
		return fragment{}, invalidFilter()
	}
	target, err := e.scopedJSON(definition)
	if err != nil || e.scope.related() {
		return foldColumn(target, definition), err
	}
	return typed(target, definition), nil
}

// scopedJSON returns the element in scope, or one of its sub-attributes. For
// references the values are columns of the referenced resource.
func (e *evaluator) scopedJSON(definition *core.Attribute) (fragment, error) {
	alias := e.scope.alias
	if e.scope.related() {
		name := strings.ToLower(definition.Name)
		switch {
		case name == "value",
			e.scope.reference != nil && name == strings.ToLower(e.scope.reference.attribute),
			e.scope.derived != nil && name == strings.ToLower(e.scope.derived.attribute):
			return raw(alias + ".id::text"), nil
		case name == "type" && e.scope.reference != nil:
			return raw(alias + ".resource_type"), nil
		case name == "type":
			return raw("'direct'::text"), nil
		case name == "display" && e.scope.derived != nil:
			return sqlf("("+alias+".resource ->> %s)", bind(e.scope.derived.display)), nil
		}
		return fragment{}, invalidFilter()
	}
	if isElementValue(definition) || definition.Type == core.TypeComplex {
		return raw(alias + ".v"), nil
	}
	return sqlf(alias+".v -> %s", bind(definition.Name)), nil
}

// assigned is true for a value other than SQL null or JSON null, "", [] and
// {}. Column values are never JSON, so only the null test applies to them.
func assigned(target fragment) fragment {
	return sqlf(`coalesce(to_jsonb(%s) not in ('null'::jsonb, '""'::jsonb, '[]'::jsonb, '{}'::jsonb), false)`, target)
}

// foldColumn makes a text column comparable with folded literals.
func foldColumn(target fragment, definition *core.Attribute) fragment {
	if definition.Type == core.TypeString && !definition.CaseExact {
		return sqlf(`lower(%s) collate "C"`, target)
	}
	return sqlf(`(%s) collate "C"`, target)
}

// isElementValue reports whether definition is a multi-valued attribute of
// simple values, whose elements are the values themselves.
func isElementValue(definition *core.Attribute) bool {
	return definition.MultiValued && definition.Type != core.TypeComplex
}

// topLevel resolves the attribute a path starts from.
func (e *evaluator) topLevel(path filter.AttrPath) *core.Attribute {
	attribute, ok := e.kind.schemas.Resolve(core.SchemaURI(path.URI), path.Name, "")
	if !ok {
		return nil
	}
	return attribute
}

// document returns the typed value of a single-valued attribute stored in the
// resource document.
func (e *evaluator) document(path filter.AttrPath, top, definition *core.Attribute) fragment {
	target := e.json(path, top, definition)
	if definition.Type == core.TypeComplex || definition.MultiValued {
		return target
	}
	return typed(target, definition)
}

// json returns the jsonb value of an attribute stored in the resource
// document.
func (e *evaluator) json(path filter.AttrPath, top, definition *core.Attribute) fragment {
	target := raw("r.resource")
	if schema := e.kind.schemas.Lookup(core.SchemaURI(path.URI)); schema != nil && e.kind.schemas.IsExtension(schema) {
		target = sqlf("%s -> %s", target, bind(string(schema.ID)))
	}
	target = sqlf("%s -> %s", target, bind(top.Name))
	if path.SubAttribute != "" && definition != top {
		target = sqlf("%s -> %s", target, bind(definition.Name))
	}
	return target
}

// keyed answers eq and sw on a keyed attribute from the key index. Keys hold
// only non-empty values, so an empty literal is answered from the document.
func (e *evaluator) keyed(k *key, definition *core.Attribute, op filter.Operator, value any) (fragment, bool) {
	s, ok := value.(string)
	if !ok || s == "" {
		return fragment{}, false
	}
	s = fold(definition, s)
	lookup := `r.id in (select k.resource_id from scim_resource_keys k
		where k.directory_id = %s and k.resource_type = %s and k.attribute = %s and `
	parts := []fragment{bind(e.tenant.DirectoryID), bind(e.kind.name), bind(k.attribute)}
	switch op {
	case filter.OpEquals:
		return sqlf(lookup+"k.value = %s)", append(parts, bind(s))...), true
	case filter.OpStartsWith:
		return sqlf(lookup+"k.value >= %s and k.value < %s)", append(parts, bind(s), bind(s+"\U0010FFFF"))...), true
	}
	return fragment{}, false
}

// typed converts a jsonb value into an SQL value comparable with literals of
// the attribute's type. Values of another JSON type become NULL.
func typed(target fragment, definition *core.Attribute) fragment {
	switch definition.Type {
	case core.TypeBoolean:
		return sqlf("(case when jsonb_typeof(%s) = 'boolean' then (%s)::boolean end)", target, target)
	case core.TypeInteger, core.TypeDecimal:
		return sqlf("(case when jsonb_typeof(%s) = 'number' then (%s)::numeric end)", target, target)
	case core.TypeDateTime:
		return sqlf(`(case when jsonb_typeof(%s) = 'string' and (%s #>> '{}') ~ '^\d{4}-\d{2}-\d{2}T'
			then (%s #>> '{}')::timestamptz end)`, target, target, target)
	}
	text := sqlf(`(case when jsonb_typeof(%s) = 'string' then (%s #>> '{}') end) collate "C"`, target, target)
	if definition.Type == core.TypeString && !definition.CaseExact {
		return sqlf(`lower(%s) collate "C"`, text)
	}
	return text
}

// compare applies one comparison operator to a typed value.
func compare(target fragment, definition *core.Attribute, op filter.Operator, value any) (fragment, error) {
	literal := literalFor(definition, value)
	switch op {
	case filter.OpEquals:
		return sqlf("%s = %s", target, literal), nil
	case filter.OpNotEquals:
		return sqlf("%s <> %s", target, literal), nil
	case filter.OpContains:
		return sqlf("strpos(%s, %s) > 0", target, literal), nil
	case filter.OpStartsWith:
		return sqlf("starts_with(%s, %s)", target, literal), nil
	case filter.OpEndsWith:
		return sqlf("right(%s, char_length(%s)) = %s", target, literal, literal), nil
	case filter.OpGreaterThan:
		return sqlf("%s > %s", target, literal), nil
	case filter.OpGreaterThanEquals:
		return sqlf("%s >= %s", target, literal), nil
	case filter.OpLessThan:
		return sqlf("%s < %s", target, literal), nil
	case filter.OpLessThanEquals:
		return sqlf("%s <= %s", target, literal), nil
	}
	return fragment{}, invalidFilter()
}

func literalFor(definition *core.Attribute, value any) fragment {
	switch definition.Type {
	case core.TypeBoolean:
		return sqlf("%s::boolean", bind(value))
	case core.TypeInteger, core.TypeDecimal:
		return sqlf("%s::numeric", bind(value))
	case core.TypeDateTime:
		return sqlf("%s::timestamptz", bind(value))
	}
	s, _ := value.(string)
	return sqlf(`%s::text collate "C"`, bind(fold(definition, s)))
}

// commonColumn maps id and meta sub-attributes, which are columns rather
// than document attributes. An empty fragment means not filterable.
func commonColumn(attribute *protocol.Attribute) (fragment, bool) {
	definition := attribute.Definition
	if id, _ := core.CommonAttribute("id"); definition == id {
		return raw(`r.id::text collate "C"`), true
	}
	meta, _ := core.CommonAttribute("meta")
	switch definition {
	case meta.SubAttribute("created"):
		return raw("r.created_at"), true
	case meta.SubAttribute("lastModified"):
		return raw("r.updated_at"), true
	case meta.SubAttribute("resourceType"):
		return raw(`r.resource_type collate "C"`), true
	case meta.SubAttribute("location"), meta.SubAttribute("version"), meta:
		return fragment{}, true
	}
	return fragment{}, false
}

func invalidFilter() error {
	return scimerrors.ErrInvalidFilter(scimerrors.InvalidFilter.Description())
}

// orderBy translates sortBy and sortOrder, RFC 7644 Section 3.4.2.3, into an
// ORDER BY that is a total order: ties break on id.
func orderBy(kind *resourceType, tenant *Tenant, query *protocol.SearchRequest) (fragment, error) {
	direction := " asc"
	if query.Descending() {
		direction = " desc"
	}
	if query.SortBy == "" {
		return raw("r.id"), nil
	}
	path, err := filter.NewAttrPath(query.SortBy)
	if err != nil {
		return fragment{}, scimerrors.ErrInvalidValue(`"sortBy" is not an attribute`)
	}
	parent, attribute, err := query.SortAttribute(kind.schemas)
	if err != nil {
		return fragment{}, err
	}
	if kind.reference(parent.Name) != nil || kind.derivedAttribute(parent.Name) != nil {
		return fragment{}, scimerrors.ErrInvalidValue(strconv.Quote(query.SortBy) + " is not sortable")
	}

	var value fragment
	e := newEvaluator(kind, tenant)
	common := &protocol.Attribute{Definition: attribute, Path: path}
	switch column, ok := commonColumn(common); {
	case ok && column.sql == "":
		return fragment{}, scimerrors.ErrInvalidValue(strconv.Quote(query.SortBy) + " is not sortable")
	case ok:
		value = column
	case parent.MultiValued:
		// A multi-valued attribute sorts by its primary element, else its first.
		source := e.document(filter.AttrPath{URI: path.URI, Name: path.Name}, parent, parent)
		element := raw("s.v")
		if !isElementValue(parent) {
			element = sqlf("s.v -> %s", bind(attribute.Name))
		}
		value = sqlf(`(select %s from jsonb_path_query(%s, '$[*]') with ordinality as s(v, n)
			order by coalesce((s.v -> 'primary') = 'true'::jsonb, false) desc, s.n limit 1)`,
			typed(element, attribute), source)
	default:
		value = e.document(path, parent, attribute)
	}
	// Unassigned values sort last ascending and first descending, as in
	// scim-go; ties keep id order either way.
	return sqlf("%s"+direction+", r.id", value), nil
}

package scim

import (
	"slices"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/models"
)

var generatedColumns = map[string]models.SCIMColumn{
	"id":                models.SCIMColumnID,
	"meta.created":      models.SCIMColumnCreated,
	"meta.lastModified": models.SCIMColumnLastModified,
}

type sqlFilter struct {
	schemas core.Schemas
	name    string
}

func (f sqlFilter) Compare(attribute *protocol.Attribute, op filter.Operator, value any) (models.SCIMFilter, error) {
	if value == nil {
		return models.SCIMFilter{}, invalidFilter()
	}
	term := models.SCIMFilter{Op: op, Value: value, Fold: folded(attribute.Definition)}
	if column, ok := f.column(attribute); ok {
		term.Column = column
		return term, nil
	}
	if op == filter.OpEquals {
		return f.match(attribute, term)
	}
	path, err := f.path(attribute)
	term.Path = path
	return term, err
}

func (f sqlFilter) Present(attribute *protocol.Attribute) (models.SCIMFilter, error) {
	term := models.SCIMFilter{Op: filter.OpPresent}
	if column, ok := f.column(attribute); ok {
		term.Column = column
		return term, nil
	}
	path, err := f.path(attribute)
	term.Path = path
	return term, err
}

func (f sqlFilter) And(left, right models.SCIMFilter) (models.SCIMFilter, error) {
	return models.SCIMFilter{And: append(termsOf(left, left.And), termsOf(right, right.And)...)}, nil
}

func (f sqlFilter) Or(left, right models.SCIMFilter) (models.SCIMFilter, error) {
	return models.SCIMFilter{Or: append(termsOf(left, left.Or), termsOf(right, right.Or)...)}, nil
}

func (f sqlFilter) Not(operand models.SCIMFilter) (models.SCIMFilter, error) {
	return models.SCIMFilter{Not: &operand}, nil
}

func (f sqlFilter) ValuePath(attribute *protocol.Attribute, valueFilter func() (models.SCIMFilter, error)) (models.SCIMFilter, error) {
	parent := attribute.Definition
	if slices.Contains(unstored, parent.Name) {
		return models.SCIMFilter{}, invalidFilter()
	}
	inner, err := valueFilter()
	if err != nil {
		return inner, err
	}
	terms := termsOf(inner, inner.Or)
	for i, term := range terms {
		element := map[string]any{}
		if !mergeTerm(element, term) {
			return models.SCIMFilter{}, invalidFilter()
		}
		terms[i] = models.SCIMFilter{Match: f.wrap(attribute.Path, parent, element)}
	}
	if len(terms) == 1 {
		return terms[0], nil
	}
	return models.SCIMFilter{Or: terms}, nil
}

func (f sqlFilter) match(attribute *protocol.Attribute, term models.SCIMFilter) (models.SCIMFilter, error) {
	definition, path := attribute.Definition, attribute.Path
	if definition.Type == core.TypeDateTime || (attribute.Parent != nil && !term.Fold) {
		return models.SCIMFilter{}, invalidFilter()
	}
	element := map[string]any{definition.Name: term.Value}
	if attribute.Parent != nil {
		return models.SCIMFilter{Match: element}, nil
	}
	parent := f.parent(attribute)
	if parent == nil || slices.Contains(unstored, parent.Name) {
		return models.SCIMFilter{}, invalidFilter()
	}
	match := models.SCIMFilter{Match: f.extension(path, element)}
	if parent != definition {
		match.Match = f.wrap(path, parent, element)
	}
	if term.Fold {
		return match, nil
	}
	keys, err := f.path(attribute)
	term.Path = keys
	return models.SCIMFilter{And: []models.SCIMFilter{match, term}}, err
}

func (f sqlFilter) column(attribute *protocol.Attribute) (models.SCIMColumn, bool) {
	key := f.key(attribute)
	if column, ok := generatedColumns[key]; ok {
		return column, true
	}
	switch key {
	case f.name:
		return models.SCIMColumnName, true
	case "externalId":
		return models.SCIMColumnExternalID, true
	case "active":
		return models.SCIMColumnActive, true
	}
	return 0, false
}

func (f sqlFilter) key(attribute *protocol.Attribute) string {
	parent := f.parent(attribute)
	switch {
	case attribute.Parent != nil || parent == nil || f.schemas.IsExtension(f.schemas.Lookup(core.SchemaURI(attribute.Path.URI))):
		return ""
	case parent == attribute.Definition:
		return parent.Name
	}
	return parent.Name + "." + attribute.Definition.Name
}

func (f sqlFilter) path(attribute *protocol.Attribute) ([]string, error) {
	definition, parent := attribute.Definition, f.parent(attribute)
	if attribute.Parent != nil || parent == nil || parent.MultiValued || definition.Type == core.TypeDateTime || slices.Contains(unstored, parent.Name) {
		return nil, invalidFilter()
	}
	keys := []string{parent.Name}
	if parent != definition {
		keys = append(keys, definition.Name)
	}
	if schema := f.schemas.Lookup(core.SchemaURI(attribute.Path.URI)); f.schemas.IsExtension(schema) {
		keys = append([]string{string(schema.ID)}, keys...)
	}
	return keys, nil
}

func (f sqlFilter) parent(attribute *protocol.Attribute) *core.Attribute {
	parent, _ := f.schemas.Resolve(core.SchemaURI(attribute.Path.URI), attribute.Path.Name, "")
	return parent
}

func (f sqlFilter) wrap(path filter.AttrPath, parent *core.Attribute, term map[string]any) map[string]any {
	var nested any = term
	if parent.MultiValued {
		nested = []any{term}
	}
	return f.extension(path, map[string]any{parent.Name: nested})
}

func (f sqlFilter) extension(path filter.AttrPath, term map[string]any) map[string]any {
	schema := f.schemas.Lookup(core.SchemaURI(path.URI))
	if !f.schemas.IsExtension(schema) {
		return term
	}
	return map[string]any{string(schema.ID): term}
}

func invalidFilter() error {
	return scimerrors.ErrInvalidFilter(scimerrors.InvalidFilter.Description())
}

func folded(definition *core.Attribute) bool {
	return !definition.CaseExact && definition.Type != core.TypeBinary && definition.Type != core.TypeReference
}

func termsOf(filter models.SCIMFilter, terms []models.SCIMFilter) []models.SCIMFilter {
	if len(terms) > 0 {
		return terms
	}
	return []models.SCIMFilter{filter}
}

func mergeTerm(element map[string]any, term models.SCIMFilter) bool {
	if term.Match == nil {
		return len(term.And) > 0 && !slices.ContainsFunc(term.And, func(t models.SCIMFilter) bool { return !mergeTerm(element, t) })
	}
	for key, value := range term.Match {
		if existing, ok := element[key]; ok && existing != value {
			return false
		}
		element[key] = value
	}
	return true
}

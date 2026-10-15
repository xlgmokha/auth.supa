package query

import (
	"strings"
	"unicode/utf8"

	"github.com/supabase-community/scim-go/pkg/filter"
)

// pg_trgm indexes three-character runs, so a shorter needle cannot use the index.
const minSubstringRunes = 3

var jsonEscapes = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

var likeEscapes = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// substring narrows a top-level co, sw or ew match with a LIKE on the lowercased document text, which the
// scim_resources_text_idx trigram index serves. A jsonpath like_regex cannot use any index and would
// otherwise evaluate every document in the table. Every match contains its needle in the document text, so the
// extra condition rejects only non-matches and the jsonpath still decides the rest.
func substring(clause Clause, f field, op filter.Operator, value any) Clause {
	text, ok := value.(string)
	if !ok || f.ref != nil || f.attribute.Parent != nil || utf8.RuneCountInString(text) < minSubstringRunes {
		return clause
	}
	// jsonb renders control characters as escapes that this needle does not model, so skip them.
	if strings.IndexFunc(text, func(r rune) bool { return r < ' ' || r == 0x7f }) >= 0 {
		return clause
	}
	needle := jsonEscapes.Replace(text)
	switch op {
	case filter.OpStartsWith:
		needle = `"` + needle
	case filter.OpEndsWith:
		needle += `"`
	case filter.OpContains:
	default:
		return clause
	}
	return and(predicate{"lower(resource::text) LIKE lower(?)", []any{"%" + likeEscapes.Replace(needle) + "%"}}, clause)
}

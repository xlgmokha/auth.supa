package query

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/supabase-community/scim-go/pkg/filter"
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

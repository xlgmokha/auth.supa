package scim

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/conf/confload"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage/test"
)

const (
	widgetURN          = core.SchemaURI("urn:example:params:scim:schemas:core:2.0:Widget")
	widgetExtensionURN = core.SchemaURI("urn:example:params:scim:schemas:extension:widget:2.0:Widget")
)

// widget is a test resource type with an attribute of every simple type, so
// the SQL translation is exercised beyond what User and Group declare.
type widget struct {
	core.Base
	Name      string           `json:"name,omitempty"`
	Code      string           `json:"code,omitempty"`
	Count     *int64           `json:"count,omitempty"`
	Weight    *float64         `json:"weight,omitempty"`
	Enabled   *bool            `json:"enabled,omitempty"`
	Born      string           `json:"born,omitempty"`
	Homepage  string           `json:"homepage,omitempty"`
	Blob      string           `json:"blob,omitempty"`
	Tags      []string         `json:"tags,omitempty"`
	Parts     []part           `json:"parts,omitempty"`
	Dims      *dims            `json:"dims,omitempty"`
	Extension *widgetExtension `json:"urn:example:params:scim:schemas:extension:widget:2.0:Widget,omitempty"`
}

type part struct {
	Value   string `json:"value,omitempty"`
	Size    *int64 `json:"size,omitempty"`
	Type    string `json:"type,omitempty"`
	Primary *bool  `json:"primary,omitempty"`
}

type dims struct {
	Width *int64 `json:"width,omitempty"`
	Unit  string `json:"unit,omitempty"`
}

type widgetExtension struct {
	Owner string `json:"owner,omitempty"`
	Level *int64 `json:"level,omitempty"`
}

func widgetSchemas() core.Schemas {
	return core.Schemas{
		core.NewSchema(widgetURN).WithName("Widget").With(
			core.NewAttribute("name", core.TypeString),
			core.NewAttribute("code", core.TypeString).AsCaseExact(),
			core.NewAttribute("count", core.TypeInteger),
			core.NewAttribute("weight", core.TypeDecimal),
			core.NewAttribute("enabled", core.TypeBoolean),
			core.NewAttribute("born", core.TypeDateTime),
			core.NewAttribute("homepage", core.TypeReference),
			core.NewAttribute("blob", core.TypeBinary),
			core.NewAttribute("tags", core.TypeString).AsMultiValued(),
			core.NewAttribute("parts", core.TypeComplex).AsMultiValued().With(
				core.NewAttribute("value", core.TypeString),
				core.NewAttribute("size", core.TypeInteger),
				core.NewAttribute("type", core.TypeString),
				core.NewAttribute("primary", core.TypeBoolean),
			),
			core.NewAttribute("dims", core.TypeComplex).With(
				core.NewAttribute("width", core.TypeInteger),
				core.NewAttribute("unit", core.TypeString),
			),
		),
		core.NewSchema(widgetExtensionURN).With(
			core.NewAttribute("owner", core.TypeString),
			core.NewAttribute("level", core.TypeInteger),
		),
	}
}

func i64(v int64) *int64           { return &v }
func f64(v float64) *float64       { return &v }
func boolean(v bool) *bool         { return &v }
func widgetNamed(n string) *widget { return &widget{Name: n} }

func widgets() []*widget {
	return []*widget{
		{Name: "Alpha", Code: "ABC", Count: i64(1), Weight: f64(1.5), Enabled: boolean(true), Born: "2019-06-01T10:00:00Z",
			Homepage: "https://Example.com/a", Blob: "aGVsbG8=", Tags: []string{"red", "blue"},
			Parts: []part{{Value: "axle", Size: i64(2), Type: "main"}, {Value: "bolt", Size: i64(5), Type: "spare", Primary: boolean(true)}},
			Dims:  &dims{Width: i64(10), Unit: "cm"}, Extension: &widgetExtension{Owner: "Bob", Level: i64(3)}},
		{Name: "beta", Code: "abc", Count: i64(3), Weight: f64(2.25), Enabled: boolean(false), Born: "2021-01-01T00:00:00Z",
			Homepage: "http://example.com/b", Tags: []string{"RED"},
			Parts: []part{{Value: "Cog", Size: i64(4), Type: "main", Primary: boolean(true)}},
			Dims:  &dims{Width: i64(25), Unit: "in"}},
		{Name: "Gamma", Code: "Bcd", Count: i64(5), Weight: f64(0.5), Born: "2020-01-01T00:00:00Z",
			Tags: []string{"green"}, Extension: &widgetExtension{Owner: "alice", Level: i64(1)}},
		{Name: "delta", Count: i64(3), Enabled: boolean(true), Homepage: "https://example.org/d", Blob: "d29ybGQ=",
			Parts: []part{{Value: "axle", Size: i64(1), Type: "spare"}}},
		{Name: "", Code: "xyz", Weight: f64(1.5), Tags: []string{}, Dims: &dims{Unit: "CM"}},
		{Name: "Epsilon", Code: "ab", Count: i64(-2), Enabled: boolean(false), Born: "2019-06-01T10:00:00+02:00",
			Parts:     []part{{Value: "nut"}, {Value: "washer", Size: i64(9), Primary: boolean(false)}},
			Extension: &widgetExtension{Level: i64(7)}},
		widgetNamed("zeta"),
		{Name: "ALPHA2", Code: "ABD", Count: i64(10), Weight: f64(10), Enabled: boolean(true), Tags: []string{"blue", "red"},
			Dims: &dims{Width: i64(10)}},
	}
}

var widgetFilters = []string{
	// string
	`name eq "alpha"`, `name eq "ALPHA"`, `name ne "alpha"`, `name co "LP"`, `name sw "a"`, `name ew "TA"`,
	`name eq ""`, `name sw ""`, `name gt "beta"`, `name ge "beta"`, `name lt "beta"`, `name le "beta"`, `name pr`, `name eq null`, `name ne null`,
	// caseExact string
	`code eq "ABC"`, `code eq "abc"`, `code co "b"`, `code sw "A"`, `code ew "d"`, `code gt "B"`, `code le "ab"`,
	// integer
	`count eq 3`, `count ne 3`, `count gt 2`, `count ge 3`, `count lt 1`, `count le -2`, `count pr`,
	// decimal
	`weight eq 1.5`, `weight gt 1`, `weight lt 2.25`, `weight ge 10`, `weight pr`,
	// boolean
	`enabled eq true`, `enabled eq false`, `enabled ne true`, `enabled pr`,
	// dateTime
	`born gt "2020-01-01T00:00:00Z"`, `born ge "2020-01-01T00:00:00Z"`, `born lt "2020-01-01T00:00:00Z"`,
	`born eq "2019-06-01T08:00:00Z"`, `born pr`,
	// reference: case sensitive
	`homepage eq "https://Example.com/a"`, `homepage eq "https://example.com/a"`, `homepage co "example"`, `homepage sw "https"`, `homepage pr`,
	// binary
	`blob eq "aGVsbG8="`, `blob ne "aGVsbG8="`, `blob pr`,
	// multi-valued simple
	`tags eq "red"`, `tags eq "RED"`, `tags ne "red"`, `tags co "re"`, `tags sw "b"`, `tags pr`,
	// multi-valued complex
	`parts.value eq "axle"`, `parts co "o"`, `parts.size gt 3`, `parts.size le 1`, `parts.type eq "SPARE"`,
	`parts[type eq "main" and size ge 4]`, `parts[primary eq true]`, `parts[value sw "w" or size lt 2]`,
	`parts[not (type pr)]`, `parts pr`, `parts.primary eq false`,
	// complex
	`dims.width gt 10`, `dims.width eq 10`, `dims.unit eq "cm"`, `dims pr`, `dims.unit pr`,
	// extension
	`urn:example:params:scim:schemas:extension:widget:2.0:Widget:owner eq "bob"`,
	`urn:example:params:scim:schemas:extension:widget:2.0:Widget:level gt 1`,
	`urn:example:params:scim:schemas:extension:widget:2.0:Widget:owner pr`,
	// combinations
	`name sw "a" and count gt 1`, `enabled eq true or tags eq "green"`, `not (count gt 2)`, `not (name pr)`,
	`(name sw "a" or name sw "b") and not (enabled eq false)`, `parts[type eq "main"] and not (dims pr)`,
	`count gt 0 and (weight lt 2 or born pr) and not (code eq "ABC")`,
}

var widgetSorts = []struct{ sortBy, sortOrder string }{
	{"name", ""}, {"name", "descending"}, {"code", ""}, {"code", "descending"},
	{"count", ""}, {"count", "descending"}, {"weight", ""}, {"enabled", ""}, {"enabled", "descending"},
	{"born", ""}, {"born", "descending"}, {"homepage", ""}, {"blob", ""},
	{"parts.size", ""}, {"parts.value", "descending"}, {"parts", ""}, {"dims.width", ""}, {"dims.unit", "descending"},
	{"urn:example:params:scim:schemas:extension:widget:2.0:Widget:owner", ""},
	{"urn:example:params:scim:schemas:extension:widget:2.0:Widget:level", "descending"},
}

func users() []*core.User {
	primary := boolean(true)
	return []*core.User{
		{UserName: "alice@example.com", Name: core.Name{GivenName: "Alice", FamilyName: "Smith"}, Active: boolean(true), Title: "Doctor",
			Emails:         []core.Email{{Value: "alice@home.example", Type: "home"}, {Value: "alice@example.com", Type: "work", Primary: primary}},
			EnterpriseUser: &core.EnterpriseUser{EmployeeNumber: "100", Department: "Cardiology", Manager: &core.Manager{Value: "m-1"}}},
		{UserName: "Bob@Example.com", Name: core.Name{GivenName: "Bob", FamilyName: "jones"}, Active: boolean(false),
			Emails: []core.Email{{Value: "bob@example.com", Type: "work"}}, Roles: []core.Role{{Value: "admin"}},
			EnterpriseUser: &core.EnterpriseUser{EmployeeNumber: "7", Department: "cardiology"}},
		{UserName: "carol", DisplayName: "Carol C", Active: boolean(true), Title: "Nurse",
			PhoneNumbers: []core.PhoneNumber{{Value: "+1 555 0100", Type: "mobile"}}},
		{UserName: "dave@example.org", Name: core.Name{FamilyName: "Smithers"}, Locale: "en-CA",
			Emails: []core.Email{{Value: "dave@example.org", Type: "work", Primary: primary}}, Roles: []core.Role{{Value: "Admin"}, {Value: "viewer"}}},
	}
}

var userFilters = []string{
	`userName eq "ALICE@example.com"`, `userName sw "b"`, `userName co "@example."`, `userName ew ".ORG"`, `userName gt "bob"`,
	`name.familyName co "smith"`, `name.givenName pr`, `name pr`, `displayName eq "carol c"`, `title eq "Doctor" or title eq "nurse"`,
	`emails co "example.com"`, `emails[type eq "work" and value ew "example.com"]`, `emails.type eq "home"`, `emails[primary eq true]`,
	`emails.value eq "ALICE@home.example"`, `phoneNumbers pr`, `roles eq "admin"`, `roles.value sw "a"`, `active eq false`, `not (active eq false)`,
	`locale pr`, `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber eq "7"`,
	`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "CARDIOLOGY"`,
	`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value eq "m-1"`,
	`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager pr`,
	`userName sw "a" or (emails[type eq "work"] and not (roles pr))`,
}

var userSorts = []struct{ sortBy, sortOrder string }{
	{"userName", ""}, {"userName", "descending"}, {"name.familyName", ""}, {"emails", ""}, {"emails.type", "descending"},
	{"active", ""}, {"title", "descending"}, {"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber", ""},
}

type oracleCase struct{ sortBy, sortOrder string }

// checkAgainstInMemory creates items through the SQL repository and through
// scim-go's in-memory repository, the reference evaluation of RFC 7644
// filters and sorts, and checks that every query answers alike.
func checkAgainstInMemory[T core.Resource](t *testing.T, kind *resourceType, items []T, clone func(T) T, label func(T) string, filters []string, sorts []oracleCase) {
	config, err := confload.LoadGlobal("../../../hack/test.env")
	require.NoError(t, err)
	db, err := test.SetupDBConnection(config)
	require.NoError(t, err)
	defer db.Close()
	require.NoError(t, models.TruncateAll(db))
	defer func() { require.NoError(t, models.TruncateAll(db)) }()

	provider := &models.SSOProvider{ID: uuid.Must(uuid.NewV4())}
	require.NoError(t, db.Create(provider))
	directory, err := models.EnsureSCIMDirectory(db, provider.ID)
	require.NoError(t, err)

	s := &Server{db: db, config: config, baseURL: BaseURL(config), types: map[string]*resourceType{kind.name: kind}}
	ours := &repository[T]{server: s, kind: kind}
	reference := server.NewRepository[T](kind.endpoint, kind.schemas)
	ctx := withTenant(context.Background(), &Tenant{
		DirectoryID:   directory.ID,
		SSOProviderID: provider.ID,
		TokenPrefix:   "scim_test",
		request:       httptest.NewRequest("GET", BasePath+kind.endpoint, nil),
	})
	for _, item := range items {
		item.Common().Schemas = []core.SchemaURI{kind.schemas.Base().ID}
		duplicate := clone(item)
		_, err := ours.Create(ctx, item)
		require.NoError(t, err)
		_, err = reference.Create(ctx, duplicate)
		require.NoError(t, err)
	}

	labels := func(items []T) []string {
		out := []string{}
		for _, item := range items {
			out = append(out, label(item))
		}
		return out
	}
	search := func(query *protocol.SearchRequest) {
		t.Helper()
		name := query.Filter + " sortBy=" + query.SortBy + " " + string(query.SortOrder)
		require.NoError(t, query.Validate(kind.schemas), name)
		expected, expectedTotal, err := reference.List(ctx, query)
		require.NoError(t, err, name)
		got, total, err := ours.List(ctx, query)
		require.NoError(t, err, name)
		if query.SortBy == "" {
			require.ElementsMatch(t, labels(expected), labels(got), name)
		} else {
			require.Equal(t, labels(expected), labels(got), name)
		}
		require.Equal(t, expectedTotal, total, name)
	}
	for _, filter := range filters {
		search(&protocol.SearchRequest{Filter: filter, StartIndex: 1, Count: 100})
	}
	for _, sort := range sorts {
		search(&protocol.SearchRequest{SortBy: sort.sortBy, SortOrder: protocol.SortOrder(sort.sortOrder), StartIndex: 1, Count: 100})
	}
	if len(sorts) > 0 {
		search(&protocol.SearchRequest{Filter: filters[0], SortBy: sorts[0].sortBy, StartIndex: 1, Count: 1})
		search(&protocol.SearchRequest{SortBy: sorts[0].sortBy, StartIndex: 2, Count: 2})
	}
}

func oracleCases(sorts []struct{ sortBy, sortOrder string }) []oracleCase {
	out := []oracleCase{}
	for _, sort := range sorts {
		out = append(out, oracleCase{sort.sortBy, sort.sortOrder})
	}
	return out
}

func TestSQLMatchesInMemoryForEveryAttributeType(t *testing.T) {
	kind := &resourceType{name: "Widget", endpoint: "/Widgets", schemas: widgetSchemas(), keys: []key{{attribute: "name"}}, hooks: noHooks{}}
	checkAgainstInMemory(t, kind, widgets(),
		func(w *widget) *widget { duplicate := *w; return &duplicate },
		func(w *widget) string { return w.Name },
		widgetFilters, oracleCases(widgetSorts))
}

func TestSQLMatchesInMemoryForUsers(t *testing.T) {
	kind := &resourceType{
		name:     "User",
		endpoint: "/Users",
		schemas: core.Schemas{
			core.NewSchema(core.SchemaUser).WithName("User").With(core.UserAttributes()...),
			core.NewSchema(core.SchemaEnterpriseUser).With(core.EnterpriseUserAttributes()...),
		},
		keys:  []key{{attribute: "userName", unique: true}, {attribute: "externalId", unique: true}},
		hooks: noHooks{},
	}
	checkAgainstInMemory(t, kind, users(),
		func(u *core.User) *core.User { duplicate := *u; return &duplicate },
		func(u *core.User) string { return u.UserName },
		userFilters, oracleCases(userSorts))
}

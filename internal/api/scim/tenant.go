package scim

import (
	"context"
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/utilities"
)

type credentialKey struct{}
type requestKey struct{}
type tenantKey struct{}

// WithCredential carries the usable credential the request's bearer token
// resolved to, if any, before the SCIM server decides whether its directory
// may be served.
func WithCredential(r *http.Request, credential *models.SCIMCredential) context.Context {
	ctx := context.WithValue(r.Context(), requestKey{}, r)
	if credential == nil {
		return ctx
	}
	return context.WithValue(ctx, credentialKey{}, credential)
}

func requestFrom(ctx context.Context) *http.Request {
	r, _ := ctx.Value(requestKey{}).(*http.Request)
	return r
}

func credentialFrom(ctx context.Context) *models.SCIMCredential {
	credential, _ := ctx.Value(credentialKey{}).(*models.SCIMCredential)
	return credential
}

// Tenant is the directory an authenticated SCIM request reads and writes.
type Tenant struct {
	DirectoryID   uuid.UUID
	SSOProviderID uuid.UUID
	TokenPrefix   string
	request       *http.Request
}

func withTenant(ctx context.Context, tenant *Tenant) context.Context {
	return context.WithValue(ctx, tenantKey{}, tenant)
}

func tenantFrom(ctx context.Context) *Tenant {
	tenant, _ := ctx.Value(tenantKey{}).(*Tenant)
	return tenant
}

// identityProvider is the provider of the identities the tenant's SSO
// provider signs accounts in with.
func (t *Tenant) identityProvider() string {
	return "sso:" + t.SSOProviderID.String()
}

func (t *Tenant) ipAddress() string {
	return utilities.GetIPAddress(t.request)
}

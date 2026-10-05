package api

import (
	"math"
	"net/http"
	"path"
	"strconv"

	"github.com/didip/tollbooth/v5"
	"github.com/didip/tollbooth/v5/limiter"
	"github.com/supabase/auth/internal/api/scim"
)

func (a *API) limitSCIMByIP(lmt *limiter.Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := a.extractBearerToken(r)
			skipsValidator := err != nil || r.URL.Path == scim.BasePath+"/ServiceProviderConfig" || path.Clean(r.URL.Path) != r.URL.Path
			if skipsValidator && a.performRateLimiting(lmt, r) != nil {
				handler(scimTooManyRequests(lmt))(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (a *API) limitedSCIMInvalidToken(lmt *limiter.Limiter) func(*http.Request) bool {
	return func(r *http.Request) bool {
		return a.performRateLimiting(lmt, r) != nil
	}
}

func (a *API) limitSCIMByProvider(lmt *limiter.Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if providerID, err := scim.ProviderID(r.Context()); err == nil && tollbooth.LimitByKeys(lmt, []string{providerID.String()}) != nil {
				handler(scimTooManyRequests(lmt))(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func scimTooManyRequests(lmt *limiter.Limiter) apiHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		if perSecond := lmt.GetMax(); perSecond > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(1/perSecond))))
		}
		return scim.SendTooManyRequests(w)
	}
}

package scim

import (
	"strings"

	"github.com/supabase/auth/internal/conf"
)

func BaseURL(config *conf.GlobalConfiguration) string {
	return strings.TrimRight(config.API.ExternalURL, "/") + BasePath
}

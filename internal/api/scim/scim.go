package scim

import (
	"strings"

	"github.com/supabase/auth/internal/conf"
)

const BasePath = "/scim/v2"

func BaseURL(config *conf.GlobalConfiguration) string {
	return strings.TrimRight(config.API.ExternalURL, "/") + BasePath
}

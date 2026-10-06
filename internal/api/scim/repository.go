package scim

import (
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/server"
)

func NewRepository[T core.Resource]() server.Repository[T] {
	return nil
}

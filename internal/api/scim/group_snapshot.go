package scim

import (
	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/ctxkey"
)

var groupSnapshotKey = ctxkey.New[*groupSnapshot]("scim_group_snapshot")

type groupSnapshot struct {
	version string
	members []uuid.UUID
}

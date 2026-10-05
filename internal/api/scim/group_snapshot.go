package scim

import (
	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase/auth/internal/ctxkey"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

var groupSnapshotKey = ctxkey.New[*groupSnapshot]("scim_group_snapshot")

type groupSnapshot struct {
	version string
	members []uuid.UUID
}

func (s *groupSnapshot) matches(version string) bool {
	return s != nil && version != "" && s.version == version
}

func (s *groupSnapshot) record(group *core.Group) {
	if s == nil {
		return
	}
	s.version, s.members = group.Meta.Version, make([]uuid.UUID, len(group.Members))
	for i, member := range group.Members {
		s.members[i] = uuid.FromStringOrNil(member.Value)
	}
}

func (s *groupSnapshot) replace(tx *storage.Connection, version string, row *models.SCIMGroup, members []uuid.UUID) (*models.SCIMGroup, models.SCIMGroupMemberChange, error) {
	if s.matches(version) {
		return models.ReplaceSCIMGroupMembersFrom(tx, row, s.members, members)
	}
	return models.ReplaceSCIMGroupMembers(tx, row, members)
}

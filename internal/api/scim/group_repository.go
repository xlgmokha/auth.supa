package scim

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

var groupSchemas = core.Schemas{core.NewSchema(core.SchemaGroup).With(core.GroupAttributes()...)}

type groupRepository struct {
	db     *storage.Connection
	config *conf.GlobalConfiguration
}

func (s *groupRepository) List(ctx context.Context, query *protocol.SearchRequest) ([]*core.Group, int, error) {
	providerID, err := ProviderID(ctx)
	if err != nil {
		return nil, 0, err
	}
	search, err := toQuery(query, groupSchemas, "displayName")
	if err != nil {
		return nil, 0, err
	}
	db := s.db.WithContext(ctx)
	rows, total, err := models.FindSCIMGroups(db, providerID, search)
	if err != nil {
		return nil, 0, err
	}
	groups, err := s.render(db, providerID, rows, protocol.ProjectionFrom(ctx))
	if err != nil {
		return nil, 0, err
	}
	return groups, total, nil
}

func (s *groupRepository) Read(ctx context.Context, id string) (*core.Group, error) {
	target, err := parseTarget(ctx, id, "")
	if err != nil {
		return nil, err
	}
	db := s.db.WithContext(ctx)
	row, err := models.FindSCIMGroup(db, target.ProviderID, target.ID)
	if err != nil {
		return nil, Error(err)
	}
	projection := protocol.ProjectionFrom(ctx)
	groups, err := s.render(db, target.ProviderID, []models.SCIMGroup{*row}, projection)
	if err != nil {
		return nil, err
	}
	if projection.Returns("members") {
		groupSnapshotKey.Value(ctx).record(groups[0])
	}
	return groups[0], nil
}

func (s *groupRepository) Create(ctx context.Context, group *core.Group) (*core.Group, error) {
	providerID, err := ProviderID(ctx)
	if err != nil {
		return nil, err
	}
	return s.save(ctx, group, func(tx *storage.Connection, resource []byte) (*models.SCIMGroup, models.AuditAction, error) {
		row, err := models.CreateSCIMGroup(tx, providerID, resource)
		return row, models.SCIMGroupCreatedAction, err
	})
}

func (s *groupRepository) Update(ctx context.Context, group *core.Group) (*core.Group, error) {
	target, err := parseTarget(ctx, group.ID, group.Meta.Version)
	if err != nil {
		return nil, err
	}
	merge := s.mergeable(ctx, group.Meta.Version)
	return s.save(ctx, group, func(tx *storage.Connection, resource []byte) (*models.SCIMGroup, models.AuditAction, error) {
		if merge {
			if row, err := models.LockUnchangedSCIMGroup(tx, target.ProviderID, target.ID, resource); err != nil || row != nil {
				return row, "", err
			}
		}
		row, changed, err := models.ReplaceSCIMGroupIfChanged(tx, target, resource)
		if err != nil || !changed {
			return row, "", err
		}
		return row, models.SCIMGroupUpdatedAction, nil
	})
}

func (s *groupRepository) Delete(ctx context.Context, group *core.Group) error {
	target, err := parseTarget(ctx, group.ID, group.Meta.Version)
	if err != nil {
		return err
	}
	r, err := requestFrom(ctx)
	if err != nil {
		return err
	}
	return Error(s.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		row, err := models.DeleteSCIMGroup(tx, target)
		if err != nil {
			return err
		}
		var resource struct {
			DisplayName string `json:"displayName"`
		}
		if err := json.Unmarshal(row.Resource, &resource); err != nil {
			return err
		}
		if err := models.RemoveSCIMMemberFromGroups(tx, row.ID); err != nil {
			return err
		}
		return audit(s.config, tx, r, groupEvent(r, models.SCIMGroupDeletedAction, row, resource.DisplayName))
	}))
}

func (s *groupRepository) save(ctx context.Context, group *core.Group, write func(*storage.Connection, []byte) (*models.SCIMGroup, models.AuditAction, error)) (*core.Group, error) {
	members := make([]uuid.UUID, 0, len(group.Members))
	for _, member := range group.Members {
		id, err := uuid.FromString(member.Value)
		if err != nil {
			return nil, errMemberNotFound()
		}
		members = append(members, id)
	}
	resource, err := encode(&core.Group{Base: group.Base, DisplayName: group.DisplayName})
	if err != nil {
		return nil, err
	}
	r, err := requestFrom(ctx)
	if err != nil {
		return nil, err
	}
	snapshot := groupSnapshotKey.Value(ctx)
	tracked := snapshot.matches(group.Meta.Version)
	var row *models.SCIMGroup
	var change models.SCIMGroupMemberChange
	err = s.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		var action models.AuditAction
		var terr error
		if row, action, terr = write(tx, resource); terr != nil {
			return terr
		}
		if tracked {
			row, change, terr = models.ReplaceSCIMGroupMembersFrom(tx, row, snapshot.members, members)
		} else {
			row, change, terr = models.ReplaceSCIMGroupMembers(tx, row, members)
		}
		if terr != nil {
			return terr
		}
		if action == "" && change.Changed() {
			action = models.SCIMGroupUpdatedAction
		}
		if action == "" {
			return nil
		}
		return audit(s.config, tx, r, groupEvent(r, action, row, group.DisplayName))
	})
	if err != nil {
		return nil, Error(err)
	}
	stored, err := row.Members()
	if err != nil {
		return nil, err
	}
	return s.compose(*row, stored)
}

func (s *groupRepository) mergeable(ctx context.Context, version string) bool {
	r := RequestKey.Value(ctx)
	blindPatch := r != nil && r.Method == http.MethodPatch && (r.Header.Get("If-Match") == "" || r.Header.Get("If-Match") == "*")
	return blindPatch && groupSnapshotKey.Value(ctx).matches(version)
}

func (s *groupRepository) render(tx *storage.Connection, providerID uuid.UUID, rows []models.SCIMGroup, projection protocol.Projection) ([]*core.Group, error) {
	members, err := s.members(tx, providerID, rows, projection)
	if err != nil {
		return nil, err
	}
	groups := make([]*core.Group, 0, len(rows))
	for _, row := range rows {
		group, err := s.compose(row, members[row.ID])
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func (s *groupRepository) members(tx *storage.Connection, providerID uuid.UUID, rows []models.SCIMGroup, projection protocol.Projection) (map[uuid.UUID][]models.SCIMGroupMembership, error) {
	members := map[uuid.UUID][]models.SCIMGroupMembership{}
	if !projection.Returns("members") {
		return members, nil
	}
	ids := make([]uuid.UUID, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	memberships, err := models.FindSCIMMembershipsByGroup(tx, providerID, ids)
	if err != nil {
		return nil, err
	}
	for _, m := range memberships {
		members[m.GroupID] = append(members[m.GroupID], m)
	}
	return members, nil
}

func (s *groupRepository) compose(row models.SCIMGroup, members []models.SCIMGroupMembership) (*core.Group, error) {
	base := BaseURL(s.config)
	group := &core.Group{}
	if err := json.Unmarshal(row.Resource, group); err != nil {
		return nil, err
	}
	group.ID = row.ID.String()
	group.Meta = core.Meta{
		ResourceType: resourceTypeGroup,
		Created:      row.CreatedAt.UTC(),
		LastModified: row.UpdatedAt.UTC(),
		Location:     base + "/Groups/" + group.ID,
		Version:      versionOf(row.UpdatedAt),
	}
	group.Schemas = []core.SchemaURI{core.SchemaGroup}
	group.Members = make([]core.Member, len(members))
	for i, member := range members {
		id := member.SCIMUserID.String()
		group.Members[i] = core.Member{Value: id, Ref: base + "/" + member.Type + "s/" + id, Type: core.ResourceTypeName(member.Type)}
	}
	return group, nil
}

func groupEvent(r *http.Request, action models.AuditAction, row *models.SCIMGroup, displayName string) auditEvent {
	traits := map[string]any{"scim_group_id": row.ID, "display_name": displayName}
	return auditEvent{Actor: actorFrom(r), Action: action, ProviderID: row.SSOProviderID, Traits: traits}
}

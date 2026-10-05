package scim

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/badoux/checkmail"
	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

var userSchemas = core.Schemas{
	core.NewSchema(core.SchemaUser).With(core.UserAttributes()...),
	core.NewSchema(core.SchemaEnterpriseUser).With(core.EnterpriseUserAttributes()...),
}

type UserRepository struct {
	db     *storage.Connection
	config *conf.GlobalConfiguration
	events UserEvents
}

func NewUserRepository(db *storage.Connection, config *conf.GlobalConfiguration, events UserEvents) *UserRepository {
	return &UserRepository{db: db, config: config, events: events}
}

func (s *UserRepository) List(ctx context.Context, query *protocol.SearchRequest) ([]*core.User, int, error) {
	providerID, err := ProviderID(ctx)
	if err != nil {
		return nil, 0, err
	}
	search, err := toQuery(query, userSchemas, "userName")
	if err != nil {
		return nil, 0, err
	}
	db := s.db.WithContext(ctx)
	rows, total, err := models.FindSCIMUsers(db, providerID, search)
	if err != nil {
		return nil, 0, err
	}
	users, err := s.render(db, providerID, rows, protocol.ProjectionFrom(ctx))
	if err != nil {
		return nil, 0, err
	}
	return users, total, nil
}

func (s *UserRepository) Read(ctx context.Context, id string) (*core.User, error) {
	target, err := parseTarget(ctx, id, "")
	if err != nil {
		return nil, err
	}
	db := s.db.WithContext(ctx)
	row, err := models.FindSCIMUser(db, target.ProviderID, target.ID)
	if err != nil {
		return nil, Error(err)
	}
	users, err := s.render(db, target.ProviderID, []models.SCIMUser{*row}, protocol.ProjectionFrom(ctx))
	if err != nil {
		return nil, err
	}
	return users[0], nil
}

func (s *UserRepository) Create(ctx context.Context, user *core.User) (*core.User, error) {
	providerID, err := ProviderID(ctx)
	if err != nil {
		return nil, err
	}
	resource, err := encodeUser(user)
	if err != nil {
		return nil, err
	}
	r, err := requestFrom(ctx)
	if err != nil {
		return nil, err
	}
	db := s.db.WithContext(ctx)
	if err := s.beforeProvision(r, db, providerID, user); err != nil {
		return nil, err
	}
	return s.save(db, r, providerID, func(tx *storage.Connection) (*models.SCIMUser, *models.User, models.AuditAction, error) {
		row, err := models.CreateSCIMUser(tx, providerID, resource)
		if err != nil {
			return nil, nil, "", err
		}
		created, err := s.events.UserProvisioned(tx, row, newProfile(user))
		return row, created, models.SCIMUserCreatedAction, err
	})
}

func (s *UserRepository) Update(ctx context.Context, user *core.User) (*core.User, error) {
	target, err := parseTarget(ctx, user.ID, user.Meta.Version)
	if err != nil {
		return nil, err
	}
	resource, err := encodeUser(user)
	if err != nil {
		return nil, err
	}
	r, err := requestFrom(ctx)
	if err != nil {
		return nil, err
	}
	db := s.db.WithContext(ctx)
	existing, err := models.FindSCIMUser(db, target.ProviderID, target.ID)
	if err != nil {
		return nil, Error(err)
	}
	linked, err := models.FindSCIMLinkedUser(db, existing)
	if err != nil {
		return nil, Error(err)
	}
	if linked == nil {
		if err := s.beforeProvision(r, db, target.ProviderID, user); err != nil {
			return nil, err
		}
	}
	return s.save(db, r, target.ProviderID, func(tx *storage.Connection) (*models.SCIMUser, *models.User, models.AuditAction, error) {
		if linked == nil {
			row, err := models.ReplaceSCIMUser(tx, target, resource)
			if err != nil {
				return nil, nil, "", err
			}
			created, err := s.events.UserProvisioned(tx, row, newProfile(user))
			return row, created, models.SCIMUserUpdatedAction, err
		}
		row, changed, err := models.ReplaceSCIMUserIfChanged(tx, target, resource)
		if err != nil || !changed {
			return row, nil, "", err
		}
		return row, nil, models.SCIMUserUpdatedAction, s.events.UserUpdated(tx, r, UserUpdate{Old: existing, Row: row, Profile: newProfile(user)})
	})
}

func (s *UserRepository) Delete(ctx context.Context, user *core.User) error {
	target, err := parseTarget(ctx, user.ID, user.Meta.Version)
	if err != nil {
		return err
	}
	r, err := requestFrom(ctx)
	if err != nil {
		return err
	}
	return Error(s.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		row, err := models.DeleteSCIMUser(tx, target)
		if err != nil {
			return err
		}
		if err := s.events.UserDeleted(tx, row); err != nil {
			return err
		}
		if err := models.RemoveSCIMMemberFromGroups(tx, row.ID); err != nil {
			return err
		}
		event, err := userEvent(tx, r, models.SCIMUserDeletedAction, row)
		if err != nil {
			return err
		}
		return audit(s.config, tx, r, event)
	}))
}

func (s *UserRepository) save(db *storage.Connection, r *http.Request, providerID uuid.UUID, write func(*storage.Connection) (*models.SCIMUser, *models.User, models.AuditAction, error)) (*core.User, error) {
	var saved *core.User
	var created *models.User
	err := db.Transaction(func(tx *storage.Connection) error {
		row, user, action, terr := write(tx)
		if terr != nil {
			return terr
		}
		created = user
		if action != "" {
			event, terr := userEvent(tx, r, action, row)
			if terr != nil {
				return terr
			}
			if terr = audit(s.config, tx, r, event); terr != nil {
				return terr
			}
		}
		users, terr := s.render(tx, providerID, []models.SCIMUser{*row}, protocol.Projection{})
		if terr != nil {
			return terr
		}
		saved = users[0]
		return nil
	})
	if err != nil {
		return nil, Error(err)
	}
	s.events.AfterUserProvisioned(r, db, created)
	return saved, nil
}

func (s *UserRepository) render(tx *storage.Connection, providerID uuid.UUID, rows []models.SCIMUser, projection protocol.Projection) ([]*core.User, error) {
	base := BaseURL(s.config)
	groups := map[uuid.UUID][]core.GroupMembership{}
	if projection.Returns("groups") {
		ids := make([]uuid.UUID, len(rows))
		for i, row := range rows {
			ids[i] = row.ID
		}
		memberships, err := models.FindSCIMMembershipsByUser(tx, providerID, ids)
		if err != nil {
			return nil, err
		}
		for _, m := range memberships {
			id := m.GroupID.String()
			groups[m.SCIMUserID] = append(groups[m.SCIMUserID], core.GroupMembership{
				Value:   id,
				Ref:     base + "/Groups/" + id,
				Display: m.Display,
				Type:    m.Type,
			})
		}
	}
	users := make([]*core.User, 0, len(rows))
	for _, row := range rows {
		user := &core.User{}
		if err := json.Unmarshal(row.Resource, user); err != nil {
			return nil, err
		}
		user.ID = row.ID.String()
		user.Meta = core.Meta{
			ResourceType: resourceTypeUser,
			Created:      row.CreatedAt.UTC(),
			LastModified: row.UpdatedAt.UTC(),
			Location:     base + "/Users/" + user.ID,
			Version:      versionOf(row.UpdatedAt),
		}
		active := row.Active()
		user.Active = &active
		user.Schemas = []core.SchemaURI{core.SchemaUser}
		if user.EnterpriseUser != nil {
			user.Schemas = append(user.Schemas, core.SchemaEnterpriseUser)
		}
		user.Groups = groups[row.ID]
		users = append(users, user)
	}
	return users, nil
}

func (s *UserRepository) beforeProvision(r *http.Request, db *storage.Connection, providerID uuid.UUID, user *core.User) error {
	if userEmail(user) == "" {
		return scimerrors.ErrInvalidValue(`"emails" or an email address "userName" is required`)
	}
	return s.events.BeforeUserProvisioned(r, db, providerID, newProfile(user))
}

func encodeUser(user *core.User) ([]byte, error) {
	resource, err := encode(user)
	if err != nil {
		return nil, err
	}
	if email := primaryEmail(user.Emails); email != "" && !isEmailAddress(email) {
		return nil, scimerrors.ErrInvalidValue(`"emails" value must be an email address`)
	}
	return resource, nil
}

func userEmail(user *core.User) string {
	if email := primaryEmail(user.Emails); email != "" {
		return email
	}
	if isEmailAddress(user.UserName) {
		return user.UserName
	}
	return ""
}

func isEmailAddress(value string) bool {
	return len(value) <= 255 && checkmail.ValidateFormat(value) == nil
}

func primaryEmail(emails []core.Email) string {
	for _, email := range emails {
		if email.Primary != nil && *email.Primary {
			return email.Value
		}
	}
	if len(emails) > 0 {
		return emails[0].Value
	}
	return ""
}

func userEvent(tx *storage.Connection, r *http.Request, action models.AuditAction, row *models.SCIMUser) (auditEvent, error) {
	linked, err := models.FindSCIMLinkedUser(tx, row)
	if err != nil {
		return auditEvent{}, err
	}
	var userID *uuid.UUID
	if linked != nil {
		userID = &linked.ID
	}
	return auditEvent{Actor: actorFrom(r), Action: action, ProviderID: row.SSOProviderID, Traits: userTraits(row, userID)}, nil
}

func userTraits(row *models.SCIMUser, userID *uuid.UUID) map[string]any {
	traits := map[string]any{
		"scim_user_id": row.ID,
		"user_name":    row.UserName(),
		"active":       row.Active(),
	}
	if userID != nil {
		traits["user_id"] = *userID
	}
	return traits
}

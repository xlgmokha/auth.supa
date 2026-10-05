package models

import (
	"database/sql"
	"time"

	"github.com/gofrs/uuid"
	pkgerrors "github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

// SCIMResource is one provisioned SCIM resource of any resource type. The
// document holds every attribute except id and meta, which are columns, and
// attributes backed by references.
type SCIMResource struct {
	ID           uuid.UUID  `db:"id"`
	DirectoryID  uuid.UUID  `db:"directory_id"`
	ResourceType string     `db:"resource_type"`
	UserID       *uuid.UUID `db:"user_id"`
	Version      int64      `db:"version"`
	Resource     JSONMap    `db:"resource"`
	CreatedAt    time.Time  `db:"created_at"`
	UpdatedAt    time.Time  `db:"updated_at"`
	DeletedAt    *time.Time `db:"deleted_at"`
}

func (SCIMResource) TableName() string {
	return "scim_resources"
}

// SCIMResourceNotFoundError is returned for a resource that does not exist,
// is tombstoned, or belongs to another directory.
type SCIMResourceNotFoundError struct{}

func (e SCIMResourceNotFoundError) Error() string {
	return "SCIM resource not found"
}

func (e SCIMResourceNotFoundError) Is(target error) bool {
	return target == errNotFound
}

// SCIMUniquenessError is returned when a write would give a directory two
// live resources with the same unique attribute value or the same account.
type SCIMUniquenessError struct {
	Attribute string
}

func (e SCIMUniquenessError) Error() string {
	return "SCIM resource " + e.Attribute + " is not unique"
}

func (e SCIMUniquenessError) Is(target error) bool {
	return target == errUniqueConstraintViolated
}

// SCIMResourceKey is a normalised attribute value that must be unique within
// a directory and resource type, or that is looked up and sorted by index.
type SCIMResourceKey struct {
	Attribute string
	Value     string
	Unique    bool
}

// SCIMReference is a directed reference from one resource to another, named
// by the referencing attribute. Queries fill in the type of the end they do
// not start from.
type SCIMReference struct {
	SourceID   uuid.UUID `db:"source_id"`
	SourceType string    `db:"source_type"`
	Attribute  string    `db:"attribute"`
	TargetID   uuid.UUID `db:"target_id"`
	TargetType string    `db:"target_type"`
}

// SCIMAncestor is a resource that references another directly (Depth 1) or
// through a chain of references (Depth > 1).
type SCIMAncestor struct {
	TargetID uuid.UUID `db:"target_id"`
	SourceID uuid.UUID `db:"source_id"`
	Depth    int       `db:"depth"`
}

// NewSCIMResource returns an unsaved resource with a time-ordered id.
func NewSCIMResource(directoryID uuid.UUID, resourceType string, document map[string]any) *SCIMResource {
	return &SCIMResource{
		ID:           uuid.Must(uuid.NewV7()),
		DirectoryID:  directoryID,
		ResourceType: resourceType,
		Version:      1,
		Resource:     document,
	}
}

// Insert stores a new resource.
func (r *SCIMResource) Insert(tx *storage.Connection) error {
	err := tx.RawQuery(
		`insert into scim_resources (id, directory_id, resource_type, user_id, resource)
		values (?, ?, ?, ?, ?) returning *`,
		r.ID, r.DirectoryID, r.ResourceType, r.UserID, r.Resource,
	).First(r)
	return pkgerrors.Wrap(err, "error creating SCIM resource")
}

// Save writes the document and bumps the version.
func (r *SCIMResource) Save(tx *storage.Connection) error {
	err := tx.RawQuery(
		`update scim_resources set resource = ?, version = version + 1, updated_at = now()
		where id = ? returning *`,
		r.Resource, r.ID,
	).First(r)
	return pkgerrors.Wrap(err, "error updating SCIM resource")
}

// SetUserID links the resource to the account it provisions. An account has
// at most one live resource per directory.
func (r *SCIMResource) SetUserID(tx *storage.Connection, userID uuid.UUID) error {
	err := tx.RawQuery(
		"update scim_resources set user_id = ? where id = ? returning *", userID, r.ID,
	).First(r)
	if isUniqueViolation(err) {
		return SCIMUniquenessError{Attribute: "account"}
	}
	return pkgerrors.Wrap(err, "error linking SCIM resource")
}

// Touch bumps the version of a resource whose references changed.
func (r *SCIMResource) Touch(tx *storage.Connection) error {
	err := tx.RawQuery(
		"update scim_resources set version = version + 1, updated_at = now() where id = ? returning *", r.ID,
	).First(r)
	return pkgerrors.Wrap(err, "error updating SCIM resource")
}

// Tombstone soft-deletes the resource. Its keys and references are removed so
// its unique values can be provisioned again; the row stays for support. It
// returns the references other resources made to it, with their source type.
func (r *SCIMResource) Tombstone(tx *storage.Connection) ([]SCIMReference, error) {
	if err := tx.RawQuery(
		"update scim_resources set deleted_at = now(), updated_at = now() where id = ? returning *", r.ID,
	).First(r); err != nil {
		return nil, pkgerrors.Wrap(err, "error deleting SCIM resource")
	}
	if err := tx.RawQuery("delete from scim_resource_keys where resource_id = ?", r.ID).Exec(); err != nil {
		return nil, pkgerrors.Wrap(err, "error deleting SCIM resource keys")
	}
	references := []SCIMReference{}
	if err := tx.RawQuery(
		`with removed as (
			delete from scim_resource_references where source_id = ? or target_id = ?
			returning source_id, attribute, target_id
		)
		select d.source_id, s.resource_type as source_type, d.attribute, d.target_id
		from removed d join scim_resources s on s.id = d.source_id
		where d.target_id = ?`,
		r.ID, r.ID, r.ID,
	).All(&references); err != nil {
		return nil, pkgerrors.Wrap(err, "error deleting SCIM resource references")
	}
	return references, nil
}

// FindSCIMResource returns a live resource of the type in the directory,
// optionally locking it for update.
func FindSCIMResource(tx *storage.Connection, directoryID uuid.UUID, resourceType string, id uuid.UUID, forUpdate bool) (*SCIMResource, error) {
	query := `select * from scim_resources
		where directory_id = ? and resource_type = ? and id = ? and deleted_at is null`
	if forUpdate {
		query += " for update"
	}
	var resource SCIMResource
	if err := tx.RawQuery(query, directoryID, resourceType, id).First(&resource); err != nil {
		if pkgerrors.Cause(err) == sql.ErrNoRows {
			return nil, SCIMResourceNotFoundError{}
		}
		return nil, pkgerrors.Wrap(err, "error finding SCIM resource")
	}
	return &resource, nil
}

// FindSCIMResourcesByID returns the live resources of the directory among ids,
// of any type.
func FindSCIMResourcesByID(tx *storage.Connection, directoryID uuid.UUID, ids []uuid.UUID) ([]*SCIMResource, error) {
	resources := []*SCIMResource{}
	if len(ids) == 0 {
		return resources, nil
	}
	if err := tx.RawQuery(
		"select * from scim_resources where directory_id = ? and id = any(?::uuid[]) and deleted_at is null order by id",
		directoryID, uuidStrings(ids),
	).All(&resources); err != nil {
		return nil, pkgerrors.Wrap(err, "error finding SCIM resources")
	}
	return resources, nil
}

// LockSCIMResourceTypes returns the type of each live resource of the
// directory among ids, locking them so none can be deleted before the
// transaction ends.
func LockSCIMResourceTypes(tx *storage.Connection, directoryID uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]string, error) {
	types := map[uuid.UUID]string{}
	if len(ids) == 0 {
		return types, nil
	}
	rows := []struct {
		ID           uuid.UUID `db:"id"`
		ResourceType string    `db:"resource_type"`
	}{}
	if err := tx.RawQuery(
		`select id, resource_type from scim_resources
		where directory_id = ? and id = any(?::uuid[]) and deleted_at is null order by id for share`,
		directoryID, uuidStrings(ids),
	).All(&rows); err != nil {
		return nil, pkgerrors.Wrap(err, "error locking SCIM resources")
	}
	for _, row := range rows {
		types[row.ID] = row.ResourceType
	}
	return types, nil
}

// AnySCIMResourceOfType reports whether any of ids is a live resource of the
// type in the directory.
func AnySCIMResourceOfType(tx *storage.Connection, directoryID uuid.UUID, resourceType string, ids []uuid.UUID) (bool, error) {
	if len(ids) == 0 {
		return false, nil
	}
	var found bool
	if err := tx.RawQuery(
		`select exists (select 1 from scim_resources
		where directory_id = ? and resource_type = ? and id = any(?::uuid[]) and deleted_at is null)`,
		directoryID, resourceType, uuidStrings(ids),
	).First(&found); err != nil {
		return false, pkgerrors.Wrap(err, "error finding SCIM resources")
	}
	return found, nil
}

type scimResourceRow struct {
	SCIMResource
	Total int `db:"total"`
}

// ListSCIMResources returns the live resources of the type in the directory
// matching where, ordered by orderBy. where and orderBy are SQL over the
// scim_resources alias r; their values are bound through args.
func ListSCIMResources(tx *storage.Connection, directoryID uuid.UUID, resourceType, where string, whereArgs []any, orderBy string, orderArgs []any, offset, limit int) ([]*SCIMResource, int, error) {
	from := " from scim_resources r where r.directory_id = ? and r.resource_type = ? and r.deleted_at is null"
	filterArgs := append([]any{directoryID, resourceType}, whereArgs...)
	if where != "" {
		from += " and (" + where + ")"
	}

	resources := []*SCIMResource{}
	count := func() ([]*SCIMResource, int, error) {
		var total int
		if err := tx.RawQuery("select count(*)"+from, filterArgs...).First(&total); err != nil {
			return nil, 0, pkgerrors.Wrap(err, "error counting SCIM resources")
		}
		return resources, total, nil
	}
	if limit == 0 {
		return count()
	}

	rows := []scimResourceRow{}
	query := "select r.*, count(*) over () as total" + from + " order by " + orderBy + " limit ? offset ?"
	args := append(append(append([]any{}, filterArgs...), orderArgs...), limit, offset)
	if err := tx.RawQuery(query, args...).All(&rows); err != nil {
		return nil, 0, pkgerrors.Wrap(err, "error listing SCIM resources")
	}
	if len(rows) == 0 && offset > 0 {
		// A page past the last row carries no window count.
		return count()
	}
	total := 0
	for i := range rows {
		resources = append(resources, &rows[i].SCIMResource)
		total = rows[i].Total
	}
	return resources, total, nil
}

// ReplaceKeys makes keys the resource's complete set of keys.
func (r *SCIMResource) ReplaceKeys(tx *storage.Connection, keys []SCIMResourceKey) error {
	if err := tx.RawQuery("delete from scim_resource_keys where resource_id = ?", r.ID).Exec(); err != nil {
		return pkgerrors.Wrap(err, "error replacing SCIM resource keys")
	}
	for _, key := range keys {
		err := tx.RawQuery(
			`insert into scim_resource_keys (directory_id, resource_type, attribute, value, resource_id, is_unique)
			values (?, ?, ?, ?, ?, ?)
			on conflict (directory_id, resource_type, attribute, value, resource_id) do nothing`,
			r.DirectoryID, r.ResourceType, key.Attribute, key.Value, r.ID, key.Unique,
		).Exec()
		if isUniqueViolation(err) {
			return SCIMUniquenessError{Attribute: key.Attribute}
		}
		if err != nil {
			return pkgerrors.Wrap(err, "error replacing SCIM resource keys")
		}
	}
	return nil
}

// AddReferences references targets from the resource through attribute and
// returns the targets that were not referenced already.
func (r *SCIMResource) AddReferences(tx *storage.Connection, attribute string, targets []uuid.UUID) ([]uuid.UUID, error) {
	added := []uuid.UUID{}
	if len(targets) == 0 {
		return added, nil
	}
	if err := tx.RawQuery(
		`insert into scim_resource_references (directory_id, source_id, attribute, target_id)
		select ?, ?, ?, t from unnest(?::uuid[]) as t
		on conflict do nothing returning target_id`,
		r.DirectoryID, r.ID, attribute, uuidStrings(targets),
	).All(&added); err != nil {
		return nil, pkgerrors.Wrap(err, "error adding SCIM resource references")
	}
	return added, nil
}

// RemoveReferences removes references to targets from the resource through
// attribute and returns the targets that were referenced.
func (r *SCIMResource) RemoveReferences(tx *storage.Connection, attribute string, targets []uuid.UUID) ([]uuid.UUID, error) {
	removed := []uuid.UUID{}
	if len(targets) == 0 {
		return removed, nil
	}
	if err := tx.RawQuery(
		`delete from scim_resource_references
		where source_id = ? and attribute = ? and target_id = any(?::uuid[]) returning target_id`,
		r.ID, attribute, uuidStrings(targets),
	).All(&removed); err != nil {
		return nil, pkgerrors.Wrap(err, "error removing SCIM resource references")
	}
	return removed, nil
}

// ReferencedIDs returns the ids the resource references through
// attribute.
func (r *SCIMResource) ReferencedIDs(tx *storage.Connection, attribute string) ([]uuid.UUID, error) {
	ids := []uuid.UUID{}
	if err := tx.RawQuery(
		"select target_id from scim_resource_references where source_id = ? and attribute = ?", r.ID, attribute,
	).All(&ids); err != nil {
		return nil, pkgerrors.Wrap(err, "error finding SCIM resource references")
	}
	return ids, nil
}

// FindSCIMReferenceTargets returns the references made through attribute by
// any of sources.
func FindSCIMReferenceTargets(tx *storage.Connection, sources []uuid.UUID, attribute string) ([]SCIMReference, error) {
	references := []SCIMReference{}
	if len(sources) == 0 {
		return references, nil
	}
	if err := tx.RawQuery(
		`select r.source_id, r.attribute, r.target_id, t.resource_type as target_type
		from scim_resource_references r join scim_resources t on t.id = r.target_id
		where r.source_id = any(?::uuid[]) and r.attribute = ? order by r.source_id, r.target_id`,
		uuidStrings(sources), attribute,
	).All(&references); err != nil {
		return nil, pkgerrors.Wrap(err, "error finding SCIM resource references")
	}
	return references, nil
}

// FindSCIMAncestors returns, for each of targets, every resource that
// references it through attribute directly or transitively, with the length
// of the shortest chain.
func FindSCIMAncestors(tx *storage.Connection, targets []uuid.UUID, attribute string) ([]SCIMAncestor, error) {
	ancestors := []SCIMAncestor{}
	if len(targets) == 0 {
		return ancestors, nil
	}
	if err := tx.RawQuery(
		`with recursive chain (target_id, source_id, depth) as (
			select target_id, source_id, 1 from scim_resource_references
			where target_id = any(?::uuid[]) and attribute = ?
			union
			select c.target_id, r.source_id, c.depth + 1 from chain c
			join scim_resource_references r on r.target_id = c.source_id and r.attribute = ?
			where c.depth < 64
		)
		select target_id, source_id, min(depth) as depth from chain
		group by target_id, source_id order by target_id, depth, source_id`,
		uuidStrings(targets), attribute, attribute,
	).All(&ancestors); err != nil {
		return nil, pkgerrors.Wrap(err, "error finding SCIM resource ancestors")
	}
	return ancestors, nil
}

func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

func isUniqueViolation(err error) bool {
	pgErr := utilities.NewPostgresError(err)
	return pgErr != nil && pgErr.IsUniqueConstraintViolated()
}

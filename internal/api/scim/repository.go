package scim

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

// resourceType describes how one SCIM resource type maps onto the generic
// resource storage. Adding a resource type never changes the schema.
type resourceType struct {
	name       string
	endpoint   string
	schemas    core.Schemas
	keys       []key
	references []reference
	derived    []derived
	hooks      hooks
}

// key is a top-level attribute whose normalised value is indexed, and
// optionally unique, within a directory.
type key struct {
	attribute string
	unique    bool
}

// reference is a multi-valued attribute whose values are ids of other
// resources in the same directory, stored as references rather than in the
// document.
type reference struct {
	attribute string
	targets   []string
	added     models.AuditAction
	removed   models.AuditAction
}

// derived is a read-only attribute computed from the resources that reference
// this one through via, directly or transitively.
type derived struct {
	attribute string
	via       string
	display   string
}

// hooks lets a resource type keep other records in step with its resources.
type hooks interface {
	afterCreate(tx *storage.Connection, tenant *Tenant, row *models.SCIMResource) error
	afterUpdate(tx *storage.Connection, tenant *Tenant, before, after *models.SCIMResource) error
	afterDelete(tx *storage.Connection, tenant *Tenant, row *models.SCIMResource) error
}

type noHooks struct{}

func (noHooks) afterCreate(*storage.Connection, *Tenant, *models.SCIMResource) error { return nil }
func (noHooks) afterUpdate(*storage.Connection, *Tenant, *models.SCIMResource, *models.SCIMResource) error {
	return nil
}
func (noHooks) afterDelete(*storage.Connection, *Tenant, *models.SCIMResource) error { return nil }

func (t *resourceType) attribute(name string) *core.Attribute {
	attribute, _ := t.schemas.Resolve("", name, "")
	return attribute
}

func (t *resourceType) reference(attribute string) *reference {
	for i := range t.references {
		if strings.EqualFold(t.references[i].attribute, attribute) {
			return &t.references[i]
		}
	}
	return nil
}

func (t *resourceType) derivedAttribute(attribute string) *derived {
	for i := range t.derived {
		if strings.EqualFold(t.derived[i].attribute, attribute) {
			return &t.derived[i]
		}
	}
	return nil
}

func (t *resourceType) key(attribute string) *key {
	for i := range t.keys {
		if strings.EqualFold(t.keys[i].attribute, attribute) {
			return &t.keys[i]
		}
	}
	return nil
}

// repository stores resources of one type for the directory of the request.
type repository[T core.Resource] struct {
	server *Server
	kind   *resourceType
}

func (r *repository[T]) Read(ctx context.Context, id string) (T, error) {
	var zero T
	tenant, err := requireTenant(ctx)
	if err != nil {
		return zero, err
	}
	db := r.server.db.WithContext(ctx)
	row, err := r.find(db, tenant, id, false)
	if err != nil {
		return zero, err
	}
	items, err := r.present(ctx, db, tenant, []*models.SCIMResource{row})
	if err != nil {
		return zero, err
	}
	return items[0], nil
}

func (r *repository[T]) List(ctx context.Context, query *protocol.SearchRequest) ([]T, int, error) {
	tenant, err := requireTenant(ctx)
	if err != nil {
		return nil, 0, err
	}
	where := fragment{}
	if query.Filter != "" {
		where, err = protocol.Filter(r.kind.schemas, query.Filter, newEvaluator(r.kind, tenant))
		if err != nil {
			return nil, 0, err
		}
	}
	order, err := orderBy(r.kind, tenant, query)
	if err != nil {
		return nil, 0, err
	}

	db := r.server.db.WithContext(ctx)
	page, err := models.ListSCIMResources(db, tenant.DirectoryID, r.kind.name, where.sql, where.args, order.sql, order.args, query.Offset(), query.Count)
	if err != nil {
		return nil, 0, err
	}
	items, err := r.present(ctx, db, tenant, page.Resources)
	if err != nil {
		return nil, 0, err
	}
	return items, page.Total, nil
}

func (r *repository[T]) Create(ctx context.Context, item T) (T, error) {
	var created T
	tenant, err := requireTenant(ctx)
	if err != nil {
		return created, err
	}
	document, wanted, err := r.encode(item)
	if err != nil {
		return created, err
	}
	err = r.server.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		row := models.NewSCIMResource(tenant.DirectoryID, r.kind.name, document)
		if err := row.Insert(tx); err != nil {
			return err
		}
		// Keys go in before anything else is written for the resource, so
		// concurrent creates of the same unique value serialise here.
		if err := row.ReplaceKeys(tx, r.keysOf(document)); err != nil {
			return err
		}
		if err := r.kind.hooks.afterCreate(tx, tenant, row); err != nil {
			return err
		}
		if _, err := r.server.syncReferences(tx, tenant, r.kind, row, wanted, nil); err != nil {
			return err
		}
		if err := r.server.audit(tx, tenant, models.SCIMResourceAction(r.kind.name, "created"), resourceTraits(row)); err != nil {
			return err
		}
		items, err := r.present(ctx, tx, tenant, []*models.SCIMResource{row})
		if err != nil {
			return err
		}
		created = items[0]
		return nil
	})
	return created, scimError(err)
}

func (r *repository[T]) Update(ctx context.Context, item T) (T, error) {
	var updated T
	tenant, err := requireTenant(ctx)
	if err != nil {
		return updated, err
	}
	document, wanted, err := r.encode(item)
	if err != nil {
		return updated, err
	}
	common := item.Common()
	err = r.server.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		if err := r.server.lockNesting(tx, tenant, r.kind, wanted); err != nil {
			return err
		}
		row, err := r.find(tx, tenant, common.ID, true)
		if err != nil {
			return err
		}
		if common.Meta.Version != "" && common.Meta.Version != etag(row.Version) {
			return scimerrors.ErrPreconditionFailed("resource has changed on the server")
		}
		before := *row
		current, err := r.server.currentReferences(tx, r.kind, row)
		if err != nil {
			return err
		}

		row.Resource = models.JSONMap(document)
		if err := row.Save(tx); err != nil {
			return err
		}
		if err := row.ReplaceKeys(tx, r.keysOf(document)); err != nil {
			return err
		}
		if _, err := r.server.syncReferences(tx, tenant, r.kind, row, wanted, current); err != nil {
			return err
		}
		if err := r.kind.hooks.afterUpdate(tx, tenant, &before, row); err != nil {
			return err
		}
		if err := r.server.audit(tx, tenant, models.SCIMResourceAction(r.kind.name, "updated"), resourceTraits(row)); err != nil {
			return err
		}
		items, err := r.present(ctx, tx, tenant, []*models.SCIMResource{row})
		if err != nil {
			return err
		}
		updated = items[0]
		return nil
	})
	return updated, scimError(err)
}

func (r *repository[T]) Delete(ctx context.Context, item T) error {
	tenant, err := requireTenant(ctx)
	if err != nil {
		return err
	}
	common := item.Common()
	err = r.server.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		row, err := r.find(tx, tenant, common.ID, true)
		if err != nil {
			return err
		}
		if common.Meta.Version != "" && common.Meta.Version != etag(row.Version) {
			return scimerrors.ErrPreconditionFailed("resource has changed on the server")
		}
		removed, err := row.Tombstone(tx)
		if err != nil {
			return err
		}
		if err := r.kind.hooks.afterDelete(tx, tenant, row); err != nil {
			return err
		}
		if err := r.server.audit(tx, tenant, models.SCIMResourceAction(r.kind.name, "deleted"), resourceTraits(row)); err != nil {
			return err
		}
		// Losing a member is a membership change of the referencing resource.
		for _, ref := range removed {
			if ref.TargetID != row.ID {
				continue
			}
			if err := r.server.auditReferenceChange(tx, tenant, ref.SourceID, ref.Attribute, row.ID, false); err != nil {
				return err
			}
		}
		return nil
	})
	return scimError(err)
}

func (r *repository[T]) find(tx *storage.Connection, tenant *Tenant, id string, forUpdate bool) (*models.SCIMResource, error) {
	resourceID, err := uuid.FromString(id)
	if err != nil {
		return nil, scimerrors.ErrNotFound("Resource " + strconv.Quote(id) + " not found")
	}
	row, err := models.FindSCIMResource(tx, tenant.DirectoryID, r.kind.name, resourceID, forUpdate)
	if models.IsNotFoundError(err) {
		return nil, scimerrors.ErrNotFound("Resource " + strconv.Quote(id) + " not found")
	}
	return row, err
}

// encode turns a resource into the document stored for it and the ids it
// references. id, meta, writeOnly attributes and derived attributes are never
// stored.
func (r *repository[T]) encode(item T) (core.Object, map[string][]string, error) {
	document, err := core.NewObject(item)
	if err != nil {
		return nil, nil, scimerrors.ErrInternal("could not encode the resource")
	}
	document.Remove("id")
	document.Remove("meta")
	for _, attribute := range r.kind.schemas.Base().Attributes {
		if attribute.Mutability == core.MutabilityWriteOnly {
			document.Remove(attribute.Name)
		}
	}
	for _, d := range r.kind.derived {
		document.Remove(d.attribute)
	}
	wanted := map[string][]string{}
	for _, ref := range r.kind.references {
		values := []string{}
		elements, _ := document.Get(ref.attribute).([]any)
		for _, element := range elements {
			if object, ok := element.(map[string]any); ok {
				if value, ok := core.Object(object).Get("value").(string); ok {
					values = append(values, value)
				}
			}
		}
		wanted[ref.attribute] = values
		document.Remove(ref.attribute)
	}
	return document, wanted, nil
}

func (r *repository[T]) keysOf(document core.Object) []models.SCIMResourceKey {
	keys := []models.SCIMResourceKey{}
	for _, k := range r.kind.keys {
		value, ok := document.Get(k.attribute).(string)
		if !ok || value == "" {
			continue
		}
		keys = append(keys, models.SCIMResourceKey{
			Attribute: k.attribute,
			Value:     fold(r.kind.attribute(k.attribute), value),
			Unique:    k.unique,
		})
	}
	return keys
}

// present turns stored rows into resources, adding id, meta, references and
// derived attributes. References and derived attributes are skipped when the
// response projection excludes them.
func (r *repository[T]) present(ctx context.Context, tx *storage.Connection, tenant *Tenant, rows []*models.SCIMResource) ([]T, error) {
	items := make([]T, len(rows))
	if len(rows) == 0 {
		return items, nil
	}
	projection := protocol.ProjectionFrom(ctx)
	ids := make([]uuid.UUID, len(rows))
	documents := make([]map[string]any, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
		documents[i] = maps.Clone(map[string]any(row.Resource))
		documents[i]["id"] = row.ID.String()
		documents[i]["meta"] = map[string]any{
			"resourceType": r.kind.name,
			"created":      row.CreatedAt,
			"lastModified": row.UpdatedAt,
			"location":     r.server.location(r.kind, row.ID),
			"version":      etag(row.Version),
		}
	}

	index := map[uuid.UUID]int{}
	for i, id := range ids {
		index[id] = i
	}
	for _, ref := range r.kind.references {
		if !projection.Returns(ref.attribute) {
			continue
		}
		references, err := models.FindSCIMReferenceTargets(tx, ids, ref.attribute)
		if err != nil {
			return nil, err
		}
		for _, reference := range references {
			document := documents[index[reference.SourceID]]
			elements, _ := document[ref.attribute].([]any)
			document[ref.attribute] = append(elements, map[string]any{
				"value": reference.TargetID.String(),
				"$ref":  r.server.location(r.server.types[reference.TargetType], reference.TargetID),
				"type":  reference.TargetType,
			})
		}
	}
	for _, d := range r.kind.derived {
		if !projection.Returns(d.attribute) {
			continue
		}
		if err := r.server.loadDerived(tx, tenant, d, ids, func(id uuid.UUID, element map[string]any) {
			document := documents[index[id]]
			elements, _ := document[d.attribute].([]any)
			document[d.attribute] = append(elements, element)
		}); err != nil {
			return nil, err
		}
	}

	for i, document := range documents {
		raw, err := json.Marshal(document)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &items[i]); err != nil {
			return nil, err
		}
	}
	return items, nil
}

func requireTenant(ctx context.Context) (*Tenant, error) {
	tenant := tenantFrom(ctx)
	if tenant == nil {
		return nil, scimerrors.ErrUnauthorized("authentication required")
	}
	return tenant, nil
}

func resourceTraits(row *models.SCIMResource) map[string]any {
	traits := map[string]any{
		"resource_id":   row.ID,
		"resource_type": row.ResourceType,
	}
	if row.UserID != nil {
		traits["user_id"] = *row.UserID
	}
	return traits
}

// fold normalises a string value the way SCIM compares it: case-insensitively
// unless the attribute is caseExact, per RFC 7643 Section 2.3.1.
func fold(attribute *core.Attribute, value string) string {
	if attribute != nil && attribute.Type == core.TypeString && !attribute.CaseExact {
		return strings.ToLower(value)
	}
	return value
}

func etag(version int64) string {
	return `W/"` + strconv.FormatInt(version, 10) + `"`
}

// scimError maps storage errors onto SCIM errors; anything else is a 500.
func scimError(err error) error {
	if err == nil {
		return nil
	}
	if scimErr, ok := errors.AsType[*scimerrors.Error](err); ok {
		return scimErr
	}
	if uniqueness, ok := errors.AsType[models.SCIMUniquenessError](err); ok {
		return scimerrors.ErrUniqueness(strconv.Quote(uniqueness.Attribute) + " must be unique")
	}
	if pgErr := utilities.NewPostgresError(err); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
		return scimerrors.ErrUniqueness("resource is not unique")
	}
	return err
}

func uniqueIDs(values []string) ([]uuid.UUID, error) {
	ids := []uuid.UUID{}
	for _, value := range values {
		id, err := uuid.FromString(value)
		if err != nil {
			return nil, scimerrors.ErrInvalidValue(strconv.Quote(value) + " is not a resource in this directory")
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

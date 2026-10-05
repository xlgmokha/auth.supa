package scim

import (
	"slices"
	"strconv"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// referenceChange is one reference added to or removed from a resource.
type referenceChange struct {
	attribute string
	target    uuid.UUID
	added     bool
}

// currentReferences returns the ids each reference attribute of row points to.
func (s *Server) currentReferences(tx *storage.Connection, kind *resourceType, row *models.SCIMResource) (map[string][]uuid.UUID, error) {
	current := map[string][]uuid.UUID{}
	for _, ref := range kind.references {
		references, err := models.FindSCIMReferenceTargets(tx, []uuid.UUID{row.ID}, ref.attribute)
		if err != nil {
			return nil, err
		}
		targets := make([]uuid.UUID, len(references))
		for i, reference := range references {
			targets[i] = reference.TargetID
		}
		current[ref.attribute] = targets
	}
	return current, nil
}

// syncReferences makes row reference exactly the wanted ids, writing only the
// difference from current, and audits each change.
func (s *Server) syncReferences(tx *storage.Connection, tenant *Tenant, kind *resourceType, row *models.SCIMResource, wanted map[string][]string, current map[string][]uuid.UUID) ([]referenceChange, error) {
	changes := []referenceChange{}
	for _, ref := range kind.references {
		want, err := uniqueIDs(wanted[ref.attribute])
		if err != nil {
			return nil, err
		}
		have := current[ref.attribute]
		var add, remove []uuid.UUID
		for _, id := range want {
			if !slices.Contains(have, id) {
				add = append(add, id)
			}
		}
		for _, id := range have {
			if !slices.Contains(want, id) {
				remove = append(remove, id)
			}
		}
		applied, err := s.applyReferences(tx, tenant, kind, &ref, row, add, remove)
		if err != nil {
			return nil, err
		}
		changes = append(changes, applied...)
	}
	return changes, nil
}

// applyReferences adds and removes references from row through ref. Adding a
// reference that exists or removing one that does not is a no-op.
func (s *Server) applyReferences(tx *storage.Connection, tenant *Tenant, kind *resourceType, ref *reference, row *models.SCIMResource, add, remove []uuid.UUID) ([]referenceChange, error) {
	if err := s.admitTargets(tx, tenant, kind, ref, row, add); err != nil {
		return nil, err
	}
	added, err := row.AddReferences(tx, ref.attribute, add)
	if err != nil {
		return nil, err
	}
	removed, err := row.RemoveReferences(tx, ref.attribute, remove)
	if err != nil {
		return nil, err
	}

	changes := []referenceChange{}
	for _, target := range added {
		changes = append(changes, referenceChange{attribute: ref.attribute, target: target, added: true})
	}
	for _, target := range removed {
		changes = append(changes, referenceChange{attribute: ref.attribute, target: target})
	}
	for _, change := range changes {
		if err := s.auditReferenceChange(tx, tenant, row.ID, change.attribute, change.target, change.added); err != nil {
			return nil, err
		}
	}
	return changes, nil
}

// admitTargets checks that every id about to be referenced is a live resource
// of an allowed type in the same directory, and that no cycle would form. The
// targets stay locked until the transaction ends, so none can be deleted
// before the reference commits.
func (s *Server) admitTargets(tx *storage.Connection, tenant *Tenant, kind *resourceType, ref *reference, row *models.SCIMResource, targets []uuid.UUID) error {
	if len(targets) == 0 {
		return nil
	}
	found, err := models.FindSCIMResourcesByID(tx, tenant.DirectoryID, targets, true)
	if err != nil {
		return err
	}
	types := map[uuid.UUID]string{}
	for _, target := range found {
		types[target.ID] = target.ResourceType
	}

	nested := false
	for _, target := range targets {
		resourceType, ok := types[target]
		if !ok || !slices.Contains(ref.targets, resourceType) {
			return scimerrors.ErrInvalidValue(strconv.Quote(target.String()) + " is not a " + ref.attribute + " candidate in this directory")
		}
		nested = nested || resourceType == kind.name
	}
	if !nested {
		return nil
	}

	// lockNesting has serialised this check with every other nesting write
	// in the directory.
	ancestors, err := models.FindSCIMAncestors(tx, []uuid.UUID{row.ID}, ref.attribute)
	if err != nil {
		return err
	}
	for _, target := range targets {
		cyclic := target == row.ID || slices.ContainsFunc(ancestors, func(a models.SCIMAncestor) bool { return a.SourceID == target })
		if cyclic {
			return scimerrors.ErrInvalidValue(strconv.Quote(target.String()) + " would make " + ref.attribute + " cyclic")
		}
	}
	return nil
}

// lockNesting serialises writes that nest resources of one type inside
// another of the same type, such as a group inside a group, so two concurrent
// requests cannot each add half of a cycle. It must run before any resource
// row is locked, or two such writes could deadlock on each other's rows.
// Resource types never change, so reading them unlocked is safe.
func (s *Server) lockNesting(tx *storage.Connection, tenant *Tenant, kind *resourceType, wanted map[string][]string) error {
	candidates := []uuid.UUID{}
	for _, ref := range kind.references {
		if !slices.Contains(ref.targets, kind.name) {
			continue
		}
		for _, value := range wanted[ref.attribute] {
			if id, err := uuid.FromString(value); err == nil {
				candidates = append(candidates, id)
			}
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	found, err := models.FindSCIMResourcesByID(tx, tenant.DirectoryID, candidates, false)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(found, func(r *models.SCIMResource) bool { return r.ResourceType == kind.name }) {
		return nil
	}
	return tx.RawQuery("select pg_advisory_xact_lock(hashtextextended(?, 0))", "scim:nesting:"+tenant.DirectoryID.String()).Exec()
}

func (s *Server) auditReferenceChange(tx *storage.Connection, tenant *Tenant, source uuid.UUID, attribute string, target uuid.UUID, added bool) error {
	kind := s.typeOfReference(attribute)
	if kind == nil {
		return nil
	}
	action := kind.reference(attribute).removed
	if added {
		action = kind.reference(attribute).added
	}
	return s.audit(tx, tenant, action, map[string]any{
		"resource_id":   source,
		"resource_type": kind.name,
		"attribute":     attribute,
		"member_id":     target,
	})
}

func (s *Server) typeOfReference(attribute string) *resourceType {
	for _, kind := range s.types {
		if kind.reference(attribute) != nil {
			return kind
		}
	}
	return nil
}

// loadDerived reports, for each of ids, the resources that reference it
// through d.via directly ("direct") or transitively ("indirect").
func (s *Server) loadDerived(tx *storage.Connection, tenant *Tenant, d derived, ids []uuid.UUID, add func(uuid.UUID, map[string]any)) error {
	ancestors, err := models.FindSCIMAncestors(tx, ids, d.via)
	if err != nil {
		return err
	}
	if len(ancestors) == 0 {
		return nil
	}
	sourceIDs := []uuid.UUID{}
	for _, ancestor := range ancestors {
		if !slices.Contains(sourceIDs, ancestor.SourceID) {
			sourceIDs = append(sourceIDs, ancestor.SourceID)
		}
	}
	sources, err := models.FindSCIMResourcesByID(tx, tenant.DirectoryID, sourceIDs, false)
	if err != nil {
		return err
	}
	byID := map[uuid.UUID]*models.SCIMResource{}
	for _, source := range sources {
		byID[source.ID] = source
	}
	for _, ancestor := range ancestors {
		source, ok := byID[ancestor.SourceID]
		if !ok {
			continue
		}
		membership := "indirect"
		if ancestor.Depth == 1 {
			membership = "direct"
		}
		element := map[string]any{
			"value": source.ID.String(),
			"$ref":  s.location(s.types[source.ResourceType], source.ID),
			"type":  membership,
		}
		if display, ok := source.Resource[d.display].(string); ok {
			element["display"] = display
		}
		add(ancestor.TargetID, element)
	}
	return nil
}

func (s *Server) location(kind *resourceType, id uuid.UUID) string {
	if kind == nil {
		return ""
	}
	return s.baseURL + kind.endpoint + "/" + id.String()
}

func (s *Server) audit(tx *storage.Connection, tenant *Tenant, action models.AuditAction, traits map[string]any) error {
	traits["sso_provider_id"] = tenant.SSOProviderID
	traits["directory_id"] = tenant.DirectoryID
	traits["outcome"] = "success"
	return models.NewSCIMAuditLogEntry(s.config.AuditLog, tenant.request, tx, tenant.SSOProviderID, tenant.TokenPrefix, action, tenant.ipAddress(), traits)
}

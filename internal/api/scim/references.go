package scim

import (
	"slices"
	"strconv"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// currentReferences returns the ids each reference attribute of row points to.
func currentReferences(tx *storage.Connection, kind *resourceType, row *models.SCIMResource) (map[string][]uuid.UUID, error) {
	current := map[string][]uuid.UUID{}
	for _, ref := range kind.references {
		targets, err := row.ReferencedIDs(tx, ref.attribute)
		if err != nil {
			return nil, err
		}
		current[ref.attribute] = targets
	}
	return current, nil
}

// syncReferences makes row reference exactly the wanted ids, writing only the
// difference from current, and audits each change.
func (s *Server) syncReferences(tx *storage.Connection, tenant *Tenant, kind *resourceType, row *models.SCIMResource, wanted, current map[string][]uuid.UUID) error {
	for i := range kind.references {
		ref := &kind.references[i]
		want, have := idSet(wanted[ref.attribute]), idSet(current[ref.attribute])
		var add, remove []uuid.UUID
		for _, id := range wanted[ref.attribute] {
			if _, ok := have[id]; !ok {
				add = append(add, id)
			}
		}
		for _, id := range current[ref.attribute] {
			if _, ok := want[id]; !ok {
				remove = append(remove, id)
			}
		}
		if _, err := s.applyReferences(tx, tenant, kind, ref, row, add, remove); err != nil {
			return err
		}
	}
	return nil
}

// applyReferences adds and removes references from row through ref, audits
// each change and reports whether there was any. Adding a reference that
// exists or removing one that does not is a no-op.
func (s *Server) applyReferences(tx *storage.Connection, tenant *Tenant, kind *resourceType, ref *reference, row *models.SCIMResource, add, remove []uuid.UUID) (bool, error) {
	if err := s.admitTargets(tx, tenant, kind, ref, row, add); err != nil {
		return false, err
	}
	added, err := row.AddReferences(tx, ref.attribute, add)
	if err != nil {
		return false, err
	}
	removed, err := row.RemoveReferences(tx, ref.attribute, remove)
	if err != nil {
		return false, err
	}

	events := make([]models.SCIMAuditEvent, 0, len(added)+len(removed))
	for _, target := range added {
		events = append(events, referenceEvent(kind, ref, row.ID, target, true))
	}
	for _, target := range removed {
		events = append(events, referenceEvent(kind, ref, row.ID, target, false))
	}
	return len(events) > 0, s.audit(tx, tenant, events...)
}

// admitTargets checks that every id about to be referenced is a live resource
// of an allowed type in the same directory, and that no cycle would form. The
// targets stay locked until the transaction ends, so none can be deleted
// before the reference commits.
func (s *Server) admitTargets(tx *storage.Connection, tenant *Tenant, kind *resourceType, ref *reference, row *models.SCIMResource, targets []uuid.UUID) error {
	if len(targets) == 0 {
		return nil
	}
	types, err := models.LockSCIMResourceTypes(tx, tenant.DirectoryID, targets)
	if err != nil {
		return err
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
	cyclic := map[uuid.UUID]struct{}{row.ID: {}}
	for _, ancestor := range ancestors {
		cyclic[ancestor.SourceID] = struct{}{}
	}
	for _, target := range targets {
		if _, ok := cyclic[target]; ok {
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
func (s *Server) lockNesting(tx *storage.Connection, tenant *Tenant, kind *resourceType, wanted map[string][]uuid.UUID) error {
	candidates := []uuid.UUID{}
	for _, ref := range kind.references {
		if slices.Contains(ref.targets, kind.name) {
			candidates = append(candidates, wanted[ref.attribute]...)
		}
	}
	nested, err := models.AnySCIMResourceOfType(tx, tenant.DirectoryID, kind.name, candidates)
	if err != nil || !nested {
		return err
	}
	return tx.RawQuery("select pg_advisory_xact_lock(hashtextextended(?, 0))", "scim:nesting:"+tenant.DirectoryID.String()).Exec()
}

// referrerEvents audits the references other resources lost when target was
// deleted, as membership changes of those resources.
func (s *Server) referrerEvents(target uuid.UUID, removed []models.SCIMReference) []models.SCIMAuditEvent {
	events := []models.SCIMAuditEvent{}
	for _, reference := range removed {
		kind := s.types[reference.SourceType]
		if kind == nil {
			continue
		}
		if ref := kind.reference(reference.Attribute); ref != nil {
			events = append(events, referenceEvent(kind, ref, reference.SourceID, target, false))
		}
	}
	return events
}

func referenceEvent(kind *resourceType, ref *reference, source, target uuid.UUID, added bool) models.SCIMAuditEvent {
	action := ref.removed
	if added {
		action = ref.added
	}
	return models.SCIMAuditEvent{Action: action, Traits: map[string]any{
		"resource_id":   source,
		"resource_type": kind.name,
		"attribute":     ref.attribute,
		"member_id":     target,
	}}
}

func idSet(ids []uuid.UUID) map[uuid.UUID]struct{} {
	set := make(map[uuid.UUID]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	return set
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
	seen := map[uuid.UUID]struct{}{}
	for _, ancestor := range ancestors {
		if _, ok := seen[ancestor.SourceID]; !ok {
			seen[ancestor.SourceID] = struct{}{}
			sourceIDs = append(sourceIDs, ancestor.SourceID)
		}
	}
	sources, err := models.FindSCIMResourcesByID(tx, tenant.DirectoryID, sourceIDs)
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

// audit records events made by the tenant's identity provider in one write.
func (s *Server) audit(tx *storage.Connection, tenant *Tenant, events ...models.SCIMAuditEvent) error {
	for _, event := range events {
		event.Traits["sso_provider_id"] = tenant.SSOProviderID
		event.Traits["directory_id"] = tenant.DirectoryID
		event.Traits["outcome"] = "success"
	}
	return models.NewSCIMAuditLogEntries(s.config.AuditLog, tenant.request, tx, tenant.SSOProviderID, tenant.TokenPrefix, tenant.ipAddress(), events)
}

// resourceEvent is the audit event for a change to row itself.
func resourceEvent(row *models.SCIMResource, change string) models.SCIMAuditEvent {
	traits := map[string]any{
		"resource_id":   row.ID,
		"resource_type": row.ResourceType,
	}
	if row.UserID != nil {
		traits["user_id"] = *row.UserID
	}
	return models.SCIMAuditEvent{Action: models.SCIMResourceAction(row.ResourceType, change), Traits: traits}
}

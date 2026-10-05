package scim

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/patch"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

// referencePatch is a PATCH that only adds and removes references, the shape
// identity providers use to sync group membership:
//
//	{"op": "add", "path": "members", "value": [{"value": "<id>"}]}
//	{"op": "remove", "path": "members[value eq \"<id>\"]"}
type referencePatch struct {
	reference  *reference
	operations []referenceOperation
}

// referenceOperation is a run of consecutive adds or removes.
type referenceOperation struct {
	add, remove []uuid.UUID
}

// patchReferences applies a reference-only PATCH as a delta, without reading
// the resource's existing references, and replies 204 like scim-go does for
// such a PATCH, per RFC 7644 Section 3.5.2. Adding a reference that exists
// or removing one that does not is a no-op. It reports false, leaving the
// request untouched, for every other request, which scim-go then serves.
func (s *Server) patchReferences(w http.ResponseWriter, r *http.Request) bool {
	query := r.URL.Query()
	if query.Has("attributes") || query.Has("excludedAttributes") {
		return false
	}
	kind, id, ok := s.referencingResource(r.URL.Path)
	if !ok {
		return false
	}
	body, err := utilities.GetBodyBytes(r)
	if err != nil {
		return false
	}
	req, err := protocol.DefaultLimits.DecodePatchRequest(bytes.NewReader(body))
	if err != nil {
		return false
	}
	p, ok := referencePatchOf(kind, req.Operations)
	if !ok {
		return false
	}
	ctx, err := s.authorize(r.Context(), "")
	if err != nil {
		return false
	}

	tenant := tenantFrom(ctx)
	var row *models.SCIMResource
	err = s.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		if err := s.lockNesting(tx, tenant, kind, p.added()); err != nil {
			return err
		}
		row, err = kind.find(tx, tenant, id, true)
		if err != nil {
			return err
		}
		if err := checkVersion(r.Header.Get("If-Match"), row); err != nil {
			return err
		}
		changed := false
		for _, operation := range p.operations {
			applied, err := s.applyReferences(tx, tenant, kind, p.reference, row, operation.add, operation.remove)
			if err != nil {
				return err
			}
			changed = changed || applied
		}
		if !changed {
			// RFC 7644 Section 3.5.2.1: a no-op does not change the resource.
			return nil
		}
		if err := row.Touch(tx); err != nil {
			return err
		}
		return s.audit(tx, tenant, resourceEvent(row, "updated"))
	})
	if err != nil {
		if err := protocol.SendError(w, scimError(err)); err != nil {
			logError(r, err)
		}
		return true
	}
	w.Header().Set("ETag", etag(row.Version))
	w.Header().Set("Content-Location", s.location(kind, row.ID))
	_ = protocol.Send(w, http.StatusNoContent, nil)
	return true
}

// added lists the ids the patch adds, by reference attribute.
func (p *referencePatch) added() map[string][]uuid.UUID {
	ids := []uuid.UUID{}
	for _, operation := range p.operations {
		ids = append(ids, operation.add...)
	}
	return map[string][]uuid.UUID{p.reference.attribute: ids}
}

// referencingResource matches "/scim/v2/<endpoint>/<id>" for a resource type
// with a reference attribute. Types with hooks always go through scim-go, so
// their hooks see every change.
func (s *Server) referencingResource(path string) (*resourceType, string, bool) {
	rest, ok := strings.CutPrefix(path, BasePath)
	if !ok {
		return nil, "", false
	}
	for _, kind := range s.types {
		if _, plain := kind.hooks.(noHooks); len(kind.references) == 0 || !plain {
			continue
		}
		id, ok := strings.CutPrefix(rest, kind.endpoint+"/")
		if ok && id != "" && !strings.Contains(id, "/") {
			return kind, id, true
		}
	}
	return nil, "", false
}

// referencePatchOf recognises a PATCH whose every operation adds values to,
// or removes one value from, the same reference attribute. Consecutive
// operations of the same kind are applied together.
func referencePatchOf(kind *resourceType, operations []patch.Operation) (*referencePatch, bool) {
	p := &referencePatch{}
	for _, operation := range operations {
		path, err := filter.NewPath(operation.Path)
		if err != nil || path.URI != "" || path.SubAttribute != "" {
			return nil, false
		}
		ref := kind.reference(path.Name)
		if ref == nil || (p.reference != nil && p.reference != ref) {
			return nil, false
		}
		p.reference = ref

		var last *referenceOperation
		if n := len(p.operations); n > 0 {
			last = &p.operations[n-1]
		}
		switch strings.ToLower(string(operation.Op)) {
		case string(patch.OpAdd):
			ids, ok := addedIDs(path, operation.Value)
			if !ok {
				return nil, false
			}
			if last != nil && len(last.remove) == 0 {
				last.add = append(last.add, ids...)
			} else {
				p.operations = append(p.operations, referenceOperation{add: ids})
			}
		case string(patch.OpRemove):
			id, ok := removedID(path, operation.Value)
			if !ok {
				return nil, false
			}
			parsed, err := uuid.FromString(id)
			if err != nil {
				// Nothing references a value that is not an id: a no-op.
				continue
			}
			if last != nil && len(last.add) == 0 {
				last.remove = append(last.remove, parsed)
			} else {
				p.operations = append(p.operations, referenceOperation{remove: []uuid.UUID{parsed}})
			}
		default:
			return nil, false
		}
	}
	return p, p.reference != nil
}

// addedIDs reads the ids of an add without a value filter. Values that are
// not ids are left to scim-go, which reports them.
func addedIDs(path filter.Path, value json.RawMessage) ([]uuid.UUID, bool) {
	if path.ValueFilter != nil {
		return nil, false
	}
	var elements []map[string]any
	if err := json.Unmarshal(value, &elements); err != nil {
		var element map[string]any
		if err := json.Unmarshal(value, &element); err != nil {
			return nil, false
		}
		elements = []map[string]any{element}
	}
	values := []string{}
	for _, element := range elements {
		found, _ := core.Object(element).Get("value").(string)
		if found == "" {
			return nil, false
		}
		values = append(values, found)
	}
	ids, err := uniqueIDs(values)
	return ids, err == nil && len(ids) > 0
}

// removedID reads the id of a remove filtered to one value, e.g.
// members[value eq "<id>"]. A remove that carries a value is left to scim-go,
// which refuses it.
func removedID(path filter.Path, value json.RawMessage) (string, bool) {
	if len(bytes.TrimSpace(value)) > 0 || path.ValueFilter == nil {
		return "", false
	}
	node := path.ValueFilter
	if node.Not() || filter.Operator(node.Operator()) != filter.OpEquals {
		return "", false
	}
	attribute := node.AttrPath()
	if attribute.URI != "" || attribute.SubAttribute != "" || !strings.EqualFold(attribute.Name, "value") {
		return "", false
	}
	id, ok := node.Value().(string)
	return id, ok
}

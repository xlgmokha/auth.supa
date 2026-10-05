package scim

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/patch"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// referencePatch is a PATCH that only adds and removes references, the shape
// identity providers use to sync group membership:
//
//	{"op": "add", "path": "members", "value": [{"value": "<id>"}]}
//	{"op": "remove", "path": "members[value eq \"<id>\"]"}
type referencePatch struct {
	kind       *resourceType
	reference  *reference
	id         string
	operations []referenceOperation
}

type referenceOperation struct {
	add bool
	ids []uuid.UUID
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
	ctx, err := s.authorize(r.Context(), "")
	if err != nil {
		return false
	}
	body, err := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return false
	}
	req, err := s.limits.DecodePatchRequest(bytes.NewReader(body))
	if err != nil {
		return false
	}
	p, ok := referencePatchOf(kind, id, req.Operations)
	if !ok {
		return false
	}

	tenant := tenantFrom(ctx)
	var row *models.SCIMResource
	err = s.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		if err := s.lockNesting(tx, tenant, kind, p.added()); err != nil {
			return err
		}
		resourceID, err := uuid.FromString(p.id)
		if err != nil {
			return scimerrors.ErrNotFound("Resource not found")
		}
		row, err = models.FindSCIMResource(tx, tenant.DirectoryID, kind.name, resourceID, true)
		if models.IsNotFoundError(err) {
			return scimerrors.ErrNotFound("Resource not found")
		}
		if err != nil {
			return err
		}
		if match := r.Header.Get("If-Match"); match != "" && match != "*" && match != etag(row.Version) {
			return scimerrors.ErrPreconditionFailed("resource has changed on the server")
		}
		changed := false
		for _, operation := range p.operations {
			var changes []referenceChange
			if operation.add {
				changes, err = s.applyReferences(tx, tenant, kind, p.reference, row, operation.ids, nil)
			} else {
				changes, err = s.applyReferences(tx, tenant, kind, p.reference, row, nil, operation.ids)
			}
			if err != nil {
				return err
			}
			changed = changed || len(changes) > 0
		}
		if !changed {
			// RFC 7644 Section 3.5.2.1: a no-op does not change the resource.
			return nil
		}
		if err := row.Touch(tx); err != nil {
			return err
		}
		return s.audit(tx, tenant, models.SCIMResourceAction(kind.name, "updated"), resourceTraits(row))
	})
	if err != nil {
		_ = protocol.SendError(w, scimError(err))
		return true
	}
	w.Header().Set("ETag", etag(row.Version))
	w.Header().Set("Content-Location", s.location(kind, row.ID))
	_ = protocol.Send(w, http.StatusNoContent, nil)
	return true
}

// added lists the values the patch adds, by reference attribute.
func (p *referencePatch) added() map[string][]string {
	values := []string{}
	for _, operation := range p.operations {
		if operation.add {
			for _, id := range operation.ids {
				values = append(values, id.String())
			}
		}
	}
	return map[string][]string{p.reference.attribute: values}
}

// referencingResource matches "/scim/v2/<endpoint>/<id>" for a resource type
// with a reference attribute.
func (s *Server) referencingResource(path string) (*resourceType, string, bool) {
	rest, ok := strings.CutPrefix(path, BasePath)
	if !ok {
		return nil, "", false
	}
	for _, kind := range s.types {
		if len(kind.references) == 0 {
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
// or removes one value from, the same reference attribute.
func referencePatchOf(kind *resourceType, id string, operations []patch.Operation) (*referencePatch, bool) {
	p := &referencePatch{kind: kind, id: id}
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

		switch strings.ToLower(string(operation.Op)) {
		case string(patch.OpAdd):
			ids, ok := addedIDs(path, operation.Value)
			if !ok {
				return nil, false
			}
			p.operations = append(p.operations, referenceOperation{add: true, ids: ids})
		case string(patch.OpRemove):
			id, ok := removedID(path, operation.Value)
			if !ok {
				return nil, false
			}
			ids := []uuid.UUID{}
			if parsed, err := uuid.FromString(id); err == nil {
				ids = append(ids, parsed)
			}
			p.operations = append(p.operations, referenceOperation{ids: ids})
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
		var found string
		for name, v := range element {
			if strings.EqualFold(name, "value") {
				found, _ = v.(string)
			}
		}
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

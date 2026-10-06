package models

import (
	"fmt"

	"github.com/gofrs/uuid"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgerrcode"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

type SCIMReference struct {
	SourceID   uuid.UUID `db:"source_id"`
	TargetID   uuid.UUID `db:"target_id"`
	TargetType string    `db:"target_type"`
}

type SCIMAncestor struct {
	TargetID uuid.UUID `db:"target_id"`
	SourceID uuid.UUID `db:"source_id"`
	Depth    int       `db:"depth"`
}

func (SCIMReference) TableName() string {
	return "scim_resource_references"
}

func (s SCIMScope) AddReferences(tx *storage.Connection, source uuid.UUID, attribute string, targets []uuid.UUID) error {
	if len(targets) == 0 {
		return nil
	}
	err := tx.RawQuery(
		fmt.Sprintf("INSERT INTO %q (sso_provider_id, source_id, attribute, target_id) SELECT ?, ?, ?, unnest(?::uuid[]) ON CONFLICT DO NOTHING", SCIMReference{}.TableName()),
		s.ProviderID, source, attribute, uuidStrings(targets),
	).Exec()
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == pgerrcode.ForeignKeyViolation || pgErr.Code == pgerrcode.CheckViolation) {
		return SCIMReferenceError{Attribute: attribute}
	}
	return errors.Wrap(err, "error adding SCIM references")
}

func (s SCIMScope) RemoveReferences(tx *storage.Connection, source uuid.UUID, attribute string, targets []uuid.UUID) error {
	if len(targets) == 0 {
		return nil
	}
	return errors.Wrap(tx.RawQuery(
		fmt.Sprintf("DELETE FROM %q WHERE source_id = ? AND attribute = ? AND target_id = any(?::uuid[])", SCIMReference{}.TableName()),
		source, attribute, uuidStrings(targets),
	).Exec(), "error removing SCIM references")
}

func (s SCIMScope) FindReferences(tx *storage.Connection, sources []uuid.UUID, attribute string) ([]SCIMReference, error) {
	references := []SCIMReference{}
	if len(sources) == 0 {
		return references, nil
	}
	err := tx.RawQuery(
		fmt.Sprintf("SELECT r.source_id, r.target_id, t.resource_type AS target_type FROM %q r JOIN %q t ON t.id = r.target_id WHERE r.source_id = any(?::uuid[]) AND r.attribute = ? ORDER BY r.source_id, r.target_id", SCIMReference{}.TableName(), SCIMResource{}.TableName()),
		uuidStrings(sources), attribute,
	).All(&references)
	return references, errors.Wrap(err, "error finding SCIM references")
}

func (s SCIMScope) LockTargets(tx *storage.Connection, ids []uuid.UUID) (map[uuid.UUID]string, error) {
	types := map[uuid.UUID]string{}
	if len(ids) == 0 {
		return types, nil
	}
	rows := []struct {
		ID           uuid.UUID `db:"id"`
		ResourceType string    `db:"resource_type"`
	}{}
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT id, resource_type FROM %q WHERE sso_provider_id = ? AND id = any(?::uuid[]) AND deleted_at IS NULL ORDER BY id FOR SHARE", SCIMResource{}.TableName()),
		s.ProviderID, uuidStrings(ids),
	).All(&rows); err != nil {
		return nil, errors.Wrap(err, "error locking SCIM references")
	}
	for _, row := range rows {
		types[row.ID] = row.ResourceType
	}
	return types, nil
}

func (s SCIMScope) FindAncestors(tx *storage.Connection, targets []uuid.UUID, attribute string) ([]SCIMAncestor, error) {
	ancestors := []SCIMAncestor{}
	if len(targets) == 0 {
		return ancestors, nil
	}
	table := SCIMReference{}.TableName()
	err := tx.RawQuery(
		fmt.Sprintf(`WITH RECURSIVE chain (target_id, source_id, depth) AS (
			SELECT target_id, source_id, 1 FROM %q WHERE target_id = any(?::uuid[]) AND attribute = ?
			UNION
			SELECT c.target_id, r.source_id, c.depth + 1 FROM chain c JOIN %q r ON r.target_id = c.source_id AND r.attribute = ? WHERE c.depth < 64
		)
		SELECT target_id, source_id, min(depth) AS depth FROM chain GROUP BY target_id, source_id ORDER BY target_id, depth, source_id`, table, table),
		uuidStrings(targets), attribute, attribute,
	).All(&ancestors)
	return ancestors, errors.Wrap(err, "error finding SCIM ancestors")
}

func (s SCIMScope) LockHierarchy(tx *storage.Connection) error {
	return errors.Wrap(tx.RawQuery("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", "scim:hierarchy:"+s.ProviderID.String()).Exec(), "error locking SCIM hierarchy")
}

func (s SCIMScope) FindAncestorIDs(tx *storage.Connection, id uuid.UUID, attribute string) ([]uuid.UUID, error) {
	ids := []uuid.UUID{}
	table := SCIMReference{}.TableName()
	err := tx.RawQuery(
		fmt.Sprintf(`WITH RECURSIVE chain (source_id) AS (
			SELECT source_id FROM %q WHERE target_id = ? AND attribute = ?
			UNION
			SELECT r.source_id FROM chain c JOIN %q r ON r.target_id = c.source_id AND r.attribute = ?
		)
		SELECT source_id FROM chain`, table, table),
		id, attribute, attribute,
	).All(&ids)
	return ids, errors.Wrap(err, "error finding SCIM ancestors")
}

func (s SCIMScope) DeleteReferences(tx *storage.Connection, id uuid.UUID) error {
	table := SCIMReference{}.TableName()
	for _, column := range []string{"source_id", "target_id"} {
		if err := tx.RawQuery(fmt.Sprintf("DELETE FROM %q WHERE %s = ?", table, column), id).Exec(); err != nil {
			return errors.Wrap(err, "error deleting SCIM references")
		}
	}
	return nil
}

func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

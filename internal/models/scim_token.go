package models

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

const (
	scimTokenScheme       = "scim_"
	scimTokenEntropyBytes = 20
	scimTokenPrefixLength = len(scimTokenScheme) + 7

	// scimTokenTouchInterval bounds how often last_used_at is written, so a
	// busy IdP does not turn every SCIM request into a write.
	scimTokenTouchInterval = time.Minute
)

// SCIMToken is a bearer token for one SCIM directory. Only the SHA-256 digest
// of the token is stored; the plaintext is returned once, on creation.
type SCIMToken struct {
	ID          uuid.UUID  `db:"id" json:"id"`
	DirectoryID uuid.UUID  `db:"directory_id" json:"-"`
	TokenHash   []byte     `db:"token_hash" json:"-"`
	Prefix      string     `db:"prefix" json:"prefix"`
	Description *string    `db:"description" json:"description"`
	CreatedAt   time.Time  `db:"created_at" json:"created_at"`
	ExpiresAt   *time.Time `db:"expires_at" json:"expires_at"`
	RevokedAt   *time.Time `db:"revoked_at" json:"revoked_at"`
	LastUsedAt  *time.Time `db:"last_used_at" json:"last_used_at"`
}

func (SCIMToken) TableName() string {
	return "scim_tokens"
}

// SCIMTokenNotFoundError is returned when a token does not exist in a
// directory.
type SCIMTokenNotFoundError struct{}

func (e SCIMTokenNotFoundError) Error() string {
	return "SCIM token not found"
}

func (e SCIMTokenNotFoundError) Is(target error) bool {
	return target == errNotFound
}

// HashSCIMToken returns the digest a token is stored and looked up by.
func HashSCIMToken(plaintext string) []byte {
	sum := sha256.Sum256([]byte(plaintext))
	return sum[:]
}

// NewSCIMToken creates a token for the directory and returns it with its
// plaintext, which is never retrievable again.
func NewSCIMToken(tx *storage.Connection, directoryID uuid.UUID, description *string, expiresAt *time.Time) (*SCIMToken, string, error) {
	entropy := make([]byte, scimTokenEntropyBytes)
	if _, err := rand.Read(entropy); err != nil {
		return nil, "", errors.Wrap(err, "error generating SCIM token")
	}
	plaintext := scimTokenScheme + hex.EncodeToString(entropy)

	token := &SCIMToken{}
	if err := tx.RawQuery(
		`insert into scim_tokens (id, directory_id, token_hash, prefix, description, expires_at)
		values (?, ?, ?, ?, ?, ?) returning *`,
		uuid.Must(uuid.NewV7()), directoryID, HashSCIMToken(plaintext), plaintext[:scimTokenPrefixLength], description, expiresAt,
	).First(token); err != nil {
		return nil, "", errors.Wrap(err, "error creating SCIM token")
	}
	return token, plaintext, nil
}

// FindActiveSCIMTokens lists a directory's tokens that are neither revoked
// nor expired, oldest first.
func FindActiveSCIMTokens(tx *storage.Connection, directoryID uuid.UUID) ([]*SCIMToken, error) {
	tokens := []*SCIMToken{}
	if err := tx.RawQuery(
		`select * from scim_tokens
		where directory_id = ? and revoked_at is null and (expires_at is null or expires_at > now())
		order by created_at, id`,
		directoryID,
	).All(&tokens); err != nil {
		return nil, errors.Wrap(err, "error listing SCIM tokens")
	}
	return tokens, nil
}

// FindSCIMToken returns one of the directory's tokens.
func FindSCIMToken(tx *storage.Connection, directoryID, id uuid.UUID) (*SCIMToken, error) {
	var token SCIMToken
	if err := tx.Q().Where("directory_id = ? and id = ?", directoryID, id).First(&token); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, SCIMTokenNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding SCIM token")
	}
	return &token, nil
}

// Revoke makes the token inoperable from now on, reporting whether it was
// still unrevoked.
func (t *SCIMToken) Revoke(tx *storage.Connection) (bool, error) {
	if t.RevokedAt != nil {
		return false, nil
	}
	if err := tx.RawQuery(
		"update scim_tokens set revoked_at = now() where id = ? returning *", t.ID,
	).First(t); err != nil {
		return false, errors.Wrap(err, "error revoking SCIM token")
	}
	return true, nil
}

// SCIMCredential is what a presented bearer token resolves to: the token, its
// directory and that directory's SSO provider, read in one query.
type SCIMCredential struct {
	TokenID          uuid.UUID  `db:"token_id"`
	Prefix           string     `db:"prefix"`
	ExpiresAt        *time.Time `db:"expires_at"`
	RevokedAt        *time.Time `db:"revoked_at"`
	LastUsedAt       *time.Time `db:"last_used_at"`
	DirectoryID      uuid.UUID  `db:"directory_id"`
	DirectoryEnabled bool       `db:"directory_enabled"`
	SSOProviderID    uuid.UUID  `db:"sso_provider_id"`
	ProviderDisabled bool       `db:"provider_disabled"`
}

// FindSCIMCredential resolves a plaintext bearer token. Revoked and expired
// tokens are returned so the caller decides how to refuse them. A token that
// could never have been issued is not found without a query.
func FindSCIMCredential(tx *storage.Connection, plaintext string) (*SCIMCredential, error) {
	if !isSCIMToken(plaintext) {
		return nil, SCIMTokenNotFoundError{}
	}
	var credential SCIMCredential
	if err := tx.RawQuery(
		`select t.id as token_id, t.prefix, t.expires_at, t.revoked_at, t.last_used_at,
			d.id as directory_id, d.enabled as directory_enabled,
			p.id as sso_provider_id, coalesce(p.disabled, false) as provider_disabled
		from scim_tokens t
		join scim_directories d on d.id = t.directory_id
		join sso_providers p on p.id = d.sso_provider_id
		where t.token_hash = ?`,
		HashSCIMToken(plaintext),
	).First(&credential); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, SCIMTokenNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding SCIM token")
	}
	return &credential, nil
}

// isSCIMToken reports whether plaintext has the shape NewSCIMToken issues.
func isSCIMToken(plaintext string) bool {
	entropy, ok := strings.CutPrefix(plaintext, scimTokenScheme)
	if !ok || len(entropy) != 2*scimTokenEntropyBytes {
		return false
	}
	_, err := hex.DecodeString(entropy)
	return err == nil
}

// IsUsable reports whether the token is neither revoked nor expired at now.
func (c *SCIMCredential) IsUsable(now time.Time) bool {
	return c.RevokedAt == nil && (c.ExpiresAt == nil || now.Before(*c.ExpiresAt))
}

// Touch records that the token was used, at most once per minute.
func (c *SCIMCredential) Touch(tx *storage.Connection, now time.Time) error {
	if c.LastUsedAt != nil && now.Sub(*c.LastUsedAt) < scimTokenTouchInterval {
		return nil
	}
	if err := tx.RawQuery("update scim_tokens set last_used_at = ? where id = ?", now, c.TokenID).Exec(); err != nil {
		return errors.Wrap(err, "error updating SCIM token")
	}
	c.LastUsedAt = &now
	return nil
}

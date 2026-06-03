// SPDX-License-Identifier: Apache-2.0

package notifications

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"system-wrangler-backend/internal/secrets"
)

// SQLiteStore persists channels + delivery history to SQLite. Tables are
// STRICT; the schema is pragma-probed so re-running NewSQLiteStore on an
// initialised db is a no-op. Vault is required to seal/preserve channel
// secrets on write; it is set after construction in main.go (and in
// tests) and must be non-nil before Create/Update.
type SQLiteStore struct {
	db    *sql.DB
	Vault *secrets.Vault

	NewID func() string
	Now   func() time.Time
}

// NewSQLiteStore creates the tables if needed and returns a store. The
// caller sets Vault before any Create/Update.
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("notifications: schema: %w", err)
	}
	return &SQLiteStore{db: db, NewID: newUUID, Now: time.Now}, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS notification_channels (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    type              TEXT NOT NULL,
    enabled           INTEGER NOT NULL,
    config            TEXT NOT NULL,
    secret_ciphertext BLOB,
    secret_nonce      BLOB,
    secret_version    INTEGER,
    created_by        TEXT NOT NULL,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS notification_deliveries (
    id           TEXT PRIMARY KEY,
    channel_id   TEXT NOT NULL,
    channel_name TEXT NOT NULL,
    channel_type TEXT NOT NULL,
    kind         TEXT NOT NULL,
    rule_name    TEXT NOT NULL,
    system_id    TEXT NOT NULL,
    status       TEXT NOT NULL,
    error        TEXT,
    at           INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS notification_deliveries_at ON notification_deliveries(at);
`

const channelColumns = `id, name, type, enabled, config,
                        secret_ciphertext, secret_nonce, secret_version,
                        created_by, created_at, updated_at`

const defaultDeliveryLimit = 100

func (s *SQLiteStore) sealSecret(plaintext string) (Sealed, error) {
	if plaintext == "" {
		return Sealed{}, nil
	}
	if s.Vault == nil {
		return Sealed{}, fmt.Errorf("%w: secret storage is unavailable (no vault configured)", ErrInvalid)
	}
	return SealWith(s.Vault, []byte(plaintext))
}

// Create inserts a new channel, sealing the secret when present.
func (s *SQLiteStore) Create(in ChannelInput, createdBy string) (Channel, error) {
	if err := in.Validate(); err != nil {
		return Channel{}, err
	}
	if createdBy == "" {
		return Channel{}, fmt.Errorf("%w: createdBy is required", ErrInvalid)
	}
	if in.Type.requiresSecret() && in.Secret == "" {
		return Channel{}, fmt.Errorf("%w: a %s channel requires a secret", ErrInvalid, in.Type)
	}
	sealed, err := s.sealSecret(in.Secret)
	if err != nil {
		return Channel{}, err
	}
	now := s.Now().UTC()
	c := Channel{
		ID:        s.NewID(),
		Name:      in.Name,
		Type:      in.Type,
		Enabled:   in.Enabled,
		Config:    in.Config,
		Secret:    sealed,
		CreatedBy: createdBy,
		CreatedAt: now,
		UpdatedAt: now,
	}
	cfgJSON, err := json.Marshal(c.Config)
	if err != nil {
		return Channel{}, fmt.Errorf("notifications: marshal config: %w", err)
	}
	if _, err := s.db.Exec(
		`INSERT INTO notification_channels
		   (id, name, type, enabled, config, secret_ciphertext, secret_nonce, secret_version,
		    created_by, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.Name, string(c.Type), boolToInt(c.Enabled), string(cfgJSON),
		nullBytes(sealed.Ciphertext), nullBytes(sealed.Nonce), nullVersion(sealed),
		c.CreatedBy, c.CreatedAt.UnixNano(), c.UpdatedAt.UnixNano(),
	); err != nil {
		return Channel{}, fmt.Errorf("notifications: insert: %w", err)
	}
	return c, nil
}

// Get returns the channel with the given id or ErrNotFound.
func (s *SQLiteStore) Get(id string) (Channel, error) {
	row := s.db.QueryRow(`SELECT `+channelColumns+` FROM notification_channels WHERE id = ?`, id)
	c, err := scanChannel(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Channel{}, ErrNotFound
	}
	return c, err
}

// List returns every channel ordered by created_at, id.
func (s *SQLiteStore) List() ([]Channel, error) {
	return s.queryChannels(`SELECT ` + channelColumns + ` FROM notification_channels ORDER BY created_at, id`)
}

// ListEnabled returns enabled channels ordered by created_at, id.
func (s *SQLiteStore) ListEnabled() ([]Channel, error) {
	return s.queryChannels(`SELECT ` + channelColumns + ` FROM notification_channels WHERE enabled = 1 ORDER BY created_at, id`)
}

func (s *SQLiteStore) queryChannels(query string) ([]Channel, error) {
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("notifications: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Channel{}
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, fmt.Errorf("notifications: scan: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("notifications: list rows: %w", err)
	}
	return out, nil
}

// Update replaces a channel. The secret is preserved when the input
// omits it (empty), re-sealed when provided, and cleared when the type
// changes without a fresh secret — so a channel never carries a secret
// that belongs to a different transport.
func (s *SQLiteStore) Update(id string, in ChannelInput) (Channel, error) {
	if err := in.Validate(); err != nil {
		return Channel{}, err
	}
	existing, err := s.Get(id)
	if err != nil {
		return Channel{}, err
	}
	var sealed Sealed
	switch {
	case in.Secret != "":
		if sealed, err = s.sealSecret(in.Secret); err != nil {
			return Channel{}, err
		}
	case in.Type == existing.Type:
		sealed = existing.Secret
	default:
		sealed = Sealed{}
	}
	if in.Type.requiresSecret() && sealed.IsZero() {
		return Channel{}, fmt.Errorf("%w: a %s channel requires a secret", ErrInvalid, in.Type)
	}
	now := s.Now().UTC()
	cfgJSON, err := json.Marshal(in.Config)
	if err != nil {
		return Channel{}, fmt.Errorf("notifications: marshal config: %w", err)
	}
	res, err := s.db.Exec(
		`UPDATE notification_channels SET
		   name = ?, type = ?, enabled = ?, config = ?,
		   secret_ciphertext = ?, secret_nonce = ?, secret_version = ?, updated_at = ?
		 WHERE id = ?`,
		in.Name, string(in.Type), boolToInt(in.Enabled), string(cfgJSON),
		nullBytes(sealed.Ciphertext), nullBytes(sealed.Nonce), nullVersion(sealed),
		now.UnixNano(), id,
	)
	if err != nil {
		return Channel{}, fmt.Errorf("notifications: update: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Channel{}, ErrNotFound
	}
	return s.Get(id)
}

// Delete removes a channel. Its delivery history is kept (denormalized),
// so an operator can still audit what a since-deleted channel sent.
func (s *SQLiteStore) Delete(id string) error {
	res, err := s.db.Exec(`DELETE FROM notification_channels WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("notifications: delete: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordDelivery appends one delivery row.
func (s *SQLiteStore) RecordDelivery(d Delivery) (Delivery, error) {
	if d.ID == "" {
		d.ID = s.NewID()
	}
	if d.At.IsZero() {
		d.At = s.Now().UTC()
	}
	if _, err := s.db.Exec(
		`INSERT INTO notification_deliveries
		   (id, channel_id, channel_name, channel_type, kind, rule_name, system_id, status, error, at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ID, d.ChannelID, d.ChannelName, string(d.ChannelType), d.Kind, d.RuleName,
		d.SystemID, string(d.Status), nullString(d.Error), d.At.UnixNano(),
	); err != nil {
		return Delivery{}, fmt.Errorf("notifications: record delivery: %w", err)
	}
	return d, nil
}

// ListDeliveries returns the most recent attempts first.
func (s *SQLiteStore) ListDeliveries(limit int) ([]Delivery, error) {
	if limit <= 0 {
		limit = defaultDeliveryLimit
	}
	rows, err := s.db.Query(
		`SELECT id, channel_id, channel_name, channel_type, kind, rule_name, system_id, status, error, at
		 FROM notification_deliveries ORDER BY at DESC, id DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("notifications: list deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Delivery{}
	for rows.Next() {
		var (
			d           Delivery
			channelType string
			status      string
			errStr      sql.NullString
			atNs        int64
		)
		if err := rows.Scan(
			&d.ID, &d.ChannelID, &d.ChannelName, &channelType, &d.Kind, &d.RuleName,
			&d.SystemID, &status, &errStr, &atNs,
		); err != nil {
			return nil, fmt.Errorf("notifications: scan delivery: %w", err)
		}
		d.ChannelType = Type(channelType)
		d.Status = DeliveryStatus(status)
		if errStr.Valid {
			d.Error = errStr.String
		}
		d.At = time.Unix(0, atNs).UTC()
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("notifications: list deliveries rows: %w", err)
	}
	return out, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanChannel(r rowScanner) (Channel, error) {
	var (
		c                    Channel
		typ                  string
		enabled              int
		cfgJSON              string
		ciphertext, nonce    []byte
		version              sql.NullInt64
		createdNs, updatedNs int64
	)
	if err := r.Scan(
		&c.ID, &c.Name, &typ, &enabled, &cfgJSON,
		&ciphertext, &nonce, &version,
		&c.CreatedBy, &createdNs, &updatedNs,
	); err != nil {
		return Channel{}, err
	}
	c.Type = Type(typ)
	c.Enabled = enabled == 1
	if err := json.Unmarshal([]byte(cfgJSON), &c.Config); err != nil {
		return Channel{}, fmt.Errorf("notifications: unmarshal config: %w", err)
	}
	if len(ciphertext) > 0 {
		c.Secret = Sealed{Ciphertext: ciphertext, Nonce: nonce, Version: int(version.Int64)}
	}
	c.CreatedAt = time.Unix(0, createdNs).UTC()
	c.UpdatedAt = time.Unix(0, updatedNs).UTC()
	return c, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func nullVersion(s Sealed) any {
	if s.IsZero() {
		return nil
	}
	return s.Version
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

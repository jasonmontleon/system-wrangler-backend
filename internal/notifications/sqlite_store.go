// SPDX-License-Identifier: Apache-2.0

package notifications

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
	// notification_deliveries predates the per-user path; add user_id to
	// existing installs (fresh ones get it from the CREATE above). SQLite
	// has no ADD COLUMN IF NOT EXISTS, so probe first.
	if err := addColumnIfMissing(db, "notification_deliveries", "user_id",
		`ALTER TABLE notification_deliveries ADD COLUMN user_id TEXT NOT NULL DEFAULT ''`); err != nil {
		return nil, fmt.Errorf("notifications: migrate deliveries: %w", err)
	}
	if err := addColumnIfMissing(db, "notification_pending", "user_id",
		`ALTER TABLE notification_pending ADD COLUMN user_id TEXT NOT NULL DEFAULT ''`); err != nil {
		return nil, fmt.Errorf("notifications: migrate pending: %w", err)
	}
	// The user_id index is created here, after the migration above, not in
	// `schema`: on a pre-per-user install the deliveries table already
	// exists without user_id, so building this index inside the schema Exec
	// would run before the ALTER and fail with "no such column: user_id".
	if _, err := db.Exec(
		`CREATE INDEX IF NOT EXISTS notification_deliveries_user ON notification_deliveries(user_id)`,
	); err != nil {
		return nil, fmt.Errorf("notifications: index deliveries user: %w", err)
	}
	return &SQLiteStore{db: db, NewID: newUUID, Now: time.Now}, nil
}

func addColumnIfMissing(db *sql.DB, table, column, alter string) error {
	row := db.QueryRow(`SELECT 1 FROM pragma_table_info(?) WHERE name = ?`, table, column)
	var found int
	switch err := row.Scan(&found); {
	case err == nil:
		return nil // already present
	case errors.Is(err, sql.ErrNoRows):
		_, err := db.Exec(alter)
		return err
	default:
		return err
	}
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
    at           INTEGER NOT NULL,
    user_id      TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX IF NOT EXISTS notification_deliveries_at ON notification_deliveries(at);

CREATE TABLE IF NOT EXISTS user_notification_channels (
    id                TEXT PRIMARY KEY,
    user_id           TEXT NOT NULL,
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

CREATE INDEX IF NOT EXISTS user_notification_channels_user ON user_notification_channels(user_id);

CREATE TABLE IF NOT EXISTS user_alert_subscription (
    user_id TEXT PRIMARY KEY,
    config  TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS user_notification_policy (
    user_id TEXT PRIMARY KEY,
    config  TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS alert_rule_routing (
    rule_id TEXT PRIMARY KEY,
    mode    TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS alert_rule_route_channels (
    rule_id    TEXT NOT NULL,
    channel_id TEXT NOT NULL,
    PRIMARY KEY (rule_id, channel_id)
) STRICT;

CREATE INDEX IF NOT EXISTS alert_rule_route_channels_channel
    ON alert_rule_route_channels(channel_id);

CREATE TABLE IF NOT EXISTS notification_policy (
    id     INTEGER PRIMARY KEY CHECK (id = 1),
    config TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS notification_pending (
    id          TEXT PRIMARY KEY,
    rule_id     TEXT NOT NULL,
    rule_name   TEXT NOT NULL,
    system_id   TEXT NOT NULL,
    severity    TEXT NOT NULL,
    kind        TEXT NOT NULL,
    message     TEXT NOT NULL,
    enqueued_at INTEGER NOT NULL,
    user_id     TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX IF NOT EXISTS notification_pending_enqueued ON notification_pending(enqueued_at);
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

func (s *SQLiteStore) queryChannels(query string, args ...any) ([]Channel, error) {
	rows, err := s.db.Query(query, args...)
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
// so an operator can still audit what a since-deleted channel sent. The
// channel is also dropped from every rule's routing selection in the same
// transaction so no rule routes to a channel that no longer exists.
func (s *SQLiteStore) Delete(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("notifications: delete begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(`DELETE FROM notification_channels WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("notifications: delete: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(`DELETE FROM alert_rule_route_channels WHERE channel_id = ?`, id); err != nil {
		return fmt.Errorf("notifications: delete route memberships: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("notifications: delete commit: %w", err)
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
		   (id, channel_id, channel_name, channel_type, kind, rule_name, system_id, status, error, at, user_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ID, d.ChannelID, d.ChannelName, string(d.ChannelType), d.Kind, d.RuleName,
		d.SystemID, string(d.Status), nullString(d.Error), d.At.UnixNano(), d.UserID,
	); err != nil {
		return Delivery{}, fmt.Errorf("notifications: record delivery: %w", err)
	}
	return d, nil
}

const deliverySelect = `SELECT id, channel_id, channel_name, channel_type, kind, rule_name, system_id, status, error, at
	 FROM notification_deliveries`

// ListDeliveries returns the most recent shared (non-personal) attempts
// first. Personal deliveries are scoped out — see ListUserDeliveries.
func (s *SQLiteStore) ListDeliveries(limit int) ([]Delivery, error) {
	return s.queryDeliveries(
		deliverySelect+` WHERE user_id = '' ORDER BY at DESC, id DESC LIMIT ?`, clampLimit(limit))
}

// ListUserDeliveries returns the most recent personal attempts for one user.
func (s *SQLiteStore) ListUserDeliveries(userID string, limit int) ([]Delivery, error) {
	return s.queryDeliveries(
		deliverySelect+` WHERE user_id = ? ORDER BY at DESC, id DESC LIMIT ?`, userID, clampLimit(limit))
}

func clampLimit(limit int) int {
	if limit <= 0 {
		return defaultDeliveryLimit
	}
	return limit
}

func (s *SQLiteStore) queryDeliveries(query string, args ...any) ([]Delivery, error) {
	rows, err := s.db.Query(query, args...)
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

// GetRouting returns the routing for one rule. When the rule has no mode
// row it reports the default all-channels routing rather than an error.
func (s *SQLiteStore) GetRouting(ruleID string) (Routing, error) {
	var mode string
	err := s.db.QueryRow(`SELECT mode FROM alert_rule_routing WHERE rule_id = ?`, ruleID).Scan(&mode)
	if errors.Is(err, sql.ErrNoRows) {
		return Routing{RuleID: ruleID, Mode: RouteModeAll}, nil
	}
	if err != nil {
		return Routing{}, fmt.Errorf("notifications: get routing: %w", err)
	}
	r := Routing{RuleID: ruleID, Mode: RouteMode(mode)}
	if r.Mode == RouteModeSelected {
		ids, err := s.routeChannelIDs(ruleID)
		if err != nil {
			return Routing{}, err
		}
		r.ChannelIDs = ids
	}
	return r, nil
}

func (s *SQLiteStore) routeChannelIDs(ruleID string) ([]string, error) {
	rows, err := s.db.Query(
		`SELECT channel_id FROM alert_rule_route_channels WHERE rule_id = ? ORDER BY channel_id`, ruleID)
	if err != nil {
		return nil, fmt.Errorf("notifications: route channels: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("notifications: scan route channel: %w", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("notifications: route channels rows: %w", err)
	}
	return out, nil
}

// SetRouting upserts a rule's mode and replaces its channel set in one
// transaction. An all-mode input clears the channel rows.
func (s *SQLiteStore) SetRouting(ruleID string, in RoutingInput) error {
	if ruleID == "" {
		return fmt.Errorf("%w: ruleId is required", ErrInvalid)
	}
	if err := in.Validate(); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("notifications: set routing begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(
		`INSERT INTO alert_rule_routing (rule_id, mode) VALUES (?, ?)
		 ON CONFLICT(rule_id) DO UPDATE SET mode = excluded.mode`,
		ruleID, string(in.Mode),
	); err != nil {
		return fmt.Errorf("notifications: upsert routing mode: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM alert_rule_route_channels WHERE rule_id = ?`, ruleID); err != nil {
		return fmt.Errorf("notifications: clear route channels: %w", err)
	}
	for _, cid := range in.ChannelIDs {
		if _, err := tx.Exec(
			`INSERT INTO alert_rule_route_channels (rule_id, channel_id) VALUES (?, ?)`, ruleID, cid,
		); err != nil {
			return fmt.Errorf("notifications: insert route channel: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("notifications: set routing commit: %w", err)
	}
	return nil
}

// ListRouting returns every rule with an explicit routing row, each with
// its selected channel ids (empty for all-mode rows).
func (s *SQLiteStore) ListRouting() ([]Routing, error) {
	rows, err := s.db.Query(`SELECT rule_id, mode FROM alert_rule_routing ORDER BY rule_id`)
	if err != nil {
		return nil, fmt.Errorf("notifications: list routing: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Routing{}
	for rows.Next() {
		var r Routing
		var mode string
		if err := rows.Scan(&r.RuleID, &mode); err != nil {
			return nil, fmt.Errorf("notifications: scan routing: %w", err)
		}
		r.Mode = RouteMode(mode)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("notifications: list routing rows: %w", err)
	}
	for i := range out {
		if out[i].Mode != RouteModeSelected {
			continue
		}
		ids, err := s.routeChannelIDs(out[i].RuleID)
		if err != nil {
			return nil, err
		}
		out[i].ChannelIDs = ids
	}
	return out, nil
}

// GetPolicy returns the singleton delivery policy, or DefaultPolicy when
// none has been stored yet.
func (s *SQLiteStore) GetPolicy() (Policy, error) {
	var cfg string
	err := s.db.QueryRow(`SELECT config FROM notification_policy WHERE id = 1`).Scan(&cfg)
	if errors.Is(err, sql.ErrNoRows) {
		return DefaultPolicy(), nil
	}
	if err != nil {
		return Policy{}, fmt.Errorf("notifications: get policy: %w", err)
	}
	var p Policy
	if err := json.Unmarshal([]byte(cfg), &p); err != nil {
		return Policy{}, fmt.Errorf("notifications: unmarshal policy: %w", err)
	}
	return p, nil
}

// SetPolicy validates and upserts the singleton policy row.
func (s *SQLiteStore) SetPolicy(in PolicyInput) error {
	if err := in.Validate(); err != nil {
		return err
	}
	cfg, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("notifications: marshal policy: %w", err)
	}
	if _, err := s.db.Exec(
		`INSERT INTO notification_policy (id, config) VALUES (1, ?)
		 ON CONFLICT(id) DO UPDATE SET config = excluded.config`, string(cfg),
	); err != nil {
		return fmt.Errorf("notifications: set policy: %w", err)
	}
	return nil
}

// EnqueuePending appends a deferred delivery row.
func (s *SQLiteStore) EnqueuePending(d PendingDelivery) (PendingDelivery, error) {
	if d.ID == "" {
		d.ID = s.NewID()
	}
	if d.EnqueuedAt.IsZero() {
		d.EnqueuedAt = s.Now().UTC()
	}
	msg, err := json.Marshal(d.Message)
	if err != nil {
		return PendingDelivery{}, fmt.Errorf("notifications: marshal pending message: %w", err)
	}
	if _, err := s.db.Exec(
		`INSERT INTO notification_pending
		   (id, rule_id, rule_name, system_id, severity, kind, message, enqueued_at, user_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ID, d.RuleID, d.RuleName, d.SystemID, d.Severity, d.Kind, string(msg), d.EnqueuedAt.UnixNano(), d.UserID,
	); err != nil {
		return PendingDelivery{}, fmt.Errorf("notifications: enqueue pending: %w", err)
	}
	return d, nil
}

// ListPending returns deferred deliveries oldest first.
func (s *SQLiteStore) ListPending() ([]PendingDelivery, error) {
	rows, err := s.db.Query(
		`SELECT id, rule_id, rule_name, system_id, severity, kind, message, enqueued_at, user_id
		 FROM notification_pending ORDER BY enqueued_at, id`)
	if err != nil {
		return nil, fmt.Errorf("notifications: list pending: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []PendingDelivery{}
	for rows.Next() {
		var (
			d    PendingDelivery
			msg  string
			atNs int64
		)
		if err := rows.Scan(
			&d.ID, &d.RuleID, &d.RuleName, &d.SystemID, &d.Severity, &d.Kind, &msg, &atNs, &d.UserID,
		); err != nil {
			return nil, fmt.Errorf("notifications: scan pending: %w", err)
		}
		if err := json.Unmarshal([]byte(msg), &d.Message); err != nil {
			return nil, fmt.Errorf("notifications: unmarshal pending message: %w", err)
		}
		d.EnqueuedAt = time.Unix(0, atNs).UTC()
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("notifications: list pending rows: %w", err)
	}
	return out, nil
}

// DeletePending removes the given pending ids.
func (s *SQLiteStore) DeletePending(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	//nolint:gosec // G202: the concatenated text is only "?" placeholders; the ids are bound parameters.
	query := `DELETE FROM notification_pending WHERE id IN (` + placeholders + `)`
	if _, err := s.db.Exec(query, args...); err != nil {
		return fmt.Errorf("notifications: delete pending: %w", err)
	}
	return nil
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

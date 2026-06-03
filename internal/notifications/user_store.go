// SPDX-License-Identifier: Apache-2.0

package notifications

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// Owner-scoped persistence for the per-user delivery path: personal
// channels, a per-user alert subscription, and a per-user delivery policy.
// Every method takes a userID and only ever touches that user's rows, so a
// user can never read or mutate another's preferences.

const userChannelColumns = `id, name, type, enabled, config,
                            secret_ciphertext, secret_nonce, secret_version,
                            created_by, created_at, updated_at`

// CreateUserChannel inserts a personal channel owned by userID.
func (s *SQLiteStore) CreateUserChannel(userID string, in ChannelInput) (Channel, error) {
	if userID == "" {
		return Channel{}, fmt.Errorf("%w: userID is required", ErrInvalid)
	}
	if err := in.Validate(); err != nil {
		return Channel{}, err
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
		ID: s.NewID(), Name: in.Name, Type: in.Type, Enabled: in.Enabled,
		Config: in.Config, Secret: sealed, CreatedBy: userID, CreatedAt: now, UpdatedAt: now,
	}
	cfgJSON, err := json.Marshal(c.Config)
	if err != nil {
		return Channel{}, fmt.Errorf("notifications: marshal config: %w", err)
	}
	if _, err := s.db.Exec(
		`INSERT INTO user_notification_channels
		   (id, user_id, name, type, enabled, config, secret_ciphertext, secret_nonce, secret_version,
		    created_by, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, userID, c.Name, string(c.Type), boolToInt(c.Enabled), string(cfgJSON),
		nullBytes(sealed.Ciphertext), nullBytes(sealed.Nonce), nullVersion(sealed),
		c.CreatedBy, c.CreatedAt.UnixNano(), c.UpdatedAt.UnixNano(),
	); err != nil {
		return Channel{}, fmt.Errorf("notifications: insert user channel: %w", err)
	}
	return c, nil
}

// GetUserChannel returns one of userID's channels or ErrNotFound. A row
// owned by another user is reported as ErrNotFound, not leaked.
func (s *SQLiteStore) GetUserChannel(userID, id string) (Channel, error) {
	row := s.db.QueryRow(
		`SELECT `+userChannelColumns+` FROM user_notification_channels WHERE id = ? AND user_id = ?`, id, userID)
	c, err := scanChannel(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Channel{}, ErrNotFound
	}
	return c, err
}

// ListUserChannels returns all of userID's channels.
func (s *SQLiteStore) ListUserChannels(userID string) ([]Channel, error) {
	return s.queryChannels(
		`SELECT `+userChannelColumns+` FROM user_notification_channels WHERE user_id = ? ORDER BY created_at, id`,
		userID)
}

// ListEnabledUserChannels returns userID's enabled channels — the set a
// personal delivery fans out to.
func (s *SQLiteStore) ListEnabledUserChannels(userID string) ([]Channel, error) {
	return s.queryChannels(
		`SELECT `+userChannelColumns+` FROM user_notification_channels WHERE user_id = ? AND enabled = 1 ORDER BY created_at, id`,
		userID)
}

// UpdateUserChannel replaces one of userID's channels, preserving the
// stored secret when the input omits it (same rules as the global Update).
func (s *SQLiteStore) UpdateUserChannel(userID, id string, in ChannelInput) (Channel, error) {
	if err := in.Validate(); err != nil {
		return Channel{}, err
	}
	existing, err := s.GetUserChannel(userID, id)
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
		`UPDATE user_notification_channels SET
		   name = ?, type = ?, enabled = ?, config = ?,
		   secret_ciphertext = ?, secret_nonce = ?, secret_version = ?, updated_at = ?
		 WHERE id = ? AND user_id = ?`,
		in.Name, string(in.Type), boolToInt(in.Enabled), string(cfgJSON),
		nullBytes(sealed.Ciphertext), nullBytes(sealed.Nonce), nullVersion(sealed),
		now.UnixNano(), id, userID,
	)
	if err != nil {
		return Channel{}, fmt.Errorf("notifications: update user channel: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Channel{}, ErrNotFound
	}
	return s.GetUserChannel(userID, id)
}

// DeleteUserChannel removes one of userID's channels.
func (s *SQLiteStore) DeleteUserChannel(userID, id string) error {
	res, err := s.db.Exec(`DELETE FROM user_notification_channels WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return fmt.Errorf("notifications: delete user channel: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetSubscription returns userID's subscription, or a disabled default when
// none is stored.
func (s *SQLiteStore) GetSubscription(userID string) (Subscription, error) {
	var cfg string
	err := s.db.QueryRow(`SELECT config FROM user_alert_subscription WHERE user_id = ?`, userID).Scan(&cfg)
	if errors.Is(err, sql.ErrNoRows) {
		return Subscription{Groups: []string{}, Severities: []string{}}, nil
	}
	if err != nil {
		return Subscription{}, fmt.Errorf("notifications: get subscription: %w", err)
	}
	var sub Subscription
	if err := json.Unmarshal([]byte(cfg), &sub); err != nil {
		return Subscription{}, fmt.Errorf("notifications: unmarshal subscription: %w", err)
	}
	return sub, nil
}

// SetSubscription upserts userID's subscription.
func (s *SQLiteStore) SetSubscription(userID string, in Subscription) error {
	if userID == "" {
		return fmt.Errorf("%w: userID is required", ErrInvalid)
	}
	if err := in.Validate(); err != nil {
		return err
	}
	cfg, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("notifications: marshal subscription: %w", err)
	}
	if _, err := s.db.Exec(
		`INSERT INTO user_alert_subscription (user_id, config) VALUES (?, ?)
		 ON CONFLICT(user_id) DO UPDATE SET config = excluded.config`, userID, string(cfg),
	); err != nil {
		return fmt.Errorf("notifications: set subscription: %w", err)
	}
	return nil
}

// ListSubscriptions returns every stored subscription, for the resolver
// that fans alerts out to subscribed users.
func (s *SQLiteStore) ListSubscriptions() ([]UserSubscription, error) {
	rows, err := s.db.Query(`SELECT user_id, config FROM user_alert_subscription ORDER BY user_id`)
	if err != nil {
		return nil, fmt.Errorf("notifications: list subscriptions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []UserSubscription{}
	for rows.Next() {
		var (
			us  UserSubscription
			cfg string
		)
		if err := rows.Scan(&us.UserID, &cfg); err != nil {
			return nil, fmt.Errorf("notifications: scan subscription: %w", err)
		}
		if err := json.Unmarshal([]byte(cfg), &us.Subscription); err != nil {
			return nil, fmt.Errorf("notifications: unmarshal subscription: %w", err)
		}
		out = append(out, us)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("notifications: list subscriptions rows: %w", err)
	}
	return out, nil
}

// GetUserPolicy returns userID's personal delivery policy, or DefaultPolicy
// when none is stored.
func (s *SQLiteStore) GetUserPolicy(userID string) (Policy, error) {
	var cfg string
	err := s.db.QueryRow(`SELECT config FROM user_notification_policy WHERE user_id = ?`, userID).Scan(&cfg)
	if errors.Is(err, sql.ErrNoRows) {
		return DefaultPolicy(), nil
	}
	if err != nil {
		return Policy{}, fmt.Errorf("notifications: get user policy: %w", err)
	}
	var p Policy
	if err := json.Unmarshal([]byte(cfg), &p); err != nil {
		return Policy{}, fmt.Errorf("notifications: unmarshal user policy: %w", err)
	}
	return p, nil
}

// SetUserPolicy validates and upserts userID's personal policy.
func (s *SQLiteStore) SetUserPolicy(userID string, in PolicyInput) error {
	if userID == "" {
		return fmt.Errorf("%w: userID is required", ErrInvalid)
	}
	if err := in.Validate(); err != nil {
		return err
	}
	cfg, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("notifications: marshal user policy: %w", err)
	}
	if _, err := s.db.Exec(
		`INSERT INTO user_notification_policy (user_id, config) VALUES (?, ?)
		 ON CONFLICT(user_id) DO UPDATE SET config = excluded.config`, userID, string(cfg),
	); err != nil {
		return fmt.Errorf("notifications: set user policy: %w", err)
	}
	return nil
}

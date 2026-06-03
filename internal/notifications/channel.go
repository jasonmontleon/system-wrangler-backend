// SPDX-License-Identifier: Apache-2.0

// Package notifications delivers fired/resolved alert transitions to
// operator-configured channels — email (SMTP-direct), Slack incoming
// webhooks, generic JSON webhooks, and SMS (a Twilio-shaped REST POST).
// It implements the alerts transition sink: the evaluator hands it each
// batch of fired/resolved transitions and the dispatcher fans them out
// to every enabled channel, recording the outcome.
//
// Per-rule routing, severity/quiet-hours, and per-user preferences are
// later roadmap items; this package delivers every transition to every
// enabled channel. Channel secrets (SMTP password, Slack URL, webhook
// auth header, SMS token) are sealed at rest via the secrets vault and
// never echoed back through the API.
package notifications

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"system-wrangler-backend/internal/secrets"
)

// Sentinel errors returned by the notifications package.
var (
	ErrNotFound = errors.New("notification channel not found")
	ErrInvalid  = errors.New("invalid notification channel")
)

const (
	maxNameLen = 255
	maxURLLen  = 2048
)

// Type identifies a channel's transport. Each interprets Config and the
// sealed Secret differently (see Validate / the senders).
type Type string

// Channel types.
const (
	TypeEmail   Type = "email"
	TypeSlack   Type = "slack"
	TypeWebhook Type = "webhook"
	TypeSMS     Type = "sms"
)

// IsValid reports whether t is a known channel type.
func (t Type) IsValid() bool {
	switch t {
	case TypeEmail, TypeSlack, TypeWebhook, TypeSMS:
		return true
	default:
		return false
	}
}

// requiresSecret reports whether a channel of this type cannot function
// without its sealed secret (Slack's webhook URL, the SMS auth token).
// Email's password and a generic webhook's auth header are optional —
// a relay may accept unauthenticated submission and a webhook may be
// unauthenticated.
func (t Type) requiresSecret() bool {
	return t == TypeSlack || t == TypeSMS
}

// Config holds the non-secret, type-specific settings. Only the fields
// relevant to a channel's Type are populated; it is safe to echo back
// through the API verbatim (the secret lives in the sealed Secret, not
// here).
type Config struct {
	// email
	SMTPHost   string `json:"smtpHost,omitempty"`
	SMTPPort   int    `json:"smtpPort,omitempty"`
	Username   string `json:"username,omitempty"`
	StartTLS   bool   `json:"startTLS,omitempty"`
	SkipVerify bool   `json:"skipVerify,omitempty"`
	// email + sms share From / To (addresses or phone numbers)
	From string   `json:"from,omitempty"`
	To   []string `json:"to,omitempty"`
	// webhook
	URL        string `json:"url,omitempty"`
	Method     string `json:"method,omitempty"`
	HeaderName string `json:"headerName,omitempty"`
	// sms
	BaseURL    string `json:"baseURL,omitempty"`
	AccountSID string `json:"accountSID,omitempty"`
}

// Sealed bundles the three values stored per encrypted secret:
// AES-256-GCM ciphertext, the nonce, and the key version it was sealed
// under. Mirrors credentials.Sealed / auth.Sealed deliberately to keep
// this package independent of those.
type Sealed struct {
	Ciphertext []byte
	Nonce      []byte
	Version    int
}

// IsZero reports whether s holds no ciphertext.
func (s Sealed) IsZero() bool { return len(s.Ciphertext) == 0 }

// SealWith encrypts plaintext through v.
func SealWith(v *secrets.Vault, plaintext []byte) (Sealed, error) {
	ct, nonce, ver, err := v.Seal(plaintext)
	if err != nil {
		return Sealed{}, err
	}
	return Sealed{Ciphertext: ct, Nonce: nonce, Version: ver}, nil
}

// OpenWith is the inverse of SealWith. Returns secrets.ErrUnknownVersion
// when the sealing key is not loaded and secrets.ErrDecrypt on auth
// failure.
func OpenWith(v *secrets.Vault, s Sealed) ([]byte, error) {
	return v.Open(s.Ciphertext, s.Nonce, s.Version)
}

// Channel is the persisted representation of one delivery channel.
type Channel struct {
	ID        string
	Name      string
	Type      Type
	Enabled   bool
	Config    Config
	Secret    Sealed // zero when the channel has no secret (unauth webhook/relay)
	CreatedBy string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ChannelInput is the operator-supplied subset accepted on create and
// update. Secret is the plaintext secret; on update an empty Secret
// means "keep the stored one" (preserve-on-omit, the credentials/auth
// pattern). Server-managed fields are filled by the store.
type ChannelInput struct {
	Name    string `json:"name"`
	Type    Type   `json:"type"`
	Enabled bool   `json:"enabled"`
	Config  Config `json:"config"`
	Secret  string `json:"secret,omitempty"`
}

// Validate normalizes and checks the input's name, type, and
// type-specific config, returning ErrInvalid wrapped with a reason.
// Secret presence is enforced by the store (which knows create vs
// update and can see the stored value), but a provided Slack secret is
// shape-checked here since it must be a URL.
func (in *ChannelInput) Validate() error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalid)
	}
	if len(in.Name) > maxNameLen {
		return fmt.Errorf("%w: name exceeds %d chars", ErrInvalid, maxNameLen)
	}
	if !in.Type.IsValid() {
		return fmt.Errorf("%w: type %q is not one of email/slack/webhook/sms", ErrInvalid, in.Type)
	}

	c := &in.Config
	c.From = strings.TrimSpace(c.From)
	c.SMTPHost = strings.TrimSpace(c.SMTPHost)
	c.Username = strings.TrimSpace(c.Username)
	c.URL = strings.TrimSpace(c.URL)
	c.HeaderName = strings.TrimSpace(c.HeaderName)
	c.BaseURL = strings.TrimSpace(c.BaseURL)
	c.AccountSID = strings.TrimSpace(c.AccountSID)
	c.To = trimList(c.To)

	switch in.Type {
	case TypeEmail:
		if c.SMTPHost == "" {
			return fmt.Errorf("%w: smtpHost is required for an email channel", ErrInvalid)
		}
		if c.SMTPPort < 1 || c.SMTPPort > 65535 {
			return fmt.Errorf("%w: smtpPort must be between 1 and 65535", ErrInvalid)
		}
		if c.From == "" {
			return fmt.Errorf("%w: from is required for an email channel", ErrInvalid)
		}
		if len(c.To) == 0 {
			return fmt.Errorf("%w: at least one recipient (to) is required", ErrInvalid)
		}
	case TypeSlack:
		if in.Secret != "" {
			if err := validateURL(in.Secret); err != nil {
				return fmt.Errorf("%w: slack webhook URL: %s", ErrInvalid, err.Error())
			}
		}
	case TypeWebhook:
		if err := validateURL(c.URL); err != nil {
			return fmt.Errorf("%w: url: %s", ErrInvalid, err.Error())
		}
		if c.Method == "" {
			c.Method = "POST"
		}
		if c.Method != "POST" && c.Method != "PUT" {
			return fmt.Errorf("%w: method must be POST or PUT", ErrInvalid)
		}
	case TypeSMS:
		if c.BaseURL == "" {
			c.BaseURL = DefaultSMSBaseURL
		}
		if err := validateURL(c.BaseURL); err != nil {
			return fmt.Errorf("%w: baseURL: %s", ErrInvalid, err.Error())
		}
		if c.AccountSID == "" {
			return fmt.Errorf("%w: accountSID is required for an sms channel", ErrInvalid)
		}
		if c.From == "" {
			return fmt.Errorf("%w: from is required for an sms channel", ErrInvalid)
		}
		if len(c.To) == 0 {
			return fmt.Errorf("%w: at least one recipient (to) is required", ErrInvalid)
		}
	}
	return nil
}

func validateURL(raw string) error {
	if raw == "" {
		return errors.New("URL is required")
	}
	if len(raw) > maxURLLen {
		return fmt.Errorf("URL exceeds %d chars", maxURLLen)
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %s", err.Error())
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("URL must be http or https")
	}
	return nil
}

func trimList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// ChannelDTO is the redacted, API-safe projection of a Channel: the
// non-secret config plus a flag for whether a secret is stored. The
// sealed secret itself is never serialized.
type ChannelDTO struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      Type      `json:"type"`
	Enabled   bool      `json:"enabled"`
	Config    Config    `json:"config"`
	HasSecret bool      `json:"hasSecret"`
	CreatedBy string    `json:"createdBy"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Redacted returns the API-safe view of the channel.
func (c Channel) Redacted() ChannelDTO {
	return ChannelDTO{
		ID:        c.ID,
		Name:      c.Name,
		Type:      c.Type,
		Enabled:   c.Enabled,
		Config:    c.Config,
		HasSecret: !c.Secret.IsZero(),
		CreatedBy: c.CreatedBy,
		CreatedAt: c.CreatedAt,
		UpdatedAt: c.UpdatedAt,
	}
}

// DeliveryStatus is the outcome of one send attempt.
type DeliveryStatus string

// DeliveryStatus values.
const (
	DeliverySuccess DeliveryStatus = "success"
	DeliveryFailed  DeliveryStatus = "failed"
	// DeliverySuppressed marks a transition that policy kept off the
	// channels entirely (a dashboard-only severity).
	DeliverySuppressed DeliveryStatus = "suppressed"
	// DeliveryDeferred marks a transition queued during quiet hours, to be
	// flushed to channels when the window ends.
	DeliveryDeferred DeliveryStatus = "deferred"
)

// Delivery is one historical send attempt, denormalized so it survives
// channel deletion and renders without a join.
type Delivery struct {
	ID          string         `json:"id"`
	ChannelID   string         `json:"channelId"`
	ChannelName string         `json:"channelName"`
	ChannelType Type           `json:"channelType"`
	Kind        string         `json:"kind"`
	RuleName    string         `json:"ruleName"`
	SystemID    string         `json:"systemId"`
	Status      DeliveryStatus `json:"status"`
	Error       string         `json:"error,omitempty"`
	At          time.Time      `json:"at"`
	// UserID is empty for shared/global deliveries and set for a personal
	// (per-user) channel delivery, scoping the per-user delivery log.
	UserID string `json:"-"`
}

// PendingDelivery is one transition deferred during quiet hours, holding
// the snapshot Message so the flusher can deliver it verbatim when the
// window ends. Channels are re-resolved from the rule's current routing at
// flush time, not stored here.
type PendingDelivery struct {
	ID         string
	RuleID     string
	RuleName   string
	SystemID   string
	Severity   string
	Kind       string // fired | resolved
	Message    Message
	EnqueuedAt time.Time
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Errorf("notifications: rand.Read: %w", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// SPDX-License-Identifier: Apache-2.0

// Package credentials owns ansible authentication state: one slot per
// scope (global / group / system) holding an optional ansible user
// and an optional SSH private key. The private key is stored sealed
// via the secrets package; the matching public key is stored in
// plaintext so operators can paste it into authorized_keys without a
// round-trip through the vault. Design and discipline:
// research/ansible-auth.md.
//
// The slot shape is deliberately permissive: a level can set just the
// user, just the key, or both. The Resolve helper walks
// system → group → global per field so a group can override the user
// while inheriting the global key (or vice versa) — the design's
// "in mixed fleets the username varies as much as the key does"
// case.
package credentials

import (
	"errors"
	"time"

	"system-wrangler-backend/internal/secrets"
)

// ScopeKind classifies what the slot's scope_id refers to. Stored as
// the ansible_credentials.scope_kind column.
type ScopeKind string

// Scope kinds. Global has an empty scope_id; Group and System point
// at the matching system_groups.id or hosts.id row.
const (
	ScopeGlobal ScopeKind = "global"
	ScopeGroup  ScopeKind = "group"
	ScopeSystem ScopeKind = "system"
)

// IsValid reports whether s is one of the three known scope kinds.
func (s ScopeKind) IsValid() bool {
	switch s {
	case ScopeGlobal, ScopeGroup, ScopeSystem:
		return true
	}
	return false
}

// Origin records where the private key came from. Stored as the
// ansible_credentials.origin column when a key is present; NULL when
// the slot only holds an ansible user.
type Origin string

// Origin values. SW-generated keys can be regenerated; user-supplied
// keys must be re-uploaded by the operator when the corresponding
// authorized_keys entry is rotated.
const (
	OriginSWGenerated  Origin = "sw_generated"
	OriginUserSupplied Origin = "user_supplied"
)

// IsValid reports whether o is one of the two known origins.
func (o Origin) IsValid() bool {
	return o == OriginSWGenerated || o == OriginUserSupplied
}

// Sealed bundles the three values stored per encrypted column:
// AES-256-GCM ciphertext (incl. auth tag), the 12-byte nonce, and the
// integer version of the key the row was sealed under. Mirrors
// auth.Sealed deliberately — duplicating the struct keeps this
// package independent of auth (the package graph already has auth
// importing credentials' future siblings via rbac).
type Sealed struct {
	Ciphertext []byte
	Nonce      []byte
	Version    int
}

// IsZero reports whether s holds no ciphertext. Used by the store
// reader to distinguish "this slot has a key" from "this slot only
// has an ansible user."
func (s Sealed) IsZero() bool {
	return len(s.Ciphertext) == 0
}

// SealWith encrypts plaintext through v and returns the Sealed
// triple. Centralised here so handlers don't repeat the three-value
// dance, matching the auth.SealWith / OpenWith pattern.
func SealWith(v *secrets.Vault, plaintext []byte) (Sealed, error) {
	ct, nonce, ver, err := v.Seal(plaintext)
	if err != nil {
		return Sealed{}, err
	}
	return Sealed{Ciphertext: ct, Nonce: nonce, Version: ver}, nil
}

// OpenWith is the inverse of SealWith. Returns
// secrets.ErrUnknownVersion when the key version is not loaded in v
// (the mismatched-key-restore case), and secrets.ErrDecrypt on any
// authentication failure.
func OpenWith(v *secrets.Vault, s Sealed) ([]byte, error) {
	return v.Open(s.Ciphertext, s.Nonce, s.Version)
}

// Slot is one row from ansible_credentials. A slot must hold at
// least one of: AnsibleUser, or (PublicKey + PrivateKey + Origin)
// — otherwise it's redundant with "no row at this scope" and the
// store rejects it.
type Slot struct {
	ID          string
	ScopeKind   ScopeKind
	ScopeID     string // empty for ScopeGlobal
	AnsibleUser string // empty means "inherit from a higher scope"
	PublicKey   string // OpenSSH authorized_keys form; empty when only AnsibleUser is set
	PrivateKey  Sealed // zero when only AnsibleUser is set
	Origin      Origin // zero when only AnsibleUser is set
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// HasKey reports whether the slot carries a private/public key
// pair. The two key fields move together — the store enforces this
// at write time.
func (s Slot) HasKey() bool {
	return s.PublicKey != "" && !s.PrivateKey.IsZero()
}

// Validate is the input-side check before Upsert. It enforces the
// "at least one of user or key" invariant and the "origin must be
// set when a key is present" invariant. Storage-shape validation
// (scope_kind, scope_id format) is checked by the store.
func (s Slot) Validate() error {
	if !s.ScopeKind.IsValid() {
		return errors.New("credentials: scope_kind must be global, group, or system")
	}
	if s.ScopeKind == ScopeGlobal && s.ScopeID != "" {
		return errors.New("credentials: scope_id must be empty for global scope")
	}
	if s.ScopeKind != ScopeGlobal && s.ScopeID == "" {
		return errors.New("credentials: scope_id required for group/system scope")
	}
	hasUser := s.AnsibleUser != ""
	hasKey := s.HasKey()
	hasPub := s.PublicKey != ""
	hasPriv := !s.PrivateKey.IsZero()
	if !hasUser && !hasKey {
		return errors.New("credentials: slot must set at least ansible_user or a key pair")
	}
	if hasPub != hasPriv {
		return errors.New("credentials: public_key and private_key must be set together")
	}
	if hasKey && !s.Origin.IsValid() {
		return errors.New("credentials: origin must be sw_generated or user_supplied when a key is present")
	}
	if !hasKey && s.Origin != "" {
		return errors.New("credentials: origin must be empty when no key is set")
	}
	return nil
}

// Sentinel errors returned by the credentials store and resolver.
var (
	ErrNotFound       = errors.New("credentials: slot not found")
	ErrInvalid        = errors.New("credentials: invalid slot")
	ErrNoCredentials  = errors.New("credentials: no credentials resolved for system")
	ErrIncompleteFlow = errors.New("credentials: resolved user or key is missing")
)

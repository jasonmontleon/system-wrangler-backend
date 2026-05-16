// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"errors"
)

// Resolved is the effective credential a connection-time caller
// receives for a given system. The Source fields record which slot
// each field actually came from so the UI (and the audit row) can
// say "user inherited from group X; key inherited from global."
type Resolved struct {
	AnsibleUser string
	UserSource  ScopeKind

	PublicKey  string
	PrivateKey Sealed
	KeySource  ScopeKind

	// KeyOrigin is the origin recorded on the slot the key came from
	// (sw_generated or user_supplied). Zero when no key resolves.
	KeyOrigin Origin
}

// Resolve walks system → group → global and returns the effective
// credential for the supplied system. systemGroupID is the system's
// current group_id (nil for ungrouped). Each field is resolved
// independently: a group-scope override of `ansible_user` doesn't
// force the key to come from the same level.
//
// Returns ErrIncompleteFlow when at least one of user or key
// resolved but the other didn't — that's a configuration error the
// operator must fix before runs can connect. Returns ErrNoCredentials
// when nothing resolved at any level.
func Resolve(store Store, systemID string, systemGroupID *string) (Resolved, error) {
	if systemID == "" {
		return Resolved{}, errors.New("credentials: systemID is required")
	}
	scopes := buildScopeChain(systemID, systemGroupID)
	var resolved Resolved
	for _, scope := range scopes {
		slot, err := store.GetByScope(scope.kind, scope.id)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return Resolved{}, err
		}
		// Per-field merge: a field already resolved by a more
		// specific scope wins over a higher-level value.
		if resolved.AnsibleUser == "" && slot.AnsibleUser != "" {
			resolved.AnsibleUser = slot.AnsibleUser
			resolved.UserSource = slot.ScopeKind
		}
		if resolved.PublicKey == "" && slot.HasKey() {
			resolved.PublicKey = slot.PublicKey
			resolved.PrivateKey = slot.PrivateKey
			resolved.KeyOrigin = slot.Origin
			resolved.KeySource = slot.ScopeKind
		}
	}
	if resolved.AnsibleUser == "" && resolved.PublicKey == "" {
		return Resolved{}, ErrNoCredentials
	}
	if resolved.AnsibleUser == "" || resolved.PublicKey == "" {
		return Resolved{}, ErrIncompleteFlow
	}
	return resolved, nil
}

type scopeRef struct {
	kind ScopeKind
	id   string
}

// buildScopeChain returns the ordered list of scopes to consult,
// most-specific first. The group level is skipped when the system is
// ungrouped — the resolver still tries global so an unassigned
// system can fall through to the install-wide default.
func buildScopeChain(systemID string, systemGroupID *string) []scopeRef {
	chain := []scopeRef{{ScopeSystem, systemID}}
	if systemGroupID != nil && *systemGroupID != "" {
		chain = append(chain, scopeRef{ScopeGroup, *systemGroupID})
	}
	chain = append(chain, scopeRef{ScopeGlobal, ""})
	return chain
}

// SPDX-License-Identifier: Apache-2.0

package exclusions

// Store is the persistence boundary. Handler talks to Store; main.go
// wires the SQLite implementation. Tests against MemStore would be
// cheap but the SQLite store is the only path and the project uses
// in-memory SQLite for unit tests, so a separate MemStore isn't
// worth the surface area.
type Store interface {
	// Create persists a new row. Returns ErrDuplicate on the
	// (scope, target_id, updater, pattern) uniqueness violation.
	Create(scope Scope, targetID, updater, pattern, reason, createdBy string) (Exclusion, error)
	// Get returns the row by id. Returns ErrNotFound if absent.
	Get(id string) (Exclusion, error)
	// Delete removes the row by id. Returns ErrNotFound if absent.
	Delete(id string) error
	// ListGlobal returns every ScopeGlobal row, ordered by created_at.
	ListGlobal() ([]Exclusion, error)
	// ListGroup returns every ScopeGroup row for the given group id.
	ListGroup(groupID string) ([]Exclusion, error)
	// ListSystem returns every ScopeSystem row for the given system id.
	ListSystem(systemID string) ([]Exclusion, error)
	// ResolveForSystem returns the deduplicated list of patterns that
	// apply when the given updater runs against the given system. The
	// union spans every scope: global rows whose updater matches,
	// group rows whose target group contains the system AND updater
	// matches, system rows for the system AND updater matches. The
	// AllUpdaters sentinel matches every updater id.
	ResolveForSystem(systemID, updaterID string) ([]string, error)
	// ResolveEffectiveForSystem returns the same union as
	// ResolveForSystem but as fully-populated Exclusion rows the UI
	// can render with attribution. Internal calls that just need the
	// patterns use ResolveForSystem; the SPA's "what will be skipped"
	// view uses this richer shape.
	ResolveEffectiveForSystem(systemID, updaterID string) ([]Exclusion, error)
}

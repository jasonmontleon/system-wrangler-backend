// SPDX-License-Identifier: Apache-2.0

package labels

// Store is the persistence boundary for system labels. Implementations
// must be goroutine-safe and enforce the "one value per key per system"
// rule: Set on an existing (system_id, key) overwrites the value rather
// than creating a duplicate row.
type Store interface {
	// Set inserts or updates a label on a system. Value is nullable.
	// AllowReserved permits the reserved prefix for internal callers
	// (system-set labels); user-facing handlers pass false.
	Set(systemID, key string, value *string, allowReserved bool) (Label, error)
	// Delete removes a label by (system_id, key). Returns ErrNotFound
	// if no such row exists.
	Delete(systemID, key string) error
	// ForSystem returns every label attached to the given system,
	// ordered by key.
	ForSystem(systemID string) ([]Label, error)
	// ForSystems returns labels for many systems in one round trip,
	// keyed by system_id. Useful for the /api/systems list response
	// which embeds each system's labels inline.
	ForSystems(systemIDs []string) (map[string][]Label, error)
	// Summary returns distinct keys with their value cardinalities, for
	// autocomplete and the filter bar. The order is by key ascending.
	Summary() ([]KeySummary, error)
}

// KeySummary describes a label key's value set: nil for bare-tag-only,
// or each observed value. Bare tags (NULL values) are represented as a
// summary entry with Value == nil.
type KeySummary struct {
	Key    string         `json:"key"`
	Values []ValueSummary `json:"values"`
	// Count is the total number of (system_id, key) rows under this
	// key, summing all values + the bare-tag bucket.
	Count int `json:"count"`
}

// ValueSummary is one observed value for a key plus how many systems
// carry that exact (key, value) pair. Value is nil for the bare-tag
// bucket.
type ValueSummary struct {
	Value *string `json:"value"`
	Count int     `json:"count"`
}

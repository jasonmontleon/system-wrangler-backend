// SPDX-License-Identifier: Apache-2.0

package holds

// Store is the persistence boundary. The Runner reads via List during
// pre-apply reconcile and writes via Replace after the playbook
// returns successfully. RemoveSystem is called from the system-delete
// cascade so deleted hosts don't leak rows.
type Store interface {
	// List returns the patterns SW manages on (systemID, updaterID),
	// sorted ascending. Empty slice when none.
	List(systemID, updaterID string) ([]string, error)
	// Replace sets the managed-pattern set for (systemID, updaterID)
	// to exactly `desired`. Rows whose pattern isn't in desired are
	// deleted; rows for patterns in desired are inserted if absent.
	// Idempotent — calling with an unchanged set is a no-op modulo
	// the SetAt timestamp on inserts.
	Replace(systemID, updaterID string, desired []string) error
	// RemoveSystem deletes every hold row for the given system. Used
	// when a host is deleted from inventory so stale rows don't
	// accumulate. Returns the affected row count.
	RemoveSystem(systemID string) (int, error)
}

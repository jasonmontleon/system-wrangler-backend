// SPDX-License-Identifier: Apache-2.0

package groups

// Store is the persistence boundary for groups. Implementations must
// populate SystemCount on every read from a JOIN against the systems
// table, so callers never have to second-guess the membership count.
type Store interface {
	Create(in GroupInput) (Group, error)
	Get(id string) (Group, error)
	List() ([]Group, error)
	Rename(id string, in GroupInput) (Group, error)
	Delete(id string) error
}

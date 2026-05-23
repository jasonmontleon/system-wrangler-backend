// SPDX-License-Identifier: Apache-2.0

package exporters

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Registry is the live view callers use to resolve "what exporter
// installers are registered." Mirrors updaters.Registry — builtins
// are baked in at construction; custom rows are pulled from the
// Store on every All / Get call so a fresh Create / Update / Delete
// is immediately visible without a refresh ceremony.
type Registry struct {
	store    Store
	builtins map[string]Definition

	mu sync.RWMutex
}

// NewRegistry wires a Registry with the supplied store and the
// compiled-in builtins. Panics on duplicate or misnamed builtin IDs
// — programmer errors, not runtime conditions.
func NewRegistry(store Store) *Registry {
	r := &Registry{
		store:    store,
		builtins: make(map[string]Definition),
	}
	for _, b := range Builtins() {
		if !IsBuiltinID(b.ID) {
			panic(fmt.Errorf("exporters: builtin id %q missing %q prefix", b.ID, PrefixBuiltin))
		}
		if _, dupe := r.builtins[b.ID]; dupe {
			panic(fmt.Errorf("exporters: duplicate builtin id %q", b.ID))
		}
		b.Source = SourceBuiltin
		r.builtins[b.ID] = b
	}
	return r
}

// All returns every active definition (builtins + non-deleted custom),
// sorted by display name then id. Soft-deleted custom rows are
// omitted; call Get for the audit/history path.
func (r *Registry) All() ([]Definition, error) {
	custom, err := r.store.ListCustom()
	if err != nil {
		return nil, err
	}
	r.mu.RLock()
	out := make([]Definition, 0, len(r.builtins)+len(custom))
	for _, b := range r.builtins {
		out = append(out, b)
	}
	r.mu.RUnlock()
	out = append(out, custom...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].DisplayName == out[j].DisplayName {
			return out[i].ID < out[j].ID
		}
		return out[i].DisplayName < out[j].DisplayName
	})
	return out, nil
}

// Get resolves one definition by id, honoring the source-namespace
// prefix. Returns ErrNotFound when the id is unknown. For custom
// ids, returns soft-deleted rows so historical audit / run-history
// lookups can render the original name.
func (r *Registry) Get(id string) (Definition, error) {
	if IsBuiltinID(id) {
		r.mu.RLock()
		defer r.mu.RUnlock()
		b, ok := r.builtins[id]
		if !ok {
			return Definition{}, ErrNotFound
		}
		return b, nil
	}
	if IsCustomID(id) {
		return r.store.GetCustom(id)
	}
	return Definition{}, fmt.Errorf("%w: id %q has no source prefix", ErrInvalid, id)
}

// CreateCustom validates the id namespace and delegates to the
// store. Builtin-prefix ids are refused.
func (r *Registry) CreateCustom(d Definition) (Definition, error) {
	if IsBuiltinID(d.ID) {
		return Definition{}, fmt.Errorf("%w: %q reserved for builtins", ErrReservedID, PrefixBuiltin)
	}
	d.Source = SourceCustom
	return r.store.CreateCustom(d)
}

// UpdateCustom delegates to the store. Builtins cannot be modified
// at runtime — pass through and let the store's ID-prefix guard
// fire.
func (r *Registry) UpdateCustom(d Definition) (Definition, error) {
	if IsBuiltinID(d.ID) {
		return Definition{}, ErrBuiltinWrite
	}
	d.Source = SourceCustom
	return r.store.UpdateCustom(d)
}

// DeleteCustom soft-deletes a custom definition. Builtins cannot be
// deleted at runtime.
func (r *Registry) DeleteCustom(id string, at time.Time) error {
	if IsBuiltinID(id) {
		return ErrBuiltinWrite
	}
	if !IsCustomID(id) {
		return fmt.Errorf("%w: id %q has no source prefix", ErrInvalid, id)
	}
	return r.store.DeleteCustom(id, at)
}

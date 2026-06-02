// SPDX-License-Identifier: Apache-2.0

// Package targeting resolves a target spec (kind + value) to the set of
// systems it points at, evaluated against the current inventory at call
// time. It is the shared substrate behind any feature that lets an
// operator aim work or rules at "every system / a group / a label
// selector / a fixed list" — schedules and alerts both speak this
// grammar. Resolution intentionally re-runs on every call so group
// membership changes and newly-joined systems are picked up
// automatically.
package targeting

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"system-wrangler-backend/internal/labels"
	"system-wrangler-backend/internal/systems"
)

// ErrInvalid is returned (wrapped) when a kind/value pair is malformed.
// Callers can errors.Is against it without depending on the message.
var ErrInvalid = errors.New("invalid target")

// Kind identifies how a target spec chooses its systems. Each kind
// interprets the companion value differently:
//
//   - Global: value is "" — every system in the inventory.
//   - Group: value is a System Group id (string).
//   - Systems: value is a JSON array of system ids.
//   - Selector: value is a k8s-subset label selector expression.
//
// The set is finite by design; a new kind requires a code change so a
// feature can't accidentally introduce one with bad scoping.
type Kind string

// Kind values.
const (
	Global   Kind = "global"
	Group    Kind = "group"
	Systems  Kind = "systems"
	Selector Kind = "selector"
)

// SystemStore is the slice of systems.Store the resolver needs.
type SystemStore interface {
	List() ([]systems.System, error)
	Get(id string) (systems.System, error)
}

// LabelStore is the slice of labels.Store the resolver needs to
// evaluate selector targets in-memory.
type LabelStore interface {
	ForSystems(systemIDs []string) (map[string][]labels.Label, error)
}

// ValidateValue checks that value is well-formed for kind, returning
// ErrInvalid (wrapped with a precise reason) when it is not. The value
// is assumed already whitespace-trimmed by the caller; this function
// does not mutate it.
func ValidateValue(kind Kind, value string) error {
	switch kind {
	case Global:
		if value != "" {
			return fmt.Errorf("%w: targetValue must be empty when targetKind=global", ErrInvalid)
		}
	case Group:
		if value == "" {
			return fmt.Errorf("%w: targetValue (group id) is required when targetKind=group", ErrInvalid)
		}
	case Systems:
		var ids []string
		if err := json.Unmarshal([]byte(value), &ids); err != nil {
			return fmt.Errorf("%w: targetValue must be a JSON array of system ids: %s", ErrInvalid, err.Error())
		}
		if len(ids) == 0 {
			return fmt.Errorf("%w: targetValue must contain at least one system id when targetKind=systems", ErrInvalid)
		}
		for _, id := range ids {
			if strings.TrimSpace(id) == "" {
				return fmt.Errorf("%w: targetValue contains an empty system id", ErrInvalid)
			}
		}
	case Selector:
		if value == "" {
			return fmt.Errorf("%w: targetValue (selector expression) is required when targetKind=selector", ErrInvalid)
		}
		if _, err := labels.ParseSelector(value); err != nil {
			return fmt.Errorf("%w: %s", ErrInvalid, err.Error())
		}
	default:
		return fmt.Errorf("%w: targetKind %q is not one of global/group/systems/selector", ErrInvalid, kind)
	}
	return nil
}

// Resolve returns the systems the kind+value point at, evaluated
// against the current inventory. Unreachable systems are NOT
// pre-filtered — callers decide what to do with them. A pinned system
// id that has gone missing (kind=systems) yields a placeholder System
// carrying StatusUnreachable so the caller can still account for it
// rather than silently dropping it.
func Resolve(kind Kind, value string, sys SystemStore, lbl LabelStore) ([]systems.System, error) {
	switch kind {
	case Global:
		return sys.List()
	case Group:
		all, err := sys.List()
		if err != nil {
			return nil, fmt.Errorf("targeting: resolve group: %w", err)
		}
		out := make([]systems.System, 0, len(all))
		for _, s := range all {
			if s.GroupID != nil && *s.GroupID == value {
				out = append(out, s)
			}
		}
		return out, nil
	case Systems:
		var ids []string
		if err := json.Unmarshal([]byte(value), &ids); err != nil {
			return nil, fmt.Errorf("targeting: resolve systems list: %w", err)
		}
		out := make([]systems.System, 0, len(ids))
		for _, id := range ids {
			s, err := sys.Get(id)
			if err != nil {
				out = append(out, systems.System{ID: id, Name: id, Status: systems.StatusUnreachable})
				continue
			}
			out = append(out, s)
		}
		return out, nil
	case Selector:
		sel, err := labels.ParseSelector(value)
		if err != nil {
			return nil, fmt.Errorf("targeting: parse selector: %w", err)
		}
		all, err := sys.List()
		if err != nil {
			return nil, fmt.Errorf("targeting: resolve selector: %w", err)
		}
		ids := make([]string, 0, len(all))
		for _, s := range all {
			ids = append(ids, s.ID)
		}
		byID, err := lbl.ForSystems(ids)
		if err != nil {
			return nil, fmt.Errorf("targeting: load labels: %w", err)
		}
		out := make([]systems.System, 0, len(all))
		for _, s := range all {
			if sel.Matches(byID[s.ID]) {
				out = append(out, s)
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: unsupported targetKind %q", ErrInvalid, kind)
	}
}

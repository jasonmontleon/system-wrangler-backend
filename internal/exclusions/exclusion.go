// SPDX-License-Identifier: Apache-2.0

// Package exclusions owns the "do not let this updater upgrade this
// package" lists at global / group / system scope. The Runner threads
// the resolved union into each apply.yml as the `sw_excluded_packages`
// extra-var so manager-native exclude flags (dnf --exclude, pacman
// --ignore, etc.) honour the operator's intent without a hold-based
// state-sync step. v1: per-invocation only. v2 picks up the
// hold-based managers (apt-mark hold, brew pin) — out of scope here.
// Full design: research/package-exclusions.md.
package exclusions

import (
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Scope classifies the layer an exclusion lives at. Stored as the
// package_exclusions.scope column; the union resolver folds matching
// rows from every scope at apply time.
type Scope string

// Scope values stored in package_exclusions.scope.
const (
	ScopeGlobal Scope = "global"
	ScopeGroup  Scope = "group"
	ScopeSystem Scope = "system"
)

// AllUpdaters is the sentinel updater id meaning "applies to every
// updater on this scope." Useful for global pins like "never touch our
// kernel regardless of which manager normally owns it."
const AllUpdaters = "*"

// MaxReasonLen caps the free-text reason field. 1 KB leaves room for a
// short rationale + a URL without inviting Wikipedia-length essays.
const MaxReasonLen = 1024

// MaxPatternLen caps the package name / glob. Real package names are
// well under 200 chars; 256 leaves slack for future glob syntax.
const MaxPatternLen = 256

// Exclusion is one persisted row. TargetID is empty for ScopeGlobal,
// the group id for ScopeGroup, the system id for ScopeSystem.
// Updater is either a registered updater id (builtin.<name> /
// custom.<name>) or AllUpdaters. Pattern is verbatim — each updater
// applies it in its native syntax. Reason is operator-provided
// rationale; empty when omitted.
type Exclusion struct {
	ID        string    `json:"id"`
	Scope     Scope     `json:"scope"`
	TargetID  string    `json:"targetId,omitempty"`
	Updater   string    `json:"updater"`
	Pattern   string    `json:"pattern"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	CreatedBy string    `json:"createdBy"`
}

// Input is the user-supplied subset accepted on create. Scope and
// TargetID are pinned by the handler from the route (admin / group /
// system) so callers can't smuggle a row into the wrong layer through
// the body.
type Input struct {
	Updater string `json:"updater"`
	Pattern string `json:"pattern"`
	Reason  string `json:"reason"`
}

// EffectiveRow is the rendered union the SystemDetail "what will be
// skipped" view consumes. It carries the source scope + the human
// label so the UI can render a "comes from <group X>" attribution
// without a second round-trip.
type EffectiveRow struct {
	Exclusion
	SourceLabel string `json:"sourceLabel,omitempty"`
}

// Sentinel errors returned by the store and handler.
var (
	ErrNotFound  = errors.New("exclusion not found")
	ErrInvalid   = errors.New("invalid exclusion")
	ErrDuplicate = errors.New("exclusion already exists")
)

// updaterIDPattern matches the registered-updater id charset, the
// AllUpdaters sentinel, or either of the two prefix-only forms. The
// store validates the id resolves later when the Resolve callback
// fires; this regex is just an input-shape guard.
var updaterIDPattern = regexp.MustCompile(
	`^(?:\*|(?:builtin|custom)\.[A-Za-z0-9_-]{1,64})$`,
)

// Validate enforces the input-side invariants. The handler runs this
// before delegating to the store so a malformed body never reaches
// the SQL layer.
func (in Input) Validate() error {
	updater := strings.TrimSpace(in.Updater)
	pattern := strings.TrimSpace(in.Pattern)
	if updater == "" {
		return fmt.Errorf("%w: updater required", ErrInvalid)
	}
	if !updaterIDPattern.MatchString(updater) {
		return fmt.Errorf("%w: updater must be '*' or builtin.<id> / custom.<id>", ErrInvalid)
	}
	if pattern == "" {
		return fmt.Errorf("%w: pattern required", ErrInvalid)
	}
	if len(pattern) > MaxPatternLen {
		return fmt.Errorf("%w: pattern exceeds %d chars", ErrInvalid, MaxPatternLen)
	}
	if len(in.Reason) > MaxReasonLen {
		return fmt.Errorf("%w: reason exceeds %d chars", ErrInvalid, MaxReasonLen)
	}
	return nil
}

// IsValid reports whether s is one of the three persisted scope
// strings. Stored values come straight from string literals in this
// package; the helper exists for handler-side guards on routes that
// derive Scope from URL shape.
func (s Scope) IsValid() bool {
	switch s {
	case ScopeGlobal, ScopeGroup, ScopeSystem:
		return true
	}
	return false
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Errorf("exclusions: rand.Read: %w", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

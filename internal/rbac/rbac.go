// SPDX-License-Identifier: Apache-2.0

// Package rbac assigns six roles in two tiers — Global / Group ×
// Admin / Operator / Auditor — and resolves each authenticated request
// to a Scope that handlers consult before reading or mutating data.
// Design and discipline: research/rbac.md.
//
// The package owns the user_roles join table; assignments are
// (user_id, group_id, role) tuples where group_id == NULL means
// "global." Resolve(userID) collapses a user's rows into a Scope; the
// middleware stamps that Scope onto request context after
// auth.RequireUser has run.
package rbac

import (
	"context"
	"errors"
	"sort"
)

// Role is the role half of a user_roles row. Three values; the tier
// (global vs group-scoped) is carried by Assignment.GroupID being
// nil or non-nil, not by the Role string itself.
type Role string

// Role values stored in user_roles.role. Admin ⊇ Operator ⊇ Auditor in
// terms of read permissions at each tier; Operator adds "run
// operations," Admin adds "edit / add / remove."
const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleAuditor  Role = "auditor"
)

// IsValid reports whether r is one of the three known role values.
func (r Role) IsValid() bool {
	switch r {
	case RoleAdmin, RoleOperator, RoleAuditor:
		return true
	}
	return false
}

// rank orders roles so the "highest" of a pair can be picked when a
// user holds multiple roles at the same scope (e.g. both Operator and
// Auditor on a group — keep Operator). Admin is highest.
func (r Role) rank() int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleOperator:
		return 2
	case RoleAuditor:
		return 1
	}
	return 0
}

// Assignment is one row from user_roles. GroupID == nil encodes a
// global-scope assignment.
type Assignment struct {
	UserID  string
	GroupID *string
	Role    Role
}

// Sentinel errors returned by the rbac store and helpers.
var (
	ErrInvalid   = errors.New("rbac: invalid input")
	ErrNotFound  = errors.New("rbac: assignment not found")
	ErrDuplicate = errors.New("rbac: assignment already exists")
	ErrNoScope   = errors.New("rbac: no scope on request context")
)

// Scope is the resolved permission set for an authenticated request.
// Compute once per request via Resolve and stamp on context with
// WithScope; downstream handlers read it via ScopeFromContext.
//
// Highest-role-wins is precomputed: a user holding both Operator and
// Auditor on a group ends up with Operator in groupRole; the original
// Assignments slice is preserved on Roles for callers that need it
// (e.g. the "list my role assignments" UI).
type Scope struct {
	UserID string
	Roles  []Assignment

	// Global is the highest global role the user holds, "" if none.
	Global Role

	// groupRole is groupID -> highest role on that group. Lookups go
	// through methods so the storage shape stays internal.
	groupRole map[string]Role
}

// NewScope builds a Scope from a deduplicated slice of assignments.
// The slice should already represent the user's full set; NewScope
// just precomputes the lookup maps. Order-independent.
func NewScope(userID string, rows []Assignment) Scope {
	s := Scope{
		UserID:    userID,
		Roles:     append([]Assignment(nil), rows...),
		groupRole: map[string]Role{},
	}
	for _, a := range rows {
		if a.GroupID == nil {
			if a.Role.rank() > s.Global.rank() {
				s.Global = a.Role
			}
			continue
		}
		if cur, ok := s.groupRole[*a.GroupID]; !ok || a.Role.rank() > cur.rank() {
			s.groupRole[*a.GroupID] = a.Role
		}
	}
	return s
}

// HasAnyRole reports whether the user holds any role anywhere. A user
// with zero rows in user_roles cannot see or do anything; the auth
// middleware still admits them so they can hit /api/auth/me, but every
// privileged endpoint refuses.
func (s Scope) HasAnyRole() bool {
	return s.Global != "" || len(s.groupRole) > 0
}

// IsGlobalAdmin reports whether the user holds the global Admin role.
// The only role that can manage users, manage groups, create raw
// systems, or grant Group Admin to others.
func (s Scope) IsGlobalAdmin() bool { return s.Global == RoleAdmin }

// IsGlobalOperator reports whether the user holds global Admin or
// global Operator. Used by "run an operation anywhere" gates.
func (s Scope) IsGlobalOperator() bool {
	return s.Global == RoleAdmin || s.Global == RoleOperator
}

// IsGlobalAuditor reports whether the user holds any global role. The
// three global roles all see every system and every audit row; what
// differs is what they can do beyond reading. Equivalent to "any
// global role."
func (s Scope) IsGlobalAuditor() bool { return s.Global != "" }

// RoleOnGroup returns the user's effective role on groupID, or "" if
// they have no group-scoped role on it. Independent of any global
// role — callers that need "can read at all" should compose
// IsGlobalAuditor || RoleOnGroup != "".
func (s Scope) RoleOnGroup(groupID string) Role { return s.groupRole[groupID] }

// CanReadGroup reports whether the user can see groupID at all.
// Global roles see every group; group-scoped users see only the
// groups they hold any role on.
func (s Scope) CanReadGroup(groupID string) bool {
	if s.IsGlobalAuditor() {
		return true
	}
	_, ok := s.groupRole[groupID]
	return ok
}

// CanOperateGroup reports whether the user can run operations against
// systems in groupID — Global Admin/Operator anywhere, Group
// Admin/Operator on this group.
func (s Scope) CanOperateGroup(groupID string) bool {
	if s.IsGlobalOperator() {
		return true
	}
	r := s.groupRole[groupID]
	return r == RoleAdmin || r == RoleOperator
}

// CanAdminGroup reports whether the user can edit / delete systems in
// groupID and grant Operator/Auditor on it. Global Admin or Group
// Admin of this group.
func (s Scope) CanAdminGroup(groupID string) bool {
	return s.IsGlobalAdmin() || s.groupRole[groupID] == RoleAdmin
}

// CanReadSystem reports whether the user can see a system whose
// current group_id is the supplied value (nil = ungrouped). Ungrouped
// systems are install-wide and visible only to global roles, per
// research/rbac.md.
func (s Scope) CanReadSystem(systemGroupID *string) bool {
	if s.IsGlobalAuditor() {
		return true
	}
	if systemGroupID == nil {
		return false
	}
	_, ok := s.groupRole[*systemGroupID]
	return ok
}

// CanCreateSystem reports whether the user can create a raw (initially
// ungrouped) system. Per research/rbac.md, only Global Admin — Group
// Admin can't create raw systems because they'd land ungrouped,
// outside any group scope.
func (s Scope) CanCreateSystem() bool { return s.IsGlobalAdmin() }

// CanDeleteSystem reports whether the user can delete the system
// whose current group_id is the supplied value. Global Admin always;
// Group Admin of the system's current group.
func (s Scope) CanDeleteSystem(systemGroupID *string) bool {
	if s.IsGlobalAdmin() {
		return true
	}
	if systemGroupID == nil {
		return false
	}
	return s.groupRole[*systemGroupID] == RoleAdmin
}

// CanEditSystem reports whether the user can mutate non-membership
// attributes of a system whose current group_id is the supplied value
// (e.g. the operator-declared platform flag). Same shape as
// CanOperateGroup but parameterised against a system row's nullable
// group_id: ungrouped systems are visible only to global Operators.
func (s Scope) CanEditSystem(systemGroupID *string) bool {
	if s.IsGlobalOperator() {
		return true
	}
	if systemGroupID == nil {
		return false
	}
	r := s.groupRole[*systemGroupID]
	return r == RoleAdmin || r == RoleOperator
}

// CanMoveSystem reports whether the user can change the group_id of a
// system from fromGroupID to toGroupID. Global Admin always; Group
// Admin can move between groups they admin (both ends must be a group
// they admin), and cannot move into or out of ungrouped (which is
// install-wide).
func (s Scope) CanMoveSystem(fromGroupID, toGroupID *string) bool {
	if s.IsGlobalAdmin() {
		return true
	}
	if fromGroupID == nil || toGroupID == nil {
		return false
	}
	return s.CanAdminGroup(*fromGroupID) && s.CanAdminGroup(*toGroupID)
}

// CanManageGroups reports whether the user can create / rename /
// delete groups. Global Admin only — group lifecycle is install-wide
// per research/rbac.md.
func (s Scope) CanManageGroups() bool { return s.IsGlobalAdmin() }

// CanManageUsers reports whether the user can create / disable /
// password-reset other users. Global Admin only.
func (s Scope) CanManageUsers() bool { return s.IsGlobalAdmin() }

// CanGrantOnGroup reports whether the user can assign `role` on
// groupID. Global Admin can assign any role anywhere. Group Admin of
// groupID can assign Operator and Auditor on that group; assigning
// Admin is install-wide-only escalation.
func (s Scope) CanGrantOnGroup(groupID string, role Role) bool {
	if !role.IsValid() {
		return false
	}
	if s.IsGlobalAdmin() {
		return true
	}
	if s.groupRole[groupID] != RoleAdmin {
		return false
	}
	return role == RoleOperator || role == RoleAuditor
}

// CanGrantGlobal reports whether the user can assign a global-scope
// role. Global Admin only.
func (s Scope) CanGrantGlobal() bool { return s.IsGlobalAdmin() }

// VisibleGroupIDs returns the deduplicated sorted list of group IDs
// the user can see. For global-role users this is empty (callers
// must short-circuit on IsGlobalAuditor() to mean "all groups," since
// the resolver doesn't know what groups exist).
func (s Scope) VisibleGroupIDs() []string {
	ids := make([]string, 0, len(s.groupRole))
	for id := range s.groupRole {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

type ctxKey int

const scopeKey ctxKey = 0

// WithScope stamps s onto ctx so downstream handlers can pull it back
// out via ScopeFromContext.
func WithScope(ctx context.Context, s Scope) context.Context {
	return context.WithValue(ctx, scopeKey, s)
}

// ScopeFromContext returns the Scope stamped on ctx and a bool
// reporting whether one was present. Handlers that require a Scope
// should treat the !ok case as a 500: the middleware chain is
// supposed to guarantee Scope is set whenever a User is.
func ScopeFromContext(ctx context.Context) (Scope, bool) {
	s, ok := ctx.Value(scopeKey).(Scope)
	return s, ok
}

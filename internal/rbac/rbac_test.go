// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"context"
	"reflect"
	"sort"
	"testing"
)

func strp(s string) *string { return &s }

func TestRoleIsValid(t *testing.T) {
	for _, tc := range []struct {
		r    Role
		want bool
	}{
		{RoleAdmin, true},
		{RoleOperator, true},
		{RoleAuditor, true},
		{Role(""), false},
		{Role("owner"), false},
	} {
		if got := tc.r.IsValid(); got != tc.want {
			t.Errorf("%q.IsValid() = %v, want %v", tc.r, got, tc.want)
		}
	}
}

func TestNewScopeKeepsHighestRolePerScope(t *testing.T) {
	rows := []Assignment{
		{UserID: "u", GroupID: nil, Role: RoleAuditor},
		{UserID: "u", GroupID: nil, Role: RoleOperator},
		{UserID: "u", GroupID: strp("g1"), Role: RoleAuditor},
		{UserID: "u", GroupID: strp("g1"), Role: RoleAdmin},
		{UserID: "u", GroupID: strp("g2"), Role: RoleOperator},
	}
	s := NewScope("u", rows)
	if s.Global != RoleOperator {
		t.Errorf("Global = %q, want operator", s.Global)
	}
	if got := s.RoleOnGroup("g1"); got != RoleAdmin {
		t.Errorf("RoleOnGroup(g1) = %q, want admin", got)
	}
	if got := s.RoleOnGroup("g2"); got != RoleOperator {
		t.Errorf("RoleOnGroup(g2) = %q, want operator", got)
	}
	if got := s.RoleOnGroup("none"); got != "" {
		t.Errorf("RoleOnGroup(none) = %q, want \"\"", got)
	}
}

func TestNewScopeEmpty(t *testing.T) {
	s := NewScope("u", nil)
	if s.HasAnyRole() {
		t.Error("HasAnyRole = true on empty scope")
	}
	if s.IsGlobalAdmin() || s.IsGlobalOperator() || s.IsGlobalAuditor() {
		t.Error("zero scope reports global role")
	}
}

func TestGlobalRoleHierarchy(t *testing.T) {
	cases := []struct {
		name           string
		role           Role
		wantAdmin      bool
		wantOperator   bool
		wantAuditor    bool
		wantManageGrp  bool
		wantManageUser bool
	}{
		{"admin", RoleAdmin, true, true, true, true, true},
		{"operator", RoleOperator, false, true, true, false, false},
		{"auditor", RoleAuditor, false, false, true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewScope("u", []Assignment{{UserID: "u", GroupID: nil, Role: tc.role}})
			if s.IsGlobalAdmin() != tc.wantAdmin {
				t.Errorf("IsGlobalAdmin = %v, want %v", s.IsGlobalAdmin(), tc.wantAdmin)
			}
			if s.IsGlobalOperator() != tc.wantOperator {
				t.Errorf("IsGlobalOperator = %v, want %v", s.IsGlobalOperator(), tc.wantOperator)
			}
			if s.IsGlobalAuditor() != tc.wantAuditor {
				t.Errorf("IsGlobalAuditor = %v, want %v", s.IsGlobalAuditor(), tc.wantAuditor)
			}
			if s.CanManageGroups() != tc.wantManageGrp {
				t.Errorf("CanManageGroups = %v, want %v", s.CanManageGroups(), tc.wantManageGrp)
			}
			if s.CanManageUsers() != tc.wantManageUser {
				t.Errorf("CanManageUsers = %v, want %v", s.CanManageUsers(), tc.wantManageUser)
			}
		})
	}
}

func TestCanReadSystemUngroupedRequiresGlobal(t *testing.T) {
	cases := []struct {
		name string
		s    Scope
		gid  *string
		want bool
	}{
		{
			name: "global admin sees ungrouped",
			s:    NewScope("u", []Assignment{{UserID: "u", Role: RoleAdmin}}),
			gid:  nil,
			want: true,
		},
		{
			name: "global auditor sees ungrouped",
			s:    NewScope("u", []Assignment{{UserID: "u", Role: RoleAuditor}}),
			gid:  nil,
			want: true,
		},
		{
			name: "group admin cannot see ungrouped",
			s:    NewScope("u", []Assignment{{UserID: "u", GroupID: strp("g1"), Role: RoleAdmin}}),
			gid:  nil,
			want: false,
		},
		{
			name: "group admin sees own group",
			s:    NewScope("u", []Assignment{{UserID: "u", GroupID: strp("g1"), Role: RoleAdmin}}),
			gid:  strp("g1"),
			want: true,
		},
		{
			name: "group admin doesn't see other group",
			s:    NewScope("u", []Assignment{{UserID: "u", GroupID: strp("g1"), Role: RoleAdmin}}),
			gid:  strp("g2"),
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.CanReadSystem(tc.gid); got != tc.want {
				t.Errorf("CanReadSystem(%v) = %v, want %v", tc.gid, got, tc.want)
			}
		})
	}
}

func TestCanDeleteSystem(t *testing.T) {
	globalAdmin := NewScope("u", []Assignment{{UserID: "u", Role: RoleAdmin}})
	groupAdmin := NewScope("u", []Assignment{{UserID: "u", GroupID: strp("g1"), Role: RoleAdmin}})
	groupOp := NewScope("u", []Assignment{{UserID: "u", GroupID: strp("g1"), Role: RoleOperator}})

	if !globalAdmin.CanDeleteSystem(nil) {
		t.Error("global admin must be able to delete ungrouped systems")
	}
	if !globalAdmin.CanDeleteSystem(strp("g1")) {
		t.Error("global admin must be able to delete grouped systems")
	}
	if groupAdmin.CanDeleteSystem(nil) {
		t.Error("group admin must not delete ungrouped systems")
	}
	if !groupAdmin.CanDeleteSystem(strp("g1")) {
		t.Error("group admin must delete systems in own group")
	}
	if groupAdmin.CanDeleteSystem(strp("g2")) {
		t.Error("group admin must not delete systems in other group")
	}
	if groupOp.CanDeleteSystem(strp("g1")) {
		t.Error("group operator must not delete systems")
	}
}

func TestCanMoveSystem(t *testing.T) {
	globalAdmin := NewScope("u", []Assignment{{UserID: "u", Role: RoleAdmin}})
	groupAdminBoth := NewScope("u", []Assignment{
		{UserID: "u", GroupID: strp("a"), Role: RoleAdmin},
		{UserID: "u", GroupID: strp("b"), Role: RoleAdmin},
	})
	groupAdminA := NewScope("u", []Assignment{{UserID: "u", GroupID: strp("a"), Role: RoleAdmin}})

	if !globalAdmin.CanMoveSystem(strp("a"), strp("b")) {
		t.Error("global admin can move anywhere")
	}
	if !globalAdmin.CanMoveSystem(strp("a"), nil) {
		t.Error("global admin can move to ungrouped")
	}
	if !groupAdminBoth.CanMoveSystem(strp("a"), strp("b")) {
		t.Error("group admin of both ends can move")
	}
	if groupAdminBoth.CanMoveSystem(strp("a"), nil) {
		t.Error("group admin cannot move to ungrouped")
	}
	if groupAdminA.CanMoveSystem(strp("a"), strp("b")) {
		t.Error("group admin of only one end cannot move")
	}
}

func TestCanGrantOnGroup(t *testing.T) {
	globalAdmin := NewScope("u", []Assignment{{UserID: "u", Role: RoleAdmin}})
	groupAdmin := NewScope("u", []Assignment{{UserID: "u", GroupID: strp("g1"), Role: RoleAdmin}})
	groupOp := NewScope("u", []Assignment{{UserID: "u", GroupID: strp("g1"), Role: RoleOperator}})

	if !globalAdmin.CanGrantOnGroup("g1", RoleAdmin) {
		t.Error("global admin must grant Admin")
	}
	if groupAdmin.CanGrantOnGroup("g1", RoleAdmin) {
		t.Error("group admin must NOT grant Admin")
	}
	if !groupAdmin.CanGrantOnGroup("g1", RoleOperator) {
		t.Error("group admin must grant Operator")
	}
	if !groupAdmin.CanGrantOnGroup("g1", RoleAuditor) {
		t.Error("group admin must grant Auditor")
	}
	if groupAdmin.CanGrantOnGroup("g2", RoleOperator) {
		t.Error("group admin must NOT grant on other groups")
	}
	if groupOp.CanGrantOnGroup("g1", RoleAuditor) {
		t.Error("group operator must NOT grant any role")
	}
	if groupAdmin.CanGrantOnGroup("g1", Role("bogus")) {
		t.Error("unknown role must be rejected")
	}
}

func TestVisibleGroupIDsDeduplicatesAndSorts(t *testing.T) {
	s := NewScope("u", []Assignment{
		{UserID: "u", GroupID: strp("b"), Role: RoleAdmin},
		{UserID: "u", GroupID: strp("a"), Role: RoleOperator},
		{UserID: "u", GroupID: strp("a"), Role: RoleAuditor},
		{UserID: "u", Role: RoleAuditor}, // global, should not appear in list
	})
	got := s.VisibleGroupIDs()
	want := []string{"a", "b"}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("VisibleGroupIDs = %v, want %v", got, want)
	}
}

func TestWithScopeContextRoundTrip(t *testing.T) {
	want := NewScope("u", []Assignment{{UserID: "u", Role: RoleAdmin}})
	ctx := WithScope(context.Background(), want)
	got, ok := ScopeFromContext(ctx)
	if !ok {
		t.Fatal("ScopeFromContext = !ok")
	}
	if got.UserID != "u" || !got.IsGlobalAdmin() {
		t.Errorf("ScopeFromContext = %+v", got)
	}
}

func TestScopeFromContextEmpty(t *testing.T) {
	if _, ok := ScopeFromContext(context.Background()); ok {
		t.Error("ScopeFromContext on empty ctx = ok, want !ok")
	}
}

func TestCanReadGroup(t *testing.T) {
	globalAuditor := NewScope("u", []Assignment{{UserID: "u", Role: RoleAuditor}})
	groupOnly := NewScope("u", []Assignment{{UserID: "u", GroupID: strp("g1"), Role: RoleAuditor}})
	empty := NewScope("u", nil)

	if !globalAuditor.CanReadGroup("any") {
		t.Error("global auditor must read any group")
	}
	if !groupOnly.CanReadGroup("g1") {
		t.Error("group auditor must read own group")
	}
	if groupOnly.CanReadGroup("g2") {
		t.Error("group auditor must NOT read other groups")
	}
	if empty.CanReadGroup("g1") {
		t.Error("empty scope must NOT read any group")
	}
}

func TestCanOperateGroup(t *testing.T) {
	globalOp := NewScope("u", []Assignment{{UserID: "u", Role: RoleOperator}})
	groupOp := NewScope("u", []Assignment{{UserID: "u", GroupID: strp("g1"), Role: RoleOperator}})
	groupAdmin := NewScope("u", []Assignment{{UserID: "u", GroupID: strp("g1"), Role: RoleAdmin}})
	groupAuditor := NewScope("u", []Assignment{{UserID: "u", GroupID: strp("g1"), Role: RoleAuditor}})

	if !globalOp.CanOperateGroup("any") {
		t.Error("global operator must operate any group")
	}
	if !groupOp.CanOperateGroup("g1") {
		t.Error("group operator must operate own group")
	}
	if !groupAdmin.CanOperateGroup("g1") {
		t.Error("group admin must operate own group")
	}
	if groupAuditor.CanOperateGroup("g1") {
		t.Error("group auditor must NOT operate")
	}
	if groupOp.CanOperateGroup("g2") {
		t.Error("group operator must NOT operate other groups")
	}
}

func TestCanCreateAndGrantGlobal(t *testing.T) {
	cases := []struct {
		name        string
		role        Role
		wantCreate  bool
		wantGlobal  bool
		globalScope bool
	}{
		{"global admin", RoleAdmin, true, true, true},
		{"global operator", RoleOperator, false, false, true},
		{"group admin", RoleAdmin, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s Scope
			if tc.globalScope {
				s = NewScope("u", []Assignment{{UserID: "u", Role: tc.role}})
			} else {
				s = NewScope("u", []Assignment{{UserID: "u", GroupID: strp("g1"), Role: tc.role}})
			}
			if s.CanCreateSystem() != tc.wantCreate {
				t.Errorf("CanCreateSystem = %v, want %v", s.CanCreateSystem(), tc.wantCreate)
			}
			if s.CanGrantGlobal() != tc.wantGlobal {
				t.Errorf("CanGrantGlobal = %v, want %v", s.CanGrantGlobal(), tc.wantGlobal)
			}
		})
	}
}

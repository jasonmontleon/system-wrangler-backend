// SPDX-License-Identifier: Apache-2.0

package groups

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"system-wrangler-backend/internal/systems"
)

func newScopedFixture(t *testing.T, visible func(ctx context.Context, g Group) bool) (*httptest.Server, *MemStore) {
	t.Helper()
	groupStore := newDeterministicMemStore()
	sysStore := systems.NewMemStore()
	h := NewHandler(groupStore, sysStore)
	h.VisibleGroup = visible
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, groupStore
}

func TestHandlerListAppliesVisibleGroup(t *testing.T) {
	srv, store := newScopedFixture(t, func(_ context.Context, g Group) bool {
		return g.Name == "prod"
	})
	if _, err := store.Create(GroupInput{Name: "prod"}); err != nil {
		t.Fatalf("Create prod: %v", err)
	}
	if _, err := store.Create(GroupInput{Name: "staging"}); err != nil {
		t.Fatalf("Create staging: %v", err)
	}
	resp := mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/groups", nil))
	defer func() { _ = resp.Body.Close() }()
	var got []Group
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].Name != "prod" {
		t.Errorf("got = %+v, want only prod", got)
	}
}

type erroringStore struct{}

func (erroringStore) Create(GroupInput) (Group, error)         { return Group{}, errFail }
func (erroringStore) Get(string) (Group, error)                { return Group{}, errFail }
func (erroringStore) List() ([]Group, error)                   { return nil, errFail }
func (erroringStore) Rename(string, GroupInput) (Group, error) { return Group{}, errFail }
func (erroringStore) Delete(string) error                      { return errFail }

var errFail = errFailedStore{}

type errFailedStore struct{}

func (errFailedStore) Error() string { return "store failed" }

type erroringSystemsStore struct{ systems.Store }

func (erroringSystemsStore) SetGroup(string, *string) error { return errFail }

// TestHandlerStoreErrorsReturn500 surfaces the 500-paths in the
// group handlers when underlying store calls fail. The stub store
// errors on every method.
func TestHandlerStoreErrorsReturn500(t *testing.T) {
	memSys := systems.NewMemStore()
	h := NewHandler(erroringStore{}, memSys)
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cases := []struct {
		method, path, body string
	}{
		{http.MethodGet, "/api/groups", ""},
		{http.MethodPost, "/api/groups", `{"name":"x"}`},
		{http.MethodGet, "/api/groups/g1", ""},
		{http.MethodPatch, "/api/groups/g1", `{"name":"y"}`},
		{http.MethodDelete, "/api/groups/g1", ""},
	}
	for _, tc := range cases {
		var body *strings.Reader
		if tc.body != "" {
			body = strings.NewReader(tc.body)
		}
		var r *http.Request
		if body != nil {
			r = mustReq(t, tc.method, srv.URL+tc.path, body)
		} else {
			r = mustReq(t, tc.method, srv.URL+tc.path, nil)
		}
		resp := mustDo(t, r)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("%s %s status = %d, want 500", tc.method, tc.path, resp.StatusCode)
		}
	}

	// setSystemGroup has three 500 branches: system-lookup, group-lookup,
	// and SetGroup itself. Hit the SetGroup branch: a real system exists,
	// the groups store finds the target group, but SetGroup errors. The
	// systems store both holds the row (so Get succeeds) AND errors on
	// SetGroup — the embedded systems.Store handles Get, the overriding
	// method handles SetGroup.
	memGroups := newDeterministicMemStore()
	g, _ := memGroups.Create(GroupInput{Name: "prod"})
	memSysWithRow := systems.NewMemStore()
	sys, _ := memSysWithRow.Create(systems.SystemInput{Name: "n", Hostname: "h"})
	h2 := NewHandler(memGroups, erroringSystemsStore{Store: memSysWithRow})
	mux2 := http.NewServeMux()
	h2.Register(mux2, nil)
	srv2 := httptest.NewServer(mux2)
	defer srv2.Close()
	resp := mustDo(t, mustReq(t, http.MethodPut, srv2.URL+"/api/systems/"+sys.ID+"/group",
		strings.NewReader(`{"groupId":"`+g.ID+`"}`)))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("setSystemGroup status = %d, want 500", resp.StatusCode)
	}

	// And the group-lookup-failure path: erroring groups store, a real
	// system in memSys so the system Get succeeds, target groupId
	// non-nil so the groups.Store.Get is actually called.
	memSys2 := systems.NewMemStore()
	sys2, _ := memSys2.Create(systems.SystemInput{Name: "n", Hostname: "h"})
	h3 := NewHandler(erroringStore{}, memSys2)
	mux3 := http.NewServeMux()
	h3.Register(mux3, nil)
	srv3 := httptest.NewServer(mux3)
	defer srv3.Close()
	resp = mustDo(t, mustReq(t, http.MethodPut, srv3.URL+"/api/systems/"+sys2.ID+"/group",
		strings.NewReader(`{"groupId":"missing"}`)))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("setSystemGroup lookup status = %d, want 500", resp.StatusCode)
	}
}

func TestHandlerCanManageGatesCreate(t *testing.T) {
	groupStore := newDeterministicMemStore()
	h := NewHandler(groupStore, systems.NewMemStore())
	h.CanManage = func(_ context.Context) bool { return false }
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/groups",
		strings.NewReader(`{"name":"prod"}`)))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	all, _ := groupStore.List()
	if len(all) != 0 {
		t.Errorf("denied create still wrote a row: %+v", all)
	}
}

func TestHandlerCanManageGatesRename(t *testing.T) {
	groupStore := newDeterministicMemStore()
	g, _ := groupStore.Create(GroupInput{Name: "prod"})
	h := NewHandler(groupStore, systems.NewMemStore())
	h.CanManage = func(_ context.Context) bool { return false }
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp := mustDo(t, mustReq(t, http.MethodPatch, srv.URL+"/api/groups/"+g.ID,
		strings.NewReader(`{"name":"renamed"}`)))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	got, _ := groupStore.Get(g.ID)
	if got.Name != "prod" {
		t.Errorf("denied rename took effect: name = %q", got.Name)
	}
}

func TestHandlerCanManageGatesDelete(t *testing.T) {
	groupStore := newDeterministicMemStore()
	g, _ := groupStore.Create(GroupInput{Name: "prod"})
	h := NewHandler(groupStore, systems.NewMemStore())
	h.CanManage = func(_ context.Context) bool { return false }
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp := mustDo(t, mustReq(t, http.MethodDelete, srv.URL+"/api/groups/"+g.ID, nil))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if _, err := groupStore.Get(g.ID); err != nil {
		t.Errorf("denied delete removed the group: %v", err)
	}
}

func TestHandlerCanMoveSystemGate(t *testing.T) {
	groupStore := newDeterministicMemStore()
	a, _ := groupStore.Create(GroupInput{Name: "a"})
	b, _ := groupStore.Create(GroupInput{Name: "b"})
	sysStore := systems.NewMemStore()
	sys, _ := sysStore.Create(systems.SystemInput{Name: "s", Hostname: "h"})
	_ = sysStore.SetGroup(sys.ID, &a.ID)

	h := NewHandler(groupStore, sysStore)
	// Allow only moves where target is b.
	h.CanMoveSystem = func(_ context.Context, _, to *string) bool {
		return to != nil && *to == b.ID
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Allowed: a → b succeeds.
	resp := mustDo(t, mustReq(t, http.MethodPut, srv.URL+"/api/systems/"+sys.ID+"/group",
		strings.NewReader(`{"groupId":"`+b.ID+`"}`)))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("allowed move status = %d, want 204", resp.StatusCode)
	}
	got, _ := sysStore.Get(sys.ID)
	if got.GroupID == nil || *got.GroupID != b.ID {
		t.Errorf("allowed move didn't take effect: %+v", got)
	}

	// Denied: b → nil (clear) refused.
	resp = mustDo(t, mustReq(t, http.MethodPut, srv.URL+"/api/systems/"+sys.ID+"/group",
		strings.NewReader(`{"groupId":null}`)))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("denied move status = %d, want 403", resp.StatusCode)
	}
	got, _ = sysStore.Get(sys.ID)
	if got.GroupID == nil || *got.GroupID != b.ID {
		t.Errorf("denied move changed the row: %+v", got)
	}
}

func TestHandlerSetSystemGroupMissingSystem(t *testing.T) {
	groupStore := newDeterministicMemStore()
	h := NewHandler(groupStore, systems.NewMemStore())
	gateCalled := false
	h.CanMoveSystem = func(_ context.Context, _, _ *string) bool {
		gateCalled = true
		return true
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp := mustDo(t, mustReq(t, http.MethodPut, srv.URL+"/api/systems/ghost/group",
		strings.NewReader(`{"groupId":null}`)))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	if gateCalled {
		t.Error("CanMoveSystem gate was called for a non-existent system")
	}
}

func TestHandlerGetAppliesVisibleGroup(t *testing.T) {
	srv, store := newScopedFixture(t, func(_ context.Context, g Group) bool {
		return g.Name == "prod"
	})
	mine, _ := store.Create(GroupInput{Name: "prod"})
	hidden, _ := store.Create(GroupInput{Name: "staging"})

	resp := mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/groups/"+mine.ID, nil))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("visible get status = %d, want 200", resp.StatusCode)
	}

	resp = mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/groups/"+hidden.ID, nil))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("hidden get status = %d, want 404", resp.StatusCode)
	}
}

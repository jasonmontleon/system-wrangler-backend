// SPDX-License-Identifier: Apache-2.0

package systems

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerListAppliesVisibleSystem(t *testing.T) {
	store := newTestStore()
	g1, g2 := "g1", "g2"
	a, _ := store.Create(SystemInput{Name: "a", Hostname: "a"})
	b, _ := store.Create(SystemInput{Name: "b", Hostname: "b"})
	c, _ := store.Create(SystemInput{Name: "c", Hostname: "c"}) // ungrouped
	_ = store.SetGroup(a.ID, &g1)
	_ = store.SetGroup(b.ID, &g2)

	h := NewHandler(store)
	h.VisibleSystem = func(_ context.Context, s System) bool {
		return s.GroupID != nil && *s.GroupID == g1
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/systems", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d", w.Code)
	}
	var got []System
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].ID != a.ID {
		t.Errorf("got = %+v, want only %s", got, a.ID)
	}
	// Make sure b and c didn't accidentally come through.
	for _, s := range got {
		if s.ID == b.ID || s.ID == c.ID {
			t.Errorf("leaked %s through scope filter", s.ID)
		}
	}
}

func TestHandlerGetAppliesVisibleSystem(t *testing.T) {
	store := newTestStore()
	g1, g2 := "g1", "g2"
	a, _ := store.Create(SystemInput{Name: "a", Hostname: "a"})
	b, _ := store.Create(SystemInput{Name: "b", Hostname: "b"})
	_ = store.SetGroup(a.ID, &g1)
	_ = store.SetGroup(b.ID, &g2)

	h := NewHandler(store)
	h.VisibleSystem = func(_ context.Context, s System) bool {
		return s.GroupID != nil && *s.GroupID == g1
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/systems/"+a.ID, nil))
	if w.Code != http.StatusOK {
		t.Errorf("visible get status = %d, want 200", w.Code)
	}

	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/systems/"+b.ID, nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("hidden get status = %d, want 404 (must not leak existence)", w.Code)
	}
}

func TestHandlerCreateRespectsCanCreate(t *testing.T) {
	store := newTestStore()
	h := NewHandler(store)
	allow := true
	h.CanCreate = func(_ context.Context) bool { return allow }
	mux := http.NewServeMux()
	h.Register(mux, nil)

	// Allowed path: 201.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/systems", nil)
	req.Body = struct{ readCloser }{readCloser{strings.NewReader(`{"name":"a","hostname":"a"}`)}}
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("allowed status = %d, want 201", w.Code)
	}

	// Denied path: 403, no row written. Also: the body must not be
	// read — gate refuses before decode — but the side-effect we
	// can assert is just the row count.
	allow = false
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/systems", nil)
	req.Body = struct{ readCloser }{readCloser{strings.NewReader(`{"name":"b","hostname":"b"}`)}}
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("denied status = %d, want 403", w.Code)
	}
	list, _ := store.List()
	if len(list) != 1 {
		t.Errorf("expected only the allowed system to persist, got %d rows", len(list))
	}
}

func TestHandlerDeleteRespectsCanDelete(t *testing.T) {
	store := newTestStore()
	mine, _ := store.Create(SystemInput{Name: "mine", Hostname: "h1"})
	theirs, _ := store.Create(SystemInput{Name: "theirs", Hostname: "h2"})
	g := "g1"
	_ = store.SetGroup(mine.ID, &g)

	h := NewHandler(store)
	// Stub gate: can delete only systems in group g1.
	h.CanDelete = func(_ context.Context, s System) bool {
		return s.GroupID != nil && *s.GroupID == g
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)

	// Allowed: mine deletes fine.
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/api/systems/"+mine.ID, nil))
	if w.Code != http.StatusNoContent {
		t.Errorf("allowed delete status = %d, want 204", w.Code)
	}

	// Denied: theirs returns 403; row remains.
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/api/systems/"+theirs.ID, nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("denied delete status = %d, want 403", w.Code)
	}
	if _, err := store.Get(theirs.ID); err != nil {
		t.Errorf("denied delete actually removed the row: %v", err)
	}
}

func TestHandlerDeleteHiddenSystemReturns404NotForbidden(t *testing.T) {
	store := newTestStore()
	sys, _ := store.Create(SystemInput{Name: "x", Hostname: "h"})
	h := NewHandler(store)
	// Caller can't see the system at all.
	h.VisibleSystem = func(_ context.Context, _ System) bool { return false }
	// CanDelete would have allowed, but visibility wins: 404 hides existence.
	h.CanDelete = func(_ context.Context, _ System) bool { return true }
	mux := http.NewServeMux()
	h.Register(mux, nil)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/api/systems/"+sys.ID, nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (existence hidden)", w.Code)
	}
}

func TestHandlerDeleteMissingSystem(t *testing.T) {
	store := newTestStore()
	h := NewHandler(store)
	// Gate is set but should never be reached since the row doesn't exist.
	gateCalled := false
	h.CanDelete = func(_ context.Context, _ System) bool {
		gateCalled = true
		return true
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/api/systems/ghost", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
	if gateCalled {
		t.Error("CanDelete gate was called for a non-existent system")
	}
}

// readCloser turns a strings.Reader into an io.ReadCloser without
// pulling in the net/http internals; needed because httptest.NewRequest
// expects an io.Reader and we want explicit control over the body.
type readCloser struct {
	*strings.Reader
}

func (readCloser) Close() error { return nil }

func TestHandlerListWithoutVisibleSystemReturnsAll(t *testing.T) {
	store := newTestStore()
	_, _ = store.Create(SystemInput{Name: "a", Hostname: "a"})
	_, _ = store.Create(SystemInput{Name: "b", Hostname: "b"})

	mux := http.NewServeMux()
	NewHandler(store).Register(mux, nil)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/systems", nil))
	var got []System
	_ = json.NewDecoder(w.Body).Decode(&got)
	if len(got) != 2 {
		t.Errorf("no-filter list len = %d, want 2", len(got))
	}
}

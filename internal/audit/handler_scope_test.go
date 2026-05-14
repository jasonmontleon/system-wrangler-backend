// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/systems"
)

// newScopeHandler boots an audit Handler against a DB that already has
// the systems schema (the scope filter joins on hosts) and lets each
// test set the per-request scope through a closure.
type scopeHandler struct {
	store   *Store
	systems *systems.SQLiteStore
	mux     *http.ServeMux
	scope   *ScopeFilter
}

func newScopeHandler(t *testing.T) *scopeHandler {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "audit_h_scope.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sys, err := systems.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("systems.NewSQLiteStore: %v", err)
	}
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStore: %v", err)
	}
	sh := &scopeHandler{store: store, systems: sys, mux: http.NewServeMux()}
	h := NewHandler(store)
	h.ScopeFilterFor = func(_ *http.Request) *ScopeFilter { return sh.scope }
	h.Register(sh.mux, nil)
	return sh
}

func (s *scopeHandler) setScope(sf *ScopeFilter) { s.scope = sf }

func (s *scopeHandler) seedSystem(t *testing.T, name, groupID string) systems.System {
	t.Helper()
	h, err := s.systems.Create(systems.SystemInput{Name: name, Hostname: name + ".local"})
	if err != nil {
		t.Fatalf("systems.Create: %v", err)
	}
	if err := s.systems.SetGroup(h.ID, &groupID); err != nil {
		t.Fatalf("systems.SetGroup: %v", err)
	}
	return h
}

func (s *scopeHandler) log(t *testing.T, e Event) {
	t.Helper()
	if err := s.store.Log(context.Background(), e); err != nil {
		t.Fatalf("Log: %v", err)
	}
}

func TestHandlerListAppliesScope(t *testing.T) {
	sh := newScopeHandler(t)
	mine := sh.seedSystem(t, "mine", "g1")
	theirs := sh.seedSystem(t, "theirs", "g2")
	sh.log(t, Event{Action: "system.create", Outcome: Success, TargetKind: "system", TargetID: mine.ID})
	sh.log(t, Event{Action: "system.create", Outcome: Success, TargetKind: "system", TargetID: theirs.ID})

	// Global caller sees both.
	sh.setScope(nil)
	w := httptest.NewRecorder()
	sh.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/admin/audit", nil))
	var resp listResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Records) != 2 {
		t.Errorf("global recs = %d, want 2", len(resp.Records))
	}

	// Group-only caller scoped to g1 sees only mine.
	sh.setScope(&ScopeFilter{GroupIDs: []string{"g1"}})
	w = httptest.NewRecorder()
	sh.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/admin/audit", nil))
	resp = listResponse{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Records) != 1 || resp.Records[0].TargetID != mine.ID {
		t.Errorf("scoped recs = %+v, want only %s", resp.Records, mine.ID)
	}
}

func TestHandlerGetAppliesScope(t *testing.T) {
	sh := newScopeHandler(t)
	mine := sh.seedSystem(t, "mine", "g1")
	theirs := sh.seedSystem(t, "theirs", "g2")
	sh.log(t, Event{Action: "system.create", Outcome: Success, TargetKind: "system", TargetID: mine.ID})
	sh.log(t, Event{Action: "system.create", Outcome: Success, TargetKind: "system", TargetID: theirs.ID})

	// Discover both record IDs as the unscoped caller.
	sh.setScope(nil)
	w := httptest.NewRecorder()
	sh.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/admin/audit", nil))
	var resp listResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var idMine, idTheirs string
	for _, r := range resp.Records {
		if r.TargetID == mine.ID {
			idMine = r.ID
		}
		if r.TargetID == theirs.ID {
			idTheirs = r.ID
		}
	}
	if idMine == "" || idTheirs == "" {
		t.Fatalf("missing seed ids: mine=%q theirs=%q", idMine, idTheirs)
	}

	// Scoped to g1, /api/admin/audit/{id} returns the row for mine, 404
	// for theirs.
	sh.setScope(&ScopeFilter{GroupIDs: []string{"g1"}})
	w = httptest.NewRecorder()
	sh.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/admin/audit/"+idMine, nil))
	if w.Code != http.StatusOK {
		t.Errorf("mine status = %d, want 200", w.Code)
	}
	w = httptest.NewRecorder()
	sh.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/admin/audit/"+idTheirs, nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("theirs status = %d, want 404", w.Code)
	}
}

func TestHandlerGetWithoutScopeReturnsRow(t *testing.T) {
	sh := newScopeHandler(t)
	sh.log(t, Event{Action: "user.create", Outcome: Success, TargetKind: "user", TargetID: "u1"})
	// No ScopeFilterFor configured returns row even though it would be
	// hidden from a group-only caller — this is the "global role" path.
	sh.setScope(nil)
	w := httptest.NewRecorder()
	sh.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/admin/audit", nil))
	var resp listResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if len(resp.Records) != 1 {
		t.Fatalf("seed list len = %d", len(resp.Records))
	}
	id := resp.Records[0].ID

	w = httptest.NewRecorder()
	sh.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/admin/audit/"+id, nil))
	if w.Code != http.StatusOK {
		t.Errorf("unscoped status = %d, want 200", w.Code)
	}
}

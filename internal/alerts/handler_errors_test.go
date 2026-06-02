// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/database"
)

// failStore wraps a real store but forces specific methods to error, so
// the handler's 500 branches are exercised. Embedding Store means only
// the overridden methods diverge.
type failStore struct {
	Store
	failList   bool
	failActive bool
	failUpdate bool
	failDelete bool
	failGet    bool
	failCreate bool
}

func (f failStore) List() ([]Rule, error) {
	if f.failList {
		return nil, errors.New("boom")
	}
	return f.Store.List()
}

func (f failStore) Get(id string) (Rule, error) {
	if f.failGet {
		return Rule{}, errors.New("boom")
	}
	return f.Store.Get(id)
}

func (f failStore) Create(in RuleInput, createdBy string) (Rule, error) {
	if f.failCreate {
		return Rule{}, errors.New("boom")
	}
	return f.Store.Create(in, createdBy)
}

func (f failStore) ListActive() ([]ActiveAlert, error) {
	if f.failActive {
		return nil, errors.New("boom")
	}
	return f.Store.ListActive()
}

func (f failStore) Update(id string, in RuleInput) (Rule, error) {
	if f.failUpdate {
		return Rule{}, errors.New("boom")
	}
	return f.Store.Update(id, in)
}

func (f failStore) Delete(id string) error {
	if f.failDelete {
		return errors.New("boom")
	}
	return f.Store.Delete(id)
}

func errFixture(t *testing.T, fs Store) *httptest.Server {
	t.Helper()
	h := &Handler{Store: fs}
	mux := http.NewServeMux()
	wrap := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := audit.WithActor(r.Context(), audit.Actor{Kind: audit.ActorUser, ID: "user-1"})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	h.Register(mux, wrap)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestHandlerListStoreError(t *testing.T) {
	srv := errFixture(t, failStore{Store: newTestStore(t), failList: true})
	resp := mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/alerts", nil))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("list error should 500, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerActiveStoreError(t *testing.T) {
	srv := errFixture(t, failStore{Store: newTestStore(t), failActive: true})
	resp := mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/alerts/active", nil))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("active error should 500, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerUpdateStoreError(t *testing.T) {
	base := newTestStore(t)
	r, _ := base.Create(validMetricInput(), "user-1")
	srv := errFixture(t, failStore{Store: base, failUpdate: true})
	resp := mustDo(t, mustReq(t, http.MethodPut, srv.URL+"/api/alerts/"+r.ID, strings.NewReader(ruleJSON(t, validMetricInput()))))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("update error should 500, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerDeleteStoreError(t *testing.T) {
	base := newTestStore(t)
	r, _ := base.Create(validMetricInput(), "user-1")
	srv := errFixture(t, failStore{Store: base, failDelete: true})
	resp := mustDo(t, mustReq(t, http.MethodDelete, srv.URL+"/api/alerts/"+r.ID, nil))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("delete error should 500, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerCreateStoreError(t *testing.T) {
	srv := errFixture(t, failStore{Store: newTestStore(t), failCreate: true})
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/alerts", strings.NewReader(ruleJSON(t, validMetricInput()))))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("create error should 500, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerGetStoreError(t *testing.T) {
	srv := errFixture(t, failStore{Store: newTestStore(t), failGet: true})
	resp := mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/alerts/anything", nil))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("get store error should 500, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

// TestHandlerUpdateRegate ensures the proposed (post-edit) shape is
// re-checked: a CanManage that allows the existing rule but rejects the
// new target must 403.
func TestHandlerUpdateRegate(t *testing.T) {
	srv, store, h := newHandlerFixture(t)
	r, _ := store.Create(validMetricInput(), "user-1")
	h.CanManage = func(_ context.Context, rule Rule) bool {
		// Allow the stored (global) rule, reject once it pivots to a group.
		return rule.TargetKind != "group"
	}
	in := validMetricInput()
	in.TargetKind = "group"
	in.TargetValue = "grp-1"
	resp := mustDo(t, mustReq(t, http.MethodPut, srv.URL+"/api/alerts/"+r.ID, strings.NewReader(ruleJSON(t, in))))
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("re-gate should 403 on target pivot, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

// TestHandlerAuditLogged drives create/update/delete through a handler
// wired to a real audit store, covering the logAudit non-nil branch and
// the audit rows each mutation writes.
func TestHandlerAuditLogged(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "audit.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("alerts store: %v", err)
	}
	auditStore, err := audit.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("audit store: %v", err)
	}
	h := &Handler{Store: store, Audit: auditStore}
	mux := http.NewServeMux()
	wrap := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := audit.WithActor(r.Context(), audit.Actor{Kind: audit.ActorUser, ID: "user-1", Label: "alice"})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	h.Register(mux, wrap)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/alerts", strings.NewReader(ruleJSON(t, validMetricInput()))))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d", resp.StatusCode)
	}
	var created Rule
	_ = json.NewDecoder(resp.Body).Decode(&created)
	_ = resp.Body.Close()

	resp = mustDo(t, mustReq(t, http.MethodPut, srv.URL+"/api/alerts/"+created.ID, strings.NewReader(ruleJSON(t, validMetricInput()))))
	_ = resp.Body.Close()
	resp = mustDo(t, mustReq(t, http.MethodDelete, srv.URL+"/api/alerts/"+created.ID, nil))
	_ = resp.Body.Close()

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action LIKE 'alert.%'`).Scan(&n); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if n != 3 {
		t.Errorf("expected 3 alert audit rows (create/update/delete), got %d", n)
	}
}

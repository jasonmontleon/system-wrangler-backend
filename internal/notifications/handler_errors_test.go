// SPDX-License-Identifier: Apache-2.0

package notifications

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/secrets"
)

// failStore wraps a real store but forces chosen methods to error.
type failStore struct {
	Store
	failList        bool
	failUpdate      bool
	failDelete      bool
	failDeliveries  bool
	failEnabled     bool
	failListRouting bool
	failSetRouting  bool
	failGetRouting  bool
}

func (f failStore) ListRouting() ([]Routing, error) {
	if f.failListRouting {
		return nil, errors.New("boom")
	}
	return f.Store.ListRouting()
}

func (f failStore) SetRouting(ruleID string, in RoutingInput) error {
	if f.failSetRouting {
		return errors.New("boom")
	}
	return f.Store.SetRouting(ruleID, in)
}

func (f failStore) GetRouting(ruleID string) (Routing, error) {
	if f.failGetRouting {
		return Routing{}, errors.New("boom")
	}
	return f.Store.GetRouting(ruleID)
}

func (f failStore) ListEnabled() ([]Channel, error) {
	if f.failEnabled {
		return nil, errors.New("boom")
	}
	return f.Store.ListEnabled()
}

func (f failStore) List() ([]Channel, error) {
	if f.failList {
		return nil, errors.New("boom")
	}
	return f.Store.List()
}

func (f failStore) Update(id string, in ChannelInput) (Channel, error) {
	if f.failUpdate {
		return Channel{}, errors.New("boom")
	}
	return f.Store.Update(id, in)
}

func (f failStore) Delete(id string) error {
	if f.failDelete {
		return errors.New("boom")
	}
	return f.Store.Delete(id)
}

func (f failStore) ListDeliveries(limit int) ([]Delivery, error) {
	if f.failDeliveries {
		return nil, errors.New("boom")
	}
	return f.Store.ListDeliveries(limit)
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
	resp := req(t, http.MethodGet, srv.URL+"/api/notifications/channels", "")
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("list error should 500, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerUpdateStoreError(t *testing.T) {
	base := newTestStore(t)
	c, _ := base.Create(emailInput(), "user-1")
	srv := errFixture(t, failStore{Store: base, failUpdate: true})
	resp := req(t, http.MethodPut, srv.URL+"/api/notifications/channels/"+c.ID, emailJSON(t))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("update error should 500, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerDeleteStoreError(t *testing.T) {
	base := newTestStore(t)
	c, _ := base.Create(emailInput(), "user-1")
	srv := errFixture(t, failStore{Store: base, failDelete: true})
	resp := req(t, http.MethodDelete, srv.URL+"/api/notifications/channels/"+c.ID, "")
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("delete error should 500, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerDeliveriesStoreError(t *testing.T) {
	srv := errFixture(t, failStore{Store: newTestStore(t), failDeliveries: true})
	resp := req(t, http.MethodGet, srv.URL+"/api/notifications/deliveries", "")
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("deliveries error should 500, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerListRoutingStoreError(t *testing.T) {
	srv := errFixture(t, failStore{Store: newTestStore(t), failListRouting: true})
	resp := req(t, http.MethodGet, srv.URL+"/api/notifications/routing", "")
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("list routing error should 500, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerSetRoutingStoreError(t *testing.T) {
	srv := errFixture(t, failStore{Store: newTestStore(t), failSetRouting: true})
	resp := req(t, http.MethodPut, srv.URL+"/api/notifications/routing/rule-1", `{"mode":"all"}`)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("set routing error should 500, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerSetRoutingGetError(t *testing.T) {
	// SetRouting succeeds but the follow-up read fails → 500.
	srv := errFixture(t, failStore{Store: newTestStore(t), failGetRouting: true})
	resp := req(t, http.MethodPut, srv.URL+"/api/notifications/routing/rule-1", `{"mode":"all"}`)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("get-after-set error should 500, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerUpdateInvalid400(t *testing.T) {
	srv, store, _ := newHandlerFixture(t)
	c, _ := store.Create(emailInput(), "user-1")
	resp := req(t, http.MethodPut, srv.URL+"/api/notifications/channels/"+c.ID, `{"name":"x","type":"bogus"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid update should 400, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerTestMissing404(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := req(t, http.MethodPost, srv.URL+"/api/notifications/channels/nope/test", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("test on missing channel should 404, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestDispatcherNowAndTimeoutOverrides(t *testing.T) {
	fixed := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	d := &Dispatcher{Now: func() time.Time { return fixed }, SendTimeout: 5 * time.Second}
	if !d.now().Equal(fixed.UTC()) {
		t.Errorf("now override not honored: %v", d.now())
	}
	if d.timeout() != 5*time.Second {
		t.Errorf("timeout override not honored: %v", d.timeout())
	}
}

// TestHandlerAuditLogged drives create/update/delete through a handler
// wired to a real audit store, covering the logAudit non-nil branch.
func TestHandlerAuditLogged(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "n-audit.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	vault, _ := secrets.NewVaultFromKey(make([]byte, secrets.KeySize))
	store.Vault = vault
	auditStore, err := audit.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("audit store: %v", err)
	}
	h := &Handler{Store: store, Audit: auditStore}
	mux := http.NewServeMux()
	wrap := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := audit.WithActor(r.Context(), audit.Actor{Kind: audit.ActorUser, ID: "user-1"})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	h.Register(mux, wrap)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp := req(t, http.MethodPost, srv.URL+"/api/notifications/channels", emailJSON(t))
	var dto ChannelDTO
	_ = json.NewDecoder(resp.Body).Decode(&dto)
	_ = resp.Body.Close()
	resp = req(t, http.MethodPut, srv.URL+"/api/notifications/channels/"+dto.ID, emailJSON(t))
	_ = resp.Body.Close()
	resp = req(t, http.MethodDelete, srv.URL+"/api/notifications/channels/"+dto.ID, "")
	_ = resp.Body.Close()

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action LIKE 'notification_channel.%'`).Scan(&n); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if n != 3 {
		t.Errorf("expected 3 audit rows, got %d", n)
	}
}

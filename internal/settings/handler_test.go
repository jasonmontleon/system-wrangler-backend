// SPDX-License-Identifier: Apache-2.0

package settings

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/database"
)

func newHandlerSrv(t *testing.T, allow bool) (*Handler, *httptest.Server) {
	t.Helper()
	dsn := "file:" + t.TempDir() + "/settings.db"
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	auditStore, err := audit.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStore: %v", err)
	}
	h := &Handler{
		Store: store,
		Audit: auditStore,
		CanManage: func(_ context.Context) bool {
			return allow
		},
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return h, srv
}

func TestListSurfacesDefaultWhenUnset(t *testing.T) {
	_, srv := newHandlerSrv(t, true)
	resp, err := http.Get(srv.URL + "/api/admin/settings")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got settingsResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Settings[KeyRunHistoryLimit] != "100" {
		t.Errorf("run_history_limit = %q, want default 100", got.Settings[KeyRunHistoryLimit])
	}
	if got.Settings[KeyUpdateConcurrencyLimit] != "4" {
		t.Errorf("update_concurrency_limit = %q, want default 4", got.Settings[KeyUpdateConcurrencyLimit])
	}
}

func TestPutUpdateConcurrencyLimit(t *testing.T) {
	h, srv := newHandlerSrv(t, true)
	req, _ := http.NewRequest(
		http.MethodPut,
		srv.URL+"/api/admin/settings/"+KeyUpdateConcurrencyLimit,
		strings.NewReader(`{"value":"8"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if v, _ := h.Store.Get(KeyUpdateConcurrencyLimit); v != "8" {
		t.Errorf("stored = %q, want 8", v)
	}
	// Out-of-range value should 400.
	req2, _ := http.NewRequest(
		http.MethodPut,
		srv.URL+"/api/admin/settings/"+KeyUpdateConcurrencyLimit,
		strings.NewReader(`{"value":"0"}`),
	)
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("out-of-range status = %d, want 400", resp2.StatusCode)
	}
}

func TestPutHappyPath(t *testing.T) {
	h, srv := newHandlerSrv(t, true)
	req, _ := http.NewRequest(
		http.MethodPut,
		srv.URL+"/api/admin/settings/"+KeyRunHistoryLimit,
		strings.NewReader(`{"value":"250"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	v, _ := h.Store.Get(KeyRunHistoryLimit)
	if v != "250" {
		t.Errorf("stored = %q, want 250", v)
	}
	// Audit row should land with key/before/after.
	rows, _, err := h.Audit.ListQuery(audit.Query{Action: "setting.set", Limit: 5})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(rows))
	}
	d := rows[0].Detail
	if d["key"] != KeyRunHistoryLimit {
		t.Errorf("detail.key = %v", d["key"])
	}
	if d["value_after"] != "250" {
		t.Errorf("detail.value_after = %v", d["value_after"])
	}
	if d["value_before"] != "" {
		t.Errorf("detail.value_before = %v, want empty (unset before)", d["value_before"])
	}
}

func TestPutRejectsOutOfRange(t *testing.T) {
	_, srv := newHandlerSrv(t, true)
	req, _ := http.NewRequest(
		http.MethodPut,
		srv.URL+"/api/admin/settings/"+KeyRunHistoryLimit,
		strings.NewReader(`{"value":"0"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestPutRejectsNonInteger(t *testing.T) {
	_, srv := newHandlerSrv(t, true)
	req, _ := http.NewRequest(
		http.MethodPut,
		srv.URL+"/api/admin/settings/"+KeyRunHistoryLimit,
		strings.NewReader(`{"value":"abc"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestPutUnknownKey(t *testing.T) {
	_, srv := newHandlerSrv(t, true)
	req, _ := http.NewRequest(
		http.MethodPut,
		srv.URL+"/api/admin/settings/no-such-key",
		strings.NewReader(`{"value":"x"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestGateRejectsNonAdmin(t *testing.T) {
	_, srv := newHandlerSrv(t, false)
	resp, err := http.Get(srv.URL + "/api/admin/settings")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("GET status = %d, want 403", resp.StatusCode)
	}
	req, _ := http.NewRequest(
		http.MethodPut,
		srv.URL+"/api/admin/settings/"+KeyRunHistoryLimit,
		strings.NewReader(`{"value":"200"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("PUT status = %d, want 403", resp2.StatusCode)
	}
}

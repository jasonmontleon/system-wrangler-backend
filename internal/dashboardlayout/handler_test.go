// SPDX-License-Identifier: Apache-2.0

package dashboardlayout

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"system-wrangler-backend/internal/auth"
	"system-wrangler-backend/internal/database"
)

func newHandlerSrv(t *testing.T, userID string) (*Handler, *httptest.Server) {
	t.Helper()
	dsn := "file:" + t.TempDir() + "/dashboardlayout.db"
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	h := &Handler{Store: store}
	mux := http.NewServeMux()
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if userID == "" {
				next.ServeHTTP(w, r)
				return
			}
			ctx := auth.WithUser(r.Context(), auth.User{ID: userID})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	h.Register(mux, mw)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return h, srv
}

func TestGetReturnsEmptyDTOForUnsetUser(t *testing.T) {
	_, srv := newHandlerSrv(t, "alice")
	resp, err := http.Get(srv.URL + "/api/dashboard/layout")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body layoutDTO
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Layout) != 0 {
		t.Errorf("Layout = %s, want empty", body.Layout)
	}
}

func TestPutThenGetRoundTrip(t *testing.T) {
	_, srv := newHandlerSrv(t, "alice")
	payload := `{"layout":[{"id":"system-health","enabled":true}]}`
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/dashboard/layout", strings.NewReader(payload))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("put status = %d", resp.StatusCode)
	}

	getResp, err := http.Get(srv.URL + "/api/dashboard/layout")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = getResp.Body.Close() }()
	raw, _ := io.ReadAll(getResp.Body)
	if !strings.Contains(string(raw), `"system-health"`) {
		t.Errorf("Get body = %s", raw)
	}
}

func TestPutRequiresValidJSONLayoutField(t *testing.T) {
	_, srv := newHandlerSrv(t, "alice")
	for _, body := range []string{
		`{`,                 // malformed JSON
		`{}`,                // missing layout field
		`{"layout":null}`,   // null layout
		`{"other":"value"}`, // unrelated field
	} {
		req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/dashboard/layout", strings.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("put: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, resp.StatusCode)
		}
	}
}

func TestPutRejectsOversizedBody(t *testing.T) {
	_, srv := newHandlerSrv(t, "alice")
	big := bytes.Repeat([]byte("a"), MaxLayoutBytes+10)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/dashboard/layout", bytes.NewReader(big))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", resp.StatusCode)
	}
}

func TestGetWithoutUserContextIs401(t *testing.T) {
	_, srv := newHandlerSrv(t, "")
	resp, err := http.Get(srv.URL + "/api/dashboard/layout")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestPutWithoutUserContextIs401(t *testing.T) {
	_, srv := newHandlerSrv(t, "")
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/dashboard/layout", strings.NewReader(`{"layout":[]}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// fakeStore is a hand-rolled Store with injectable error paths. The
// DeleteByUserTx method takes *sql.Tx to satisfy the interface, but
// the GET/PUT tests never exercise it.
type fakeStore struct {
	getErr error
	setErr error
}

func (s *fakeStore) Get(string) (string, error)           { return "", s.getErr }
func (s *fakeStore) Set(string, string) error             { return s.setErr }
func (s *fakeStore) DeleteByUserTx(*sql.Tx, string) error { return nil }

func newHandlerWithStore(t *testing.T, store Store) *httptest.Server {
	t.Helper()
	h := &Handler{Store: store}
	mux := http.NewServeMux()
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := auth.WithUser(r.Context(), auth.User{ID: "alice"})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	h.Register(mux, mw)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestGetSurfaces500OnStoreError(t *testing.T) {
	srv := newHandlerWithStore(t, &fakeStore{getErr: errors.New("boom")})
	resp, err := http.Get(srv.URL + "/api/dashboard/layout")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestPutSurfaces500OnStoreError(t *testing.T) {
	srv := newHandlerWithStore(t, &fakeStore{setErr: errors.New("boom")})
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/dashboard/layout", strings.NewReader(`{"layout":[]}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandlerWithNilStoreIs503(t *testing.T) {
	srv := newHandlerWithStore(t, nil)
	resp, err := http.Get(srv.URL + "/api/dashboard/layout")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/dashboard/layout", strings.NewReader(`{"layout":[]}`))
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("put status = %d, want 503", resp2.StatusCode)
	}
}

func TestRegisterWithNilMiddleware(t *testing.T) {
	h := &Handler{Store: nil}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/dashboard/layout")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = resp.Body.Close()
	// No user context stamped, so handler returns 401 first.
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

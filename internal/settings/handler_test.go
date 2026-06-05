// SPDX-License-Identifier: Apache-2.0

package settings

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/database"
)

type errStore struct {
	Store
	allErr error
	setErr error
}

func (e *errStore) All() (map[string]string, error) {
	if e.allErr != nil {
		return nil, e.allErr
	}
	if e.Store != nil {
		return e.Store.All()
	}
	return map[string]string{}, nil
}

func (e *errStore) Set(_, _ string) error {
	if e.setErr != nil {
		return e.setErr
	}
	return nil
}

func (e *errStore) Get(string) (string, error) {
	return "", nil
}

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

func TestPutProbeKnobs(t *testing.T) {
	// The three probe keys all route through the same setIntFromBody
	// helper, so a single table covers happy-path, non-integer, and
	// out-of-range for each.
	for _, key := range []string{
		KeyProbeIntervalSeconds,
		KeyProbeFailureThreshold,
		KeyProbeSuccessThreshold,
	} {
		t.Run(key+"_ok", func(t *testing.T) {
			h, srv := newHandlerSrv(t, true)
			req, _ := http.NewRequest(
				http.MethodPut,
				srv.URL+"/api/admin/settings/"+key,
				strings.NewReader(`{"value":"5"}`),
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
			if v, _ := h.Store.Get(key); v != "5" {
				t.Errorf("stored = %q, want 5", v)
			}
		})
		t.Run(key+"_bad_integer", func(t *testing.T) {
			_, srv := newHandlerSrv(t, true)
			req, _ := http.NewRequest(
				http.MethodPut,
				srv.URL+"/api/admin/settings/"+key,
				strings.NewReader(`{"value":"not-a-number"}`),
			)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("put: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
		})
		t.Run(key+"_out_of_range", func(t *testing.T) {
			_, srv := newHandlerSrv(t, true)
			req, _ := http.NewRequest(
				http.MethodPut,
				srv.URL+"/api/admin/settings/"+key,
				strings.NewReader(`{"value":"0"}`),
			)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("put: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
		})
	}
}

func TestListSurfacesProbeDefaults(t *testing.T) {
	_, srv := newHandlerSrv(t, true)
	resp, err := http.Get(srv.URL + "/api/admin/settings")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got struct {
		Settings map[string]string `json:"settings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, key := range []string{
		KeyProbeIntervalSeconds,
		KeyProbeFailureThreshold,
		KeyProbeSuccessThreshold,
		KeyScheduleMisfireGraceSeconds,
	} {
		if _, ok := got.Settings[key]; !ok {
			t.Errorf("%s missing from list response", key)
		}
	}
	if got.Settings[KeyScheduleMisfireGraceSeconds] != strconv.Itoa(DefaultScheduleMisfireGraceSeconds) {
		t.Errorf("schedule_misfire_grace_seconds = %q, want default %d",
			got.Settings[KeyScheduleMisfireGraceSeconds], DefaultScheduleMisfireGraceSeconds)
	}
}

func TestPutScheduleMisfireGrace(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		h, srv := newHandlerSrv(t, true)
		req, _ := http.NewRequest(
			http.MethodPut,
			srv.URL+"/api/admin/settings/"+KeyScheduleMisfireGraceSeconds,
			strings.NewReader(`{"value":"300"}`),
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
		if v, _ := h.Store.Get(KeyScheduleMisfireGraceSeconds); v != "300" {
			t.Errorf("stored = %q, want 300", v)
		}
	})
	t.Run("bad_integer", func(t *testing.T) {
		_, srv := newHandlerSrv(t, true)
		req, _ := http.NewRequest(
			http.MethodPut,
			srv.URL+"/api/admin/settings/"+KeyScheduleMisfireGraceSeconds,
			strings.NewReader(`{"value":"soon"}`),
		)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("put: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
	})
	t.Run("below_min", func(t *testing.T) {
		_, srv := newHandlerSrv(t, true)
		req, _ := http.NewRequest(
			http.MethodPut,
			srv.URL+"/api/admin/settings/"+KeyScheduleMisfireGraceSeconds,
			strings.NewReader(`{"value":"30"}`),
		)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("put: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
	})
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

func TestListNilStoreReturns503(t *testing.T) {
	h := &Handler{CanManage: func(context.Context) bool { return true }}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/admin/settings")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

func TestListAllError500(t *testing.T) {
	h := &Handler{
		Store:     &errStore{allErr: errors.New("db down")},
		CanManage: func(context.Context) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/admin/settings")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestPutNilStoreReturns503(t *testing.T) {
	h := &Handler{CanManage: func(context.Context) bool { return true }}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPut,
		srv.URL+"/api/admin/settings/"+KeyRunHistoryLimit,
		strings.NewReader(`{"value":"200"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

func TestPutBadJSON(t *testing.T) {
	_, srv := newHandlerSrv(t, true)
	req, _ := http.NewRequest(http.MethodPut,
		srv.URL+"/api/admin/settings/"+KeyRunHistoryLimit,
		strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestPutUpdateConcurrencyNonInteger(t *testing.T) {
	_, srv := newHandlerSrv(t, true)
	req, _ := http.NewRequest(http.MethodPut,
		srv.URL+"/api/admin/settings/"+KeyUpdateConcurrencyLimit,
		strings.NewReader(`{"value":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestPutUpdateConcurrencyOutOfRange(t *testing.T) {
	_, srv := newHandlerSrv(t, true)
	req, _ := http.NewRequest(http.MethodPut,
		srv.URL+"/api/admin/settings/"+KeyUpdateConcurrencyLimit,
		strings.NewReader(`{"value":"-1"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestPutInternalErrorOnStoreFailure(t *testing.T) {
	h := &Handler{
		Store:     &errStore{setErr: errors.New("write failure")},
		CanManage: func(context.Context) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPut,
		srv.URL+"/api/admin/settings/"+KeyRunHistoryLimit,
		strings.NewReader(`{"value":"100"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestAllowedNilCanManageAllowsThrough(t *testing.T) {
	dsn := "file:" + t.TempDir() + "/nil.db"
	db, _ := database.Open(dsn)
	t.Cleanup(func() { _ = db.Close() })
	store, _ := NewSQLiteStore(db)
	h := &Handler{Store: store}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/admin/settings")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (nil CanManage permits)", resp.StatusCode)
	}
}

// newFakeHandlerSrv builds a Handler over an in-memory fakeStore (no
// audit) so log-level dispatch — including the OnLogLevelChange hook —
// can be asserted without a real DB.
func newFakeHandlerSrv(t *testing.T) (*fakeStore, *[]string, *httptest.Server) {
	t.Helper()
	store := newFakeStore()
	var applied []string
	h := &Handler{
		Store:     store,
		CanManage: func(_ context.Context) bool { return true },
		OnLogLevelChange: func(component, level string) {
			applied = append(applied, component+"="+level)
		},
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return store, &applied, srv
}

func putValue(t *testing.T, srv *httptest.Server, key, value string) int {
	t.Helper()
	req, _ := http.NewRequest(
		http.MethodPut,
		srv.URL+"/api/admin/settings/"+key,
		strings.NewReader(`{"value":"`+value+`"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func TestPutLogLevelHappyPath(t *testing.T) {
	store, applied, srv := newFakeHandlerSrv(t)
	if code := putValue(t, srv, LogLevelKey("schedule"), "warn"); code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", code)
	}
	if v, _ := store.Get(LogLevelKey("schedule")); v != "warn" {
		t.Errorf("stored = %q, want warn", v)
	}
	if len(*applied) != 1 || (*applied)[0] != "schedule=warn" {
		t.Errorf("OnLogLevelChange calls = %v, want [schedule=warn]", *applied)
	}
}

func TestPutLogLevelRejectsBadLevel(t *testing.T) {
	_, applied, srv := newFakeHandlerSrv(t)
	if code := putValue(t, srv, LogLevelKey("probe"), "loud"); code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", code)
	}
	if len(*applied) != 0 {
		t.Errorf("OnLogLevelChange should not fire on a rejected value, got %v", *applied)
	}
}

func TestPutLogLevelUnknownComponentIs404(t *testing.T) {
	_, _, srv := newFakeHandlerSrv(t)
	if code := putValue(t, srv, LogLevelKey("bogus"), "info"); code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", code)
	}
}

func TestListSurfacesLogLevelDefaults(t *testing.T) {
	_, srv := newHandlerSrv(t, true)
	resp, err := http.Get(srv.URL + "/api/admin/settings")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var got settingsResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, c := range []string{"probe", "alert", "schedule", "notification", "promtargets", "scrape", "request"} {
		if got.Settings[LogLevelKey(c)] != DefaultLogLevel {
			t.Errorf("%s = %q, want default %q", LogLevelKey(c), got.Settings[LogLevelKey(c)], DefaultLogLevel)
		}
	}
}

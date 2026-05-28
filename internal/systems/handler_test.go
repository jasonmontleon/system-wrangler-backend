// SPDX-License-Identifier: Apache-2.0

package systems

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"system-wrangler-backend/internal/labels"
)

func newTestServer(t *testing.T) (*httptest.Server, *MemStore) {
	t.Helper()
	store := newTestStore()
	mux := http.NewServeMux()
	NewHandler(store).Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, store
}

func decodeJSON(t *testing.T, r io.Reader, v any) {
	t.Helper()
	if err := json.NewDecoder(r).Decode(v); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

func TestHandlerOnDeleteFiresOnSuccessOnly(t *testing.T) {
	var called atomic.Int32
	store := newTestStore()
	h := NewHandler(store)
	h.OnDelete = func() { called.Add(1) }
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sys, _ := store.Create(SystemInput{Name: "x", Hostname: "y"})

	// Successful delete fires the callback.
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/systems/"+sys.ID, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if got := called.Load(); got != 1 {
		t.Errorf("after success: called = %d, want 1", got)
	}

	// Second delete (404) does NOT fire the callback.
	req2, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/systems/"+sys.ID, nil)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp2.StatusCode)
	}
	if got := called.Load(); got != 1 {
		t.Errorf("after 404: called = %d, want still 1", got)
	}
}

func TestHandlerOnCreateFiresOnSuccessOnly(t *testing.T) {
	var called atomic.Int32
	store := newTestStore()
	h := NewHandler(store)
	h.OnCreate = func() { called.Add(1) }
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Successful create fires the callback.
	resp, err := http.Post(srv.URL+"/api/systems", "application/json",
		strings.NewReader(`{"name":"x","hostname":"y"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	if got := called.Load(); got != 1 {
		t.Errorf("after success: called = %d, want 1", got)
	}

	// Validation failure does NOT fire the callback.
	resp2, err := http.Post(srv.URL+"/api/systems", "application/json",
		strings.NewReader(`{"name":"","hostname":"y"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp2.StatusCode)
	}
	if got := called.Load(); got != 1 {
		t.Errorf("after validation error: called = %d, want still 1", got)
	}
}

func TestHandlerCreate(t *testing.T) {
	srv, store := newTestServer(t)

	body := strings.NewReader(`{"name":"host1","hostname":"10.0.0.1"}`)
	resp, err := http.Post(srv.URL+"/api/systems", "application/json", body)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/api/systems/id-1" {
		t.Errorf("Location = %q, want /api/systems/id-1", loc)
	}
	var got System
	decodeJSON(t, resp.Body, &got)
	if got.ID != "id-1" || got.Name != "host1" || got.Hostname != "10.0.0.1" {
		t.Errorf("got %+v", got)
	}

	// Verify it actually landed in the store.
	if _, err := store.Get("id-1"); err != nil {
		t.Errorf("not in store: %v", err)
	}
}

func TestHandlerCreateInvalid(t *testing.T) {
	srv, _ := newTestServer(t)
	tests := []struct {
		name string
		body string
		want int
	}{
		{"missing name", `{"hostname":"1.1.1.1"}`, http.StatusBadRequest},
		{"missing hostname", `{"name":"x"}`, http.StatusBadRequest},
		{"bad json", `not json`, http.StatusBadRequest},
		{"unknown field", `{"name":"x","hostname":"y","extra":1}`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := http.Post(srv.URL+"/api/systems", "application/json", strings.NewReader(tt.body))
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tt.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.want)
			}
			var body struct {
				Error string `json:"error"`
			}
			decodeJSON(t, resp.Body, &body)
			if body.Error == "" {
				t.Error("error body missing")
			}
		})
	}
}

func TestHandlerListAndGet(t *testing.T) {
	srv, store := newTestServer(t)
	for _, name := range []string{"a", "b"} {
		if _, err := store.Create(SystemInput{Name: name, Hostname: "1.1.1.1"}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	resp, err := http.Get(srv.URL + "/api/systems")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var systems []System
	decodeJSON(t, resp.Body, &systems)
	if len(systems) != 2 {
		t.Fatalf("len = %d, want 2", len(systems))
	}

	// GET by id
	resp2, err := http.Get(srv.URL + "/api/systems/" + systems[0].ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp2.StatusCode)
	}
	var single System
	decodeJSON(t, resp2.Body, &single)
	if single.ID != systems[0].ID {
		t.Errorf("got %q, want %q", single.ID, systems[0].ID)
	}
}

// TestHandlerListLabelsEnrichmentAndSelector exercises the
// SystemLabels hook (which decorates rows with their label set) and
// the ?labels= selector filter, both added when the labels feature
// landed.
func TestHandlerListLabelsEnrichmentAndSelector(t *testing.T) {
	store := newTestStore()
	a, err := store.Create(SystemInput{Name: "a", Hostname: "a.example"})
	if err != nil {
		t.Fatalf("seed a: %v", err)
	}
	b, err := store.Create(SystemInput{Name: "b", Hostname: "b.example"})
	if err != nil {
		t.Fatalf("seed b: %v", err)
	}
	prod := "prod"
	stg := "staging"
	labelMap := map[string][]labels.Label{
		a.ID: {{Key: "env", Value: &prod}, {Key: "oncall", Value: nil}},
		b.ID: {{Key: "env", Value: &stg}},
	}
	h := NewHandler(store)
	h.SystemLabels = func(ids []string) (map[string][]labels.Label, error) {
		out := make(map[string][]labels.Label, len(ids))
		for _, id := range ids {
			if ls, ok := labelMap[id]; ok {
				out[id] = ls
			}
		}
		return out, nil
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Unfiltered list returns both systems with their labels attached.
	resp := mustGet(t, srv.URL+"/api/systems")
	defer func() { _ = resp.Body.Close() }()
	var all []System
	decodeJSON(t, resp.Body, &all)
	if len(all) != 2 {
		t.Fatalf("len = %d, want 2", len(all))
	}
	for _, s := range all {
		if len(s.Labels) == 0 {
			t.Errorf("system %q has no labels in response", s.Name)
		}
	}

	// ?labels=env=prod returns only system a.
	resp2 := mustGet(t, srv.URL+"/api/systems?labels=env%3Dprod")
	defer func() { _ = resp2.Body.Close() }()
	var filtered []System
	decodeJSON(t, resp2.Body, &filtered)
	if len(filtered) != 1 || filtered[0].ID != a.ID {
		t.Errorf("filtered = %+v, want only %s", filtered, a.ID)
	}

	// Bad selector → 400.
	resp3 := mustGet(t, srv.URL+"/api/systems?labels=env%3D%21bad")
	defer func() { _ = resp3.Body.Close() }()
	if resp3.StatusCode != http.StatusBadRequest {
		t.Errorf("bad selector status = %d, want 400", resp3.StatusCode)
	}
}

// TestHandlerGetLabelsEnrichment ensures the single-system endpoint
// runs through enrichLabels as well so the SPA can avoid a second
// fetch on the detail page.
func TestHandlerGetLabelsEnrichment(t *testing.T) {
	store := newTestStore()
	sys, err := store.Create(SystemInput{Name: "x", Hostname: "x.example"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	prod := "prod"
	h := NewHandler(store)
	h.SystemLabels = func(_ []string) (map[string][]labels.Label, error) {
		return map[string][]labels.Label{sys.ID: {{Key: "env", Value: &prod}}}, nil
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp := mustGet(t, srv.URL+"/api/systems/"+sys.ID)
	defer func() { _ = resp.Body.Close() }()
	var got System
	decodeJSON(t, resp.Body, &got)
	if len(got.Labels) != 1 || got.Labels[0].Key != "env" {
		t.Errorf("labels = %+v, want [env=prod]", got.Labels)
	}
}

func mustGet(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec,noctx
	if err != nil {
		t.Fatalf("get %q: %v", url, err)
	}
	return resp
}

func TestHandlerGetMissing(t *testing.T) {
	srv, _ := newTestServer(t)
	resp, err := http.Get(srv.URL + "/api/systems/nope")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandlerDelete(t *testing.T) {
	srv, store := newTestServer(t)
	h, _ := store.Create(SystemInput{Name: "x", Hostname: "1.1.1.1"})

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/systems/"+h.ID, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}

	if _, err := store.Get(h.ID); !errors.Is(err, ErrNotFound) {
		t.Error("system still present after delete")
	}

	// Second delete should 404
	req2, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/systems/"+h.ID, nil)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("second delete status = %d, want 404", resp2.StatusCode)
	}
}

func TestHandlerSetPlatform(t *testing.T) {
	srv, store := newTestServer(t)
	h, _ := store.Create(SystemInput{Name: "x", Hostname: "1.1.1.1"})

	body := strings.NewReader(`{"isWindows":true}`)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/systems/"+h.ID+"/platform", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}

	got, err := store.Get(h.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.IsWindows {
		t.Errorf("IsWindows did not persist")
	}

	// Toggle back to false.
	off := strings.NewReader(`{"isWindows":false}`)
	req2, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/systems/"+h.ID+"/platform", off)
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusNoContent {
		t.Fatalf("toggle-off status = %d, want 204", resp2.StatusCode)
	}
	got, _ = store.Get(h.ID)
	if got.IsWindows {
		t.Errorf("IsWindows did not clear")
	}
}

func TestHandlerSetPlatform404Missing(t *testing.T) {
	srv, _ := newTestServer(t)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/systems/nope/platform",
		strings.NewReader(`{"isWindows":true}`))
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandlerSetPlatform400BadJSON(t *testing.T) {
	srv, store := newTestServer(t)
	h, _ := store.Create(SystemInput{Name: "x", Hostname: "1.1.1.1"})
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/systems/"+h.ID+"/platform",
		strings.NewReader(`not json`))
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlerSetPlatform403Locked(t *testing.T) {
	store := newTestStore()
	h, _ := store.Create(SystemInput{Name: "x", Hostname: "1.1.1.1"})
	hh := NewHandler(store)
	hh.CanEdit = func(_ context.Context, _ System) bool { return false }
	mux := http.NewServeMux()
	hh.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/systems/"+h.ID+"/platform",
		strings.NewReader(`{"isWindows":true}`))
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHandlerBulkEvent(t *testing.T) {
	type call struct {
		action, selector string
		ids              []string
		skipped          []BulkSkipped
	}
	captured := &call{}
	h := NewHandler(newTestStore())
	h.BulkAudit = func(
		_ context.Context,
		action, selector string,
		ids []string,
		skipped []BulkSkipped,
	) {
		captured.action = action
		captured.selector = selector
		captured.ids = ids
		captured.skipped = skipped
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body := strings.NewReader(`{
		"action": "check",
		"selector": "env=prod",
		"systemIds": ["a", "b"],
		"skipped": [{"systemId": "c", "reason": "unreachable"}]
	}`)
	resp, err := http.Post(srv.URL+"/api/systems/bulk-event", "application/json", body) //nolint:noctx,gosec
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if captured.action != "check" || captured.selector != "env=prod" {
		t.Errorf("captured = %+v", captured)
	}
	if len(captured.ids) != 2 || len(captured.skipped) != 1 {
		t.Errorf("captured ids/skipped = %+v", captured)
	}
}

func TestHandlerBulkEvent_RejectsUnknownAction(t *testing.T) {
	h := NewHandler(newTestStore())
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/systems/bulk-event", "application/json",
		strings.NewReader(`{"action":"delete","systemIds":["a"]}`)) //nolint:noctx,gosec
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlerBulkEvent_RejectsEmptySystemIDs(t *testing.T) {
	h := NewHandler(newTestStore())
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/systems/bulk-event", "application/json",
		strings.NewReader(`{"action":"check","systemIds":[]}`)) //nolint:noctx,gosec
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlerBulkEvent_NoAuditHookStill204(t *testing.T) {
	h := NewHandler(newTestStore())
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/systems/bulk-event", "application/json",
		strings.NewReader(`{"action":"apply","systemIds":["a"]}`)) //nolint:noctx,gosec
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
}

// Verifies internal errors from the store surface as 500. Uses a stub store
// since MemStore can't be made to fail List/Get/Delete naturally.
func TestHandlerStoreErrors(t *testing.T) {
	failErr := errors.New("boom")
	stub := &stubStore{err: failErr}
	mux := http.NewServeMux()
	NewHandler(stub).Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cases := []struct {
		name string
		req  func() *http.Request
	}{
		{"list", func() *http.Request {
			r, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/systems", nil)
			return r
		}},
		{"get", func() *http.Request {
			r, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/systems/x", nil)
			return r
		}},
		{"create", func() *http.Request {
			r, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/systems",
				bytes.NewBufferString(`{"name":"x","hostname":"y"}`))
			return r
		}},
		{"delete", func() *http.Request {
			r, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/systems/x", nil)
			return r
		}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := http.DefaultClient.Do(tt.req())
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusInternalServerError {
				t.Errorf("status = %d, want 500", resp.StatusCode)
			}
		})
	}
}

type stubStore struct{ err error }

func (s *stubStore) Create(SystemInput) (System, error)            { return System{}, s.err }
func (s *stubStore) CreateTx(*sql.Tx, SystemInput) (System, error) { return System{}, s.err }
func (s *stubStore) Get(string) (System, error)                    { return System{}, s.err }
func (s *stubStore) List() ([]System, error)                       { return nil, s.err }
func (s *stubStore) Delete(string) error                           { return s.err }
func (s *stubStore) DeleteTx(*sql.Tx, string) error                { return s.err }
func (s *stubStore) UpdateProbe(string, bool, time.Time) error {
	return s.err
}
func (s *stubStore) SetGroup(string, *string) error            { return s.err }
func (s *stubStore) SetPlatform(string, bool) error            { return s.err }
func (s *stubStore) SetPlatformTx(*sql.Tx, string, bool) error { return s.err }
func (s *stubStore) SetPlatformInfo(string, string, string, string) error {
	return s.err
}

// SPDX-License-Identifier: Apache-2.0

package systems

import (
	"bytes"
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
func (s *stubStore) SetGroup(string, *string) error { return s.err }

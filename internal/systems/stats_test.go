// SPDX-License-Identifier: Apache-2.0

package systems

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestListEnrichesWithSystemStats verifies the per-request hook
// merges the injected stats into each row, leaves rows the producer
// doesn't mention untouched, and writes a PendingUpdates pointer
// even when the count is 0 (so "checked, none pending" renders
// distinct from "never checked").
func TestListEnrichesWithSystemStats(t *testing.T) {
	store := newTestStore()
	a, _ := store.Create(SystemInput{Name: "a", Hostname: "a.example"})
	b, _ := store.Create(SystemInput{Name: "b", Hostname: "b.example"})

	checked := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	h := NewHandler(store)
	h.SystemStats = func() (map[string]Stats, error) {
		return map[string]Stats{
			a.ID: {LastCheckedAt: &checked, PendingUpdates: 4},
			// b is not in the map — represents "never checked."
		}, nil
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/api/systems")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var got []System
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byID := map[string]System{}
	for _, s := range got {
		byID[s.ID] = s
	}
	gotA := byID[a.ID]
	if gotA.LastCheckedAt == nil || !gotA.LastCheckedAt.Equal(checked) {
		t.Errorf("A.LastCheckedAt = %v, want %v", gotA.LastCheckedAt, checked)
	}
	if gotA.PendingUpdates == nil || *gotA.PendingUpdates != 4 {
		t.Errorf("A.PendingUpdates = %v, want 4", gotA.PendingUpdates)
	}
	gotB := byID[b.ID]
	if gotB.LastCheckedAt != nil {
		t.Errorf("B.LastCheckedAt = %v, want nil (never checked)", gotB.LastCheckedAt)
	}
	if gotB.PendingUpdates != nil {
		t.Errorf("B.PendingUpdates = %v, want nil (never checked)", gotB.PendingUpdates)
	}
}

// TestListEnrichesWithRunningFlag pins the Phase-1 SSE contract on
// the systems handler side: a Stats.Running=true producer value must
// land on the serialized System as `running: true`, which is what
// the SPA reads to keep a row's spinner lit across navigation.
func TestListEnrichesWithRunningFlag(t *testing.T) {
	store := newTestStore()
	busy, _ := store.Create(SystemInput{Name: "busy", Hostname: "busy.example"})
	idle, _ := store.Create(SystemInput{Name: "idle", Hostname: "idle.example"})
	h := NewHandler(store)
	h.SystemStats = func() (map[string]Stats, error) {
		return map[string]Stats{
			busy.ID: {Running: true},
			idle.ID: {Running: false},
		}, nil
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/api/systems")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var got []System
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byID := map[string]System{}
	for _, s := range got {
		byID[s.ID] = s
	}
	if !byID[busy.ID].Running {
		t.Errorf("busy.Running = false, want true")
	}
	if byID[idle.ID].Running {
		t.Errorf("idle.Running = true, want false")
	}
}

// TestListSystemStatsFailureLogsAndContinues asserts the API does
// not refuse to serve systems just because the stats producer
// errored — the rows simply lack the enrichment.
func TestListSystemStatsFailureLogsAndContinues(t *testing.T) {
	store := newTestStore()
	_, _ = store.Create(SystemInput{Name: "a", Hostname: "a.example"})
	h := NewHandler(store)
	h.SystemStats = func() (map[string]Stats, error) {
		return nil, errors.New("boom")
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/api/systems")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 even on stats error", resp.StatusCode)
	}
	var got []System
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if len(got) != 1 {
		t.Fatalf("len = %d", len(got))
	}
	if got[0].PendingUpdates != nil {
		t.Errorf("PendingUpdates should be nil when stats failed: %v", got[0].PendingUpdates)
	}
}

// TestListSurfacesLastRunFailure verifies the stats producer's
// LastRunFailed / LastRunReason flow through to the JSON response.
func TestListSurfacesLastRunFailure(t *testing.T) {
	store := newTestStore()
	a, _ := store.Create(SystemInput{Name: "a", Hostname: "a.example"})
	h := NewHandler(store)
	h.SystemStats = func() (map[string]Stats, error) {
		return map[string]Stats{
			a.ID: {LastRunFailed: true, LastRunReason: "apply exit 2"},
		}, nil
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/api/systems")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var got []System
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d", len(got))
	}
	if !got[0].LastRunFailed {
		t.Errorf("LastRunFailed = false, want true")
	}
	if got[0].LastRunReason != "apply exit 2" {
		t.Errorf("LastRunReason = %q", got[0].LastRunReason)
	}
}

// TestGetEnrichesWithSystemStats covers the single-system path.
func TestGetEnrichesWithSystemStats(t *testing.T) {
	store := newTestStore()
	a, _ := store.Create(SystemInput{Name: "a", Hostname: "a.example"})
	checked := time.Now().UTC()
	h := NewHandler(store)
	h.SystemStats = func() (map[string]Stats, error) {
		return map[string]Stats{a.ID: {LastCheckedAt: &checked, PendingUpdates: 0}}, nil
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/api/systems/" + a.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var got System
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.PendingUpdates == nil || *got.PendingUpdates != 0 {
		t.Errorf("PendingUpdates = %v, want pointer to 0", got.PendingUpdates)
	}
	if got.LastCheckedAt == nil {
		t.Errorf("LastCheckedAt nil")
	}
}

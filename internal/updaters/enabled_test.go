// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"system-wrangler-backend/internal/systems"
)

func TestSetEnabledRoundTrip(t *testing.T) {
	store := newStore(t)
	now := time.Now()
	if err := store.UpsertAvailability("sys-1", "builtin.dnf", now); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Fresh inserts default to enabled=true.
	list, err := store.AvailabilityFor("sys-1")
	if err != nil {
		t.Fatalf("AvailabilityFor: %v", err)
	}
	if len(list) != 1 || !list[0].Enabled {
		t.Fatalf("default not enabled: %+v", list)
	}
	if err := store.SetEnabled("sys-1", "builtin.dnf", false); err != nil {
		t.Fatalf("SetEnabled false: %v", err)
	}
	list, _ = store.AvailabilityFor("sys-1")
	if list[0].Enabled {
		t.Errorf("still enabled after SetEnabled(false): %+v", list[0])
	}
	// Re-inspect must not flip a deliberately-disabled row back on.
	if err := store.UpsertAvailability("sys-1", "builtin.dnf", now.Add(time.Minute)); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	list, _ = store.AvailabilityFor("sys-1")
	if list[0].Enabled {
		t.Errorf("re-inspection silently re-enabled: %+v", list[0])
	}
}

func TestSetEnabledNotFound(t *testing.T) {
	store := newStore(t)
	if err := store.SetEnabled("sys-x", "builtin.dnf", true); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestSetEnabledRejectsEmpty(t *testing.T) {
	store := newStore(t)
	if err := store.SetEnabled("", "builtin.dnf", true); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty system: err = %v", err)
	}
}

func TestListSystemUpdatersUnion(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	// Seed: dnf detected and enabled by default.
	now := time.Now()
	if err := rf.store.UpsertAvailability(rf.systemID, "builtin.dnf", now); err != nil {
		t.Fatalf("seed: %v", err)
	}
	resp, err := http.Get(srv.URL + "/api/systems/" + rf.systemID + "/updaters")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got systemUpdatersResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Updaters) == 0 {
		t.Fatalf("expected at least one row, got 0")
	}
	var dnf *systemUpdaterDTO
	for i := range got.Updaters {
		if got.Updaters[i].UpdaterID == "builtin.dnf" {
			dnf = &got.Updaters[i]
		}
	}
	if dnf == nil || !dnf.Installed || !dnf.Enabled {
		t.Errorf("dnf row = %+v, want installed+enabled", dnf)
	}
}

func TestSetEnabledHandlerToggle(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	if err := rf.store.UpsertAvailability(rf.systemID, "builtin.dnf", time.Now()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	req, _ := http.NewRequest(
		http.MethodPut,
		srv.URL+"/api/systems/"+rf.systemID+"/updaters/builtin.dnf/enabled",
		strings.NewReader(`{"enabled": false}`),
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
	list, _ := rf.store.AvailabilityFor(rf.systemID)
	if list[0].Enabled {
		t.Errorf("flag did not flip: %+v", list[0])
	}
}

func TestSetEnabledHandlerNotFound(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	req, _ := http.NewRequest(
		http.MethodPut,
		srv.URL+"/api/systems/"+rf.systemID+"/updaters/builtin.dnf/enabled",
		strings.NewReader(`{"enabled": true}`),
	)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (not detected yet)", resp.StatusCode)
	}
}

func TestSetEnabledHandlerForbidden(t *testing.T) {
	h, srv, rf := newHandlerFixture(t)
	h.CanOperateSystem = func(context.Context, systems.System) bool { return false }
	req, _ := http.NewRequest(
		http.MethodPut,
		srv.URL+"/api/systems/"+rf.systemID+"/updaters/builtin.dnf/enabled",
		strings.NewReader(`{"enabled": true}`),
	)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestListSystemUpdatersHidden(t *testing.T) {
	h, srv, rf := newHandlerFixture(t)
	h.CanReadSystem = func(context.Context, systems.System) bool { return false }
	resp, err := http.Get(srv.URL + "/api/systems/" + rf.systemID + "/updaters")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (hidden system)", resp.StatusCode)
	}
}

func TestSetEnabledBrokenStore(t *testing.T) {
	rf := newRunnerFixture(t)
	broken := brokenStore(t)
	h := &Handler{
		Runner:           rf.runner,
		Store:            broken,
		Systems:          &systemsLookupForRunner{get: func(id string) (systems.System, error) { return loadSystemBare(rf, id) }},
		CanOperateSystem: func(context.Context, systems.System) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(
		http.MethodPut,
		srv.URL+"/api/systems/"+rf.systemID+"/updaters/builtin.dnf/enabled",
		strings.NewReader(`{"enabled": true}`),
	)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestSetEnabledBadJSON(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	if err := rf.store.UpsertAvailability(rf.systemID, "builtin.dnf", time.Now()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	req, _ := http.NewRequest(
		http.MethodPut,
		srv.URL+"/api/systems/"+rf.systemID+"/updaters/builtin.dnf/enabled",
		strings.NewReader("not json"),
	)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// Smoke: the addEnabledColumn migration is idempotent across boots
// of an already-migrated DB.
func TestAddEnabledColumnIdempotent(t *testing.T) {
	_, _, _, db := newStoreWithSiblings(t)
	if err := addEnabledColumn(db); err != nil {
		t.Errorf("second migration: %v", err)
	}
}

func TestListSystemUpdatersRunnerUnconfigured(t *testing.T) {
	rf := newRunnerFixture(t)
	h := &Handler{
		Runner:        nil,
		Store:         rf.store,
		Systems:       &systemsLookupForRunner{get: func(id string) (systems.System, error) { return loadSystemBare(rf, id) }},
		CanReadSystem: func(context.Context, systems.System) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/api/systems/" + rf.systemID + "/updaters")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

func TestListSystemUpdatersBrokenAvailability(t *testing.T) {
	// Hand-build a Handler whose Runner.Registry works but whose
	// outer Store errors on AvailabilityFor — exercises the second
	// 500 branch in listSystemUpdaters (registry succeeded, the
	// availability lookup did not).
	rf := newRunnerFixture(t)
	broken := brokenStore(t)
	h := &Handler{
		Runner:        rf.runner, // registry is fine
		Store:         broken,    // AvailabilityFor will error
		Systems:       &systemsLookupForRunner{get: func(id string) (systems.System, error) { return loadSystemBare(rf, id) }},
		CanReadSystem: func(context.Context, systems.System) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/api/systems/" + rf.systemID + "/updaters")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestListSystemUpdatersBrokenStore(t *testing.T) {
	rf := newRunnerFixture(t)
	broken := brokenStore(t)
	h := &Handler{
		Runner: &Runner{
			Registry: NewRegistry(broken), // Registry.All errors out
			Store:    broken,
			Ansible:  rf.runner.Ansible,
			Audit:    rf.auditStore,
		},
		Store:         broken,
		Systems:       &systemsLookupForRunner{get: func(id string) (systems.System, error) { return loadSystemBare(rf, id) }},
		CanReadSystem: func(context.Context, systems.System) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/api/systems/" + rf.systemID + "/updaters")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestSetEnabledRejectsEmptyUpdater(t *testing.T) {
	// Path param is required by mux routing, so we exercise the
	// store-level guard directly. Empty updater_id can't happen via
	// HTTP, but the validation belt-and-braces stays useful for any
	// future caller.
	store := newStore(t)
	if err := store.SetEnabled("sys", "", true); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}

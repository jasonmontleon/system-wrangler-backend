// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"system-wrangler-backend/internal/ansible"
	"system-wrangler-backend/internal/systems"
)

// systemsLookupForRunner wraps the systems store in the slice the
// updater handler asks for. The test fixture's *systems.SQLiteStore
// is the production type so it satisfies the existing handler.Get
// signature directly — this wrapper exists for the rare test that
// wants to force a different response.
type systemsLookupForRunner struct {
	get func(id string) (systems.System, error)
}

func (l *systemsLookupForRunner) Get(id string) (systems.System, error) {
	return l.get(id)
}

func newHandlerFixture(t *testing.T) (*Handler, *httptest.Server, *runnerFixture) {
	t.Helper()
	rf := newRunnerFixture(t)
	h := &Handler{
		Runner:           rf.runner,
		Store:            rf.store,
		Systems:          &systemsLookupForRunner{get: func(id string) (systems.System, error) { return loadSystem(t, rf, id) }},
		CanOperateSystem: func(context.Context, systems.System) bool { return true },
		CanReadSystem:    func(context.Context, systems.System) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return h, srv, rf
}

func loadSystem(t *testing.T, rf *runnerFixture, id string) (systems.System, error) {
	t.Helper()
	if id != rf.systemID {
		return systems.System{}, systems.ErrNotFound
	}
	return systems.System{ID: rf.systemID, Name: "host-x", Hostname: "x.example"}, nil
}

func TestHandlerInspect(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	rf.queue(ansible.Run{
		Status:   ansible.RunSuccess,
		ExitCode: 0,
		Stdout:   []byte(`"msg": "SW_DETECTED: builtin.dnf"`),
	}, nil)
	resp, err := http.Post(srv.URL+"/api/systems/"+rf.systemID+"/inspect", "application/json", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got inspectDTO
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Status != ansible.RunSuccess {
		t.Errorf("status = %q, want success", got.Status)
	}
	if len(got.Detected) != 1 || got.Detected[0] != "builtin.dnf" {
		t.Errorf("detected = %v", got.Detected)
	}
	if got.RunID == "" {
		t.Errorf("runId not surfaced")
	}
}

func TestHandlerCheckAndApply(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	// Two queued responses cover both POSTs.
	rf.queue(ansible.Run{
		Status:   ansible.RunSuccess,
		Stdout:   []byte(`"msg": "SW_AFFECTED_COUNT: 5"`),
		ExitCode: 0,
	}, nil)
	rf.queue(ansible.Run{
		Status:   ansible.RunSuccess,
		Stdout:   []byte(`"msg": "SW_AFFECTED_COUNT: 5"`),
		ExitCode: 0,
	}, nil)

	check := postJSON(t, srv.URL+"/api/systems/"+rf.systemID+"/updaters/builtin.dnf/check")
	if check.StatusCode != http.StatusOK {
		t.Fatalf("check status = %d", check.StatusCode)
	}
	var checkDTO runDTO
	_ = json.NewDecoder(check.Body).Decode(&checkDTO)
	_ = check.Body.Close()
	if checkDTO.Kind != RunKindCheck || checkDTO.AffectedCount != 5 {
		t.Errorf("check = %+v", checkDTO)
	}

	apply := postJSON(t, srv.URL+"/api/systems/"+rf.systemID+"/updaters/builtin.dnf/apply")
	if apply.StatusCode != http.StatusOK {
		t.Fatalf("apply status = %d", apply.StatusCode)
	}
	var applyDTO runDTO
	_ = json.NewDecoder(apply.Body).Decode(&applyDTO)
	_ = apply.Body.Close()
	if applyDTO.Kind != RunKindApply {
		t.Errorf("apply kind = %q", applyDTO.Kind)
	}
}

func TestHandlerCheckUnknownUpdater(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	resp := postJSON(t, srv.URL+"/api/systems/"+rf.systemID+"/updaters/builtin.nope/check")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandlerConflictReturns409WithHolder(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	// Seed the lock so the next call collides.
	if err := rf.store.AcquireLock(rf.systemID, "holder-run", time.Now()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	resp := postJSON(t, srv.URL+"/api/systems/"+rf.systemID+"/inspect")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
	var got conflictDTO
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got.ConflictingRun != "holder-run" {
		t.Errorf("conflictingRun = %q, want holder-run", got.ConflictingRun)
	}
}

func TestHandlerForbidden(t *testing.T) {
	h, srv, rf := newHandlerFixture(t)
	h.CanOperateSystem = func(context.Context, systems.System) bool { return false }
	resp := postJSON(t, srv.URL+"/api/systems/"+rf.systemID+"/inspect")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHandlerSystemNotFound(t *testing.T) {
	_, srv, _ := newHandlerFixture(t)
	resp := postJSON(t, srv.URL+"/api/systems/ghost/inspect")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandlerListRuns(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	// Seed two runs to exercise the listing and the limit param.
	for i, kind := range []RunKind{RunKindInspect, RunKindCheck} {
		if err := rf.store.InsertRun(Run{
			ID:        "r-" + string(kind),
			SystemID:  rf.systemID,
			UpdaterID: "builtin.dnf",
			Kind:      kind,
			StartedAt: time.Now().Add(-time.Duration(i) * time.Minute),
		}); err != nil {
			t.Fatalf("seed run %d: %v", i, err)
		}
	}
	resp, err := http.Get(srv.URL + "/api/systems/" + rf.systemID + "/updater-runs?limit=10")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got runsResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Runs) != 2 {
		t.Errorf("runs = %d, want 2", len(got.Runs))
	}
}

func TestHandlerListRunsHiddenSystem(t *testing.T) {
	h, srv, rf := newHandlerFixture(t)
	h.CanReadSystem = func(context.Context, systems.System) bool { return false }
	resp, err := http.Get(srv.URL + "/api/systems/" + rf.systemID + "/updater-runs")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (hidden system)", resp.StatusCode)
	}
}

func TestHandlerRunnerUnconfigured(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	// Surgically nil the runner — service unavailable should fall
	// out of inspect / check / apply.
	h := &Handler{
		Runner:           nil,
		Store:            rf.store,
		Systems:          &systemsLookupForRunner{get: func(id string) (systems.System, error) { return loadSystem(t, rf, id) }},
		CanOperateSystem: func(context.Context, systems.System) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv2 := httptest.NewServer(mux)
	t.Cleanup(srv2.Close)
	resp := postJSON(t, srv2.URL+"/api/systems/"+rf.systemID+"/inspect")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("inspect status = %d, want 503", resp.StatusCode)
	}
	resp2 := postJSON(t, srv2.URL+"/api/systems/"+rf.systemID+"/updaters/builtin.dnf/check")
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("check status = %d, want 503", resp2.StatusCode)
	}
	_ = srv // silence unused
}

func postJSON(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/json", nil) //nolint:gosec
	if err != nil {
		t.Fatalf("post %q: %v", url, err)
	}
	return resp
}

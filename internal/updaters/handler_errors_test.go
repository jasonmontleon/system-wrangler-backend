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

	"system-wrangler-backend/internal/ansible"
	"system-wrangler-backend/internal/systems"
)

// systemsLookupErr returns the supplied err on every Get; lets the
// test exercise the 500 branch in loadSystem.
type systemsLookupErr struct{ err error }

func (s *systemsLookupErr) Get(_ string) (systems.System, error) { return systems.System{}, s.err }

func TestHandlerLookupReturns500OnUnknownError(t *testing.T) {
	rf := newRunnerFixture(t)
	h := &Handler{
		Runner:           rf.runner,
		Store:            rf.store,
		Systems:          &systemsLookupErr{err: errors.New("disk fell off")},
		CanOperateSystem: func(context.Context, systems.System) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp := postJSON(t, srv.URL+"/api/systems/x/inspect")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandlerForbiddenCheckAndApply(t *testing.T) {
	h, srv, rf := newHandlerFixture(t)
	h.CanOperateSystem = func(context.Context, systems.System) bool { return false }
	for _, ep := range []string{"check", "apply"} {
		resp := postJSON(t, srv.URL+"/api/systems/"+rf.systemID+"/updaters/builtin.dnf/"+ep)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", ep, resp.StatusCode)
		}
	}
}

func TestHandlerInspectAnsibleErrorReturns500(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	rf.queue(ansible.Run{Status: ansible.RunFailure, ExitCode: -1}, errors.New("exec died"))
	resp := postJSON(t, srv.URL+"/api/systems/"+rf.systemID+"/inspect")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandlerCheckAnsibleErrorReturns500(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	rf.queue(ansible.Run{Status: ansible.RunFailure, ExitCode: -1}, errors.New("exec died"))
	resp := postJSON(t, srv.URL+"/api/systems/"+rf.systemID+"/updaters/builtin.dnf/check")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandlerListRunsLimitInvalidIgnored(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	// limit=abc is non-numeric: handler falls back to its default;
	// we just confirm the call still succeeds.
	resp, err := http.Get(srv.URL + "/api/systems/" + rf.systemID + "/updater-runs?limit=abc")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestHandlerListRunsReturnsRow(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	// Seed one finished run so the DTO has both startedAt and
	// finishedAt populated; verifies the optional fields serialize.
	if err := rf.store.InsertRun(Run{
		ID:        "r-1",
		SystemID:  rf.systemID,
		UpdaterID: "builtin.dnf",
		Kind:      RunKindApply,
		StartedAt: time.Now(),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := rf.store.FinishRun("r-1", time.Now(), 0, 0, "ok\n"); err != nil {
		t.Fatalf("finish: %v", err)
	}
	resp, _ := http.Get(srv.URL + "/api/systems/" + rf.systemID + "/updater-runs")
	defer func() { _ = resp.Body.Close() }()
	var got runsResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Runs) != 1 || got.Runs[0].LogTail != "ok\n" {
		t.Errorf("runs = %+v", got.Runs)
	}
}

func TestHandlerCanOperateNilDefaultsTrue(t *testing.T) {
	rf := newRunnerFixture(t)
	h := &Handler{
		Runner:           rf.runner,
		Store:            rf.store,
		Systems:          &systemsLookupForRunner{get: func(id string) (systems.System, error) { return loadSystemBare(rf, id) }},
		CanOperateSystem: nil, // explicit
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rf.queue(ansible.Run{Status: ansible.RunSuccess}, nil)
	resp := postJSON(t, srv.URL+"/api/systems/"+rf.systemID+"/inspect")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (nil canOperate defaults to allowed)", resp.StatusCode)
	}
}

func loadSystemBare(rf *runnerFixture, id string) (systems.System, error) {
	if id != rf.systemID {
		return systems.System{}, systems.ErrNotFound
	}
	return systems.System{ID: rf.systemID, Name: "host-x", Hostname: "x.example"}, nil
}

// Keep the strings import live for the body sniff below.
var _ = strings.Contains

// SPDX-License-Identifier: Apache-2.0

package exporters

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"system-wrangler-backend/internal/systems"
)

// erroringLookup returns a non-NotFound error so the handler hits the 500 path.
type erroringLookup struct{ err error }

func (e erroringLookup) Get(string) (systems.System, error) {
	return systems.System{}, e.err
}

func TestHandlerSystemLookupError500(t *testing.T) {
	rf := newRunnerFixture(t)
	h := &Handler{
		Runner:           rf.runner,
		Store:            rf.store,
		Systems:          erroringLookup{err: errors.New("db down")},
		CanReadSystem:    func(context.Context, systems.System) bool { return true },
		CanOperateSystem: func(context.Context, systems.System) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/systems/x/exporters")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandlerRunNotFoundOnUnknownExporter(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	resp, _ := http.Post(srv.URL+"/api/systems/"+rf.systemID+"/exporters/builtin.unknown/install", "application/json", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandlerListRuns404(t *testing.T) {
	_, srv, _ := newHandlerFixture(t)
	resp, _ := http.Get(srv.URL + "/api/systems/missing/exporter-runs")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandlerListRunsRespectsLimitQuery(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	resp, _ := http.Get(srv.URL + "/api/systems/" + rf.systemID + "/exporter-runs?limit=5")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestHandlerListRunsIgnoresBogusLimit(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	resp, _ := http.Get(srv.URL + "/api/systems/" + rf.systemID + "/exporter-runs?limit=notanumber")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestHandlerSetSettingsForbidden(t *testing.T) {
	rf := newRunnerFixture(t)
	h := &Handler{
		Runner:           rf.runner,
		Store:            rf.store,
		Systems:          lookupFn(func(string) (systems.System, error) { return systems.System{ID: rf.systemID}, nil }),
		CanOperateSystem: func(context.Context, systems.System) bool { return false },
		CanReadSystem:    func(context.Context, systems.System) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/systems/"+rf.systemID+"/exporter-settings", bytes.NewBufferString(`{"scrapeMode":"localhost"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHandlerSetSettingsBadJSON(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/systems/"+rf.systemID+"/exporter-settings", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlerListRunsScopeBlocked(t *testing.T) {
	rf := newRunnerFixture(t)
	h := &Handler{
		Runner:        rf.runner,
		Store:         rf.store,
		Systems:       lookupFn(func(string) (systems.System, error) { return systems.System{ID: rf.systemID}, nil }),
		CanReadSystem: func(context.Context, systems.System) bool { return false },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/systems/" + rf.systemID + "/exporter-runs")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandlerListProbeError(t *testing.T) {
	// Probe failure must not break the list — handler just leaves
	// DetectedPkgManagers empty and continues.
	rf := newRunnerFixture(t)
	h := &Handler{
		Runner:           rf.runner,
		Store:            rf.store,
		Systems:          lookupFn(func(string) (systems.System, error) { return systems.System{ID: rf.systemID}, nil }),
		Probe:            stubProbe{err: errors.New("boom")},
		CanReadSystem:    func(context.Context, systems.System) bool { return true },
		CanOperateSystem: func(context.Context, systems.System) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/systems/" + rf.systemID + "/exporters")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

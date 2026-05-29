// SPDX-License-Identifier: Apache-2.0

package exporters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

type listErrStore struct {
	Store
	err error
}

func (l *listErrStore) ListSystemExporters(string) ([]SystemExporter, error) {
	return nil, l.err
}

type listRunsErrStore struct {
	Store
	err error
}

func (l *listRunsErrStore) ListRuns(string, int) ([]Run, error) { return nil, l.err }

type setScrapeModeErrStore struct {
	Store
	err error
}

func (s *setScrapeModeErrStore) SetScrapeMode(string, ScrapeMode) error { return s.err }

type registryErrStore struct {
	Store
	err error
}

// All() on Registry calls Store.ListCustom; we fail that.
func (r *registryErrStore) ListCustom() ([]Definition, error) { return nil, r.err }

func TestHandlerListRunsStoreError500(t *testing.T) {
	rf := newRunnerFixture(t)
	h := &Handler{
		Runner:           rf.runner,
		Store:            &listRunsErrStore{Store: rf.store, err: errors.New("list runs boom")},
		Systems:          lookupFn(func(string) (systems.System, error) { return systems.System{ID: rf.systemID}, nil }),
		CanReadSystem:    func(context.Context, systems.System) bool { return true },
		CanOperateSystem: func(context.Context, systems.System) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/systems/" + rf.systemID + "/exporter-runs")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandlerSetScrapeModeStoreError500(t *testing.T) {
	rf := newRunnerFixture(t)
	h := &Handler{
		Runner:           rf.runner,
		Store:            &setScrapeModeErrStore{Store: rf.store, err: errors.New("setmode boom")},
		Systems:          lookupFn(func(string) (systems.System, error) { return systems.System{ID: rf.systemID}, nil }),
		CanReadSystem:    func(context.Context, systems.System) bool { return true },
		CanOperateSystem: func(context.Context, systems.System) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPut,
		srv.URL+"/api/systems/"+rf.systemID+"/exporter-settings",
		bytes.NewBufferString(`{"scrapeMode":"localhost"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandlerSetScrapeModeInvalid400(t *testing.T) {
	rf := newRunnerFixture(t)
	h := &Handler{
		Runner:           rf.runner,
		Store:            &setScrapeModeErrStore{Store: rf.store, err: ErrInvalid},
		Systems:          lookupFn(func(string) (systems.System, error) { return systems.System{ID: rf.systemID}, nil }),
		CanReadSystem:    func(context.Context, systems.System) bool { return true },
		CanOperateSystem: func(context.Context, systems.System) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPut,
		srv.URL+"/api/systems/"+rf.systemID+"/exporter-settings",
		bytes.NewBufferString(`{"scrapeMode":"localhost"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlerListRegistryError500(t *testing.T) {
	rf := newRunnerFixture(t)
	rf.runner.Registry = NewRegistry(&registryErrStore{Store: rf.store, err: errors.New("reg boom")})
	h := &Handler{
		Runner:           rf.runner,
		Store:            rf.store,
		Systems:          lookupFn(func(string) (systems.System, error) { return systems.System{ID: rf.systemID}, nil }),
		CanReadSystem:    func(context.Context, systems.System) bool { return true },
		CanOperateSystem: func(context.Context, systems.System) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/systems/" + rf.systemID + "/exporters")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

type settingsErrStore struct {
	Store
	err error
}

func (s *settingsErrStore) GetSettings(string) (SystemSettings, error) {
	return SystemSettings{}, s.err
}

func TestHandlerListNoRunnerReturns503(t *testing.T) {
	rf := newRunnerFixture(t)
	h := &Handler{
		Store:            rf.store,
		Systems:          lookupFn(func(string) (systems.System, error) { return systems.System{ID: rf.systemID}, nil }),
		CanReadSystem:    func(context.Context, systems.System) bool { return true },
		CanOperateSystem: func(context.Context, systems.System) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/systems/" + rf.systemID + "/exporters")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

func TestHandlerListSystemExportersError500(t *testing.T) {
	rf := newRunnerFixture(t)
	h := &Handler{
		Runner:           rf.runner,
		Store:            &listErrStore{Store: rf.store, err: errors.New("rows boom")},
		Systems:          lookupFn(func(string) (systems.System, error) { return systems.System{ID: rf.systemID}, nil }),
		CanReadSystem:    func(context.Context, systems.System) bool { return true },
		CanOperateSystem: func(context.Context, systems.System) bool { return true },
		Probe:            stubProbe{managers: []string{"builtin.dnf"}},
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/systems/" + rf.systemID + "/exporters")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandlerListSettingsError500(t *testing.T) {
	rf := newRunnerFixture(t)
	h := &Handler{
		Runner:           rf.runner,
		Store:            &settingsErrStore{Store: rf.store, err: errors.New("settings boom")},
		Systems:          lookupFn(func(string) (systems.System, error) { return systems.System{ID: rf.systemID}, nil }),
		CanReadSystem:    func(context.Context, systems.System) bool { return true },
		CanOperateSystem: func(context.Context, systems.System) bool { return true },
		Probe:            stubProbe{managers: []string{"builtin.dnf"}},
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/systems/" + rf.systemID + "/exporters")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandlerListIncludesRemovedRow(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	at := time.Now().UTC()
	_ = rf.store.UpsertSystemExporter(SystemExporter{
		SystemID: rf.systemID, ExporterID: "builtin.dnf.exporter",
		State: StateRemoved, LastStatusAt: &at, LastReason: "uninstalled",
	})
	resp, _ := http.Get(srv.URL + "/api/systems/" + rf.systemID + "/exporters")
	defer func() { _ = resp.Body.Close() }()
	var body SystemExportersResponseDTO
	_ = json.NewDecoder(resp.Body).Decode(&body)
	var dnf *SystemExporterDTO
	for i := range body.Exporters {
		if body.Exporters[i].ExporterID == "builtin.dnf.exporter" {
			dnf = &body.Exporters[i]
		}
	}
	if dnf == nil {
		t.Fatal("dnf builtin missing")
	}
	if dnf.Installed {
		t.Errorf("Installed = true, want false (removed)")
	}
	if dnf.State != StateRemoved {
		t.Errorf("State = %q, want removed", dnf.State)
	}
	if dnf.LastReason != "uninstalled" {
		t.Errorf("LastReason = %q", dnf.LastReason)
	}
}

func TestHandlerSetScrapeBadJSON(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	req, _ := http.NewRequest(http.MethodPut,
		srv.URL+"/api/systems/"+rf.systemID+"/exporters/builtin.dnf.exporter/scrape",
		bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlerInstallNoRunnerReturns503(t *testing.T) {
	rf := newRunnerFixture(t)
	h := &Handler{
		Store:            rf.store,
		Systems:          lookupFn(func(string) (systems.System, error) { return systems.System{ID: rf.systemID}, nil }),
		CanOperateSystem: func(context.Context, systems.System) bool { return true },
		CanReadSystem:    func(context.Context, systems.System) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Post(srv.URL+"/api/systems/"+rf.systemID+"/exporters/builtin.dnf.exporter/install",
		"application/json", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
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

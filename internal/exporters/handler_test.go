// SPDX-License-Identifier: Apache-2.0

package exporters

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"system-wrangler-backend/internal/ansible"
	"system-wrangler-backend/internal/systems"
)

// stubProbe returns a fixed pkg manager list — lets the handler
// tests exercise availability without spinning up an updater store.
type stubProbe struct {
	managers []string
	err      error
}

func (s stubProbe) DetectedPkgManagers(string) ([]string, error) {
	return s.managers, s.err
}

type lookupFn func(id string) (systems.System, error)

func (f lookupFn) Get(id string) (systems.System, error) { return f(id) }

func newHandlerFixture(t *testing.T) (*Handler, *httptest.Server, *runnerFixture) {
	t.Helper()
	rf := newRunnerFixture(t)
	h := &Handler{
		Runner: rf.runner,
		Store:  rf.store,
		Systems: lookupFn(func(id string) (systems.System, error) {
			if id != rf.systemID {
				return systems.System{}, systems.ErrNotFound
			}
			return systems.System{ID: rf.systemID, Name: "host", Hostname: "host.example"}, nil
		}),
		Probe:            stubProbe{managers: []string{"builtin.dnf"}},
		CanOperateSystem: func(context.Context, systems.System) bool { return true },
		CanReadSystem:    func(context.Context, systems.System) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return h, srv, rf
}

func TestHandlerListAvailability(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	resp, err := http.Get(srv.URL + "/api/systems/" + rf.systemID + "/exporters")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body SystemExportersResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.ScrapeMode != ScrapeLocalhost {
		t.Errorf("scrape mode = %q, want localhost", body.ScrapeMode)
	}
	if len(body.DetectedPkgManagers) != 1 || body.DetectedPkgManagers[0] != "builtin.dnf" {
		t.Errorf("pkg managers = %v", body.DetectedPkgManagers)
	}
	var dnf *SystemExporterDTO
	for i := range body.Exporters {
		if body.Exporters[i].ExporterID == "builtin.dnf.exporter" {
			dnf = &body.Exporters[i]
		}
	}
	if dnf == nil {
		t.Fatal("dnf builtin missing from response")
	}
	if dnf.Availability != AvailabilityAvailable {
		t.Errorf("availability = %q, want available", dnf.Availability)
	}
}

func TestHandlerListUnknownWhenNoDetections(t *testing.T) {
	rf := newRunnerFixture(t)
	h := &Handler{
		Runner:           rf.runner,
		Store:            rf.store,
		Systems:          lookupFn(func(string) (systems.System, error) { return systems.System{ID: rf.systemID}, nil }),
		Probe:            stubProbe{managers: []string{}},
		CanOperateSystem: func(context.Context, systems.System) bool { return true },
		CanReadSystem:    func(context.Context, systems.System) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/systems/" + rf.systemID + "/exporters")
	defer func() { _ = resp.Body.Close() }()
	var body SystemExportersResponseDTO
	_ = json.NewDecoder(resp.Body).Decode(&body)
	for _, e := range body.Exporters {
		if e.Availability != AvailabilityUnknown {
			t.Errorf("%s availability = %q, want unknown", e.ExporterID, e.Availability)
		}
	}
}

func TestHandlerInstallSuccess(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	rf.queue(ansible.Run{
		Status:   ansible.RunSuccess,
		ExitCode: 0,
		Stdout: []byte(
			"\"msg\": \"SW_EXPORTER_PORT: 9100\"\n" +
				"\"msg\": \"SW_EXPORTER_SERVICE: node_exporter.service\"\n" +
				"\"msg\": \"SW_EXPORTER_STATE: running\"\n",
		),
	}, nil)
	resp, err := http.Post(srv.URL+"/api/systems/"+rf.systemID+"/exporters/builtin.dnf.exporter/install", "application/json", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got runDTO
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.State != StateRunning {
		t.Errorf("state = %q", got.State)
	}
}

func TestHandlerInstallForbidden(t *testing.T) {
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
	resp, _ := http.Post(srv.URL+"/api/systems/"+rf.systemID+"/exporters/builtin.dnf.exporter/install", "application/json", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHandlerStatus(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	rf.queue(ansible.Run{Status: ansible.RunSuccess, ExitCode: 0,
		Stdout: []byte("\"msg\": \"SW_EXPORTER_STATE: running\"\n"),
	}, nil)
	resp, _ := http.Post(srv.URL+"/api/systems/"+rf.systemID+"/exporters/builtin.dnf.exporter/status", "application/json", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestHandlerRemoveBadRequest(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	// All builtins now ship remove.yml; seed a custom installer
	// without one to exercise the 400-on-missing-remove path.
	d := validDef()
	d.ID = "custom.no-remove"
	if _, err := rf.store.CreateCustom(d); err != nil {
		t.Fatalf("CreateCustom: %v", err)
	}
	resp, _ := http.Post(srv.URL+"/api/systems/"+rf.systemID+"/exporters/custom.no-remove/remove", "application/json", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlerInstallConflict(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	// Hold the lock so the next install collides.
	if err := rf.locker.AcquireLock(rf.systemID, "other", rf.runner.now()); err != nil {
		t.Fatalf("seed lock: %v", err)
	}
	resp, _ := http.Post(srv.URL+"/api/systems/"+rf.systemID+"/exporters/builtin.dnf.exporter/install", "application/json", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
	var body conflictDTO
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body.ConflictingRun != "other" {
		t.Errorf("conflicting run = %q, want \"other\"", body.ConflictingRun)
	}
}

func TestHandlerListRuns(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	rf.queue(ansible.Run{Status: ansible.RunSuccess, ExitCode: 0}, nil)
	if _, err := rf.runner.Status(context.Background(), rf.systemID, "builtin.dnf.exporter"); err != nil {
		t.Fatalf("seed Status: %v", err)
	}
	resp, _ := http.Get(srv.URL + "/api/systems/" + rf.systemID + "/exporter-runs")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body runsResponseDTO
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if len(body.Runs) == 0 {
		t.Errorf("runs empty")
	}
}

func TestHandlerSetScrapeMode(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	body := bytes.NewBufferString(`{"scrapeMode":"localhost"}`)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/systems/"+rf.systemID+"/exporter-settings", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestHandlerSetScrapeModeRejectsMTLSToday(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	body := bytes.NewBufferString(`{"scrapeMode":"mtls-self"}`)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/systems/"+rf.systemID+"/exporter-settings", body)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlerSetScrapeToggle(t *testing.T) {
	h, srv, rf := newHandlerFixture(t)
	notified := 0
	h.Notify = func(string) { notified++ }
	// Seed an installed row so the toggle has a target.
	if err := rf.store.UpsertSystemExporter(SystemExporter{
		SystemID: rf.systemID, ExporterID: "builtin.dnf.exporter",
		State: StateRunning, Port: 9100,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	url := srv.URL + "/api/systems/" + rf.systemID + "/exporters/builtin.dnf.exporter/scrape"

	// First flip: enabled=false → 200, ScrapeEnabled=false in response.
	resp, err := http.DefaultClient.Do(mustPut(t, url, `{"enabled":false}`))
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	var out scrapeResponseDTO
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.ScrapeEnabled {
		t.Errorf("ScrapeEnabled = true after disable")
	}
	if notified != 1 {
		t.Errorf("notified = %d, want 1 after first flip", notified)
	}

	// Idempotent: disable again → 200, no second Notify.
	resp2, _ := http.DefaultClient.Do(mustPut(t, url, `{"enabled":false}`))
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("idempotent status = %d", resp2.StatusCode)
	}
	if notified != 1 {
		t.Errorf("notified = %d after idempotent call, want 1", notified)
	}

	// Re-enable: 200, true, second Notify.
	resp3, _ := http.DefaultClient.Do(mustPut(t, url, `{"enabled":true}`))
	defer func() { _ = resp3.Body.Close() }()
	var out3 scrapeResponseDTO
	_ = json.NewDecoder(resp3.Body).Decode(&out3)
	if !out3.ScrapeEnabled {
		t.Errorf("ScrapeEnabled = false after re-enable")
	}
	if notified != 2 {
		t.Errorf("notified = %d, want 2 after re-enable", notified)
	}
}

func TestHandlerSetScrapeMissingRow(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	url := srv.URL + "/api/systems/" + rf.systemID + "/exporters/builtin.dnf.exporter/scrape"
	resp, _ := http.DefaultClient.Do(mustPut(t, url, `{"enabled":false}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (no installed row yet)", resp.StatusCode)
	}
}

func TestHandlerSetScrapeForbidden(t *testing.T) {
	h, srv, rf := newHandlerFixture(t)
	h.CanOperateSystem = func(context.Context, systems.System) bool { return false }
	url := srv.URL + "/api/systems/" + rf.systemID + "/exporters/builtin.dnf.exporter/scrape"
	resp, _ := http.DefaultClient.Do(mustPut(t, url, `{"enabled":false}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func mustPut(t *testing.T, url, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestHandlerSetScrapeModeInvalid(t *testing.T) {
	_, srv, rf := newHandlerFixture(t)
	body := bytes.NewBufferString(`{"scrapeMode":"bogus"}`)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/systems/"+rf.systemID+"/exporter-settings", body)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestHandlerSystemNotFound(t *testing.T) {
	_, srv, _ := newHandlerFixture(t)
	resp, _ := http.Get(srv.URL + "/api/systems/missing/exporters")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandlerReadGate(t *testing.T) {
	rf := newRunnerFixture(t)
	h := &Handler{
		Runner:        rf.runner,
		Store:         rf.store,
		Systems:       lookupFn(func(string) (systems.System, error) { return systems.System{ID: rf.systemID}, nil }),
		Probe:         stubProbe{},
		CanReadSystem: func(context.Context, systems.System) bool { return false },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/systems/" + rf.systemID + "/exporters")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("scope-hidden system should 404, got %d", resp.StatusCode)
	}
}

func TestResolveAvailability(t *testing.T) {
	none := map[string]bool{}
	if got := resolveAvailability("builtin.dnf", []string{}, none); got != AvailabilityUnknown {
		t.Errorf("empty detected = %q, want unknown", got)
	}
	set := map[string]bool{"builtin.dnf": true}
	if got := resolveAvailability("builtin.dnf", []string{"builtin.dnf"}, set); got != AvailabilityAvailable {
		t.Errorf("matching = %q, want available", got)
	}
	if got := resolveAvailability("builtin.apt", []string{"builtin.dnf"}, set); got != AvailabilityUnavailable {
		t.Errorf("non-matching = %q, want unavailable", got)
	}
}

func TestHandlerInstallInvalidJSONPassesThrough(t *testing.T) {
	// install endpoint reads no body — invalid body must still succeed.
	_, srv, rf := newHandlerFixture(t)
	rf.queue(ansible.Run{Status: ansible.RunSuccess, ExitCode: 0}, nil)
	resp, _ := http.Post(srv.URL+"/api/systems/"+rf.systemID+"/exporters/builtin.dnf.exporter/install", "application/json", strings.NewReader("not json"))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

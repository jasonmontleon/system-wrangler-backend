// SPDX-License-Identifier: Apache-2.0

package ansible

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"system-wrangler-backend/internal/systems"
)

func newHandlerFixture(t *testing.T) (*Handler, *httptest.Server, *fixture) {
	t.Helper()
	f := newFixture(t)
	h := &Handler{
		Runner:          f.runner,
		Systems:         f.systems,
		CanManageSystem: func(context.Context, systems.System) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return h, srv, f
}

func TestHandlerTestConnectionOK(t *testing.T) {
	h, srv, f := newHandlerFixture(t)
	_ = h
	f.seedCredentials()
	f.seedAcceptedHostKey()
	f.exec.queue(AnsibleAdHocBinary, fakeResp{
		stdout: `h-a.example | SUCCESS => {"ping": "pong"}`,
		exit:   0,
	})

	resp, err := http.Post(srv.URL+"/api/systems/"+f.system.ID+"/test-connection", "application/json", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got testConnectionDTO
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got.Status != RunSuccess || got.Reason != "pong" {
		t.Errorf("got = %#v", got)
	}
}

func TestHandlerTestConnectionForbidden(t *testing.T) {
	h, srv, f := newHandlerFixture(t)
	h.CanManageSystem = func(context.Context, systems.System) bool { return false }
	f.seedCredentials()
	f.seedAcceptedHostKey()
	resp, err := http.Post(srv.URL+"/api/systems/"+f.system.ID+"/test-connection", "application/json", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHandlerTestConnectionMissingSystem(t *testing.T) {
	_, srv, _ := newHandlerFixture(t)
	resp, err := http.Post(srv.URL+"/api/systems/no-such-system/test-connection", "application/json", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandlerTestConnectionNoRunner(t *testing.T) {
	h, srv, f := newHandlerFixture(t)
	h.Runner = nil
	resp, err := http.Post(srv.URL+"/api/systems/"+f.system.ID+"/test-connection", "application/json", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

// failingSystems returns a non-NotFound error so handler hits the 500
// lookup path. Distinct from the missing-system test above which hits 404.
type failingSystems struct{}

func (failingSystems) Get(string) (systems.System, error) {
	return systems.System{}, errStub
}

var errStub = stubErr("db down")

type stubErr string

func (s stubErr) Error() string { return string(s) }

func TestHandlerTestConnectionLookupError500(t *testing.T) {
	h, srv, _ := newHandlerFixture(t)
	h.Systems = failingSystems{}
	resp, err := http.Post(srv.URL+"/api/systems/x/test-connection", "application/json", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

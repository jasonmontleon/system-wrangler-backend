// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminUpdateNotFound(t *testing.T) {
	_, srv, _, _ := newAdminFixture(t)
	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/admin/updater-definitions/custom.ghost", bytes.NewReader(mustJSON(t, updateInputDTO{
		DisplayName:   "x",
		DetectBinary:  "x",
		CheckPlaybook: "- hosts: all\n",
		ApplyPlaybook: "- hosts: all\n",
	})))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAdminUpdateBadJSON(t *testing.T) {
	_, srv, _, rf := newAdminFixture(t)
	if _, err := rf.registry.CreateCustom(sampleDef("custom.tt")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/admin/updater-definitions/custom.tt", strings.NewReader("not json"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminUpdateForbidden(t *testing.T) {
	h, srv, _, _ := newAdminFixture(t)
	h.CanManage = func(context.Context) bool { return false }
	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/admin/updater-definitions/custom.tt", bytes.NewReader(mustJSON(t, updateInputDTO{})))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAdminDeleteBadID(t *testing.T) {
	_, srv, _, _ := newAdminFixture(t)
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/admin/updater-definitions/no-prefix", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminDeleteForbidden(t *testing.T) {
	h, srv, _, _ := newAdminFixture(t)
	h.CanManage = func(context.Context) bool { return false }
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/admin/updater-definitions/custom.x", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAdminListErrorPropagates(t *testing.T) {
	// Build an admin handler against a closed-db store so List
	// errors propagate as 500.
	rf := newRunnerFixture(t)
	store := brokenStore(t)
	reg := NewRegistry(store)
	h := &AdminHandler{
		Registry:  reg,
		Audit:     rf.auditStore,
		CanManage: func(context.Context) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/api/admin/updater-definitions")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestAdminEmitAuditNilStore(_ *testing.T) {
	// emitAudit no-ops when Audit is nil.
	h := &AdminHandler{}
	h.emitAudit(context.Background(), "updater.create", "success", Definition{}, nil)
}

func TestAdminNowOverride(t *testing.T) {
	// Just exercise the Now field path; the wider TestAdminDeleteSoftDeletes
	// covers the default branch implicitly.
	h := &AdminHandler{}
	if h.now().IsZero() {
		t.Errorf("now() returned zero")
	}
}

func TestAdminUpdateInlineCredentialRejected(t *testing.T) {
	_, srv, _, rf := newAdminFixture(t)
	if _, err := rf.registry.CreateCustom(sampleDef("custom.up")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	patch := updateInputDTO{
		DisplayName:   "ok",
		DetectBinary:  "x",
		CheckPlaybook: "- hosts: all\n  vars:\n    token: hunter2\n",
		ApplyPlaybook: "- hosts: all\n",
	}
	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/admin/updater-definitions/custom.up", bytes.NewReader(mustJSON(t, patch)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	body, _ := readBody(resp)
	if !strings.Contains(body, "token") {
		t.Errorf("body should name offending key: %s", body)
	}
}

func TestWriteGuardErrorDefault(t *testing.T) {
	rec := httptest.NewRecorder()
	writeGuardError(rec, errInternal("boom"))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("code = %d, want 500", rec.Code)
	}
}

func TestWriteStoreErrorDefault(t *testing.T) {
	rec := httptest.NewRecorder()
	writeStoreError(rec, errInternal("disk fell off"))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("code = %d, want 500", rec.Code)
	}
}

func errInternal(msg string) error {
	return &nakedErr{msg}
}

type nakedErr struct{ msg string }

func (e *nakedErr) Error() string { return e.msg }

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

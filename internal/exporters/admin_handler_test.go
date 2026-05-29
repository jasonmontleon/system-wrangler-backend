// SPDX-License-Identifier: Apache-2.0

package exporters

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/systems"
)

type stubSyntax struct{ err error }

func (s stubSyntax) Check(context.Context, []byte) error { return s.err }

func newAdminFixture(t *testing.T) (*AdminHandler, *httptest.Server, *audit.Store) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "admin.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := systems.NewSQLiteStore(db); err != nil {
		t.Fatalf("systems.NewSQLiteStore: %v", err)
	}
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	auditStore, err := audit.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStore: %v", err)
	}
	reg := NewRegistry(store)
	h := &AdminHandler{
		Registry:  reg,
		Syntax:    stubSyntax{},
		Audit:     auditStore,
		CanManage: func(context.Context) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return h, srv, auditStore
}

func TestAdminListIncludesBuiltins(t *testing.T) {
	_, srv, _ := newAdminFixture(t)
	resp, err := http.Get(srv.URL + "/api/admin/exporter-definitions")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body listResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	found := false
	for _, d := range body.Definitions {
		if d.ID == "builtin.dnf.exporter" {
			found = true
		}
	}
	if !found {
		t.Errorf("dnf builtin missing")
	}
}

func TestAdminCreateUpdateDelete(t *testing.T) {
	_, srv, _ := newAdminFixture(t)

	in := createInputDTO{
		ID:                  "myexp",
		DisplayName:         "My exporter",
		AppliesToPkgManager: "builtin.apt",
		ExporterKind:        KindNodeExporter,
		BindPort:            9100,
		InstallPlaybook:     "- hosts: all\n  tasks: []\n",
		StatusPlaybook:      "- hosts: all\n  tasks: []\n",
	}
	resp := postJSON(t, srv.URL+"/api/admin/exporter-definitions", in)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d", resp.StatusCode)
	}
	var created definitionDTO
	_ = json.NewDecoder(resp.Body).Decode(&created)
	_ = resp.Body.Close()
	if created.ID != "custom.myexp" {
		t.Errorf("id = %q, want custom.myexp", created.ID)
	}

	patch := updateInputDTO{
		DisplayName:         "Renamed",
		AppliesToPkgManager: "builtin.apt",
		ExporterKind:        KindNodeExporter,
		BindPort:            9100,
		InstallPlaybook:     "- hosts: all\n  tasks: []\n",
		StatusPlaybook:      "- hosts: all\n  tasks: []\n",
	}
	resp = patchJSON(t, srv.URL+"/api/admin/exporter-definitions/custom.myexp", patch)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update status = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/admin/exporter-definitions/custom.myexp", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete status = %d", resp.StatusCode)
	}
}

func TestAdminCreateRejectsBuiltinIDPrefix(t *testing.T) {
	_, srv, _ := newAdminFixture(t)
	in := createInputDTO{
		ID:                  "builtin.evil",
		DisplayName:         "evil",
		AppliesToPkgManager: "builtin.apt",
		ExporterKind:        KindNodeExporter,
		BindPort:            9100,
		InstallPlaybook:     "- hosts: all\n  tasks: []\n",
		StatusPlaybook:      "- hosts: all\n  tasks: []\n",
	}
	resp := postJSON(t, srv.URL+"/api/admin/exporter-definitions", in)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminCreateRejectsInlineCredential(t *testing.T) {
	_, srv, _ := newAdminFixture(t)
	in := createInputDTO{
		ID:                  "leak",
		DisplayName:         "leak",
		AppliesToPkgManager: "builtin.apt",
		ExporterKind:        KindNodeExporter,
		BindPort:            9100,
		InstallPlaybook:     "- hosts: all\n  vars:\n    password: secret\n",
		StatusPlaybook:      "- hosts: all\n  tasks: []\n",
	}
	resp := postJSON(t, srv.URL+"/api/admin/exporter-definitions", in)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminCreateForbiddenWhenCannotManage(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "admin-forbidden.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := systems.NewSQLiteStore(db); err != nil {
		t.Fatalf("systems: %v", err)
	}
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	auditStore, _ := audit.NewSQLiteStore(db)
	h := &AdminHandler{
		Registry:  NewRegistry(store),
		Audit:     auditStore,
		CanManage: func(context.Context) bool { return false },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp := postJSON(t, srv.URL+"/api/admin/exporter-definitions", createInputDTO{ID: "x"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAdminSyntaxRejection(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "admin-syntax.db")
	db, _ := database.Open(dsn)
	t.Cleanup(func() { _ = db.Close() })
	_, _ = systems.NewSQLiteStore(db)
	store, _ := NewSQLiteStore(db)
	auditStore, _ := audit.NewSQLiteStore(db)
	h := &AdminHandler{
		Registry:  NewRegistry(store),
		Syntax:    stubSyntax{err: ErrSyntax},
		Audit:     auditStore,
		CanManage: func(context.Context) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp := postJSON(t, srv.URL+"/api/admin/exporter-definitions", createInputDTO{
		ID:                  "broken",
		DisplayName:         "broken",
		AppliesToPkgManager: "builtin.apt",
		ExporterKind:        KindNodeExporter,
		BindPort:            9100,
		InstallPlaybook:     "- hosts: all\n  tasks: []\n",
		StatusPlaybook:      "- hosts: all\n  tasks: []\n",
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminUpdateBadID(t *testing.T) {
	_, srv, _ := newAdminFixture(t)
	resp := patchJSON(t, srv.URL+"/api/admin/exporter-definitions/builtin.dnf.exporter", updateInputDTO{})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminListRegistryError500(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "admin-listerr.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, _ = systems.NewSQLiteStore(db)
	store, _ := NewSQLiteStore(db)
	auditStore, _ := audit.NewSQLiteStore(db)
	// Wrap so Registry.All() fails.
	reg := NewRegistry(&registryErrStore{Store: store, err: errAdminTestStub("reg boom")})
	h := &AdminHandler{
		Registry:  reg,
		Audit:     auditStore,
		CanManage: func(context.Context) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/admin/exporter-definitions")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

type errAdminTestStub string

func (e errAdminTestStub) Error() string { return string(e) }

func TestAdminCreateBadJSON(t *testing.T) {
	_, srv, _ := newAdminFixture(t)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/admin/exporter-definitions",
		bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminCreateEmptyIDRejected(t *testing.T) {
	_, srv, _ := newAdminFixture(t)
	resp := postJSON(t, srv.URL+"/api/admin/exporter-definitions", createInputDTO{ID: ""})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminCreateConflictOnDuplicate(t *testing.T) {
	_, srv, _ := newAdminFixture(t)
	in := createInputDTO{
		ID:                  "dup",
		DisplayName:         "Dup",
		AppliesToPkgManager: "builtin.apt",
		ExporterKind:        KindNodeExporter,
		BindPort:            9100,
		InstallPlaybook:     "- hosts: all\n  tasks: []\n",
		StatusPlaybook:      "- hosts: all\n  tasks: []\n",
	}
	resp := postJSON(t, srv.URL+"/api/admin/exporter-definitions", in)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first create status = %d", resp.StatusCode)
	}
	resp2 := postJSON(t, srv.URL+"/api/admin/exporter-definitions", in)
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("second create status = %d, want 409", resp2.StatusCode)
	}
}

func TestAdminUpdateForbidden(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "admin-u-forbidden.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, _ = systems.NewSQLiteStore(db)
	store, _ := NewSQLiteStore(db)
	auditStore, _ := audit.NewSQLiteStore(db)
	h := &AdminHandler{
		Registry:  NewRegistry(store),
		Audit:     auditStore,
		CanManage: func(context.Context) bool { return false },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp := patchJSON(t, srv.URL+"/api/admin/exporter-definitions/custom.x", updateInputDTO{})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAdminUpdateBadJSON(t *testing.T) {
	_, srv, _ := newAdminFixture(t)
	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/admin/exporter-definitions/custom.x",
		bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminUpdateUnknown(t *testing.T) {
	_, srv, _ := newAdminFixture(t)
	resp := patchJSON(t, srv.URL+"/api/admin/exporter-definitions/custom.nope", updateInputDTO{
		DisplayName:         "x",
		AppliesToPkgManager: "builtin.apt",
		ExporterKind:        KindNodeExporter,
		BindPort:            9100,
		InstallPlaybook:     "- hosts: all\n  tasks: []\n",
		StatusPlaybook:      "- hosts: all\n  tasks: []\n",
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAdminDeleteForbidden(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "admin-d-forbidden.db")
	db, _ := database.Open(dsn)
	t.Cleanup(func() { _ = db.Close() })
	_, _ = systems.NewSQLiteStore(db)
	store, _ := NewSQLiteStore(db)
	auditStore, _ := audit.NewSQLiteStore(db)
	h := &AdminHandler{
		Registry:  NewRegistry(store),
		Audit:     auditStore,
		CanManage: func(context.Context) bool { return false },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/admin/exporter-definitions/custom.x", nil)
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAdminDeleteBadID(t *testing.T) {
	_, srv, _ := newAdminFixture(t)
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/admin/exporter-definitions/builtin.dnf.exporter", nil)
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminCanManageNilAllowsThrough(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "admin-nilcanmanage.db")
	db, _ := database.Open(dsn)
	t.Cleanup(func() { _ = db.Close() })
	_, _ = systems.NewSQLiteStore(db)
	store, _ := NewSQLiteStore(db)
	auditStore, _ := audit.NewSQLiteStore(db)
	h := &AdminHandler{
		Registry: NewRegistry(store),
		Syntax:   stubSyntax{},
		Audit:    auditStore,
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp := postJSON(t, srv.URL+"/api/admin/exporter-definitions", createInputDTO{
		ID:                  "nilcheck",
		DisplayName:         "nilcheck",
		AppliesToPkgManager: "builtin.apt",
		ExporterKind:        KindNodeExporter,
		BindPort:            9100,
		InstallPlaybook:     "- hosts: all\n  tasks: []\n",
		StatusPlaybook:      "- hosts: all\n  tasks: []\n",
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want 201", resp.StatusCode)
	}
}

func TestAdminGuardChecksRemoveCredentials(t *testing.T) {
	_, srv, _ := newAdminFixture(t)
	resp := postJSON(t, srv.URL+"/api/admin/exporter-definitions", createInputDTO{
		ID:                  "rmleak",
		DisplayName:         "rmleak",
		AppliesToPkgManager: "builtin.apt",
		ExporterKind:        KindNodeExporter,
		BindPort:            9100,
		InstallPlaybook:     "- hosts: all\n  tasks: []\n",
		StatusPlaybook:      "- hosts: all\n  tasks: []\n",
		RemovePlaybook:      "- hosts: all\n  vars:\n    password: leak\n",
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminDeleteUnknown(t *testing.T) {
	_, srv, _ := newAdminFixture(t)
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/admin/exporter-definitions/custom.unknown", nil)
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func postJSON(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(b)) //nolint:gosec // test-controlled URL
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	return resp
}

func patchJSON(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPatch, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	return resp
}

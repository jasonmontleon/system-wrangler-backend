// SPDX-License-Identifier: Apache-2.0

package hostkeys

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/systems"
)

type handlerFixture struct {
	srv     *httptest.Server
	store   *SQLiteStore
	systems *systems.SQLiteStore
	audit   *audit.Store
	handler *Handler
	allow   func(context.Context, systems.System) bool
}

func newFixture(t *testing.T) *handlerFixture {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "hk-h.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	sysStore, err := systems.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("systems.NewSQLiteStore: %v", err)
	}
	hkStore, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("hostkeys.NewSQLiteStore: %v", err)
	}
	auditStore, err := audit.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStore: %v", err)
	}

	f := &handlerFixture{
		store:   hkStore,
		systems: sysStore,
		audit:   auditStore,
		allow:   func(context.Context, systems.System) bool { return true },
	}
	f.handler = &Handler{
		Store:           hkStore,
		Systems:         sysStore,
		Audit:           auditStore,
		CanManageSystem: func(ctx context.Context, s systems.System) bool { return f.allow(ctx, s) },
	}
	mux := http.NewServeMux()
	f.handler.Register(mux, nil)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *handlerFixture) do(t *testing.T, method, path string, body any) *http.Response {
	t.Helper()
	var rdr *bytes.Buffer
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewBuffer(b)
	} else {
		rdr = bytes.NewBuffer(nil)
	}
	req, err := http.NewRequest(method, f.srv.URL+path, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func (f *handlerFixture) addSystem(t *testing.T, name string) systems.System {
	t.Helper()
	sys, err := f.systems.Create(systems.SystemInput{Name: name, Hostname: name + ".example"})
	if err != nil {
		t.Fatalf("systems.Create: %v", err)
	}
	return sys
}

// scanFx is a fake Executor for handler tests; canned response per
// call. Matches the hostkeys.Executor shape.
type scanFx struct {
	stdout, stderr []byte
	exit           int
	err            error
}

func (s *scanFx) Run(_ context.Context, _ string, _ []string, _ []string, _ []byte) ([]byte, []byte, int, error) {
	return s.stdout, s.stderr, s.exit, s.err
}

func TestScanCapturesOfferedKeys(t *testing.T) {
	f := newFixture(t)
	sys := f.addSystem(t, "scan-host")
	line, fp := genKeyscanLine(sys.Hostname)
	f.handler.Executor = &scanFx{stdout: []byte(line), exit: 0}

	resp := f.do(t, http.MethodPost, "/api/systems/"+sys.ID+"/host-keys/scan", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got struct {
		HostKeys []hostKeyDTO `json:"hostKeys"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if len(got.HostKeys) != 1 {
		t.Fatalf("len = %d, want 1", len(got.HostKeys))
	}
	if got.HostKeys[0].State != StatePending || got.HostKeys[0].Fingerprint != fp {
		t.Errorf("unexpected captured row: %#v", got.HostKeys[0])
	}
	// pending audit row emitted.
	rows, _, _ := f.audit.ListQuery(audit.Query{Action: "system.host_key.pending", Limit: 5})
	if len(rows) != 1 {
		t.Errorf("pending audit rows = %d, want 1", len(rows))
	}
}

func TestScanNoExecutorReturns503(t *testing.T) {
	f := newFixture(t)
	sys := f.addSystem(t, "scan-host-2")
	f.handler.Executor = nil
	resp := f.do(t, http.MethodPost, "/api/systems/"+sys.ID+"/host-keys/scan", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

func TestScanForbidden(t *testing.T) {
	f := newFixture(t)
	sys := f.addSystem(t, "scan-host-3")
	f.handler.Executor = &scanFx{}
	f.allow = func(context.Context, systems.System) bool { return false }
	resp := f.do(t, http.MethodPost, "/api/systems/"+sys.ID+"/host-keys/scan", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestScanSystemMissing(t *testing.T) {
	f := newFixture(t)
	f.handler.Executor = &scanFx{}
	resp := f.do(t, http.MethodPost, "/api/systems/no-such/host-keys/scan", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestScanExecutorFailureReturns502(t *testing.T) {
	f := newFixture(t)
	sys := f.addSystem(t, "scan-host-4")
	f.handler.Executor = &scanFx{exit: 1} // empty stdout + non-zero exit
	resp := f.do(t, http.MethodPost, "/api/systems/"+sys.ID+"/host-keys/scan", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
}

func TestListEmpty(t *testing.T) {
	f := newFixture(t)
	sys := f.addSystem(t, "h-a")
	resp := f.do(t, http.MethodGet, "/api/systems/"+sys.ID+"/host-keys", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got struct {
		HostKeys []hostKeyDTO `json:"hostKeys"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if len(got.HostKeys) != 0 {
		t.Errorf("expected empty list, got %d", len(got.HostKeys))
	}
}

func TestListSystemMissing(t *testing.T) {
	f := newFixture(t)
	resp := f.do(t, http.MethodGet, "/api/systems/no-such/host-keys", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestListForbidden(t *testing.T) {
	f := newFixture(t)
	sys := f.addSystem(t, "h-b")
	f.allow = func(context.Context, systems.System) bool { return false }
	resp := f.do(t, http.MethodGet, "/api/systems/"+sys.ID+"/host-keys", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAcceptHappyPath(t *testing.T) {
	f := newFixture(t)
	sys := f.addSystem(t, "h-c")
	if _, err := f.store.RecordPending(sys.ID, "ssh-ed25519", "AAAA", "SHA256:abc"); err != nil {
		t.Fatalf("RecordPending: %v", err)
	}
	resp := f.do(t, http.MethodPost, "/api/systems/"+sys.ID+"/host-keys/accept", map[string]any{
		"algorithm":   "ssh-ed25519",
		"fingerprint": "SHA256:abc",
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got hostKeyDTO
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got.State != StateAccepted {
		t.Errorf("state = %q", got.State)
	}
	// One audit row, action accept (not replace).
	recs, _, err := f.audit.ListQuery(audit.Query{Action: "system.host_key.accept", Limit: 5})
	if err != nil {
		t.Fatalf("ListQuery: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("audit rows = %d", len(recs))
	}
	if recs[0].Detail["fingerprint"] != "SHA256:abc" {
		t.Errorf("audit fingerprint = %v", recs[0].Detail["fingerprint"])
	}
}

func TestAcceptReplaceEmitsReplaceAudit(t *testing.T) {
	f := newFixture(t)
	sys := f.addSystem(t, "h-d")
	// Seed an accepted ed25519 row.
	if _, err := f.store.RecordPending(sys.ID, "ssh-ed25519", "AAAA", "SHA256:old"); err != nil {
		t.Fatalf("RecordPending: %v", err)
	}
	if _, _, err := f.store.Accept(sys.ID, "ssh-ed25519", "SHA256:old", "u"); err != nil {
		t.Fatalf("seed Accept: %v", err)
	}
	// Pending replacement.
	if _, err := f.store.RecordPending(sys.ID, "ssh-ed25519", "BBBB", "SHA256:new"); err != nil {
		t.Fatalf("RecordPending replace: %v", err)
	}
	resp := f.do(t, http.MethodPost, "/api/systems/"+sys.ID+"/host-keys/accept", map[string]any{
		"algorithm":   "ssh-ed25519",
		"fingerprint": "SHA256:new",
	})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	recs, _, err := f.audit.ListQuery(audit.Query{Action: "system.host_key.replace", Limit: 5})
	if err != nil {
		t.Fatalf("ListQuery: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("audit rows = %d", len(recs))
	}
	if recs[0].Detail["prior_fingerprint"] != "SHA256:old" {
		t.Errorf("prior_fingerprint = %v", recs[0].Detail["prior_fingerprint"])
	}
}

func TestAcceptStaleFingerprintHandler(t *testing.T) {
	f := newFixture(t)
	sys := f.addSystem(t, "h-e")
	if _, err := f.store.RecordPending(sys.ID, "ssh-ed25519", "AAAA", "SHA256:current"); err != nil {
		t.Fatalf("RecordPending: %v", err)
	}
	resp := f.do(t, http.MethodPost, "/api/systems/"+sys.ID+"/host-keys/accept", map[string]any{
		"algorithm":   "ssh-ed25519",
		"fingerprint": "SHA256:stale",
	})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
}

func TestAcceptNoPendingHandler(t *testing.T) {
	f := newFixture(t)
	sys := f.addSystem(t, "h-f")
	resp := f.do(t, http.MethodPost, "/api/systems/"+sys.ID+"/host-keys/accept", map[string]any{
		"algorithm":   "ssh-ed25519",
		"fingerprint": "SHA256:x",
	})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAcceptBadRequest(t *testing.T) {
	f := newFixture(t)
	sys := f.addSystem(t, "h-g")
	resp := f.do(t, http.MethodPost, "/api/systems/"+sys.ID+"/host-keys/accept", map[string]any{})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestDeletePendingEmitsReject(t *testing.T) {
	f := newFixture(t)
	sys := f.addSystem(t, "h-h")
	hk, err := f.store.RecordPending(sys.ID, "ssh-ed25519", "AAAA", "SHA256:abc")
	if err != nil {
		t.Fatalf("RecordPending: %v", err)
	}
	resp := f.do(t, http.MethodDelete, "/api/systems/"+sys.ID+"/host-keys/"+hk.ID, nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	recs, _, _ := f.audit.ListQuery(audit.Query{Action: "system.host_key.reject", Limit: 5})
	if len(recs) != 1 {
		t.Errorf("reject audit rows = %d, want 1", len(recs))
	}
}

func TestDeleteAcceptedEmitsDelete(t *testing.T) {
	f := newFixture(t)
	sys := f.addSystem(t, "h-i")
	if _, err := f.store.RecordPending(sys.ID, "ssh-ed25519", "AAAA", "SHA256:abc"); err != nil {
		t.Fatalf("RecordPending: %v", err)
	}
	hk, _, err := f.store.Accept(sys.ID, "ssh-ed25519", "SHA256:abc", "u")
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	resp := f.do(t, http.MethodDelete, "/api/systems/"+sys.ID+"/host-keys/"+hk.ID, nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	recs, _, _ := f.audit.ListQuery(audit.Query{Action: "system.host_key.delete", Limit: 5})
	if len(recs) != 1 {
		t.Errorf("delete audit rows = %d, want 1", len(recs))
	}
}

func TestDeleteWrongSystem(t *testing.T) {
	// Key id from system A should 404 when accessed through system B's path.
	f := newFixture(t)
	sysA := f.addSystem(t, "h-j")
	sysB := f.addSystem(t, "h-k")
	hk, err := f.store.RecordPending(sysA.ID, "ssh-ed25519", "AAAA", "SHA256:abc")
	if err != nil {
		t.Fatalf("RecordPending: %v", err)
	}
	resp := f.do(t, http.MethodDelete, "/api/systems/"+sysB.ID+"/host-keys/"+hk.ID, nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestDeleteMissingKey(t *testing.T) {
	f := newFixture(t)
	sys := f.addSystem(t, "h-l")
	resp := f.do(t, http.MethodDelete, "/api/systems/"+sys.ID+"/host-keys/none", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestListStoreError500(t *testing.T) {
	f := newFixture(t)
	sys := f.addSystem(t, "list-err")
	h := &Handler{
		Store:           &listErrStore{Store: f.store, err: errors.New("rows boom")},
		Systems:         f.systems,
		Audit:           f.audit,
		CanManageSystem: func(context.Context, systems.System) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/systems/" + sys.ID + "/host-keys")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestAcceptBadJSON(t *testing.T) {
	f := newFixture(t)
	sys := f.addSystem(t, "bad-json")
	req, _ := http.NewRequest(http.MethodPost,
		f.srv.URL+"/api/systems/"+sys.ID+"/host-keys/accept",
		bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestDeleteForbidden(t *testing.T) {
	f := newFixture(t)
	sys := f.addSystem(t, "del-forb")
	f.allow = func(context.Context, systems.System) bool { return false }
	resp := f.do(t, http.MethodDelete, "/api/systems/"+sys.ID+"/host-keys/anything", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestDeleteStoreErrorOnLookup(t *testing.T) {
	f := newFixture(t)
	sys := f.addSystem(t, "del-err")
	h := &Handler{
		Store:           &getErrStore{Store: f.store, err: errors.New("get boom")},
		Systems:         f.systems,
		Audit:           f.audit,
		CanManageSystem: func(context.Context, systems.System) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/systems/"+sys.ID+"/host-keys/x", nil)
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

type listErrStore struct {
	Store
	err error
}

func (l *listErrStore) List(string) ([]HostKey, error) {
	return nil, l.err
}

type acceptErrStore struct {
	Store
	err error
}

func (a *acceptErrStore) Accept(string, string, string, string) (HostKey, bool, error) {
	return HostKey{}, false, a.err
}

func (a *acceptErrStore) AcceptedFor(string) ([]HostKey, error) {
	return nil, nil
}

func TestAcceptMissingFields(t *testing.T) {
	f := newFixture(t)
	sys := f.addSystem(t, "accept-bad")
	resp := f.do(t, http.MethodPost, "/api/systems/"+sys.ID+"/host-keys/accept", map[string]any{
		"algorithm": "ssh-ed25519",
		// no fingerprint
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAcceptStoreInternalError(t *testing.T) {
	f := newFixture(t)
	sys := f.addSystem(t, "accept-err")
	h := &Handler{
		Store:           &acceptErrStore{Store: f.store, err: errors.New("accept boom")},
		Systems:         f.systems,
		Audit:           f.audit,
		CanManageSystem: func(context.Context, systems.System) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost,
		srv.URL+"/api/systems/"+sys.ID+"/host-keys/accept",
		bytes.NewBufferString(`{"algorithm":"ssh-ed25519","fingerprint":"SHA256:x"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestScanMissingSystemForbidden(t *testing.T) {
	f := newFixture(t)
	sys := f.addSystem(t, "scan-forb")
	f.allow = func(context.Context, systems.System) bool { return false }
	resp := f.do(t, http.MethodPost, "/api/systems/"+sys.ID+"/host-keys/scan", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

type getErrStore struct {
	Store
	err error
}

func (g *getErrStore) Get(string) (HostKey, error) {
	return HostKey{}, g.err
}

func TestAcceptForbidden(t *testing.T) {
	f := newFixture(t)
	sys := f.addSystem(t, "h-m")
	f.allow = func(context.Context, systems.System) bool { return false }
	resp := f.do(t, http.MethodPost, "/api/systems/"+sys.ID+"/host-keys/accept", map[string]any{
		"algorithm":   "ssh-ed25519",
		"fingerprint": "fp",
	})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

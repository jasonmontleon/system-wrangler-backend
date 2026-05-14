// SPDX-License-Identifier: Apache-2.0

package groups

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/systems"
)

func newHandlerFixture(t *testing.T) (*httptest.Server, *MemStore, *systems.MemStore) {
	t.Helper()
	groupStore := newDeterministicMemStore()
	sysStore := systems.NewMemStore()
	var sysCounter atomic.Int64
	sysStore.NewID = func() string { return fmt.Sprintf("sid-%d", sysCounter.Add(1)) }
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var tick atomic.Int64
	sysStore.Now = func() time.Time {
		return base.Add(time.Duration(tick.Add(1)) * time.Second)
	}
	groupStore.Counter = func() map[string]int {
		counts := map[string]int{}
		all, _ := sysStore.List()
		for _, h := range all {
			if h.GroupID != nil {
				counts[*h.GroupID]++
			}
		}
		return counts
	}
	groupStore.OnDel = func(id string) { sysStore.ClearGroup(id) }

	mux := http.NewServeMux()
	NewHandler(groupStore, sysStore).Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, groupStore, sysStore
}

func mustDo(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	// Tests build URLs from httptest.Server; G704 SSRF-via-taint is a
	// false positive when the URL flows in from a test helper.
	resp, err := http.DefaultClient.Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func TestHandlerCreateThenList(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)

	body := strings.NewReader(`{"name":"prod"}`)
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/groups", body))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/groups", nil))
	defer func() { _ = resp.Body.Close() }()
	var got []Group
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].Name != "prod" {
		t.Errorf("List = %+v, want one 'prod'", got)
	}
}

func TestHandlerCreateRejectsDuplicate(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	for i, want := range []int{http.StatusCreated, http.StatusConflict} {
		resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/groups",
			strings.NewReader(`{"name":"prod"}`)))
		if resp.StatusCode != want {
			t.Errorf("attempt %d: status = %d, want %d", i, resp.StatusCode, want)
		}
		_ = resp.Body.Close()
	}
}

func TestHandlerCreateInvalidBody(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/groups",
		strings.NewReader(`{"name":""}`)))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerRenameAndDelete(t *testing.T) {
	srv, store, _ := newHandlerFixture(t)
	g, _ := store.Create(GroupInput{Name: "x"})

	resp := mustDo(t, mustReq(t, http.MethodPatch, srv.URL+"/api/groups/"+g.ID,
		strings.NewReader(`{"name":"y"}`)))
	if resp.StatusCode != http.StatusOK {
		t.Errorf("rename status = %d, want 200", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = mustDo(t, mustReq(t, http.MethodDelete, srv.URL+"/api/groups/"+g.ID, nil))
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete status = %d, want 204", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/groups/"+g.ID, nil))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("get after delete status = %d, want 404", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerSetSystemGroup(t *testing.T) {
	srv, gstore, sys := newHandlerFixture(t)
	g, _ := gstore.Create(GroupInput{Name: "g"})
	h, _ := sys.Create(systems.SystemInput{Name: "h", Hostname: "1.1.1.1"})

	body := fmt.Sprintf(`{"groupId":%q}`, g.ID)
	resp := mustDo(t, mustReq(t, http.MethodPut,
		srv.URL+"/api/systems/"+h.ID+"/group", strings.NewReader(body)))
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("assign status = %d, want 204", resp.StatusCode)
	}
	_ = resp.Body.Close()

	got, _ := sys.Get(h.ID)
	if got.GroupID == nil || *got.GroupID != g.ID {
		t.Errorf("after set GroupID = %v, want %q", got.GroupID, g.ID)
	}

	// Clear with explicit null.
	resp = mustDo(t, mustReq(t, http.MethodPut,
		srv.URL+"/api/systems/"+h.ID+"/group", strings.NewReader(`{"groupId":null}`)))
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("clear status = %d, want 204", resp.StatusCode)
	}
	_ = resp.Body.Close()
	got, _ = sys.Get(h.ID)
	if got.GroupID != nil {
		t.Errorf("after clear GroupID = %v, want nil", got.GroupID)
	}
}

func TestHandlerSetSystemGroupRejectsUnknownGroup(t *testing.T) {
	srv, _, sys := newHandlerFixture(t)
	h, _ := sys.Create(systems.SystemInput{Name: "h", Hostname: "1.1.1.1"})
	resp := mustDo(t, mustReq(t, http.MethodPut,
		srv.URL+"/api/systems/"+h.ID+"/group", strings.NewReader(`{"groupId":"bogus"}`)))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerSetSystemGroupRejectsUnknownSystem(t *testing.T) {
	srv, gstore, _ := newHandlerFixture(t)
	g, _ := gstore.Create(GroupInput{Name: "g"})
	body := fmt.Sprintf(`{"groupId":%q}`, g.ID)
	resp := mustDo(t, mustReq(t, http.MethodPut,
		srv.URL+"/api/systems/missing/group", strings.NewReader(body)))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerFireChangeOnCreate(t *testing.T) {
	groupStore := newDeterministicMemStore()
	sysStore := systems.NewMemStore()
	var calls atomic.Int32
	h := NewHandler(groupStore, sysStore)
	h.OnChange = func() { calls.Add(1) }
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/groups",
		strings.NewReader(`{"name":"prod"}`)))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if got := calls.Load(); got != 1 {
		t.Errorf("OnChange called %d times, want 1", got)
	}
}

func TestHandlerCreateRejectsMalformedJSON(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/groups",
		strings.NewReader(`{not-json}`)))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerGetMissing(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/groups/missing", nil))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerRenameValidationErrors(t *testing.T) {
	srv, store, _ := newHandlerFixture(t)
	g, _ := store.Create(GroupInput{Name: "x"})
	cases := []struct {
		body string
		want int
	}{
		{`{`, http.StatusBadRequest},
		{`{"name":""}`, http.StatusBadRequest},
	}
	for _, c := range cases {
		resp := mustDo(t, mustReq(t, http.MethodPatch, srv.URL+"/api/groups/"+g.ID,
			strings.NewReader(c.body)))
		if resp.StatusCode != c.want {
			t.Errorf("body %q: status = %d, want %d", c.body, resp.StatusCode, c.want)
		}
		_ = resp.Body.Close()
	}
}

func TestHandlerRenameMissing(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodPatch, srv.URL+"/api/groups/missing",
		strings.NewReader(`{"name":"y"}`)))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerRenameDuplicate(t *testing.T) {
	srv, store, _ := newHandlerFixture(t)
	a, _ := store.Create(GroupInput{Name: "a"})
	if _, err := store.Create(GroupInput{Name: "b"}); err != nil {
		t.Fatalf("Create b: %v", err)
	}
	resp := mustDo(t, mustReq(t, http.MethodPatch, srv.URL+"/api/groups/"+a.ID,
		strings.NewReader(`{"name":"b"}`)))
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerDeleteMissing(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodDelete, srv.URL+"/api/groups/missing", nil))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerSetSystemGroupRejectsMalformedJSON(t *testing.T) {
	srv, _, sys := newHandlerFixture(t)
	h, _ := sys.Create(systems.SystemInput{Name: "h", Hostname: "1.1.1.1"})
	resp := mustDo(t, mustReq(t, http.MethodPut,
		srv.URL+"/api/systems/"+h.ID+"/group", strings.NewReader(`{`)))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerAuditLogsCreate(t *testing.T) {
	dsn := "file:" + t.TempDir() + "/audit.db"
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	auditStore, err := audit.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStore: %v", err)
	}

	gstore := newDeterministicMemStore()
	sys := systems.NewMemStore()
	h := NewHandler(gstore, sys)
	h.Audit = auditStore
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/groups",
		strings.NewReader(`{"name":"audited"}`)))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	rows, _, err := auditStore.ListQuery(audit.Query{Limit: 10})
	if err != nil {
		t.Fatalf("audit ListQuery: %v", err)
	}
	if len(rows) != 1 || rows[0].Action != "system_group.create" {
		t.Errorf("audit rows = %+v, want one system_group.create", rows)
	}
}

func TestHandlerGetSurfacesStoreError(t *testing.T) {
	stub := &stubStore{getErr: errBoom}
	mux := http.NewServeMux()
	NewHandler(stub, systems.NewMemStore()).Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp := mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/groups/whatever", nil))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerListSurfacesStoreError(t *testing.T) {
	stub := &stubStore{listErr: errBoom}
	mux := http.NewServeMux()
	NewHandler(stub, systems.NewMemStore()).Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp := mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/groups", nil))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

var errBoom = fmt.Errorf("boom")

type stubStore struct {
	listErr error
	getErr  error
}

func (s *stubStore) Create(GroupInput) (Group, error) { return Group{}, s.listErr }
func (s *stubStore) Get(string) (Group, error) {
	if s.getErr != nil {
		return Group{}, s.getErr
	}
	return Group{}, ErrNotFound
}
func (s *stubStore) List() ([]Group, error)                   { return nil, s.listErr }
func (s *stubStore) Rename(string, GroupInput) (Group, error) { return Group{}, ErrNotFound }
func (s *stubStore) Delete(string) error                      { return ErrNotFound }

func mustReq(t *testing.T, method, url string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

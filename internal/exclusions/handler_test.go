// SPDX-License-Identifier: Apache-2.0

package exclusions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/groups"
	"system-wrangler-backend/internal/systems"
)

// handlerFixture wires the SQLite-backed Store to an httptest.Server
// and stamps an actor onto request contexts. RBAC predicates are
// allow-by-default; individual tests override them to verify denials.
type handlerFixture struct {
	srv     *httptest.Server
	store   *SQLiteStore
	audit   *audit.Store
	systems *systems.SQLiteStore
	groups  *groups.SQLiteStore
}

func newHandlerFixture(t *testing.T) *handlerFixture {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "exclusion-handler.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sysStore, err := systems.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("systems.NewSQLiteStore: %v", err)
	}
	groupStore, err := groups.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("groups.NewSQLiteStore: %v", err)
	}
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("exclusions.NewSQLiteStore: %v", err)
	}
	auditStore, err := audit.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStore: %v", err)
	}

	h := &Handler{
		Store: store,
		Audit: auditStore,
		// Allow-by-default — tests override per-case.
		CanManageGlobal: func(context.Context) bool { return true },
		CanReadGroup:    func(context.Context, string) bool { return true },
		CanManageGroup:  func(context.Context, string) bool { return true },
		CanReadSystem:   func(context.Context, string) bool { return true },
		CanManageSystem: func(context.Context, string) bool { return true },
	}
	mux := http.NewServeMux()
	// Stamp an actor on every request so audit + createScope's actor
	// guard see a real id.
	stamp := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := audit.WithActor(r.Context(), audit.Actor{
				Kind: audit.ActorUser, ID: "u-actor", Label: "actor",
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	h.Register(mux, stamp)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &handlerFixture{srv: srv, store: store, audit: auditStore, systems: sysStore, groups: groupStore}
}

func (f *handlerFixture) do(t *testing.T, method, path, body string) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = bytes.NewBufferString(body)
	}
	req, err := http.NewRequest(method, f.srv.URL+path, rdr)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if rdr != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	//nolint:gosec // G107: URL composed from httptest server, not user input.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func decode(t *testing.T, r *http.Response, into any) {
	t.Helper()
	defer func() { _ = r.Body.Close() }()
	if err := json.NewDecoder(r.Body).Decode(into); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

func TestHandlerCreateGlobalThenList(t *testing.T) {
	f := newHandlerFixture(t)
	resp := f.do(t, http.MethodPost, "/api/admin/package-exclusions",
		`{"updater":"builtin.dnf","pattern":"kernel*","reason":"fleet pin"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create status = %d, body=%s", resp.StatusCode, string(body))
	}
	var created Exclusion
	decode(t, resp, &created)
	if created.Scope != ScopeGlobal || created.Updater != "builtin.dnf" || created.CreatedBy != "u-actor" {
		t.Errorf("created = %+v", created)
	}
	resp2 := f.do(t, http.MethodGet, "/api/admin/package-exclusions", "")
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d", resp2.StatusCode)
	}
	var rows []Exclusion
	decode(t, resp2, &rows)
	if len(rows) != 1 {
		t.Errorf("rows = %v", rows)
	}
}

func TestHandlerCreateGlobalRejectsBadUpdater(t *testing.T) {
	f := newHandlerFixture(t)
	resp := f.do(t, http.MethodPost, "/api/admin/package-exclusions",
		`{"updater":"nope","pattern":"kernel"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body=%s", resp.StatusCode, string(body))
	}
}

func TestHandlerCreateGlobalDuplicateIs409(t *testing.T) {
	f := newHandlerFixture(t)
	body := `{"updater":"builtin.dnf","pattern":"kernel"}`
	r1 := f.do(t, http.MethodPost, "/api/admin/package-exclusions", body)
	defer func() { _ = r1.Body.Close() }()
	r2 := f.do(t, http.MethodPost, "/api/admin/package-exclusions", body)
	defer func() { _ = r2.Body.Close() }()
	if r2.StatusCode != http.StatusConflict {
		b, _ := io.ReadAll(r2.Body)
		t.Fatalf("status = %d, body=%s", r2.StatusCode, string(b))
	}
}

func TestHandlerCreateGlobalForbiddenWithoutManage(t *testing.T) {
	f := newHandlerFixture(t)
	// Override the gate to deny.
	h := &Handler{
		Store:           f.store,
		Audit:           f.audit,
		CanManageGlobal: func(context.Context) bool { return false },
	}
	mux := http.NewServeMux()
	h.Register(mux, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := audit.WithActor(r.Context(), audit.Actor{Kind: audit.ActorUser, ID: "u", Label: "u"})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/admin/package-exclusions",
		strings.NewReader(`{"updater":"builtin.dnf","pattern":"k"}`))
	if err != nil {
		t.Fatalf("req: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	//nolint:gosec
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHandlerDeleteGlobalLogsAudit(t *testing.T) {
	f := newHandlerFixture(t)
	resp := f.do(t, http.MethodPost, "/api/admin/package-exclusions",
		`{"updater":"builtin.dnf","pattern":"k"}`)
	defer func() { _ = resp.Body.Close() }()
	var row Exclusion
	decode(t, resp, &row)
	resp2 := f.do(t, http.MethodDelete, "/api/admin/package-exclusions/"+row.ID, "")
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", resp2.StatusCode)
	}
	rows, _, err := f.audit.ListQuery(audit.Query{Action: "package_exclusion.delete", Limit: 5})
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("audit rows = %d, want 1", len(rows))
	}
}

func TestHandlerDeleteGlobalRefusesWrongScope(t *testing.T) {
	f := newHandlerFixture(t)
	// Create a group-scope row directly so its id is "real" but its scope
	// doesn't match the global delete route.
	g, _ := f.groups.Create(groups.GroupInput{Name: "prod"})
	row, err := f.store.Create(ScopeGroup, g.ID, "builtin.dnf", "k", "", "u")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	resp := f.do(t, http.MethodDelete, "/api/admin/package-exclusions/"+row.ID, "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (cross-scope delete)", resp.StatusCode)
	}
	// Row must still be there.
	if _, err := f.store.Get(row.ID); err != nil {
		t.Errorf("row should survive cross-scope delete attempt: %v", err)
	}
}

func TestHandlerGroupScopeRoundTrip(t *testing.T) {
	f := newHandlerFixture(t)
	g, _ := f.groups.Create(groups.GroupInput{Name: "prod"})
	resp := f.do(t, http.MethodPost, "/api/groups/"+g.ID+"/package-exclusions",
		`{"updater":"builtin.dnf","pattern":"nginx"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body=%s", resp.StatusCode, string(body))
	}
	var row Exclusion
	decode(t, resp, &row)
	if row.Scope != ScopeGroup || row.TargetID != g.ID {
		t.Errorf("row = %+v, want group/%s", row, g.ID)
	}
	resp2 := f.do(t, http.MethodGet, "/api/groups/"+g.ID+"/package-exclusions", "")
	defer func() { _ = resp2.Body.Close() }()
	var rows []Exclusion
	decode(t, resp2, &rows)
	if len(rows) != 1 {
		t.Errorf("list rows = %v", rows)
	}
}

func TestHandlerSystemEffectiveUnion(t *testing.T) {
	f := newHandlerFixture(t)
	g, _ := f.groups.Create(groups.GroupInput{Name: "prod"})
	h, _ := f.systems.Create(systems.SystemInput{Name: "h", Hostname: "1.1.1.1"})
	if err := f.systems.SetGroup(h.ID, &g.ID); err != nil {
		t.Fatalf("SetGroup: %v", err)
	}
	if _, err := f.store.Create(ScopeGlobal, "", "builtin.dnf", "kernel", "", "u"); err != nil {
		t.Fatalf("global: %v", err)
	}
	if _, err := f.store.Create(ScopeGroup, g.ID, "builtin.dnf", "nginx", "", "u"); err != nil {
		t.Fatalf("group: %v", err)
	}
	resp := f.do(t, http.MethodGet,
		"/api/systems/"+h.ID+"/package-exclusions/effective?updater=builtin.dnf", "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var rows []Exclusion
	decode(t, resp, &rows)
	if len(rows) != 2 {
		t.Errorf("rows = %v", rows)
	}
}

func TestHandlerSystemEffectiveRequiresUpdaterParam(t *testing.T) {
	f := newHandlerFixture(t)
	h, _ := f.systems.Create(systems.SystemInput{Name: "h", Hostname: "1.1.1.1"})
	resp := f.do(t, http.MethodGet, "/api/systems/"+h.ID+"/package-exclusions/effective", "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlerGroupDeleteRoundTrip(t *testing.T) {
	f := newHandlerFixture(t)
	g, _ := f.groups.Create(groups.GroupInput{Name: "prod"})
	row, err := f.store.Create(ScopeGroup, g.ID, "builtin.dnf", "nginx", "", "u")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	resp := f.do(t, http.MethodDelete,
		"/api/groups/"+g.ID+"/package-exclusions/"+row.ID, "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if _, err := f.store.Get(row.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("row should be gone: err = %v", err)
	}
}

func TestHandlerGroupDeleteForbiddenWithoutManage(t *testing.T) {
	f := newHandlerFixture(t)
	g, _ := f.groups.Create(groups.GroupInput{Name: "prod"})
	row, _ := f.store.Create(ScopeGroup, g.ID, "builtin.dnf", "nginx", "", "u")
	// Rebuild the handler with a deny gate.
	h := &Handler{
		Store:          f.store,
		Audit:          f.audit,
		CanManageGroup: func(context.Context, string) bool { return false },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodDelete,
		srv.URL+"/api/groups/"+g.ID+"/package-exclusions/"+row.ID, nil)
	//nolint:gosec
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHandlerSystemCreateAndDelete(t *testing.T) {
	f := newHandlerFixture(t)
	h, _ := f.systems.Create(systems.SystemInput{Name: "h", Hostname: "1.1.1.1"})
	create := f.do(t, http.MethodPost,
		"/api/systems/"+h.ID+"/package-exclusions",
		`{"updater":"builtin.dnf","pattern":"redis"}`)
	defer func() { _ = create.Body.Close() }()
	if create.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(create.Body)
		t.Fatalf("create status = %d, body=%s", create.StatusCode, string(body))
	}
	var row Exclusion
	decode(t, create, &row)
	if row.Scope != ScopeSystem || row.TargetID != h.ID {
		t.Errorf("row = %+v", row)
	}
	del := f.do(t, http.MethodDelete,
		"/api/systems/"+h.ID+"/package-exclusions/"+row.ID, "")
	defer func() { _ = del.Body.Close() }()
	if del.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status = %d", del.StatusCode)
	}
}

func TestHandlerSystemForbiddenCreate(t *testing.T) {
	h := &Handler{
		Store:           &noopStore{},
		CanManageSystem: func(context.Context, string) bool { return false },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodPost,
		srv.URL+"/api/systems/sid/package-exclusions",
		strings.NewReader(`{"updater":"builtin.dnf","pattern":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	//nolint:gosec
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHandlerGroupListForbiddenIs404(t *testing.T) {
	h := &Handler{
		Store:        &noopStore{},
		CanReadGroup: func(context.Context, string) bool { return false },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	//nolint:gosec
	resp, err := http.Get(srv.URL + "/api/groups/gid/package-exclusions")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandlerCreateUnauthenticated(t *testing.T) {
	// Handler with no stamping middleware — actorIDFromCtx returns ""
	// so createScope short-circuits with 401.
	h := &Handler{
		Store:           &noopStore{},
		CanManageGlobal: func(context.Context) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodPost,
		srv.URL+"/api/admin/package-exclusions",
		strings.NewReader(`{"updater":"builtin.dnf","pattern":"k"}`))
	req.Header.Set("Content-Type", "application/json")
	//nolint:gosec
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestHandlerCreateInvalidJSON(t *testing.T) {
	f := newHandlerFixture(t)
	resp := f.do(t, http.MethodPost, "/api/admin/package-exclusions", `{bogus`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlerEffectiveBadUpdaterReturns400(t *testing.T) {
	f := newHandlerFixture(t)
	h, _ := f.systems.Create(systems.SystemInput{Name: "h", Hostname: "1.1.1.1"})
	// Empty systemID via the resolver path: pass updater='' to trigger
	// ErrInvalid from ResolveEffectiveForSystem.
	resp := f.do(t, http.MethodGet,
		"/api/systems/"+h.ID+"/package-exclusions/effective?updater=", "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlerSystemListForbiddenWithoutRead(t *testing.T) {
	h := &Handler{
		Store:           &noopStore{},
		CanReadSystem:   func(context.Context, string) bool { return false },
		CanManageSystem: func(context.Context, string) bool { return false },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	//nolint:gosec
	resp, err := http.Get(srv.URL + "/api/systems/sid/package-exclusions")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// noopStore is a Store stub used only to assert handler-side gate
// behaviour without instantiating a real db.
type noopStore struct{}

func (noopStore) Create(Scope, string, string, string, string, string) (Exclusion, error) {
	return Exclusion{}, errors.New("noop")
}
func (noopStore) Get(string) (Exclusion, error)          { return Exclusion{}, ErrNotFound }
func (noopStore) Delete(string) error                    { return ErrNotFound }
func (noopStore) ListGlobal() ([]Exclusion, error)       { return nil, nil }
func (noopStore) ListGroup(string) ([]Exclusion, error)  { return nil, nil }
func (noopStore) ListSystem(string) ([]Exclusion, error) { return nil, nil }
func (noopStore) ResolveForSystem(string, string) ([]string, error) {
	return nil, nil
}
func (noopStore) ResolveEffectiveForSystem(string, string) ([]Exclusion, error) {
	return nil, nil
}

// erroringStore returns a non-sentinel error on every method so the
// handler's 500 path gets exercised across endpoints.
type erroringStore struct{}

var errStoreBoom = errors.New("store down")

func (erroringStore) Create(Scope, string, string, string, string, string) (Exclusion, error) {
	return Exclusion{}, errStoreBoom
}
func (erroringStore) Get(string) (Exclusion, error)          { return Exclusion{}, errStoreBoom }
func (erroringStore) Delete(string) error                    { return errStoreBoom }
func (erroringStore) ListGlobal() ([]Exclusion, error)       { return nil, errStoreBoom }
func (erroringStore) ListGroup(string) ([]Exclusion, error)  { return nil, errStoreBoom }
func (erroringStore) ListSystem(string) ([]Exclusion, error) { return nil, errStoreBoom }
func (erroringStore) ResolveForSystem(string, string) ([]string, error) {
	return nil, errStoreBoom
}
func (erroringStore) ResolveEffectiveForSystem(string, string) ([]Exclusion, error) {
	return nil, errStoreBoom
}

func TestHandlerDeleteGlobalForbiddenWithoutManage(t *testing.T) {
	f := newHandlerFixture(t)
	// Plant a row first as global admin would.
	created, err := f.store.Create(ScopeGlobal, "", "builtin.dnf", "x*", "r", "u")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Strip manage perms on the handler.
	h := &Handler{
		Store:           f.store,
		CanManageGlobal: func(context.Context) bool { return false },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/admin/package-exclusions/"+created.ID, nil)
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHandlerCreateGroupForbiddenWithoutManage(t *testing.T) {
	h := &Handler{
		Store:          noopStore{},
		CanManageGroup: func(context.Context, string) bool { return false },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Post(srv.URL+"/api/groups/g1/package-exclusions", "application/json",
		strings.NewReader(`{"updater":"builtin.dnf","pattern":"x*"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHandlerDeleteSystemForbiddenWithoutManage(t *testing.T) {
	h := &Handler{
		Store:           noopStore{},
		CanManageSystem: func(context.Context, string) bool { return false },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/systems/s1/package-exclusions/x", nil)
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHandlerEffectiveSystemForbiddenReturns404(t *testing.T) {
	h := &Handler{
		Store:         noopStore{},
		CanReadSystem: func(context.Context, string) bool { return false },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/systems/s1/package-exclusions/effective?updater=builtin.dnf")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandlerCreateScopeRejectsInvalidViaStore(t *testing.T) {
	h := &Handler{
		Store:           invalidCreateStore{},
		CanManageGlobal: func(context.Context) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := audit.WithActor(r.Context(), audit.Actor{Kind: audit.ActorUser, ID: "u", Label: "u"})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Post(srv.URL+"/api/admin/package-exclusions", "application/json",
		strings.NewReader(`{"updater":"builtin.dnf","pattern":"x*"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

type invalidCreateStore struct{ noopStore }

func (invalidCreateStore) Create(Scope, string, string, string, string, string) (Exclusion, error) {
	return Exclusion{}, ErrInvalid
}

func TestHandlerDeleteWrongScopeIs404(t *testing.T) {
	f := newHandlerFixture(t)
	created, err := f.store.Create(ScopeGroup, "g-abc", "builtin.dnf", "x*", "r", "u")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	resp := f.do(t, http.MethodDelete, "/api/groups/g-DIFFERENT/package-exclusions/"+created.ID, "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandlerGateAllowsWhenGateNil(t *testing.T) {
	h := &Handler{Store: noopStore{}}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/admin/package-exclusions")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestHandlerAuditNilDoesNotPanic(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "no-audit.db")
	db, _ := database.Open(dsn)
	t.Cleanup(func() { _ = db.Close() })
	_, _ = systems.NewSQLiteStore(db)
	_, _ = groups.NewSQLiteStore(db)
	store, _ := NewSQLiteStore(db)
	h := &Handler{
		Store:           store,
		CanManageGlobal: func(context.Context) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := audit.WithActor(r.Context(), audit.Actor{Kind: audit.ActorUser, ID: "u", Label: "u"})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Post(srv.URL+"/api/admin/package-exclusions", "application/json",
		strings.NewReader(`{"updater":"builtin.dnf","pattern":"x*"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want 201", resp.StatusCode)
	}
}

func TestHandlerStoreErrorsReturn500(t *testing.T) {
	h := &Handler{
		Store:           erroringStore{},
		CanManageGlobal: func(context.Context) bool { return true },
		CanReadGroup:    func(context.Context, string) bool { return true },
		CanManageGroup:  func(context.Context, string) bool { return true },
		CanReadSystem:   func(context.Context, string) bool { return true },
		CanManageSystem: func(context.Context, string) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := audit.WithActor(r.Context(), audit.Actor{Kind: audit.ActorUser, ID: "u", Label: "u"})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/admin/package-exclusions"},
		{http.MethodGet, "/api/groups/g1/package-exclusions"},
		{http.MethodGet, "/api/systems/s1/package-exclusions"},
		{http.MethodGet, "/api/systems/s1/package-exclusions/effective?updater=builtin.dnf"},
	}
	for _, c := range cases {
		req, _ := http.NewRequest(c.method, srv.URL+c.path, nil)
		//nolint:gosec
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", c.method, c.path, err)
		}
		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("%s %s: status = %d, want 500", c.method, c.path, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}

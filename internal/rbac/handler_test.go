// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/auth"
	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/groups"
	"system-wrangler-backend/internal/systems"
)

type handlerFixture struct {
	db    *sql.DB
	store *SQLiteStore
	auth  *auth.SQLiteAuthStore
	grp   *groups.SQLiteStore
	audit *audit.Store
	mux   *http.ServeMux
	srv   *httptest.Server
	scope *Scope
}

func newHandlerFixture(t *testing.T) *handlerFixture {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "rbac_h.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	a, err := auth.NewSQLiteAuthStore(db)
	if err != nil {
		t.Fatalf("auth.NewSQLiteAuthStore: %v", err)
	}
	if _, err := systems.NewSQLiteStore(db); err != nil {
		t.Fatalf("systems.NewSQLiteStore: %v", err)
	}
	g, err := groups.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("groups.NewSQLiteStore: %v", err)
	}
	au, err := audit.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStore: %v", err)
	}
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	f := &handlerFixture{
		db:    db,
		store: store,
		auth:  a,
		grp:   g,
		audit: au,
		mux:   http.NewServeMux(),
	}
	h := NewHandler(store, a, g)
	h.Audit = au
	// Tests set f.scope before each request; the middleware stamps it
	// onto the context so the handler can read it. A nil f.scope means
	// "no auth" — the request lands without a Scope, matching what
	// happens in production when middleware misorders.
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if f.scope != nil {
				ctx = WithScope(ctx, *f.scope)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	h.Register(f.mux, mw)
	f.srv = httptest.NewServer(f.mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *handlerFixture) setScope(s Scope) { f.scope = &s }

func (f *handlerFixture) clearScope() { f.scope = nil }

func (f *handlerFixture) mustUser(t *testing.T, name string) string {
	t.Helper()
	u, err := f.auth.Create(name, "hash")
	if err != nil {
		t.Fatalf("auth.Create %s: %v", name, err)
	}
	return u.ID
}

func (f *handlerFixture) mustGroup(t *testing.T, name string) groups.Group {
	t.Helper()
	g, err := f.grp.Create(groups.GroupInput{Name: name})
	if err != nil {
		t.Fatalf("groups.Create %s: %v", name, err)
	}
	return g
}

func mustReq(t *testing.T, method, url string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return req
}

func doReq(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	// Test-controlled URLs from httptest.Server; gosec SSRF false positive.
	resp, err := http.DefaultClient.Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	return resp
}

func TestGrantGroupAsGlobalAdmin(t *testing.T) {
	f := newHandlerFixture(t)
	target := f.mustUser(t, "alice")
	g := f.mustGroup(t, "prod")
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))

	body := strings.NewReader(`{"userId":"` + target + `","role":"admin"}`)
	resp := doReq(t, mustReq(t, http.MethodPost, f.srv.URL+"/api/groups/"+g.ID+"/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, raw)
	}
	var dto roleAssignmentDTO
	if err := json.NewDecoder(resp.Body).Decode(&dto); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dto.UserID != target || dto.Role != RoleAdmin || dto.GroupID == nil || *dto.GroupID != g.ID {
		t.Errorf("dto = %+v, want target=%s admin on %s", dto, target, g.ID)
	}
	if dto.Username != "alice" || dto.GroupName != "prod" {
		t.Errorf("dto labels = %q / %q, want alice / prod", dto.Username, dto.GroupName)
	}
}

func TestGrantGroupAsGroupAdminCannotAssignAdmin(t *testing.T) {
	f := newHandlerFixture(t)
	target := f.mustUser(t, "alice")
	g := f.mustGroup(t, "prod")
	f.setScope(NewScope("caller", []Assignment{
		{UserID: "caller", GroupID: &g.ID, Role: RoleAdmin},
	}))
	body := strings.NewReader(`{"userId":"` + target + `","role":"admin"}`)
	resp := doReq(t, mustReq(t, http.MethodPost, f.srv.URL+"/api/groups/"+g.ID+"/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestGrantGroupAsGroupAdminAssignsOperator(t *testing.T) {
	f := newHandlerFixture(t)
	target := f.mustUser(t, "alice")
	g := f.mustGroup(t, "prod")
	f.setScope(NewScope("caller", []Assignment{
		{UserID: "caller", GroupID: &g.ID, Role: RoleAdmin},
	}))
	body := strings.NewReader(`{"userId":"` + target + `","role":"operator"}`)
	resp := doReq(t, mustReq(t, http.MethodPost, f.srv.URL+"/api/groups/"+g.ID+"/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, raw)
	}
}

func TestGrantGroupAsAuditorForbidden(t *testing.T) {
	f := newHandlerFixture(t)
	target := f.mustUser(t, "alice")
	g := f.mustGroup(t, "prod")
	f.setScope(NewScope("caller", []Assignment{
		{UserID: "caller", GroupID: &g.ID, Role: RoleAuditor},
	}))
	body := strings.NewReader(`{"userId":"` + target + `","role":"operator"}`)
	resp := doReq(t, mustReq(t, http.MethodPost, f.srv.URL+"/api/groups/"+g.ID+"/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestGrantGroupUnknownGroup(t *testing.T) {
	f := newHandlerFixture(t)
	target := f.mustUser(t, "alice")
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	body := strings.NewReader(`{"userId":"` + target + `","role":"admin"}`)
	resp := doReq(t, mustReq(t, http.MethodPost, f.srv.URL+"/api/groups/nope/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestGrantGroupUnknownUser(t *testing.T) {
	f := newHandlerFixture(t)
	g := f.mustGroup(t, "prod")
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	body := strings.NewReader(`{"userId":"ghost","role":"admin"}`)
	resp := doReq(t, mustReq(t, http.MethodPost, f.srv.URL+"/api/groups/"+g.ID+"/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestGrantGroupDuplicate(t *testing.T) {
	f := newHandlerFixture(t)
	target := f.mustUser(t, "alice")
	g := f.mustGroup(t, "prod")
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	body := func() *strings.Reader { return strings.NewReader(`{"userId":"` + target + `","role":"operator"}`) }
	resp := doReq(t, mustReq(t, http.MethodPost, f.srv.URL+"/api/groups/"+g.ID+"/role-assignments", body()))
	_ = resp.Body.Close()
	resp2 := doReq(t, mustReq(t, http.MethodPost, f.srv.URL+"/api/groups/"+g.ID+"/role-assignments", body()))
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("second grant status = %d, want 409", resp2.StatusCode)
	}
}

func TestGrantGroupBadRole(t *testing.T) {
	f := newHandlerFixture(t)
	target := f.mustUser(t, "alice")
	g := f.mustGroup(t, "prod")
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	body := strings.NewReader(`{"userId":"` + target + `","role":"emperor"}`)
	resp := doReq(t, mustReq(t, http.MethodPost, f.srv.URL+"/api/groups/"+g.ID+"/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestGrantGroupBadJSON(t *testing.T) {
	f := newHandlerFixture(t)
	g := f.mustGroup(t, "prod")
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	body := strings.NewReader(`{not json}`)
	resp := doReq(t, mustReq(t, http.MethodPost, f.srv.URL+"/api/groups/"+g.ID+"/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestGrantGroupMissingUserId(t *testing.T) {
	f := newHandlerFixture(t)
	g := f.mustGroup(t, "prod")
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	body := strings.NewReader(`{"role":"admin"}`)
	resp := doReq(t, mustReq(t, http.MethodPost, f.srv.URL+"/api/groups/"+g.ID+"/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestRevokeGroupAsGroupAdmin(t *testing.T) {
	f := newHandlerFixture(t)
	target := f.mustUser(t, "alice")
	g := f.mustGroup(t, "prod")
	gid := g.ID
	if err := f.store.Grant(Assignment{UserID: target, GroupID: &gid, Role: RoleOperator}); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	f.setScope(NewScope("caller", []Assignment{
		{UserID: "caller", GroupID: &g.ID, Role: RoleAdmin},
	}))
	url := f.srv.URL + "/api/groups/" + g.ID + "/role-assignments/" + target + "/operator"
	resp := doReq(t, mustReq(t, http.MethodDelete, url, nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
	rows, _ := f.store.Resolve(target)
	if len(rows) != 0 {
		t.Errorf("after revoke, rows = %+v, want empty", rows)
	}
}

func TestRevokeGroupAsGroupAdminCannotRevokeAdmin(t *testing.T) {
	f := newHandlerFixture(t)
	target := f.mustUser(t, "alice")
	g := f.mustGroup(t, "prod")
	gid := g.ID
	_ = f.store.Grant(Assignment{UserID: target, GroupID: &gid, Role: RoleAdmin})
	f.setScope(NewScope("caller", []Assignment{
		{UserID: "caller", GroupID: &g.ID, Role: RoleAdmin},
	}))
	url := f.srv.URL + "/api/groups/" + g.ID + "/role-assignments/" + target + "/admin"
	resp := doReq(t, mustReq(t, http.MethodDelete, url, nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestRevokeGroupMissingAssignment(t *testing.T) {
	f := newHandlerFixture(t)
	target := f.mustUser(t, "alice")
	g := f.mustGroup(t, "prod")
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	url := f.srv.URL + "/api/groups/" + g.ID + "/role-assignments/" + target + "/operator"
	resp := doReq(t, mustReq(t, http.MethodDelete, url, nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestRevokeGroupBadRole(t *testing.T) {
	f := newHandlerFixture(t)
	target := f.mustUser(t, "alice")
	g := f.mustGroup(t, "prod")
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	url := f.srv.URL + "/api/groups/" + g.ID + "/role-assignments/" + target + "/emperor"
	resp := doReq(t, mustReq(t, http.MethodDelete, url, nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestListGroupAsGroupAuditor(t *testing.T) {
	f := newHandlerFixture(t)
	target := f.mustUser(t, "alice")
	g := f.mustGroup(t, "prod")
	gid := g.ID
	_ = f.store.Grant(Assignment{UserID: target, GroupID: &gid, Role: RoleOperator})
	f.setScope(NewScope("caller", []Assignment{
		{UserID: "caller", GroupID: &g.ID, Role: RoleAuditor},
	}))
	resp := doReq(t, mustReq(t, http.MethodGet, f.srv.URL+"/api/groups/"+g.ID+"/role-assignments", nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body struct {
		Assignments []roleAssignmentDTO `json:"assignments"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Assignments) != 1 || body.Assignments[0].Username != "alice" {
		t.Errorf("body = %+v, want one alice", body)
	}
}

func TestListGroupOutsideScopeForbidden(t *testing.T) {
	f := newHandlerFixture(t)
	g := f.mustGroup(t, "prod")
	other := f.mustGroup(t, "staging")
	f.setScope(NewScope("caller", []Assignment{
		{UserID: "caller", GroupID: &other.ID, Role: RoleAuditor},
	}))
	resp := doReq(t, mustReq(t, http.MethodGet, f.srv.URL+"/api/groups/"+g.ID+"/role-assignments", nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestListGroupMissingGroup(t *testing.T) {
	f := newHandlerFixture(t)
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	resp := doReq(t, mustReq(t, http.MethodGet, f.srv.URL+"/api/groups/nope/role-assignments", nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAdminListGlobalAdminOnly(t *testing.T) {
	f := newHandlerFixture(t)
	f.setScope(NewScope("op", []Assignment{{UserID: "op", Role: RoleOperator}}))
	resp := doReq(t, mustReq(t, http.MethodGet, f.srv.URL+"/api/admin/role-assignments", nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAdminListReturnsAllRows(t *testing.T) {
	f := newHandlerFixture(t)
	uid := f.mustUser(t, "alice")
	g := f.mustGroup(t, "prod")
	gid := g.ID
	_ = f.store.Grant(Assignment{UserID: uid, GroupID: &gid, Role: RoleOperator})
	_ = f.store.Grant(Assignment{UserID: uid, Role: RoleAuditor})

	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	resp := doReq(t, mustReq(t, http.MethodGet, f.srv.URL+"/api/admin/role-assignments", nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body struct {
		Assignments []roleAssignmentDTO `json:"assignments"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Two for alice + one backfilled global admin row.
	if len(body.Assignments) < 2 {
		t.Errorf("expected at least 2 rows, got %d: %+v", len(body.Assignments), body.Assignments)
	}
	var sawGlobal, sawGroup bool
	for _, a := range body.Assignments {
		if a.UserID == uid && a.GroupID == nil && a.Role == RoleAuditor {
			sawGlobal = true
		}
		if a.UserID == uid && a.GroupID != nil && *a.GroupID == g.ID {
			sawGroup = true
			if a.GroupName != "prod" {
				t.Errorf("groupName = %q, want prod", a.GroupName)
			}
		}
	}
	if !sawGlobal || !sawGroup {
		t.Errorf("missing rows: global=%v group=%v in %+v", sawGlobal, sawGroup, body.Assignments)
	}
}

func TestAdminGrantGlobal(t *testing.T) {
	f := newHandlerFixture(t)
	uid := f.mustUser(t, "alice")
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	body := strings.NewReader(`{"userId":"` + uid + `","groupId":null,"role":"operator"}`)
	resp := doReq(t, mustReq(t, http.MethodPost, f.srv.URL+"/api/admin/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, raw)
	}
	rows, _ := f.store.Resolve(uid)
	want := false
	for _, r := range rows {
		if r.GroupID == nil && r.Role == RoleOperator {
			want = true
		}
	}
	if !want {
		t.Errorf("expected global operator row for %s, got %+v", uid, rows)
	}
}

func TestAdminGrantNonAdminForbidden(t *testing.T) {
	f := newHandlerFixture(t)
	uid := f.mustUser(t, "alice")
	f.setScope(NewScope("op", []Assignment{{UserID: "op", Role: RoleOperator}}))
	body := strings.NewReader(`{"userId":"` + uid + `","groupId":null,"role":"auditor"}`)
	resp := doReq(t, mustReq(t, http.MethodPost, f.srv.URL+"/api/admin/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAdminGrantUnknownUser(t *testing.T) {
	f := newHandlerFixture(t)
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	body := strings.NewReader(`{"userId":"ghost","groupId":null,"role":"auditor"}`)
	resp := doReq(t, mustReq(t, http.MethodPost, f.srv.URL+"/api/admin/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAdminGrantUnknownGroup(t *testing.T) {
	f := newHandlerFixture(t)
	uid := f.mustUser(t, "alice")
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	body := strings.NewReader(`{"userId":"` + uid + `","groupId":"nope","role":"auditor"}`)
	resp := doReq(t, mustReq(t, http.MethodPost, f.srv.URL+"/api/admin/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAdminGrantEmptyGroupIDRejected(t *testing.T) {
	f := newHandlerFixture(t)
	uid := f.mustUser(t, "alice")
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	body := strings.NewReader(`{"userId":"` + uid + `","groupId":"","role":"auditor"}`)
	resp := doReq(t, mustReq(t, http.MethodPost, f.srv.URL+"/api/admin/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminGrantBadJSON(t *testing.T) {
	f := newHandlerFixture(t)
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	body := strings.NewReader(`{not json}`)
	resp := doReq(t, mustReq(t, http.MethodPost, f.srv.URL+"/api/admin/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminGrantBadRole(t *testing.T) {
	f := newHandlerFixture(t)
	uid := f.mustUser(t, "alice")
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	body := strings.NewReader(`{"userId":"` + uid + `","groupId":null,"role":"king"}`)
	resp := doReq(t, mustReq(t, http.MethodPost, f.srv.URL+"/api/admin/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminGrantMissingUserId(t *testing.T) {
	f := newHandlerFixture(t)
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	body := strings.NewReader(`{"role":"auditor"}`)
	resp := doReq(t, mustReq(t, http.MethodPost, f.srv.URL+"/api/admin/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminRevokeGlobal(t *testing.T) {
	f := newHandlerFixture(t)
	uid := f.mustUser(t, "alice")
	_ = f.store.Grant(Assignment{UserID: uid, Role: RoleAuditor})
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	body := strings.NewReader(`{"userId":"` + uid + `","groupId":null,"role":"auditor"}`)
	resp := doReq(t, mustReq(t, http.MethodDelete, f.srv.URL+"/api/admin/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
}

func TestAdminRevokeNonAdminForbidden(t *testing.T) {
	f := newHandlerFixture(t)
	uid := f.mustUser(t, "alice")
	f.setScope(NewScope("op", []Assignment{{UserID: "op", Role: RoleOperator}}))
	body := strings.NewReader(`{"userId":"` + uid + `","groupId":null,"role":"auditor"}`)
	resp := doReq(t, mustReq(t, http.MethodDelete, f.srv.URL+"/api/admin/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAdminRevokeMissingAssignment(t *testing.T) {
	f := newHandlerFixture(t)
	uid := f.mustUser(t, "alice")
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	body := strings.NewReader(`{"userId":"` + uid + `","groupId":null,"role":"auditor"}`)
	resp := doReq(t, mustReq(t, http.MethodDelete, f.srv.URL+"/api/admin/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAdminRevokeBadJSON(t *testing.T) {
	f := newHandlerFixture(t)
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	body := strings.NewReader(`{nope}`)
	resp := doReq(t, mustReq(t, http.MethodDelete, f.srv.URL+"/api/admin/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminRevokeBadRole(t *testing.T) {
	f := newHandlerFixture(t)
	uid := f.mustUser(t, "alice")
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	body := strings.NewReader(`{"userId":"` + uid + `","groupId":null,"role":"king"}`)
	resp := doReq(t, mustReq(t, http.MethodDelete, f.srv.URL+"/api/admin/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminRevokeMissingUserId(t *testing.T) {
	f := newHandlerFixture(t)
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	body := strings.NewReader(`{"role":"auditor"}`)
	resp := doReq(t, mustReq(t, http.MethodDelete, f.srv.URL+"/api/admin/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminRevokeEmptyGroupID(t *testing.T) {
	f := newHandlerFixture(t)
	uid := f.mustUser(t, "alice")
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	body := strings.NewReader(`{"userId":"` + uid + `","groupId":"","role":"auditor"}`)
	resp := doReq(t, mustReq(t, http.MethodDelete, f.srv.URL+"/api/admin/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestMyScopeReturnsGlobalAndGroups(t *testing.T) {
	f := newHandlerFixture(t)
	g := f.mustGroup(t, "prod")
	other := f.mustGroup(t, "staging")
	f.setScope(NewScope("caller", []Assignment{
		{UserID: "caller", Role: RoleOperator},
		{UserID: "caller", GroupID: &g.ID, Role: RoleAdmin},
		{UserID: "caller", GroupID: &other.ID, Role: RoleAuditor},
	}))
	resp := doReq(t, mustReq(t, http.MethodGet, f.srv.URL+"/api/me/scope", nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var dto scopeDTO
	if err := json.NewDecoder(resp.Body).Decode(&dto); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dto.Global != RoleOperator {
		t.Errorf("global = %q, want operator", dto.Global)
	}
	if dto.Groups[g.ID] != RoleAdmin || dto.Groups[other.ID] != RoleAuditor {
		t.Errorf("groups = %+v", dto.Groups)
	}
}

func TestMyScopeEmptyForUserWithNoRoles(t *testing.T) {
	f := newHandlerFixture(t)
	f.setScope(NewScope("bare", nil))
	resp := doReq(t, mustReq(t, http.MethodGet, f.srv.URL+"/api/me/scope", nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var dto scopeDTO
	if err := json.NewDecoder(resp.Body).Decode(&dto); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dto.Global != "" {
		t.Errorf("global = %q, want \"\"", dto.Global)
	}
	if len(dto.Groups) != 0 {
		t.Errorf("groups = %+v, want empty", dto.Groups)
	}
}

func TestMyScopeMissing500(t *testing.T) {
	f := newHandlerFixture(t)
	f.clearScope()
	resp := doReq(t, mustReq(t, http.MethodGet, f.srv.URL+"/api/me/scope", nil))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandlersRequireScope(t *testing.T) {
	f := newHandlerFixture(t)
	f.clearScope()
	for _, tc := range []struct {
		method, path string
		body         string
	}{
		{http.MethodGet, "/api/groups/x/role-assignments", ""},
		{http.MethodPost, "/api/groups/x/role-assignments", `{}`},
		{http.MethodDelete, "/api/groups/x/role-assignments/u/admin", ""},
		{http.MethodGet, "/api/admin/role-assignments", ""},
		{http.MethodPost, "/api/admin/role-assignments", `{}`},
		{http.MethodDelete, "/api/admin/role-assignments", `{}`},
		{http.MethodGet, "/api/me/scope", ""},
	} {
		var body io.Reader
		if tc.body != "" {
			body = strings.NewReader(tc.body)
		}
		resp := doReq(t, mustReq(t, tc.method, f.srv.URL+tc.path, body))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("%s %s status = %d, want 500", tc.method, tc.path, resp.StatusCode)
		}
	}
}

func TestGrantEmitsAuditRow(t *testing.T) {
	f := newHandlerFixture(t)
	target := f.mustUser(t, "alice")
	g := f.mustGroup(t, "prod")
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	body := strings.NewReader(`{"userId":"` + target + `","role":"operator"}`)
	resp := doReq(t, mustReq(t, http.MethodPost, f.srv.URL+"/api/groups/"+g.ID+"/role-assignments", body))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("grant status = %d", resp.StatusCode)
	}
	recs, _, err := f.audit.ListQuery(audit.Query{Action: "role.grant"})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(recs))
	}
	rec := recs[0]
	if rec.TargetKind != "user" || rec.TargetID != target {
		t.Errorf("audit row target = %s/%s, want user/%s", rec.TargetKind, rec.TargetID, target)
	}
	if rec.TargetLabel != "alice" {
		t.Errorf("audit target label = %q, want alice", rec.TargetLabel)
	}
	if rec.Detail["role"] != "operator" {
		t.Errorf("audit detail role = %v, want operator", rec.Detail["role"])
	}
	if rec.Detail["group_id"] != g.ID {
		t.Errorf("audit detail group_id = %v, want %s", rec.Detail["group_id"], g.ID)
	}
}

func TestRevokeEmitsAuditRow(t *testing.T) {
	f := newHandlerFixture(t)
	target := f.mustUser(t, "alice")
	g := f.mustGroup(t, "prod")
	gid := g.ID
	_ = f.store.Grant(Assignment{UserID: target, GroupID: &gid, Role: RoleOperator})
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	url := f.srv.URL + "/api/groups/" + g.ID + "/role-assignments/" + target + "/operator"
	resp := doReq(t, mustReq(t, http.MethodDelete, url, nil))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke status = %d", resp.StatusCode)
	}
	recs, _, err := f.audit.ListQuery(audit.Query{Action: "role.revoke"})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(recs))
	}
	if recs[0].Detail["role"] != "operator" {
		t.Errorf("audit detail role = %v, want operator", recs[0].Detail["role"])
	}
}

// TestHandlerDBErrorsReturn500 closes the underlying DB after seeding,
// then asserts every endpoint surfaces a 500 instead of panicking or
// silently dropping the request. Covers the "store call failed mid-
// handler" branches that are otherwise hard to exercise.
func TestHandlerDBErrorsReturn500(t *testing.T) {
	f := newHandlerFixture(t)
	uid := f.mustUser(t, "alice")
	g := f.mustGroup(t, "prod")
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	if err := f.db.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}
	cases := []struct {
		name, method, path string
		body               string
	}{
		{"listGroup", http.MethodGet, "/api/groups/" + g.ID + "/role-assignments", ""},
		{"grantGroup", http.MethodPost, "/api/groups/" + g.ID + "/role-assignments", `{"userId":"` + uid + `","role":"operator"}`},
		{"revokeGroup", http.MethodDelete, "/api/groups/" + g.ID + "/role-assignments/" + uid + "/operator", ""},
		{"listAdmin", http.MethodGet, "/api/admin/role-assignments", ""},
		{"grantAdmin", http.MethodPost, "/api/admin/role-assignments", `{"userId":"` + uid + `","groupId":null,"role":"operator"}`},
		{"revokeAdmin", http.MethodDelete, "/api/admin/role-assignments", `{"userId":"` + uid + `","groupId":null,"role":"operator"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			resp := doReq(t, mustReq(t, tc.method, f.srv.URL+tc.path, body))
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusInternalServerError {
				t.Errorf("status = %d, want 500", resp.StatusCode)
			}
		})
	}
}

func TestRegisterAcceptsNilMiddleware(t *testing.T) {
	mux := http.NewServeMux()
	(&Handler{}).Register(mux, nil)
	// Hitting the mux without a scope on context exercises the "no mw,
	// no scope" path; we just want to confirm Register didn't panic.
	req := httptest.NewRequest(http.MethodGet, "/api/admin/role-assignments", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (missing scope)", w.Code)
	}
}

func TestAdminGrantOnSpecificGroup(t *testing.T) {
	f := newHandlerFixture(t)
	uid := f.mustUser(t, "alice")
	g := f.mustGroup(t, "prod")
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	body := strings.NewReader(`{"userId":"` + uid + `","groupId":"` + g.ID + `","role":"operator"}`)
	resp := doReq(t, mustReq(t, http.MethodPost, f.srv.URL+"/api/admin/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, raw)
	}
	var dto roleAssignmentDTO
	if err := json.NewDecoder(resp.Body).Decode(&dto); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dto.GroupID == nil || *dto.GroupID != g.ID || dto.GroupName != "prod" {
		t.Errorf("dto = %+v, want groupId=%s name=prod", dto, g.ID)
	}
}

func TestAdminGrantDuplicate(t *testing.T) {
	f := newHandlerFixture(t)
	uid := f.mustUser(t, "alice")
	_ = f.store.Grant(Assignment{UserID: uid, Role: RoleOperator})
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	body := strings.NewReader(`{"userId":"` + uid + `","groupId":null,"role":"operator"}`)
	resp := doReq(t, mustReq(t, http.MethodPost, f.srv.URL+"/api/admin/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
}

func TestAdminListCachesGroupNames(t *testing.T) {
	f := newHandlerFixture(t)
	uid1 := f.mustUser(t, "alice")
	uid2 := f.mustUser(t, "bob")
	g := f.mustGroup(t, "prod")
	gid := g.ID
	_ = f.store.Grant(Assignment{UserID: uid1, GroupID: &gid, Role: RoleAdmin})
	_ = f.store.Grant(Assignment{UserID: uid2, GroupID: &gid, Role: RoleAuditor})

	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	resp := doReq(t, mustReq(t, http.MethodGet, f.srv.URL+"/api/admin/role-assignments", nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body struct {
		Assignments []roleAssignmentDTO `json:"assignments"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	seen := 0
	for _, a := range body.Assignments {
		if a.GroupID != nil && *a.GroupID == g.ID {
			if a.GroupName != "prod" {
				t.Errorf("group name = %q, want prod", a.GroupName)
			}
			seen++
		}
	}
	if seen != 2 {
		t.Errorf("group rows seen = %d, want 2 (cache reuse)", seen)
	}
}

func TestAdminGrantGlobalEmitsAuditWithNullGroup(t *testing.T) {
	f := newHandlerFixture(t)
	uid := f.mustUser(t, "alice")
	f.setScope(NewScope("admin", []Assignment{{UserID: "admin", Role: RoleAdmin}}))
	body := strings.NewReader(`{"userId":"` + uid + `","groupId":null,"role":"operator"}`)
	resp := doReq(t, mustReq(t, http.MethodPost, f.srv.URL+"/api/admin/role-assignments", body))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	recs, _, _ := f.audit.ListQuery(audit.Query{Action: "role.grant"})
	if len(recs) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(recs))
	}
	// JSON null lands as nil interface; SetSafe stored it.
	if v, present := recs[0].Detail["group_id"]; !present || v != nil {
		t.Errorf("audit detail group_id = %v (present=%v), want explicit nil", v, present)
	}
}

func TestAdminRevokeLastGlobalAdminReturns409(t *testing.T) {
	f := newHandlerFixture(t)
	uid := f.mustUser(t, "alice")
	if err := f.store.Grant(Assignment{UserID: uid, Role: RoleAdmin}); err != nil {
		t.Fatalf("seed global admin: %v", err)
	}
	f.setScope(NewScope(uid, []Assignment{{UserID: uid, Role: RoleAdmin}}))
	body := strings.NewReader(`{"userId":"` + uid + `","groupId":null,"role":"admin"}`)
	resp := doReq(t, mustReq(t, http.MethodDelete, f.srv.URL+"/api/admin/role-assignments", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
	rows, _ := f.store.Resolve(uid)
	if len(rows) != 1 || rows[0].Role != RoleAdmin {
		t.Errorf("alice lost her global admin row despite 409: %+v", rows)
	}
}

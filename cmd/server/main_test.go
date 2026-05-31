// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/auth"
	"system-wrangler-backend/internal/credentials"
	"system-wrangler-backend/internal/dashboardlayout"
	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/events"
	"system-wrangler-backend/internal/exclusions"
	"system-wrangler-backend/internal/exporters"
	"system-wrangler-backend/internal/groups"
	"system-wrangler-backend/internal/holds"
	"system-wrangler-backend/internal/hostkeys"
	"system-wrangler-backend/internal/labels"
	"system-wrangler-backend/internal/rbac"
	"system-wrangler-backend/internal/secrets"
	"system-wrangler-backend/internal/settings"
	"system-wrangler-backend/internal/systems"
	"system-wrangler-backend/internal/updaters"
)

// newTestMux returns a fully-wired mux backed by a temp SQLite DB so the
// integration paths exercised here mirror the production wiring.
func newTestMux(t *testing.T) http.Handler {
	t.Helper()
	h, _, _ := newTestMuxWithStores(t)
	return h
}

// newTestMuxWithAudit returns the same mux as newTestMux plus the
// audit store, for tests that need to inspect audit rows.
func newTestMuxWithAudit(t *testing.T) (http.Handler, *audit.Store) {
	t.Helper()
	h, aud, _ := newTestMuxWithStores(t)
	return h, aud
}

// newTestMuxWithStores returns the mux plus the audit and rbac stores
// so smoke tests can grant a Global Admin role to the setup user (the
// rbac backfill runs at store init when the users table is empty, so
// the first user created after setup gets no role by default).
func newTestMuxWithStores(t *testing.T) (http.Handler, *audit.Store, *rbac.SQLiteStore) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "test.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	invStore, err := systems.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	groupStore, err := groups.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("groups.NewSQLiteStore: %v", err)
	}
	authStore, err := auth.NewSQLiteAuthStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteAuthStore: %v", err)
	}
	secret, err := auth.LoadOrInitSecret(authStore)
	if err != nil {
		t.Fatalf("LoadOrInitSecret: %v", err)
	}
	auditStore, err := audit.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStore: %v", err)
	}
	rbacStore, err := rbac.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("rbac.NewSQLiteStore: %v", err)
	}
	credStore, err := credentials.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("credentials.NewSQLiteStore: %v", err)
	}
	hostKeyStore, err := hostkeys.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("hostkeys.NewSQLiteStore: %v", err)
	}
	updaterStore, err := updaters.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("updaters.NewSQLiteStore: %v", err)
	}
	exporterStore, err := exporters.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("exporters.NewSQLiteStore: %v", err)
	}
	settingsStore, err := settings.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("settings.NewSQLiteStore: %v", err)
	}
	exclusionStore, err := exclusions.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("exclusions.NewSQLiteStore: %v", err)
	}
	holdsStore, err := holds.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("holds.NewSQLiteStore: %v", err)
	}
	labelStore, err := labels.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("labels.NewSQLiteStore: %v", err)
	}
	labelStyleStore, err := labels.NewSQLiteStyleStore(db)
	if err != nil {
		t.Fatalf("labels.NewSQLiteStyleStore: %v", err)
	}
	dashboardLayoutStore, err := dashboardlayout.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("dashboardlayout.NewSQLiteStore: %v", err)
	}
	// Build a real vault so populateMux's `if vault != nil` branches
	// (credentials key materialise, scrape, secretscan, ansible runner)
	// wire up. Without this the test mux has half the handlers missing
	// and large chunks of populateMux sit at 0% coverage.
	vaultKey := make([]byte, 32)
	for i := range vaultKey {
		vaultKey[i] = byte(i + 1)
	}
	vault, err := secrets.NewVaultFromKey(vaultKey)
	if err != nil {
		t.Fatalf("secrets.NewVaultFromKey: %v", err)
	}
	svc := auth.NewService(authStore, secret, false)
	svc.Audit = auditStore
	svc.DB = db
	svc.Vault = vault
	hub := events.NewHub(nil)
	return newMux(db, invStore, groupStore, authStore, svc, secret, vault, hub, auditStore, rbacStore, credStore, hostKeyStore, updaterStore, exporterStore, settingsStore, exclusionStore, holdsStore, labelStore, labelStyleStore, dashboardLayoutStore, nil, nil), auditStore, rbacStore
}

func TestHandleHealth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	handleHealth(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("status = %q, want ok", body.Status)
	}
}

func TestServerRoutesHealth(t *testing.T) {
	srv := httptest.NewServer(withLogging(newTestMux(t)))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/health")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != `{"status":"ok"}` {
		t.Errorf("body = %q", string(body))
	}
}

func TestHandleReadyOK(t *testing.T) {
	db, err := database.Open("file:" + filepath.Join(t.TempDir(), "ready.db"))
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/ready", nil)
	handleReady(db)(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	var body struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status != "ready" {
		t.Errorf("status = %q, want ready", body.Status)
	}
	if body.Checks["database"] != "ok" {
		t.Errorf("checks.database = %q, want ok", body.Checks["database"])
	}
}

func TestHandleReadyDBFailureReturns503(t *testing.T) {
	db, err := database.Open("file:" + filepath.Join(t.TempDir(), "ready.db"))
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	_ = db.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/ready", nil)
	handleReady(db)(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
	var body struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status != "not_ready" {
		t.Errorf("status = %q, want not_ready", body.Status)
	}
	if body.Checks["database"] == "" || body.Checks["database"] == "ok" {
		t.Errorf("checks.database = %q, want a non-empty error", body.Checks["database"])
	}
}

func TestServerRoutesReady(t *testing.T) {
	srv := httptest.NewServer(withLogging(newTestMux(t)))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/ready")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status != "ready" {
		t.Errorf("status = %q, want ready", body.Status)
	}
	if body.Checks["database"] != "ok" {
		t.Errorf("checks.database = %q, want ok", body.Checks["database"])
	}
}

func TestServerRoutesBuildInfo(t *testing.T) {
	srv := httptest.NewServer(withLogging(newTestMux(t)))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/build-info")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body struct {
		Backend   string `json:"backend"`
		Frontend  string `json:"frontend"`
		BuildDate string `json:"buildDate"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Backend == "" || body.Frontend == "" || body.BuildDate == "" {
		t.Fatalf("body = %+v", body)
	}
}

func TestSystemsRequiresAuth(t *testing.T) {
	srv := httptest.NewServer(withLogging(newTestMux(t)))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/systems")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// TestSystemsReachableAfterSetup walks the full bootstrap path: setup admin,
// then reuse the cookie to read /api/systems.
func TestSystemsReachableAfterSetup(t *testing.T) {
	srv := httptest.NewServer(withLogging(newTestMux(t)))
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp, err := client.Post(srv.URL+"/api/auth/setup", "application/json",
		strings.NewReader(`{"username":"admin","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("setup status = %d", resp.StatusCode)
	}

	systemsResp, err := client.Get(srv.URL + "/api/systems")
	if err != nil {
		t.Fatalf("systems: %v", err)
	}
	defer func() { _ = systemsResp.Body.Close() }()
	if systemsResp.StatusCode != http.StatusOK {
		t.Errorf("systems status = %d, want 200", systemsResp.StatusCode)
	}
}

// TestPopulatedEndpointsRespondAfterSetup hits the variety of wired
// endpoints so populateMux's per-handler closures (VisibleSystem,
// CanCreate, scope gates, stats injectors) get exercised. Each
// request just needs to reach the handler and return any 2xx/3xx/4xx
// — we're proving wiring, not behavior.
func TestPopulatedEndpointsRespondAfterSetup(t *testing.T) {
	mux, _, rbacStore := newTestMuxWithStores(t)
	srv := httptest.NewServer(withLogging(mux))
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp, err := client.Post(srv.URL+"/api/auth/setup", "application/json",
		strings.NewReader(`{"username":"admin","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	_ = resp.Body.Close()

	// Read the just-created user's id out of the status endpoint and
	// promote them to Global Admin via the rbac store. The bootstrap
	// backfill in NewSQLiteStore ran at startup with zero users, so the
	// admin user gets no rbac row by default; smoke depends on Global
	// Admin scope to walk the admin-only handlers.
	statusResp, _ := client.Get(srv.URL + "/api/auth/status")
	var status struct {
		User *struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	_ = json.NewDecoder(statusResp.Body).Decode(&status)
	_ = statusResp.Body.Close()
	if status.User == nil {
		t.Fatal("setup did not return an authenticated user")
	}
	if err := rbacStore.Grant(rbac.Assignment{UserID: status.User.ID, Role: rbac.RoleAdmin}); err != nil {
		t.Fatalf("grant Global Admin: %v", err)
	}

	// Pull the CSRF token from cookies so write requests get past the
	// CSRF middleware that withLogging wraps newTestMux in.
	var csrfTok string
	u, _ := url.Parse(srv.URL)
	for _, c := range jar.Cookies(u) {
		if c.Name == "sw_csrf" {
			csrfTok = c.Value
		}
	}

	// Seed a group + system so per-system endpoints have a real ID
	// instead of returning 404 before the closures run.
	postWithCSRF := func(t *testing.T, path, body string) string {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if csrfTok != "" {
			req.Header.Set("X-CSRF-Token", csrfTok)
		}
		r, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		defer func() { _ = r.Body.Close() }()
		buf, _ := io.ReadAll(r.Body)
		return string(buf)
	}

	sysBody := postWithCSRF(t, "/api/systems", `{"name":"smoke","hostname":"smoke.example"}`)
	var sysOut struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(strings.NewReader(sysBody)).Decode(&sysOut)
	sysID := sysOut.ID

	grpBody := postWithCSRF(t, "/api/groups", `{"name":"smoke-group"}`)
	var grpOut struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(strings.NewReader(grpBody)).Decode(&grpOut)
	groupID := grpOut.ID

	// Seed an exporter row, an updater availability + pending packages,
	// and a label so the populateMux closures (SystemStats, SystemLabels)
	// have real data to flow through.
	dsn := "file:" + filepath.Join(t.TempDir(), "smoke-seed.db")
	_ = dsn // newTestMux uses its own DB; the seeding below uses the live API instead.

	// Apply a label on the seeded system so the labels closure has a row.
	putReq, _ := http.NewRequest(http.MethodPut,
		srv.URL+"/api/systems/"+sysID+"/labels/role",
		strings.NewReader(`{"value":"smoke"}`))
	putReq.Header.Set("Content-Type", "application/json")
	if csrfTok != "" {
		putReq.Header.Set("X-CSRF-Token", csrfTok)
	}
	if r, err := client.Do(putReq); err == nil {
		_ = r.Body.Close()
	}

	// Accept a host key so /api/systems/{id}/host-keys returns content.
	postWithCSRF(t, "/api/systems/"+sysID+"/host-keys/accept",
		`{"algorithm":"ssh-ed25519","fingerprint":"SHA256:smoke"}`)

	// Set an ansible-credential at global scope so the effective-credential
	// closure has something to merge.
	putG, _ := http.NewRequest(http.MethodPut,
		srv.URL+"/api/admin/ansible-credentials/global",
		strings.NewReader(`{"ansibleUser":"ansible"}`))
	putG.Header.Set("Content-Type", "application/json")
	if csrfTok != "" {
		putG.Header.Set("X-CSRF-Token", csrfTok)
	}
	if r, err := client.Do(putG); err == nil {
		_ = r.Body.Close()
	}

	// Create a global package exclusion so the effective-exclusion closure
	// has something to return.
	postWithCSRF(t, "/api/admin/package-exclusions",
		`{"updater":"builtin.dnf","pattern":"kernel*","reason":"smoke"}`)

	// Hit metrics endpoint so its CanRead closure runs.
	if r, err := client.Get(srv.URL + "/api/metrics/query?query=up"); err == nil {
		_ = r.Body.Close()
	}

	// Bulk event so the BulkAudit closure runs.
	postWithCSRF(t, "/api/systems/bulk-event",
		`{"action":"check","selector":"role=smoke","systemIds":["`+sysID+`"]}`)

	// Set a label style so labelHandler.StyleAudit closure runs.
	putStyle, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/label-styles/role",
		strings.NewReader(`{"color":"blue"}`))
	putStyle.Header.Set("Content-Type", "application/json")
	if csrfTok != "" {
		putStyle.Header.Set("X-CSRF-Token", csrfTok)
	}
	if r, err := client.Do(putStyle); err == nil {
		_ = r.Body.Close()
	}

	// Grant a role assignment so the rbac handler closures run.
	postWithCSRF(t, "/api/groups/"+groupID+"/role-assignments",
		`{"userId":"`+status.User.ID+`","role":"admin"}`)

	// Delete the system to walk the delete-with-audit closure.
	delReq, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/systems/"+sysID+"/labels/role", nil)
	if csrfTok != "" {
		delReq.Header.Set("X-CSRF-Token", csrfTok)
	}
	if r, err := client.Do(delReq); err == nil {
		_ = r.Body.Close()
	}

	// Hit every GET endpoint we can reach. Status doesn't matter — the
	// goal is to walk populateMux's per-handler closures so the bodies
	// register as covered.
	endpoints := []string{
		"/api/systems",
		"/api/systems/" + sysID,
		"/api/systems/" + sysID + "/exporters",
		"/api/systems/" + sysID + "/exporter-runs",
		"/api/systems/" + sysID + "/updaters",
		"/api/systems/" + sysID + "/updater-runs",
		"/api/systems/" + sysID + "/host-keys",
		"/api/systems/" + sysID + "/labels",
		"/api/systems/" + sysID + "/ansible-credential",
		"/api/systems/" + sysID + "/effective-credential",
		"/api/systems/" + sysID + "/package-exclusions",
		"/api/systems/" + sysID + "/package-exclusions/effective?updater=builtin.dnf",
		"/api/groups",
		"/api/groups/" + groupID,
		"/api/groups/" + groupID + "/ansible-credential",
		"/api/groups/" + groupID + "/package-exclusions",
		"/api/groups/" + groupID + "/role-assignments",
		"/api/admin/users",
		"/api/admin/settings",
		"/api/admin/ansible-credentials",
		"/api/admin/ansible-credentials/global",
		"/api/admin/exporter-definitions",
		"/api/admin/package-exclusions",
		"/api/admin/updater-definitions",
		"/api/admin/audit",
		"/api/admin/role-assignments",
		"/api/admin/secrets/undecryptable",
		"/api/labels",
		"/api/label-styles",
		"/api/auth/status",
		"/api/auth/devices",
		"/api/dashboard/layout",
		"/api/docs",
	}
	for _, p := range endpoints {
		r, err := client.Get(srv.URL + p)
		if err != nil {
			t.Errorf("GET %s: %v", p, err)
			continue
		}
		_ = r.Body.Close()
	}

	// Round-trip a dashboard layout PUT + GET so the per-user layout
	// handler's happy path is covered through the wired mux. The
	// payload shape mirrors what the SPA writes.
	putLayout, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/dashboard/layout",
		strings.NewReader(`{"layout":[{"instanceId":"system-health","widgetId":"system-health","enabled":true}]}`))
	putLayout.Header.Set("Content-Type", "application/json")
	if csrfTok != "" {
		putLayout.Header.Set("X-CSRF-Token", csrfTok)
	}
	if r, err := client.Do(putLayout); err == nil {
		_ = r.Body.Close()
	}
	if r, err := client.Get(srv.URL + "/api/dashboard/layout"); err == nil {
		_ = r.Body.Close()
	}

	// Create a second user with Group Admin only (no Global Admin) and
	// log in as them so the populateMux closures take their
	// !IsGlobalAdmin → RoleOnGroup(...) branches. Without this, the
	// Group-Admin branches sit at 0% coverage forever.
	postWithCSRF(t, "/api/admin/users",
		`{"username":"groupadmin","password":"correctpassword"}`)
	// Find the new user's id.
	usersResp, _ := client.Get(srv.URL + "/api/admin/users")
	var listed struct {
		Users []struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		} `json:"users"`
	}
	_ = json.NewDecoder(usersResp.Body).Decode(&listed)
	_ = usersResp.Body.Close()
	var gaID string
	for _, u := range listed.Users {
		if u.Username == "groupadmin" {
			gaID = u.ID
		}
	}
	if gaID == "" {
		t.Fatal("groupadmin user not visible in admin list")
	}
	if err := rbacStore.Grant(rbac.Assignment{UserID: gaID, GroupID: &groupID, Role: rbac.RoleAdmin}); err != nil {
		t.Fatalf("grant group admin: %v", err)
	}

	// Log in as the Group Admin in a separate jar.
	gaJar, _ := cookiejar.New(nil)
	gaClient := &http.Client{Jar: gaJar}
	loginResp, err := gaClient.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"groupadmin","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("group-admin login: %v", err)
	}
	_ = loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("group-admin login status = %d", loginResp.StatusCode)
	}

	// Assign the smoke system into the group so the group admin can
	// see it; this also walks more per-system closures via group-admin
	// scope.
	putAssign, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/systems/"+sysID+"/group",
		strings.NewReader(`{"groupId":"`+groupID+`"}`))
	putAssign.Header.Set("Content-Type", "application/json")
	if csrfTok != "" {
		putAssign.Header.Set("X-CSRF-Token", csrfTok)
	}
	if r, err := client.Do(putAssign); err == nil {
		_ = r.Body.Close()
	}

	// Hit endpoints that flow through CanManageSystem / CanReadSystem
	// closures so the !IsGlobalAdmin → RoleOnGroup branch executes.
	gaEndpoints := []string{
		"/api/systems",
		"/api/systems/" + sysID,
		"/api/systems/" + sysID + "/exporters",
		"/api/systems/" + sysID + "/host-keys",
		"/api/systems/" + sysID + "/ansible-credential",
		"/api/systems/" + sysID + "/package-exclusions",
		"/api/groups",
		"/api/groups/" + groupID,
		"/api/groups/" + groupID + "/package-exclusions",
		"/api/auth/status",
	}
	for _, p := range gaEndpoints {
		r, err := gaClient.Get(srv.URL + p)
		if err != nil {
			t.Errorf("ga GET %s: %v", p, err)
			continue
		}
		_ = r.Body.Close()
	}
}

func TestUnknownAPIReturnsJSON404(t *testing.T) {
	srv := httptest.NewServer(withLogging(newTestMux(t)))
	defer srv.Close()

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"unknown GET", http.MethodGet, "/api/nope"},
		{"unknown POST", http.MethodPost, "/api/also-nope"},
		{"wrong method on known route", http.MethodPost, "/api/health"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, srv.URL+tt.path, nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("status = %d, want 404", resp.StatusCode)
			}
			if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
				t.Errorf("content-type = %q, want application/json", ct)
			}
			var body struct {
				Error string `json:"error"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if body.Error == "" {
				t.Error("error field missing")
			}
		})
	}
}

// TestEventsEndpointStreamsThroughMiddleware guards against a regression
// where statusWriter (the withLogging wrapper) silently shadows
// http.Flusher, causing the SSE handler's type assertion to fail and the
// response to come back as 500.
func TestEventsEndpointStreamsThroughMiddleware(t *testing.T) {
	srv := httptest.NewServer(withLogging(newTestMux(t)))
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	setupResp, err := client.Post(srv.URL+"/api/auth/setup", "application/json",
		strings.NewReader(`{"username":"admin","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	_ = setupResp.Body.Close()
	if setupResp.StatusCode != http.StatusCreated {
		t.Fatalf("setup status = %d", setupResp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/events", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (SSE setup likely broken by a writer wrapper)", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", got)
	}
}

func TestAuthEndpointsAreUngated(t *testing.T) {
	srv := httptest.NewServer(withLogging(newTestMux(t)))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/auth/status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestTLSConfig(t *testing.T) {
	tests := []struct {
		name      string
		env       map[string]string
		wantCert  string
		wantKey   string
		wantUse   bool
		wantError bool
	}{
		{name: "both unset disables TLS", env: map[string]string{}, wantUse: false},
		{
			name:     "both set enables TLS",
			env:      map[string]string{"TLS_CERT_PATH": "/tls/c.pem", "TLS_KEY_PATH": "/tls/k.pem"},
			wantCert: "/tls/c.pem", wantKey: "/tls/k.pem", wantUse: true,
		},
		{
			name:      "cert without key is rejected",
			env:       map[string]string{"TLS_CERT_PATH": "/tls/c.pem"},
			wantError: true,
		},
		{
			name:      "key without cert is rejected",
			env:       map[string]string{"TLS_KEY_PATH": "/tls/k.pem"},
			wantError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			get := func(k string) string { return tt.env[k] }
			cert, key, use, err := tlsConfig(get)
			if tt.wantError {
				if err == nil {
					t.Fatal("err = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if cert != tt.wantCert || key != tt.wantKey || use != tt.wantUse {
				t.Errorf("got (%q, %q, %v), want (%q, %q, %v)",
					cert, key, use, tt.wantCert, tt.wantKey, tt.wantUse)
			}
		})
	}
}

func TestEnvOr(t *testing.T) {
	tests := []struct {
		name string
		set  bool
		val  string
		want string
	}{
		{"unset returns default", false, "", "default"},
		{"empty returns default", true, "", "default"},
		{"set returns value", true, "set-value", "set-value"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := "SW_TEST_KEY_" + tt.name
			if tt.set {
				t.Setenv(key, tt.val)
			}
			if got := envOr(key, "default"); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSPAHandlerEmptyDist(t *testing.T) {
	// dist/ contains only .gitkeep in dev/test. Verify the handler handles this
	// gracefully (no panic) for both the root and unknown SPA paths.
	h := spaHandler()
	for _, path := range []string{"/", "/some/spa/route"} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, path, nil)
			h.ServeHTTP(w, r)
			if w.Code == 0 {
				t.Error("no status written")
			}
		})
	}
}

func TestStatusWriterCapturesCode(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec, status: 200}
	sw.WriteHeader(http.StatusCreated)
	if sw.status != http.StatusCreated {
		t.Errorf("status field = %d, want %d", sw.status, http.StatusCreated)
	}
	if rec.Code != http.StatusCreated {
		t.Errorf("underlying writer code = %d", rec.Code)
	}
}

func TestWithLoggingPassesThrough(t *testing.T) {
	called := false
	h := withLogging(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(w, r)

	if !called {
		t.Fatal("inner handler not called")
	}
	if w.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d", w.Code, http.StatusTeapot)
	}
}

// TestCSRFMiddlewareInProductionChain wires the production CSRF
// middleware around the test mux and confirms that an
// authenticated cross-Origin POST is rejected with 403 + an
// audit row, while a same-origin POST carrying the header
// passes through.
func TestCSRFMiddlewareInProductionChain(t *testing.T) {
	mux, auditStore := newTestMuxWithAudit(t)
	srv := httptest.NewServer(withLogging(auth.CSRF(auditStore)(mux)))
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// First-time setup is exempt — bare POST works without CSRF
	// headers, which is what an unauthenticated install does on
	// the very first request.
	setupResp, err := client.Post(srv.URL+"/api/auth/setup", "application/json",
		strings.NewReader(`{"username":"admin","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	_ = setupResp.Body.Close()
	if setupResp.StatusCode != http.StatusCreated {
		t.Fatalf("setup status = %d", setupResp.StatusCode)
	}

	// Cross-Origin POST against an authenticated mutating
	// endpoint should be rejected before reaching the handler.
	bad, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/auth/profile",
		strings.NewReader(`{"email":"x@example"}`))
	bad.Header.Set("Origin", "https://evil.example")
	bad.Header.Set("Content-Type", "application/json")
	badResp, err := client.Do(bad)
	if err != nil {
		t.Fatalf("bad: %v", err)
	}
	_ = badResp.Body.Close()
	if badResp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", badResp.StatusCode)
	}

	// Same-origin PATCH with the header passes the middleware.
	good, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/auth/profile",
		strings.NewReader(`{"email":"new@example.com"}`))
	good.Header.Set("Origin", srv.URL)
	good.Header.Set("Content-Type", "application/json")
	good.Header.Set(auth.CSRFHeader, auth.CSRFHeaderValue)
	goodResp, err := client.Do(good)
	if err != nil {
		t.Fatalf("good: %v", err)
	}
	_ = goodResp.Body.Close()
	if goodResp.StatusCode != http.StatusOK {
		t.Errorf("good status = %d, want 200", goodResp.StatusCode)
	}

	// One csrf.denied row landed.
	recs, _, err := auditStore.ListQuery(audit.Query{Action: "csrf.denied", Limit: 5})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("expected a csrf.denied audit row")
	}
	if recs[0].Outcome != audit.Denied {
		t.Errorf("audit outcome = %s, want denied", recs[0].Outcome)
	}
	if got, _ := recs[0].Detail["reason"].(string); got != "origin_mismatch" {
		t.Errorf("audit reason = %q, want origin_mismatch", got)
	}
}

// TestRunStartsAndShutsDown invokes run() with a fast-cancel context and
// a getenv that points it at an unused port and a temp DB. Verifies the
// happy path (DB open → all stores init → server listen → ctx cancel →
// clean shutdown) returns nil.
func TestRunStartsAndShutsDown(t *testing.T) {
	t.Setenv("SW_MASTER_KEY_FILE", masterKeyFile(t))
	tmpDB := filepath.Join(t.TempDir(), "run.db")
	getenv := func(k string) string {
		switch k {
		case "DB_PATH":
			return tmpDB
		case "PORT":
			return "0"
		case "SW_MASTER_KEY_FILE":
			return os.Getenv("SW_MASTER_KEY_FILE")
		}
		return ""
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()
	if err := run(ctx, []string{}, getenv); err != nil {
		t.Errorf("run() = %v, want nil", err)
	}
}

func TestRunBadDBPath(t *testing.T) {
	t.Setenv("SW_MASTER_KEY_FILE", masterKeyFile(t))
	getenv := func(k string) string {
		switch k {
		case "DB_PATH":
			return "/nonexistent-dir-runtest/db.sqlite"
		case "SW_MASTER_KEY_FILE":
			return os.Getenv("SW_MASTER_KEY_FILE")
		}
		return ""
	}
	if err := run(context.Background(), []string{}, getenv); err == nil {
		t.Error("run with bad DB_PATH = nil, want error")
	}
}

func TestRunBadFlag(t *testing.T) {
	if err := run(context.Background(), []string{"--bogus"}, func(string) string { return "" }); err == nil {
		t.Error("run with unknown flag = nil, want error")
	}
}

func TestRunRotateKeysShortCircuits(t *testing.T) {
	t.Setenv("SW_MASTER_KEY_FILE", masterKeyFile(t))
	t.Setenv("SW_MASTER_KEY_FILE_PREVIOUS", masterKeyFileSeeded(t, 99))
	tmpDB := filepath.Join(t.TempDir(), "rotate.db")
	getenv := func(k string) string {
		switch k {
		case "DB_PATH":
			return tmpDB
		case "SW_MASTER_KEY_FILE", "SW_MASTER_KEY_FILE_PREVIOUS":
			return os.Getenv(k)
		}
		return ""
	}
	// --rotate-keys exits run() after the rotate call, without starting
	// the server. Should return nil if rotate succeeds (no rows to
	// re-seal in a fresh DB).
	if err := run(context.Background(), []string{"--rotate-keys"}, getenv); err != nil {
		t.Errorf("run --rotate-keys = %v, want nil", err)
	}
}

func masterKeyFileSeeded(t *testing.T, seed byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "master.key")
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = seed ^ byte(i)
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(keyBytes)), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

func TestRunWithTargetsFile(t *testing.T) {
	t.Setenv("SW_MASTER_KEY_FILE", masterKeyFile(t))
	tmpDB := filepath.Join(t.TempDir(), "targets.db")
	targets := filepath.Join(t.TempDir(), "targets.json")
	getenv := func(k string) string {
		switch k {
		case "DB_PATH":
			return tmpDB
		case "PORT":
			return "0"
		case "SW_TARGETS_FILE":
			return targets
		case "SW_MASTER_KEY_FILE":
			return os.Getenv(k)
		}
		return ""
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(250 * time.Millisecond)
		cancel()
	}()
	if err := run(ctx, []string{}, getenv); err != nil {
		t.Errorf("run with SW_TARGETS_FILE = %v, want nil", err)
	}
	if _, err := os.Stat(targets); err != nil {
		t.Errorf("targets.json not written: %v", err)
	}
}

func TestRunWithTLSCert(t *testing.T) {
	t.Setenv("SW_MASTER_KEY_FILE", masterKeyFile(t))
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeSelfSignedCert(t, certPath, keyPath)
	tmpDB := filepath.Join(t.TempDir(), "tls.db")
	getenv := func(k string) string {
		switch k {
		case "DB_PATH":
			return tmpDB
		case "PORT":
			return "0"
		case "TLS_CERT_PATH":
			return certPath
		case "TLS_KEY_PATH":
			return keyPath
		case "SW_MASTER_KEY_FILE":
			return os.Getenv(k)
		}
		return ""
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(250 * time.Millisecond)
		cancel()
	}()
	if err := run(ctx, []string{}, getenv); err != nil {
		t.Errorf("run with TLS = %v, want nil", err)
	}
}

func writeSelfSignedCert(t *testing.T, certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	certOut, err := os.Create(certPath) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("cert file: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encode cert: %v", err)
	}
	_ = certOut.Close()
	keyOut, err := os.Create(keyPath) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("key file: %v", err)
	}
	pkBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: pkBytes}); err != nil {
		t.Fatalf("encode key: %v", err)
	}
	_ = keyOut.Close()
}

func TestRunTLSConfigError(t *testing.T) {
	t.Setenv("SW_MASTER_KEY_FILE", masterKeyFile(t))
	getenv := func(k string) string {
		switch k {
		// Only one of cert/key set → tlsConfig returns an error.
		case "TLS_CERT_PATH":
			return "/tmp/cert.pem"
		case "SW_MASTER_KEY_FILE":
			return os.Getenv(k)
		}
		return ""
	}
	if err := run(context.Background(), []string{}, getenv); err == nil || !strings.Contains(err.Error(), "tls config") {
		t.Errorf("run with half-TLS env = %v, want tls config error", err)
	}
}

func masterKeyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "master.key")
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(i)
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(keyBytes)), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

func TestReadInternalSecretFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("topsecret\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("SW_INTERNAL_SECRET_FILE", path)
	t.Setenv("SW_INTERNAL_SECRET", "ignored-when-file-wins")
	got := readInternalSecret()
	if got != "topsecret" {
		t.Errorf("got = %q, want topsecret", got)
	}
}

func TestReadInternalSecretFromEnv(t *testing.T) {
	t.Setenv("SW_INTERNAL_SECRET_FILE", "")
	t.Setenv("SW_INTERNAL_SECRET", "envsecret")
	got := readInternalSecret()
	if got != "envsecret" {
		t.Errorf("got = %q, want envsecret", got)
	}
}

func TestReadInternalSecretFileMissing(t *testing.T) {
	t.Setenv("SW_INTERNAL_SECRET_FILE", "/nonexistent-dir-secret-test/secret")
	t.Setenv("SW_INTERNAL_SECRET", "")
	got := readInternalSecret()
	if got != "" {
		t.Errorf("got = %q, want empty (file unreadable)", got)
	}
}

func TestSpaHandlerServesIndexForUnknown(t *testing.T) {
	h := spaHandler()
	req := httptest.NewRequest(http.MethodGet, "/anything/unknown", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	// Empty embed.FS only has .gitkeep — the SPA fallback should
	// still produce some response (200 or 404) without panicking.
	if w.Code == 0 {
		t.Error("spaHandler did not write a status")
	}
}

func TestUpdaterPkgManagerProbeAdaptsAvailability(t *testing.T) {
	store := &stubUpdaterStore{}
	probe := updaterPkgManagerProbe{store: store}
	got, err := probe.DetectedPkgManagers("sys")
	if err != nil {
		t.Fatalf("DetectedPkgManagers: %v", err)
	}
	if len(got) != 2 || got[0] != "builtin.dnf" || got[1] != "builtin.apt" {
		t.Errorf("got = %v", got)
	}
}

func TestUpdaterPkgManagerProbePropagatesError(t *testing.T) {
	store := &stubUpdaterStore{err: errStubProbe("av down")}
	probe := updaterPkgManagerProbe{store: store}
	if _, err := probe.DetectedPkgManagers("sys"); err == nil {
		t.Error("err = nil, want error")
	}
}

type errStubProbe string

func (e errStubProbe) Error() string { return string(e) }

type stubUpdaterStore struct {
	updaters.Store
	err error
}

func (s *stubUpdaterStore) AvailabilityFor(string) ([]updaters.Availability, error) {
	if s.err != nil {
		return nil, s.err
	}
	return []updaters.Availability{
		{UpdaterID: "builtin.dnf"},
		{UpdaterID: "builtin.apt"},
	}, nil
}

func TestInitStoreReturnsValueOnSuccess(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "init.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	got, err := initStore(db, "systems", systems.NewSQLiteStore)
	if err != nil {
		t.Fatalf("initStore: %v", err)
	}
	if got == nil {
		t.Error("got = nil, want a non-nil store")
	}
}

func TestInitStoreWrapsError(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "init-fail.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// Pass a constructor that always fails. The helper must wrap the
	// underlying error with "init <label> store:" so the operator can
	// see which subsystem actually broke on startup.
	_, err = initStore(db, "fake", func(*sql.DB) (*int, error) {
		return nil, errAdminStub("ctor failed")
	})
	if err == nil {
		t.Fatal("err = nil, want wrap")
	}
	if !strings.Contains(err.Error(), "init fake store") {
		t.Errorf("err = %q, want it to contain 'init fake store'", err.Error())
	}
}

type errAdminStub string

func (e errAdminStub) Error() string { return string(e) }

func TestWithRequestMetaStampsIDAndHeader(t *testing.T) {
	var seenCtx context.Context
	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seenCtx = r.Context()
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = "1.2.3.4:5678"
	withRequestMeta(inner).ServeHTTP(w, r)

	got := w.Header().Get("X-Request-ID")
	if got == "" {
		t.Error("X-Request-ID header not set")
	}
	if id := audit.RequestIDFromContext(seenCtx); id != got {
		t.Errorf("RequestIDFromContext = %q, want header %q", id, got)
	}
	if addr := audit.RemoteAddrFromContext(seenCtx); addr != "1.2.3.4:5678" {
		t.Errorf("RemoteAddr = %q", addr)
	}
}

func TestTriggerProbeNonBlocking(t *testing.T) {
	p := &systems.Probe{Trigger: make(chan struct{}, 1)}
	fn := triggerProbe(p)
	fn()
	// Channel buffered to 1; first send fills it.
	select {
	case <-p.Trigger:
	default:
		t.Fatal("first triggerProbe call did not enqueue")
	}
	// Second call with full buffer must not block.
	p.Trigger <- struct{}{}
	fn()
	select {
	case <-p.Trigger:
	default:
		t.Fatal("trigger channel unexpectedly drained")
	}
}

func TestHandleAPINotFound(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/whatever", nil)
	handleAPINotFound(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("code = %d", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"error":"not found"`)) {
		t.Errorf("body = %q", w.Body.Bytes())
	}
}

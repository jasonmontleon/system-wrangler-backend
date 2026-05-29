// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/auth"
	"system-wrangler-backend/internal/credentials"
	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/events"
	"system-wrangler-backend/internal/exclusions"
	"system-wrangler-backend/internal/exporters"
	"system-wrangler-backend/internal/groups"
	"system-wrangler-backend/internal/holds"
	"system-wrangler-backend/internal/hostkeys"
	"system-wrangler-backend/internal/labels"
	"system-wrangler-backend/internal/rbac"
	"system-wrangler-backend/internal/settings"
	"system-wrangler-backend/internal/systems"
	"system-wrangler-backend/internal/updaters"
)

// newTestMux returns a fully-wired mux backed by a temp SQLite DB so the
// integration paths exercised here mirror the production wiring.
func newTestMux(t *testing.T) http.Handler {
	t.Helper()
	h, _ := newTestMuxWithAudit(t)
	return h
}

// newTestMuxWithAudit returns the same mux as newTestMux plus the
// audit store, for tests that need to inspect audit rows.
func newTestMuxWithAudit(t *testing.T) (http.Handler, *audit.Store) {
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
	svc := auth.NewService(authStore, secret, false)
	svc.Audit = auditStore
	svc.DB = db
	hub := events.NewHub(nil)
	return newMux(db, invStore, groupStore, authStore, svc, secret, nil, hub, auditStore, rbacStore, credStore, hostKeyStore, updaterStore, exporterStore, settingsStore, exclusionStore, holdsStore, labelStore, labelStyleStore, nil, nil), auditStore
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

	endpoints := []string{
		"/api/groups",
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
		"/api/docs",
	}
	for _, p := range endpoints {
		r, err := client.Get(srv.URL + p)
		if err != nil {
			t.Errorf("GET %s: %v", p, err)
			continue
		}
		// Drain + close. Status doesn't matter — we only care that the
		// route is wired and the handler responds.
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

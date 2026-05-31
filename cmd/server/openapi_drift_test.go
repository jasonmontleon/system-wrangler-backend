// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

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
	"system-wrangler-backend/internal/openapi"
	"system-wrangler-backend/internal/rbac"
	"system-wrangler-backend/internal/schedules"
	"system-wrangler-backend/internal/secrets"
	"system-wrangler-backend/internal/settings"
	"system-wrangler-backend/internal/systems"
	"system-wrangler-backend/internal/updaters"
)

// TestOpenAPISpecMatchesMux is the drift test. It walks every pattern
// the production wiring registers and asserts the openapi/spec.yaml
// describes the exact same set — and vice versa. The hand-written
// spec rots without this guard the moment a new route lands.
//
// "Pattern" here means a Go ServeMux pattern of the form
// "METHOD /path". For each registered pattern this test:
//
//   - normalizes "METHOD /path" into the same shape the spec uses.
//   - looks the spec up and fails if it's missing.
//
// Then the reverse: spec entries with no registered pattern fail.
func TestOpenAPISpecMatchesMux(t *testing.T) {
	registered := recordRoutes(t)
	specified := parseSpecRoutes(t, openapi.Spec)

	// Routes that are intentionally not part of the documented API
	// surface: SPA file server, the /api/* JSON-404 catchall, and the
	// /internal/scrape endpoint Prometheus uses (gated by shared
	// secret, off the user-facing surface). All are mounted by
	// populateMux but are not endpoints.
	notInSpec := map[string]bool{
		"GET /":     true,
		"GET /api/": true,
		"GET /internal/scrape/{system}/{exporter}": true,
	}

	for got := range registered {
		if notInSpec[got] {
			continue
		}
		if !specified[got] {
			t.Errorf("mux registers %q but openapi/spec.yaml has no matching operation", got)
		}
	}

	for want := range specified {
		if !registered[want] {
			t.Errorf("openapi/spec.yaml documents %q but no handler is registered for it", want)
		}
	}
}

// recordRoutes runs populateMux against a recording wrapper so the test
// observes every Handle call. Dependencies match newTestMux so the
// recorded set mirrors what production wires up.
func recordRoutes(t *testing.T) map[string]bool {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "drift.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	invStore, err := systems.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("systems store: %v", err)
	}
	groupStore, err := groups.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("groups store: %v", err)
	}
	authStore, err := auth.NewSQLiteAuthStore(db)
	if err != nil {
		t.Fatalf("auth store: %v", err)
	}
	secret, err := auth.LoadOrInitSecret(authStore)
	if err != nil {
		t.Fatalf("LoadOrInitSecret: %v", err)
	}
	auditStore, err := audit.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("audit store: %v", err)
	}
	rbacStore, err := rbac.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("rbac store: %v", err)
	}
	credStore, err := credentials.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("credentials store: %v", err)
	}
	hostKeyStore, err := hostkeys.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("hostkeys store: %v", err)
	}
	updaterStore, err := updaters.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("updaters store: %v", err)
	}
	exporterStore, err := exporters.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("exporters store: %v", err)
	}
	settingsStore, err := settings.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("settings store: %v", err)
	}
	exclusionStore, err := exclusions.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("exclusions store: %v", err)
	}
	holdsStore, err := holds.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("holds store: %v", err)
	}
	labelStore, err := labels.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("labels store: %v", err)
	}
	labelStyleStore, err := labels.NewSQLiteStyleStore(db)
	if err != nil {
		t.Fatalf("label styles store: %v", err)
	}
	dashboardLayoutStore, err := dashboardlayout.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("dashboardlayout store: %v", err)
	}
	scheduleStore, err := schedules.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("schedules store: %v", err)
	}
	svc := auth.NewService(authStore, secret, false)
	svc.Audit = auditStore
	svc.DB = db
	hub := events.NewHub(nil)

	// A non-nil vault makes populateMux register the conditional
	// secretscan route. The key is a fixed test value — nothing in
	// this test actually seals or opens secrets.
	vault, err := secrets.NewVaultFromKey(make([]byte, secrets.KeySize))
	if err != nil {
		t.Fatalf("secrets vault: %v", err)
	}

	rec := &recordingMux{patterns: map[string]bool{}}
	populateMux(t.Context(), rec, db, invStore, groupStore, authStore, svc, secret, vault, hub, auditStore, rbacStore, credStore, hostKeyStore, updaterStore, exporterStore, settingsStore, exclusionStore, holdsStore, labelStore, labelStyleStore, dashboardLayoutStore, scheduleStore, nil, nil)
	return rec.patterns
}

// recordingMux satisfies router.Mux by logging every pattern instead
// of routing requests. Patterns are normalized to "METHOD /path" with
// methodless catchalls left bare ("/api/", "/") so the assertion can
// special-case them.
type recordingMux struct {
	patterns map[string]bool
}

func (r *recordingMux) Handle(pattern string, _ http.Handler) {
	key := normalizePattern(pattern)
	r.patterns[key] = true
}

// normalizePattern returns the pattern with the method left in place.
// Methodless patterns (the /api/ catchall and the SPA root) are
// prefixed with "GET " so the assertion can match them against the
// `notInSpec` set, which uses that shape.
func normalizePattern(p string) string {
	if strings.ContainsRune(p, ' ') {
		return p
	}
	return "GET " + p
}

// parseSpecRoutes pulls the (method, path) tuples out of spec.yaml
// using a small line scanner. Hand-written YAML uses a fixed style:
//
//	paths:
//	  /api/foo:
//	    get:
//	    post:
//	  /api/bar/{id}:
//	    delete:
//
// Two-space-indented `/...:` lines are paths; four-space-indented
// `<verb>:` lines under them are operations. A real YAML parser is
// overkill for a structure we control.
func parseSpecRoutes(t *testing.T, spec []byte) map[string]bool {
	t.Helper()
	pathRE := regexp.MustCompile(`^  (/\S*?):\s*$`)
	opRE := regexp.MustCompile(`^    (get|post|put|patch|delete|head|options):\s*$`)

	out := map[string]bool{}
	inPaths := false
	var currentPath string
	for _, line := range strings.Split(string(spec), "\n") {
		if strings.HasPrefix(line, "paths:") {
			inPaths = true
			continue
		}
		if !inPaths {
			continue
		}
		// A top-level key (no leading space) outside the `paths:`
		// block terminates path scanning.
		if line != "" && !strings.HasPrefix(line, " ") {
			break
		}
		if m := pathRE.FindStringSubmatch(line); m != nil {
			currentPath = m[1]
			continue
		}
		if currentPath == "" {
			continue
		}
		if m := opRE.FindStringSubmatch(line); m != nil {
			method := strings.ToUpper(m[1])
			out[method+" "+currentPath] = true
		}
	}
	if len(out) == 0 {
		t.Fatal("spec.yaml parser found zero operations — parser is broken")
	}
	return out
}

// TestOpenAPISpecParserSanity ensures the path/operation parser
// extracts a few known entries. Cheap insurance against a future YAML
// reformat that breaks the scanner silently.
func TestOpenAPISpecParserSanity(t *testing.T) {
	got := parseSpecRoutes(t, openapi.Spec)
	want := []string{
		"GET /api/health",
		"POST /api/auth/login",
		"DELETE /api/auth/totp",
		"GET /api/admin/audit/{id}",
		"POST /api/admin/role-assignments",
		"DELETE /api/groups/{id}/role-assignments/{userId}/{role}",
		"PUT /api/systems/{id}/group",
		"PUT /api/systems/{id}/platform",
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("spec parser missed %q", w)
		}
	}
	if t.Failed() {
		keys := make([]string, 0, len(got))
		for k := range got {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		t.Logf("parser saw %d operations:\n  %s", len(keys), strings.Join(keys, "\n  "))
	}
}

// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/database"
)

func newAuditStore(t *testing.T, db *sql.DB) *audit.Store {
	t.Helper()
	s, err := audit.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("audit store: %v", err)
	}
	return s
}

func newHandlerFixture(t *testing.T) (*Handler, *audit.Store, func()) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "src.db")
	db, err := database.Open("file:" + dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE marker (k TEXT PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO marker(k, v) VALUES ('hello', 'world')`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	auditStore := newAuditStore(t, db)
	svc := &Service{DB: db, TempDir: t.TempDir()}
	h := &Handler{
		Service: svc,
		Audit:   auditStore,
		Now:     func() time.Time { return time.Date(2026, 5, 15, 12, 34, 56, 0, time.UTC) },
	}
	return h, auditStore, func() { _ = db.Close() }
}

func latestAudit(t *testing.T, store *audit.Store) audit.Record {
	t.Helper()
	recs, _, err := store.ListQuery(audit.Query{Action: "db.backup", Limit: 1})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("no db.backup audit row")
	}
	return recs[0]
}

func TestHandler_Create_Success(t *testing.T) {
	h, auditStore, cleanup := newHandlerFixture(t)
	defer cleanup()

	mux := http.NewServeMux()
	h.Register(mux, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/backup", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/vnd.sqlite3" {
		t.Errorf("Content-Type = %q", got)
	}
	wantCD := `attachment; filename="system-wrangler-20260515T123456Z.db"`
	if got := rec.Header().Get("Content-Disposition"); got != wantCD {
		t.Errorf("Content-Disposition = %q, want %q", got, wantCD)
	}
	if rec.Header().Get("Content-Length") == "" {
		t.Error("Content-Length not set")
	}
	body := rec.Body.Bytes()
	if !strings.HasPrefix(string(body), "SQLite format 3") {
		t.Errorf("body is not a SQLite snapshot (header=%q)", string(body[:16]))
	}

	row := latestAudit(t, auditStore)
	if row.Outcome != audit.Success {
		t.Errorf("audit outcome = %s, want success", row.Outcome)
	}
	if got, _ := row.Detail["bytes"].(float64); got <= 0 {
		t.Errorf("audit detail bytes = %v, want > 0", row.Detail["bytes"])
	}
}

func TestHandler_Create_ForbiddenWhenCanCreateFalse(t *testing.T) {
	h, auditStore, cleanup := newHandlerFixture(t)
	defer cleanup()
	h.CanCreate = func(context.Context) bool { return false }

	req := httptest.NewRequest(http.MethodPost, "/api/admin/backup", nil)
	rec := httptest.NewRecorder()
	h.create(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] == "" {
		t.Error("expected error message")
	}
	row := latestAudit(t, auditStore)
	if row.Outcome != audit.Denied {
		t.Errorf("audit outcome = %s, want denied", row.Outcome)
	}
}

func TestHandler_Create_AllowedWhenCanCreateTrue(t *testing.T) {
	h, _, cleanup := newHandlerFixture(t)
	defer cleanup()
	called := false
	h.CanCreate = func(context.Context) bool { called = true; return true }

	req := httptest.NewRequest(http.MethodPost, "/api/admin/backup", nil)
	rec := httptest.NewRecorder()
	h.create(rec, req)

	if !called {
		t.Error("CanCreate not invoked")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandler_Create_ConflictWhenInFlight(t *testing.T) {
	h, auditStore, cleanup := newHandlerFixture(t)
	defer cleanup()

	// Park an in-flight snapshot to force the second call into the
	// ErrInFlight branch.
	parked, err := h.Service.Create(context.Background())
	if err != nil {
		t.Fatalf("park snapshot: %v", err)
	}
	defer func() { _ = parked.Close() }()

	req := httptest.NewRequest(http.MethodPost, "/api/admin/backup", nil)
	rec := httptest.NewRecorder()
	h.create(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] == "" {
		t.Error("expected error message")
	}

	row := latestAudit(t, auditStore)
	if row.Outcome != audit.Failure {
		t.Errorf("audit outcome = %s, want failure", row.Outcome)
	}
	if got, _ := row.Detail["reason"].(string); got != "in_flight" {
		t.Errorf("audit detail reason = %q, want in_flight", got)
	}
}

func TestHandler_Create_NilAuditDoesNotPanic(t *testing.T) {
	h, _, cleanup := newHandlerFixture(t)
	defer cleanup()
	h.Audit = nil

	req := httptest.NewRequest(http.MethodPost, "/api/admin/backup", nil)
	rec := httptest.NewRecorder()
	h.create(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestNewHandler(t *testing.T) {
	svc := &Service{}
	h := NewHandler(svc)
	if h.Service != svc {
		t.Error("NewHandler did not bind Service")
	}
}

func TestHandler_Now_DefaultsToTimeNow(t *testing.T) {
	h := &Handler{}
	before := time.Now().Add(-time.Second)
	got := h.now()
	if got.Before(before) {
		t.Errorf("now() = %v, want >= %v", got, before)
	}
}

func TestHandler_Create_VacuumFailureReturns500(t *testing.T) {
	h, auditStore, cleanup := newHandlerFixture(t)
	defer cleanup()
	// Point the Service at a directory that doesn't exist so VACUUM INTO
	// fails to open the destination file.
	h.Service.TempDir = filepath.Join(t.TempDir(), "no-such-dir")

	req := httptest.NewRequest(http.MethodPost, "/api/admin/backup", nil)
	rec := httptest.NewRecorder()
	h.create(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	row := latestAudit(t, auditStore)
	if row.Outcome != audit.Failure {
		t.Errorf("audit outcome = %s, want failure", row.Outcome)
	}
	if got, _ := row.Detail["reason"].(string); got != "create_failed" {
		t.Errorf("audit detail reason = %q, want create_failed", got)
	}
}

// failingWriter wraps an http.ResponseWriter and returns an error from
// Write after firstBytes have been written so the stream_failed branch
// of create() can be exercised.
type failingWriter struct {
	http.ResponseWriter
	firstBytes int
	written    int
}

func (f *failingWriter) Write(p []byte) (int, error) {
	if f.written >= f.firstBytes {
		return 0, errors.New("connection reset")
	}
	n := f.firstBytes - f.written
	if n > len(p) {
		n = len(p)
	}
	out, err := f.ResponseWriter.Write(p[:n])
	f.written += out
	if err != nil {
		return out, err
	}
	if out < len(p) {
		return out, errors.New("connection reset")
	}
	return out, nil
}

func TestHandler_Create_StreamFailureRecordsFailureAudit(t *testing.T) {
	h, auditStore, cleanup := newHandlerFixture(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/api/admin/backup", nil)
	base := httptest.NewRecorder()
	fw := &failingWriter{ResponseWriter: base, firstBytes: 16}
	h.create(fw, req)

	row := latestAudit(t, auditStore)
	if row.Outcome != audit.Failure {
		t.Errorf("audit outcome = %s, want failure", row.Outcome)
	}
	if got, _ := row.Detail["reason"].(string); got != "stream_failed" {
		t.Errorf("audit detail reason = %q, want stream_failed", got)
	}
	if got, _ := row.Detail["bytes"].(float64); got <= 0 {
		t.Errorf("audit detail bytes = %v, want > 0", row.Detail["bytes"])
	}
}

func TestHandler_LogAudit_StoreErrorIsSwallowed(t *testing.T) {
	// Build an audit store on a DB that gets closed before Log runs so
	// every Log() call returns an error — exercising the slog-and-
	// continue branch in logAudit.
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	adb, err := database.Open("file:" + dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	store, err := audit.NewSQLiteStore(adb)
	if err != nil {
		t.Fatalf("audit store: %v", err)
	}
	_ = adb.Close()

	h := &Handler{Audit: store}
	// Must not panic; the error path just slog.Error's.
	h.logAudit(context.Background(), audit.Event{Action: "db.backup", Outcome: audit.Success})
}

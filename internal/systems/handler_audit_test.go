// SPDX-License-Identifier: Apache-2.0

package systems

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/database"
)

// fullStack returns a handler wired against a real SQLite DB and audit
// store. The audit store reads back the rows the handler wrote so
// assertions can verify the audit row landed in the same transaction
// as the systems row. AuditEmit closes over the audit.Store the way
// main.go does in production — the handler itself never imports audit.
func fullStack(t *testing.T) (*Handler, *SQLiteStore, *audit.Store) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "audit.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	auditStore, err := audit.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStore: %v", err)
	}
	h := NewHandler(store)
	h.DB = db
	h.AuditEmit = func(ctx context.Context, tx *sql.Tx, action string, sys System, detail map[string]any) error {
		d := audit.NewDetail()
		for k, v := range detail {
			_ = d.SetSafe(k, v)
		}
		return auditStore.LogTx(ctx, tx, audit.Event{
			Action:      action,
			Outcome:     audit.Success,
			TargetKind:  "system",
			TargetID:    sys.ID,
			TargetLabel: sys.Name,
			Detail:      d,
		})
	}
	return h, store, auditStore
}

func TestHandlerCreateEmitsAuditRow(t *testing.T) {
	h, _, auditStore := fullStack(t)
	mux := http.NewServeMux()
	h.Register(mux, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/systems",
		strings.NewReader(`{"name":"db1","hostname":"10.0.0.5"}`))
	req = req.WithContext(audit.WithActor(req.Context(),
		audit.Actor{Kind: audit.ActorUser, ID: "u-1", Label: "alice"}))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", w.Code)
	}
	var sys System
	_ = json.NewDecoder(w.Body).Decode(&sys)

	rows, _, err := auditStore.ListQuery(audit.Query{Action: "system.create"})
	if err != nil {
		t.Fatalf("ListQuery: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(rows))
	}
	got := rows[0]
	if got.TargetKind != "system" || got.TargetID != sys.ID || got.TargetLabel != "db1" {
		t.Errorf("target = (%s, %s, %s), want (system, %s, db1)",
			got.TargetKind, got.TargetID, got.TargetLabel, sys.ID)
	}
	if got.ActorLabel != "alice" || got.ActorID != "u-1" {
		t.Errorf("actor = (%s, %s), want (alice, u-1)", got.ActorLabel, got.ActorID)
	}
	if got.Outcome != audit.Success {
		t.Errorf("outcome = %s, want success", got.Outcome)
	}
	if got.Detail["hostname"] != "10.0.0.5" {
		t.Errorf("detail.hostname = %v, want 10.0.0.5", got.Detail["hostname"])
	}
}

func TestHandlerDeleteEmitsAuditRow(t *testing.T) {
	h, store, auditStore := fullStack(t)
	mux := http.NewServeMux()
	h.Register(mux, nil)
	sys, err := store.Create(SystemInput{Name: "victim", Hostname: "10.0.0.6"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/systems/"+sys.ID, nil)
	req = req.WithContext(audit.WithActor(req.Context(),
		audit.Actor{Kind: audit.ActorUser, ID: "u-2", Label: "bob"}))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}

	rows, _, err := auditStore.ListQuery(audit.Query{Action: "system.delete"})
	if err != nil {
		t.Fatalf("ListQuery: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(rows))
	}
	got := rows[0]
	if got.TargetID != sys.ID || got.TargetLabel != "victim" {
		t.Errorf("target = (%s, %s), want (%s, victim)", got.TargetID, got.TargetLabel, sys.ID)
	}
	// Row was actually removed (commit succeeded).
	if _, err := store.Get(sys.ID); err == nil {
		t.Error("system row still present after delete")
	}
}

func TestHandlerCreateAuditRollsBackOnDuplicate(t *testing.T) {
	// Forcing a write error inside the transaction is awkward without a
	// shim; instead we use the fact that the audit store would itself
	// fail an insert if the audit_log row's required fields are
	// somehow blank. We simulate that by swapping in an audit.Store
	// whose NewID always errors — Audit.LogTx will fail, the
	// surrounding transaction must roll back, and no system row may
	// remain.
	h, store, auditStore := fullStack(t)
	auditStore.NewID = func() (string, error) { return "", context.Canceled }

	mux := http.NewServeMux()
	h.Register(mux, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/systems",
		strings.NewReader(`{"name":"x","hostname":"y"}`))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	list, _ := store.List()
	if len(list) != 0 {
		t.Errorf("expected rollback to leave 0 systems, got %d", len(list))
	}
}

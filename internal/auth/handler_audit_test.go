// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"system-wrangler-backend/internal/audit"
)

// newAuditServiceFromStore wraps the existing SQLiteAuthStore so the
// password-change and TOTP audit emissions can be exercised against a
// real audit table — same wiring shape as cmd/server/main.go.
func newAuditServiceFromStore(t *testing.T, s *SQLiteAuthStore) (*Service, *audit.Store) {
	t.Helper()
	auditStore, err := audit.NewSQLiteStore(s.db)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStore: %v", err)
	}
	secret, err := LoadOrInitSecret(s)
	if err != nil {
		t.Fatalf("LoadOrInitSecret: %v", err)
	}
	svc := NewService(s, secret, false)
	svc.Audit = auditStore
	svc.DB = s.db
	return svc, auditStore
}

func TestHandleChangePasswordEmitsAuditRow(t *testing.T) {
	s := newTestAuthStore(t)
	svc, auditStore := newAuditServiceFromStore(t, s)

	hash, err := HashPassword("oldpassword123")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	u, err := s.Create("alice", hash)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	mux := http.NewServeMux()
	svc.RegisterProtected(mux, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), u)))
		})
	})

	body := strings.NewReader(`{"currentPassword":"oldpassword123","newPassword":"newpassword456"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password", body)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}

	rows, _, err := auditStore.ListQuery(audit.Query{Action: "auth.password.change"})
	if err != nil {
		t.Fatalf("ListQuery: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0].TargetID != u.ID || rows[0].TargetLabel != "alice" {
		t.Errorf("target = (%s, %s), want (%s, alice)", rows[0].TargetID, rows[0].TargetLabel, u.ID)
	}
}

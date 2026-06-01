// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func sessionTestTime() time.Time {
	return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
}

func TestLogoutRevokesCurrentSession(t *testing.T) {
	now := sessionTestTime()
	users := &stubUserStore{}
	if _, err := users.Create("alice", "h"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sessions := newStubSessionStore()
	sessions.put(Session{ID: "sid-current", UserID: "alice-id", LastSeenAt: now, ExpiresAt: now.Add(24 * time.Hour)})
	sessions.put(Session{ID: "sid-other", UserID: "alice-id", LastSeenAt: now, ExpiresAt: now.Add(24 * time.Hour)})

	svc := NewService(users, testSecret, false)
	svc.Now = func() time.Time { return now }
	svc.Sessions = sessions
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: signSID(t, "alice-id", "sid-current", now.Add(24*time.Hour))}) //nolint:gosec
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if _, ok := sessions.rows["sid-current"]; ok {
		t.Error("current session should be revoked on logout")
	}
	if _, ok := sessions.rows["sid-other"]; !ok {
		t.Error("logout should only revoke the current session, not others")
	}
}

func TestChangePasswordRevokesOtherSessions(t *testing.T) {
	now := sessionTestTime()
	users := &stubUserStore{}
	hash, err := HashPassword("currentpassword")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := users.Create("alice", hash); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sessions := newStubSessionStore()
	sessions.put(Session{ID: "sid-current", UserID: "alice-id", LastSeenAt: now, ExpiresAt: now.Add(24 * time.Hour)})
	sessions.put(Session{ID: "sid-other", UserID: "alice-id", LastSeenAt: now, ExpiresAt: now.Add(24 * time.Hour)})

	svc := NewService(users, testSecret, false)
	svc.Now = func() time.Time { return now }
	svc.Sessions = sessions
	mw := RequireUser(testSecret, users, svc.Now, WithSessions(sessions))
	mux := http.NewServeMux()
	svc.RegisterProtected(mux, mw)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/password",
		strings.NewReader(`{"currentPassword":"currentpassword","newPassword":"newpassword123"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: CookieName, Value: signSID(t, "alice-id", "sid-current", now.Add(24*time.Hour))}) //nolint:gosec
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("change password: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if _, ok := sessions.rows["sid-current"]; !ok {
		t.Error("the session that changed the password should survive")
	}
	if _, ok := sessions.rows["sid-other"]; ok {
		t.Error("other sessions should be revoked on password change")
	}
}

func TestAdminDisableRevokesSessions(t *testing.T) {
	now := sessionTestTime()
	users := &stubUserStore{}
	if _, err := users.Create("alice", "h"); err != nil { // the admin
		t.Fatalf("seed alice: %v", err)
	}
	if _, err := users.Create("bob", "h"); err != nil { // the target
		t.Fatalf("seed bob: %v", err)
	}
	sessions := newStubSessionStore()
	sessions.put(Session{ID: "bob-sid", UserID: "bob-id", LastSeenAt: now, ExpiresAt: now.Add(24 * time.Hour)})

	svc := NewService(users, testSecret, false)
	svc.Now = func() time.Time { return now }
	svc.Sessions = sessions
	// Stamp alice as the actor without needing a real cookie.
	stamp := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, _ := users.GetByID("alice-id")
			next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), u)))
		})
	}
	mux := http.NewServeMux()
	svc.RegisterAdmin(mux, stamp)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/admin/users/bob-id",
		strings.NewReader(`{"disabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if _, ok := sessions.rows["bob-sid"]; ok {
		t.Error("disabling bob should revoke his sessions")
	}
}

func TestAdminResetPasswordRevokesSessions(t *testing.T) {
	now := sessionTestTime()
	users := &stubUserStore{}
	if _, err := users.Create("alice", "h"); err != nil {
		t.Fatalf("seed alice: %v", err)
	}
	if _, err := users.Create("bob", "h"); err != nil {
		t.Fatalf("seed bob: %v", err)
	}
	sessions := newStubSessionStore()
	sessions.put(Session{ID: "bob-sid", UserID: "bob-id", LastSeenAt: now, ExpiresAt: now.Add(24 * time.Hour)})

	svc := NewService(users, testSecret, false)
	svc.Now = func() time.Time { return now }
	svc.Sessions = sessions
	stamp := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, _ := users.GetByID("alice-id")
			next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), u)))
		})
	}
	mux := http.NewServeMux()
	svc.RegisterAdmin(mux, stamp)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/admin/users/bob-id/password",
		strings.NewReader(`{"password":"brandnewpassword"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if _, ok := sessions.rows["bob-sid"]; ok {
		t.Error("admin password reset should revoke the target's sessions")
	}
}

func TestAdminDeleteRevokesSessions(t *testing.T) {
	now := sessionTestTime()
	users := &stubUserStore{}
	if _, err := users.Create("alice", "h"); err != nil {
		t.Fatalf("seed alice: %v", err)
	}
	if _, err := users.Create("bob", "h"); err != nil {
		t.Fatalf("seed bob: %v", err)
	}
	sessions := newStubSessionStore()
	sessions.put(Session{ID: "bob-sid", UserID: "bob-id", LastSeenAt: now, ExpiresAt: now.Add(24 * time.Hour)})

	svc := NewService(users, testSecret, false)
	svc.Now = func() time.Time { return now }
	svc.Sessions = sessions
	stamp := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, _ := users.GetByID("alice-id")
			next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), u)))
		})
	}
	mux := http.NewServeMux()
	svc.RegisterAdmin(mux, stamp)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/admin/users/bob-id", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if _, ok := sessions.rows["bob-sid"]; ok {
		t.Error("deleting bob should clear his sessions")
	}
}

func TestCurrentSessionIDNoCookie(t *testing.T) {
	svc := NewService(&stubUserStore{}, testSecret, false)
	svc.Now = sessionTestTime
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	if sid := svc.currentSessionID(r); sid != "" {
		t.Errorf("sid = %q, want empty with no cookie", sid)
	}
}

func TestCurrentSessionIDBadCookie(t *testing.T) {
	svc := NewService(&stubUserStore{}, testSecret, false)
	svc.Now = sessionTestTime
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: "garbage"}) //nolint:gosec
	if sid := svc.currentSessionID(r); sid != "" {
		t.Errorf("sid = %q, want empty for an unverifiable cookie", sid)
	}
}

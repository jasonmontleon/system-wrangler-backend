// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"encoding/json"
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

// adminSessionsFixture builds a Service + test server wired with the
// admin routes and a user-stamping middleware, plus a seeded target user
// "bob-id" with one session "bob-sid".
func adminSessionsFixture(t *testing.T) (*httptest.Server, *stubSessionStore) {
	t.Helper()
	now := sessionTestTime()
	users := &stubUserStore{}
	if _, err := users.Create("alice", "h"); err != nil {
		t.Fatalf("seed alice: %v", err)
	}
	if _, err := users.Create("bob", "h"); err != nil {
		t.Fatalf("seed bob: %v", err)
	}
	sessions := newStubSessionStore()
	sessions.put(Session{ID: "bob-sid", UserID: "bob-id", Label: "Chrome on Windows", LastSeenAt: now, ExpiresAt: now.Add(24 * time.Hour)})

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
	return srv, sessions
}

func TestAdminListUserSessions(t *testing.T) {
	srv, _ := adminSessionsFixture(t)
	resp := doReq(t, http.MethodGet, srv.URL+"/api/admin/users/bob-id/sessions", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got []Session
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].ID != "bob-sid" {
		t.Errorf("sessions = %+v, want one bob-sid", got)
	}
}

func TestAdminListUserSessionsUnknownUser(t *testing.T) {
	srv, _ := adminSessionsFixture(t)
	resp := doReq(t, http.MethodGet, srv.URL+"/api/admin/users/ghost/sessions", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAdminRevokeUserSession(t *testing.T) {
	srv, sessions := adminSessionsFixture(t)
	resp := doReq(t, http.MethodDelete, srv.URL+"/api/admin/users/bob-id/sessions/bob-sid", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if _, ok := sessions.rows["bob-sid"]; ok {
		t.Error("bob-sid should be revoked")
	}
}

func TestAdminRevokeUserSessionNotFound(t *testing.T) {
	srv, _ := adminSessionsFixture(t)
	resp := doReq(t, http.MethodDelete, srv.URL+"/api/admin/users/bob-id/sessions/ghost-sid", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAdminRevokeUserSessionWrongOwnerIsScoped(t *testing.T) {
	// bob-sid belongs to bob; revoking it via alice-id must not match
	// (the revoke is scoped to the path user), so the row survives.
	srv, sessions := adminSessionsFixture(t)
	resp := doReq(t, http.MethodDelete, srv.URL+"/api/admin/users/alice-id/sessions/bob-sid", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	if _, ok := sessions.rows["bob-sid"]; !ok {
		t.Error("bob-sid should survive a mis-scoped revoke")
	}
}

// adminSessionHandlerCall invokes one of the admin session handlers
// directly with the path values and an optional stamped user, returning
// the recorder. Bypasses the mux so individual branches are reachable
// without a full server.
func adminSessionHandlerCall(svc *Service, method, id, sid string, stampUser bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/admin", nil)
	if id != "" {
		r.SetPathValue("id", id)
	}
	if sid != "" {
		r.SetPathValue("sid", sid)
	}
	if stampUser {
		r = r.WithContext(WithUser(r.Context(), User{ID: "alice-id", Username: "alice"}))
	}
	w := httptest.NewRecorder()
	if method == http.MethodGet {
		svc.handleAdminListUserSessions(w, r)
	} else {
		svc.handleAdminRevokeUserSession(w, r)
	}
	return w
}

func TestAdminListUserSessionsUnauthorized(t *testing.T) {
	svc := NewService(&stubUserStore{}, testSecret, false)
	svc.Sessions = newStubSessionStore()
	if w := adminSessionHandlerCall(svc, http.MethodGet, "bob-id", "", false); w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestAdminRevokeUserSessionUnauthorized(t *testing.T) {
	svc := NewService(&stubUserStore{}, testSecret, false)
	svc.Sessions = newStubSessionStore()
	if w := adminSessionHandlerCall(svc, http.MethodDelete, "bob-id", "sid", false); w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestAdminListUserSessionsNilStore(t *testing.T) {
	svc := NewService(&stubUserStore{}, testSecret, false) // Sessions nil
	w := adminSessionHandlerCall(svc, http.MethodGet, "bob-id", "", true)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if strings.TrimSpace(w.Body.String()) != "[]" {
		t.Errorf("body = %q, want []", w.Body.String())
	}
}

func TestAdminRevokeUserSessionNilStore(t *testing.T) {
	svc := NewService(&stubUserStore{}, testSecret, false) // Sessions nil
	if w := adminSessionHandlerCall(svc, http.MethodDelete, "bob-id", "sid", true); w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}

func TestAdminListUserSessionsMissingID(t *testing.T) {
	svc := NewService(&stubUserStore{}, testSecret, false)
	svc.Sessions = newStubSessionStore()
	if w := adminSessionHandlerCall(svc, http.MethodGet, "", "", true); w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAdminRevokeUserSessionMissingIDs(t *testing.T) {
	svc := NewService(&stubUserStore{}, testSecret, false)
	svc.Sessions = newStubSessionStore()
	if w := adminSessionHandlerCall(svc, http.MethodDelete, "bob-id", "", true); w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAdminListUserSessionsLookupError(t *testing.T) {
	users := &stubUserStore{failOn: "GetByID", err: errInjected}
	svc := NewService(users, testSecret, false)
	svc.Sessions = newStubSessionStore()
	if w := adminSessionHandlerCall(svc, http.MethodGet, "bob-id", "", true); w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestAdminRevokeUserSessionLookupError(t *testing.T) {
	users := &stubUserStore{failOn: "GetByID", err: errInjected}
	svc := NewService(users, testSecret, false)
	svc.Sessions = newStubSessionStore()
	if w := adminSessionHandlerCall(svc, http.MethodDelete, "bob-id", "sid", true); w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestAdminListUserSessionsListError(t *testing.T) {
	users := &stubUserStore{}
	if _, err := users.Create("bob", "h"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sessions := newStubSessionStore()
	sessions.failOn = "ListSessions"
	sessions.err = errInjected
	svc := NewService(users, testSecret, false)
	svc.Sessions = sessions
	if w := adminSessionHandlerCall(svc, http.MethodGet, "bob-id", "", true); w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestAdminRevokeUserSessionRevokeError(t *testing.T) {
	users := &stubUserStore{}
	if _, err := users.Create("bob", "h"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sessions := newStubSessionStore()
	sessions.put(Session{ID: "bob-sid", UserID: "bob-id"})
	sessions.failOn = "RevokeSession"
	sessions.err = errInjected
	svc := NewService(users, testSecret, false)
	svc.Sessions = sessions
	if w := adminSessionHandlerCall(svc, http.MethodDelete, "bob-id", "bob-sid", true); w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
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

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

// newSessionService builds a Service whose UserStore is a seeded stub
// and whose SessionStore is the in-memory stub, plus the protected mux
// wired with a RequireUser that enforces sessions. Returns the server,
// the session store, and a cookie string for alice's current session
// "sid-current".
func newSessionService(t *testing.T) (*httptest.Server, *stubSessionStore, *http.Cookie) {
	t.Helper()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	users := &stubUserStore{}
	if _, err := users.Create("alice", "h"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sessions := newStubSessionStore()
	sessions.put(Session{ID: "sid-current", UserID: "alice-id", Label: "Firefox on Linux", LastSeenAt: now, ExpiresAt: now.Add(24 * time.Hour)})

	svc := NewService(users, testSecret, false)
	svc.Now = func() time.Time { return now }
	svc.Sessions = sessions

	mux := http.NewServeMux()
	mw := RequireUser(testSecret, users, svc.Now, WithSessions(sessions))
	svc.RegisterSessions(mux, mw)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cookie := &http.Cookie{Name: CookieName, Value: signSID(t, "alice-id", "sid-current", now.Add(24*time.Hour))} //nolint:gosec
	return srv, sessions, cookie
}

func doReq(t *testing.T, method, url string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func TestHandleListSessionsMarksCurrent(t *testing.T) {
	srv, sessions, cookie := newSessionService(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	sessions.put(Session{ID: "sid-other", UserID: "alice-id", Label: "Chrome on Windows", LastSeenAt: now, ExpiresAt: now.Add(24 * time.Hour)})

	resp := doReq(t, http.MethodGet, srv.URL+"/api/auth/sessions", cookie)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got []Session
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	var currentCount int
	for _, s := range got {
		if s.Current {
			currentCount++
			if s.ID != "sid-current" {
				t.Errorf("current marked on %s, want sid-current", s.ID)
			}
		}
	}
	if currentCount != 1 {
		t.Errorf("current count = %d, want exactly 1", currentCount)
	}
}

func TestHandleRevokeSessionOther(t *testing.T) {
	srv, sessions, cookie := newSessionService(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	sessions.put(Session{ID: "sid-other", UserID: "alice-id", LastSeenAt: now, ExpiresAt: now.Add(24 * time.Hour)})

	resp := doReq(t, http.MethodDelete, srv.URL+"/api/auth/sessions/sid-other", cookie)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if _, ok := sessions.rows["sid-other"]; ok {
		t.Error("sid-other should be gone")
	}
	// Revoking another session does not clear our own cookie.
	for _, c := range resp.Cookies() {
		if c.Name == CookieName && c.MaxAge < 0 {
			t.Error("revoking another session should not clear the current cookie")
		}
	}
}

func TestHandleRevokeSessionCurrentClearsCookie(t *testing.T) {
	srv, sessions, cookie := newSessionService(t)
	resp := doReq(t, http.MethodDelete, srv.URL+"/api/auth/sessions/sid-current", cookie)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if _, ok := sessions.rows["sid-current"]; ok {
		t.Error("sid-current should be gone")
	}
	var cleared bool
	for _, c := range resp.Cookies() {
		if c.Name == CookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("revoking the current session should clear the cookie")
	}
}

func TestHandleRevokeSessionNotFound(t *testing.T) {
	srv, _, cookie := newSessionService(t)
	resp := doReq(t, http.MethodDelete, srv.URL+"/api/auth/sessions/ghost", cookie)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandleRevokeOtherSessions(t *testing.T) {
	srv, sessions, cookie := newSessionService(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	sessions.put(Session{ID: "sid-a", UserID: "alice-id", LastSeenAt: now, ExpiresAt: now.Add(24 * time.Hour)})
	sessions.put(Session{ID: "sid-b", UserID: "alice-id", LastSeenAt: now, ExpiresAt: now.Add(24 * time.Hour)})

	resp := doReq(t, http.MethodPost, srv.URL+"/api/auth/sessions/revoke-others", cookie)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body struct {
		Revoked int `json:"revoked"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Revoked != 2 {
		t.Errorf("revoked = %d, want 2", body.Revoked)
	}
	if _, ok := sessions.rows["sid-current"]; !ok {
		t.Error("current session should survive revoke-others")
	}
}

func TestHandleSessionsRequireAuth(t *testing.T) {
	srv, _, _ := newSessionService(t)
	// No cookie → middleware refuses.
	resp := doReq(t, http.MethodGet, srv.URL+"/api/auth/sessions", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestHandleSessionsNilStore(t *testing.T) {
	// A Service with no SessionStore still answers list (empty) and
	// returns 503 on the mutating endpoints. We bypass the
	// session-enforcing middleware by stamping the user directly.
	users := &stubUserStore{}
	if _, err := users.Create("alice", "h"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc := NewService(users, testSecret, false)
	stampMW := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, _ := users.GetByID("alice-id")
			next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), u)))
		})
	}
	mux := http.NewServeMux()
	svc.RegisterSessions(mux, stampMW)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	listResp := doReq(t, http.MethodGet, srv.URL+"/api/auth/sessions", nil)
	defer func() { _ = listResp.Body.Close() }()
	if listResp.StatusCode != http.StatusOK {
		t.Errorf("list status = %d, want 200", listResp.StatusCode)
	}
	var got []Session
	_ = json.NewDecoder(listResp.Body).Decode(&got)
	if len(got) != 0 {
		t.Errorf("list = %v, want empty", got)
	}

	delResp := doReq(t, http.MethodDelete, srv.URL+"/api/auth/sessions/x", nil)
	defer func() { _ = delResp.Body.Close() }()
	if delResp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("delete status = %d, want 503", delResp.StatusCode)
	}

	othersResp := doReq(t, http.MethodPost, srv.URL+"/api/auth/sessions/revoke-others", nil)
	defer func() { _ = othersResp.Body.Close() }()
	if othersResp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("revoke-others status = %d, want 503", othersResp.StatusCode)
	}
}

func TestHandleListSessionsUnauthorized(t *testing.T) {
	// Direct call with no user stamped on the context → 401.
	svc := NewService(&stubUserStore{}, testSecret, false)
	svc.Sessions = newStubSessionStore()
	w := httptest.NewRecorder()
	svc.handleListSessions(w, httptest.NewRequest(http.MethodGet, "/api/auth/sessions", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRegisterSessionsNilMiddleware(t *testing.T) {
	// A nil middleware must default to a pass-through rather than panic.
	svc := NewService(&stubUserStore{}, testSecret, false)
	mux := http.NewServeMux()
	svc.RegisterSessions(mux, nil)
	// Route is reachable (no auth wrapper); with no user stamped it 401s
	// from the handler itself.
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	resp := doReq(t, http.MethodGet, srv.URL+"/api/auth/sessions", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestIssueCookieCreateSessionError(t *testing.T) {
	// When the session row can't be created, setup must fail loud (500)
	// rather than handing out a cookie with no backing session.
	users := &stubUserStore{}
	sessions := newStubSessionStore()
	sessions.failOn = "CreateSession"
	sessions.err = errInjected
	svc := NewService(users, testSecret, false)
	svc.Now = func() time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) }
	svc.Sessions = sessions
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := http.Post(srv.URL+"/api/auth/setup", "application/json",
		strings.NewReader(`{"username":"admin","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestIssueCookiePruneErrorStillSucceeds(t *testing.T) {
	// A failed prune is logged but must not break the login that
	// just succeeded.
	users := &stubUserStore{}
	sessions := newStubSessionStore()
	sessions.failOn = "DeleteExpiredSessions"
	sessions.err = errInjected
	svc := NewService(users, testSecret, false)
	svc.Now = func() time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) }
	svc.Sessions = sessions
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := http.Post(srv.URL+"/api/auth/setup", "application/json",
		strings.NewReader(`{"username":"admin","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want 201 despite prune failure", resp.StatusCode)
	}
}

func TestHandleListSessionsError(t *testing.T) {
	srv, sessions, cookie := newSessionService(t)
	sessions.failOn = "ListSessions"
	sessions.err = errInjected
	resp := doReq(t, http.MethodGet, srv.URL+"/api/auth/sessions", cookie)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandleRevokeSessionError(t *testing.T) {
	srv, sessions, cookie := newSessionService(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	sessions.put(Session{ID: "sid-other", UserID: "alice-id", LastSeenAt: now, ExpiresAt: now.Add(24 * time.Hour)})
	sessions.failOn = "RevokeSession"
	sessions.err = errInjected
	resp := doReq(t, http.MethodDelete, srv.URL+"/api/auth/sessions/sid-other", cookie)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandleRevokeSessionMissingID(t *testing.T) {
	// A trailing-slash path leaves the id empty; Go's mux won't match the
	// {id} pattern, so this 404s at the router. The explicit empty-id 400
	// inside the handler is still worth guarding, exercised here by a
	// direct handler call.
	users := &stubUserStore{}
	if _, err := users.Create("alice", "h"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc := NewService(users, testSecret, false)
	svc.Sessions = newStubSessionStore()
	u, _ := users.GetByID("alice-id")
	r := httptest.NewRequest(http.MethodDelete, "/api/auth/sessions/", nil)
	r = r.WithContext(WithUser(r.Context(), u))
	w := httptest.NewRecorder()
	svc.handleRevokeSession(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for empty id", w.Code)
	}
}

func TestHandleRevokeOthersError(t *testing.T) {
	srv, sessions, cookie := newSessionService(t)
	sessions.failOn = "RevokeOtherUserSessions"
	sessions.err = errInjected
	resp := doReq(t, http.MethodPost, srv.URL+"/api/auth/sessions/revoke-others", cookie)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

// TestIssueCookieCreatesSessionRow drives setup end-to-end and confirms
// a session row was created with a sid that matches the issued cookie.
func TestIssueCookieCreatesSessionRow(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	users := &stubUserStore{}
	sessions := newStubSessionStore()
	svc := NewService(users, testSecret, false)
	svc.Now = func() time.Time { return now }
	svc.Sessions = sessions
	var idn int
	svc.NewID = func() string { idn++; return "sid-new" }

	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := http.Post(srv.URL+"/api/auth/setup", "application/json",
		strings.NewReader(`{"username":"admin","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if _, ok := sessions.rows["sid-new"]; !ok {
		t.Fatal("setup should have created a session row")
	}
	// The cookie should carry the sid we minted.
	var found bool
	for _, c := range resp.Cookies() {
		if c.Name == CookieName {
			claims, err := VerifyToken(testSecret, now, PurposeSession, c.Value)
			if err != nil {
				t.Fatalf("verify cookie: %v", err)
			}
			if claims.SID != "sid-new" {
				t.Errorf("cookie sid = %q, want sid-new", claims.SID)
			}
			found = true
		}
	}
	if !found {
		t.Error("no session cookie set")
	}
}

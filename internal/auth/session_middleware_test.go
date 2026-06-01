// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// errInjected is the canned error stub stores return when failOn fires.
var errInjected = errors.New("injected store failure")

// stubSessionStore is an in-memory SessionStore for middleware and
// handler tests. failOn names a method that should return err instead
// of its normal result, so the error paths can be exercised.
type stubSessionStore struct {
	rows    map[string]Session
	touched map[string]time.Time
	failOn  string
	err     error
}

func newStubSessionStore() *stubSessionStore {
	return &stubSessionStore{rows: map[string]Session{}, touched: map[string]time.Time{}}
}

func (s *stubSessionStore) put(sess Session) {
	s.rows[sess.ID] = sess
}

func (s *stubSessionStore) CreateSession(sess Session) error {
	if s.failOn == "CreateSession" {
		return s.err
	}
	s.rows[sess.ID] = sess
	return nil
}

func (s *stubSessionStore) GetSession(id string) (Session, error) {
	if s.failOn == "GetSession" {
		return Session{}, s.err
	}
	sess, ok := s.rows[id]
	if !ok {
		return Session{}, ErrSessionNotFound
	}
	return sess, nil
}

func (s *stubSessionStore) TouchSession(id string, lastSeen time.Time) error {
	if s.failOn == "TouchSession" {
		return s.err
	}
	s.touched[id] = lastSeen
	if sess, ok := s.rows[id]; ok {
		sess.LastSeenAt = lastSeen
		s.rows[id] = sess
	}
	return nil
}

func (s *stubSessionStore) RevokeSession(id, userID string) error {
	if s.failOn == "RevokeSession" {
		return s.err
	}
	sess, ok := s.rows[id]
	if !ok || sess.UserID != userID {
		return ErrSessionNotFound
	}
	delete(s.rows, id)
	return nil
}

func (s *stubSessionStore) RevokeUserSessions(userID string) (int, error) {
	if s.failOn == "RevokeUserSessions" {
		return 0, s.err
	}
	n := 0
	for id, sess := range s.rows {
		if sess.UserID == userID {
			delete(s.rows, id)
			n++
		}
	}
	return n, nil
}

func (s *stubSessionStore) RevokeOtherUserSessions(userID, keepID string) (int, error) {
	if s.failOn == "RevokeOtherUserSessions" {
		return 0, s.err
	}
	n := 0
	for id, sess := range s.rows {
		if sess.UserID == userID && id != keepID {
			delete(s.rows, id)
			n++
		}
	}
	return n, nil
}

func (s *stubSessionStore) ListSessions(userID string) ([]Session, error) {
	if s.failOn == "ListSessions" {
		return nil, s.err
	}
	out := []Session{}
	for _, sess := range s.rows {
		if sess.UserID == userID {
			out = append(out, sess)
		}
	}
	return out, nil
}

func (s *stubSessionStore) DeleteExpiredSessions(before time.Time) (int, error) {
	if s.failOn == "DeleteExpiredSessions" {
		return 0, s.err
	}
	n := 0
	for id, sess := range s.rows {
		if !sess.ExpiresAt.After(before) {
			delete(s.rows, id)
			n++
		}
	}
	return n, nil
}

// signSID is a test helper that mints a session cookie carrying a sid
// claim, mirroring what Service.issueCookie produces in production.
func signSID(t *testing.T, uid, sid string, exp time.Time) string {
	t.Helper()
	tok, err := SignToken(testSecret, PurposeSession, TokenClaims{UID: uid, SID: sid}, exp)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	return tok
}

func newSessionMiddlewareFixture(t *testing.T) (*stubUserStore, *stubSessionStore) {
	t.Helper()
	users := &stubUserStore{}
	if _, err := users.Create("alice", "h"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return users, newStubSessionStore()
}

func TestRequireUserWithSessionsAcceptsLiveSession(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	users, sessions := newSessionMiddlewareFixture(t)
	sessions.put(Session{ID: "sid-1", UserID: "alice-id", LastSeenAt: now, ExpiresAt: now.Add(time.Hour)})
	mw := RequireUser(testSecret, users, func() time.Time { return now }, WithSessions(sessions))

	called := false
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: signSID(t, "alice-id", "sid-1", now.Add(time.Hour))}) //nolint:gosec
	w := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(w, r)
	if !called {
		t.Fatalf("inner not called; status=%d", w.Code)
	}
}

func TestRequireUserWithSessionsRejectsMissingSid(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	users, sessions := newSessionMiddlewareFixture(t)
	mw := RequireUser(testSecret, users, func() time.Time { return now }, WithSessions(sessions))

	// A cookie with no sid (the old stateless form) must be refused.
	tok, _ := SignSession(testSecret, "alice-id", now.Add(time.Hour))
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: tok}) //nolint:gosec
	w := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("inner should not be called")
	})).ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireUserWithSessionsRejectsRevoked(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	users, sessions := newSessionMiddlewareFixture(t)
	// sid-1 was never inserted (or was revoked) → GetSession misses.
	mw := RequireUser(testSecret, users, func() time.Time { return now }, WithSessions(sessions))
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: signSID(t, "alice-id", "sid-1", now.Add(time.Hour))}) //nolint:gosec
	w := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("inner should not be called for a revoked session")
	})).ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireUserWithSessionsRejectsUserMismatch(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	users, sessions := newSessionMiddlewareFixture(t)
	// Row belongs to someone else than the cookie's uid.
	sessions.put(Session{ID: "sid-1", UserID: "mallory-id", LastSeenAt: now, ExpiresAt: now.Add(time.Hour)})
	mw := RequireUser(testSecret, users, func() time.Time { return now }, WithSessions(sessions))
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: signSID(t, "alice-id", "sid-1", now.Add(time.Hour))}) //nolint:gosec
	w := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("inner should not be called on uid mismatch")
	})).ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireUserWithSessionsRejectsExpiredRow(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	users, sessions := newSessionMiddlewareFixture(t)
	sessions.put(Session{ID: "sid-1", UserID: "alice-id", LastSeenAt: now, ExpiresAt: now.Add(-time.Minute)})
	mw := RequireUser(testSecret, users, func() time.Time { return now }, WithSessions(sessions))
	// Sign a cookie that itself hasn't expired so we isolate the row-expiry check.
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: signSID(t, "alice-id", "sid-1", now.Add(time.Hour))}) //nolint:gosec
	w := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("inner should not be called for an expired row")
	})).ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireUserWithSessionsTouchThrottle(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	users, sessions := newSessionMiddlewareFixture(t)
	cookie := &http.Cookie{Name: CookieName, Value: signSID(t, "alice-id", "sid-1", now.Add(24*time.Hour))} //nolint:gosec
	mw := RequireUser(testSecret, users, func() time.Time { return now }, WithSessions(sessions))
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	// Fresh last_seen → no touch.
	sessions.put(Session{ID: "sid-1", UserID: "alice-id", LastSeenAt: now.Add(-time.Minute), ExpiresAt: now.Add(24 * time.Hour)})
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.AddCookie(cookie)
	mw(next).ServeHTTP(httptest.NewRecorder(), r)
	if _, touched := sessions.touched["sid-1"]; touched {
		t.Error("recent session should not be touched")
	}

	// Stale last_seen → touch.
	sessions.put(Session{ID: "sid-1", UserID: "alice-id", LastSeenAt: now.Add(-2 * SessionTouchInterval), ExpiresAt: now.Add(24 * time.Hour)})
	r2 := httptest.NewRequest(http.MethodGet, "/x", nil)
	r2.AddCookie(cookie)
	mw(next).ServeHTTP(httptest.NewRecorder(), r2)
	if ts, touched := sessions.touched["sid-1"]; !touched || !ts.Equal(now) {
		t.Errorf("stale session should be touched to now; touched=%v ts=%v", touched, ts)
	}
}

func TestRequireUserWithSessionsTouchErrorStillAllows(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	users, sessions := newSessionMiddlewareFixture(t)
	sessions.put(Session{ID: "sid-1", UserID: "alice-id", LastSeenAt: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour)})
	sessions.failOn = "TouchSession"
	sessions.err = errInjected
	mw := RequireUser(testSecret, users, func() time.Time { return now }, WithSessions(sessions))
	called := false
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: signSID(t, "alice-id", "sid-1", now.Add(24*time.Hour))}) //nolint:gosec
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(httptest.NewRecorder(), r)
	if !called {
		t.Error("a touch failure should not block the request")
	}
}

func TestRequireUserWithSessionsStoreErrorRejects(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	users, sessions := newSessionMiddlewareFixture(t)
	sessions.failOn = "GetSession"
	sessions.err = errInjected
	mw := RequireUser(testSecret, users, func() time.Time { return now }, WithSessions(sessions))
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: signSID(t, "alice-id", "sid-1", now.Add(time.Hour))}) //nolint:gosec
	w := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("inner should not be called when the session lookup errors")
	})).ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (fail closed)", w.Code)
	}
}

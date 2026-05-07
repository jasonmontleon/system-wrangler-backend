// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// stubUserStore lets us drive RequireUser without SQLite.
type stubUserStore struct {
	users  map[string]User
	hashes map[string]string
	count  int
	failOn string
	err    error
}

func (s *stubUserStore) Count() (int, error) {
	if s.failOn == "Count" {
		return 0, s.err
	}
	return s.count, nil
}
func (s *stubUserStore) Create(username, hash string) (User, error) {
	if s.failOn == "Create" {
		return User{}, s.err
	}
	if s.users == nil {
		s.users = map[string]User{}
		s.hashes = map[string]string{}
	}
	id := username + "-id"
	u := User{ID: id, Username: username, CreatedAt: time.Now()}
	s.users[id] = u
	s.hashes[username] = hash
	s.count++
	return u, nil
}
func (s *stubUserStore) GetByUsername(name string) (User, string, error) {
	if s.failOn == "GetByUsername" {
		return User{}, "", s.err
	}
	for _, u := range s.users {
		if u.Username == name {
			return u, s.hashes[name], nil
		}
	}
	return User{}, "", ErrUserNotFound
}
func (s *stubUserStore) GetByID(id string) (User, error) {
	if s.failOn == "GetByID" {
		return User{}, s.err
	}
	u, ok := s.users[id]
	if !ok {
		return User{}, ErrUserNotFound
	}
	return u, nil
}
func (s *stubUserStore) GetHashByID(id string) (string, error) {
	if s.failOn == "GetHashByID" {
		return "", s.err
	}
	u, ok := s.users[id]
	if !ok {
		return "", ErrUserNotFound
	}
	return s.hashes[u.Username], nil
}
func (s *stubUserStore) UpdateProfile(id, email, theme string) (User, error) {
	if s.failOn == "UpdateProfile" {
		return User{}, s.err
	}
	u, ok := s.users[id]
	if !ok {
		return User{}, ErrUserNotFound
	}
	if !ValidTheme(theme) {
		return User{}, ErrInvalid
	}
	u.Email = email
	u.Theme = theme
	s.users[id] = u
	return u, nil
}
func (s *stubUserStore) UpdatePassword(id, hash string) error {
	if s.failOn == "UpdatePassword" {
		return s.err
	}
	u, ok := s.users[id]
	if !ok {
		return ErrUserNotFound
	}
	s.hashes[u.Username] = hash
	return nil
}

func TestRequireUserAllowsValidCookie(t *testing.T) {
	store := &stubUserStore{}
	if _, err := store.Create("alice", "h"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	tok, _ := SignSession(testSecret, "alice-id", now.Add(time.Hour))

	var seen User
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		u, ok := UserFromContext(r.Context())
		if !ok {
			t.Error("no user in ctx")
		}
		seen = u
	})
	mw := RequireUser(testSecret, store, func() time.Time { return now })

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: tok})
	w := httptest.NewRecorder()
	mw(next).ServeHTTP(w, req)

	if w.Code != http.StatusOK && w.Code != 0 {
		t.Errorf("status = %d, want passthrough", w.Code)
	}
	if seen.Username != "alice" {
		t.Errorf("user = %+v", seen)
	}
}

func TestRequireUserRejectsNoCookie(t *testing.T) {
	store := &stubUserStore{}
	mw := RequireUser(testSecret, store, nil)
	w := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("inner handler called")
	})).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireUserRejectsExpired(t *testing.T) {
	store := &stubUserStore{}
	if _, err := store.Create("alice", "h"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	tok, _ := SignSession(testSecret, "alice-id", now.Add(-time.Second))

	mw := RequireUser(testSecret, store, func() time.Time { return now })
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: tok})
	w := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("inner handler called")
	})).ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireUserRejectsDeletedUser(t *testing.T) {
	store := &stubUserStore{}
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	// Sign a cookie for a user-id that does not exist in the store.
	tok, _ := SignSession(testSecret, "ghost", now.Add(time.Hour))

	mw := RequireUser(testSecret, store, func() time.Time { return now })
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: tok})
	w := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("inner handler called")
	})).ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireUserStoreError(t *testing.T) {
	store := &stubUserStore{
		users:  map[string]User{"u": {ID: "u", Username: "x"}},
		failOn: "GetByID",
		err:    errors.New("db down"),
	}
	now := time.Now()
	tok, _ := SignSession(testSecret, "u", now.Add(time.Hour))

	mw := RequireUser(testSecret, store, func() time.Time { return now })
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: tok})
	w := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("inner handler called")
	})).ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestUserFromContextAbsent(t *testing.T) {
	if _, ok := UserFromContext(httptest.NewRequest(http.MethodGet, "/", nil).Context()); ok {
		t.Error("expected ok=false for unstamped context")
	}
}

// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// stubUserStore lets us drive RequireUser without SQLite.
type stubUserStore struct {
	users             map[string]User
	hashes            map[string]string
	count             int
	failOn            string
	err               error
	forceCountEnabled *int // when non-nil, CountEnabled returns this value
}

func (s *stubUserStore) get(id string) (User, bool) {
	u, ok := s.users[id]
	return u, ok
}

func (s *stubUserStore) put(u User) {
	if s.users == nil {
		s.users = map[string]User{}
	}
	s.users[u.ID] = u
}

func (s *stubUserStore) Count() (int, error) {
	if s.failOn == "Count" {
		return 0, s.err
	}
	return s.count, nil
}
func (s *stubUserStore) CountEnabled() (int, error) {
	if s.failOn == "CountEnabled" {
		return 0, s.err
	}
	if s.forceCountEnabled != nil {
		return *s.forceCountEnabled, nil
	}
	n := 0
	for _, u := range s.users {
		if !u.Disabled {
			n++
		}
	}
	return n, nil
}
func (s *stubUserStore) Create(username, hash string) (User, error) {
	if s.failOn == "Create" {
		return User{}, s.err
	}
	username = strings.TrimSpace(username)
	if len(username) < MinUsernameLen {
		return User{}, ErrInvalid
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
	u.MustChangePassword = false
	u.FailedAttempts = 0
	u.LockedUntil = nil
	s.users[id] = u
	return nil
}
func (s *stubUserStore) UpdatePasswordTx(_ *sql.Tx, id, hash string) error {
	return s.UpdatePassword(id, hash)
}
func (s *stubUserStore) ListUsers() ([]User, error) {
	if s.failOn == "ListUsers" {
		return nil, s.err
	}
	out := []User{}
	for _, u := range s.users {
		out = append(out, u)
	}
	return out, nil
}
func (s *stubUserStore) Delete(id string) error {
	if s.failOn == "Delete" {
		return s.err
	}
	u, ok := s.users[id]
	if !ok {
		return ErrUserNotFound
	}
	delete(s.users, id)
	delete(s.hashes, u.Username)
	s.count--
	return nil
}
func (s *stubUserStore) SetDisabled(id string, disabled bool, now time.Time) (User, error) {
	if s.failOn == "SetDisabled" {
		return User{}, s.err
	}
	u, ok := s.users[id]
	if !ok {
		return User{}, ErrUserNotFound
	}
	u.Disabled = disabled
	if disabled {
		t := now.UTC()
		u.DisabledAt = &t
	} else {
		u.DisabledAt = nil
	}
	s.users[id] = u
	return u, nil
}

func (s *stubUserStore) RecordLoginFailure(id string, lockedUntil *time.Time) (int, error) {
	if s.failOn == "RecordLoginFailure" {
		return 0, s.err
	}
	u, ok := s.users[id]
	if !ok {
		return 0, ErrUserNotFound
	}
	u.FailedAttempts++
	if lockedUntil != nil {
		t := lockedUntil.UTC()
		u.LockedUntil = &t
	}
	s.users[id] = u
	return u.FailedAttempts, nil
}

func (s *stubUserStore) ClearLoginFailures(id string) error {
	if s.failOn == "ClearLoginFailures" {
		return s.err
	}
	u, ok := s.users[id]
	if !ok {
		return ErrUserNotFound
	}
	u.FailedAttempts = 0
	u.LockedUntil = nil
	s.users[id] = u
	return nil
}

func (s *stubUserStore) AdminSetPassword(id, hash string) error {
	if s.failOn == "AdminSetPassword" {
		return s.err
	}
	u, ok := s.users[id]
	if !ok {
		return ErrUserNotFound
	}
	s.hashes[u.Username] = hash
	u.MustChangePassword = true
	u.FailedAttempts = 0
	u.LockedUntil = nil
	s.users[id] = u
	return nil
}

func (s *stubUserStore) AdminResetTOTP(id string) error {
	if s.failOn == "AdminResetTOTP" {
		return s.err
	}
	u, ok := s.users[id]
	if !ok {
		return ErrUserNotFound
	}
	u.TotpEnabled = false
	u.FailedAttempts = 0
	u.LockedUntil = nil
	s.users[id] = u
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
	req.AddCookie(&http.Cookie{Name: CookieName, Value: tok}) //nolint:gosec // G124: test cookie sent in a request; server-side attributes don't apply.
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
	req.AddCookie(&http.Cookie{Name: CookieName, Value: tok}) //nolint:gosec // G124: test cookie sent in a request; server-side attributes don't apply.
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
	req.AddCookie(&http.Cookie{Name: CookieName, Value: tok}) //nolint:gosec // G124: test cookie sent in a request; server-side attributes don't apply.
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
	req.AddCookie(&http.Cookie{Name: CookieName, Value: tok}) //nolint:gosec // G124: test cookie sent in a request; server-side attributes don't apply.
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

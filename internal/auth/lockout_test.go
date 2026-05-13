// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newLockoutTestServer(t *testing.T) (*httptest.Server, *Service, *stubUserStore) {
	t.Helper()
	store := &stubUserStore{}
	svc := NewService(store, testSecret, false)
	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, svc, store
}

func seedLockoutUser(t *testing.T, store *stubUserStore, username string) User {
	t.Helper()
	hash, err := HashPassword("correctpassword")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	u, err := store.Create(username, hash)
	if err != nil {
		t.Fatalf("seed %s: %v", username, err)
	}
	return u
}

func TestLoginBumpsFailureCounter(t *testing.T) {
	srv, _, store := newLockoutTestServer(t)
	u := seedLockoutUser(t, store, "alice")

	for i := 0; i < 3; i++ {
		resp, err := http.Post(srv.URL+"/api/auth/login", "application/json",
			strings.NewReader(`{"username":"alice","password":"wrongpassword"}`))
		if err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
		_ = resp.Body.Close()
	}
	got, _ := store.get(u.ID)
	if got.FailedAttempts != 3 {
		t.Errorf("FailedAttempts = %d, want 3", got.FailedAttempts)
	}
	if got.LockedUntil != nil {
		t.Errorf("LockedUntil = %v, want nil before threshold", got.LockedUntil)
	}
}

func TestLoginLocksAtThreshold(t *testing.T) {
	srv, _, store := newLockoutTestServer(t)
	u := seedLockoutUser(t, store, "alice")

	for i := 0; i < LockoutThreshold; i++ {
		resp, _ := http.Post(srv.URL+"/api/auth/login", "application/json",
			strings.NewReader(`{"username":"alice","password":"wrongpassword"}`))
		_ = resp.Body.Close()
	}
	got, _ := store.get(u.ID)
	if got.FailedAttempts != LockoutThreshold {
		t.Errorf("FailedAttempts = %d, want %d", got.FailedAttempts, LockoutThreshold)
	}
	if got.LockedUntil == nil {
		t.Fatal("LockedUntil = nil after threshold reached")
	}
}

func TestLoginLockedRevealsOnCorrectPassword(t *testing.T) {
	srv, _, store := newLockoutTestServer(t)
	u := seedLockoutUser(t, store, "alice")
	// Lock the user directly via the store.
	until := time.Date(2026, 5, 13, 12, 1, 0, 0, time.UTC)
	got, _ := store.get(u.ID)
	got.LockedUntil = &until
	got.FailedAttempts = LockoutThreshold
	store.put(got)

	resp, err := http.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusLocked {
		t.Errorf("status = %d, want 423", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] != "account locked" {
		t.Errorf("error = %q, want 'account locked'", body["error"])
	}
	if body["lockedUntil"] != until.UTC().Format(time.RFC3339) {
		t.Errorf("lockedUntil = %q, want %q", body["lockedUntil"], until.UTC().Format(time.RFC3339))
	}
}

func TestLoginLockedHidesOnWrongPassword(t *testing.T) {
	srv, _, store := newLockoutTestServer(t)
	u := seedLockoutUser(t, store, "alice")
	until := time.Date(2026, 5, 13, 12, 1, 0, 0, time.UTC)
	got, _ := store.get(u.ID)
	got.LockedUntil = &until
	got.FailedAttempts = LockoutThreshold
	store.put(got)

	resp, err := http.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"wrongpassword"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (opaque on wrong pw + lock)", resp.StatusCode)
	}
	// Counter must not bump on an already-locked attempt.
	got, _ = store.get(u.ID)
	if got.FailedAttempts != LockoutThreshold {
		t.Errorf("FailedAttempts = %d, want %d (no bump on already-locked)", got.FailedAttempts, LockoutThreshold)
	}
}

func TestLoginSuccessClearsLockout(t *testing.T) {
	srv, _, store := newLockoutTestServer(t)
	u := seedLockoutUser(t, store, "alice")
	got, _ := store.get(u.ID)
	got.FailedAttempts = 3
	store.put(got)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp, err := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	got, _ = store.get(u.ID)
	if got.FailedAttempts != 0 {
		t.Errorf("FailedAttempts after success = %d, want 0", got.FailedAttempts)
	}
}

func TestLoginExpiredLockoutAllows(t *testing.T) {
	srv, svc, store := newLockoutTestServer(t)
	u := seedLockoutUser(t, store, "alice")
	// Lock with an expiry that's already in the past relative to svc.Now.
	old := svc.Now().Add(-time.Minute)
	got, _ := store.get(u.ID)
	got.LockedUntil = &old
	got.FailedAttempts = LockoutThreshold
	store.put(got)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp, err := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (lockout expired)", resp.StatusCode)
	}
}

func TestThrottle429AfterLimit(t *testing.T) {
	srv, svc, store := newLockoutTestServer(t)
	seedLockoutUser(t, store, "alice")
	svc.LoginThrottle = NewThrottle(time.Minute, 3, svc.Now)

	var lastStatus int
	for i := 0; i < 5; i++ {
		resp, err := http.Post(srv.URL+"/api/auth/login", "application/json",
			strings.NewReader(`{"username":"alice","password":"wrongpassword"}`))
		if err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
		lastStatus = resp.StatusCode
		_ = resp.Body.Close()
	}
	if lastStatus != http.StatusTooManyRequests {
		t.Errorf("last status = %d, want 429", lastStatus)
	}
}

func TestThrottle429ProvidesRetryAfter(t *testing.T) {
	srv, svc, store := newLockoutTestServer(t)
	seedLockoutUser(t, store, "alice")
	svc.LoginThrottle = NewThrottle(time.Minute, 1, svc.Now)

	resp, _ := http.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"wrongpassword"}`))
	_ = resp.Body.Close()
	resp2, err := http.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"wrongpassword"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp2.StatusCode)
	}
	if resp2.Header.Get("Retry-After") == "" {
		t.Error("Retry-After header missing on 429")
	}
}

func TestLoginUnknownUserStillThrottles(t *testing.T) {
	srv, svc, _ := newLockoutTestServer(t)
	svc.LoginThrottle = NewThrottle(time.Minute, 2, svc.Now)

	for i := 0; i < 2; i++ {
		resp, _ := http.Post(srv.URL+"/api/auth/login", "application/json",
			strings.NewReader(`{"username":"ghost","password":"correctpassword"}`))
		_ = resp.Body.Close()
	}
	resp, _ := http.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"ghost","password":"correctpassword"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429 (per-IP throttle on missing user)", resp.StatusCode)
	}
}

func TestMustChangePasswordBlocksProtected(t *testing.T) {
	store := &stubUserStore{}
	svc := NewService(store, testSecret, false)
	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }
	mux := http.NewServeMux()
	svc.Register(mux)
	mw := RequireUser(testSecret, store, func() time.Time { return now })
	svc.RegisterProtected(mux, mw)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	u := seedLockoutUser(t, store, "alice")
	got, _ := store.get(u.ID)
	got.MustChangePassword = true
	store.put(got)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	loginResp, err := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	_ = loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", loginResp.StatusCode)
	}

	// /profile must be gated.
	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/auth/profile",
		strings.NewReader(`{"email":"a@b","theme":""}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("patch profile: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("profile status = %d, want 403; body=%s", resp.StatusCode, body)
	}
}

func TestMustChangePasswordAllowsPasswordChange(t *testing.T) {
	store := &stubUserStore{}
	svc := NewService(store, testSecret, false)
	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }
	mux := http.NewServeMux()
	svc.Register(mux)
	mw := RequireUser(testSecret, store, func() time.Time { return now })
	svc.RegisterProtected(mux, mw)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	u := seedLockoutUser(t, store, "alice")
	got, _ := store.get(u.ID)
	got.MustChangePassword = true
	store.put(got)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	loginResp, _ := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	_ = loginResp.Body.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/password",
		strings.NewReader(`{"currentPassword":"correctpassword","newPassword":"freshpassword"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post password: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, want 204; body=%s", resp.StatusCode, body)
	}
	got, _ = store.get(u.ID)
	if got.MustChangePassword {
		t.Error("MustChangePassword still set after self-change")
	}
}

func TestStatusExposesMustChangePassword(t *testing.T) {
	srv, _, store := newLockoutTestServer(t)
	u := seedLockoutUser(t, store, "alice")
	got, _ := store.get(u.ID)
	got.MustChangePassword = true
	store.put(got)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	loginResp, _ := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	_ = loginResp.Body.Close()

	statusResp, err := client.Get(srv.URL + "/api/auth/status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	defer func() { _ = statusResp.Body.Close() }()
	var body statusResponse
	_ = json.NewDecoder(statusResp.Body).Decode(&body)
	if body.User == nil || !body.User.MustChangePassword {
		t.Errorf("status user = %+v, want MustChangePassword true", body.User)
	}
}

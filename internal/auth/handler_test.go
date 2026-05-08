// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestService(t *testing.T) (*Service, *stubUserStore) {
	t.Helper()
	store := &stubUserStore{}
	svc := NewService(store, testSecret, false)
	svc.Now = func() time.Time { return time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC) }
	return svc, store
}

func newTestServer(t *testing.T) (*httptest.Server, *Service, *stubUserStore) {
	t.Helper()
	svc, store := newTestService(t)
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, svc, store
}

func TestStatusEmptyDB(t *testing.T) {
	srv, _, _ := newTestServer(t)
	resp, err := http.Get(srv.URL + "/api/auth/status")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body statusResponse
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if !body.SetupRequired || body.Authenticated {
		t.Errorf("got %+v, want setup_required=true authenticated=false", body)
	}
}

func TestSetupSucceedsThenIsBlocked(t *testing.T) {
	srv, _, store := newTestServer(t)
	resp, err := http.Post(srv.URL+"/api/auth/setup", "application/json",
		strings.NewReader(`{"username":"admin","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	cookies := resp.Cookies()
	var hasSession bool
	for _, c := range cookies {
		if c.Name == CookieName && c.Value != "" {
			hasSession = true
		}
	}
	if !hasSession {
		t.Error("session cookie not set on setup response")
	}
	if store.count != 1 {
		t.Errorf("store count = %d, want 1", store.count)
	}

	// Second setup must fail with 403.
	resp2, err := http.Post(srv.URL+"/api/auth/setup", "application/json",
		strings.NewReader(`{"username":"another","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("setup2: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("second setup status = %d, want 403", resp2.StatusCode)
	}
}

func TestSetupValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		body string
		want int
	}{
		{"missing username", `{"password":"correctpassword"}`, http.StatusBadRequest},
		{"missing password", `{"username":"x"}`, http.StatusBadRequest},
		{"short password", `{"username":"x","password":"short"}`, http.StatusBadRequest},
		{"bad json", `not json`, http.StatusBadRequest},
		{"unknown field", `{"username":"x","password":"correctpassword","extra":1}`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, _, _ := newTestServer(t)
			resp, err := http.Post(srv.URL+"/api/auth/setup", "application/json", strings.NewReader(tt.body))
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tt.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.want)
			}
		})
	}
}

func TestLoginAndStatusFlow(t *testing.T) {
	srv, svc, store := newTestServer(t)

	// Seed a user with a real bcrypt hash.
	hash, _ := HashPassword("correctpassword")
	if _, err := store.Create("alice", hash); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// Wrong password.
	resp, err := http.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"wrongpassword"}`))
	if err != nil {
		t.Fatalf("login wrong: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong-password status = %d, want 401", resp.StatusCode)
	}

	// Right password.
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	loginResp, err := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = loginResp.Body.Close() }()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", loginResp.StatusCode)
	}

	// Now /status should report authenticated.
	statusResp, err := client.Get(srv.URL + "/api/auth/status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	defer func() { _ = statusResp.Body.Close() }()
	var body statusResponse
	_ = json.NewDecoder(statusResp.Body).Decode(&body)
	if !body.Authenticated || body.User == nil || body.User.Username != "alice" {
		t.Errorf("status body = %+v", body)
	}

	// Logout clears.
	logoutResp, err := client.Post(srv.URL+"/api/auth/logout", "application/json", nil)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	_ = logoutResp.Body.Close()
	if logoutResp.StatusCode != http.StatusNoContent {
		t.Errorf("logout status = %d", logoutResp.StatusCode)
	}

	// Confirm cookie delete went through and status is anonymous again.
	statusResp2, err := client.Get(srv.URL + "/api/auth/status")
	if err != nil {
		t.Fatalf("post-logout status: %v", err)
	}
	defer func() { _ = statusResp2.Body.Close() }()
	var body2 statusResponse
	_ = json.NewDecoder(statusResp2.Body).Decode(&body2)
	if body2.Authenticated {
		t.Errorf("still authenticated after logout: %+v", body2)
	}

	_ = svc // referenced for clarity; not needed in this test
}

func TestLoginUnknownUser(t *testing.T) {
	srv, _, _ := newTestServer(t)
	resp, err := http.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"nobody","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestLoginBadInput(t *testing.T) {
	srv, _, _ := newTestServer(t)
	resp, err := http.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"","password":""}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// TestHandlerStoreErrors exercises the 500 paths on each endpoint by injecting
// a store that fails the relevant call.
func TestHandlerStoreErrors(t *testing.T) {
	tests := []struct {
		name   string
		failOn string
		// builder describes the request; status path each handler takes
		// when the named method on the store returns an error.
		method string
		path   string
		body   string
		want   int
	}{
		{
			name: "status count fails", failOn: "Count",
			method: http.MethodGet, path: "/api/auth/status",
			want: http.StatusInternalServerError,
		},
		{
			name: "setup count fails", failOn: "Count",
			method: http.MethodPost, path: "/api/auth/setup",
			body: `{"username":"u","password":"correctpassword"}`,
			want: http.StatusInternalServerError,
		},
		{
			name: "login lookup fails", failOn: "GetByUsername",
			method: http.MethodPost, path: "/api/auth/login",
			body: `{"username":"u","password":"correctpassword"}`,
			want: http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &stubUserStore{failOn: tt.failOn, err: errors.New("db down")}
			svc := NewService(store, testSecret, false)
			svc.Now = func() time.Time { return time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC) }
			mux := http.NewServeMux()
			svc.Register(mux)
			srv := httptest.NewServer(mux)
			defer srv.Close()

			var resp *http.Response
			var err error
			if tt.method == http.MethodGet {
				resp, err = http.Get(srv.URL + tt.path)
			} else {
				resp, err = http.Post(srv.URL+tt.path, "application/json", strings.NewReader(tt.body))
			}
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tt.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.want)
			}
		})
	}
}

// TestSetupCreateConflict covers the rare case where Count returns 0 but
// Create still rejects the username (concurrent setup attempt would race
// here — exercised via the stub).
func TestSetupCreateConflict(t *testing.T) {
	store := &stubUserStore{failOn: "Create", err: ErrUserExists}
	svc := NewService(store, testSecret, false)
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/auth/setup", "application/json",
		strings.NewReader(`{"username":"u","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

// newProtectedTestServer wires both Register and RegisterProtected behind
// the real RequireUser middleware so profile/password endpoints can be
// exercised end-to-end.
func newProtectedTestServer(t *testing.T) (*httptest.Server, *Service, *stubUserStore) {
	t.Helper()
	store := &stubUserStore{}
	svc := NewService(store, testSecret, false)
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }
	mux := http.NewServeMux()
	svc.Register(mux)
	mw := RequireUser(testSecret, store, func() time.Time { return now })
	svc.RegisterProtected(mux, mw)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, svc, store
}

func loggedInClient(t *testing.T, srv *httptest.Server, username string) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp, err := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"`+username+`","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", resp.StatusCode)
	}
	return client
}

func TestUpdateProfileHappyPath(t *testing.T) {
	srv, _, store := newProtectedTestServer(t)
	hash, _ := HashPassword("correctpassword")
	if _, err := store.Create("alice", hash); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	client := loggedInClient(t, srv, "alice")

	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/auth/profile",
		strings.NewReader(`{"email":"alice@example.com","theme":"light"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	var got User
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Email != "alice@example.com" || got.Theme != "light" {
		t.Errorf("got %+v", got)
	}
}

func TestUpdateProfileRequiresAuth(t *testing.T) {
	srv, _, _ := newProtectedTestServer(t)
	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/auth/profile",
		strings.NewReader(`{"email":"x","theme":"dark"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestUpdateProfileValidation(t *testing.T) {
	srv, _, store := newProtectedTestServer(t)
	hash, _ := HashPassword("correctpassword")
	if _, err := store.Create("alice", hash); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	client := loggedInClient(t, srv, "alice")

	tests := []struct {
		name string
		body string
		want int
	}{
		{"bad json", `not json`, http.StatusBadRequest},
		{"unknown field", `{"email":"a","theme":"dark","extra":1}`, http.StatusBadRequest},
		{"invalid theme", `{"email":"a","theme":"neon"}`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/auth/profile",
				strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("patch: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tt.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.want)
			}
		})
	}
}

func TestUpdateProfileStoreFailure(t *testing.T) {
	srv, _, store := newProtectedTestServer(t)
	hash, _ := HashPassword("correctpassword")
	if _, err := store.Create("alice", hash); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	client := loggedInClient(t, srv, "alice")

	store.failOn = "UpdateProfile"
	store.err = errors.New("db down")

	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/auth/profile",
		strings.NewReader(`{"email":"a","theme":"dark"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestUpdateProfileUserGone(t *testing.T) {
	srv, _, store := newProtectedTestServer(t)
	hash, _ := HashPassword("correctpassword")
	if _, err := store.Create("alice", hash); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	client := loggedInClient(t, srv, "alice")

	store.failOn = "UpdateProfile"
	store.err = ErrUserNotFound

	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/auth/profile",
		strings.NewReader(`{"email":"a","theme":"dark"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestChangePasswordHappyPath(t *testing.T) {
	srv, _, store := newProtectedTestServer(t)
	hash, _ := HashPassword("correctpassword")
	if _, err := store.Create("alice", hash); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	client := loggedInClient(t, srv, "alice")

	resp, err := client.Post(srv.URL+"/api/auth/password", "application/json",
		strings.NewReader(`{"currentPassword":"correctpassword","newPassword":"newsecretpw"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	// Confirm we can log in with the new password and not the old one.
	resp2, _ := http.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("old pw login status = %d, want 401", resp2.StatusCode)
	}
	resp3, _ := http.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"newsecretpw"}`))
	_ = resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("new pw login status = %d, want 200", resp3.StatusCode)
	}
}

func TestChangePasswordRequiresCurrent(t *testing.T) {
	srv, _, store := newProtectedTestServer(t)
	hash, _ := HashPassword("correctpassword")
	if _, err := store.Create("alice", hash); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	client := loggedInClient(t, srv, "alice")

	resp, err := client.Post(srv.URL+"/api/auth/password", "application/json",
		strings.NewReader(`{"currentPassword":"wrongone","newPassword":"newsecretpw"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestChangePasswordValidation(t *testing.T) {
	srv, _, store := newProtectedTestServer(t)
	hash, _ := HashPassword("correctpassword")
	if _, err := store.Create("alice", hash); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	client := loggedInClient(t, srv, "alice")

	tests := []struct {
		name string
		body string
		want int
	}{
		{"bad json", `not json`, http.StatusBadRequest},
		{"missing fields", `{"currentPassword":""}`, http.StatusBadRequest},
		{"unknown field", `{"currentPassword":"a","newPassword":"b","x":1}`, http.StatusBadRequest},
		{"too short", `{"currentPassword":"correctpassword","newPassword":"short"}`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.Post(srv.URL+"/api/auth/password", "application/json",
				strings.NewReader(tt.body))
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tt.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.want)
			}
		})
	}
}

func TestChangePasswordRequiresAuth(t *testing.T) {
	srv, _, _ := newProtectedTestServer(t)
	resp, err := http.Post(srv.URL+"/api/auth/password", "application/json",
		strings.NewReader(`{"currentPassword":"a","newPassword":"correctpassword"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestChangePasswordHashLoadFails(t *testing.T) {
	srv, _, store := newProtectedTestServer(t)
	hash, _ := HashPassword("correctpassword")
	if _, err := store.Create("alice", hash); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	client := loggedInClient(t, srv, "alice")

	store.failOn = "GetHashByID"
	store.err = errors.New("db down")
	resp, err := client.Post(srv.URL+"/api/auth/password", "application/json",
		strings.NewReader(`{"currentPassword":"correctpassword","newPassword":"newsecretpw"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestChangePasswordUpdateFails(t *testing.T) {
	srv, _, store := newProtectedTestServer(t)
	hash, _ := HashPassword("correctpassword")
	if _, err := store.Create("alice", hash); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	client := loggedInClient(t, srv, "alice")

	store.failOn = "UpdatePassword"
	store.err = errors.New("db down")
	resp, err := client.Post(srv.URL+"/api/auth/password", "application/json",
		strings.NewReader(`{"currentPassword":"correctpassword","newPassword":"newsecretpw"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

// TestProtectedHandlersWithoutContext exercises the (very narrow) defensive
// branch where the protected handler is invoked without RequireUser having
// stamped a user onto the context. In production that's impossible — but
// we keep the explicit 401 so a misconfigured mux fails closed.
func TestProtectedHandlersWithoutContext(t *testing.T) {
	store := &stubUserStore{}
	svc := NewService(store, testSecret, false)

	tests := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		body    string
	}{
		{"profile", svc.handleUpdateProfile, http.MethodPatch, `{"email":"a","theme":"dark"}`},
		{"password", svc.handleChangePassword, http.MethodPost, `{"currentPassword":"a","newPassword":"correctpassword"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/x", strings.NewReader(tt.body))
			w := httptest.NewRecorder()
			tt.handler(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", w.Code)
			}
		})
	}
}

// TestSetupInvalidUsername covers the ErrInvalid-from-Create path.
func TestSetupInvalidUsername(t *testing.T) {
	store := &stubUserStore{failOn: "Create", err: ErrInvalid}
	svc := NewService(store, testSecret, false)
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/auth/setup", "application/json",
		strings.NewReader(`{"username":"u","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

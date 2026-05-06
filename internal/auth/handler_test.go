// SPDX-License-Identifier: AGPL-3.0-or-later

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
	defer resp.Body.Close()
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
	defer resp.Body.Close()
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
	defer resp2.Body.Close()
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
			defer resp.Body.Close()
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
	store.Create("alice", hash)

	// Wrong password.
	resp, err := http.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"wrongpassword"}`))
	if err != nil {
		t.Fatalf("login wrong: %v", err)
	}
	resp.Body.Close()
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
	defer loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", loginResp.StatusCode)
	}

	// Now /status should report authenticated.
	statusResp, err := client.Get(srv.URL + "/api/auth/status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	defer statusResp.Body.Close()
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
	logoutResp.Body.Close()
	if logoutResp.StatusCode != http.StatusNoContent {
		t.Errorf("logout status = %d", logoutResp.StatusCode)
	}

	// Confirm cookie delete went through and status is anonymous again.
	statusResp2, err := client.Get(srv.URL + "/api/auth/status")
	if err != nil {
		t.Fatalf("post-logout status: %v", err)
	}
	defer statusResp2.Body.Close()
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
	defer resp.Body.Close()
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
	defer resp.Body.Close()
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
			defer resp.Body.Close()
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
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
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
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

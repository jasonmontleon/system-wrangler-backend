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

func newAdminTestServer(t *testing.T) (*httptest.Server, *Service, *stubUserStore) {
	t.Helper()
	store := &stubUserStore{}
	svc := NewService(store, testSecret, false)
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }
	mux := http.NewServeMux()
	svc.Register(mux)
	mw := RequireUser(testSecret, store, func() time.Time { return now })
	svc.RegisterAdmin(mux, mw)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, svc, store
}

func seedUser(t *testing.T, store *stubUserStore, username string) User {
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

func TestAdminListUsersRequiresAuth(t *testing.T) {
	srv, _, _ := newAdminTestServer(t)
	resp, err := http.Get(srv.URL + "/api/admin/users")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAdminListUsers(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")

	resp, err := client.Get(srv.URL + "/api/admin/users")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	var got struct {
		Users []User `json:"users"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Users) != 2 {
		t.Errorf("len = %d, want 2", len(got.Users))
	}
}

func TestAdminListUsersStoreError(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	client := loggedInClient(t, srv, "alice")
	store.failOn = "ListUsers"
	store.err = errAdminTest{}
	resp, err := client.Get(srv.URL + "/api/admin/users")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestAdminCreateUserHappyPath(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	client := loggedInClient(t, srv, "alice")

	resp, err := client.Post(srv.URL+"/api/admin/users", "application/json",
		strings.NewReader(`{"username":"bob","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	var got User
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Username != "bob" || got.Disabled {
		t.Errorf("got %+v", got)
	}
	if store.count != 2 {
		t.Errorf("store count = %d, want 2", store.count)
	}
}

func TestAdminCreateUserRequiresAuth(t *testing.T) {
	srv, _, _ := newAdminTestServer(t)
	resp, err := http.Post(srv.URL+"/api/admin/users", "application/json",
		strings.NewReader(`{"username":"x","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAdminCreateUserValidation(t *testing.T) {
	tests := []struct {
		name string
		body string
		want int
	}{
		{"bad json", `not json`, http.StatusBadRequest},
		{"unknown field", `{"username":"u","password":"correctpassword","x":1}`, http.StatusBadRequest},
		{"short password", `{"username":"u","password":"short"}`, http.StatusBadRequest},
		{"empty username", `{"username":"","password":"correctpassword"}`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, _, store := newAdminTestServer(t)
			seedUser(t, store, "alice")
			client := loggedInClient(t, srv, "alice")
			resp, err := client.Post(srv.URL+"/api/admin/users", "application/json",
				strings.NewReader(tt.body))
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tt.want {
				body, _ := io.ReadAll(resp.Body)
				t.Errorf("status = %d, want %d, body=%s", resp.StatusCode, tt.want, body)
			}
		})
	}
}

func TestAdminCreateUserDuplicate(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	client := loggedInClient(t, srv, "alice")
	store.failOn = "Create"
	store.err = ErrUserExists
	resp, err := client.Post(srv.URL+"/api/admin/users", "application/json",
		strings.NewReader(`{"username":"bob","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
}

func TestAdminCreateUserStoreError(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	client := loggedInClient(t, srv, "alice")
	store.failOn = "Create"
	store.err = errAdminTest{}
	resp, err := client.Post(srv.URL+"/api/admin/users", "application/json",
		strings.NewReader(`{"username":"bob","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestAdminDisableThenEnableUser(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")

	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/admin/users/"+bob.ID,
		strings.NewReader(`{"disabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("disable status = %d, body=%s", resp.StatusCode, body)
	}
	var disabled User
	if err := json.NewDecoder(resp.Body).Decode(&disabled); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !disabled.Disabled || disabled.DisabledAt == nil {
		t.Errorf("after disable: %+v", disabled)
	}

	req2, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/admin/users/"+bob.ID,
		strings.NewReader(`{"disabled":false}`))
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("patch enable: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("re-enable status = %d, want 200", resp2.StatusCode)
	}
	var enabled User
	_ = json.NewDecoder(resp2.Body).Decode(&enabled)
	if enabled.Disabled {
		t.Error("re-enable: still disabled")
	}
}

func TestAdminCannotDisableSelf(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	alice := seedUser(t, store, "alice")
	seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")

	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/admin/users/"+alice.ID,
		strings.NewReader(`{"disabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// TestAdminCannotDisableLastEnabled drives the guard by forcing
// CountEnabled to return 1 via the stub override. In real flow the guard
// is belt-and-suspenders (any caller is themselves enabled, so the
// underlying invariant catches the "leave zero enabled" case), but we
// keep the explicit check and prove it fires.
func TestAdminCannotDisableLastEnabled(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")
	one := 1
	store.forceCountEnabled = &one

	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/admin/users/"+bob.ID,
		strings.NewReader(`{"disabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, want 400, body=%s", resp.StatusCode, body)
	}
}

// Re-enabling an already-disabled user must skip the CountEnabled check
// entirely (since re-enable can only increase the count).
func TestAdminEnableSkipsCountCheck(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	if _, err := store.SetDisabled(bob.ID, true, time.Now()); err != nil {
		t.Fatalf("pre-disable bob: %v", err)
	}
	one := 1
	store.forceCountEnabled = &one // would trip if the guard fired
	client := loggedInClient(t, srv, "alice")

	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/admin/users/"+bob.ID,
		strings.NewReader(`{"disabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (guard should not fire on enable)", resp.StatusCode)
	}
}

func TestAdminUpdateUserNotFound(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	client := loggedInClient(t, srv, "alice")

	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/admin/users/ghost",
		strings.NewReader(`{"disabled":true}`))
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

func TestAdminUpdateUserBadRequest(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")

	for _, tt := range []struct {
		name string
		body string
	}{
		{"bad json", `not json`},
		{"no fields", `{}`},
		{"unknown field", `{"disabled":true,"x":1}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/admin/users/"+bob.ID,
				strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("patch: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
		})
	}
}

func TestAdminUpdateUserStoreErrors(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")

	tests := []struct {
		failOn string
		want   int
	}{
		{"GetByID", http.StatusInternalServerError},
		{"CountEnabled", http.StatusInternalServerError},
		{"SetDisabled", http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.failOn, func(t *testing.T) {
			store.failOn = tt.failOn
			store.err = errAdminTest{}
			req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/admin/users/"+bob.ID,
				strings.NewReader(`{"disabled":true}`))
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("patch: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != tt.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.want)
			}
		})
	}
	store.failOn = ""
}

func TestAdminLoginRejectsDisabledUser(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	alice := seedUser(t, store, "alice")
	if _, err := store.SetDisabled(alice.ID, true, time.Now()); err != nil {
		t.Fatalf("disable: %v", err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp, err := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAdminMiddlewareRejectsDisabledMidSession(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	alice := seedUser(t, store, "alice")
	client := loggedInClient(t, srv, "alice")
	if _, err := store.SetDisabled(alice.ID, true, time.Now()); err != nil {
		t.Fatalf("disable: %v", err)
	}
	resp, err := client.Get(srv.URL + "/api/admin/users")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 after disable", resp.StatusCode)
	}
}

func TestAdminRegisterNilMiddleware(t *testing.T) {
	store := &stubUserStore{}
	svc := NewService(store, testSecret, false)
	mux := http.NewServeMux()
	svc.RegisterAdmin(mux, nil)
	// Should compile + register without panicking; route is reachable.
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/api/admin/users")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = resp.Body.Close()
}

func TestAdminDeleteUser(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	if _, err := store.SetDisabled(bob.ID, true, time.Now()); err != nil {
		t.Fatalf("disable bob: %v", err)
	}
	client := loggedInClient(t, srv, "alice")

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/admin/users/"+bob.ID, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 204, body=%s", resp.StatusCode, body)
	}
	if _, err := store.GetByID(bob.ID); err == nil {
		t.Error("bob still present after delete")
	}
}

func TestAdminDeleteUserEnabledRemoved(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	seedUser(t, store, "carol")
	client := loggedInClient(t, srv, "alice")

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/admin/users/"+bob.ID, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, want 204, body=%s", resp.StatusCode, body)
	}
}

func TestAdminCannotDeleteSelf(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	alice := seedUser(t, store, "alice")
	seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/admin/users/"+alice.ID, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminCannotDeleteLastEnabled(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")
	one := 1
	store.forceCountEnabled = &one

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/admin/users/"+bob.ID, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminDeleteUserNotFound(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	client := loggedInClient(t, srv, "alice")

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/admin/users/ghost", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAdminDeleteUserStoreErrors(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")

	tests := []struct {
		failOn string
		want   int
	}{
		{"GetByID", http.StatusInternalServerError},
		{"CountEnabled", http.StatusInternalServerError},
		{"Delete", http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.failOn, func(t *testing.T) {
			store.failOn = tt.failOn
			store.err = errAdminTest{}
			req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/admin/users/"+bob.ID, nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("delete: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != tt.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.want)
			}
		})
	}
	store.failOn = ""
}

func TestAdminDeleteUserRequiresAuth(t *testing.T) {
	srv, _, _ := newAdminTestServer(t)
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/admin/users/x", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

type errAdminTest struct{}

func (errAdminTest) Error() string { return "admin test error" }

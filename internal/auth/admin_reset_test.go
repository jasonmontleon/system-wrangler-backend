// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"system-wrangler-backend/internal/database"
)

func TestAdminResetPasswordSetsMustChange(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")

	resp, err := client.Post(
		srv.URL+"/api/admin/users/"+bob.ID+"/password",
		"application/json",
		strings.NewReader(`{"password":"newadminset"}`),
	)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	got, _ := store.get(bob.ID)
	if !got.MustChangePassword {
		t.Error("MustChangePassword not set after admin reset")
	}
	if store.hashes["bob"] == "" {
		t.Error("hash not updated")
	}
}

func TestAdminResetPasswordClearsLockout(t *testing.T) {
	srv, svc, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")

	// Lock bob.
	until := svc.Now().Add(10 * 60 * 1e9) // 10 min
	got, _ := store.get(bob.ID)
	got.FailedAttempts = LockoutThreshold
	got.LockedUntil = &until
	store.put(got)

	resp, err := client.Post(
		srv.URL+"/api/admin/users/"+bob.ID+"/password",
		"application/json",
		strings.NewReader(`{"password":"newadminset"}`),
	)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	got, _ = store.get(bob.ID)
	if got.FailedAttempts != 0 || got.LockedUntil != nil {
		t.Errorf("lockout not cleared: attempts=%d lockedUntil=%v", got.FailedAttempts, got.LockedUntil)
	}
}

func TestAdminResetPasswordRejectsSelf(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	alice := seedUser(t, store, "alice")
	client := loggedInClient(t, srv, "alice")

	resp, err := client.Post(
		srv.URL+"/api/admin/users/"+alice.ID+"/password",
		"application/json",
		strings.NewReader(`{"password":"newadminset"}`),
	)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminResetPasswordShortPassword(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")

	resp, err := client.Post(
		srv.URL+"/api/admin/users/"+bob.ID+"/password",
		"application/json",
		strings.NewReader(`{"password":"short"}`),
	)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for short password", resp.StatusCode)
	}
}

func TestAdminResetPasswordNotFound(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	client := loggedInClient(t, srv, "alice")

	resp, err := client.Post(
		srv.URL+"/api/admin/users/missing/password",
		"application/json",
		strings.NewReader(`{"password":"newadminset"}`),
	)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAdminResetPasswordBadJSON(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")

	resp, err := client.Post(
		srv.URL+"/api/admin/users/"+bob.ID+"/password",
		"application/json",
		strings.NewReader(`not json`),
	)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminResetPasswordLookupError(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")
	store.failOn = "GetByID"
	store.err = errAdminTest{}

	resp, err := client.Post(
		srv.URL+"/api/admin/users/"+bob.ID+"/password",
		"application/json",
		strings.NewReader(`{"password":"newadminset"}`),
	)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestAdminResetTOTPLookupError(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")
	store.failOn = "GetByID"
	store.err = errAdminTest{}

	resp, err := client.Post(
		srv.URL+"/api/admin/users/"+bob.ID+"/totp/reset",
		"application/json",
		nil,
	)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestAdminResetTOTPStoreError(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")
	store.failOn = "AdminResetTOTP"
	store.err = errAdminTest{}

	resp, err := client.Post(
		srv.URL+"/api/admin/users/"+bob.ID+"/totp/reset",
		"application/json",
		nil,
	)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestAdminResetPasswordEmptyPassword(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")

	resp, err := client.Post(
		srv.URL+"/api/admin/users/"+bob.ID+"/password",
		"application/json",
		strings.NewReader(`{"password":""}`),
	)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	// HashPassword rejects empty as ErrInvalid → 400.
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminResetPasswordSetPasswordNotFound(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")
	store.failOn = "AdminSetPassword"
	store.err = ErrUserNotFound

	resp, err := client.Post(
		srv.URL+"/api/admin/users/"+bob.ID+"/password",
		"application/json",
		strings.NewReader(`{"password":"newadminset"}`),
	)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAdminResetTOTPNotFoundFromReset(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")
	store.failOn = "AdminResetTOTP"
	store.err = ErrUserNotFound

	resp, err := client.Post(
		srv.URL+"/api/admin/users/"+bob.ID+"/totp/reset",
		"application/json",
		nil,
	)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAdminDeleteUserLastGlobalAdmin(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")
	store.failOn = "Delete"
	store.err = ErrLastGlobalAdmin

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/admin/users/"+bob.ID, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
}

func TestAdminDeleteUserCountError(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")
	store.failOn = "CountEnabled"
	store.err = errAdminTest{}

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/admin/users/"+bob.ID, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestAdminDeleteUserLookupError(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")
	store.failOn = "GetByID"
	store.err = errAdminTest{}

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/admin/users/"+bob.ID, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandleStatusCountError(t *testing.T) {
	store := &stubUserStore{failOn: "Count", err: errAdminTest{}}
	svc := NewService(store, testSecret, false)
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/auth/status")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandleSetupCountError(t *testing.T) {
	store := &stubUserStore{failOn: "Count", err: errAdminTest{}}
	svc := NewService(store, testSecret, false)
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/auth/setup", "application/json",
		strings.NewReader(`{"username":"admin","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandleSetupAlreadyComplete(t *testing.T) {
	store := &stubUserStore{count: 1}
	svc := NewService(store, testSecret, false)
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/auth/setup", "application/json",
		strings.NewReader(`{"username":"admin","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHandleSetupBadJSON(t *testing.T) {
	store := &stubUserStore{}
	svc := NewService(store, testSecret, false)
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/auth/setup", "application/json",
		strings.NewReader("not json"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandleSetupShortPassword(t *testing.T) {
	store := &stubUserStore{}
	svc := NewService(store, testSecret, false)
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/auth/setup", "application/json",
		strings.NewReader(`{"username":"admin","password":"x"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminCreateUserUnauthorized(t *testing.T) {
	svc := NewService(&stubUserStore{}, testSecret, false)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/admin/users",
		strings.NewReader(`{"username":"x","password":"y"}`))
	svc.handleCreateUser(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", w.Code)
	}
}

func TestAdminUpdateUserUnauthorized(t *testing.T) {
	svc := NewService(&stubUserStore{}, testSecret, false)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPatch, "/api/admin/users/x",
		strings.NewReader(`{"disabled":true}`))
	svc.handleUpdateUser(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", w.Code)
	}
}

func TestAdminDeleteUserUnauthorized(t *testing.T) {
	svc := NewService(&stubUserStore{}, testSecret, false)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/admin/users/x", nil)
	svc.handleDeleteUser(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", w.Code)
	}
}

func TestAdminResetPasswordUnauthorized(t *testing.T) {
	svc := NewService(&stubUserStore{}, testSecret, false)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/admin/users/x/password",
		strings.NewReader(`{"password":"y"}`))
	svc.handleAdminResetPassword(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", w.Code)
	}
}

func TestAdminResetTOTPUnauthorized(t *testing.T) {
	svc := NewService(&stubUserStore{}, testSecret, false)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/admin/users/x/totp/reset", nil)
	svc.handleAdminResetTOTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", w.Code)
	}
}

func TestAdminUpdateUserBadJSON(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")
	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/admin/users/"+bob.ID,
		strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminUpdateUserDisableSelfRejected(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	alice := seedUser(t, store, "alice")
	client := loggedInClient(t, srv, "alice")
	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/admin/users/"+alice.ID,
		strings.NewReader(`{"disabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (self-disable refused)", resp.StatusCode)
	}
}

func TestAdminUpdateUserSetDisabledNotFound(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	carol := seedUser(t, store, "carol")
	_ = carol
	client := loggedInClient(t, srv, "alice")
	store.failOn = "SetDisabled"
	store.err = ErrUserNotFound
	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/admin/users/"+bob.ID,
		strings.NewReader(`{"disabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// TestSQLiteAuthStoreClosedDBSurfacesErrors closes the underlying *sql.DB
// and then calls every public method on the store, asserting each one
// returns a non-nil error. This bulk-covers the "if err != nil { return
// ... }" branch on each db.Exec / db.Query call, which is unreachable
// against a healthy in-memory DB but lives on the hot path the moment
// the operator's disk goes read-only or the pool gets torn down mid-
// request.
func TestSQLiteAuthStoreClosedDBSurfacesErrors(t *testing.T) {
	dsn := "file:" + t.TempDir() + "/closed.db"
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	store, err := NewSQLiteAuthStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteAuthStore: %v", err)
	}
	// Seed a user before closing so the GetBy* methods have a target.
	u, err := store.Create("ghost", "hashbytes")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	type call struct {
		name string
		fn   func() error
	}
	calls := []call{
		{"Count", func() error { _, err := store.Count(); return err }},
		{"CountEnabled", func() error { _, err := store.CountEnabled(); return err }},
		{"Create", func() error { _, err := store.Create("a", "h"); return err }},
		{"GetByUsername", func() error { _, _, err := store.GetByUsername("ghost"); return err }},
		{"GetByID", func() error { _, err := store.GetByID(u.ID); return err }},
		{"GetHashByID", func() error { _, err := store.GetHashByID(u.ID); return err }},
		{"UpdateProfile", func() error { _, err := store.UpdateProfile(u.ID, "e", "dark"); return err }},
		{"UpdatePassword", func() error { return store.UpdatePassword(u.ID, "newh") }},
		{"ClearLoginFailures", func() error { return store.ClearLoginFailures(u.ID) }},
		{"RecordLoginFailure", func() error { _, err := store.RecordLoginFailure(u.ID, nil); return err }},
		{"SetDisabled", func() error { _, err := store.SetDisabled(u.ID, true, time.Now()); return err }},
		{"ListUsers", func() error { _, err := store.ListUsers(); return err }},
		{"Delete", func() error { return store.Delete(u.ID) }},
		{"AdminSetPassword", func() error { return store.AdminSetPassword(u.ID, "h2") }},
		{"GetTOTPState", func() error { _, err := store.GetTOTPState(u.ID); return err }},
		{"SetPendingSecret", func() error {
			return store.SetPendingSecret(u.ID, Sealed{Ciphertext: []byte{1}, Nonce: []byte{2}})
		}},
		{"AdminResetTOTP", func() error { return store.AdminResetTOTP(u.ID) }},
		{"InsertRecoveryCodes", func() error { return store.InsertRecoveryCodes(u.ID, []string{"h"}) }},
		{"ConsumeRecoveryCode", func() error {
			return store.ConsumeRecoveryCode(u.ID, "code", time.Now())
		}},
		{"CountUndecryptableTOTP-nilVault", func() error {
			_, err := store.CountUndecryptableTOTP(nil)
			return err
		}},
		{"ListUndecryptableTOTP-nilVault", func() error {
			_, err := store.ListUndecryptableTOTP(nil)
			return err
		}},
		{"CountUndecryptableTOTP", func() error {
			_, err := store.CountUndecryptableTOTP(fixedVault(t))
			return err
		}},
		{"ListUndecryptableTOTP", func() error {
			_, err := store.ListUndecryptableTOTP(fixedVault(t))
			return err
		}},
		{"RotateKeys", func() error {
			_, err := store.RotateKeys(fixedVault(t), nil)
			return err
		}},
		{"MigrateLegacyTOTPSecrets", func() error {
			return store.MigrateLegacyTOTPSecrets(fixedVault(t))
		}},
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			if err := c.fn(); err == nil {
				t.Errorf("%s on closed DB returned nil error, expected failure", c.name)
			}
		})
	}
}

func TestHandleUpdateProfileUnauthorized(t *testing.T) {
	svc := NewService(&stubUserStore{}, testSecret, false)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/auth/profile",
		strings.NewReader(`{"email":"e","theme":"light"}`))
	svc.handleUpdateProfile(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", w.Code)
	}
}

func TestHandleUpdateProfileBadJSON(t *testing.T) {
	store := &stubUserStore{}
	svc := NewService(store, testSecret, false)
	mux := http.NewServeMux()
	svc.RegisterProtected(mux, RequireUser(testSecret, store, svc.Now))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	user := seedUser(t, store, "alice")
	_ = user
	client := loggedInClientWith(t, srv, "alice", testSecret, store, svc.Now)
	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/auth/profile",
		strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandleUpdateProfileInvalidTheme(t *testing.T) {
	store := &stubUserStore{}
	svc := NewService(store, testSecret, false)
	mux := http.NewServeMux()
	svc.RegisterProtected(mux, RequireUser(testSecret, store, svc.Now))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	seedUser(t, store, "alice")
	client := loggedInClientWith(t, srv, "alice", testSecret, store, svc.Now)
	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/auth/profile",
		strings.NewReader(`{"email":"","theme":"neon-pink"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandleUpdateProfileStoreUserNotFound(t *testing.T) {
	store := &stubUserStore{failOn: "UpdateProfile", err: ErrUserNotFound}
	svc := NewService(store, testSecret, false)
	mux := http.NewServeMux()
	svc.RegisterProtected(mux, RequireUser(testSecret, store, svc.Now))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	seedUser(t, store, "alice")
	client := loggedInClientWith(t, srv, "alice", testSecret, store, svc.Now)
	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/auth/profile",
		strings.NewReader(`{"email":"a@b","theme":"light"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandleChangePasswordUnauthorized(t *testing.T) {
	svc := NewService(&stubUserStore{}, testSecret, false)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/auth/password",
		strings.NewReader(`{"currentPassword":"a","newPassword":"b"}`))
	svc.handleChangePassword(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", w.Code)
	}
}

func TestHandleChangePasswordBadJSON(t *testing.T) {
	store := &stubUserStore{}
	svc := NewService(store, testSecret, false)
	mux := http.NewServeMux()
	svc.RegisterProtected(mux, RequireUser(testSecret, store, svc.Now))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	seedUser(t, store, "alice")
	client := loggedInClientWith(t, srv, "alice", testSecret, store, svc.Now)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/password",
		strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandleChangePasswordEmptyFields(t *testing.T) {
	store := &stubUserStore{}
	svc := NewService(store, testSecret, false)
	mux := http.NewServeMux()
	svc.RegisterProtected(mux, RequireUser(testSecret, store, svc.Now))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	seedUser(t, store, "alice")
	client := loggedInClientWith(t, srv, "alice", testSecret, store, svc.Now)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/password",
		strings.NewReader(`{"currentPassword":"","newPassword":""}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// loggedInClientWith builds a cookie-jar client whose session cookie is
// pre-signed for username — bypassing the login round-trip for tests
// that only care about the post-login handlers.
func loggedInClientWith(t *testing.T, srv *httptest.Server, username string, secret []byte, store UserStore, now func() time.Time) *http.Client {
	t.Helper()
	u, _, err := store.GetByUsername(username)
	if err != nil {
		t.Fatalf("GetByUsername(%s): %v", username, err)
	}
	tok, err := SignSession(secret, u.ID, now().Add(time.Hour))
	if err != nil {
		t.Fatalf("SignSession: %v", err)
	}
	jar, _ := cookiejar.New(nil)
	parsedURL, _ := url.Parse(srv.URL)
	jar.SetCookies(parsedURL, []*http.Cookie{{Name: CookieName, Value: tok}}) //nolint:gosec // G124: test cookie attached to a jar; server-side attributes don't apply.
	return &http.Client{Jar: jar}
}

func TestHandleTOTPSetupUnauthorized(t *testing.T) {
	svc := NewService(&stubUserStore{}, testSecret, false)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/auth/totp/setup", nil)
	svc.handleTOTPSetup(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", w.Code)
	}
}

func TestHandleTOTPConfirmUnauthorized(t *testing.T) {
	svc := NewService(&stubUserStore{}, testSecret, false)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/auth/totp/confirm",
		strings.NewReader(`{"code":"123456"}`))
	svc.handleTOTPConfirm(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", w.Code)
	}
}

func TestHandleTOTPSetupNotConfigured(t *testing.T) {
	store := &stubUserStore{}
	svc := NewService(store, testSecret, false)
	u := seedUser(t, store, "alice")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/auth/totp/setup", nil).
		WithContext(withUserCtx(t, u))
	svc.handleTOTPSetup(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("code = %d, want 503", w.Code)
	}
}

func TestHandleTOTPConfirmBadJSON(t *testing.T) {
	store := &stubUserStore{}
	svc := NewService(store, testSecret, false)
	svc.Vault = fixedVault(t)
	svc.TOTPStore = newStubTOTPStore()
	svc.RecoveryStore = newStubRecoveryStore()
	u := seedUser(t, store, "alice")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/auth/totp/confirm",
		strings.NewReader("not json")).WithContext(withUserCtx(t, u))
	svc.handleTOTPConfirm(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", w.Code)
	}
}

func TestHandleTOTPConfirmNotConfigured(t *testing.T) {
	store := &stubUserStore{}
	svc := NewService(store, testSecret, false)
	u := seedUser(t, store, "alice")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/auth/totp/confirm",
		strings.NewReader(`{"code":"123456"}`)).WithContext(withUserCtx(t, u))
	svc.handleTOTPConfirm(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("code = %d, want 503", w.Code)
	}
}

func TestHandleTOTPConfirmNoPending(t *testing.T) {
	store := &stubUserStore{}
	svc := NewService(store, testSecret, false)
	svc.Vault = fixedVault(t)
	svc.TOTPStore = newStubTOTPStore()
	svc.RecoveryStore = newStubRecoveryStore()
	u := seedUser(t, store, "alice")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/auth/totp/confirm",
		strings.NewReader(`{"code":"123456"}`)).WithContext(withUserCtx(t, u))
	svc.handleTOTPConfirm(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400 (no pending)", w.Code)
	}
}

func TestHandleTOTPVerifyNotConfigured(t *testing.T) {
	store := &stubUserStore{}
	svc := NewService(store, testSecret, false)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/auth/totp/verify",
		strings.NewReader(`{"code":"123456"}`))
	svc.handleTOTPVerify(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("code = %d, want 503", w.Code)
	}
}

func TestHandleTOTPConfirmEmptyCode(t *testing.T) {
	store := &stubUserStore{}
	svc := NewService(store, testSecret, false)
	svc.Vault = fixedVault(t)
	svc.TOTPStore = newStubTOTPStore()
	svc.RecoveryStore = newStubRecoveryStore()
	u := seedUser(t, store, "alice")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/auth/totp/confirm",
		strings.NewReader(`{"code":""}`)).WithContext(withUserCtx(t, u))
	svc.handleTOTPConfirm(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", w.Code)
	}
}

func withUserCtx(_ *testing.T, u User) context.Context {
	return WithUser(context.Background(), u)
}

func TestHandleLoginBadJSON(t *testing.T) {
	store := &stubUserStore{}
	svc := NewService(store, testSecret, false)
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader("not json"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandleLoginUnknownUserIs401(t *testing.T) {
	store := &stubUserStore{}
	svc := NewService(store, testSecret, false)
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"ghost","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestHandleLoginGetByUsernameError(t *testing.T) {
	store := &stubUserStore{failOn: "GetByUsername", err: errAdminTest{}}
	svc := NewService(store, testSecret, false)
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandleSetupCreateError(t *testing.T) {
	store := &stubUserStore{failOn: "Create", err: errAdminTest{}}
	svc := NewService(store, testSecret, false)
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/auth/setup", "application/json",
		strings.NewReader(`{"username":"admin","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestAdminCreateUserHashError(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	client := loggedInClient(t, srv, "alice")

	resp, err := client.Post(srv.URL+"/api/admin/users", "application/json",
		strings.NewReader(`{"username":"bob","password":""}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminResetPasswordStoreError(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	client := loggedInClient(t, srv, "alice")
	store.failOn = "AdminSetPassword"
	store.err = errAdminTest{}

	resp, err := client.Post(
		srv.URL+"/api/admin/users/"+bob.ID+"/password",
		"application/json",
		strings.NewReader(`{"password":"newadminset"}`),
	)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestAdminResetPasswordRequiresAuth(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	bob := seedUser(t, store, "bob")
	resp, err := http.Post(
		srv.URL+"/api/admin/users/"+bob.ID+"/password",
		"application/json",
		strings.NewReader(`{"password":"newadminset"}`),
	)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAdminResetTOTPClearsState(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	bob := seedUser(t, store, "bob")
	got, _ := store.get(bob.ID)
	got.TotpEnabled = true
	store.put(got)
	client := loggedInClient(t, srv, "alice")

	resp, err := client.Post(
		srv.URL+"/api/admin/users/"+bob.ID+"/totp/reset",
		"application/json",
		nil,
	)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	got, _ = store.get(bob.ID)
	if got.TotpEnabled {
		t.Error("TotpEnabled still set after admin reset")
	}
}

func TestAdminResetTOTPRejectsSelf(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	alice := seedUser(t, store, "alice")
	client := loggedInClient(t, srv, "alice")

	resp, err := client.Post(
		srv.URL+"/api/admin/users/"+alice.ID+"/totp/reset",
		"application/json",
		nil,
	)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminResetTOTPNotFound(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	seedUser(t, store, "alice")
	client := loggedInClient(t, srv, "alice")

	resp, err := client.Post(
		srv.URL+"/api/admin/users/missing/totp/reset",
		"application/json",
		nil,
	)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAdminResetTOTPRequiresAuth(t *testing.T) {
	srv, _, store := newAdminTestServer(t)
	bob := seedUser(t, store, "bob")
	resp, err := http.Post(
		srv.URL+"/api/admin/users/"+bob.ID+"/totp/reset",
		"application/json",
		nil,
	)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

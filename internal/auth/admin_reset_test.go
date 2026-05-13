// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"io"
	"net/http"
	"strings"
	"testing"
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

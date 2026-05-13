// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"testing"
	"time"
)

func TestRecordLoginFailureBumpsAndLocks(t *testing.T) {
	s := newTestAuthStore(t)
	u, err := s.Create("alice", "hashvalue")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	n, err := s.RecordLoginFailure(u.ID, nil)
	if err != nil {
		t.Fatalf("RecordLoginFailure: %v", err)
	}
	if n != 1 {
		t.Errorf("first attempt count = %d, want 1", n)
	}

	until := time.Date(2026, 5, 13, 12, 5, 0, 0, time.UTC)
	n, err = s.RecordLoginFailure(u.ID, &until)
	if err != nil {
		t.Fatalf("RecordLoginFailure: %v", err)
	}
	if n != 2 {
		t.Errorf("second attempt count = %d, want 2", n)
	}

	got, err := s.GetByID(u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.FailedAttempts != 2 {
		t.Errorf("FailedAttempts = %d, want 2", got.FailedAttempts)
	}
	if got.LockedUntil == nil || !got.LockedUntil.Equal(until) {
		t.Errorf("LockedUntil = %v, want %v", got.LockedUntil, until)
	}
}

func TestRecordLoginFailureUnknownUser(t *testing.T) {
	s := newTestAuthStore(t)
	if _, err := s.RecordLoginFailure("ghost", nil); err == nil {
		t.Error("expected error for missing user")
	}
}

func TestClearLoginFailures(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "hashvalue")
	until := time.Date(2026, 5, 13, 12, 5, 0, 0, time.UTC)
	if _, err := s.RecordLoginFailure(u.ID, &until); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := s.ClearLoginFailures(u.ID); err != nil {
		t.Fatalf("ClearLoginFailures: %v", err)
	}
	got, _ := s.GetByID(u.ID)
	if got.FailedAttempts != 0 || got.LockedUntil != nil {
		t.Errorf("after clear: attempts=%d lockedUntil=%v", got.FailedAttempts, got.LockedUntil)
	}
}

func TestClearLoginFailuresUnknownUser(t *testing.T) {
	s := newTestAuthStore(t)
	if err := s.ClearLoginFailures("ghost"); err == nil {
		t.Error("expected error for missing user")
	}
}

func TestAdminSetPasswordSetsFlagAndClearsLockout(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "orighash")
	until := time.Date(2026, 5, 13, 12, 5, 0, 0, time.UTC)
	if _, err := s.RecordLoginFailure(u.ID, &until); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := s.AdminSetPassword(u.ID, "newhash"); err != nil {
		t.Fatalf("AdminSetPassword: %v", err)
	}
	got, err := s.GetByID(u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if !got.MustChangePassword {
		t.Error("MustChangePassword not set")
	}
	if got.FailedAttempts != 0 || got.LockedUntil != nil {
		t.Errorf("lockout not cleared: attempts=%d locked=%v", got.FailedAttempts, got.LockedUntil)
	}
	hash, err := s.GetHashByID(u.ID)
	if err != nil {
		t.Fatalf("GetHashByID: %v", err)
	}
	if hash != "newhash" {
		t.Errorf("hash = %q, want newhash", hash)
	}
}

func TestAdminSetPasswordUnknownUser(t *testing.T) {
	s := newTestAuthStore(t)
	if err := s.AdminSetPassword("ghost", "h"); err == nil {
		t.Error("expected error for missing user")
	}
}

func TestStoreAdminResetTOTPClearsState(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")
	if err := s.SetPendingSecret(u.ID, Sealed{Ciphertext: []byte("c"), Nonce: []byte("n"), Version: 1}); err != nil {
		t.Fatalf("SetPendingSecret: %v", err)
	}
	if err := s.ActivateTOTP(u.ID, Sealed{Ciphertext: []byte("c"), Nonce: []byte("n"), Version: 1}, time.Now()); err != nil {
		t.Fatalf("ActivateTOTP: %v", err)
	}
	if err := s.InsertRecoveryCodes(u.ID, []string{"h1", "h2"}); err != nil {
		t.Fatalf("InsertRecoveryCodes: %v", err)
	}
	until := time.Date(2026, 5, 13, 12, 5, 0, 0, time.UTC)
	if _, err := s.RecordLoginFailure(u.ID, &until); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := s.AdminResetTOTP(u.ID); err != nil {
		t.Fatalf("AdminResetTOTP: %v", err)
	}
	got, _ := s.GetByID(u.ID)
	if got.TotpEnabled {
		t.Error("TotpEnabled still true after reset")
	}
	if got.FailedAttempts != 0 || got.LockedUntil != nil {
		t.Errorf("lockout not cleared")
	}
	state, err := s.GetTOTPState(u.ID)
	if err != nil {
		t.Fatalf("GetTOTPState: %v", err)
	}
	if state.Enabled || !state.Secret.IsZero() {
		t.Errorf("totp state not cleared: %+v", state)
	}
}

func TestStoreAdminResetTOTPUnknownUser(t *testing.T) {
	s := newTestAuthStore(t)
	if err := s.AdminResetTOTP("ghost"); err == nil {
		t.Error("expected error for missing user")
	}
}

func TestUpdatePasswordClearsMustChangeAndLockout(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "orighash")
	if err := s.AdminSetPassword(u.ID, "admininitial"); err != nil {
		t.Fatalf("AdminSetPassword: %v", err)
	}
	if err := s.UpdatePassword(u.ID, "userchosen"); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	got, _ := s.GetByID(u.ID)
	if got.MustChangePassword {
		t.Error("MustChangePassword still set after user change")
	}
}

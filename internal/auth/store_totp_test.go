// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"
	"testing"
	"time"
)

func TestTOTPStorePendingActivateGet(t *testing.T) {
	s := newTestAuthStore(t)
	u, err := s.Create("alice", "h")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.SetPendingSecret(u.ID, []byte("pending-ct")); err != nil {
		t.Fatalf("SetPendingSecret: %v", err)
	}
	state, err := s.GetTOTPState(u.ID)
	if err != nil {
		t.Fatalf("GetTOTPState: %v", err)
	}
	if state.Enabled {
		t.Error("enabled before confirm")
	}
	if string(state.Pending) != "pending-ct" {
		t.Errorf("pending = %q", state.Pending)
	}

	confirmedAt := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	if err := s.ActivateTOTP(u.ID, []byte("active-ct"), confirmedAt); err != nil {
		t.Fatalf("ActivateTOTP: %v", err)
	}
	state, err = s.GetTOTPState(u.ID)
	if err != nil {
		t.Fatalf("GetTOTPState 2: %v", err)
	}
	if !state.Enabled {
		t.Error("not enabled after activate")
	}
	if string(state.Secret) != "active-ct" {
		t.Errorf("secret = %q", state.Secret)
	}
	if state.Pending != nil {
		t.Errorf("pending should be cleared, got %q", state.Pending)
	}
	if state.Epoch != 0 || state.LastStep != 0 {
		t.Errorf("epoch=%d lastStep=%d, want 0/0", state.Epoch, state.LastStep)
	}
}

func TestSetPendingSecretMissing(t *testing.T) {
	s := newTestAuthStore(t)
	if err := s.SetPendingSecret("ghost", []byte("x")); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("err = %v, want ErrUserNotFound", err)
	}
}

func TestActivateTOTPMissing(t *testing.T) {
	s := newTestAuthStore(t)
	if err := s.ActivateTOTP("ghost", []byte("x"), time.Now()); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("err = %v, want ErrUserNotFound", err)
	}
}

func TestGetTOTPStateMissing(t *testing.T) {
	s := newTestAuthStore(t)
	if _, err := s.GetTOTPState("ghost"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("err = %v, want ErrUserNotFound", err)
	}
}

func TestDisableTOTPBumpsEpochAndClearsRelated(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")
	if err := s.ActivateTOTP(u.ID, []byte("ct"), time.Now()); err != nil {
		t.Fatalf("ActivateTOTP: %v", err)
	}
	if err := s.InsertRecoveryCodes(u.ID, []string{"hash1", "hash2"}); err != nil {
		t.Fatalf("InsertRecoveryCodes: %v", err)
	}
	if err := s.InsertDevice(TrustedDevice{
		ID: "d1", UserID: u.ID, Label: "Firefox on Linux",
		CreatedAt: time.Now(), LastUsedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour), TOTPEpoch: 0,
	}); err != nil {
		t.Fatalf("InsertDevice: %v", err)
	}

	if err := s.DisableTOTP(u.ID); err != nil {
		t.Fatalf("DisableTOTP: %v", err)
	}
	state, _ := s.GetTOTPState(u.ID)
	if state.Enabled {
		t.Error("still enabled after disable")
	}
	if state.Secret != nil {
		t.Error("secret not cleared")
	}
	if state.Epoch != 1 {
		t.Errorf("epoch = %d, want 1", state.Epoch)
	}
	devices, _ := s.ListDevices(u.ID)
	if len(devices) != 0 {
		t.Errorf("devices remain: %d", len(devices))
	}
	// The recovery codes are gone, so consume of any code returns ErrUnauthorized.
	if err := s.ConsumeRecoveryCode(u.ID, "anything", time.Now()); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("after disable consume err = %v, want ErrUnauthorized", err)
	}
}

func TestDisableTOTPMissing(t *testing.T) {
	s := newTestAuthStore(t)
	if err := s.DisableTOTP("ghost"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("err = %v, want ErrUserNotFound", err)
	}
}

func TestConsumeStepRejectsReplay(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")
	if err := s.ConsumeStep(u.ID, 100); err != nil {
		t.Fatalf("first ConsumeStep: %v", err)
	}
	if err := s.ConsumeStep(u.ID, 100); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("replay step err = %v, want ErrUnauthorized", err)
	}
	if err := s.ConsumeStep(u.ID, 99); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("backwards step err = %v, want ErrUnauthorized", err)
	}
	if err := s.ConsumeStep(u.ID, 101); err != nil {
		t.Errorf("forwards step err = %v, want nil", err)
	}
}

func TestRecoveryCodesInsertAndConsume(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")
	codes, _ := GenerateRecoveryCodes(3)
	hashes := make([]string, 0, len(codes))
	for _, c := range codes {
		h, err := HashRecoveryCode(c)
		if err != nil {
			t.Fatalf("HashRecoveryCode: %v", err)
		}
		hashes = append(hashes, h)
	}
	if err := s.InsertRecoveryCodes(u.ID, hashes); err != nil {
		t.Fatalf("InsertRecoveryCodes: %v", err)
	}
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	if err := s.ConsumeRecoveryCode(u.ID, codes[1], now); err != nil {
		t.Fatalf("ConsumeRecoveryCode: %v", err)
	}
	// Replay should fail.
	if err := s.ConsumeRecoveryCode(u.ID, codes[1], now); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("replay err = %v, want ErrUnauthorized", err)
	}
	// Wrong code rejected.
	if err := s.ConsumeRecoveryCode(u.ID, "WRONG-CODE", now); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("wrong code err = %v, want ErrUnauthorized", err)
	}
	// Other codes still consumable.
	if err := s.ConsumeRecoveryCode(u.ID, codes[0], now); err != nil {
		t.Errorf("other code: %v", err)
	}
}

func TestInsertRecoveryCodesReplacesExisting(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")
	if err := s.InsertRecoveryCodes(u.ID, []string{"old1", "old2"}); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := s.InsertRecoveryCodes(u.ID, []string{"new1"}); err != nil {
		t.Fatalf("second insert: %v", err)
	}
	// Verify only the new code remains by attempting to consume the old one.
	// (No real codes here; we test by counting via DeleteRecoveryCodes, which
	// returns no error either way — instead, list directly.)
	rows, err := s.db.Query(`SELECT code_hash FROM recovery_codes WHERE user_id = ?`, u.ID)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer func() { _ = rows.Close() }()
	got := []string{}
	for rows.Next() {
		var h string
		_ = rows.Scan(&h)
		got = append(got, h)
	}
	if len(got) != 1 || got[0] != "new1" {
		t.Errorf("rows = %v, want [new1]", got)
	}
}

func TestDeleteRecoveryCodes(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")
	_ = s.InsertRecoveryCodes(u.ID, []string{"h1"})
	if err := s.DeleteRecoveryCodes(u.ID); err != nil {
		t.Fatalf("DeleteRecoveryCodes: %v", err)
	}
	if err := s.ConsumeRecoveryCode(u.ID, "anything", time.Now()); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("after delete err = %v", err)
	}
}

func TestDeviceCRUD(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	d := TrustedDevice{
		ID: "dev-1", UserID: u.ID, Label: "Firefox on Linux",
		CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour), TOTPEpoch: 0,
	}
	if err := s.InsertDevice(d); err != nil {
		t.Fatalf("InsertDevice: %v", err)
	}
	got, err := s.GetDevice("dev-1")
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if got.UserID != u.ID || got.Label != "Firefox on Linux" {
		t.Errorf("got = %+v", got)
	}

	later := now.Add(time.Hour)
	if err := s.TouchDevice("dev-1", later); err != nil {
		t.Fatalf("TouchDevice: %v", err)
	}
	got2, _ := s.GetDevice("dev-1")
	if !got2.LastUsedAt.Equal(later) {
		t.Errorf("last_used_at = %v, want %v", got2.LastUsedAt, later)
	}

	devices, err := s.ListDevices(u.ID)
	if err != nil || len(devices) != 1 {
		t.Errorf("ListDevices: %d devices, err=%v", len(devices), err)
	}

	if err := s.DeleteDevice("dev-1", u.ID); err != nil {
		t.Fatalf("DeleteDevice: %v", err)
	}
	if _, err := s.GetDevice("dev-1"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("after delete err = %v, want ErrUserNotFound", err)
	}
}

func TestDeviceCrossUserDelete(t *testing.T) {
	s := newTestAuthStore(t)
	a, _ := s.Create("alice", "h")
	b, _ := s.Create("bob", "h")
	now := time.Now()
	_ = s.InsertDevice(TrustedDevice{
		ID: "dev-a", UserID: a.ID, Label: "x", CreatedAt: now, LastUsedAt: now, ExpiresAt: now,
	})
	if err := s.DeleteDevice("dev-a", b.ID); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("cross-user delete err = %v, want ErrUserNotFound", err)
	}
	// Original device still present.
	if _, err := s.GetDevice("dev-a"); err != nil {
		t.Errorf("original survived? err = %v", err)
	}
}

func TestDeleteDevicesForUser(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")
	now := time.Now()
	for _, id := range []string{"d1", "d2", "d3"} {
		_ = s.InsertDevice(TrustedDevice{
			ID: id, UserID: u.ID, Label: "x",
			CreatedAt: now, LastUsedAt: now, ExpiresAt: now,
		})
	}
	if err := s.DeleteDevicesForUser(u.ID); err != nil {
		t.Fatalf("DeleteDevicesForUser: %v", err)
	}
	devices, _ := s.ListDevices(u.ID)
	if len(devices) != 0 {
		t.Errorf("devices remain: %d", len(devices))
	}
}

func TestTouchDeviceMissing(t *testing.T) {
	s := newTestAuthStore(t)
	if err := s.TouchDevice("ghost", time.Now()); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("err = %v, want ErrUserNotFound", err)
	}
}

func TestGetDeviceMissing(t *testing.T) {
	s := newTestAuthStore(t)
	if _, err := s.GetDevice("ghost"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("err = %v, want ErrUserNotFound", err)
	}
}

func TestListDevicesEmpty(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")
	devices, err := s.ListDevices(u.ID)
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(devices) != 0 {
		t.Errorf("got %d devices, want 0", len(devices))
	}
}

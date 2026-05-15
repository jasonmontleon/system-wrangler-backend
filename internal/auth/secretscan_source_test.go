// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"testing"
	"time"

	"system-wrangler-backend/internal/secrets"
)

func TestTOTPScanSource_NameAndConversion(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")
	sealed, _ := sealUnderKey(t, 100, []byte("alice"))
	if err := s.ActivateTOTP(u.ID, sealed, time.Now()); err != nil {
		t.Fatalf("ActivateTOTP: %v", err)
	}
	curVault, _ := secrets.NewVaultFromKey(deterministicVaultKey(101))

	src := TOTPScanSource{Store: s}
	if src.Name() != "user_totp" {
		t.Errorf("Name = %q, want user_totp", src.Name())
	}

	items, err := src.ListUndecryptable(curVault)
	if err != nil {
		t.Fatalf("ListUndecryptable: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1", len(items))
	}
	got := items[0]
	if got.Kind != "user_totp" || got.Field != "secret" || got.TargetID != u.ID || got.TargetLabel != "alice" {
		t.Errorf("item = %+v, fields don't match", got)
	}

	n, err := src.CountUndecryptable(curVault)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 1 {
		t.Errorf("Count = %d, want 1", n)
	}
}

func TestTOTPScanSource_PropagatesErrors(t *testing.T) {
	src := TOTPScanSource{Store: &SQLiteAuthStore{}}
	// Underlying ListUndecryptableTOTP errors on nil vault. Confirm the
	// adapter propagates it rather than swallowing.
	if _, err := src.ListUndecryptable(nil); err == nil {
		t.Error("ListUndecryptable(nil): want error, got nil")
	}
	if _, err := src.CountUndecryptable(nil); err == nil {
		t.Error("CountUndecryptable(nil): want error, got nil")
	}
}

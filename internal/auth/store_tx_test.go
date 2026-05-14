// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"
	"testing"
	"time"
)

// TestStoreTxMethodsPersistThroughTx exercises every newly-introduced
// SQLiteAuthStore.*Tx method against a real transaction. The audit
// refactor leaves these unreachable through the handler tests (those
// use stub stores), so a dedicated unit pins the Tx-aware code path.
func TestStoreTxMethodsPersistThroughTx(t *testing.T) {
	s := newTestAuthStore(t)
	u, err := s.Create("alice", "h")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// UpdatePasswordTx through a real tx.
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := s.UpdatePasswordTx(tx, u.ID, "newhash"); err != nil {
		t.Fatalf("UpdatePasswordTx: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	gotHash, err := s.GetHashByID(u.ID)
	if err != nil {
		t.Fatalf("GetHashByID: %v", err)
	}
	if gotHash != "newhash" {
		t.Errorf("hash after UpdatePasswordTx = %q, want newhash", gotHash)
	}
	// UpdatePasswordTx on a missing user returns ErrUserNotFound.
	tx2, _ := s.db.Begin()
	if err := s.UpdatePasswordTx(tx2, "ghost", "x"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("UpdatePasswordTx(ghost) = %v, want ErrUserNotFound", err)
	}
	_ = tx2.Rollback()

	// ActivateTOTPTx + InsertRecoveryCodesTx in one tx.
	sealed := fakeSealed("active-secret")
	tx3, _ := s.db.Begin()
	if err := s.ActivateTOTPTx(tx3, u.ID, sealed, time.Now()); err != nil {
		t.Fatalf("ActivateTOTPTx: %v", err)
	}
	if err := s.InsertRecoveryCodesTx(tx3, u.ID, []string{"h1", "h2"}); err != nil {
		t.Fatalf("InsertRecoveryCodesTx: %v", err)
	}
	if err := tx3.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	state, err := s.GetTOTPState(u.ID)
	if err != nil {
		t.Fatalf("GetTOTPState: %v", err)
	}
	if !state.Enabled {
		t.Error("ActivateTOTPTx did not enable TOTP")
	}

	// ConsumeRecoveryCodeTx on a known hash — the stored hashes are
	// plain strings here so CompareRecoveryCode against any input
	// fails; the path is still exercised. ErrUnauthorized confirms
	// the SQL ran without returning a database error.
	tx4, _ := s.db.Begin()
	if err := s.ConsumeRecoveryCodeTx(tx4, u.ID, "anything", time.Now()); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("ConsumeRecoveryCodeTx unmatched = %v, want ErrUnauthorized", err)
	}
	_ = tx4.Rollback()

	// DisableTOTPTx and verify rows are cleared.
	tx5, _ := s.db.Begin()
	if err := s.DisableTOTPTx(tx5, u.ID); err != nil {
		t.Fatalf("DisableTOTPTx: %v", err)
	}
	if err := tx5.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	state, _ = s.GetTOTPState(u.ID)
	if state.Enabled {
		t.Error("DisableTOTPTx did not disable TOTP")
	}
}

// TestStoreTxMethodsNilFallback verifies each *Tx method delegates to
// its non-tx sibling when passed a nil tx — this keeps the in-handler
// fallback path (when DB/Audit aren't wired) honest.
func TestStoreTxMethodsNilFallback(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")

	if err := s.UpdatePasswordTx(nil, u.ID, "h2"); err != nil {
		t.Errorf("UpdatePasswordTx(nil): %v", err)
	}
	if err := s.ActivateTOTPTx(nil, u.ID, fakeSealed("s"), time.Now()); err != nil {
		t.Errorf("ActivateTOTPTx(nil): %v", err)
	}
	if err := s.InsertRecoveryCodesTx(nil, u.ID, []string{"r"}); err != nil {
		t.Errorf("InsertRecoveryCodesTx(nil): %v", err)
	}
	if err := s.ConsumeRecoveryCodeTx(nil, u.ID, "wrong", time.Now()); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("ConsumeRecoveryCodeTx(nil) = %v, want ErrUnauthorized", err)
	}
	if err := s.DisableTOTPTx(nil, u.ID); err != nil {
		t.Errorf("DisableTOTPTx(nil): %v", err)
	}
}

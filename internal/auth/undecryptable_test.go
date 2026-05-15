// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"testing"
	"time"

	"system-wrangler-backend/internal/secrets"
)

func TestListUndecryptableTOTP_AllReadable(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")
	v, _ := secrets.NewVaultFromKey(deterministicVaultKey(40))
	sealed, err := SealWith(v, []byte("alice secret"))
	if err != nil {
		t.Fatalf("SealWith: %v", err)
	}
	if err := s.ActivateTOTP(u.ID, sealed, time.Now()); err != nil {
		t.Fatalf("ActivateTOTP: %v", err)
	}
	out, err := s.ListUndecryptableTOTP(v)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("got %d undecryptable rows, want 0: %+v", len(out), out)
	}
	n, err := s.CountUndecryptableTOTP(v)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 0 {
		t.Errorf("Count = %d, want 0", n)
	}
}

func TestListUndecryptableTOTP_MismatchedKey(t *testing.T) {
	s := newTestAuthStore(t)
	alice, _ := s.Create("alice", "h")
	bob, _ := s.Create("bob", "h")
	carol, _ := s.Create("carol", "h")

	// Alice's secret sealed under key A.
	sealedAlice, _ := sealUnderKey(t, 80, []byte("alice"))
	if err := s.ActivateTOTP(alice.ID, sealedAlice, time.Now()); err != nil {
		t.Fatalf("ActivateTOTP alice: %v", err)
	}
	// Bob has a pending enrollment sealed under key A as well.
	sealedBobPending, _ := sealUnderKey(t, 80, []byte("bob"))
	if err := s.SetPendingSecret(bob.ID, sealedBobPending); err != nil {
		t.Fatalf("SetPendingSecret bob: %v", err)
	}
	// Carol's secret is sealed under the currently-loaded key.
	curVault, _ := secrets.NewVaultFromKey(deterministicVaultKey(81))
	sealedCarol, err := SealWith(curVault, []byte("carol"))
	if err != nil {
		t.Fatalf("SealWith carol: %v", err)
	}
	if err := s.ActivateTOTP(carol.ID, sealedCarol, time.Now()); err != nil {
		t.Fatalf("ActivateTOTP carol: %v", err)
	}

	// Vault loaded with only the new key — alice and bob's rows fail.
	out, err := s.ListUndecryptableTOTP(curVault)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(out), out)
	}
	// Ordered by username, so alice first then bob.
	if out[0].Username != "alice" || out[0].Field != TOTPFieldSecret {
		t.Errorf("row 0 = {%s, %s}, want {alice, secret}", out[0].Username, out[0].Field)
	}
	if out[1].Username != "bob" || out[1].Field != TOTPFieldPending {
		t.Errorf("row 1 = {%s, %s}, want {bob, pending}", out[1].Username, out[1].Field)
	}

	n, err := s.CountUndecryptableTOTP(curVault)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 2 {
		t.Errorf("Count = %d, want 2", n)
	}
}

func TestListUndecryptableTOTP_BothColumnsBroken(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")
	old1, _ := sealUnderKey(t, 90, []byte("active"))
	old2, _ := sealUnderKey(t, 90, []byte("pending"))
	if err := s.ActivateTOTP(u.ID, old1, time.Now()); err != nil {
		t.Fatalf("ActivateTOTP: %v", err)
	}
	if err := s.SetPendingSecret(u.ID, old2); err != nil {
		t.Fatalf("SetPendingSecret: %v", err)
	}
	curVault, _ := secrets.NewVaultFromKey(deterministicVaultKey(91))

	out, err := s.ListUndecryptableTOTP(curVault)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(out), out)
	}
	// Same user, both fields. Ordering: secret first per query column
	// order (secret column projected before pending).
	fields := []TOTPField{out[0].Field, out[1].Field}
	if fields[0] != TOTPFieldSecret || fields[1] != TOTPFieldPending {
		t.Errorf("fields = %v, want [secret, pending]", fields)
	}
	for _, r := range out {
		if r.UserID != u.ID || r.Username != "alice" {
			t.Errorf("row %+v has wrong user identity", r)
		}
	}
}

func TestListUndecryptableTOTP_NilVault(t *testing.T) {
	s := newTestAuthStore(t)
	if _, err := s.ListUndecryptableTOTP(nil); err == nil {
		t.Error("List with nil vault: want error, got nil")
	}
	if _, err := s.CountUndecryptableTOTP(nil); err == nil {
		t.Error("Count with nil vault: want error, got nil")
	}
}

func TestListUndecryptableTOTP_UsersWithoutTOTPIgnored(t *testing.T) {
	s := newTestAuthStore(t)
	_, _ = s.Create("alice", "h")
	_, _ = s.Create("bob", "h")
	curVault, _ := secrets.NewVaultFromKey(deterministicVaultKey(95))

	out, err := s.ListUndecryptableTOTP(curVault)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("got %d rows for users without TOTP, want 0: %+v", len(out), out)
	}
}

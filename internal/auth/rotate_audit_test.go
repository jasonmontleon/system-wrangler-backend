// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"testing"
	"time"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/secrets"
)

// TestRotateKeysEmitsStartCompleteRows verifies the operator-visible
// audit trail: one start row plus one complete row, the complete row
// pointing back at the start row via detail.parent_id, both
// actor_kind=system since rotation is system-emitted.
func TestRotateKeysEmitsStartCompleteRows(t *testing.T) {
	s := newTestAuthStore(t)
	auditStore, err := audit.NewSQLiteStore(s.db)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStore: %v", err)
	}

	u, _ := s.Create("alice", "h")
	oldSealed, _ := sealUnderKey(t, 110, []byte("secret"))
	if err := s.ActivateTOTP(u.ID, oldSealed, time.Now()); err != nil {
		t.Fatalf("ActivateTOTP: %v", err)
	}
	prev := deterministicVaultKey(110)
	cur := deterministicVaultKey(111)
	curVault, _ := secrets.NewVaultFromKey(cur)
	_ = loadPrevKeyForTest(curVault, prev)

	if _, err := s.RotateKeys(curVault, auditStore); err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}

	starts, _, err := auditStore.ListQuery(audit.Query{Action: "secret.rotate.start"})
	if err != nil {
		t.Fatalf("list start: %v", err)
	}
	if len(starts) != 1 {
		t.Fatalf("starts = %d, want 1", len(starts))
	}
	start := starts[0]
	if start.ActorKind != audit.ActorSystem {
		t.Errorf("start actor = %s, want system", start.ActorKind)
	}

	completes, _, err := auditStore.ListQuery(audit.Query{Action: "secret.rotate.complete"})
	if err != nil {
		t.Fatalf("list complete: %v", err)
	}
	if len(completes) != 1 {
		t.Fatalf("completes = %d, want 1", len(completes))
	}
	complete := completes[0]
	if complete.Outcome != audit.Success {
		t.Errorf("complete outcome = %s, want success", complete.Outcome)
	}
	gotParent, _ := complete.Detail["parent_id"].(string)
	if gotParent != start.ID {
		t.Errorf("complete.detail.parent_id = %q, want %q", gotParent, start.ID)
	}
	if rows, _ := complete.Detail["rows_rewrapped"].(float64); rows != 1 {
		t.Errorf("rows_rewrapped = %v, want 1", complete.Detail["rows_rewrapped"])
	}
}

// TestRotateKeysFailureEmitsFailureComplete checks that the complete
// row is still written when the underlying rotation surfaces an error
// (operator dropped the previous key), so the audit trail records the
// attempt rather than going silent on failure.
func TestRotateKeysFailureEmitsFailureComplete(t *testing.T) {
	s := newTestAuthStore(t)
	auditStore, err := audit.NewSQLiteStore(s.db)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStore: %v", err)
	}
	u, _ := s.Create("alice", "h")
	oldSealed, _ := sealUnderKey(t, 120, []byte("secret"))
	if err := s.ActivateTOTP(u.ID, oldSealed, time.Now()); err != nil {
		t.Fatalf("ActivateTOTP: %v", err)
	}
	// Vault without the previous key — rotation must fail.
	curVault, _ := secrets.NewVaultFromKey(deterministicVaultKey(121))
	if _, err := s.RotateKeys(curVault, auditStore); err == nil {
		t.Fatal("want error from unknown previous version")
	}
	completes, _, _ := auditStore.ListQuery(audit.Query{Action: "secret.rotate.complete"})
	if len(completes) != 1 {
		t.Fatalf("completes = %d, want 1", len(completes))
	}
	if completes[0].Outcome != audit.Failure {
		t.Errorf("failure complete outcome = %s, want failure", completes[0].Outcome)
	}
	if _, ok := completes[0].Detail["error"].(string); !ok {
		t.Errorf("failure complete detail.error missing: %+v", completes[0].Detail)
	}
}

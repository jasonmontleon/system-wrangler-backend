// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"
	"testing"
	"time"
)

func sampleSession(id, userID string, base time.Time) Session {
	return Session{
		ID:         id,
		UserID:     userID,
		Label:      "Firefox on Linux",
		IP:         "10.0.0.5",
		CreatedAt:  base,
		LastSeenAt: base,
		ExpiresAt:  base.Add(DefaultSessionTTL),
	}
}

func TestCreateAndGetSession(t *testing.T) {
	s := newTestAuthStore(t)
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	want := sampleSession("sess-1", "user-1", base)
	if err := s.CreateSession(want); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	got, err := s.GetSession("sess-1")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.UserID != "user-1" || got.Label != want.Label || got.IP != want.IP {
		t.Errorf("got %+v", got)
	}
	if !got.CreatedAt.Equal(base) || !got.ExpiresAt.Equal(base.Add(DefaultSessionTTL)) {
		t.Errorf("timestamps round-trip wrong: %+v", got)
	}
}

func TestGetSessionMissing(t *testing.T) {
	s := newTestAuthStore(t)
	if _, err := s.GetSession("nope"); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("err = %v, want ErrSessionNotFound", err)
	}
}

func TestTouchSession(t *testing.T) {
	s := newTestAuthStore(t)
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	if err := s.CreateSession(sampleSession("sess-1", "user-1", base)); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	later := base.Add(10 * time.Minute)
	if err := s.TouchSession("sess-1", later); err != nil {
		t.Fatalf("TouchSession: %v", err)
	}
	got, _ := s.GetSession("sess-1")
	if !got.LastSeenAt.Equal(later) {
		t.Errorf("lastSeen = %v, want %v", got.LastSeenAt, later)
	}
}

func TestTouchSessionMissingIsNoError(t *testing.T) {
	s := newTestAuthStore(t)
	if err := s.TouchSession("ghost", time.Now()); err != nil {
		t.Errorf("touch on missing row should be a no-op, got %v", err)
	}
}

func TestRevokeSessionScopedToUser(t *testing.T) {
	s := newTestAuthStore(t)
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	_ = s.CreateSession(sampleSession("sess-1", "user-1", base))

	// Wrong owner → not found, row survives.
	if err := s.RevokeSession("sess-1", "user-2"); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("cross-user revoke err = %v, want ErrSessionNotFound", err)
	}
	if _, err := s.GetSession("sess-1"); err != nil {
		t.Errorf("row should survive cross-user revoke, got %v", err)
	}
	// Right owner → gone.
	if err := s.RevokeSession("sess-1", "user-1"); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if _, err := s.GetSession("sess-1"); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("row should be gone, got %v", err)
	}
}

func TestRevokeUserSessions(t *testing.T) {
	s := newTestAuthStore(t)
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	_ = s.CreateSession(sampleSession("a", "user-1", base))
	_ = s.CreateSession(sampleSession("b", "user-1", base))
	_ = s.CreateSession(sampleSession("c", "user-2", base))

	n, err := s.RevokeUserSessions("user-1")
	if err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if n != 2 {
		t.Errorf("revoked = %d, want 2", n)
	}
	got, _ := s.ListSessions("user-2")
	if len(got) != 1 {
		t.Errorf("user-2 sessions = %d, want 1 (untouched)", len(got))
	}
}

func TestRevokeOtherUserSessions(t *testing.T) {
	s := newTestAuthStore(t)
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	_ = s.CreateSession(sampleSession("keep", "user-1", base))
	_ = s.CreateSession(sampleSession("kill-1", "user-1", base))
	_ = s.CreateSession(sampleSession("kill-2", "user-1", base))

	n, err := s.RevokeOtherUserSessions("user-1", "keep")
	if err != nil {
		t.Fatalf("RevokeOtherUserSessions: %v", err)
	}
	if n != 2 {
		t.Errorf("revoked = %d, want 2", n)
	}
	got, _ := s.ListSessions("user-1")
	if len(got) != 1 || got[0].ID != "keep" {
		t.Errorf("survivors = %+v, want only keep", got)
	}
}

func TestRevokeOtherUserSessionsEmptyKeepRevokesAll(t *testing.T) {
	s := newTestAuthStore(t)
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	_ = s.CreateSession(sampleSession("a", "user-1", base))
	_ = s.CreateSession(sampleSession("b", "user-1", base))
	n, err := s.RevokeOtherUserSessions("user-1", "")
	if err != nil {
		t.Fatalf("RevokeOtherUserSessions: %v", err)
	}
	if n != 2 {
		t.Errorf("revoked = %d, want 2", n)
	}
}

func TestListSessionsOrdersByLastSeen(t *testing.T) {
	s := newTestAuthStore(t)
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	old := sampleSession("old", "user-1", base)
	old.LastSeenAt = base.Add(-time.Hour)
	fresh := sampleSession("fresh", "user-1", base)
	fresh.LastSeenAt = base.Add(time.Hour)
	_ = s.CreateSession(old)
	_ = s.CreateSession(fresh)

	got, err := s.ListSessions("user-1")
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(got) != 2 || got[0].ID != "fresh" || got[1].ID != "old" {
		t.Errorf("order = %+v, want fresh then old", got)
	}
}

func TestListSessionsEmpty(t *testing.T) {
	s := newTestAuthStore(t)
	got, err := s.ListSessions("nobody")
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d, want empty", len(got))
	}
}

func TestDeleteExpiredSessions(t *testing.T) {
	s := newTestAuthStore(t)
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	expired := sampleSession("expired", "user-1", base)
	expired.ExpiresAt = base.Add(-time.Minute)
	live := sampleSession("live", "user-1", base)
	live.ExpiresAt = base.Add(time.Hour)
	_ = s.CreateSession(expired)
	_ = s.CreateSession(live)

	n, err := s.DeleteExpiredSessions(base)
	if err != nil {
		t.Fatalf("DeleteExpiredSessions: %v", err)
	}
	if n != 1 {
		t.Errorf("pruned = %d, want 1", n)
	}
	if _, err := s.GetSession("live"); err != nil {
		t.Errorf("live session should survive, got %v", err)
	}
}

func TestSessionStoreErrorsOnClosedDB(t *testing.T) {
	s := newTestAuthStore(t)
	// Close the underlying handle so every query errors, exercising the
	// error-wrap paths.
	if err := s.db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	if err := s.CreateSession(sampleSession("x", "u", base)); err == nil {
		t.Error("CreateSession on closed DB: want error")
	}
	if _, err := s.GetSession("x"); err == nil {
		t.Error("GetSession on closed DB: want error")
	}
	if err := s.TouchSession("x", base); err == nil {
		t.Error("TouchSession on closed DB: want error")
	}
	if err := s.RevokeSession("x", "u"); err == nil {
		t.Error("RevokeSession on closed DB: want error")
	}
	if _, err := s.RevokeUserSessions("u"); err == nil {
		t.Error("RevokeUserSessions on closed DB: want error")
	}
	if _, err := s.RevokeOtherUserSessions("u", "k"); err == nil {
		t.Error("RevokeOtherUserSessions on closed DB: want error")
	}
	if _, err := s.ListSessions("u"); err == nil {
		t.Error("ListSessions on closed DB: want error")
	}
	if _, err := s.DeleteExpiredSessions(base); err == nil {
		t.Error("DeleteExpiredSessions on closed DB: want error")
	}
}

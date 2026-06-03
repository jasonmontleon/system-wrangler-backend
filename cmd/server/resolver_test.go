// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"path/filepath"
	"testing"

	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/notifications"
	"system-wrangler-backend/internal/rbac"
	"system-wrangler-backend/internal/secrets"
	"system-wrangler-backend/internal/systems"
)

// fakeScoper returns canned assignments per user.
type fakeScoper struct {
	rows map[string][]rbac.Assignment
	err  error
}

func (f fakeScoper) Resolve(userID string) ([]rbac.Assignment, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.rows[userID], nil
}

func ptr(s string) *string { return &s }

func newNotifStore(t *testing.T) *notifications.SQLiteStore {
	t.Helper()
	db, err := database.Open("file:" + filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st, err := notifications.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("notif store: %v", err)
	}
	vault, _ := secrets.NewVaultFromKey(make([]byte, secrets.KeySize))
	st.Vault = vault
	return st
}

func TestSubscriberResolverRBACGating(t *testing.T) {
	subStore := newNotifStore(t)
	// Alice and Bob both subscribe to everything they can see, all severities.
	if err := subStore.SetSubscription("alice", notifications.Subscription{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := subStore.SetSubscription("bob", notifications.Subscription{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// Carol is subscribed but only to critical.
	if err := subStore.SetSubscription("carol", notifications.Subscription{Enabled: true, Severities: []string{"critical"}}); err != nil {
		t.Fatal(err)
	}

	sysStore := systems.NewMemStore()
	sys, err := sysStore.Create(systems.SystemInput{Name: "web1", Hostname: "web1.example.com"})
	if err != nil {
		t.Fatalf("create system: %v", err)
	}
	if err := sysStore.SetGroup(sys.ID, ptr("g1")); err != nil {
		t.Fatalf("set group: %v", err)
	}

	// Alice can read g1 (group auditor); Bob has no roles; Carol can read g1.
	scoper := fakeScoper{rows: map[string][]rbac.Assignment{
		"alice": {{UserID: "alice", GroupID: ptr("g1"), Role: rbac.RoleAuditor}},
		"bob":   {},
		"carol": {{UserID: "carol", GroupID: ptr("g1"), Role: rbac.RoleAuditor}},
	}}

	resolve := subscriberResolver(sysStore, subStore, scoper)

	// At warning: Alice yes (visible, all-severity), Bob no (can't see),
	// Carol no (subscribed to critical only).
	got, err := resolve(sys.ID, "warning")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(got) != 1 || got[0] != "alice" {
		t.Errorf("warning subscribers = %v, want [alice]", got)
	}

	// At critical: Alice and Carol (both visible + match), still not Bob.
	got, err = resolve(sys.ID, "critical")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(got) != 2 || !contains(got, "alice") || !contains(got, "carol") {
		t.Errorf("critical subscribers = %v, want [alice carol]", got)
	}
}

func TestSubscriberResolverSkipsScopeError(t *testing.T) {
	subStore := newNotifStore(t)
	_ = subStore.SetSubscription("alice", notifications.Subscription{Enabled: true})
	sysStore := systems.NewMemStore()
	sys, _ := sysStore.Create(systems.SystemInput{Name: "web1", Hostname: "web1.example.com"})

	// A scope-resolution failure drops that user rather than leaking the alert.
	resolve := subscriberResolver(sysStore, subStore, fakeScoper{err: errors.New("db down")})
	got, err := resolve(sys.ID, "critical")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("subscribers = %v, want none (scope error)", got)
	}
}

func TestSubscriberResolverUnknownSystem(t *testing.T) {
	subStore := newNotifStore(t)
	resolve := subscriberResolver(systems.NewMemStore(), subStore, fakeScoper{})
	if _, err := resolve("ghost", "critical"); err == nil {
		t.Error("resolve on a missing system should error")
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

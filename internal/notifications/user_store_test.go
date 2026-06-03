// SPDX-License-Identifier: Apache-2.0

package notifications

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestUserChannelCreateGetRoundTrip(t *testing.T) {
	st := newTestStore(t)
	c, err := st.CreateUserChannel("alice", emailInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if c.ID == "" || c.CreatedBy != "alice" {
		t.Errorf("server fields wrong: %+v", c)
	}
	got, err := st.GetUserChannel("alice", c.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	pt, err := OpenWith(st.Vault, got.Secret)
	if err != nil || string(pt) != "hunter2" {
		t.Errorf("secret round-trip wrong: %q %v", pt, err)
	}
}

func TestUserChannelOwnerIsolation(t *testing.T) {
	st := newTestStore(t)
	c, _ := st.CreateUserChannel("alice", emailInput())

	// Bob cannot see, update, or delete Alice's channel.
	if _, err := st.GetUserChannel("bob", c.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("bob get alice's channel = %v, want ErrNotFound", err)
	}
	if _, err := st.UpdateUserChannel("bob", c.ID, emailInput()); !errors.Is(err, ErrNotFound) {
		t.Errorf("bob update = %v, want ErrNotFound", err)
	}
	if err := st.DeleteUserChannel("bob", c.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("bob delete = %v, want ErrNotFound", err)
	}
	bobList, _ := st.ListUserChannels("bob")
	if len(bobList) != 0 {
		t.Errorf("bob list = %d, want 0", len(bobList))
	}
	aliceList, _ := st.ListUserChannels("alice")
	if len(aliceList) != 1 {
		t.Errorf("alice list = %d, want 1", len(aliceList))
	}
}

func TestUserChannelListEnabledAndUpdateDelete(t *testing.T) {
	st := newTestStore(t)
	on, _ := st.CreateUserChannel("alice", webhookInput("on", "https://on", true))
	_, _ = st.CreateUserChannel("alice", webhookInput("off", "https://off", false))

	enabled, _ := st.ListEnabledUserChannels("alice")
	if len(enabled) != 1 || enabled[0].ID != on.ID {
		t.Errorf("enabled = %+v, want just the on channel", enabled)
	}

	// Update preserves the secret when omitted.
	upd := webhookInput("on", "https://on2", true)
	got, err := st.UpdateUserChannel("alice", on.ID, upd)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if got.Config.URL != "https://on2" {
		t.Errorf("update did not persist: %+v", got.Config)
	}

	if err := st.DeleteUserChannel("alice", on.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := st.GetUserChannel("alice", on.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("get after delete = %v, want ErrNotFound", err)
	}
}

func TestUserChannelCreateValidation(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.CreateUserChannel("", emailInput()); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty uid should be ErrInvalid, got %v", err)
	}
	if _, err := st.CreateUserChannel("alice", ChannelInput{Name: "s", Type: TypeSlack}); !errors.Is(err, ErrInvalid) {
		t.Errorf("slack without secret should be ErrInvalid, got %v", err)
	}
}

func TestSubscriptionRoundTripAndDefault(t *testing.T) {
	st := newTestStore(t)
	def, err := st.GetSubscription("alice")
	if err != nil {
		t.Fatalf("get default: %v", err)
	}
	if def.Enabled {
		t.Error("default subscription should be disabled")
	}

	in := Subscription{Enabled: true, Groups: []string{"g1", "g1", " "}, Severities: []string{"critical"}}
	if err := st.SetSubscription("alice", in); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, _ := st.GetSubscription("alice")
	if !got.Enabled || !reflect.DeepEqual(got.Groups, []string{"g1"}) || !reflect.DeepEqual(got.Severities, []string{"critical"}) {
		t.Errorf("subscription not normalized/persisted: %+v", got)
	}

	all, _ := st.ListSubscriptions()
	if len(all) != 1 || all[0].UserID != "alice" {
		t.Errorf("list subscriptions = %+v", all)
	}
}

func TestSubscriptionValidation(t *testing.T) {
	st := newTestStore(t)
	if err := st.SetSubscription("", Subscription{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty uid should be ErrInvalid, got %v", err)
	}
	if err := st.SetSubscription("alice", Subscription{Severities: []string{"fatal"}}); !errors.Is(err, ErrInvalid) {
		t.Errorf("unknown severity should be ErrInvalid, got %v", err)
	}
}

func TestSubscriptionMatches(t *testing.T) {
	s := Subscription{Enabled: true, Groups: []string{"g1"}, Severities: []string{"critical"}}
	if !s.Matches("g1", "critical") {
		t.Error("should match g1/critical")
	}
	if s.Matches("g2", "critical") {
		t.Error("should not match other group")
	}
	if s.Matches("g1", "info") {
		t.Error("should not match other severity")
	}
	if (Subscription{Enabled: false}).Matches("g1", "critical") {
		t.Error("disabled should never match")
	}
	// Empty groups + severities = everything (when enabled).
	if !(Subscription{Enabled: true}).Matches("anything", "info") {
		t.Error("empty filters should match all when enabled")
	}
}

func TestUserPolicyRoundTripAndDefault(t *testing.T) {
	st := newTestStore(t)
	def, err := st.GetUserPolicy("alice")
	if err != nil {
		t.Fatalf("get default: %v", err)
	}
	if def.Timezone != "UTC" || def.Severities["info"] != ModeDashboard {
		t.Errorf("default user policy = %+v", def)
	}
	in := Policy{Timezone: "America/New_York", Windows: []QuietWindow{{Start: "22:00", End: "08:00"}}}
	if err := st.SetUserPolicy("alice", in); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, _ := st.GetUserPolicy("alice")
	if got.Timezone != "America/New_York" || len(got.Windows) != 1 {
		t.Errorf("user policy not persisted: %+v", got)
	}
	// Isolation: Bob still gets the default.
	bob, _ := st.GetUserPolicy("bob")
	if bob.Timezone != "UTC" {
		t.Errorf("bob policy leaked alice's: %+v", bob)
	}
}

func TestUserPolicyValidation(t *testing.T) {
	st := newTestStore(t)
	if err := st.SetUserPolicy("", Policy{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty uid should be ErrInvalid, got %v", err)
	}
	if err := st.SetUserPolicy("alice", Policy{Timezone: "Bad/Zone"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad tz should be ErrInvalid, got %v", err)
	}
}

func TestUserDeliveriesScopedFromGlobal(t *testing.T) {
	st := newTestStore(t)
	_, _ = st.RecordDelivery(Delivery{ChannelName: "shared", Kind: "fired", Status: DeliverySuccess, At: time.Now()})
	_, _ = st.RecordDelivery(Delivery{ChannelName: "personal", Kind: "test", Status: DeliverySuccess, At: time.Now(), UserID: "alice"})

	global, _ := st.ListDeliveries(0)
	if len(global) != 1 || global[0].ChannelName != "shared" {
		t.Errorf("global deliveries should exclude personal: %+v", global)
	}
	mine, _ := st.ListUserDeliveries("alice", 0)
	if len(mine) != 1 || mine[0].ChannelName != "personal" {
		t.Errorf("user deliveries wrong: %+v", mine)
	}
	bob, _ := st.ListUserDeliveries("bob", 0)
	if len(bob) != 0 {
		t.Errorf("bob deliveries = %d, want 0", len(bob))
	}
}

func TestUserStoreDBErrors(t *testing.T) {
	st := newTestStore(t)
	c, _ := st.CreateUserChannel("alice", webhookInput("h", "https://x", true))
	_ = st.db.Close()
	if _, err := st.GetUserChannel("alice", c.ID); err == nil {
		t.Error("GetUserChannel on closed db should error")
	}
	if _, err := st.ListUserChannels("alice"); err == nil {
		t.Error("ListUserChannels on closed db should error")
	}
	if _, err := st.GetSubscription("alice"); err == nil {
		t.Error("GetSubscription on closed db should error")
	}
	if err := st.SetSubscription("alice", Subscription{}); err == nil {
		t.Error("SetSubscription on closed db should error")
	}
	if _, err := st.ListSubscriptions(); err == nil {
		t.Error("ListSubscriptions on closed db should error")
	}
	if _, err := st.GetUserPolicy("alice"); err == nil {
		t.Error("GetUserPolicy on closed db should error")
	}
	if err := st.SetUserPolicy("alice", Policy{Timezone: "UTC"}); err == nil {
		t.Error("SetUserPolicy on closed db should error")
	}
	if _, err := st.ListUserDeliveries("alice", 0); err == nil {
		t.Error("ListUserDeliveries on closed db should error")
	}
}

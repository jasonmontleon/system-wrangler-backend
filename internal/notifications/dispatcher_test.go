// SPDX-License-Identifier: Apache-2.0

package notifications

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"system-wrangler-backend/internal/alerts"
	"system-wrangler-backend/internal/secrets"
)

type fakeSender struct {
	mu    sync.Mutex
	calls []fakeCall
	err   error
}

type fakeCall struct {
	channel Channel
	secret  string
	msg     Message
}

func (f *fakeSender) Send(_ context.Context, c Channel, secret string, msg Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fakeCall{c, secret, msg})
	return f.err
}

func (f *fakeSender) snapshot() []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeCall(nil), f.calls...)
}

func webhookInput(name, url string, enabled bool) ChannelInput {
	return ChannelInput{Name: name, Type: TypeWebhook, Enabled: enabled, Config: Config{URL: url}}
}

func firedTransition() alerts.Transition {
	return alerts.Transition{
		Rule:     alerts.Rule{Name: "High memory", Severity: alerts.SeverityCritical, ConditionKind: alerts.KindMetric},
		SystemID: "sys-1", Value: 95, Kind: alerts.TransitionFired, At: time.Unix(1700000000, 0).UTC(),
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		if cond() {
			return
		}
		select {
		case <-deadline:
			t.Fatal("condition not met within deadline")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestDispatcherEmitFansOutToEnabledOnly(t *testing.T) {
	st := newTestStore(t)
	on, _ := st.Create(webhookInput("on", "https://x/on", true), "u")
	_, _ = st.Create(webhookInput("off", "https://x/off", false), "u")
	fake := &fakeSender{}
	d := &Dispatcher{
		Store:      st,
		Senders:    Senders{TypeWebhook: fake},
		SystemName: func(id string) string { return "name-" + id },
	}
	d.Emit(context.Background(), []alerts.Transition{firedTransition()})

	waitFor(t, func() bool { return len(fake.snapshot()) == 1 })
	calls := fake.snapshot()
	if calls[0].channel.ID != on.ID {
		t.Errorf("delivered to wrong channel: %s", calls[0].channel.Name)
	}
	if calls[0].msg.SystemName != "name-sys-1" {
		t.Errorf("system name not resolved: %q", calls[0].msg.SystemName)
	}
	if calls[0].msg.Subject != "[FIRING] High memory on name-sys-1" {
		t.Errorf("subject wrong: %q", calls[0].msg.Subject)
	}
	// A delivery row is recorded.
	waitFor(t, func() bool {
		ds, _ := st.ListDeliveries(0)
		return len(ds) == 1 && ds[0].Status == DeliverySuccess
	})
}

func TestDispatcherRecordsFailure(t *testing.T) {
	st := newTestStore(t)
	_, _ = st.Create(webhookInput("on", "https://x", true), "u")
	d := &Dispatcher{Store: st, Senders: Senders{TypeWebhook: &fakeSender{err: errors.New("boom")}}}
	d.Emit(context.Background(), []alerts.Transition{firedTransition()})
	waitFor(t, func() bool {
		ds, _ := st.ListDeliveries(0)
		return len(ds) == 1 && ds[0].Status == DeliveryFailed && ds[0].Error == "boom"
	})
}

func TestDispatcherEmitNoChannelsNoop(t *testing.T) {
	st := newTestStore(t)
	d := &Dispatcher{Store: st, Senders: Senders{}}
	d.Emit(context.Background(), []alerts.Transition{firedTransition()})
	// Nothing recorded.
	ds, _ := st.ListDeliveries(0)
	if len(ds) != 0 {
		t.Errorf("expected no deliveries, got %d", len(ds))
	}
}

func TestDispatcherDecryptsSecret(t *testing.T) {
	st := newTestStore(t)
	in := webhookInput("auth", "https://x", true)
	in.Config.HeaderName = "X-Token"
	in.Secret = "s3cr3t"
	c, _ := st.Create(in, "u")
	fake := &fakeSender{}
	d := &Dispatcher{Store: st, Vault: st.Vault, Senders: Senders{TypeWebhook: fake}}
	if err := d.Test(context.Background(), mustGet(t, st, c.ID)); err != nil {
		t.Fatalf("test send: %v", err)
	}
	calls := fake.snapshot()
	if len(calls) != 1 || calls[0].secret != "s3cr3t" {
		t.Errorf("secret not decrypted/passed: %+v", calls)
	}
}

func TestDispatcherTestReportsAndRecords(t *testing.T) {
	st := newTestStore(t)
	c, _ := st.Create(webhookInput("on", "https://x", true), "u")
	d := &Dispatcher{Store: st, Senders: Senders{TypeWebhook: &fakeSender{err: errors.New("down")}}}
	err := d.Test(context.Background(), mustGet(t, st, c.ID))
	if err == nil || err.Error() != "down" {
		t.Errorf("Test should return the send error, got %v", err)
	}
	ds, _ := st.ListDeliveries(0)
	if len(ds) != 1 || ds[0].Kind != "test" || ds[0].Status != DeliveryFailed {
		t.Errorf("test delivery not recorded: %+v", ds)
	}
}

func TestDispatcherSendOneNoSender(t *testing.T) {
	st := newTestStore(t)
	c, _ := st.Create(webhookInput("on", "https://x", true), "u")
	d := &Dispatcher{Store: st, Senders: Senders{}} // no webhook sender
	if err := d.Test(context.Background(), mustGet(t, st, c.ID)); err == nil {
		t.Error("expected error when no sender registered for type")
	}
}

func TestDispatcherSendOneSecretNoVault(t *testing.T) {
	st := newTestStore(t)
	in := webhookInput("auth", "https://x", true)
	in.Config.HeaderName = "X-Token"
	in.Secret = "s3cr3t"
	c, _ := st.Create(in, "u")
	// Vault nil but the channel carries a sealed secret → sendOne refuses.
	d := &Dispatcher{Store: st, Vault: nil, Senders: Senders{TypeWebhook: &fakeSender{}}}
	if err := d.Test(context.Background(), mustGet(t, st, c.ID)); err == nil {
		t.Error("expected error opening a secret with no vault")
	}
}

func TestDispatcherSendOneDecryptError(t *testing.T) {
	st := newTestStore(t) // secret sealed under st.Vault (all-zero key)
	in := webhookInput("auth", "https://x", true)
	in.Config.HeaderName = "X-Token"
	in.Secret = "s3cr3t"
	c, _ := st.Create(in, "u")
	wrong, err := secrets.NewVaultFromKey(bytes.Repeat([]byte{0xAB}, secrets.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	d := &Dispatcher{Store: st, Vault: wrong, Senders: Senders{TypeWebhook: &fakeSender{}}}
	if err := d.Test(context.Background(), mustGet(t, st, c.ID)); err == nil {
		t.Error("expected decrypt error with the wrong vault key")
	}
}

func TestDispatcherEmitListEnabledError(t *testing.T) {
	st := newTestStore(t)
	d := &Dispatcher{Store: failStore{Store: st, failEnabled: true}, Senders: Senders{TypeWebhook: &fakeSender{}}}
	// Must not panic; nothing recorded.
	d.Emit(context.Background(), []alerts.Transition{firedTransition()})
	ds, _ := st.ListDeliveries(0)
	if len(ds) != 0 {
		t.Errorf("expected no deliveries on ListEnabled error, got %d", len(ds))
	}
}

func TestDispatcherMessageUnreachableAndResolved(t *testing.T) {
	d := &Dispatcher{}
	tr := alerts.Transition{
		Rule:     alerts.Rule{Name: "down", Severity: alerts.SeverityWarning, ConditionKind: alerts.KindUnreachable},
		SystemID: "sys-9", Value: 1, Kind: alerts.TransitionResolved, At: time.Unix(1700000000, 0).UTC(),
	}
	msg := d.message(tr)
	if msg.Subject != "[RESOLVED] down on sys-9" {
		t.Errorf("subject wrong: %q", msg.Subject)
	}
	if !strings.Contains(msg.Body, "Observed value: unreachable") {
		t.Errorf("unreachable value not rendered: %q", msg.Body)
	}
}

func mustGet(t *testing.T, st *SQLiteStore, id string) Channel {
	t.Helper()
	c, err := st.Get(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	return c
}

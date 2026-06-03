// SPDX-License-Identifier: Apache-2.0

package notifications

import (
	"context"
	"testing"
	"time"

	"system-wrangler-backend/internal/alerts"
)

type fakeResolver struct {
	users []string
	err   error
}

func (f fakeResolver) Subscribers(_, _ string) ([]string, error) {
	return f.users, f.err
}

// personalDispatcher builds a dispatcher with no shared channels (so only
// the personal path can fire), a fake sender, and the given resolver.
func personalDispatcher(t *testing.T, resolver SubscriberResolver) (*SQLiteStore, *fakeSender, *Dispatcher) {
	t.Helper()
	st := newTestStore(t)
	fake := &fakeSender{}
	d := &Dispatcher{
		Store: st, Senders: Senders{TypeWebhook: fake}, Subscribers: resolver,
		Now: func() time.Time { return time.Unix(1700000000, 0).UTC() },
	}
	return st, fake, d
}

func TestEmitPersonalDeliversToSubscriber(t *testing.T) {
	st, fake, d := personalDispatcher(t, fakeResolver{users: []string{"alice"}})
	_, _ = st.CreateUserChannel("alice", webhookInput("a", "https://a", true))
	// critical → always by default.
	d.Emit(context.Background(), []alerts.Transition{sevTransition("r1", "critical", alerts.TransitionFired)})
	waitFor(t, func() bool { return len(fake.snapshot()) == 1 })
	waitFor(t, func() bool {
		ds, _ := st.ListUserDeliveries("alice", 0)
		return len(ds) == 1 && ds[0].Status == DeliverySuccess
	})
	// Nothing landed in the shared log.
	if g, _ := st.ListDeliveries(0); len(g) != 0 {
		t.Errorf("shared deliveries = %d, want 0", len(g))
	}
}

func TestEmitPersonalQuietDefersByUserPolicy(t *testing.T) {
	st, fake, d := personalDispatcher(t, fakeResolver{users: []string{"alice"}})
	_, _ = st.CreateUserChannel("alice", webhookInput("a", "https://a", true))
	_ = st.SetUserPolicy("alice", allDayPolicy())
	d.Emit(context.Background(), []alerts.Transition{sevTransition("r1", "warning", alerts.TransitionFired)})
	waitFor(t, func() bool {
		p, _ := st.ListPending()
		return len(p) == 1 && p[0].UserID == "alice"
	})
	if len(fake.snapshot()) != 0 {
		t.Errorf("deferred personal transition should not send, got %d", len(fake.snapshot()))
	}
}

func TestEmitPersonalDashboardSuppresses(t *testing.T) {
	st, fake, d := personalDispatcher(t, fakeResolver{users: []string{"alice"}})
	_, _ = st.CreateUserChannel("alice", webhookInput("a", "https://a", true))
	// info → dashboard by default: a suppressed row in alice's log, no send.
	d.Emit(context.Background(), []alerts.Transition{sevTransition("r1", "info", alerts.TransitionFired)})
	waitFor(t, func() bool {
		ds, _ := st.ListUserDeliveries("alice", 0)
		return len(ds) == 1 && ds[0].Status == DeliverySuppressed
	})
	if len(fake.snapshot()) != 0 {
		t.Errorf("dashboard severity should not send, got %d", len(fake.snapshot()))
	}
}

func TestEmitPersonalIgnoresGlobalQuietHours(t *testing.T) {
	st, fake, d := personalDispatcher(t, fakeResolver{users: []string{"alice"}})
	_, _ = st.CreateUserChannel("alice", webhookInput("a", "https://a", true))
	// Global is quiet 24/7, but Alice's default policy pages criticals — her
	// personal path is independent of the global policy.
	_ = st.SetPolicy(allDayPolicy())
	d.Emit(context.Background(), []alerts.Transition{sevTransition("r1", "critical", alerts.TransitionFired)})
	waitFor(t, func() bool { return len(fake.snapshot()) == 1 })
}

func TestEmitResolverErrorSkipsPersonal(t *testing.T) {
	st, fake, d := personalDispatcher(t, fakeResolver{err: context.DeadlineExceeded})
	_, _ = st.CreateUserChannel("alice", webhookInput("a", "https://a", true))
	d.Emit(context.Background(), []alerts.Transition{sevTransition("r1", "critical", alerts.TransitionFired)})
	if len(fake.snapshot()) != 0 {
		t.Errorf("resolver error should skip personal delivery, got %d", len(fake.snapshot()))
	}
}

func TestSubscriberResolverFunc(t *testing.T) {
	var r SubscriberResolver = SubscriberResolverFunc(func(sys, sev string) ([]string, error) {
		if sys != "s1" || sev != "critical" {
			t.Errorf("unexpected args %q %q", sys, sev)
		}
		return []string{"x"}, nil
	})
	got, err := r.Subscribers("s1", "critical")
	if err != nil || len(got) != 1 || got[0] != "x" {
		t.Errorf("adapter = %v %v", got, err)
	}
}

func TestEmitPersonalCachesPerUserAcrossBatch(t *testing.T) {
	st, fake, d := personalDispatcher(t, fakeResolver{users: []string{"alice"}})
	_, _ = st.CreateUserChannel("alice", webhookInput("a", "https://a", true))
	// Two transitions for the same subscriber: her policy + channels are
	// loaded once and reused (cache-hit path).
	d.Emit(context.Background(), []alerts.Transition{
		sevTransition("r1", "critical", alerts.TransitionFired),
		sevTransition("r2", "critical", alerts.TransitionFired),
	})
	waitFor(t, func() bool { return len(fake.snapshot()) == 2 })
}

func TestFlushPersonalDeliversWhenUserOutsideQuiet(t *testing.T) {
	st, fake, d := personalDispatcher(t, nil)
	_, _ = st.CreateUserChannel("alice", webhookInput("a", "https://a", true))
	_, _ = st.EnqueuePending(PendingDelivery{
		UserID: "alice", RuleID: "r1", SystemID: "s1", Kind: "fired", Message: Message{Kind: "fired"},
	})
	// Alice has no personal policy → default (no windows) → flush delivers.
	d.FlushPending(context.Background())
	waitFor(t, func() bool { return len(fake.snapshot()) == 1 })
	waitFor(t, func() bool { p, _ := st.ListPending(); return len(p) == 0 })
}

func TestFlushPersonalLeavesWhenUserQuiet(t *testing.T) {
	st, fake, d := personalDispatcher(t, nil)
	_, _ = st.CreateUserChannel("alice", webhookInput("a", "https://a", true))
	_ = st.SetUserPolicy("alice", allDayPolicy())
	_, _ = st.EnqueuePending(PendingDelivery{
		UserID: "alice", RuleID: "r1", SystemID: "s1", Kind: "fired", Message: Message{Kind: "fired"},
	})
	d.FlushPending(context.Background())
	if len(fake.snapshot()) != 0 {
		t.Errorf("flush during the user's quiet hours should be a no-op, sent %d", len(fake.snapshot()))
	}
	if p, _ := st.ListPending(); len(p) != 1 {
		t.Errorf("personal pending should survive, got %d", len(p))
	}
}

func TestFlushPersonalCollapses(t *testing.T) {
	st, fake, d := personalDispatcher(t, nil)
	_, _ = st.CreateUserChannel("alice", webhookInput("a", "https://a", true))
	_, _ = st.EnqueuePending(PendingDelivery{UserID: "alice", RuleID: "r1", SystemID: "s1", Kind: "fired", Message: Message{Kind: "fired"}})
	_, _ = st.EnqueuePending(PendingDelivery{UserID: "alice", RuleID: "r1", SystemID: "s1", Kind: "resolved", Message: Message{Kind: "resolved"}})
	d.FlushPending(context.Background())
	waitFor(t, func() bool { p, _ := st.ListPending(); return len(p) == 0 })
	if len(fake.snapshot()) != 0 {
		t.Errorf("fired+resolved should collapse, sent %d", len(fake.snapshot()))
	}
}

func TestFlushGlobalAndPersonalIndependent(t *testing.T) {
	st, _, d := personalDispatcher(t, nil)
	shared, _ := st.Create(webhookInput("shared", "https://s", true), "admin")
	_, _ = st.CreateUserChannel("alice", webhookInput("a", "https://a", true))
	// Global is quiet 24/7 (shared pending stays); Alice is not (personal flushes).
	_ = st.SetPolicy(allDayPolicy())
	_, _ = st.EnqueuePending(PendingDelivery{RuleID: "r1", SystemID: "s1", Kind: "fired", Message: Message{Kind: "fired"}})
	_, _ = st.EnqueuePending(PendingDelivery{UserID: "alice", RuleID: "r1", SystemID: "s1", Kind: "fired", Message: Message{Kind: "fired"}})

	d.FlushPending(context.Background())
	// Only Alice's personal delivery fires; the shared one stays deferred.
	waitFor(t, func() bool {
		ds, _ := st.ListUserDeliveries("alice", 0)
		return len(ds) == 1
	})
	if g, _ := st.ListDeliveries(0); len(g) != 0 {
		t.Errorf("shared should remain deferred under global quiet hours, sent %d (channel %s)", len(g), shared.ID)
	}
	p, _ := st.ListPending()
	if len(p) != 1 || p[0].UserID != "" {
		t.Errorf("the shared pending row should remain, got %+v", p)
	}
}

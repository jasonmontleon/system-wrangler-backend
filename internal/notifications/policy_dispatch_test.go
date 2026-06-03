// SPDX-License-Identifier: Apache-2.0

package notifications

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"system-wrangler-backend/internal/alerts"
)

func sevTransition(ruleID, sev string, kind alerts.TransitionKind) alerts.Transition {
	return alerts.Transition{
		Rule: alerts.Rule{
			ID: ruleID, Name: "R-" + ruleID,
			Severity: alerts.Severity(sev), ConditionKind: alerts.KindMetric,
		},
		SystemID: "sys-1", Value: 95, Kind: kind, At: time.Unix(1700000000, 0).UTC(),
	}
}

// allDayPolicy is quiet 24/7, forcing every quiet-mode transition to defer.
func allDayPolicy() Policy {
	return Policy{Timezone: "UTC", Windows: []QuietWindow{{Start: "00:00", End: "24:00"}}}
}

func dispatcherWithChannel(t *testing.T) (*SQLiteStore, *fakeSender, *Dispatcher) {
	t.Helper()
	st := newTestStore(t)
	_, _ = st.Create(webhookInput("hook", "https://x", true), "u")
	fake := &fakeSender{}
	d := &Dispatcher{Store: st, Senders: Senders{TypeWebhook: fake}, Now: func() time.Time { return time.Unix(1700000000, 0).UTC() }}
	return st, fake, d
}

func TestEmitDashboardSeveritySuppressed(t *testing.T) {
	st, fake, d := dispatcherWithChannel(t)
	// info → dashboard by default: recorded suppressed, never sent, not queued.
	d.Emit(context.Background(), []alerts.Transition{sevTransition("r1", "info", alerts.TransitionFired)})
	waitFor(t, func() bool {
		ds, _ := st.ListDeliveries(0)
		return len(ds) == 1 && ds[0].Status == DeliverySuppressed
	})
	if len(fake.snapshot()) != 0 {
		t.Errorf("dashboard severity should not send, got %d", len(fake.snapshot()))
	}
	if pending, _ := st.ListPending(); len(pending) != 0 {
		t.Errorf("dashboard severity should not defer, got %d", len(pending))
	}
}

func TestEmitQuietSeverityDefersInsideWindow(t *testing.T) {
	st, fake, d := dispatcherWithChannel(t)
	_ = st.SetPolicy(allDayPolicy())
	// warning → quiet; inside the all-day window it is deferred, not sent.
	d.Emit(context.Background(), []alerts.Transition{sevTransition("r1", "warning", alerts.TransitionFired)})
	waitFor(t, func() bool {
		pending, _ := st.ListPending()
		return len(pending) == 1
	})
	if len(fake.snapshot()) != 0 {
		t.Errorf("deferred transition should not send, got %d", len(fake.snapshot()))
	}
	ds, _ := st.ListDeliveries(0)
	if len(ds) != 1 || ds[0].Status != DeliveryDeferred {
		t.Errorf("expected one deferred row, got %+v", ds)
	}
}

func TestEmitQuietSeverityDeliversOutsideWindow(t *testing.T) {
	st, fake, d := dispatcherWithChannel(t)
	// No quiet window → warning delivers immediately.
	d.Emit(context.Background(), []alerts.Transition{sevTransition("r1", "warning", alerts.TransitionFired)})
	waitFor(t, func() bool { return len(fake.snapshot()) == 1 })
	if pending, _ := st.ListPending(); len(pending) != 0 {
		t.Errorf("should not defer outside a window, got %d", len(pending))
	}
}

func TestEmitAlwaysSeverityIgnoresQuietHours(t *testing.T) {
	st, fake, d := dispatcherWithChannel(t)
	_ = st.SetPolicy(allDayPolicy())
	// critical → always: delivered even inside the all-day window.
	d.Emit(context.Background(), []alerts.Transition{sevTransition("r1", "critical", alerts.TransitionFired)})
	waitFor(t, func() bool { return len(fake.snapshot()) == 1 })
	if pending, _ := st.ListPending(); len(pending) != 0 {
		t.Errorf("always severity should not defer, got %d", len(pending))
	}
}

// --- flusher ---

func TestFlushPendingDeliversLast(t *testing.T) {
	st, fake, d := dispatcherWithChannel(t)
	// No quiet window → flush proceeds. Two fired updates for one pair;
	// the last is delivered once.
	_, _ = st.EnqueuePending(PendingDelivery{RuleID: "r1", SystemID: "s1", Kind: "fired", Message: Message{Kind: "fired", Subject: "first"}})
	_, _ = st.EnqueuePending(PendingDelivery{RuleID: "r1", SystemID: "s1", Kind: "fired", Message: Message{Kind: "fired", Subject: "second"}})
	d.FlushPending(context.Background())
	waitFor(t, func() bool { return len(fake.snapshot()) == 1 })
	if got := fake.snapshot()[0].msg.Subject; got != "second" {
		t.Errorf("delivered %q, want the last (second)", got)
	}
	waitFor(t, func() bool { p, _ := st.ListPending(); return len(p) == 0 })
}

func TestFlushPendingCollapsesFiredAndResolved(t *testing.T) {
	st, fake, d := dispatcherWithChannel(t)
	_, _ = st.EnqueuePending(PendingDelivery{RuleID: "r1", SystemID: "s1", Kind: "fired", Message: Message{Kind: "fired"}})
	_, _ = st.EnqueuePending(PendingDelivery{RuleID: "r1", SystemID: "s1", Kind: "resolved", Message: Message{Kind: "resolved"}})
	d.FlushPending(context.Background())
	waitFor(t, func() bool { p, _ := st.ListPending(); return len(p) == 0 })
	if len(fake.snapshot()) != 0 {
		t.Errorf("fired+resolved should collapse to nothing, sent %d", len(fake.snapshot()))
	}
}

func TestFlushPendingResolvedOnlyDelivers(t *testing.T) {
	st, fake, d := dispatcherWithChannel(t)
	// A resolved with no matching deferred fire (the fire was sent before
	// quiet hours) still notifies that it cleared.
	_, _ = st.EnqueuePending(PendingDelivery{RuleID: "r1", SystemID: "s1", Kind: "resolved", Message: Message{Kind: "resolved"}})
	d.FlushPending(context.Background())
	waitFor(t, func() bool { return len(fake.snapshot()) == 1 })
}

func TestFlushPendingNoopWhileQuiet(t *testing.T) {
	st, fake, d := dispatcherWithChannel(t)
	_ = st.SetPolicy(allDayPolicy())
	_, _ = st.EnqueuePending(PendingDelivery{RuleID: "r1", SystemID: "s1", Kind: "fired", Message: Message{Kind: "fired"}})
	d.FlushPending(context.Background())
	if len(fake.snapshot()) != 0 {
		t.Errorf("flush during quiet hours should be a no-op, sent %d", len(fake.snapshot()))
	}
	if p, _ := st.ListPending(); len(p) != 1 {
		t.Errorf("pending should survive a quiet-hours flush, got %d", len(p))
	}
}

func TestFlusherRunFlushesThenStops(t *testing.T) {
	st, fake, d := dispatcherWithChannel(t)
	_, _ = st.EnqueuePending(PendingDelivery{RuleID: "r1", SystemID: "s1", Kind: "fired", Message: Message{Kind: "fired"}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go (&Flusher{Dispatcher: d, Interval: 10 * time.Millisecond}).Run(ctx)
	waitFor(t, func() bool { return len(fake.snapshot()) == 1 })
	cancel()
}

func TestFlusherIntervalDefault(t *testing.T) {
	f := &Flusher{}
	if f.interval() != DefaultFlushInterval {
		t.Errorf("default interval = %v, want %v", f.interval(), DefaultFlushInterval)
	}
}

// --- handler ---

func TestHandlerPolicyGetAndPut(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := req(t, http.MethodGet, srv.URL+"/api/notifications/policy", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get policy = %d", resp.StatusCode)
	}
	var def Policy
	_ = json.NewDecoder(resp.Body).Decode(&def)
	_ = resp.Body.Close()
	if def.Timezone != "UTC" {
		t.Errorf("default tz = %q", def.Timezone)
	}

	body := `{"timezone":"America/New_York","windows":[{"days":[1,2],"start":"22:00","end":"08:00"}],"severities":{"warning":"always"}}`
	resp = req(t, http.MethodPut, srv.URL+"/api/notifications/policy", body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put policy = %d", resp.StatusCode)
	}
	var got Policy
	_ = json.NewDecoder(resp.Body).Decode(&got)
	_ = resp.Body.Close()
	if got.Timezone != "America/New_York" || got.Severities["warning"] != ModeAlways || len(got.Windows) != 1 {
		t.Errorf("put response = %+v", got)
	}
}

func TestHandlerPolicyPutInvalidAndBadJSON(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := req(t, http.MethodPut, srv.URL+"/api/notifications/policy", `{"timezone":"Bad/Zone"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid tz should 400, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	resp = req(t, http.MethodPut, srv.URL+"/api/notifications/policy", `{bad`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad JSON should 400, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerPolicyForbidden(t *testing.T) {
	srv, _, h := newHandlerFixture(t)
	h.CanManage = func(context.Context) bool { return false }
	for _, m := range []struct{ method, body string }{
		{http.MethodGet, ""},
		{http.MethodPut, `{"timezone":"UTC"}`},
	} {
		resp := req(t, m.method, srv.URL+"/api/notifications/policy", m.body)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s policy should 403, got %d", m.method, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}

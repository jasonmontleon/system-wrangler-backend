// SPDX-License-Identifier: Apache-2.0

package notifications

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"testing"

	"system-wrangler-backend/internal/alerts"
)

func TestRouteModeIsValid(t *testing.T) {
	for _, m := range []RouteMode{RouteModeAll, RouteModeSelected} {
		if !m.IsValid() {
			t.Errorf("%q should be valid", m)
		}
	}
	if RouteMode("bogus").IsValid() {
		t.Error("bogus mode should be invalid")
	}
}

func TestRoutingInputValidate(t *testing.T) {
	tests := []struct {
		name     string
		in       RoutingInput
		wantErr  bool
		wantMode RouteMode
		wantIDs  []string
	}{
		{"empty mode defaults to all", RoutingInput{}, false, RouteModeAll, nil},
		{"all clears ids", RoutingInput{Mode: RouteModeAll, ChannelIDs: []string{"a"}}, false, RouteModeAll, nil},
		{"invalid mode", RoutingInput{Mode: "bogus"}, true, "", nil},
		{"selected trims and dedupes", RoutingInput{Mode: RouteModeSelected, ChannelIDs: []string{" a ", "b", "a", "  ", ""}}, false, RouteModeSelected, []string{"a", "b"}},
		{"selected empty stays empty", RoutingInput{Mode: RouteModeSelected}, false, RouteModeSelected, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := tt.in
			err := in.Validate()
			if tt.wantErr {
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("want ErrInvalid, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if in.Mode != tt.wantMode {
				t.Errorf("mode = %q, want %q", in.Mode, tt.wantMode)
			}
			if !reflect.DeepEqual(in.ChannelIDs, tt.wantIDs) {
				t.Errorf("ids = %#v, want %#v", in.ChannelIDs, tt.wantIDs)
			}
		})
	}
}

func TestGetRoutingDefaultWhenAbsent(t *testing.T) {
	st := newTestStore(t)
	r, err := st.GetRouting("rule-x")
	if err != nil {
		t.Fatalf("get routing: %v", err)
	}
	if r.Mode != RouteModeAll || len(r.ChannelIDs) != 0 {
		t.Errorf("absent routing = %+v, want all/none", r)
	}
}

func TestSetGetRoutingRoundTrip(t *testing.T) {
	st := newTestStore(t)
	if err := st.SetRouting("rule-1", RoutingInput{Mode: RouteModeSelected, ChannelIDs: []string{"c2", "c1"}}); err != nil {
		t.Fatalf("set: %v", err)
	}
	r, err := st.GetRouting("rule-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if r.Mode != RouteModeSelected {
		t.Errorf("mode = %q", r.Mode)
	}
	if !reflect.DeepEqual(r.ChannelIDs, []string{"c1", "c2"}) {
		t.Errorf("ids = %#v, want sorted [c1 c2]", r.ChannelIDs)
	}
}

func TestSetRoutingReplacesSetAndSwitchToAllClears(t *testing.T) {
	st := newTestStore(t)
	_ = st.SetRouting("rule-1", RoutingInput{Mode: RouteModeSelected, ChannelIDs: []string{"c1", "c2"}})
	// Replace the set.
	_ = st.SetRouting("rule-1", RoutingInput{Mode: RouteModeSelected, ChannelIDs: []string{"c3"}})
	r, _ := st.GetRouting("rule-1")
	if !reflect.DeepEqual(r.ChannelIDs, []string{"c3"}) {
		t.Errorf("after replace ids = %#v, want [c3]", r.ChannelIDs)
	}
	// Switch to all clears the channel rows.
	_ = st.SetRouting("rule-1", RoutingInput{Mode: RouteModeAll})
	r, _ = st.GetRouting("rule-1")
	if r.Mode != RouteModeAll || len(r.ChannelIDs) != 0 {
		t.Errorf("after switch-to-all = %+v, want all/none", r)
	}
}

func TestSetRoutingRejectsEmptyRuleAndInvalidMode(t *testing.T) {
	st := newTestStore(t)
	if err := st.SetRouting("", RoutingInput{Mode: RouteModeAll}); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty ruleId should be ErrInvalid, got %v", err)
	}
	if err := st.SetRouting("rule-1", RoutingInput{Mode: "bogus"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("invalid mode should be ErrInvalid, got %v", err)
	}
}

func TestListRoutingReturnsExplicitRows(t *testing.T) {
	st := newTestStore(t)
	_ = st.SetRouting("rule-a", RoutingInput{Mode: RouteModeSelected, ChannelIDs: []string{"c1"}})
	_ = st.SetRouting("rule-b", RoutingInput{Mode: RouteModeAll})
	rs, err := st.ListRouting()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rs) != 2 {
		t.Fatalf("len = %d, want 2", len(rs))
	}
	// Ordered by rule_id: rule-a (selected, with ids), rule-b (all, none).
	if rs[0].RuleID != "rule-a" || !reflect.DeepEqual(rs[0].ChannelIDs, []string{"c1"}) {
		t.Errorf("row 0 = %+v", rs[0])
	}
	if rs[1].RuleID != "rule-b" || rs[1].Mode != RouteModeAll || len(rs[1].ChannelIDs) != 0 {
		t.Errorf("row 1 = %+v", rs[1])
	}
}

func TestChannelDeleteCascadesRouting(t *testing.T) {
	st := newTestStore(t)
	c, _ := st.Create(webhookInput("hook", "https://x", true), "u")
	other, _ := st.Create(webhookInput("hook2", "https://y", true), "u")
	_ = st.SetRouting("rule-1", RoutingInput{Mode: RouteModeSelected, ChannelIDs: []string{c.ID, other.ID}})

	if err := st.Delete(c.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	r, _ := st.GetRouting("rule-1")
	if !reflect.DeepEqual(r.ChannelIDs, []string{other.ID}) {
		t.Errorf("after channel delete ids = %#v, want [%s]", r.ChannelIDs, other.ID)
	}
}

// --- dispatcher routing ---

func ruleTransition(ruleID string) alerts.Transition {
	tr := firedTransition()
	tr.Rule.ID = ruleID
	return tr
}

func TestDispatcherSelectedRoutesToChosenEnabledOnly(t *testing.T) {
	st := newTestStore(t)
	a, _ := st.Create(webhookInput("a", "https://a", true), "u")
	b, _ := st.Create(webhookInput("b", "https://b", true), "u")
	_ = st.SetRouting("rule-1", RoutingInput{Mode: RouteModeSelected, ChannelIDs: []string{a.ID}})
	fake := &fakeSender{}
	d := &Dispatcher{Store: st, Senders: Senders{TypeWebhook: fake}}
	d.Emit(context.Background(), []alerts.Transition{ruleTransition("rule-1")})

	waitFor(t, func() bool { return len(fake.snapshot()) == 1 })
	calls := fake.snapshot()
	if calls[0].channel.ID != a.ID {
		t.Errorf("routed to %s, want %s (b=%s)", calls[0].channel.ID, a.ID, b.ID)
	}
}

func TestDispatcherSelectedSkipsDisabledAndUnknown(t *testing.T) {
	st := newTestStore(t)
	enabled, _ := st.Create(webhookInput("on", "https://on", true), "u")
	disabled, _ := st.Create(webhookInput("off", "https://off", false), "u")
	// Route to the disabled channel + a bogus id; neither should fire.
	_ = st.SetRouting("rule-1", RoutingInput{Mode: RouteModeSelected, ChannelIDs: []string{disabled.ID, "ghost"}})
	fake := &fakeSender{}
	d := &Dispatcher{Store: st, Senders: Senders{TypeWebhook: fake}}
	d.Emit(context.Background(), []alerts.Transition{ruleTransition("rule-1")})
	// Nothing delivered; also nothing recorded.
	ds, _ := st.ListDeliveries(0)
	if len(ds) != 0 || len(fake.snapshot()) != 0 {
		t.Errorf("disabled/unknown routing fired: deliveries=%d calls=%d (enabled=%s)", len(ds), len(fake.snapshot()), enabled.ID)
	}
}

func TestDispatcherEmptySelectionDeliversNowhere(t *testing.T) {
	st := newTestStore(t)
	_, _ = st.Create(webhookInput("on", "https://on", true), "u")
	_ = st.SetRouting("rule-1", RoutingInput{Mode: RouteModeSelected, ChannelIDs: nil})
	fake := &fakeSender{}
	d := &Dispatcher{Store: st, Senders: Senders{TypeWebhook: fake}}
	d.Emit(context.Background(), []alerts.Transition{ruleTransition("rule-1")})
	if len(fake.snapshot()) != 0 {
		t.Errorf("empty selection delivered %d", len(fake.snapshot()))
	}
}

func TestDispatcherAllModeReachesEveryEnabled(t *testing.T) {
	st := newTestStore(t)
	_, _ = st.Create(webhookInput("a", "https://a", true), "u")
	_, _ = st.Create(webhookInput("b", "https://b", true), "u")
	// Explicit all-mode row (not just the implicit default).
	_ = st.SetRouting("rule-1", RoutingInput{Mode: RouteModeAll})
	fake := &fakeSender{}
	d := &Dispatcher{Store: st, Senders: Senders{TypeWebhook: fake}}
	d.Emit(context.Background(), []alerts.Transition{ruleTransition("rule-1")})
	waitFor(t, func() bool { return len(fake.snapshot()) == 2 })
}

func TestDispatcherGetRoutingErrorFallsBackToAll(t *testing.T) {
	st := newTestStore(t)
	_, _ = st.Create(webhookInput("on", "https://on", true), "u")
	fake := &fakeSender{}
	// A GetRouting failure must not drop the alert — it falls back to the
	// all-channels default so a routing-table glitch can't silence delivery.
	d := &Dispatcher{Store: failStore{Store: st, failGetRouting: true}, Senders: Senders{TypeWebhook: fake}}
	d.Emit(context.Background(), []alerts.Transition{ruleTransition("rule-1")})
	waitFor(t, func() bool { return len(fake.snapshot()) == 1 })
}

func TestRoutingStoreDBErrors(t *testing.T) {
	st := newTestStore(t)
	// Seed a row so Delete reaches its first Exec before the closed-db error.
	c, _ := st.Create(webhookInput("hook", "https://x", true), "u")
	_ = st.db.Close()

	if _, err := st.GetRouting("r"); err == nil {
		t.Error("GetRouting on closed db should error")
	}
	if err := st.SetRouting("r", RoutingInput{Mode: RouteModeAll}); err == nil {
		t.Error("SetRouting on closed db should error")
	}
	if _, err := st.ListRouting(); err == nil {
		t.Error("ListRouting on closed db should error")
	}
	if err := st.Delete(c.ID); err == nil {
		t.Error("Delete on closed db should error")
	}
}

// --- handler routing ---

func TestHandlerRoutingPutAndList(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	body := `{"mode":"selected","channelIds":["c1","c2"]}`
	resp := req(t, http.MethodPut, srv.URL+"/api/notifications/routing/rule-1", body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put routing = %d", resp.StatusCode)
	}
	var got Routing
	_ = json.NewDecoder(resp.Body).Decode(&got)
	_ = resp.Body.Close()
	if got.Mode != RouteModeSelected || !reflect.DeepEqual(got.ChannelIDs, []string{"c1", "c2"}) {
		t.Errorf("put response = %+v", got)
	}

	resp = req(t, http.MethodGet, srv.URL+"/api/notifications/routing", "")
	var list []Routing
	_ = json.NewDecoder(resp.Body).Decode(&list)
	_ = resp.Body.Close()
	if len(list) != 1 || list[0].RuleID != "rule-1" {
		t.Errorf("list routing = %+v", list)
	}
}

func TestHandlerRoutingPutInvalidAndBadJSON(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := req(t, http.MethodPut, srv.URL+"/api/notifications/routing/rule-1", `{"mode":"bogus"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid mode should 400, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	resp = req(t, http.MethodPut, srv.URL+"/api/notifications/routing/rule-1", `{bad`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad JSON should 400, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerRoutingForbidden(t *testing.T) {
	srv, _, h := newHandlerFixture(t)
	h.CanManage = func(context.Context) bool { return false }
	for _, m := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/notifications/routing", ""},
		{http.MethodPut, "/api/notifications/routing/rule-1", `{"mode":"all"}`},
	} {
		resp := req(t, m.method, srv.URL+m.path, m.body)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s should 403, got %d", m.method, m.path, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}

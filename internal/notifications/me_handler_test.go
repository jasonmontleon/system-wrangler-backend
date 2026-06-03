// SPDX-License-Identifier: Apache-2.0

package notifications

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"system-wrangler-backend/internal/audit"
)

// meFixture builds a MeHandler server whose middleware injects userID as
// the request actor, sharing the given store so multiple users can be
// simulated against one database.
func meFixture(t *testing.T, store Store, userID string) (*httptest.Server, *MeHandler) {
	t.Helper()
	h := &MeHandler{Store: store}
	mux := http.NewServeMux()
	wrap := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if userID != "" {
				r = r.WithContext(audit.WithActor(r.Context(), audit.Actor{Kind: audit.ActorUser, ID: userID}))
			}
			next.ServeHTTP(w, r)
		})
	}
	h.Register(mux, wrap)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, h
}

// callJSON performs one request, owning the response lifecycle (read +
// close), optionally unmarshaling the body into dst, and returns the
// status and the raw body.
func callJSON(t *testing.T, method, url, body string, dst any) (int, string) {
	t.Helper()
	resp := req(t, method, url, body)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if dst != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, dst); err != nil {
			t.Fatalf("unmarshal into %T: %v (%s)", dst, err, raw)
		}
	}
	return resp.StatusCode, string(raw)
}

func TestMeChannelCreateListRedacts(t *testing.T) {
	srv, _ := meFixture(t, newTestStore(t), "alice")
	var dto ChannelDTO
	status, raw := callJSON(t, http.MethodPost, srv.URL+"/api/notifications/me/channels", emailJSON(t), &dto)
	if status != http.StatusCreated {
		t.Fatalf("create = %d", status)
	}
	if strings.Contains(raw, "hunter2") {
		t.Fatalf("response leaked secret: %s", raw)
	}
	if !dto.HasSecret || dto.ID == "" {
		t.Errorf("redacted DTO wrong: %+v", dto)
	}

	var list []ChannelDTO
	callJSON(t, http.MethodGet, srv.URL+"/api/notifications/me/channels", "", &list)
	if len(list) != 1 {
		t.Errorf("list = %d, want 1", len(list))
	}

	var one ChannelDTO
	if status, _ := callJSON(t, http.MethodGet, srv.URL+"/api/notifications/me/channels/"+dto.ID, "", &one); status != http.StatusOK || one.ID != dto.ID {
		t.Errorf("get single = %d id=%s", status, one.ID)
	}
}

func TestMeChannelOwnerIsolation(t *testing.T) {
	store := newTestStore(t)
	aliceSrv, _ := meFixture(t, store, "alice")
	bobSrv, _ := meFixture(t, store, "bob")

	var dto ChannelDTO
	callJSON(t, http.MethodPost, aliceSrv.URL+"/api/notifications/me/channels", emailJSON(t), &dto)

	// Bob can't see, edit, or delete Alice's channel.
	for _, tc := range []struct {
		method, suffix, body string
		want                 int
	}{
		{http.MethodGet, "/" + dto.ID, "", http.StatusNotFound},
		{http.MethodPut, "/" + dto.ID, emailJSON(t), http.StatusNotFound},
		{http.MethodDelete, "/" + dto.ID, "", http.StatusNotFound},
	} {
		status, _ := callJSON(t, tc.method, bobSrv.URL+"/api/notifications/me/channels"+tc.suffix, tc.body, nil)
		if status != tc.want {
			t.Errorf("bob %s %s = %d, want %d", tc.method, tc.suffix, status, tc.want)
		}
	}
	var bobList []ChannelDTO
	callJSON(t, http.MethodGet, bobSrv.URL+"/api/notifications/me/channels", "", &bobList)
	if len(bobList) != 0 {
		t.Errorf("bob list = %d, want 0", len(bobList))
	}
}

func TestMeNoActor401(t *testing.T) {
	srv, _ := meFixture(t, newTestStore(t), "")
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/notifications/me/channels", ""},
		{http.MethodPost, "/api/notifications/me/channels", emailJSON(t)},
		{http.MethodPut, "/api/notifications/me/channels/x", emailJSON(t)},
		{http.MethodDelete, "/api/notifications/me/channels/x", ""},
		{http.MethodPost, "/api/notifications/me/channels/x/test", ""},
		{http.MethodGet, "/api/notifications/me/subscription", ""},
		{http.MethodPut, "/api/notifications/me/subscription", `{"enabled":true}`},
		{http.MethodGet, "/api/notifications/me/policy", ""},
		{http.MethodPut, "/api/notifications/me/policy", `{"timezone":"UTC"}`},
		{http.MethodGet, "/api/notifications/me/deliveries", ""},
	} {
		status, _ := callJSON(t, tc.method, srv.URL+tc.path, tc.body, nil)
		if status != http.StatusUnauthorized {
			t.Errorf("%s %s without actor = %d, want 401", tc.method, tc.path, status)
		}
	}
}

func TestMeChannelCreateInvalidAndBadJSON(t *testing.T) {
	srv, _ := meFixture(t, newTestStore(t), "alice")
	if status, _ := callJSON(t, http.MethodPost, srv.URL+"/api/notifications/me/channels", `{"name":"","type":"email"}`, nil); status != http.StatusBadRequest {
		t.Errorf("invalid create = %d, want 400", status)
	}
	if status, _ := callJSON(t, http.MethodPost, srv.URL+"/api/notifications/me/channels", `{bad`, nil); status != http.StatusBadRequest {
		t.Errorf("bad JSON = %d, want 400", status)
	}
}

func TestMeChannelTest(t *testing.T) {
	store := newTestStore(t)
	srv, h := meFixture(t, store, "alice")
	fake := &fakeSender{}
	h.Dispatcher = &Dispatcher{Store: store, Senders: Senders{TypeWebhook: fake}, Vault: store.Vault}

	c, _ := store.CreateUserChannel("alice", webhookInput("h", "https://x", true))
	var res TestResult
	callJSON(t, http.MethodPost, srv.URL+"/api/notifications/me/channels/"+c.ID+"/test", "", &res)
	if !res.OK {
		t.Errorf("test result = %+v, want ok", res)
	}
	if len(fake.snapshot()) != 1 {
		t.Errorf("sender calls = %d, want 1", len(fake.snapshot()))
	}
	// The attempt is recorded against Alice's personal log, not the global one.
	mine, _ := store.ListUserDeliveries("alice", 0)
	if len(mine) != 1 {
		t.Errorf("user deliveries = %d, want 1", len(mine))
	}
	global, _ := store.ListDeliveries(0)
	if len(global) != 0 {
		t.Errorf("global deliveries = %d, want 0", len(global))
	}
}

func TestMeChannelTestNoDispatcher503(t *testing.T) {
	store := newTestStore(t)
	srv, _ := meFixture(t, store, "alice")
	c, _ := store.CreateUserChannel("alice", webhookInput("h", "https://x", true))
	if status, _ := callJSON(t, http.MethodPost, srv.URL+"/api/notifications/me/channels/"+c.ID+"/test", "", nil); status != http.StatusServiceUnavailable {
		t.Errorf("test without dispatcher = %d, want 503", status)
	}
}

func TestMeSubscription(t *testing.T) {
	srv, _ := meFixture(t, newTestStore(t), "alice")
	var def Subscription
	callJSON(t, http.MethodGet, srv.URL+"/api/notifications/me/subscription", "", &def)
	if def.Enabled {
		t.Error("default subscription should be disabled")
	}

	var got Subscription
	callJSON(t, http.MethodPut, srv.URL+"/api/notifications/me/subscription",
		`{"enabled":true,"groups":["g1"],"severities":["critical"]}`, &got)
	if !got.Enabled || len(got.Groups) != 1 {
		t.Errorf("put subscription = %+v", got)
	}

	if status, _ := callJSON(t, http.MethodPut, srv.URL+"/api/notifications/me/subscription", `{"severities":["fatal"]}`, nil); status != http.StatusBadRequest {
		t.Errorf("invalid severity = %d, want 400", status)
	}
}

func TestMePolicy(t *testing.T) {
	srv, _ := meFixture(t, newTestStore(t), "alice")
	var def Policy
	callJSON(t, http.MethodGet, srv.URL+"/api/notifications/me/policy", "", &def)
	if def.Timezone != "UTC" {
		t.Errorf("default policy tz = %q", def.Timezone)
	}

	var got Policy
	callJSON(t, http.MethodPut, srv.URL+"/api/notifications/me/policy",
		`{"timezone":"America/New_York","windows":[],"severities":{"warning":"always"}}`, &got)
	if got.Timezone != "America/New_York" || got.Severities["warning"] != ModeAlways {
		t.Errorf("put policy = %+v", got)
	}

	if status, _ := callJSON(t, http.MethodPut, srv.URL+"/api/notifications/me/policy", `{"timezone":"Bad/Zone"}`, nil); status != http.StatusBadRequest {
		t.Errorf("invalid tz = %d, want 400", status)
	}
}

func TestMeDeliveries(t *testing.T) {
	store := newTestStore(t)
	srv, _ := meFixture(t, store, "alice")
	_, _ = store.RecordDelivery(Delivery{ChannelName: "p", Kind: "test", Status: DeliverySuccess, UserID: "alice"})
	var ds []Delivery
	callJSON(t, http.MethodGet, srv.URL+"/api/notifications/me/deliveries", "", &ds)
	if len(ds) != 1 {
		t.Errorf("deliveries = %d, want 1", len(ds))
	}
}

func TestMeLifecycleWithAudit(t *testing.T) {
	store := newTestStore(t)
	auditStore, err := audit.NewSQLiteStore(store.db)
	if err != nil {
		t.Fatalf("audit store: %v", err)
	}
	srv, h := meFixture(t, store, "alice")
	h.Audit = auditStore

	var dto ChannelDTO
	callJSON(t, http.MethodPost, srv.URL+"/api/notifications/me/channels", emailJSON(t), &dto)
	if status, _ := callJSON(t, http.MethodPut, srv.URL+"/api/notifications/me/channels/"+dto.ID, emailJSON(t), nil); status != http.StatusOK {
		t.Errorf("update = %d, want 200", status)
	}
	if status, _ := callJSON(t, http.MethodDelete, srv.URL+"/api/notifications/me/channels/"+dto.ID, "", nil); status != http.StatusNoContent {
		t.Errorf("delete = %d, want 204", status)
	}
	callJSON(t, http.MethodPut, srv.URL+"/api/notifications/me/subscription", `{"enabled":true}`, nil)
	callJSON(t, http.MethodPut, srv.URL+"/api/notifications/me/policy", `{"timezone":"UTC"}`, nil)

	var n int
	if err := store.db.QueryRow(
		`SELECT COUNT(*) FROM audit_log WHERE action LIKE 'user_notification_%'`).Scan(&n); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if n != 5 {
		t.Errorf("audit rows = %d, want 5 (create/update/delete/subscription/policy)", n)
	}
}

func TestMeStoreErrors(t *testing.T) {
	store := newTestStore(t)
	srv, _ := meFixture(t, store, "alice")
	_ = store.db.Close()
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/notifications/me/channels", ""},
		{http.MethodPost, "/api/notifications/me/channels", emailJSON(t)},
		{http.MethodGet, "/api/notifications/me/channels/x", ""},
		{http.MethodPut, "/api/notifications/me/channels/x", emailJSON(t)},
		{http.MethodDelete, "/api/notifications/me/channels/x", ""},
		{http.MethodPost, "/api/notifications/me/channels/x/test", ""},
		{http.MethodGet, "/api/notifications/me/subscription", ""},
		{http.MethodPut, "/api/notifications/me/subscription", `{"enabled":true}`},
		{http.MethodGet, "/api/notifications/me/policy", ""},
		{http.MethodPut, "/api/notifications/me/policy", `{"timezone":"UTC"}`},
		{http.MethodGet, "/api/notifications/me/deliveries", ""},
	} {
		if status, _ := callJSON(t, tc.method, srv.URL+tc.path, tc.body, nil); status != http.StatusInternalServerError {
			t.Errorf("%s %s on closed db = %d, want 500", tc.method, tc.path, status)
		}
	}
}

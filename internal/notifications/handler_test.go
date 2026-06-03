// SPDX-License-Identifier: Apache-2.0

package notifications

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"system-wrangler-backend/internal/audit"
)

func newHandlerFixture(t *testing.T) (*httptest.Server, *SQLiteStore, *Handler) {
	t.Helper()
	store := newTestStore(t)
	h := &Handler{Store: store}
	mux := http.NewServeMux()
	wrap := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := audit.WithActor(r.Context(), audit.Actor{Kind: audit.ActorUser, ID: "user-1"})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	h.Register(mux, wrap)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, store, h
}

func req(t *testing.T, method, url, body string) *http.Response {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	rq, err := http.NewRequestWithContext(context.Background(), method, url, r)
	if err != nil {
		t.Fatalf("req: %v", err)
	}
	if body != "" {
		rq.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(rq) //nolint:gosec // test URL
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func emailJSON(t *testing.T) string {
	t.Helper()
	b, _ := json.Marshal(emailInput()) //nolint:gosec // G117: write-only input DTO, builds a request body in a test
	return string(b)
}

func TestHandlerCreateGetRedactsSecret(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := req(t, http.MethodPost, srv.URL+"/api/notifications/channels", emailJSON(t))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if strings.Contains(string(raw), "hunter2") || strings.Contains(string(raw), "ciphertext") {
		t.Fatalf("response leaked secret material: %s", raw)
	}
	var dto ChannelDTO
	_ = json.Unmarshal(raw, &dto)
	if !dto.HasSecret || dto.ID == "" {
		t.Errorf("redacted DTO wrong: %+v", dto)
	}

	resp = req(t, http.MethodGet, srv.URL+"/api/notifications/channels/"+dto.ID, "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("get status = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerCreateInvalid(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := req(t, http.MethodPost, srv.URL+"/api/notifications/channels", `{"name":"","type":"email"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid create should 400, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerCreateUnknownField(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := req(t, http.MethodPost, srv.URL+"/api/notifications/channels", `{"bogus":1}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown field should 400, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerForbidden(t *testing.T) {
	srv, _, h := newHandlerFixture(t)
	h.CanManage = func(context.Context) bool { return false }
	for _, m := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/notifications/channels", ""},
		{http.MethodPost, "/api/notifications/channels", emailJSON(t)},
		{http.MethodGet, "/api/notifications/deliveries", ""},
	} {
		resp := req(t, m.method, srv.URL+m.path, m.body)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s should 403, got %d", m.method, m.path, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}

func TestHandlerCreateNoUser401(t *testing.T) {
	store := newTestStore(t)
	h := &Handler{Store: store}
	mux := http.NewServeMux()
	h.Register(mux, nil) // no actor middleware
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp := req(t, http.MethodPost, srv.URL+"/api/notifications/channels", emailJSON(t))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("missing actor should 401, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerListAndUpdateDelete(t *testing.T) {
	srv, store, _ := newHandlerFixture(t)
	c, _ := store.Create(emailInput(), "user-1")

	resp := req(t, http.MethodGet, srv.URL+"/api/notifications/channels", "")
	var list []ChannelDTO
	_ = json.NewDecoder(resp.Body).Decode(&list)
	_ = resp.Body.Close()
	if len(list) != 1 {
		t.Fatalf("list = %d, want 1", len(list))
	}

	upd := emailInput()
	upd.Name = "renamed"
	upd.Secret = ""           // omit → keep
	b, _ := json.Marshal(upd) //nolint:gosec // G117: write-only input DTO in a test

	resp = req(t, http.MethodPut, srv.URL+"/api/notifications/channels/"+c.ID, string(b))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update status = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = req(t, http.MethodDelete, srv.URL+"/api/notifications/channels/"+c.ID, "")
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete status = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerGetUpdateDeleteMissing404(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	for _, m := range []struct{ method, body string }{
		{http.MethodGet, ""},
		{http.MethodPut, emailJSON(t)},
		{http.MethodDelete, ""},
	} {
		resp := req(t, m.method, srv.URL+"/api/notifications/channels/nope", m.body)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s missing should 404, got %d", m.method, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}

func TestHandlerTestSend(t *testing.T) {
	srv, store, h := newHandlerFixture(t)
	// A webhook channel pointed at a server that 200s.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	in := webhookInput("wh", target.URL, true)
	c, _ := store.Create(in, "user-1")
	h.Dispatcher = &Dispatcher{Store: store, Vault: store.Vault, Senders: NewSenders(target.Client(), nil)}

	resp := req(t, http.MethodPost, srv.URL+"/api/notifications/channels/"+c.ID+"/test", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("test status = %d", resp.StatusCode)
	}
	var tr TestResult
	_ = json.NewDecoder(resp.Body).Decode(&tr)
	_ = resp.Body.Close()
	if !tr.OK {
		t.Errorf("test should succeed: %+v", tr)
	}
}

func TestHandlerTestSendReportsFailure(t *testing.T) {
	srv, store, h := newHandlerFixture(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer target.Close()
	c, _ := store.Create(webhookInput("wh", target.URL, true), "user-1")
	h.Dispatcher = &Dispatcher{Store: store, Vault: store.Vault, Senders: NewSenders(target.Client(), nil)}

	resp := req(t, http.MethodPost, srv.URL+"/api/notifications/channels/"+c.ID+"/test", "")
	var tr TestResult
	_ = json.NewDecoder(resp.Body).Decode(&tr)
	_ = resp.Body.Close()
	if tr.OK || tr.Error == "" {
		t.Errorf("test should report failure: %+v", tr)
	}
}

func TestHandlerTestNoDispatcher(t *testing.T) {
	srv, store, _ := newHandlerFixture(t)
	c, _ := store.Create(emailInput(), "user-1")
	resp := req(t, http.MethodPost, srv.URL+"/api/notifications/channels/"+c.ID+"/test", "")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("test without dispatcher should 503, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerDeliveries(t *testing.T) {
	srv, store, _ := newHandlerFixture(t)
	_, _ = store.RecordDelivery(Delivery{ChannelID: "c", ChannelName: "n", ChannelType: TypeWebhook, Kind: "fired", RuleName: "r", SystemID: "s", Status: DeliverySuccess})
	resp := req(t, http.MethodGet, srv.URL+"/api/notifications/deliveries?limit=10", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deliveries status = %d", resp.StatusCode)
	}
	var ds []Delivery
	_ = json.NewDecoder(resp.Body).Decode(&ds)
	_ = resp.Body.Close()
	if len(ds) != 1 {
		t.Errorf("deliveries = %d, want 1", len(ds))
	}
}

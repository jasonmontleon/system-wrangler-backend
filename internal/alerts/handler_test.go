// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"system-wrangler-backend/internal/audit"
)

func newHandlerFixture(t *testing.T) (*httptest.Server, *SQLiteStore, *Handler) {
	t.Helper()
	store := newTestStore(t)
	h := &Handler{Store: store}
	mux := http.NewServeMux()
	wrap := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := audit.WithActor(r.Context(), audit.Actor{
				Kind: audit.ActorUser, ID: "user-1", Label: "alice",
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	h.Register(mux, wrap)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, store, h
}

func mustReq(t *testing.T, method, url string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func mustDo(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // test URL
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func ruleJSON(t *testing.T, in RuleInput) string {
	t.Helper()
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func TestHandlerCreateAndGet(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	body := ruleJSON(t, validMetricInput())
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/alerts", strings.NewReader(body)))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d", resp.StatusCode)
	}
	var created Rule
	_ = json.NewDecoder(resp.Body).Decode(&created)
	_ = resp.Body.Close()
	if created.ID == "" {
		t.Fatal("no id returned")
	}
	if loc := resp.Header.Get("Location"); loc != "/api/alerts/"+created.ID {
		t.Errorf("Location = %q", loc)
	}

	resp = mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/alerts/"+created.ID, nil))
	if resp.StatusCode != http.StatusOK {
		t.Errorf("get status = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerCreateBadJSON(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/alerts", strings.NewReader(`{"bogus":1}`)))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown field should 400, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerCreateInvalidRule(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	in := validMetricInput()
	in.Name = ""
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/alerts", strings.NewReader(ruleJSON(t, in))))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid rule should 400, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerCreateNoUser401(t *testing.T) {
	store := newTestStore(t)
	h := &Handler{Store: store}
	mux := http.NewServeMux()
	h.Register(mux, nil) // no middleware → no actor
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/alerts", strings.NewReader(ruleJSON(t, validMetricInput()))))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("missing actor should 401, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerListFiltersByVisibility(t *testing.T) {
	srv, store, h := newHandlerFixture(t)
	a, _ := store.Create(validMetricInput(), "user-1")
	hidden := validMetricInput()
	hidden.Name = "secret"
	_, _ = store.Create(hidden, "user-1")
	h.VisibleRule = func(_ context.Context, r Rule) bool { return r.ID == a.ID }

	resp := mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/alerts", nil))
	var got []Rule
	_ = json.NewDecoder(resp.Body).Decode(&got)
	_ = resp.Body.Close()
	if len(got) != 1 || got[0].ID != a.ID {
		t.Errorf("visibility filter not applied: %+v", got)
	}
}

func TestHandlerGetHiddenIs404(t *testing.T) {
	srv, store, h := newHandlerFixture(t)
	r, _ := store.Create(validMetricInput(), "user-1")
	h.VisibleRule = func(context.Context, Rule) bool { return false }
	resp := mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/alerts/"+r.ID, nil))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("hidden rule should 404, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerGetMissing404(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/alerts/nope", nil))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing rule should 404, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerCreateForbidden(t *testing.T) {
	srv, _, h := newHandlerFixture(t)
	h.CanManage = func(context.Context, Rule) bool { return false }
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/alerts", strings.NewReader(ruleJSON(t, validMetricInput()))))
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("create should 403, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerUpdate(t *testing.T) {
	srv, store, _ := newHandlerFixture(t)
	r, _ := store.Create(validMetricInput(), "user-1")
	in := validMetricInput()
	in.Name = "updated"
	resp := mustDo(t, mustReq(t, http.MethodPut, srv.URL+"/api/alerts/"+r.ID, strings.NewReader(ruleJSON(t, in))))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update status = %d", resp.StatusCode)
	}
	var updated Rule
	_ = json.NewDecoder(resp.Body).Decode(&updated)
	_ = resp.Body.Close()
	if updated.Name != "updated" {
		t.Errorf("update not applied: %+v", updated)
	}
}

func TestHandlerUpdateMissing404(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodPut, srv.URL+"/api/alerts/nope", strings.NewReader(ruleJSON(t, validMetricInput()))))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("update missing should 404, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerUpdateInvalid400(t *testing.T) {
	srv, store, _ := newHandlerFixture(t)
	r, _ := store.Create(validMetricInput(), "user-1")
	in := validMetricInput()
	in.Comparator = "near"
	resp := mustDo(t, mustReq(t, http.MethodPut, srv.URL+"/api/alerts/"+r.ID, strings.NewReader(ruleJSON(t, in))))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid update should 400, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerUpdateForbidden(t *testing.T) {
	srv, store, h := newHandlerFixture(t)
	r, _ := store.Create(validMetricInput(), "user-1")
	h.CanManage = func(context.Context, Rule) bool { return false }
	resp := mustDo(t, mustReq(t, http.MethodPut, srv.URL+"/api/alerts/"+r.ID, strings.NewReader(ruleJSON(t, validMetricInput()))))
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("update should 403, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerDelete(t *testing.T) {
	srv, store, _ := newHandlerFixture(t)
	r, _ := store.Create(validMetricInput(), "user-1")
	resp := mustDo(t, mustReq(t, http.MethodDelete, srv.URL+"/api/alerts/"+r.ID, nil))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if _, err := store.Get(r.ID); err == nil {
		t.Error("rule should be gone")
	}
}

func TestHandlerDeleteMissing404(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodDelete, srv.URL+"/api/alerts/nope", nil))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("delete missing should 404, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerDeleteForbidden(t *testing.T) {
	srv, store, h := newHandlerFixture(t)
	r, _ := store.Create(validMetricInput(), "user-1")
	h.CanManage = func(context.Context, Rule) bool { return false }
	resp := mustDo(t, mustReq(t, http.MethodDelete, srv.URL+"/api/alerts/"+r.ID, nil))
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("delete should 403, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHandlerActiveFilterAndName(t *testing.T) {
	srv, store, h := newHandlerFixture(t)
	in := validMetricInput()
	in.Enabled = true
	r, _ := store.Create(in, "user-1")
	now := time.Now().UTC()
	_ = store.PutInstance(Instance{RuleID: r.ID, SystemID: "visible", State: StateFiring, FirstBreachAt: now, FiredAt: &now, LastEvalAt: now})
	_ = store.PutInstance(Instance{RuleID: r.ID, SystemID: "hidden", State: StateFiring, FirstBreachAt: now, FiredAt: &now, LastEvalAt: now})
	h.VisibleSystem = func(_ context.Context, sysID string) bool { return sysID == "visible" }
	h.SystemName = func(sysID string) string { return "name-of-" + sysID }

	resp := mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/alerts/active", nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("active status = %d", resp.StatusCode)
	}
	var got []ActiveAlert
	_ = json.NewDecoder(resp.Body).Decode(&got)
	_ = resp.Body.Close()
	if len(got) != 1 || got[0].SystemID != "visible" {
		t.Fatalf("visibility filter not applied: %+v", got)
	}
	if got[0].SystemName != "name-of-visible" {
		t.Errorf("system name not enriched: %q", got[0].SystemName)
	}
}

func TestHandlerCatalog(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/alerts/catalog", nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("catalog status = %d", resp.StatusCode)
	}
	var got []CatalogEntry
	_ = json.NewDecoder(resp.Body).Decode(&got)
	_ = resp.Body.Close()
	if len(got) != len(catalog) {
		t.Errorf("catalog returned %d entries, want %d", len(got), len(catalog))
	}
}

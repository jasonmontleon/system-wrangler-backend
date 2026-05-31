// SPDX-License-Identifier: Apache-2.0

package schedules

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
	"system-wrangler-backend/internal/systems"
	"system-wrangler-backend/internal/updaters"
)

func newHandlerFixture(t *testing.T) (*httptest.Server, *SQLiteStore, *Handler) {
	t.Helper()
	store, _ := newStore(t)
	h := &Handler{Store: store}
	mux := http.NewServeMux()
	// Stamp a default actor so create() doesn't 401 in tests that
	// don't care about RBAC.
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

const validBody = `{
  "name": "Nightly check",
  "cronExpr": "0 3 * * *",
  "timezone": "UTC",
  "runCheck": true,
  "runApply": false,
  "rebootAfterApply": false,
  "targetKind": "global",
  "targetValue": "",
  "enabled": true
}`

func TestCreateThenList(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/schedules", strings.NewReader(validBody)))
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create status = %d, body=%s", resp.StatusCode, body)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/api/schedules/") {
		t.Errorf("Location = %q", loc)
	}
	_ = resp.Body.Close()

	resp = mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/schedules", nil))
	defer func() { _ = resp.Body.Close() }()
	var got []Schedule
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].Name != "Nightly check" {
		t.Errorf("List = %+v", got)
	}
}

func TestCreateRejectsMissingActor(t *testing.T) {
	store, _ := newStore(t)
	h := &Handler{Store: store}
	mux := http.NewServeMux()
	h.Register(mux, nil) // no middleware → no actor
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/schedules", strings.NewReader(validBody)))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestCreateInvalidBody(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/schedules", strings.NewReader(`{"name":""}`)))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestCreateMalformedJSON(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/schedules", strings.NewReader(`not json`)))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestCreateRejectsUnknownField(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	body := strings.Replace(validBody, `"enabled": true`, `"enabled": true, "iAmNew": 1`, 1)
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/schedules", strings.NewReader(body)))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestGetUpdateDeleteRoundTrip(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/schedules", strings.NewReader(validBody)))
	var created Schedule
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	_ = resp.Body.Close()

	resp = mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/schedules/"+created.ID, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	updated := strings.Replace(validBody, `"Nightly check"`, `"Renamed"`, 1)
	resp = mustDo(t, mustReq(t, http.MethodPut, srv.URL+"/api/schedules/"+created.ID, strings.NewReader(updated)))
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("update status = %d, body=%s", resp.StatusCode, body)
	}
	var post Schedule
	_ = json.NewDecoder(resp.Body).Decode(&post)
	_ = resp.Body.Close()
	if post.Name != "Renamed" {
		t.Errorf("Update Name = %q, want %q", post.Name, "Renamed")
	}

	resp = mustDo(t, mustReq(t, http.MethodDelete, srv.URL+"/api/schedules/"+created.ID, nil))
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete status = %d, want 204", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestGetMissing(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/schedules/does-not-exist", nil))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestUpdateMissing(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodPut, srv.URL+"/api/schedules/missing", strings.NewReader(validBody)))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestUpdateInvalidBody(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/schedules", strings.NewReader(validBody)))
	var created Schedule
	_ = json.NewDecoder(resp.Body).Decode(&created)
	_ = resp.Body.Close()

	bad := strings.Replace(validBody, `"0 3 * * *"`, `"every wednesday"`, 1)
	resp = mustDo(t, mustReq(t, http.MethodPut, srv.URL+"/api/schedules/"+created.ID, strings.NewReader(bad)))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestDeleteMissing(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodDelete, srv.URL+"/api/schedules/missing", nil))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestListRunsReturnsHistory(t *testing.T) {
	srv, store, _ := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/schedules", strings.NewReader(validBody)))
	var created Schedule
	_ = json.NewDecoder(resp.Body).Decode(&created)
	_ = resp.Body.Close()

	for i := 0; i < 3; i++ {
		r, _ := store.RecordRunStart(created.ID)
		_ = store.RecordRunFinish(r.ID, StatusSuccess, 1, 1, 0, "")
	}
	resp = mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/schedules/"+created.ID+"/runs", nil))
	defer func() { _ = resp.Body.Close() }()
	var got []ScheduleRun
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("ListRuns = %d, want 3", len(got))
	}
}

func TestListRunsRespectsLimitQuery(t *testing.T) {
	srv, store, _ := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/schedules", strings.NewReader(validBody)))
	var created Schedule
	_ = json.NewDecoder(resp.Body).Decode(&created)
	_ = resp.Body.Close()
	for i := 0; i < 5; i++ {
		r, _ := store.RecordRunStart(created.ID)
		_ = store.RecordRunFinish(r.ID, StatusSuccess, 1, 1, 0, "")
	}
	resp = mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/schedules/"+created.ID+"/runs?limit=2", nil))
	defer func() { _ = resp.Body.Close() }()
	var got []ScheduleRun
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if len(got) != 2 {
		t.Errorf("limit=2 returned %d", len(got))
	}
}

func TestListRunsMissingSchedule(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/schedules/missing/runs", nil))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestVisibilityFilterHidesRowsFromList(t *testing.T) {
	srv, _, h := newHandlerFixture(t)
	// Create two schedules.
	resp1 := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/schedules", strings.NewReader(validBody)))
	_ = resp1.Body.Close()
	groupBody := strings.Replace(validBody, `"global"`, `"group"`, 1)
	groupBody = strings.Replace(groupBody, `"targetValue": ""`, `"targetValue": "grp-1"`, 1)
	resp2 := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/schedules", strings.NewReader(groupBody)))
	_ = resp2.Body.Close()

	h.VisibleSchedule = func(_ context.Context, sch Schedule) bool {
		return sch.TargetKind == TargetGroup
	}

	resp := mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/schedules", nil))
	defer func() { _ = resp.Body.Close() }()
	var got []Schedule
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if len(got) != 1 || got[0].TargetKind != TargetGroup {
		t.Errorf("Filtered list = %+v", got)
	}
}

func TestVisibilityFilterHides404OnGet(t *testing.T) {
	srv, _, h := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/schedules", strings.NewReader(validBody)))
	var created Schedule
	_ = json.NewDecoder(resp.Body).Decode(&created)
	_ = resp.Body.Close()
	h.VisibleSchedule = func(context.Context, Schedule) bool { return false }
	resp = mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/schedules/"+created.ID, nil))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestCanManageBlocksCreate(t *testing.T) {
	srv, _, h := newHandlerFixture(t)
	h.CanManage = func(context.Context, Schedule) bool { return false }
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/schedules", strings.NewReader(validBody)))
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestCanManageBlocksUpdate(t *testing.T) {
	srv, _, h := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/schedules", strings.NewReader(validBody)))
	var created Schedule
	_ = json.NewDecoder(resp.Body).Decode(&created)
	_ = resp.Body.Close()
	h.CanManage = func(context.Context, Schedule) bool { return false }
	resp = mustDo(t, mustReq(t, http.MethodPut, srv.URL+"/api/schedules/"+created.ID, strings.NewReader(validBody)))
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestCanManageBlocksUpdatePivotingTargetKind(t *testing.T) {
	srv, _, h := newHandlerFixture(t)
	// Allow create against `global` but disallow pivoting to `group`.
	h.CanManage = func(_ context.Context, sch Schedule) bool {
		return sch.TargetKind == TargetGlobal
	}
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/schedules", strings.NewReader(validBody)))
	var created Schedule
	_ = json.NewDecoder(resp.Body).Decode(&created)
	_ = resp.Body.Close()

	pivot := strings.Replace(validBody, `"global"`, `"group"`, 1)
	pivot = strings.Replace(pivot, `"targetValue": ""`, `"targetValue": "grp-1"`, 1)
	resp = mustDo(t, mustReq(t, http.MethodPut, srv.URL+"/api/schedules/"+created.ID, strings.NewReader(pivot)))
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

// Exercises the handlers' store-failure branches by closing the
// SQLite handle out from under them. Each request must respond 5xx
// instead of crashing.
func TestHandlerSurfaces500WhenStoreFails(t *testing.T) {
	store, db := newStore(t)
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
	created, _ := store.Create(validInput(), "user-1")
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	cases := []struct {
		method, path string
	}{
		{http.MethodGet, "/api/schedules"},
		{http.MethodGet, "/api/schedules/" + created.ID},
		{http.MethodPost, "/api/schedules"},
		{http.MethodPut, "/api/schedules/" + created.ID},
		{http.MethodDelete, "/api/schedules/" + created.ID},
		{http.MethodGet, "/api/schedules/" + created.ID + "/runs"},
	}
	for _, c := range cases {
		var body io.Reader
		if c.method == http.MethodPost || c.method == http.MethodPut {
			body = strings.NewReader(validBody)
		}
		resp := mustDo(t, mustReq(t, c.method, srv.URL+c.path, body))
		if resp.StatusCode < 500 {
			t.Errorf("%s %s: status = %d, want 5xx", c.method, c.path, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}

func TestListRunsHiddenScheduleReturns404(t *testing.T) {
	srv, _, h := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/schedules", strings.NewReader(validBody)))
	var created Schedule
	_ = json.NewDecoder(resp.Body).Decode(&created)
	_ = resp.Body.Close()
	h.VisibleSchedule = func(context.Context, Schedule) bool { return false }
	resp = mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/schedules/"+created.ID+"/runs", nil))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestListRunsIgnoresGarbageLimit(t *testing.T) {
	srv, store, _ := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/schedules", strings.NewReader(validBody)))
	var created Schedule
	_ = json.NewDecoder(resp.Body).Decode(&created)
	_ = resp.Body.Close()
	for i := 0; i < 3; i++ {
		r, _ := store.RecordRunStart(created.ID)
		_ = store.RecordRunFinish(r.ID, StatusSuccess, 1, 1, 0, "")
	}
	// limit=abc → ignored → default cap → all 3 returned.
	resp = mustDo(t, mustReq(t, http.MethodGet, srv.URL+"/api/schedules/"+created.ID+"/runs?limit=abc", nil))
	defer func() { _ = resp.Body.Close() }()
	var got []ScheduleRun
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if len(got) != 3 {
		t.Errorf("garbage limit returned %d, want 3", len(got))
	}
}

func TestRunNowReturns202AndFires(t *testing.T) {
	store, _ := newStore(t)
	o, _ := newFiringOrchestrator(t)
	o.Store = store
	o.Systems = fakeSysStore{systems: []systems.System{{ID: "s1"}}}
	o.Registry = fakeRegistry{defs: []updaters.Definition{{ID: "dnf"}}}
	o.Updaters = fakeAvailStore{rows: []updaters.Availability{{UpdaterID: "dnf", Enabled: true}}}
	fired := make(chan struct{}, 1)
	o.Runner = &fakeRunner{
		check: func(string, string) (updaters.RunResult, error) {
			select {
			case fired <- struct{}{}:
			default:
			}
			return ok()
		},
	}
	h := &Handler{Store: store, Orchestrator: o}
	mux := http.NewServeMux()
	h.Register(mux, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := audit.WithActor(r.Context(), audit.Actor{Kind: audit.ActorUser, ID: "user-1"})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	sch, _ := store.Create(validInput(), "user-1")
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/schedules/"+sch.ID+"/run-now", nil))
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status = %d, want 202", resp.StatusCode)
	}
	_ = resp.Body.Close()

	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("expected the orchestrator to fire after run-now")
	}
}

func TestRunNowReturns503WithoutOrchestrator(t *testing.T) {
	srv, store, _ := newHandlerFixture(t)
	sch, _ := store.Create(validInput(), "user-1")
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/schedules/"+sch.ID+"/run-now", nil))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestRunNowReturns404ForMissingSchedule(t *testing.T) {
	srv, _, _ := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/schedules/missing/run-now", nil))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestRunNowRespectsCanManage(t *testing.T) {
	srv, store, h := newHandlerFixture(t)
	sch, _ := store.Create(validInput(), "user-1")
	h.CanManage = func(context.Context, Schedule) bool { return false }
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/schedules/"+sch.ID+"/run-now", nil))
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestCanManageBlocksDelete(t *testing.T) {
	srv, _, h := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, http.MethodPost, srv.URL+"/api/schedules", strings.NewReader(validBody)))
	var created Schedule
	_ = json.NewDecoder(resp.Body).Decode(&created)
	_ = resp.Body.Close()
	h.CanManage = func(context.Context, Schedule) bool { return false }
	resp = mustDo(t, mustReq(t, http.MethodDelete, srv.URL+"/api/schedules/"+created.ID, nil))
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

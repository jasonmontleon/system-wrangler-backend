// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"system-wrangler-backend/internal/database"
)

// newTestHandler returns a Handler backed by a fresh store + a test
// mux for httptest, with no auth middleware (read-side auth is layered
// on by the server, not the handler).
func newTestHandler(t *testing.T) (*Handler, *Store, *http.ServeMux) {
	t.Helper()
	s := newTestStore(t)
	h := NewHandler(s)
	mux := http.NewServeMux()
	h.Register(mux, nil)
	return h, s, mux
}

func TestHandlerList_Empty(t *testing.T) {
	_, _, mux := newTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/admin/audit", nil)
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp listResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Records) != 0 {
		t.Errorf("records = %d, want 0", len(resp.Records))
	}
	if resp.Next != nil {
		t.Errorf("next on empty list: %+v", resp.Next)
	}
}

func TestHandlerList_FiltersAndPagination(t *testing.T) {
	_, s, mux := newTestHandler(t)
	for k := 0; k < 4; k++ {
		if err := s.Log(context.Background(), Event{Action: "system.create", Outcome: Success}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Log(context.Background(), Event{Action: "auth.login.failed", Outcome: Failure}); err != nil {
		t.Fatal(err)
	}

	// limit=2 -> 2 records + cursor
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/admin/audit?limit=2", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var page1 listResponse
	_ = json.NewDecoder(w.Body).Decode(&page1)
	if len(page1.Records) != 2 || page1.Next == nil {
		t.Fatalf("page1: records=%d next=%v", len(page1.Records), page1.Next)
	}

	// fetch page2 with cursor
	u := "/api/admin/audit?limit=2&after_ms=" + strconv.FormatInt(page1.Next.AfterMillis, 10) +
		"&after_id=" + page1.Next.AfterID
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, u, nil))
	var page2 listResponse
	_ = json.NewDecoder(w.Body).Decode(&page2)
	if len(page2.Records) != 2 {
		t.Fatalf("page2 size = %d", len(page2.Records))
	}
	// IDs unique across pages
	for _, r := range page2.Records {
		for _, r1 := range page1.Records {
			if r.ID == r1.ID {
				t.Errorf("duplicate ID %q across pages", r.ID)
			}
		}
	}

	// action filter
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/admin/audit?action=auth.login.failed", nil))
	var resp listResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if len(resp.Records) != 1 || resp.Records[0].Action != "auth.login.failed" {
		t.Errorf("action filter: %+v", resp.Records)
	}

	// outcome filter
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/admin/audit?outcome=failure", nil))
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if len(resp.Records) != 1 || resp.Records[0].Outcome != Failure {
		t.Errorf("outcome filter: %+v", resp.Records)
	}
}

func TestHandlerList_LabelAndRequestIDQueryParams(t *testing.T) {
	_, s, mux := newTestHandler(t)
	ctx := context.Background()

	alice := WithActor(ctx, Actor{Kind: ActorUser, ID: "u1", Label: "alice"})
	alice = WithRequestID(alice, "req-abc")
	bob := WithActor(ctx, Actor{Kind: ActorUser, ID: "u2", Label: "bob"})
	if err := s.Log(alice, Event{
		Action: "system.create", Outcome: Success,
		TargetKind: "system", TargetID: "sys-1", TargetLabel: "db-prod",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Log(bob, Event{
		Action: "system.delete", Outcome: Success,
		TargetKind: "system", TargetID: "sys-2", TargetLabel: "web-1",
	}); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, url string
		want      int
	}{
		{"actor_label substring", "/api/admin/audit?actor_label=ali", 1},
		{"target_label substring", "/api/admin/audit?target_label=db-", 1},
		{"target_label other match", "/api/admin/audit?target_label=web", 1},
		{"request_id exact", "/api/admin/audit?request_id=req-abc", 1},
		{"request_id miss", "/api/admin/audit?request_id=nope", 0},
		{"actor_label miss", "/api/admin/audit?actor_label=zzz", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tt.url, nil))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
			}
			var resp listResponse
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(resp.Records) != tt.want {
				t.Errorf("rows = %d, want %d", len(resp.Records), tt.want)
			}
		})
	}
}

func TestHandlerList_BadParams(t *testing.T) {
	_, _, mux := newTestHandler(t)
	cases := []string{
		"/api/admin/audit?since=notnum",
		"/api/admin/audit?until=notnum",
		"/api/admin/audit?limit=0",
		"/api/admin/audit?limit=notnum",
		"/api/admin/audit?after_ms=notnum",
		"/api/admin/audit?after_ms=123", // missing after_id
		"/api/admin/audit?after_id=abc", // missing after_ms
	}
	for _, u := range cases {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, u, nil))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", u, w.Code)
		}
	}
}

func TestHandlerGet_OkAndNotFound(t *testing.T) {
	_, s, mux := newTestHandler(t)
	if err := s.Log(context.Background(), Event{Action: "x", Outcome: Success}); err != nil {
		t.Fatal(err)
	}
	recs, _, _ := s.ListQuery(Query{})
	id := recs[0].ID

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/admin/audit/"+id, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("get ok: status = %d body=%s", w.Code, w.Body.String())
	}
	var r Record
	_ = json.NewDecoder(w.Body).Decode(&r)
	if r.ID != id {
		t.Errorf("got id %q, want %q", r.ID, id)
	}

	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/admin/audit/nope", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("get missing: status = %d, want 404", w.Code)
	}
}

func TestHandlerList_SinceUntilParse(t *testing.T) {
	_, s, mux := newTestHandler(t)
	t0 := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return t0 }
	if err := s.Log(context.Background(), Event{Action: "x", Outcome: Success}); err != nil {
		t.Fatal(err)
	}
	// since just before t0 and until just after should include the row.
	u := "/api/admin/audit?since=" + strconv.FormatInt(t0.Add(-time.Millisecond).UnixMilli(), 10) +
		"&until=" + strconv.FormatInt(t0.Add(time.Millisecond).UnixMilli(), 10)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, u, nil))
	var resp listResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if len(resp.Records) != 1 {
		t.Errorf("since/until window: got %d rows", len(resp.Records))
	}
}

func TestHandlerList_ExactTailOmitsNext(t *testing.T) {
	// Regression: when the page size exactly matches the remaining rows,
	// the response must not advertise a next-page cursor — otherwise the
	// UI exposes a "Next" button that lands on an empty page.
	_, s, mux := newTestHandler(t)
	for k := 0; k < 25; k++ {
		if err := s.Log(context.Background(), Event{Action: "x", Outcome: Success}); err != nil {
			t.Fatal(err)
		}
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/admin/audit?limit=25", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var resp listResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Records) != 25 {
		t.Errorf("records = %d, want 25", len(resp.Records))
	}
	if resp.Next != nil {
		t.Errorf("next on exact-tail page: %+v, want nil", resp.Next)
	}
}

func TestRegister_NilMiddlewareAllowed(t *testing.T) {
	s := newTestStore(t)
	h := NewHandler(s)
	mux := http.NewServeMux()
	// Should not panic with nil mw.
	h.Register(mux, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/admin/audit", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandlerClear_ForbiddenWhenCanClearNil(t *testing.T) {
	_, _, mux := newTestHandler(t)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/api/admin/audit", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (CanClear nil must deny)", w.Code)
	}
}

func TestHandlerClear_ForbiddenWhenCanClearFalse(t *testing.T) {
	h, _, mux := newTestHandler(t)
	h.CanClear = func(*http.Request) bool { return false }
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/api/admin/audit", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestHandlerClear_TruncatesAndAppendsMarker(t *testing.T) {
	h, s, mux := newTestHandler(t)
	h.CanClear = func(*http.Request) bool { return true }
	for i := 0; i < 5; i++ {
		if err := s.Log(context.Background(), Event{Action: "x", Outcome: Success}); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/api/admin/audit", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var resp clearResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.RowsDeleted != 5 {
		t.Errorf("rowsDeleted = %d, want 5", resp.RowsDeleted)
	}
	// Surviving log should have exactly the audit.clear marker.
	got, _, _ := s.ListQuery(Query{})
	if len(got) != 1 || got[0].Action != "audit.clear" {
		t.Fatalf("surviving rows = %+v, want one audit.clear", got)
	}
	if rd, ok := got[0].Detail["rows_deleted"].(float64); !ok || rd != 5 {
		t.Errorf("audit.clear detail rows_deleted = %v, want 5", got[0].Detail["rows_deleted"])
	}
	if _, present := got[0].Detail["older_than_days"]; present {
		t.Errorf("older_than_days must be absent on truncate-all: %v", got[0].Detail)
	}
}

func TestHandlerClear_OlderThanDaysParam(t *testing.T) {
	h, s, mux := newTestHandler(t)
	h.CanClear = func(*http.Request) bool { return true }
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/api/admin/audit?older_than_days=30", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	got, _, _ := s.ListQuery(Query{})
	if len(got) != 1 || got[0].Action != "audit.clear" {
		t.Fatalf("surviving = %+v", got)
	}
	if v, _ := got[0].Detail["older_than_days"].(float64); v != 30 {
		t.Errorf("older_than_days = %v, want 30", got[0].Detail["older_than_days"])
	}
}

func TestHandlerClear_RejectsBadOlderThanDays(t *testing.T) {
	h, _, mux := newTestHandler(t)
	h.CanClear = func(*http.Request) bool { return true }
	for _, bad := range []string{"0", "-1", "abc", "3651"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/api/admin/audit?older_than_days="+bad, nil))
		if w.Code != http.StatusBadRequest {
			t.Errorf("older_than_days=%q status = %d, want 400", bad, w.Code)
		}
	}
}

// TestHandlerStoreErrors uses a closed-DB store to surface 500 errors
// from the audit list and get endpoints.
func TestHandlerStoreErrors(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "h-closed.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	h := NewHandler(s)
	h.CanClear = func(*http.Request) bool { return true }
	mux := http.NewServeMux()
	h.Register(mux, nil)

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/admin/audit"},
		{http.MethodGet, "/api/admin/audit/x"},
		{http.MethodDelete, "/api/admin/audit?older_than_days=30"},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(tc.method, tc.path, nil)
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusInternalServerError {
			t.Errorf("%s %s status = %d, want 500", tc.method, tc.path, w.Code)
		}
	}
}

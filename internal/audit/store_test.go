// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"system-wrangler-backend/internal/database"
)

// newTestStore opens a per-test SQLite DB and returns an audit.Store with
// deterministic NewID / Now so assertions can be exact.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "audit.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	var counter atomic.Int64
	s.NewID = func() (string, error) {
		return fmt.Sprintf("id-%04d", counter.Add(1)), nil
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var tick atomic.Int64
	s.Now = func() time.Time {
		return base.Add(time.Duration(tick.Add(1)) * time.Millisecond)
	}
	return s
}

func TestNewSQLiteStore_Idempotent(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "audit.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := NewSQLiteStore(db); err != nil {
		t.Fatalf("first NewSQLiteStore: %v", err)
	}
	if _, err := NewSQLiteStore(db); err != nil {
		t.Fatalf("second NewSQLiteStore: %v", err)
	}
}

func TestLog_WritesRow(t *testing.T) {
	s := newTestStore(t)
	ctx := WithActor(context.Background(), Actor{Kind: ActorUser, ID: "u1", Label: "alice"})
	ctx = WithRequestID(ctx, "req-1")
	ctx = WithRemoteAddr(ctx, "10.0.0.1:55555")

	d := NewDetail()
	_ = d.SetSafe("attempted_username", "bob")
	if err := s.Log(ctx, Event{
		Action:      "auth.login.failed",
		Outcome:     Failure,
		TargetKind:  "user",
		TargetID:    "u2",
		TargetLabel: "bob",
		Detail:      d,
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}

	recs, _, err := s.ListQuery(Query{})
	if err != nil {
		t.Fatalf("ListQuery: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("ListQuery returned %d rows, want 1", len(recs))
	}
	r := recs[0]
	if r.Action != "auth.login.failed" || r.Outcome != Failure {
		t.Errorf("action/outcome = %q/%q", r.Action, r.Outcome)
	}
	if r.ActorKind != ActorUser || r.ActorID != "u1" || r.ActorLabel != "alice" {
		t.Errorf("actor: %+v", r)
	}
	if r.TargetKind != "user" || r.TargetID != "u2" || r.TargetLabel != "bob" {
		t.Errorf("target: %+v", r)
	}
	if r.RequestID != "req-1" || r.RequestIP != "10.0.0.1:55555" {
		t.Errorf("request meta: id=%q ip=%q", r.RequestID, r.RequestIP)
	}
	if got := r.Detail["attempted_username"]; got != "bob" {
		t.Errorf("detail attempted_username = %v, want bob", got)
	}
	if r.OccurredAt.IsZero() {
		t.Errorf("OccurredAt is zero")
	}
}

func TestLog_ValidatesRequiredFields(t *testing.T) {
	s := newTestStore(t)
	if err := s.Log(context.Background(), Event{Outcome: Success}); err == nil {
		t.Error("Log with empty Action: want error, got nil")
	}
	if err := s.Log(context.Background(), Event{Action: "foo"}); err == nil {
		t.Error("Log with empty Outcome: want error, got nil")
	}
}

func TestLog_DefaultsUnauthenticatedActor(t *testing.T) {
	s := newTestStore(t)
	if err := s.Log(context.Background(), Event{
		Action:  "auth.login.failed",
		Outcome: Failure,
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	recs, _, _ := s.ListQuery(Query{})
	if len(recs) != 1 || recs[0].ActorKind != ActorUnauthenticated {
		t.Errorf("expected one unauthenticated row, got %+v", recs)
	}
}

func TestLogTx_CommitWritesRow(t *testing.T) {
	s := newTestStore(t)
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := s.LogTx(context.Background(), tx, Event{
		Action: "system.delete", Outcome: Success,
	}); err != nil {
		t.Fatalf("LogTx: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	recs, _, _ := s.ListQuery(Query{})
	if len(recs) != 1 {
		t.Errorf("want 1 row after commit, got %d", len(recs))
	}
}

func TestLogTx_RollbackDropsRow(t *testing.T) {
	s := newTestStore(t)
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := s.LogTx(context.Background(), tx, Event{
		Action: "system.delete", Outcome: Success,
	}); err != nil {
		t.Fatalf("LogTx: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	recs, _, _ := s.ListQuery(Query{})
	if len(recs) != 0 {
		t.Errorf("want 0 rows after rollback, got %d", len(recs))
	}
}

func TestLogTx_NilTxRejected(t *testing.T) {
	s := newTestStore(t)
	if err := s.LogTx(context.Background(), nil, Event{Action: "x", Outcome: Success}); err == nil {
		t.Error("LogTx with nil tx: want error, got nil")
	}
}

func TestGet_NotFound(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Get("missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get missing: want ErrNotFound, got %v", err)
	}
}

func TestGet_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	if err := s.Log(context.Background(), Event{
		Action:  "system.create",
		Outcome: Success,
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	recs, _, _ := s.ListQuery(Query{})
	r, err := s.Get(recs[0].ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if r.ID != recs[0].ID || r.Action != "system.create" {
		t.Errorf("Get returned %+v", r)
	}
}

func TestListQuery_Filters(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	mustLog := func(e Event) {
		if err := s.Log(ctx, e); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	aliceCtx := WithActor(ctx, Actor{Kind: ActorUser, ID: "u-alice", Label: "alice"})
	bobCtx := WithActor(ctx, Actor{Kind: ActorUser, ID: "u-bob", Label: "bob"})
	if err := s.Log(aliceCtx, Event{Action: "system.create", Outcome: Success, TargetKind: "system", TargetID: "sys-1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Log(bobCtx, Event{Action: "system.delete", Outcome: Success, TargetKind: "system", TargetID: "sys-1"}); err != nil {
		t.Fatal(err)
	}
	mustLog(Event{Action: "auth.login.failed", Outcome: Failure})

	all, _, err := s.ListQuery(Query{})
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("baseline rows = %d, want 3", len(all))
	}

	// Order: newest first, so most recent action ranks #0.
	if all[0].Action != "auth.login.failed" {
		t.Errorf("first row action = %q, want auth.login.failed", all[0].Action)
	}

	// actor filter
	rs, _, _ := s.ListQuery(Query{ActorID: "u-alice"})
	if len(rs) != 1 || rs[0].Action != "system.create" {
		t.Errorf("actor filter: %+v", rs)
	}

	// action exact
	rs, _, _ = s.ListQuery(Query{Action: "system.delete"})
	if len(rs) != 1 || rs[0].ActorID != "u-bob" {
		t.Errorf("action exact: %+v", rs)
	}

	// action prefix
	rs, _, _ = s.ListQuery(Query{Action: "system.*"})
	if len(rs) != 2 {
		t.Errorf("action prefix system.*: %d rows", len(rs))
	}

	// outcome
	rs, _, _ = s.ListQuery(Query{Outcome: Failure})
	if len(rs) != 1 || rs[0].Action != "auth.login.failed" {
		t.Errorf("outcome failure: %+v", rs)
	}

	// target
	rs, _, _ = s.ListQuery(Query{TargetKind: "system", TargetID: "sys-1"})
	if len(rs) != 2 {
		t.Errorf("target sys-1: %d rows", len(rs))
	}
}

func TestListQuery_LabelAndRequestIDFilters(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Three rows: actor labels alice / bob / alicia; target labels db-1 /
	// db-2 / web-1; one of them carries a request id used by the search.
	aliceCtx := WithActor(ctx, Actor{Kind: ActorUser, ID: "u-alice", Label: "alice"})
	bobCtx := WithActor(ctx, Actor{Kind: ActorUser, ID: "u-bob", Label: "bob"})
	aliciaCtx := WithActor(ctx, Actor{Kind: ActorUser, ID: "u-alicia", Label: "alicia"})
	aliciaCtx = WithRequestID(aliciaCtx, "req-XYZ")

	if err := s.Log(aliceCtx, Event{
		Action: "system.create", Outcome: Success,
		TargetKind: "system", TargetID: "sys-1", TargetLabel: "db-1",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Log(bobCtx, Event{
		Action: "system.delete", Outcome: Success,
		TargetKind: "system", TargetID: "sys-2", TargetLabel: "db-2",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Log(aliciaCtx, Event{
		Action: "system.create", Outcome: Success,
		TargetKind: "system", TargetID: "sys-3", TargetLabel: "web-1",
	}); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		q         Query
		wantCount int
		wantFirst string // actor label of the newest matching row
	}{
		{"actor_label substring matches alice prefix", Query{ActorLabel: "alic"}, 2, "alicia"},
		{"actor_label is case-insensitive", Query{ActorLabel: "ALICE"}, 1, "alice"},
		{"target_label substring matches db-*", Query{TargetLabel: "db-"}, 2, "bob"},
		{"target_label exact case-insensitive", Query{TargetLabel: "WEB-1"}, 1, "alicia"},
		{"request_id exact", Query{RequestID: "req-XYZ"}, 1, "alicia"},
		{"request_id miss returns empty", Query{RequestID: "no-such"}, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs, _, err := s.ListQuery(tt.q)
			if err != nil {
				t.Fatalf("ListQuery: %v", err)
			}
			if len(rs) != tt.wantCount {
				t.Fatalf("rows = %d, want %d (%+v)", len(rs), tt.wantCount, rs)
			}
			if tt.wantCount > 0 && rs[0].ActorLabel != tt.wantFirst {
				t.Errorf("rs[0].ActorLabel = %q, want %q", rs[0].ActorLabel, tt.wantFirst)
			}
		})
	}
}

func TestListQuery_LabelFilterEscapesWildcards(t *testing.T) {
	// A user-supplied % or _ must not be treated as a SQL wildcard.
	s := newTestStore(t)
	ctx := context.Background()
	literal := WithActor(ctx, Actor{Kind: ActorUser, ID: "u1", Label: "a%b"})
	plain := WithActor(ctx, Actor{Kind: ActorUser, ID: "u2", Label: "aZZb"})
	if err := s.Log(literal, Event{Action: "x", Outcome: Success}); err != nil {
		t.Fatal(err)
	}
	if err := s.Log(plain, Event{Action: "x", Outcome: Success}); err != nil {
		t.Fatal(err)
	}
	// Searching for a literal "%" should match only the row whose label
	// actually contains a percent sign, not every row.
	rs, _, err := s.ListQuery(Query{ActorLabel: "%"})
	if err != nil {
		t.Fatalf("ListQuery: %v", err)
	}
	if len(rs) != 1 || rs[0].ActorLabel != "a%b" {
		t.Errorf("got %+v, want one row with label a%%b", rs)
	}
}

func TestListQuery_TimeWindow(t *testing.T) {
	s := newTestStore(t)
	// Custom Now: three rows one minute apart.
	t0 := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	var i atomic.Int64
	s.Now = func() time.Time {
		return t0.Add(time.Duration(i.Add(1)-1) * time.Minute)
	}
	for k := 0; k < 3; k++ {
		if err := s.Log(context.Background(), Event{Action: "x", Outcome: Success}); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	// since = t0 + 1min, until = t0 + 2min -> exactly the middle row
	rs, _, _ := s.ListQuery(Query{
		Since: t0.Add(1 * time.Minute),
		Until: t0.Add(2 * time.Minute),
	})
	if len(rs) != 1 {
		t.Fatalf("time window: %d rows", len(rs))
	}
	want := t0.Add(1 * time.Minute).UnixMilli()
	if rs[0].OccurredAt.UnixMilli() != want {
		t.Errorf("matched row time = %v, want %v", rs[0].OccurredAt.UnixMilli(), want)
	}
}

func TestListQuery_LimitCapped(t *testing.T) {
	s := newTestStore(t)
	for k := 0; k < 5; k++ {
		if err := s.Log(context.Background(), Event{Action: "x", Outcome: Success}); err != nil {
			t.Fatal(err)
		}
	}
	rs, hasMore, _ := s.ListQuery(Query{Limit: 2})
	if len(rs) != 2 {
		t.Errorf("limit=2: got %d", len(rs))
	}
	if !hasMore {
		t.Error("limit=2 over 5 rows: hasMore = false, want true")
	}
	rs, hasMore, _ = s.ListQuery(Query{Limit: 10000}) // capped at MaxLimit; with 5 rows still returns 5
	if len(rs) != 5 {
		t.Errorf("limit oversize: got %d, want 5", len(rs))
	}
	if hasMore {
		t.Error("limit oversize over 5 rows: hasMore = true, want false")
	}
}

func TestListQuery_HasMoreOnExactTail(t *testing.T) {
	// Regression: a page that exactly fills the limit at the tail of the
	// table must report hasMore=false, so the API does not advertise a
	// next-page cursor that would land on an empty page.
	s := newTestStore(t)
	for k := 0; k < 5; k++ {
		if err := s.Log(context.Background(), Event{Action: "x", Outcome: Success}); err != nil {
			t.Fatal(err)
		}
	}
	rs, hasMore, err := s.ListQuery(Query{Limit: 5})
	if err != nil {
		t.Fatalf("ListQuery: %v", err)
	}
	if len(rs) != 5 {
		t.Errorf("len = %d, want 5", len(rs))
	}
	if hasMore {
		t.Error("hasMore = true on exact-tail page, want false")
	}
}

func TestListQuery_KeysetPagination(t *testing.T) {
	s := newTestStore(t)
	for k := 0; k < 7; k++ {
		if err := s.Log(context.Background(), Event{Action: "x", Outcome: Success}); err != nil {
			t.Fatal(err)
		}
	}
	page1, hasMore1, err := s.ListQuery(Query{Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(page1) != 3 {
		t.Fatalf("page1 size = %d, want 3", len(page1))
	}
	if !hasMore1 {
		t.Error("page1 hasMore = false, want true")
	}
	cursorMs := page1[2].OccurredAt.UnixMilli()
	cursorID := page1[2].ID
	page2, hasMore2, err := s.ListQuery(Query{Limit: 3, AfterMillis: cursorMs, AfterID: cursorID})
	if err != nil {
		t.Fatal(err)
	}
	if len(page2) != 3 {
		t.Fatalf("page2 size = %d, want 3", len(page2))
	}
	if !hasMore2 {
		t.Error("page2 hasMore = false, want true")
	}
	// pages must not overlap
	seen := map[string]bool{}
	for _, r := range append(append([]Record{}, page1...), page2...) {
		if seen[r.ID] {
			t.Errorf("duplicate ID across pages: %s", r.ID)
		}
		seen[r.ID] = true
	}
	page3, hasMore3, _ := s.ListQuery(Query{Limit: 3, AfterMillis: page2[len(page2)-1].OccurredAt.UnixMilli(), AfterID: page2[len(page2)-1].ID})
	if len(page3) != 1 {
		t.Errorf("page3 size = %d, want 1 (tail)", len(page3))
	}
	if hasMore3 {
		t.Error("page3 hasMore = true, want false (tail)")
	}
}

func TestLog_FailsOnClosedDB(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "audit.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	s, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	_ = db.Close()
	if err := s.Log(context.Background(), Event{Action: "x", Outcome: Success}); err == nil {
		t.Error("Log on closed DB: want error, got nil")
	}
}

func TestNewID_PropagatesError(t *testing.T) {
	s := newTestStore(t)
	wantErr := errors.New("boom")
	s.NewID = func() (string, error) { return "", wantErr }
	if err := s.Log(context.Background(), Event{Action: "x", Outcome: Success}); !errors.Is(err, wantErr) {
		t.Errorf("Log: want wrapped %v, got %v", wantErr, err)
	}
}

// Compile-time: scanRecord rejects junk detail JSON via its returned error.
func TestScanRecord_BadDetailJSON(t *testing.T) {
	s := newTestStore(t)
	// Insert a row with an intentionally invalid detail JSON via raw SQL.
	_, err := s.db.Exec(`INSERT INTO audit_log (id, occurred_at, actor_kind, action, outcome, detail)
		VALUES (?, ?, ?, ?, ?, ?)`,
		"bad-1", time.Now().UnixMilli(), string(ActorSystem), "x", string(Success), `{not json`)
	if err != nil {
		t.Fatalf("seed bad row: %v", err)
	}
	if _, err := s.Get("bad-1"); err == nil {
		t.Error("Get with invalid detail JSON: want error, got nil")
	}
}

// Ensures the package-level execer interface is satisfied by *sql.DB and
// *sql.Tx. If the stdlib ever narrows these signatures this catches it.
var (
	_ execer = (*sql.DB)(nil)
	_ execer = (*sql.Tx)(nil)
)

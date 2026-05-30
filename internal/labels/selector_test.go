// SPDX-License-Identifier: Apache-2.0

package labels_test

import (
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/labels"
	"system-wrangler-backend/internal/systems"
)

func TestParseSelector_Forms(t *testing.T) {
	prod := "prod"
	cache := "cache"
	usEast := "us-east"
	usWest := "us-west"
	empty := ""

	cases := []struct {
		name string
		in   string
		want labels.Selector
	}{
		{name: "empty", in: "", want: labels.Selector{}},
		{name: "whitespace only", in: "   \t  ", want: labels.Selector{}},
		{name: "bare key", in: "env", want: labels.Selector{{Op: labels.OpHas, Key: "env"}}},
		{name: "not has", in: "!owner", want: labels.Selector{{Op: labels.OpNotHas, Key: "owner"}}},
		{name: "equality", in: "env=prod", want: labels.Selector{{Op: labels.OpEq, Key: "env", Values: []string{prod}}}},
		{name: "inequality", in: "role!=cache", want: labels.Selector{{Op: labels.OpNotEq, Key: "role", Values: []string{cache}}}},
		{name: "in", in: "region in (us-east,us-west)", want: labels.Selector{{Op: labels.OpIn, Key: "region", Values: []string{usEast, usWest}}}},
		{name: "notin", in: "region notin (us-east,us-west)", want: labels.Selector{{Op: labels.OpNotIn, Key: "region", Values: []string{usEast, usWest}}}},
		{name: "compound", in: "env=prod,role!=cache,!owner", want: labels.Selector{
			{Op: labels.OpEq, Key: "env", Values: []string{prod}},
			{Op: labels.OpNotEq, Key: "role", Values: []string{cache}},
			{Op: labels.OpNotHas, Key: "owner"},
		}},
		{name: "spaces around tokens", in: "  env  =  prod  ,  role  !=  cache  ", want: labels.Selector{
			{Op: labels.OpEq, Key: "env", Values: []string{prod}},
			{Op: labels.OpNotEq, Key: "role", Values: []string{cache}},
		}},
		{name: "prefixed key", in: "example.com/role=db", want: labels.Selector{
			{Op: labels.OpEq, Key: "example.com/role", Values: []string{"db"}},
		}},
		{name: "reserved prefix allowed", in: "system-wrangler.io/discovered=ansible", want: labels.Selector{
			{Op: labels.OpEq, Key: "system-wrangler.io/discovered", Values: []string{"ansible"}},
		}},
		{name: "empty value", in: "env=", want: labels.Selector{
			{Op: labels.OpEq, Key: "env", Values: []string{empty}},
		}},
		{name: "research doc team and not owner", in: "team,!owner", want: labels.Selector{
			{Op: labels.OpHas, Key: "team"},
			{Op: labels.OpNotHas, Key: "owner"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := labels.ParseSelector(tc.in)
			if err != nil {
				t.Fatalf("labels.ParseSelector(%q) err = %v", tc.in, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got = %+v\nwant = %+v", got, tc.want)
			}
		})
	}
}

func TestParseSelector_Errors(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{name: "trailing comma", in: "env=prod,"},
		{name: "leading comma", in: ",env=prod"},
		{name: "stray equals", in: "=prod"},
		{name: "stray bang", in: "!"},
		{name: "bad operator word", in: "region under (us-east)"},
		{name: "unterminated in list", in: "region in (us-east"},
		{name: "empty in list", in: "region in ()"},
		{name: "missing in open paren", in: "region in us-east"},
		{name: "illegal char", in: "env=prod@us-east"},
		{name: "invalid key charset", in: "env!=foo bar"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := labels.ParseSelector(tc.in); err == nil {
				t.Errorf("labels.ParseSelector(%q) = nil err, want error", tc.in)
			}
		})
	}
}

func TestParseSelector_ExtraErrors(t *testing.T) {
	cases := []string{
		"!",
		"!=value",
		"key in)",
		",key=value",
	}
	for _, c := range cases {
		if _, err := labels.ParseSelector(c); err == nil {
			t.Errorf("ParseSelector(%q) = nil err, want error", c)
		}
	}
}

func TestParseSelector_RejectsBadKeyCharsetInSelector(t *testing.T) {
	// A key that's too long should bubble up through labels.ParseSelector even
	// though tokenize itself doesn't enforce length.
	long := strings.Repeat("a", 300)
	if _, err := labels.ParseSelector(long); err == nil {
		t.Errorf("labels.ParseSelector with overlong key should error")
	}
}

func TestSelectorMatches(t *testing.T) {
	prod := "prod"
	stg := "staging"
	db := "db"
	mkLabels := func(pairs ...any) []labels.Label {
		out := make([]labels.Label, 0, len(pairs)/2)
		for i := 0; i < len(pairs); i += 2 {
			key := pairs[i].(string)
			switch v := pairs[i+1].(type) {
			case string:
				val := v
				out = append(out, labels.Label{Key: key, Value: &val})
			case *string:
				val := *v
				out = append(out, labels.Label{Key: key, Value: &val})
			case nil:
				out = append(out, labels.Label{Key: key, Value: nil})
			default:
				t.Fatalf("mkLabels: unsupported value type %T", v)
			}
		}
		return out
	}

	cases := []struct {
		name     string
		selector string
		labels   []labels.Label
		want     bool
	}{
		{name: "empty selector matches anything", selector: "", labels: nil, want: true},
		{name: "has matches bare tag", selector: "oncall", labels: mkLabels("oncall", nil), want: true},
		{name: "has matches kv too", selector: "env", labels: mkLabels("env", "prod"), want: true},
		{name: "has misses absent", selector: "env", labels: mkLabels("role", "db"), want: false},
		{name: "not has misses present", selector: "!env", labels: mkLabels("env", "prod"), want: false},
		{name: "not has matches absent", selector: "!env", labels: mkLabels("role", "db"), want: true},
		{name: "eq matches", selector: "env=prod", labels: mkLabels("env", &prod), want: true},
		{name: "eq misses wrong value", selector: "env=prod", labels: mkLabels("env", &stg), want: false},
		{name: "eq misses absent", selector: "env=prod", labels: mkLabels("role", "db"), want: false},
		{name: "eq misses bare tag", selector: "env=prod", labels: mkLabels("env", nil), want: false},
		{name: "neq matches different value", selector: "env!=prod", labels: mkLabels("env", &stg), want: true},
		{name: "neq matches absent", selector: "env!=prod", labels: mkLabels("role", "db"), want: true},
		{name: "neq matches bare tag", selector: "env!=prod", labels: mkLabels("env", nil), want: true},
		{name: "neq misses same value", selector: "env!=prod", labels: mkLabels("env", &prod), want: false},
		{name: "in matches", selector: "env in (prod,staging)", labels: mkLabels("env", &stg), want: true},
		{name: "in misses outside", selector: "env in (prod,staging)", labels: mkLabels("env", "dev"), want: false},
		{name: "in misses absent", selector: "env in (prod)", labels: mkLabels(), want: false},
		{name: "in misses bare", selector: "env in (prod)", labels: mkLabels("env", nil), want: false},
		{name: "notin matches outside", selector: "env notin (prod,staging)", labels: mkLabels("env", "dev"), want: true},
		{name: "notin matches absent", selector: "env notin (prod)", labels: mkLabels(), want: true},
		{name: "notin matches bare", selector: "env notin (prod)", labels: mkLabels("env", nil), want: true},
		{name: "notin misses in-set", selector: "env notin (prod,staging)", labels: mkLabels("env", &prod), want: false},
		{name: "compound passes only if all pass",
			selector: "env=prod,role=db",
			labels:   mkLabels("env", &prod, "role", &db),
			want:     true},
		{name: "compound fails if one fails",
			selector: "env=prod,role=db",
			labels:   mkLabels("env", &prod, "role", "web"),
			want:     false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sel, err := labels.ParseSelector(tc.selector)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.selector, err)
			}
			got := sel.Matches(tc.labels)
			if got != tc.want {
				t.Errorf("Matches = %v, want %v\nselector: %q\nlabels: %+v", got, tc.want, tc.selector, tc.labels)
			}
		})
	}
}

func TestSelectorSQL_Forms(t *testing.T) {
	cases := []struct {
		name     string
		selector string
		wantSQL  string
		wantArgs []any
	}{
		{name: "empty", selector: "", wantSQL: "", wantArgs: nil},
		{
			name:     "has",
			selector: "env",
			wantSQL:  "EXISTS (SELECT 1 FROM system_labels WHERE system_id = h.id AND key = ?)",
			wantArgs: []any{"env"},
		},
		{
			name:     "not has",
			selector: "!env",
			wantSQL:  "NOT EXISTS (SELECT 1 FROM system_labels WHERE system_id = h.id AND key = ?)",
			wantArgs: []any{"env"},
		},
		{
			name:     "eq",
			selector: "env=prod",
			wantSQL:  "EXISTS (SELECT 1 FROM system_labels WHERE system_id = h.id AND key = ? AND value = ?)",
			wantArgs: []any{"env", "prod"},
		},
		{
			name:     "neq",
			selector: "env!=prod",
			wantSQL:  "NOT EXISTS (SELECT 1 FROM system_labels WHERE system_id = h.id AND key = ? AND value = ?)",
			wantArgs: []any{"env", "prod"},
		},
		{
			name:     "in",
			selector: "env in (prod,staging)",
			wantSQL:  "EXISTS (SELECT 1 FROM system_labels WHERE system_id = h.id AND key = ? AND value IN (?,?))",
			wantArgs: []any{"env", "prod", "staging"},
		},
		{
			name:     "notin",
			selector: "env notin (prod,staging)",
			wantSQL:  "NOT EXISTS (SELECT 1 FROM system_labels WHERE system_id = h.id AND key = ? AND value IN (?,?))",
			wantArgs: []any{"env", "prod", "staging"},
		},
		{
			name:     "compound joins with AND",
			selector: "env=prod,!owner",
			wantSQL: "EXISTS (SELECT 1 FROM system_labels WHERE system_id = h.id AND key = ? AND value = ?)" +
				" AND NOT EXISTS (SELECT 1 FROM system_labels WHERE system_id = h.id AND key = ?)",
			wantArgs: []any{"env", "prod", "owner"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sel, err := labels.ParseSelector(tc.selector)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			gotSQL, gotArgs := sel.SQL("h.id")
			if gotSQL != tc.wantSQL {
				t.Errorf("SQL = %q\nwant = %q", gotSQL, tc.wantSQL)
			}
			if !reflect.DeepEqual(gotArgs, tc.wantArgs) {
				t.Errorf("args = %+v\nwant = %+v", gotArgs, tc.wantArgs)
			}
		})
	}
}

// TestSelectorSQL_AgainstSQLite is the end-to-end sanity check that the
// generated SQL actually filters rows the way Matches() says it should.
// Seeds three systems with overlapping labels and asserts the filtered
// id set for a representative selector.
func TestSelectorSQL_AgainstSQLite(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "labels-sql-e2e.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	sysStore, err := systems.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("systems init: %v", err)
	}
	store, err := labels.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("labels init: %v", err)
	}
	mk := func(name string, pairs ...any) string {
		sys, err := sysStore.Create(systems.SystemInput{Name: name, Hostname: name + ".example"})
		if err != nil {
			t.Fatalf("systems.Create: %v", err)
		}
		for i := 0; i < len(pairs); i += 2 {
			k := pairs[i].(string)
			var v *string
			if pairs[i+1] != nil {
				s := pairs[i+1].(string)
				v = &s
			}
			if _, err := store.Set(sys.ID, k, v, false); err != nil {
				t.Fatalf("set %s=%v on %s: %v", k, v, name, err)
			}
		}
		return sys.ID
	}
	prodDB := mk("prodDB", "env", "prod", "role", "db")
	prodWeb := mk("prodWeb", "env", "prod", "role", "web", "oncall", nil)
	stgDB := mk("stgDB", "env", "staging", "role", "db")

	run := func(selector string) []string {
		sel, err := labels.ParseSelector(selector)
		if err != nil {
			t.Fatalf("parse %q: %v", selector, err)
		}
		frag, args := sel.SQL("h.id")
		where := ""
		if frag != "" {
			where = " WHERE " + frag
		}
		q := "SELECT h.id FROM hosts h" + where + " ORDER BY h.id" //nolint:gosec
		rows, err := db.Query(q, args...)
		if err != nil {
			t.Fatalf("query %q: %v", selector, err)
		}
		defer func() { _ = rows.Close() }()
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatalf("scan: %v", err)
			}
			ids = append(ids, id)
		}
		sort.Strings(ids)
		return ids
	}
	expect := func(ids []string, want ...string) {
		t.Helper()
		sort.Strings(want)
		if !reflect.DeepEqual(ids, want) {
			t.Errorf("ids = %+v, want %+v", ids, want)
		}
	}

	expect(run("env=prod"), prodDB, prodWeb)
	expect(run("env=prod,role=db"), prodDB)
	expect(run("env=prod,role!=db"), prodWeb)
	expect(run("role in (db,cache)"), prodDB, stgDB)
	expect(run("oncall"), prodWeb)
	expect(run("!oncall"), prodDB, stgDB)
	// Empty selector returns all systems.
	expect(run(""), prodDB, prodWeb, stgDB)
}

func TestParseSelector_BangWithoutKey(t *testing.T) {
	_, err := labels.ParseSelector("!=foo")
	if err == nil {
		t.Fatalf("expected error parsing '!=foo' bare")
	}
	if !errors.Is(err, labels.ErrInvalid) {
		t.Errorf("err = %v, want labels.ErrInvalid", err)
	}
}

// TestParseSelector_EmptyValueInList covers the legal-empty branch in
// parseListValue (a `,,` sequence inside the parens) and complements
// the empty-value `env=` case in TestParseSelector_Forms.
func TestParseSelector_EmptyValueInList(t *testing.T) {
	got, err := labels.ParseSelector("env in (prod,,staging)")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 1 || len(got[0].Values) != 3 || got[0].Values[1] != "" {
		t.Errorf("got = %+v, want middle value empty string", got)
	}
}

// TestParseSelector_BangThenEquals captures '!key=val' which our
// grammar does not accept (the '!' prefix is only valid for the bare-
// existence form).
func TestParseSelector_BangThenEquals(t *testing.T) {
	if _, err := labels.ParseSelector("!env=prod"); err == nil {
		t.Errorf("expected '!env=prod' to error (grammar permits only !key)")
	}
}

// TestParseSelector_TokenKindCoverage exercises error paths that
// surface each operator name in error messages, lifting tokenKindName
// coverage.
func TestParseSelector_TokenKindCoverage(t *testing.T) {
	for _, in := range []string{
		",",   // stray comma → error mentioning identifier
		"!()", // bang then unexpected paren
		"env=(",
	} {
		if _, err := labels.ParseSelector(in); err == nil {
			t.Errorf("labels.ParseSelector(%q) = nil err, want error", in)
		}
	}
}

// TestParseSelector_OverlongValue exercises the validate-error branch
// inside parseListValue and parseValue (the value satisfies the
// tokenizer but blows the per-value length cap).
func TestParseSelector_OverlongValue(t *testing.T) {
	long := strings.Repeat("a", 64) // one over the maxValueLen of 63
	if _, err := labels.ParseSelector("env=" + long); err == nil {
		t.Errorf("overlong = value should error")
	}
	if _, err := labels.ParseSelector("env in (" + long + ")"); err == nil {
		t.Errorf("overlong in() value should error")
	}
}

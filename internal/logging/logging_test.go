// SPDX-License-Identifier: Apache-2.0

package logging_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"system-wrangler-backend/internal/logging"
)

// withBase points all component loggers at a fresh JSON buffer and
// returns it. The base level is Debug so the only gating in play is the
// per-component LevelVar under test.
func withBase(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	logging.SetBase(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return &buf
}

// lines decodes every JSON record written to buf.
func lines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("decode %q: %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

func TestComponentStampsAttribute(t *testing.T) {
	buf := withBase(t)
	logging.Component(logging.Alert).Info("evaluated")

	recs := lines(t, buf)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	if got := recs[0]["component"]; got != logging.Alert {
		t.Fatalf("component = %v, want %q", got, logging.Alert)
	}
	if got := recs[0]["msg"]; got != "evaluated" {
		t.Fatalf("msg = %v", got)
	}
}

func TestDefaultLevelSuppressesDebug(t *testing.T) {
	buf := withBase(t)
	lg := logging.Component("test-default")
	lg.Debug("noisy")
	lg.Info("kept")

	recs := lines(t, buf)
	if len(recs) != 1 {
		t.Fatalf("want only the info line, got %d: %s", len(recs), buf.String())
	}
	if recs[0]["msg"] != "kept" {
		t.Fatalf("unexpected surviving record: %v", recs[0])
	}
}

func TestSetLevelTakesEffectLiveOnExistingLogger(t *testing.T) {
	buf := withBase(t)
	lg := logging.Component("test-live")

	lg.Debug("before") // suppressed at default info
	if got := len(lines(t, buf)); got != 0 {
		t.Fatalf("debug leaked at info level: %d records", got)
	}

	if err := logging.SetLevel("test-live", "debug"); err != nil {
		t.Fatalf("SetLevel: %v", err)
	}
	lg.Debug("after") // same logger instance now passes

	recs := lines(t, buf)
	if len(recs) != 1 || recs[0]["msg"] != "after" {
		t.Fatalf("expected the after-debug line, got %v", recs)
	}
}

func TestComponentsAreIndependent(t *testing.T) {
	buf := withBase(t)
	loud := logging.Component("test-loud")
	quiet := logging.Component("test-quiet")
	if err := logging.SetLevel("test-loud", "debug"); err != nil {
		t.Fatalf("SetLevel: %v", err)
	}

	loud.Debug("loud-debug")
	quiet.Debug("quiet-debug")

	recs := lines(t, buf)
	if len(recs) != 1 {
		t.Fatalf("want only the loud debug, got %d: %s", len(recs), buf.String())
	}
	if recs[0]["component"] != "test-loud" {
		t.Fatalf("wrong component survived: %v", recs[0])
	}
}

func TestSetLevelInvalidLeavesLevelUnchanged(t *testing.T) {
	buf := withBase(t)
	lg := logging.Component("test-invalid")
	if err := logging.SetLevel("test-invalid", "debug"); err != nil {
		t.Fatalf("SetLevel debug: %v", err)
	}
	if err := logging.SetLevel("test-invalid", "bogus"); err == nil {
		t.Fatal("expected error for bogus level")
	}
	lg.Debug("still-debug")
	if got := len(lines(t, buf)); got != 1 {
		t.Fatalf("invalid level should not have raised the threshold; got %d records", got)
	}
}

func TestWithAttrsPreservesComponentAndLevel(t *testing.T) {
	buf := withBase(t)
	lg := logging.Component("test-with").With("rule_id", "r1")
	if err := logging.SetLevel("test-with", "debug"); err != nil {
		t.Fatalf("SetLevel: %v", err)
	}
	lg.Debug("derived")

	recs := lines(t, buf)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	if recs[0]["component"] != "test-with" {
		t.Fatalf("component lost through With: %v", recs[0])
	}
	if recs[0]["rule_id"] != "r1" {
		t.Fatalf("attr lost through With: %v", recs[0])
	}
}

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in    string
		want  slog.Level
		valid bool
	}{
		{"debug", slog.LevelDebug, true},
		{"INFO", slog.LevelInfo, true},
		{" Warn ", slog.LevelWarn, true},
		{"warning", slog.LevelWarn, true},
		{"error", slog.LevelError, true},
		{"err", slog.LevelError, true},
		{"", slog.LevelInfo, false},
		{"trace", slog.LevelInfo, false},
	}
	for _, c := range cases {
		got, ok := logging.ParseLevel(c.in)
		if ok != c.valid || got != c.want {
			t.Errorf("ParseLevel(%q) = (%v, %v), want (%v, %v)", c.in, got, ok, c.want, c.valid)
		}
	}
}

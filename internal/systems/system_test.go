// SPDX-License-Identifier: AGPL-3.0-or-later

package systems

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

func TestSystemInputValidate(t *testing.T) {
	long := strings.Repeat("a", maxFieldLen+1)
	tests := []struct {
		name    string
		in      SystemInput
		wantErr bool
		wantMsg string
	}{
		{"ok", SystemInput{Name: "host1", Hostname: "1.2.3.4"}, false, ""},
		{"trims and accepts", SystemInput{Name: "  ok  ", Hostname: " 1.2.3.4 "}, false, ""},
		{"empty name", SystemInput{Name: "", Hostname: "1.2.3.4"}, true, "name is required"},
		{"whitespace name", SystemInput{Name: "   ", Hostname: "1.2.3.4"}, true, "name is required"},
		{"empty hostname", SystemInput{Name: "host1", Hostname: ""}, true, "hostname is required"},
		{"name too long", SystemInput{Name: long, Hostname: "1.2.3.4"}, true, "exceeds"},
		{"hostname too long", SystemInput{Name: "host1", Hostname: long}, true, "exceeds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.in.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, ErrInvalid) {
					t.Errorf("err = %v, want wrapping ErrInvalid", err)
				}
				if !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("err msg = %q, want substring %q", err.Error(), tt.wantMsg)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestNewUUIDFormat(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := newUUID()
		if !re.MatchString(id) {
			t.Fatalf("id %q does not match v4 pattern", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}

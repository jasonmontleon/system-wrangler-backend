// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestGenerateRecoveryCodesShape(t *testing.T) {
	codes, err := GenerateRecoveryCodes(RecoveryCodeCount)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	if len(codes) != RecoveryCodeCount {
		t.Fatalf("len = %d, want %d", len(codes), RecoveryCodeCount)
	}
	seen := map[string]struct{}{}
	for _, c := range codes {
		if len(c) != RecoveryCodeLength+1 {
			t.Errorf("code %q length = %d, want %d", c, len(c), RecoveryCodeLength+1)
		}
		if !strings.Contains(c, "-") {
			t.Errorf("code %q missing hyphen", c)
		}
		if _, dup := seen[c]; dup {
			t.Errorf("duplicate code %q", c)
		}
		seen[c] = struct{}{}
	}
}

func TestGenerateRecoveryCodesRejectsZeroOrNegative(t *testing.T) {
	for _, n := range []int{0, -1} {
		if _, err := GenerateRecoveryCodes(n); err == nil {
			t.Errorf("n=%d: want error", n)
		}
	}
}

func TestNormalizeRecoveryCode(t *testing.T) {
	tests := []struct{ in, want string }{
		{"abc12-def34", "ABC12DEF34"},
		{"  abc12 def34  ", "ABC12DEF34"},
		{"ABC12DEF34", "ABC12DEF34"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := NormalizeRecoveryCode(tt.in); got != tt.want {
			t.Errorf("Normalize(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestHashAndCompareRecoveryCode(t *testing.T) {
	codes, _ := GenerateRecoveryCodes(1)
	code := codes[0]
	hash, err := HashRecoveryCode(code)
	if err != nil {
		t.Fatalf("HashRecoveryCode: %v", err)
	}
	if hash == code {
		t.Error("hash equals code")
	}
	// Match accepts the original formatting.
	if err := CompareRecoveryCode(hash, code); err != nil {
		t.Errorf("Compare same: %v", err)
	}
	// Match accepts the normalized form (no hyphen, lowercase).
	if err := CompareRecoveryCode(hash, strings.ToLower(strings.ReplaceAll(code, "-", ""))); err != nil {
		t.Errorf("Compare normalized: %v", err)
	}
	// Wrong code rejected.
	if err := CompareRecoveryCode(hash, "WRONG-CODE"); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("Compare wrong err = %v, want ErrUnauthorized", err)
	}
}

func TestHashRecoveryCodeRejectsEmpty(t *testing.T) {
	if _, err := HashRecoveryCode("   "); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}

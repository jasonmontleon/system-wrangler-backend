// SPDX-License-Identifier: Apache-2.0

package labels

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateKey(t *testing.T) {
	cases := []struct {
		name           string
		key            string
		allowReserved  bool
		wantErr        error
		wantErrContain string
	}{
		{name: "simple", key: "env"},
		{name: "with dots", key: "io.k8s.role"},
		{name: "with dash and underscore", key: "team_a-b"},
		{name: "with prefix", key: "example.com/role"},
		{name: "reserved blocked", key: "system-wrangler.io/discovered-via", wantErr: ErrReserved},
		{name: "reserved allowed", key: "system-wrangler.io/discovered-via", allowReserved: true},
		{name: "empty", key: "", wantErr: ErrInvalid, wantErrContain: "required"},
		{name: "illegal char", key: "env!", wantErr: ErrInvalid, wantErrContain: "illegal"},
		{name: "slash but empty prefix", key: "/role", wantErr: ErrInvalid, wantErrContain: "empty"},
		{name: "slash but empty name", key: "example.com/", wantErr: ErrInvalid, wantErrContain: "empty"},
		{name: "name too long", key: strings.Repeat("a", maxSegmentLen+1), wantErr: ErrInvalid, wantErrContain: "exceeds"},
		{name: "prefix too long", key: strings.Repeat("a", maxSegmentLen+1) + "/x", wantErr: ErrInvalid, wantErrContain: "exceeds"},
		{name: "total too long", key: strings.Repeat("a", maxKeyLen+1), wantErr: ErrInvalid, wantErrContain: "exceeds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateKey(tc.key, tc.allowReserved)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("ValidateKey(%q) = %v, want nil", tc.key, err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ValidateKey(%q) err = %v, want %v", tc.key, err, tc.wantErr)
			}
			if tc.wantErrContain != "" && !strings.Contains(err.Error(), tc.wantErrContain) {
				t.Fatalf("ValidateKey(%q) err = %q, want substring %q", tc.key, err, tc.wantErrContain)
			}
		})
	}
}

func TestValidateValue(t *testing.T) {
	empty := ""
	val := "prod"
	bad := "with space"
	long := strings.Repeat("a", maxValueLen+1)
	cases := []struct {
		name    string
		value   *string
		wantErr error
	}{
		{name: "nil ok", value: nil},
		{name: "empty ok", value: &empty},
		{name: "simple ok", value: &val},
		{name: "illegal char", value: &bad, wantErr: ErrInvalid},
		{name: "too long", value: &long, wantErr: ErrInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateValue(tc.value)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

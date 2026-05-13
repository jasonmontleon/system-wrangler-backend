// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"testing"
)

func TestDetail_SetSafe_RejectsDenyKeys(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want bool // true = should reject
	}{
		{"password", "password", true},
		{"PASSWORD upper", "PASSWORD", true},
		{"current_password", "current_password", true},
		{"new_password", "new_password", true},
		{"session_token", "session_token", true},
		{"totp_secret", "totp_secret", true},
		{"recovery_code", "recovery_code", true},
		{"recovery_codes", "recovery_codes", true},
		{"cookie value", "session_cookie", true},
		{"bearer", "bearer_value", true},
		{"credential", "credential_id", true},
		{"private_key", "private_key", true},
		{"private-key dash", "private-key", true},
		{"plain key", "key", false},
		{"public_key fingerprint not in denylist", "public_fingerprint", false},
		{"username", "username", false},
		{"attempted_username", "attempted_username", false},
		{"reason", "reason", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDetail()
			err := d.SetSafe(tt.key, "v")
			rejected := errors.Is(err, ErrUnsafeDetailKey)
			if rejected != tt.want {
				t.Fatalf("SetSafe(%q): rejected=%v want=%v err=%v", tt.key, rejected, tt.want, err)
			}
			if tt.want {
				if _, ok := d[tt.key]; ok {
					t.Errorf("rejected key %q still landed in detail map", tt.key)
				}
			} else {
				if v, ok := d[tt.key]; !ok || v != "v" {
					t.Errorf("safe key %q missing or wrong value: %v ok=%v", tt.key, v, ok)
				}
			}
		})
	}
}

func TestActorFromContext_DefaultIsUnauthenticated(t *testing.T) {
	got := ActorFromContext(context.Background())
	if got.Kind != ActorUnauthenticated {
		t.Errorf("default actor kind = %q, want unauthenticated", got.Kind)
	}
	if got.ID != "" || got.Label != "" {
		t.Errorf("default actor has nonzero id/label: %+v", got)
	}
}

func TestActorFromContext_RoundTrip(t *testing.T) {
	want := Actor{Kind: ActorUser, ID: "u1", Label: "alice"}
	ctx := WithActor(context.Background(), want)
	got := ActorFromContext(ctx)
	if got != want {
		t.Errorf("round-trip mismatch: got %+v want %+v", got, want)
	}
}

func TestRequestID_RoundTrip(t *testing.T) {
	if got := RequestIDFromContext(context.Background()); got != "" {
		t.Errorf("default request id = %q, want empty", got)
	}
	ctx := WithRequestID(context.Background(), "req-123")
	if got := RequestIDFromContext(ctx); got != "req-123" {
		t.Errorf("request id = %q, want req-123", got)
	}
}

func TestRemoteAddr_RoundTrip(t *testing.T) {
	if got := RemoteAddrFromContext(context.Background()); got != "" {
		t.Errorf("default remote = %q, want empty", got)
	}
	ctx := WithRemoteAddr(context.Background(), "10.0.0.1:54321")
	if got := RemoteAddrFromContext(ctx); got != "10.0.0.1:54321" {
		t.Errorf("remote = %q, want 10.0.0.1:54321", got)
	}
}

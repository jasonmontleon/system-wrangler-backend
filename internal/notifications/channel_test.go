// SPDX-License-Identifier: Apache-2.0

package notifications

import (
	"errors"
	"strings"
	"testing"
)

func emailInput() ChannelInput {
	return ChannelInput{
		Name:    "ops email",
		Type:    TypeEmail,
		Enabled: true,
		Config: Config{
			SMTPHost: "smtp.example.com",
			SMTPPort: 587,
			From:     "alerts@example.com",
			To:       []string{"oncall@example.com"},
			StartTLS: true,
		},
		Secret: "hunter2",
	}
}

func TestValidateEmailOK(t *testing.T) {
	in := emailInput()
	if err := in.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateWebhookDefaultsMethod(t *testing.T) {
	in := ChannelInput{Name: "wh", Type: TypeWebhook, Config: Config{URL: "https://example.com/hook"}}
	if err := in.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if in.Config.Method != "POST" {
		t.Errorf("method default = %q, want POST", in.Config.Method)
	}
}

func TestValidateSMSDefaultsBaseURL(t *testing.T) {
	in := ChannelInput{
		Name:   "sms",
		Type:   TypeSMS,
		Config: Config{AccountSID: "AC123", From: "+15550000000", To: []string{"+15551112222"}},
		Secret: "tok",
	}
	if err := in.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if in.Config.BaseURL != DefaultSMSBaseURL {
		t.Errorf("baseURL default = %q, want %q", in.Config.BaseURL, DefaultSMSBaseURL)
	}
}

func TestValidateSlackChecksSecretURL(t *testing.T) {
	in := ChannelInput{Name: "slack", Type: TypeSlack, Secret: "https://hooks.slack.com/services/x"} //nolint:gosec // test fixture, not a real credential
	if err := in.Validate(); err != nil {
		t.Fatalf("valid slack URL rejected: %v", err)
	}
	bad := ChannelInput{Name: "slack", Type: TypeSlack, Secret: "not-a-url"}
	if err := bad.Validate(); !errors.Is(err, ErrInvalid) {
		t.Errorf("expected ErrInvalid for bad slack URL, got %v", err)
	}
}

func TestValidateErrors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ChannelInput)
	}{
		{"empty name", func(in *ChannelInput) { in.Name = "  " }},
		{"long name", func(in *ChannelInput) { in.Name = strings.Repeat("x", maxNameLen+1) }},
		{"bad type", func(in *ChannelInput) { in.Type = "carrier-pigeon" }},
		{"email no host", func(in *ChannelInput) { in.Config.SMTPHost = "" }},
		{"email bad port", func(in *ChannelInput) { in.Config.SMTPPort = 0 }},
		{"email no from", func(in *ChannelInput) { in.Config.From = "" }},
		{"email no to", func(in *ChannelInput) { in.Config.To = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := emailInput()
			tt.mutate(&in)
			if err := in.Validate(); !errors.Is(err, ErrInvalid) {
				t.Errorf("expected ErrInvalid, got %v", err)
			}
		})
	}
}

func TestValidateWebhookErrors(t *testing.T) {
	tests := []struct {
		name string
		in   ChannelInput
	}{
		{"no url", ChannelInput{Name: "w", Type: TypeWebhook}},
		{"bad scheme", ChannelInput{Name: "w", Type: TypeWebhook, Config: Config{URL: "ftp://x"}}},
		{"bad method", ChannelInput{Name: "w", Type: TypeWebhook, Config: Config{URL: "https://x", Method: "DELETE"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := tt.in
			if err := in.Validate(); !errors.Is(err, ErrInvalid) {
				t.Errorf("expected ErrInvalid, got %v", err)
			}
		})
	}
}

func TestValidateSMSErrors(t *testing.T) {
	base := ChannelInput{
		Name:   "sms",
		Type:   TypeSMS,
		Config: Config{AccountSID: "AC", From: "+1", To: []string{"+2"}},
		Secret: "t",
	}
	tests := []struct {
		name   string
		mutate func(*ChannelInput)
	}{
		{"no sid", func(in *ChannelInput) { in.Config.AccountSID = "" }},
		{"no from", func(in *ChannelInput) { in.Config.From = "" }},
		{"no to", func(in *ChannelInput) { in.Config.To = nil }},
		{"bad base", func(in *ChannelInput) { in.Config.BaseURL = "ftp://x" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := base
			in.Config.To = []string{"+2"}
			tt.mutate(&in)
			if err := in.Validate(); !errors.Is(err, ErrInvalid) {
				t.Errorf("expected ErrInvalid, got %v", err)
			}
		})
	}
}

func TestValidateTrimsRecipients(t *testing.T) {
	in := emailInput()
	in.Config.To = []string{" a@x ", "", "b@x"}
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(in.Config.To) != 2 || in.Config.To[0] != "a@x" {
		t.Errorf("recipients not trimmed/compacted: %#v", in.Config.To)
	}
}

func TestRedactedHidesSecret(t *testing.T) {
	c := Channel{
		ID:     "c1",
		Name:   "slack",
		Type:   TypeSlack,
		Secret: Sealed{Ciphertext: []byte("x"), Nonce: []byte("n"), Version: 1},
	}
	dto := c.Redacted()
	if !dto.HasSecret {
		t.Error("HasSecret should be true")
	}
	// The DTO type has no field that could carry the ciphertext.
	empty := Channel{ID: "c2", Type: TypeWebhook}.Redacted()
	if empty.HasSecret {
		t.Error("HasSecret should be false when no secret")
	}
}

func TestTypeIsValid(t *testing.T) {
	for _, ty := range []Type{TypeEmail, TypeSlack, TypeWebhook, TypeSMS} {
		if !ty.IsValid() {
			t.Errorf("%q should be valid", ty)
		}
	}
	if Type("pager").IsValid() {
		t.Error("pager should be invalid")
	}
}

func TestNewUUIDUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		id := newUUID()
		if len(id) != 36 || seen[id] {
			t.Fatalf("bad/duplicate uuid %q", id)
		}
		seen[id] = true
	}
}

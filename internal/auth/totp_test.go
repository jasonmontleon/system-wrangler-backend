// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func TestGenerateTOTPSecretFields(t *testing.T) {
	secret, uri, qr, err := GenerateTOTPSecret("alice")
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if len(secret) != 20 {
		t.Errorf("secret length = %d, want 20", len(secret))
	}
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse uri: %v", err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" {
		t.Errorf("uri scheme/host = %s/%s", u.Scheme, u.Host)
	}
	if !strings.Contains(u.Path, "alice") {
		t.Errorf("uri path %q lacks account name", u.Path)
	}
	if u.Query().Get("issuer") != TOTPIssuer {
		t.Errorf("issuer = %q", u.Query().Get("issuer"))
	}
	// PNG magic header.
	if len(qr) < 8 || string(qr[1:4]) != "PNG" {
		t.Errorf("qr lacks PNG header: %x", qr[:8])
	}
}

func TestVerifyTOTPCodeAcceptsCurrentWindow(t *testing.T) {
	secret, _, _, err := GenerateTOTPSecret("alice")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	code, err := totp.GenerateCodeCustom(totpEncoding.EncodeToString(secret), now, totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	step, err := VerifyTOTPCode(secret, code, now, 0)
	if err != nil {
		t.Fatalf("VerifyTOTPCode: %v", err)
	}
	if step <= 0 {
		t.Errorf("step = %d, want > 0", step)
	}
}

func TestVerifyTOTPCodeAcceptsPriorStepSkew(t *testing.T) {
	secret, _, _, _ := GenerateTOTPSecret("alice")
	now := time.Date(2026, 5, 6, 12, 0, 30, 0, time.UTC)
	prior := now.Add(-30 * time.Second)
	code, _ := totp.GenerateCodeCustom(totpEncoding.EncodeToString(secret), prior, totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if _, err := VerifyTOTPCode(secret, code, now, 0); err != nil {
		t.Errorf("prior-step skew err = %v, want nil", err)
	}
}

func TestVerifyTOTPCodeAcceptsNextStepSkew(t *testing.T) {
	secret, _, _, _ := GenerateTOTPSecret("alice")
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	next := now.Add(30 * time.Second)
	code, _ := totp.GenerateCodeCustom(totpEncoding.EncodeToString(secret), next, totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if _, err := VerifyTOTPCode(secret, code, now, 0); err != nil {
		t.Errorf("next-step skew err = %v, want nil", err)
	}
}

func TestVerifyTOTPCodeRejectsRotatedCode(t *testing.T) {
	secret, _, _, _ := GenerateTOTPSecret("alice")
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	longAgo := now.Add(-5 * time.Minute)
	code, _ := totp.GenerateCodeCustom(totpEncoding.EncodeToString(secret), longAgo, totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if _, err := VerifyTOTPCode(secret, code, now, 0); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("rotated err = %v, want ErrUnauthorized", err)
	}
}

func TestVerifyTOTPCodeReplayRejected(t *testing.T) {
	secret, _, _, _ := GenerateTOTPSecret("alice")
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	code, _ := totp.GenerateCodeCustom(totpEncoding.EncodeToString(secret), now, totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	step, err := VerifyTOTPCode(secret, code, now, 0)
	if err != nil {
		t.Fatalf("first verify: %v", err)
	}
	// Replay the same code with lastStep = step.
	if _, err := VerifyTOTPCode(secret, code, now, step); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("replay err = %v, want ErrUnauthorized", err)
	}
}

func TestVerifyTOTPCodeRejectsEmpty(t *testing.T) {
	secret, _, _, _ := GenerateTOTPSecret("alice")
	if _, err := VerifyTOTPCode(secret, "", time.Now(), 0); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("empty code err = %v, want ErrUnauthorized", err)
	}
}

func TestVerifyTOTPCodeRejectsWrongLength(t *testing.T) {
	secret, _, _, _ := GenerateTOTPSecret("alice")
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	if _, err := VerifyTOTPCode(secret, "12345", now, 0); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("short code err = %v, want ErrUnauthorized", err)
	}
}

func TestVerifyTOTPCodeRejectsEmptySecret(t *testing.T) {
	if _, err := VerifyTOTPCode(nil, "123456", time.Now(), 0); err == nil {
		t.Error("want error for empty secret")
	}
}

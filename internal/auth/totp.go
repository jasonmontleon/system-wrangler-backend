// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"image/png"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTPIssuer is the label baked into the otpauth:// URI. Authenticator apps
// display this above the account name.
const TOTPIssuer = "System Wrangler"

// totpPeriod is the standard 30-second TOTP step.
const totpPeriod uint = 30

// totpQRSize is the QR PNG side length in pixels — large enough to scan from
// a webcam, small enough to keep the data URI under ~6 KB.
const totpQRSize = 256

// totpDigits and totpAlgorithm are pinned to the values every authenticator
// app supports out of the box. Changing these would break already-enrolled
// users, so they are constants rather than knobs.
var (
	totpDigits    = otp.DigitsSix
	totpAlgorithm = otp.AlgorithmSHA1
)

// totpEncoding is the base32 alphabet without padding, matching what every
// authenticator app expects for the otpauth secret parameter.
var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret produces a fresh shared secret plus the otpauth:// URI
// the user scans (or copies) and a 256x256 PNG QR rendering of that URI. The
// raw secret bytes are returned so the caller can encrypt them at rest with
// the KEK; the otpauth URI and QR contain the same secret in base32 form,
// which is unavoidable (the user has to share it with their authenticator).
func GenerateTOTPSecret(username string) (secret []byte, uri string, qrPNG []byte, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      TOTPIssuer,
		AccountName: username,
		Period:      totpPeriod,
		SecretSize:  20,
		Digits:      totpDigits,
		Algorithm:   totpAlgorithm,
	})
	if err != nil {
		return nil, "", nil, fmt.Errorf("auth: generate totp: %w", err)
	}
	rawSecret, err := totpEncoding.DecodeString(key.Secret())
	if err != nil {
		return nil, "", nil, fmt.Errorf("auth: decode totp secret: %w", err)
	}
	img, err := key.Image(totpQRSize, totpQRSize)
	if err != nil {
		return nil, "", nil, fmt.Errorf("auth: render qr: %w", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, "", nil, fmt.Errorf("auth: encode qr png: %w", err)
	}
	return rawSecret, key.URL(), buf.Bytes(), nil
}

// VerifyTOTPCode checks code against secret at time now with ±1 step skew.
// It returns the matched step counter so the caller can persist it as the
// new "last consumed step" floor — passing this back as lastStep on the next
// call rejects replays of the same code within its valid window.
//
// Returns ErrUnauthorized on any failure (no match, replay, malformed code).
// The returned step is meaningful only when err == nil.
func VerifyTOTPCode(secret []byte, code string, now time.Time, lastStep int64) (int64, error) {
	if len(secret) == 0 {
		return 0, errors.New("auth: empty totp secret")
	}
	if len(code) == 0 {
		return 0, ErrUnauthorized
	}
	secretB32 := totpEncoding.EncodeToString(secret)
	period := int64(totpPeriod)
	currentStep := now.Unix() / period
	// Iterate the skew window. For each candidate step, compute the expected
	// code and constant-time compare. The replay guard rejects any step ≤
	// lastStep — TOTP codes are valid for one step (plus skew), but a single
	// code must consume the highest step it matches at so a replay within
	// that window is rejected.
	for _, delta := range []int64{0, -1, 1} {
		step := currentStep + delta
		if step <= lastStep {
			continue
		}
		t := time.Unix(step*period, 0).UTC()
		expected, err := totp.GenerateCodeCustom(secretB32, t, totp.ValidateOpts{
			Period:    totpPeriod,
			Digits:    totpDigits,
			Algorithm: totpAlgorithm,
		})
		if err != nil {
			return 0, fmt.Errorf("auth: generate candidate code: %w", err)
		}
		if len(expected) != len(code) {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(code), []byte(expected)) == 1 {
			return step, nil
		}
	}
	return 0, ErrUnauthorized
}

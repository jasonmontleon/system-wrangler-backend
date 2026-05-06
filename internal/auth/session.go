// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SessionSecretKey is the meta-table key under which the HMAC signing key is
// stored. Generated once on first start, persisted forever after.
const SessionSecretKey = "session_secret"

// CookieName is the name of the session cookie. Prefixed `sw_` to make it
// recognizable in dev tools and avoid collision with any `session` cookies
// from sibling services on the same host.
const CookieName = "sw_session"

// DefaultSessionTTL is the cookie max-age. Fixed (no sliding refresh) for v1.
const DefaultSessionTTL = 30 * 24 * time.Hour

type sessionPayload struct {
	UID string `json:"uid"`
	Exp int64  `json:"exp"`
}

// SignSession encodes a session token: base64url(payload).base64url(hmac).
// Both halves use base64url without padding so the value is cookie-safe and
// has no `=` characters.
func SignSession(secret []byte, userID string, expires time.Time) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("auth: empty signing secret")
	}
	payload, err := json.Marshal(sessionPayload{UID: userID, Exp: expires.Unix()})
	if err != nil {
		return "", fmt.Errorf("auth: marshal session: %w", err)
	}
	enc := base64.RawURLEncoding
	body := enc.EncodeToString(payload)
	mac := hmacSum(secret, []byte(body))
	return body + "." + enc.EncodeToString(mac), nil
}

// VerifySession parses a token, checks the HMAC in constant time, and
// confirms the expiry has not passed. Returns the user ID on success.
func VerifySession(secret []byte, now time.Time, token string) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("auth: empty signing secret")
	}
	body, sig, ok := strings.Cut(token, ".")
	if !ok {
		return "", ErrUnauthorized
	}
	enc := base64.RawURLEncoding
	gotMac, err := enc.DecodeString(sig)
	if err != nil {
		return "", ErrUnauthorized
	}
	wantMac := hmacSum(secret, []byte(body))
	if !hmac.Equal(gotMac, wantMac) {
		return "", ErrUnauthorized
	}
	payloadBytes, err := enc.DecodeString(body)
	if err != nil {
		return "", ErrUnauthorized
	}
	var p sessionPayload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return "", ErrUnauthorized
	}
	if now.Unix() >= p.Exp {
		return "", ErrUnauthorized
	}
	return p.UID, nil
}

func hmacSum(secret, data []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(data)
	return h.Sum(nil)
}

// LoadOrInitSecret returns the persisted HMAC signing key. On first call
// against a fresh DB it generates 32 random bytes and saves them.
func LoadOrInitSecret(s SecretStore) ([]byte, error) {
	val, ok, err := s.LoadSecret(SessionSecretKey)
	if err != nil {
		return nil, err
	}
	if ok {
		return val, nil
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("auth: generate secret: %w", err)
	}
	if err := s.SaveSecret(SessionSecretKey, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

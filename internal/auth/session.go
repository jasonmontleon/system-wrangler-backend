// SPDX-License-Identifier: Apache-2.0

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

// Token purposes provide domain separation across the multiple cookies signed
// with the same HMAC secret. A token issued for one purpose cannot be replayed
// for another because Verify rejects a payload whose `p` field doesn't match.
const (
	PurposeSession       = "session"
	PurposeTOTPChallenge = "totp_challenge"
	PurposeTrustedDevice = "trusted_device"
)

// TokenClaims is the cross-purpose claim set carried in a signed token. Not
// every field is meaningful for every purpose: sessions use UID; the TOTP
// challenge uses UID + Nonce; trusted-device uses UID + DeviceID + Epoch.
// `omitempty` keeps unused fields out of the wire payload to minimise cookie
// size.
type TokenClaims struct {
	UID      string `json:"uid,omitempty"`
	DeviceID string `json:"did,omitempty"`
	Epoch    int64  `json:"epoch,omitempty"`
	Nonce    string `json:"n,omitempty"`
}

type tokenPayload struct {
	Purpose string `json:"p"`
	Exp     int64  `json:"exp"`
	TokenClaims
}

// SignToken encodes a purpose-tagged token: base64url(payload).base64url(hmac).
// Both halves use base64url without padding so the value is cookie-safe.
func SignToken(secret []byte, purpose string, claims TokenClaims, expires time.Time) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("auth: empty signing secret")
	}
	if purpose == "" {
		return "", errors.New("auth: empty token purpose")
	}
	payload, err := json.Marshal(tokenPayload{
		Purpose:     purpose,
		Exp:         expires.Unix(),
		TokenClaims: claims,
	})
	if err != nil {
		return "", fmt.Errorf("auth: marshal token: %w", err)
	}
	enc := base64.RawURLEncoding
	body := enc.EncodeToString(payload)
	mac := hmacSum(secret, []byte(body))
	return body + "." + enc.EncodeToString(mac), nil
}

// VerifyToken parses a token, checks the HMAC in constant time, confirms the
// expiry has not passed, and rejects a purpose mismatch. Domain separation
// via `purpose` prevents a token signed for one cookie (e.g. a 5-minute TOTP
// challenge) being replayed as another (e.g. a 30-day session).
func VerifyToken(secret []byte, now time.Time, purpose, token string) (TokenClaims, error) {
	if len(secret) == 0 {
		return TokenClaims{}, errors.New("auth: empty signing secret")
	}
	body, sig, ok := strings.Cut(token, ".")
	if !ok {
		return TokenClaims{}, ErrUnauthorized
	}
	enc := base64.RawURLEncoding
	gotMac, err := enc.DecodeString(sig)
	if err != nil {
		return TokenClaims{}, ErrUnauthorized
	}
	wantMac := hmacSum(secret, []byte(body))
	if !hmac.Equal(gotMac, wantMac) {
		return TokenClaims{}, ErrUnauthorized
	}
	payloadBytes, err := enc.DecodeString(body)
	if err != nil {
		return TokenClaims{}, ErrUnauthorized
	}
	var p tokenPayload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return TokenClaims{}, ErrUnauthorized
	}
	if p.Purpose != purpose {
		return TokenClaims{}, ErrUnauthorized
	}
	if now.Unix() >= p.Exp {
		return TokenClaims{}, ErrUnauthorized
	}
	return p.TokenClaims, nil
}

// SignSession is the session-purpose specialization of SignToken, retained as
// the canonical entrypoint for issuing session cookies.
func SignSession(secret []byte, userID string, expires time.Time) (string, error) {
	return SignToken(secret, PurposeSession, TokenClaims{UID: userID}, expires)
}

// VerifySession is the session-purpose specialization of VerifyToken. It
// returns the user ID on success.
func VerifySession(secret []byte, now time.Time, token string) (string, error) {
	claims, err := VerifyToken(secret, now, PurposeSession, token)
	if err != nil {
		return "", err
	}
	return claims.UID, nil
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

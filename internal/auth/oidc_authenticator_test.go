// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// discoveryServer stands up a minimal OIDC discovery endpoint so
// oidc.NewProvider succeeds without a real IdP. tokenHandler, when set,
// serves the token endpoint.
func discoveryServer(t *testing.T, tokenHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/auth",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		})
	})
	if tokenHandler != nil {
		mux.HandleFunc("/token", tokenHandler)
	}
	return srv
}

func TestNewOIDCAuthenticatorAndAuthCodeURL(t *testing.T) {
	srv := discoveryServer(t, nil)
	provider, err := oidc.NewProvider(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	cfg := &OIDCConfig{
		ClientID:      "client-1",
		ClientSecret:  "secret",
		RedirectURL:   "https://app.example.com/api/auth/oidc/callback",
		Scopes:        []string{"openid", "email"},
		UsernameClaim: "preferred_username",
	}
	auth := NewOIDCAuthenticator(provider, cfg)

	raw := auth.AuthCodeURL("state-xyz", "nonce-abc", "verifier-123")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}
	q := u.Query()
	checks := map[string]string{
		"state":                 "state-xyz",
		"nonce":                 "nonce-abc",
		"client_id":             "client-1",
		"response_type":         "code",
		"code_challenge_method": "S256",
		"redirect_uri":          cfg.RedirectURL,
	}
	for k, want := range checks {
		if got := q.Get(k); got != want {
			t.Errorf("auth url %s = %q, want %q", k, got, want)
		}
	}
	if q.Get("code_challenge") == "" {
		t.Error("auth url missing code_challenge")
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Errorf("scope = %q, want it to include openid", q.Get("scope"))
	}
}

// fakeVerifier lets us drive Exchange's post-token-endpoint logic without
// a signed JWT.
type fakeVerifier struct {
	tok *oidc.IDToken
	err error
}

func (f fakeVerifier) Verify(_ context.Context, _ string) (*oidc.IDToken, error) {
	return f.tok, f.err
}

func tokenJSON(t *testing.T, body map[string]any) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}
}

func TestOIDCExchangeNoIDToken(t *testing.T) {
	srv := discoveryServer(t, tokenJSON(t, map[string]any{
		"access_token": "at", "token_type": "bearer",
	}))
	a := &oidcAuthenticator{
		oauth: &oauth2.Config{
			ClientID: "c", ClientSecret: "s",
			Endpoint: oauth2.Endpoint{TokenURL: srv.URL + "/token", AuthURL: srv.URL + "/auth"},
		},
		usernameClaim: "preferred_username",
	}
	if _, err := a.Exchange(context.Background(), "code", oauth2.GenerateVerifier()); err == nil {
		t.Fatal("want error when token response has no id_token")
	}
}

func TestOIDCExchangeVerifyError(t *testing.T) {
	srv := discoveryServer(t, tokenJSON(t, map[string]any{ //nolint:gosec // G101: test token fixture, not a real credential
		"access_token": "at", "token_type": "bearer", "id_token": "raw-id-token",
	}))
	a := &oidcAuthenticator{
		oauth: &oauth2.Config{
			ClientID: "c", ClientSecret: "s",
			Endpoint: oauth2.Endpoint{TokenURL: srv.URL + "/token", AuthURL: srv.URL + "/auth"},
		},
		verifier:      fakeVerifier{err: context.Canceled},
		usernameClaim: "preferred_username",
	}
	if _, err := a.Exchange(context.Background(), "code", oauth2.GenerateVerifier()); err == nil {
		t.Fatal("want error when id_token verification fails")
	}
}

// b64 is the base64url-no-padding encoding the JWT/JWKS wire format uses.
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signRS256 mints a compact JWT signed with RS256 — enough for go-oidc's
// real verifier to accept it given the matching JWKS.
func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	payload, _ := json.Marshal(claims)
	signingInput := b64(header) + "." + b64(payload)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + b64(sig)
}

// TestOIDCExchangeHappyPath drives the production authenticator end to end
// against a fake IdP: real discovery, real JWKS, a real RS256-signed ID
// token, and the real go-oidc verifier — confirming the claim mapping.
func TestOIDCExchangeHappyPath(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	const kid = "test-key"
	const clientID = "client-1"

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/auth",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid,
				"n": b64(key.N.Bytes()),
				"e": b64(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		idToken := signRS256(t, key, kid, map[string]any{
			"iss":                srv.URL,
			"aud":                clientID,
			"sub":                "subject-123",
			"exp":                time.Now().Add(time.Hour).Unix(),
			"iat":                time.Now().Unix(),
			"nonce":              "nonce-xyz",
			"preferred_username": "alice",
			"email":              "alice@example.com",
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "bearer", "id_token": idToken,
		})
	})

	provider, err := oidc.NewProvider(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	a := NewOIDCAuthenticator(provider, &OIDCConfig{
		ClientID:      clientID,
		ClientSecret:  "secret",
		RedirectURL:   "https://app/cb",
		Scopes:        []string{"openid"},
		UsernameClaim: "preferred_username",
	})

	claims, err := a.Exchange(context.Background(), "code", oauth2.GenerateVerifier())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if claims.Username != "alice" || claims.Email != "alice@example.com" {
		t.Errorf("claims = %+v, want alice / alice@example.com", claims)
	}
	if claims.Subject != "subject-123" || claims.Nonce != "nonce-xyz" {
		t.Errorf("claims subject/nonce = %q/%q", claims.Subject, claims.Nonce)
	}
}

func TestEndSessionURL(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/auth",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
			"end_session_endpoint":   srv.URL + "/logout",
		})
	})
	provider, err := oidc.NewProvider(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	a := NewOIDCAuthenticator(provider, &OIDCConfig{
		ClientID:    "client-1",
		RedirectURL: "https://app.example.com:8443/api/auth/oidc/callback",
		Scopes:      []string{"openid"},
	})

	got, ok := a.EndSessionURL()
	if !ok {
		t.Fatal("EndSessionURL ok=false, want true when end_session_endpoint is advertised")
	}
	if !strings.HasPrefix(got, srv.URL+"/logout?") {
		t.Errorf("EndSessionURL = %q, want it to start with %q", got, srv.URL+"/logout?")
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Query().Get("client_id") != "client-1" {
		t.Errorf("client_id = %q", u.Query().Get("client_id"))
	}
	if u.Query().Get("post_logout_redirect_uri") != "https://app.example.com:8443/" {
		t.Errorf("post_logout_redirect_uri = %q, want app origin", u.Query().Get("post_logout_redirect_uri"))
	}
}

func TestEndSessionURLUnsupported(t *testing.T) {
	srv := discoveryServer(t, nil) // discovery doc has no end_session_endpoint
	provider, err := oidc.NewProvider(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	a := NewOIDCAuthenticator(provider, &OIDCConfig{ClientID: "c", RedirectURL: "https://app/cb"})
	if _, ok := a.EndSessionURL(); ok {
		t.Error("EndSessionURL ok=true, want false when provider advertises none")
	}
}

func TestOriginOf(t *testing.T) {
	tests := []struct{ in, want string }{
		{"https://app.example.com:8443/api/auth/oidc/callback", "https://app.example.com:8443/"},
		{"http://localhost:8080/cb", "http://localhost:8080/"},
		{"", ""},
		{"/relative/only", ""},
		{"::not-a-url", ""},
	}
	for _, tt := range tests {
		if got := originOf(tt.in); got != tt.want {
			t.Errorf("originOf(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestOIDCExchangeTokenEndpointError(t *testing.T) {
	srv := discoveryServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	})
	a := &oidcAuthenticator{
		oauth: &oauth2.Config{
			ClientID: "c", ClientSecret: "s",
			Endpoint: oauth2.Endpoint{TokenURL: srv.URL + "/token", AuthURL: srv.URL + "/auth"},
		},
		usernameClaim: "preferred_username",
	}
	if _, err := a.Exchange(context.Background(), "code", oauth2.GenerateVerifier()); err == nil {
		t.Fatal("want error when token endpoint rejects the exchange")
	}
}

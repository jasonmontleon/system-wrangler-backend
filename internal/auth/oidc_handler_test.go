// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeOIDC is a no-network OIDCAuthenticator: it records what the handlers
// pass in and returns canned claims (or an error) on Exchange.
type fakeOIDC struct {
	authURL string

	gotState, gotNonce, gotVerifier string

	claims      OIDCClaims
	exchangeErr error
	gotCode     string
	gotExchVer  string
}

func (f *fakeOIDC) AuthCodeURL(state, nonce, pkceVerifier string) string {
	f.gotState, f.gotNonce, f.gotVerifier = state, nonce, pkceVerifier
	return f.authURL
}

func (f *fakeOIDC) Exchange(_ context.Context, code, verifier string) (OIDCClaims, error) {
	f.gotCode, f.gotExchVer = code, verifier
	if f.exchangeErr != nil {
		return OIDCClaims{}, f.exchangeErr
	}
	return f.claims, nil
}

func newOIDCService(t *testing.T, fake OIDCAuthenticator, cfg *OIDCConfig) (*Service, *stubUserStore) {
	t.Helper()
	svc, store := newTestService(t)
	svc.OIDC = fake
	svc.OIDCConfig = cfg
	return svc, store
}

// signState mints a valid state cookie the callback will accept.
func signState(t *testing.T, svc *Service, state, nonce, verifier string) *http.Cookie {
	t.Helper()
	tok, err := SignToken(svc.Secret, PurposeOIDCState,
		TokenClaims{State: state, Nonce: nonce, Verifier: verifier}, svc.Now().Add(OIDCStateTTL))
	if err != nil {
		t.Fatalf("sign state: %v", err)
	}
	return &http.Cookie{Name: OIDCStateCookie, Value: tok}
}

func hasCookie(cookies []*http.Cookie, name string) (*http.Cookie, bool) {
	for _, c := range cookies {
		if c.Name == name {
			return c, true
		}
	}
	return nil, false
}

func TestOIDCLoginRedirect(t *testing.T) {
	fake := &fakeOIDC{authURL: "https://idp.example.com/authorize?x=1"}
	svc, _ := newOIDCService(t, fake, &OIDCConfig{DisplayName: "SSO"})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login", nil)
	svc.handleOIDCLogin(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != fake.authURL {
		t.Errorf("Location = %q, want %q", loc, fake.authURL)
	}
	c, ok := hasCookie(w.Result().Cookies(), OIDCStateCookie)
	if !ok || c.Value == "" {
		t.Fatal("state cookie not set")
	}
	// The cookie verifies and carries the same state/nonce/verifier the
	// authenticator was handed.
	claims, err := VerifyToken(svc.Secret, svc.Now(), PurposeOIDCState, c.Value)
	if err != nil {
		t.Fatalf("state cookie does not verify: %v", err)
	}
	if claims.State != fake.gotState || claims.Nonce != fake.gotNonce || claims.Verifier != fake.gotVerifier {
		t.Errorf("cookie/authenticator mismatch: cookie=%+v fake state/nonce/ver=%q/%q/%q",
			claims, fake.gotState, fake.gotNonce, fake.gotVerifier)
	}
	if fake.gotState == "" || fake.gotNonce == "" || fake.gotVerifier == "" {
		t.Error("authenticator got empty state/nonce/verifier")
	}
}

func TestOIDCLoginSignError(t *testing.T) {
	fake := &fakeOIDC{authURL: "https://idp/authorize"}
	svc, _ := newOIDCService(t, fake, &OIDCConfig{})
	svc.Secret = nil // SignToken refuses an empty secret

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login", nil)
	svc.handleOIDCLogin(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestOIDCCallbackHappyPath(t *testing.T) {
	fake := &fakeOIDC{claims: OIDCClaims{Username: "alice", Nonce: "nonce-1"}}
	svc, store := newOIDCService(t, fake, &OIDCConfig{})
	hash, _ := HashPassword("correctpassword")
	if _, err := store.Create("alice", hash); err != nil {
		t.Fatalf("seed: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?state=S1&code=auth-code", nil)
	r.AddCookie(signState(t, svc, "S1", "nonce-1", "verifier-1"))
	svc.handleOIDCCallback(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != oidcSuccessRedirect {
		t.Errorf("Location = %q, want %q", loc, oidcSuccessRedirect)
	}
	if fake.gotCode != "auth-code" {
		t.Errorf("exchanged code = %q, want %q", fake.gotCode, "auth-code")
	}
	if fake.gotExchVer != "verifier-1" {
		t.Errorf("exchanged verifier = %q, want %q", fake.gotExchVer, "verifier-1")
	}
	if _, ok := hasCookie(w.Result().Cookies(), CookieName); !ok {
		t.Error("session cookie not issued")
	}
	// The state cookie is cleared (MaxAge < 0).
	if c, ok := hasCookie(w.Result().Cookies(), OIDCStateCookie); !ok || c.MaxAge >= 0 {
		t.Errorf("state cookie not cleared: %+v", c)
	}
}

func TestOIDCCallbackFailures(t *testing.T) {
	tests := []struct {
		name      string
		withState bool // attach a valid state cookie?
		query     string
		nonce     string // cookie nonce (claims nonce is "good")
		claims    OIDCClaims
		exchErr   error
		seedUser  *User
	}{
		{name: "missing state cookie", withState: false, query: "?state=S1&code=c"},
		{name: "state mismatch", withState: true, query: "?state=OTHER&code=c", nonce: "good"},
		{name: "no code", withState: true, query: "?state=S1", nonce: "good"},
		{name: "exchange error", withState: true, query: "?state=S1&code=c", nonce: "good", exchErr: errors.New("boom")},
		{name: "nonce mismatch", withState: true, query: "?state=S1&code=c", nonce: "good", claims: OIDCClaims{Username: "x", Nonce: "bad"}},
		{name: "no username claim", withState: true, query: "?state=S1&code=c", nonce: "good", claims: OIDCClaims{Username: "", Nonce: "good"}},
		{name: "unknown user no provision", withState: true, query: "?state=S1&code=c", nonce: "good", claims: OIDCClaims{Username: "ghost", Nonce: "good"}},
		{name: "disabled user", withState: true, query: "?state=S1&code=c", nonce: "good",
			claims: OIDCClaims{Username: "bob", Nonce: "good"}, seedUser: &User{ID: "bob-id", Username: "bob", Disabled: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := tt.claims
			if claims.Username == "" && tt.name != "no username claim" {
				// Default to a present-but-irrelevant claim for the
				// rows that fail before the username check.
				claims = OIDCClaims{Username: "alice", Nonce: "good"}
			}
			fake := &fakeOIDC{claims: claims, exchangeErr: tt.exchErr}
			svc, store := newOIDCService(t, fake, &OIDCConfig{})
			if tt.seedUser != nil {
				store.put(*tt.seedUser)
			}

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback"+tt.query, nil)
			if tt.withState {
				r.AddCookie(signState(t, svc, "S1", tt.nonce, "verifier-1"))
			}
			svc.handleOIDCCallback(w, r)

			if w.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302", w.Code)
			}
			if loc := w.Header().Get("Location"); loc != oidcErrorRedirect {
				t.Errorf("Location = %q, want %q", loc, oidcErrorRedirect)
			}
			if _, ok := hasCookie(w.Result().Cookies(), CookieName); ok {
				t.Error("session cookie should not be issued on failure")
			}
		})
	}
}

func TestOIDCCallbackExpiredState(t *testing.T) {
	fake := &fakeOIDC{claims: OIDCClaims{Username: "alice", Nonce: "n"}}
	svc, _ := newOIDCService(t, fake, &OIDCConfig{})
	// Sign a state token that is already expired relative to svc.Now().
	tok, err := SignToken(svc.Secret, PurposeOIDCState,
		TokenClaims{State: "S1", Nonce: "n", Verifier: "v"}, svc.Now().Add(-time.Minute))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?state=S1&code=c", nil)
	r.AddCookie(&http.Cookie{Name: OIDCStateCookie, Value: tok})
	svc.handleOIDCCallback(w, r)

	if loc := w.Header().Get("Location"); loc != oidcErrorRedirect {
		t.Errorf("expired state should redirect to error, got %q", loc)
	}
}

func TestOIDCCallbackClearFailuresNonFatal(t *testing.T) {
	// A ClearLoginFailures error is logged but must not fail the login —
	// the cookie is already issued by that point.
	fake := &fakeOIDC{claims: OIDCClaims{Username: "alice", Nonce: "n"}}
	svc, store := newOIDCService(t, fake, &OIDCConfig{})
	hash, _ := HashPassword("correctpassword")
	if _, err := store.Create("alice", hash); err != nil {
		t.Fatalf("seed: %v", err)
	}
	store.failOn = "ClearLoginFailures"
	store.err = errors.New("transient")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?state=S1&code=c", nil)
	r.AddCookie(signState(t, svc, "S1", "n", "v"))
	svc.handleOIDCCallback(w, r)

	if w.Header().Get("Location") != oidcSuccessRedirect {
		t.Errorf("clear-failures error should not block login, got %q", w.Header().Get("Location"))
	}
	if _, ok := hasCookie(w.Result().Cookies(), CookieName); !ok {
		t.Error("session cookie should still be issued")
	}
}

func TestOIDCCallbackProvisionsUser(t *testing.T) {
	fake := &fakeOIDC{claims: OIDCClaims{Username: "newcomer", Email: "n@x.io", Nonce: "n"}}
	svc, store := newOIDCService(t, fake, &OIDCConfig{Provision: true})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?state=S1&code=c", nil)
	r.AddCookie(signState(t, svc, "S1", "n", "v"))
	svc.handleOIDCCallback(w, r)

	if w.Header().Get("Location") != oidcSuccessRedirect {
		t.Fatalf("provision happy path should redirect to %q, got %q", oidcSuccessRedirect, w.Header().Get("Location"))
	}
	if store.count != 1 {
		t.Errorf("store count = %d, want 1 provisioned user", store.count)
	}
	// The provisioned user is created with no roles — RBAC grants are an
	// admin's job afterward. The auth store doesn't track roles, so the
	// contract we assert here is just "created + signed in".
	if _, ok := hasCookie(w.Result().Cookies(), CookieName); !ok {
		t.Error("session cookie not issued for provisioned user")
	}
}

func TestOIDCCallbackProvisionCreateError(t *testing.T) {
	fake := &fakeOIDC{claims: OIDCClaims{Username: "newcomer", Nonce: "n"}}
	svc, store := newOIDCService(t, fake, &OIDCConfig{Provision: true})
	store.failOn = "Create"
	store.err = errors.New("insert failed")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?state=S1&code=c", nil)
	r.AddCookie(signState(t, svc, "S1", "n", "v"))
	svc.handleOIDCCallback(w, r)

	if w.Header().Get("Location") != oidcErrorRedirect {
		t.Errorf("create failure should refuse login, got %q", w.Header().Get("Location"))
	}
}

func TestOIDCCallbackEmptyStateClaim(t *testing.T) {
	// A state cookie that verifies but carries no state/verifier (e.g. a
	// token issued for a different purpose-but-same-shape) is rejected.
	fake := &fakeOIDC{claims: OIDCClaims{Username: "alice", Nonce: "n"}}
	svc, _ := newOIDCService(t, fake, &OIDCConfig{})
	tok, err := SignToken(svc.Secret, PurposeOIDCState, TokenClaims{Nonce: "n"}, svc.Now().Add(OIDCStateTTL))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?state=S1&code=c", nil)
	r.AddCookie(&http.Cookie{Name: OIDCStateCookie, Value: tok})
	svc.handleOIDCCallback(w, r)

	if w.Header().Get("Location") != oidcErrorRedirect {
		t.Errorf("empty-state cookie should redirect to error, got %q", w.Header().Get("Location"))
	}
}

func TestOIDCCallbackLookupError(t *testing.T) {
	fake := &fakeOIDC{claims: OIDCClaims{Username: "alice", Nonce: "n"}}
	svc, store := newOIDCService(t, fake, &OIDCConfig{})
	store.failOn = "GetByUsername"
	store.err = errors.New("db down")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?state=S1&code=c", nil)
	r.AddCookie(signState(t, svc, "S1", "n", "v"))
	svc.handleOIDCCallback(w, r)

	if w.Header().Get("Location") != oidcErrorRedirect {
		t.Errorf("lookup error should redirect to error, got %q", w.Header().Get("Location"))
	}
}

func TestOIDCCallbackSessionError(t *testing.T) {
	fake := &fakeOIDC{claims: OIDCClaims{Username: "alice", Nonce: "n"}}
	svc, store := newOIDCService(t, fake, &OIDCConfig{})
	hash, _ := HashPassword("correctpassword")
	if _, err := store.Create("alice", hash); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// A session store that fails CreateSession makes issueCookie return an
	// error, exercising the callback's session-failure branch.
	svc.Sessions = &stubSessionStore{failOn: "CreateSession", err: errInjected}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?state=S1&code=c", nil)
	r.AddCookie(signState(t, svc, "S1", "n", "v"))
	svc.handleOIDCCallback(w, r)

	if w.Header().Get("Location") != oidcErrorRedirect {
		t.Errorf("session failure should redirect to error, got %q", w.Header().Get("Location"))
	}
	if _, ok := hasCookie(w.Result().Cookies(), CookieName); ok {
		t.Error("session cookie should not be issued when CreateSession fails")
	}
}

func TestRegisterOIDCMountsRoutes(t *testing.T) {
	fake := &fakeOIDC{authURL: "https://idp/authorize"}
	svc, _ := newOIDCService(t, fake, &OIDCConfig{})
	mux := http.NewServeMux()
	svc.RegisterOIDC(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Don't follow the redirect — just confirm the route is mounted.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(srv.URL + "/api/auth/oidc/login")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302 (route mounted)", resp.StatusCode)
	}
}

func TestRegisterOIDCNoopWhenDisabled(t *testing.T) {
	svc, _ := newTestService(t) // no OIDC set
	mux := http.NewServeMux()
	svc.RegisterOIDC(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/api/auth/oidc/login")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (route not registered)", resp.StatusCode)
	}
}

func TestStatusReportsOIDC(t *testing.T) {
	fake := &fakeOIDC{}
	svc, _ := newOIDCService(t, fake, &OIDCConfig{DisplayName: "Acme SSO"})
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/api/auth/status")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body statusResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.OIDCEnabled {
		t.Error("oidcEnabled should be true")
	}
	if body.OIDCDisplayName != "Acme SSO" {
		t.Errorf("oidcDisplayName = %q, want %q", body.OIDCDisplayName, "Acme SSO")
	}
}

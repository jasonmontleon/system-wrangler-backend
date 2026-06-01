// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func makeEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadTrustHeaderConfigDisabled(t *testing.T) {
	cases := map[string]string{
		"empty": "",
		"zero":  "0",
		"false": "false",
		"no":    "no",
		"off":   "off",
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := LoadTrustHeaderConfig(makeEnv(map[string]string{
				envTrustHeaderAuth:  v,
				envTrustHeaderCIDRs: "10.0.0.0/8",
			}))
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if cfg != nil {
				t.Errorf("cfg = %+v, want nil", cfg)
			}
		})
	}
}

func TestLoadTrustHeaderConfigEnabled(t *testing.T) {
	cfg, err := LoadTrustHeaderConfig(makeEnv(map[string]string{
		envTrustHeaderAuth:  "1",
		envTrustHeaderCIDRs: "10.0.0.0/8, 192.168.1.0/24",
	}))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if cfg == nil {
		t.Fatalf("cfg nil, want populated")
	}
	if cfg.HeaderName != defaultTrustHeader {
		t.Errorf("HeaderName = %q, want default %q", cfg.HeaderName, defaultTrustHeader)
	}
	if len(cfg.ProxyCIDRs) != 2 {
		t.Errorf("ProxyCIDRs len = %d, want 2", len(cfg.ProxyCIDRs))
	}
}

func TestLoadTrustHeaderConfigCustomHeader(t *testing.T) {
	cfg, err := LoadTrustHeaderConfig(makeEnv(map[string]string{
		envTrustHeaderAuth:  "true",
		envTrustHeaderName:  " Remote-User ",
		envTrustHeaderCIDRs: "10.0.0.0/8",
	}))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if cfg.HeaderName != "Remote-User" {
		t.Errorf("HeaderName = %q, want trimmed Remote-User", cfg.HeaderName)
	}
}

func TestLoadTrustHeaderConfigRequiresCIDR(t *testing.T) {
	_, err := LoadTrustHeaderConfig(makeEnv(map[string]string{
		envTrustHeaderAuth:  "yes",
		envTrustHeaderCIDRs: "",
	}))
	if err == nil {
		t.Fatal("err = nil, want refusal when CIDR list is empty")
	}
	if !strings.Contains(err.Error(), envTrustHeaderCIDRs) {
		t.Errorf("err = %v, want mention of CIDR env var", err)
	}
}

func TestLoadTrustHeaderConfigInvalidCIDR(t *testing.T) {
	_, err := LoadTrustHeaderConfig(makeEnv(map[string]string{
		envTrustHeaderAuth:  "on",
		envTrustHeaderCIDRs: "not-a-cidr",
	}))
	if err == nil {
		t.Fatal("err = nil, want CIDR parse error")
	}
}

func TestLoadTrustHeaderConfigBlanksDoNotCount(t *testing.T) {
	// Commas with whitespace-only entries should be tolerated; a list
	// that parses to zero CIDRs after trimming must still be refused.
	cfg, err := LoadTrustHeaderConfig(makeEnv(map[string]string{
		envTrustHeaderAuth:  "1",
		envTrustHeaderCIDRs: " , , 10.0.0.0/8 , ",
	}))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(cfg.ProxyCIDRs) != 1 {
		t.Errorf("ProxyCIDRs len = %d, want 1", len(cfg.ProxyCIDRs))
	}

	if _, err := LoadTrustHeaderConfig(makeEnv(map[string]string{
		envTrustHeaderAuth:  "1",
		envTrustHeaderCIDRs: " , , , ",
	})); err == nil {
		t.Fatal("err = nil, want refusal when every CIDR entry was blank")
	}
}

func mustConfig(t *testing.T) *TrustHeaderConfig {
	t.Helper()
	cfg, err := LoadTrustHeaderConfig(makeEnv(map[string]string{
		envTrustHeaderAuth:  "1",
		envTrustHeaderCIDRs: "10.0.0.0/8",
	}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return cfg
}

func TestAllowsRemoteNilConfig(t *testing.T) {
	var c *TrustHeaderConfig
	if c.AllowsRemote("10.0.0.5:1234") {
		t.Error("nil config should never allow")
	}
}

func TestAllowsRemoteWithPort(t *testing.T) {
	c := mustConfig(t)
	if !c.AllowsRemote("10.0.0.5:55123") {
		t.Error("10.0.0.5 should be inside 10.0.0.0/8")
	}
	if c.AllowsRemote("11.0.0.5:55123") {
		t.Error("11.0.0.5 should be outside 10.0.0.0/8")
	}
}

func TestAllowsRemoteWithoutPort(t *testing.T) {
	c := mustConfig(t)
	if !c.AllowsRemote("10.0.0.5") {
		t.Error("10.0.0.5 should be inside the CIDR even without port")
	}
}

func TestAllowsRemoteInvalidIP(t *testing.T) {
	c := mustConfig(t)
	if c.AllowsRemote("not-an-ip") {
		t.Error("unparseable IP must not be allowed")
	}
	if c.AllowsRemote("") {
		t.Error("empty remote must not be allowed")
	}
}

func TestResolveUserSuccess(t *testing.T) {
	store := &stubUserStore{}
	if _, err := store.Create("alice", "h"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	cfg := mustConfig(t)

	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	r.RemoteAddr = "10.0.0.5:55555"
	r.Header.Set(defaultTrustHeader, "alice")

	u, ok := cfg.ResolveUser(r, store)
	if !ok {
		t.Fatal("ok = false, want resolved user")
	}
	if u.Username != "alice" {
		t.Errorf("user = %+v", u)
	}
}

func TestResolveUserUntrustedSource(t *testing.T) {
	store := &stubUserStore{}
	if _, err := store.Create("alice", "h"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	cfg := mustConfig(t)
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = "8.8.8.8:1234"
	r.Header.Set(defaultTrustHeader, "alice")
	if _, ok := cfg.ResolveUser(r, store); ok {
		t.Error("expected refusal from untrusted source")
	}
}

func TestResolveUserHeaderAbsent(t *testing.T) {
	store := &stubUserStore{}
	cfg := mustConfig(t)
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = "10.0.0.5:1234"
	if _, ok := cfg.ResolveUser(r, store); ok {
		t.Error("expected refusal when header is absent")
	}
	r.Header.Set(defaultTrustHeader, "   ")
	if _, ok := cfg.ResolveUser(r, store); ok {
		t.Error("whitespace-only header must not authenticate")
	}
}

func TestResolveUserMissingUser(t *testing.T) {
	store := &stubUserStore{}
	cfg := mustConfig(t)
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = "10.0.0.5:1234"
	r.Header.Set(defaultTrustHeader, "ghost")
	if _, ok := cfg.ResolveUser(r, store); ok {
		t.Error("unknown username should not authenticate")
	}
}

func TestResolveUserDisabledUser(t *testing.T) {
	store := &stubUserStore{}
	if _, err := store.Create("alice", "h"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := store.SetDisabled("alice-id", true, time.Now()); err != nil {
		t.Fatalf("disable: %v", err)
	}
	cfg := mustConfig(t)
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = "10.0.0.5:1234"
	r.Header.Set(defaultTrustHeader, "alice")
	if _, ok := cfg.ResolveUser(r, store); ok {
		t.Error("disabled user must not authenticate via trust header")
	}
}

func TestResolveUserStoreError(t *testing.T) {
	store := &stubUserStore{failOn: "GetByUsername", err: errors.New("db down")}
	cfg := mustConfig(t)
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = "10.0.0.5:1234"
	r.Header.Set(defaultTrustHeader, "alice")
	if _, ok := cfg.ResolveUser(r, store); ok {
		t.Error("store error should not authenticate")
	}
}

func TestResolveUserNilReceiver(t *testing.T) {
	var c *TrustHeaderConfig
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set(defaultTrustHeader, "alice")
	if _, ok := c.ResolveUser(r, &stubUserStore{}); ok {
		t.Error("nil config should never authenticate")
	}
}

func TestResolveUserNilStore(t *testing.T) {
	cfg := mustConfig(t)
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = "10.0.0.5:1234"
	r.Header.Set(defaultTrustHeader, "alice")
	if _, ok := cfg.ResolveUser(r, nil); ok {
		t.Error("nil store should never authenticate")
	}
}

func TestRequireUserAcceptsTrustHeader(t *testing.T) {
	store := &stubUserStore{}
	if _, err := store.Create("alice", "h"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	cfg := mustConfig(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	mw := RequireUser(testSecret, store, func() time.Time { return now }, WithTrustHeader(cfg))

	var seen User
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		u, ok := UserFromContext(r.Context())
		if !ok {
			t.Error("no user in ctx")
		}
		seen = u
	})

	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	r.RemoteAddr = "10.0.0.5:1111"
	r.Header.Set(defaultTrustHeader, "alice")
	w := httptest.NewRecorder()
	mw(next).ServeHTTP(w, r)

	if seen.Username != "alice" {
		t.Errorf("user = %+v", seen)
	}
	if w.Code != http.StatusOK && w.Code != 0 {
		t.Errorf("status = %d, want passthrough", w.Code)
	}
}

func TestRequireUserPrefersTrustHeaderOverBadCookie(t *testing.T) {
	store := &stubUserStore{}
	if _, err := store.Create("alice", "h"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	cfg := mustConfig(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	mw := RequireUser(testSecret, store, func() time.Time { return now }, WithTrustHeader(cfg))

	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = "10.0.0.5:1234"
	r.Header.Set(defaultTrustHeader, "alice")
	r.AddCookie(&http.Cookie{Name: CookieName, Value: "garbage"}) //nolint:gosec
	w := httptest.NewRecorder()
	called := false
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })).ServeHTTP(w, r)

	if !called {
		t.Fatalf("inner handler not called; status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestRequireUserFallsBackToCookieWhenHeaderNotTrusted(t *testing.T) {
	store := &stubUserStore{}
	if _, err := store.Create("alice", "h"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	cfg := mustConfig(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	mw := RequireUser(testSecret, store, func() time.Time { return now }, WithTrustHeader(cfg))

	tok, err := SignSession(testSecret, "alice-id", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	// Untrusted source — the header must be ignored, and the cookie path
	// must take over.
	r.RemoteAddr = "8.8.8.8:1234"
	r.Header.Set(defaultTrustHeader, "spoofed")
	r.AddCookie(&http.Cookie{Name: CookieName, Value: tok}) //nolint:gosec

	var seen User
	mw(http.HandlerFunc(func(_ http.ResponseWriter, rr *http.Request) {
		u, _ := UserFromContext(rr.Context())
		seen = u
	})).ServeHTTP(httptest.NewRecorder(), r)

	if seen.Username != "alice" {
		t.Errorf("user = %+v, want alice from cookie", seen)
	}
}

func TestServiceUserFromCookieHonorsTrustHeader(t *testing.T) {
	store := &stubUserStore{}
	if _, err := store.Create("alice", "h"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	cfg := mustConfig(t)
	s := NewService(store, testSecret, false)
	s.TrustHeader = cfg

	r := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	r.RemoteAddr = "10.0.0.5:1234"
	r.Header.Set(defaultTrustHeader, "alice")
	u, ok := s.userFromCookie(r)
	if !ok {
		t.Fatal("expected user resolved via trust header")
	}
	if u.Username != "alice" {
		t.Errorf("user = %+v", u)
	}
}

func TestServiceStatusReportsTrustHeaderUser(t *testing.T) {
	store := &stubUserStore{}
	if _, err := store.Create("alice", "h"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	cfg := mustConfig(t)
	s := NewService(store, testSecret, false)
	s.TrustHeader = cfg

	mux := http.NewServeMux()
	s.Register(mux)

	r := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	r.RemoteAddr = "10.0.0.5:1234"
	r.Header.Set(defaultTrustHeader, "alice")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"authenticated":true`) {
		t.Errorf("body = %q, want authenticated:true", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"username":"alice"`) {
		t.Errorf("body = %q, want alice", w.Body.String())
	}
}

func TestTruthyEnv(t *testing.T) {
	for _, v := range []string{"1", "true", "TRUE", "Yes", "on", " on "} {
		if !truthyEnv(v) {
			t.Errorf("truthyEnv(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", "0", "no", "false", "off", "maybe"} {
		if truthyEnv(v) {
			t.Errorf("truthyEnv(%q) = true, want false", v)
		}
	}
}

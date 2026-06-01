// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"reflect"
	"strings"
	"testing"
)

// envMap builds a getenv func from a map for table-driven config tests.
func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadOIDCConfigDisabled(t *testing.T) {
	for _, v := range []string{"", "0", "false", "off", "nonsense"} {
		cfg, err := LoadOIDCConfig(envMap(map[string]string{envOIDCEnabled: v}))
		if err != nil {
			t.Errorf("%q: unexpected err %v", v, err)
		}
		if cfg != nil {
			t.Errorf("%q: want nil config when disabled, got %+v", v, cfg)
		}
	}
}

func TestLoadOIDCConfigComplete(t *testing.T) {
	cfg, err := LoadOIDCConfig(envMap(map[string]string{ //nolint:gosec // G101: env-var-name constants as map keys, not credentials
		envOIDCEnabled:      "1",
		envOIDCIssuer:       "https://idp.example.com",
		envOIDCClientID:     "client",
		envOIDCClientSecret: "cs-1",
		envOIDCRedirectURL:  "https://app.example.com/api/auth/oidc/callback",
	}))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if cfg == nil {
		t.Fatal("want config, got nil")
	}
	// Defaults applied.
	if cfg.UsernameClaim != defaultOIDCUsernameClaim {
		t.Errorf("username claim = %q, want default %q", cfg.UsernameClaim, defaultOIDCUsernameClaim)
	}
	if cfg.DefaultRole != defaultOIDCDefaultRole {
		t.Errorf("default role = %q, want %q", cfg.DefaultRole, defaultOIDCDefaultRole)
	}
	if cfg.DisplayName != defaultOIDCDisplayName {
		t.Errorf("display name = %q, want %q", cfg.DisplayName, defaultOIDCDisplayName)
	}
	if cfg.Provision {
		t.Error("provision should default off")
	}
	want := []string{"openid", "profile", "email"}
	if !reflect.DeepEqual(cfg.Scopes, want) {
		t.Errorf("scopes = %v, want %v", cfg.Scopes, want)
	}
}

func TestLoadOIDCConfigOverrides(t *testing.T) {
	cfg, err := LoadOIDCConfig(envMap(map[string]string{ //nolint:gosec // G101: env-var-name constants as map keys, not credentials
		envOIDCEnabled:       "yes",
		envOIDCIssuer:        "https://idp",
		envOIDCClientID:      "c",
		envOIDCClientSecret:  "s",
		envOIDCRedirectURL:   "https://app/cb",
		envOIDCScopes:        "openid groups",
		envOIDCUsernameClaim: "email",
		envOIDCProvision:     "true",
		envOIDCDefaultRole:   "operator",
		envOIDCDisplayName:   "Acme SSO",
	}))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if cfg.UsernameClaim != "email" || cfg.DefaultRole != "operator" || cfg.DisplayName != "Acme SSO" {
		t.Errorf("overrides not applied: %+v", cfg)
	}
	if !cfg.Provision {
		t.Error("provision should be on")
	}
	want := []string{"openid", "groups"}
	if !reflect.DeepEqual(cfg.Scopes, want) {
		t.Errorf("scopes = %v, want %v", cfg.Scopes, want)
	}
}

func TestLoadOIDCConfigMissingFields(t *testing.T) {
	base := map[string]string{ //nolint:gosec // G101: env-var-name constants as map keys, not credentials
		envOIDCEnabled:      "1",
		envOIDCIssuer:       "https://idp",
		envOIDCClientID:     "c",
		envOIDCClientSecret: "s",
		envOIDCRedirectURL:  "https://app/cb",
	}
	for _, drop := range []string{envOIDCIssuer, envOIDCClientID, envOIDCClientSecret, envOIDCRedirectURL} {
		m := make(map[string]string, len(base))
		for k, v := range base {
			m[k] = v
		}
		delete(m, drop)
		cfg, err := LoadOIDCConfig(envMap(m))
		if err == nil {
			t.Errorf("dropping %s: want error, got nil (cfg=%+v)", drop, cfg)
			continue
		}
		if !strings.Contains(err.Error(), drop) {
			t.Errorf("dropping %s: error %q should name the missing var", drop, err)
		}
	}
}

func TestParseScopesAlwaysIncludesOpenID(t *testing.T) {
	tests := []struct {
		raw  string
		want []string
	}{
		{"", []string{"openid", "profile", "email"}},
		{"profile", []string{"openid", "profile"}},
		{"openid email email", []string{"openid", "email"}},
		{"  groups  roles ", []string{"openid", "groups", "roles"}},
	}
	for _, tt := range tests {
		got := parseScopes(tt.raw)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("parseScopes(%q) = %v, want %v", tt.raw, got, tt.want)
		}
	}
}

func TestStringClaim(t *testing.T) {
	claims := map[string]any{
		"preferred_username": "  alice  ",
		"email":              "alice@example.com",
		"count":              42,
	}
	if got := stringClaim(claims, "preferred_username"); got != "alice" {
		t.Errorf("trimmed username = %q, want %q", got, "alice")
	}
	if got := stringClaim(claims, "email"); got != "alice@example.com" {
		t.Errorf("email = %q", got)
	}
	if got := stringClaim(claims, "count"); got != "" {
		t.Errorf("non-string claim = %q, want empty", got)
	}
	if got := stringClaim(claims, "absent"); got != "" {
		t.Errorf("absent claim = %q, want empty", got)
	}
}

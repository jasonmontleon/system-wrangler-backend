// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDC env vars. The master switch defaults to off, matching the
// trust-header mode: an offline install with no IdP must keep working,
// so SSO is opt-in and the local cookie path stays the floor.
const (
	envOIDCEnabled       = "SW_OIDC_ENABLED"
	envOIDCIssuer        = "SW_OIDC_ISSUER"
	envOIDCClientID      = "SW_OIDC_CLIENT_ID"
	envOIDCClientSecret  = "SW_OIDC_CLIENT_SECRET" //nolint:gosec // G101: env var name, not a credential
	envOIDCRedirectURL   = "SW_OIDC_REDIRECT_URL"  //nolint:gosec // G101: env var name, not a credential
	envOIDCScopes        = "SW_OIDC_SCOPES"
	envOIDCUsernameClaim = "SW_OIDC_USERNAME_CLAIM"
	envOIDCProvision     = "SW_OIDC_PROVISION"
	envOIDCDefaultRole   = "SW_OIDC_DEFAULT_ROLE"
	envOIDCDisplayName   = "SW_OIDC_DISPLAY_NAME"

	defaultOIDCScopes        = "openid profile email"
	defaultOIDCUsernameClaim = "preferred_username"
	defaultOIDCDefaultRole   = "auditor"
	defaultOIDCDisplayName   = "SSO"
)

// OIDCConfig is the validated configuration for OpenID Connect single
// sign-on. It is nil when the mode is off. The struct holds only parsed
// scalars; the live provider/verifier objects (which require a network
// round trip to the IdP's discovery endpoint) are constructed separately
// in cmd/server and handed to the Service as an OIDCAuthenticator, so the
// auth package stays free of network dependencies and is unit-testable
// with a fake.
//
// DefaultRole is kept as an opaque string here on purpose: validating it
// against the rbac package would create an import cycle (rbac already
// imports auth), so cmd/server validates it at startup instead.
type OIDCConfig struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	Scopes        []string
	UsernameClaim string
	Provision     bool
	DefaultRole   string
	DisplayName   string
}

// LoadOIDCConfig reads the SW_OIDC_* env vars and returns a validated
// config, or nil when the mode is off. SW_OIDC_ENABLED is the master
// switch (1/true/yes/on enables). When enabled, issuer, client id, client
// secret, and redirect URL are all mandatory — a half-configured SSO is a
// misconfiguration we refuse loudly rather than starting in a broken
// state (mirrors LoadTrustHeaderConfig refusing without a CIDR).
func LoadOIDCConfig(getenv func(string) string) (*OIDCConfig, error) {
	if !truthyEnv(getenv(envOIDCEnabled)) {
		return nil, nil
	}
	cfg := &OIDCConfig{
		Issuer:        strings.TrimSpace(getenv(envOIDCIssuer)),
		ClientID:      strings.TrimSpace(getenv(envOIDCClientID)),
		ClientSecret:  strings.TrimSpace(getenv(envOIDCClientSecret)),
		RedirectURL:   strings.TrimSpace(getenv(envOIDCRedirectURL)),
		UsernameClaim: strings.TrimSpace(getenv(envOIDCUsernameClaim)),
		Provision:     truthyEnv(getenv(envOIDCProvision)),
		DefaultRole:   strings.TrimSpace(getenv(envOIDCDefaultRole)),
		DisplayName:   strings.TrimSpace(getenv(envOIDCDisplayName)),
	}
	missing := make([]string, 0, 4)
	if cfg.Issuer == "" {
		missing = append(missing, envOIDCIssuer)
	}
	if cfg.ClientID == "" {
		missing = append(missing, envOIDCClientID)
	}
	if cfg.ClientSecret == "" {
		missing = append(missing, envOIDCClientSecret)
	}
	if cfg.RedirectURL == "" {
		missing = append(missing, envOIDCRedirectURL)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("auth: %s is set but these are empty: %s",
			envOIDCEnabled, strings.Join(missing, ", "))
	}
	cfg.Scopes = parseScopes(getenv(envOIDCScopes))
	if cfg.UsernameClaim == "" {
		cfg.UsernameClaim = defaultOIDCUsernameClaim
	}
	if cfg.DefaultRole == "" {
		cfg.DefaultRole = defaultOIDCDefaultRole
	}
	if cfg.DisplayName == "" {
		cfg.DisplayName = defaultOIDCDisplayName
	}
	return cfg, nil
}

// parseScopes splits a space-separated scope list, falling back to the
// default ("openid profile email") when unset. "openid" is always
// included since the OIDC flow is meaningless without it.
func parseScopes(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = defaultOIDCScopes
	}
	seen := map[string]struct{}{}
	scopes := make([]string, 0, 4)
	for _, f := range strings.Fields(raw) {
		if _, ok := seen[f]; ok {
			continue
		}
		seen[f] = struct{}{}
		scopes = append(scopes, f)
	}
	if _, ok := seen[oidc.ScopeOpenID]; !ok {
		scopes = append([]string{oidc.ScopeOpenID}, scopes...)
	}
	return scopes
}

// OIDCClaims is the subset of ID-token claims the callback needs: the
// stable subject, the username (from the configured claim), the email,
// and the nonce (compared against the value the login step planted in the
// state cookie).
type OIDCClaims struct {
	Subject  string
	Username string
	Email    string
	Nonce    string
}

// OIDCAuthenticator abstracts the IdP interaction so the HTTP handlers can
// be tested with a fake. The concrete implementation talks to a real
// provider; tests inject a stub that returns canned claims.
type OIDCAuthenticator interface {
	// AuthCodeURL builds the provider's authorization-endpoint URL,
	// binding this request to the given state and nonce. The PKCE
	// verifier is passed in; the S256 challenge sent to the IdP is
	// derived from it here so the verifier never leaves the backend.
	AuthCodeURL(state, nonce, pkceVerifier string) string
	// Exchange swaps an authorization code (with its PKCE verifier) for
	// tokens, verifies the ID token's signature and standard claims, and
	// returns the extracted claim set.
	Exchange(ctx context.Context, code, pkceVerifier string) (OIDCClaims, error)
}

// idTokenVerifier is the slice of *oidc.IDTokenVerifier the authenticator
// uses. Pulled out as an interface so the concrete type's collaborators
// can be faked in isolation if needed.
type idTokenVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)
}

// oidcAuthenticator is the production OIDCAuthenticator: an oauth2 config
// for the redirect + code exchange, plus a go-oidc verifier for the ID
// token, and the name of the claim to treat as the username.
type oidcAuthenticator struct {
	oauth         *oauth2.Config
	verifier      idTokenVerifier
	usernameClaim string
}

// NewOIDCAuthenticator wires a real authenticator from a discovered
// provider. Constructed in cmd/server after oidc.NewProvider succeeds.
func NewOIDCAuthenticator(provider *oidc.Provider, cfg *OIDCConfig) OIDCAuthenticator {
	return &oidcAuthenticator{
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       cfg.Scopes,
		},
		verifier:      provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		usernameClaim: cfg.UsernameClaim,
	}
}

func (a *oidcAuthenticator) AuthCodeURL(state, nonce, pkceVerifier string) string {
	return a.oauth.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(pkceVerifier),
	)
}

// errNoIDToken is returned when the token endpoint's response omits the
// id_token field — a provider that isn't actually doing OIDC.
var errNoIDToken = errors.New("auth: oidc token response had no id_token")

func (a *oidcAuthenticator) Exchange(ctx context.Context, code, pkceVerifier string) (OIDCClaims, error) {
	tok, err := a.oauth.Exchange(ctx, code, oauth2.VerifierOption(pkceVerifier))
	if err != nil {
		return OIDCClaims{}, fmt.Errorf("auth: oidc code exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return OIDCClaims{}, errNoIDToken
	}
	idToken, err := a.verifier.Verify(ctx, rawID)
	if err != nil {
		return OIDCClaims{}, fmt.Errorf("auth: oidc verify id_token: %w", err)
	}
	var raw map[string]any
	if err := idToken.Claims(&raw); err != nil {
		return OIDCClaims{}, fmt.Errorf("auth: oidc decode claims: %w", err)
	}
	return OIDCClaims{
		Subject:  idToken.Subject,
		Username: stringClaim(raw, a.usernameClaim),
		Email:    stringClaim(raw, "email"),
		Nonce:    idToken.Nonce,
	}, nil
}

// stringClaim returns the named claim as a trimmed string, or "" when it's
// absent or not a string. Numbers and other JSON types are deliberately
// ignored — a username/email claim that isn't a string is treated as
// missing rather than coerced.
func stringClaim(claims map[string]any, name string) string {
	if v, ok := claims[name].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

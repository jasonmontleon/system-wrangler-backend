// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// Trust-header auth env vars. The master switch defaults to off so a
// misconfigured deployment cannot be tricked into trusting a header
// it shouldn't.
const (
	envTrustHeaderAuth   = "SW_TRUST_HEADER_AUTH"
	envTrustHeaderName   = "SW_TRUST_HEADER_NAME"
	envTrustHeaderCIDRs  = "SW_TRUST_HEADER_PROXY_CIDRS"
	defaultTrustHeader   = "X-Forwarded-User"
	defaultTrustCIDRList = ""
)

// TrustHeaderConfig configures reverse-proxy trust-header auth mode.
//
// When this mode is on, the backend treats the value of HeaderName as
// the authenticated username for the request — but only when the
// request's remote address is inside one of the ProxyCIDRs. The CIDR
// allowlist is the load-bearing safety check: without it, anyone who
// can reach the backend's port directly could authenticate as anyone
// by setting the header themselves. We refuse startup unless at
// least one CIDR is configured.
//
// Intended for deployments where a trusted upstream proxy (Authelia,
// oauth2-proxy, nginx auth_request, etc.) already authenticates the
// user and stamps the username into the request, stripping any
// caller-supplied copy of the same header.
type TrustHeaderConfig struct {
	HeaderName string
	ProxyCIDRs []*net.IPNet
}

// LoadTrustHeaderConfig reads the trust-header env vars and returns a
// validated config, or nil when the mode is off. SW_TRUST_HEADER_AUTH
// is the master switch (1/true/yes/on enables; anything else
// disables). When enabled, SW_TRUST_HEADER_PROXY_CIDRS must contain
// at least one valid CIDR; the empty string is a misconfiguration we
// refuse loudly rather than silently degrading to "trust anyone."
func LoadTrustHeaderConfig(getenv func(string) string) (*TrustHeaderConfig, error) {
	if !truthyEnv(getenv(envTrustHeaderAuth)) {
		return nil, nil
	}
	name := strings.TrimSpace(getenv(envTrustHeaderName))
	if name == "" {
		name = defaultTrustHeader
	}
	raw := strings.TrimSpace(getenv(envTrustHeaderCIDRs))
	if raw == "" {
		return nil, fmt.Errorf("auth: %s is set but %s is empty — refusing to trust the header from any source",
			envTrustHeaderAuth, envTrustHeaderCIDRs)
	}
	cidrs := make([]*net.IPNet, 0, 4)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("auth: %s: invalid CIDR %q: %w", envTrustHeaderCIDRs, part, err)
		}
		cidrs = append(cidrs, ipnet)
	}
	if len(cidrs) == 0 {
		return nil, errors.New("auth: " + envTrustHeaderCIDRs + " parsed to zero CIDRs")
	}
	return &TrustHeaderConfig{HeaderName: name, ProxyCIDRs: cidrs}, nil
}

// AllowsRemote reports whether the given remote address (in host or
// host:port form) falls inside one of the configured proxy CIDRs.
// A nil config never allows — callers can dispatch on nil without a
// separate guard.
func (c *TrustHeaderConfig) AllowsRemote(remoteAddr string) bool {
	if c == nil {
		return false
	}
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range c.ProxyCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ResolveUser returns the User identified by the trust header on r,
// or ok=false when the request is ineligible for trust-header auth
// (config off, source not in CIDRs, header empty, user unknown, user
// disabled). Callers fall back to whatever other authentication
// mechanism they ordinarily use when ok is false. Nil-safe: a nil
// receiver always returns ok=false.
func (c *TrustHeaderConfig) ResolveUser(r *http.Request, store UserStore) (User, bool) {
	if c == nil || store == nil {
		return User{}, false
	}
	if !c.AllowsRemote(clientIP(r)) {
		return User{}, false
	}
	name := strings.TrimSpace(r.Header.Get(c.HeaderName))
	if name == "" {
		return User{}, false
	}
	u, _, err := store.GetByUsername(name)
	if err != nil {
		return User{}, false
	}
	if u.Disabled {
		return User{}, false
	}
	return u, true
}

// truthyEnv returns true for the common positive values an operator
// might use to flip a boolean env. Anything else (including empty
// string and "0") is false.
func truthyEnv(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

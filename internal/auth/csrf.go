// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"log/slog"
	"net/http"
	"net/url"

	"system-wrangler-backend/internal/audit"
)

// CSRFHeader is the custom header the SPA (and any non-browser
// caller using cookie auth) must include on every mutating
// request. The value is a literal — the defense is that adding a
// non-CORS-safelisted header to a cross-origin fetch forces a
// preflight that this server never approves, so an attacker page
// cannot send a request that satisfies this check. See
// research/csrf.md for the full rationale.
const (
	CSRFHeader      = "X-Sw-Csrf"
	CSRFHeaderValue = "1"
)

// csrfExemptPaths are mutating endpoints that carry no session
// cookie by design (the first-time setup POST, the login POST).
// Anything else is held to both checks.
var csrfExemptPaths = map[string]struct{}{
	"/api/auth/setup": {},
	"/api/auth/login": {},
}

// CSRF returns middleware that enforces the design in
// research/csrf.md. Two layered checks on every mutating method:
// the Origin (or Referer fallback) must match the request Host,
// and the request must carry CSRFHeader=CSRFHeaderValue. Safe
// methods (GET/HEAD/OPTIONS) and exempt paths pass through
// unchanged. Requests that arrive without a session cookie also
// pass through — only cookie-authenticated requests are CSRF
// targets, and a future Bearer-token auth path inherits the
// bypass for free.
//
// auditStore is optional. When non-nil, each denial emits one
// csrf.denied row carrying the Origin, Referer, Host, path,
// method, and a has_header bool. nil disables emission (tests
// and stub callers).
func CSRF(auditStore *audit.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isMutatingMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			if _, exempt := csrfExemptPaths[r.URL.Path]; exempt {
				next.ServeHTTP(w, r)
				return
			}
			if _, err := r.Cookie(CookieName); err != nil {
				// No session cookie — request can't be riding on a
				// browser-attached session, so there's nothing for
				// CSRF to defend. Includes future Bearer-token
				// requests by construction.
				next.ServeHTTP(w, r)
				return
			}
			// Sec-Fetch-Site is a soft assertion. We log when the
			// browser claims something other than same-origin (or
			// "none" for top-level user-initiated navigations) so
			// an operator can see the trail of a future hardening
			// decision, but don't block — older browsers and
			// non-browser clients legitimately omit it.
			if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
				// Header / path are user-controlled; slog's kv form
				// doesn't interpolate them into the message, so
				// gosec G706 is a false positive here.
				slog.Warn("csrf sec-fetch-site mismatch", //nolint:gosec
					"value", sfs, "method", r.Method, "path", r.URL.Path)
			}
			if reason := csrfCheckOrigin(r); reason != "" {
				csrfDeny(auditStore, r, reason)
				writeError(w, http.StatusForbidden, "csrf check failed")
				return
			}
			if r.Header.Get(CSRFHeader) != CSRFHeaderValue {
				csrfDeny(auditStore, r, "header_missing")
				writeError(w, http.StatusForbidden, "csrf check failed")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// isMutatingMethod reports whether m is a method the middleware
// enforces against. HEAD and OPTIONS pass through as safe;
// CONNECT/TRACE aren't served at all, so they aren't enumerated.
func isMutatingMethod(m string) bool {
	switch m {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// csrfCheckOrigin returns "" if Origin (or, in its absence,
// Referer) matches r.Host. Otherwise it returns a short reason
// suitable for the audit row: "origin_mismatch",
// "referer_mismatch", or "origin_and_referer_absent".
func csrfCheckOrigin(r *http.Request) string {
	if o := r.Header.Get("Origin"); o != "" {
		if originMatchesHost(o, r.Host) {
			return ""
		}
		return "origin_mismatch"
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		if originMatchesHost(ref, r.Host) {
			return ""
		}
		return "referer_mismatch"
	}
	return "origin_and_referer_absent"
}

// originMatchesHost parses originOrRef as a URL and compares its
// Host with the request Host. A non-URL string never matches.
// Port-sensitive: "sw.local:8080" and "sw.local:443" are
// different origins per the same-origin policy.
func originMatchesHost(originOrRef, host string) bool {
	u, err := url.Parse(originOrRef)
	if err != nil {
		return false
	}
	return u.Host == host
}

// csrfDeny writes one csrf.denied audit row describing the
// rejection. nil auditStore is a no-op so tests don't need to
// stand one up.
func csrfDeny(auditStore *audit.Store, r *http.Request, reason string) {
	if auditStore == nil {
		return
	}
	d := audit.NewDetail()
	_ = d.SetSafe("reason", reason)
	_ = d.SetSafe("origin", r.Header.Get("Origin"))
	_ = d.SetSafe("referer", r.Header.Get("Referer"))
	_ = d.SetSafe("host", r.Host)
	_ = d.SetSafe("path", r.URL.Path)
	_ = d.SetSafe("method", r.Method)
	_ = d.SetSafe("has_header", r.Header.Get(CSRFHeader) == CSRFHeaderValue)
	if err := auditStore.Log(r.Context(), audit.Event{
		Action:      "csrf.denied",
		Outcome:     audit.Denied,
		TargetKind:  "http",
		TargetLabel: r.Method + " " + r.URL.Path,
		Detail:      d,
	}); err != nil {
		slog.Error("csrf audit", "err", err)
	}
}

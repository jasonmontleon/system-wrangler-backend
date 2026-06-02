// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"

	"golang.org/x/oauth2"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/router"
)

// oidcCallbackPath is where a failed SSO flow sends the browser. The SPA
// reads the error query param and shows a banner; success redirects to the
// app root instead.
const (
	oidcSuccessRedirect = "/"
	oidcErrorRedirect   = "/?error=oidc"
)

// RegisterOIDC attaches the two unauthenticated SSO routes. Both are GET
// because they're reached by a full browser navigation / IdP redirect, not
// an XHR. No-op when OIDC is off, so cmd/server can call it
// unconditionally.
func (s *Service) RegisterOIDC(mux router.Mux) {
	if s.OIDC == nil {
		return
	}
	mux.Handle("GET /api/auth/oidc/login", http.HandlerFunc(s.handleOIDCLogin))
	mux.Handle("GET /api/auth/oidc/callback", http.HandlerFunc(s.handleOIDCCallback))
}

// handleOIDCLogin starts the authorization-code-with-PKCE flow: it mints a
// random state + nonce + PKCE verifier, stashes all three in a short-lived
// signed cookie, and redirects the browser to the IdP. The cookie is the
// only server-side state — there is no pending-login table — so the
// callback is stateless beyond verifying this cookie.
func (s *Service) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	// state and nonce are opaque per-login randoms; s.NewID (a UUID in
	// production) is the same injectable randomness seam the TOTP
	// challenge cookie uses. The PKCE verifier comes from oauth2's helper.
	state := s.NewID()
	nonce := s.NewID()
	verifier := oauth2.GenerateVerifier()
	exp := s.Now().Add(OIDCStateTTL)
	tok, err := SignToken(s.Secret, PurposeOIDCState,
		TokenClaims{State: state, Nonce: nonce, Verifier: verifier}, exp)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "sso unavailable")
		slog.Error("auth oidc state sign", "err", err)
		return
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is set from s.SecureCookie at runtime; gosec only recognises a literal true.
		Name:     OIDCStateCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.SecureCookie,
		SameSite: http.SameSiteLaxMode,
		Expires:  exp,
		MaxAge:   int(OIDCStateTTL.Seconds()),
	})
	http.Redirect(w, r, s.OIDC.AuthCodeURL(state, nonce, verifier), http.StatusFound)
}

// handleOIDCCallback completes the flow. Every failure path clears the
// state cookie and bounces the browser to the SPA's error redirect rather
// than rendering JSON, since the user got here by a redirect and expects
// to land back in the app.
func (s *Service) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.readOIDCState(r)
	if !ok {
		s.failOIDC(w, r, "missing or invalid state")
		return
	}
	s.clearOIDCStateCookie(w)
	// Constant-time compare of the round-tripped state against the cookie:
	// the CSRF guard for the redirect flow.
	got := r.URL.Query().Get("state")
	if subtle.ConstantTimeCompare([]byte(got), []byte(claims.State)) != 1 {
		s.failOIDC(w, r, "state mismatch")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		s.failOIDC(w, r, "no authorization code")
		return
	}
	idc, err := s.OIDC.Exchange(r.Context(), code, claims.Verifier)
	if err != nil {
		s.failOIDC(w, r, "code exchange failed")
		slog.Warn("auth oidc exchange", "err", err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(idc.Nonce), []byte(claims.Nonce)) != 1 {
		s.failOIDC(w, r, "nonce mismatch")
		return
	}
	if idc.Username == "" {
		s.failOIDC(w, r, "id token had no username claim")
		return
	}
	u, ok := s.resolveOIDCUser(r, idc)
	if !ok {
		s.failOIDC(w, r, "user resolution failed")
		return
	}
	if err := s.issueCookie(w, r, u.ID); err != nil {
		s.failOIDC(w, r, "session failed")
		slog.Error("auth oidc cookie", "err", err)
		return
	}
	if err := s.Store.ClearLoginFailures(u.ID); err != nil {
		slog.Warn("auth oidc clear failures", "err", err, "user_id", u.ID)
	}
	s.logLoginSuccess(r, u, "oidc")
	http.Redirect(w, r, oidcSuccessRedirect, http.StatusFound)
}

// resolveOIDCUser maps the verified ID-token claims to a local account:
// look up by the username claim, and either provision a new row (when
// SW_OIDC_PROVISION is on) or refuse an unknown user. A disabled account
// is always refused.
func (s *Service) resolveOIDCUser(r *http.Request, idc OIDCClaims) (User, bool) {
	u, _, err := s.Store.GetByUsername(idc.Username)
	if err == nil {
		if u.Disabled {
			s.logLoginFailed(r.Context(), idc.Username, "disabled")
			return User{}, false
		}
		return u, true
	}
	if !errors.Is(err, ErrUserNotFound) {
		slog.Error("auth oidc lookup", "err", err)
		return User{}, false
	}
	if s.OIDCConfig == nil || !s.OIDCConfig.Provision {
		s.logLoginFailed(r.Context(), idc.Username, "oidc_no_provision")
		return User{}, false
	}
	return s.provisionOIDCUser(r, idc)
}

// provisionOIDCUser creates a password-less local account for a
// first-time SSO user. The account gets a bcrypt hash of random bytes so
// the column's NOT NULL holds and no password can ever verify (an admin
// password-reset can later set a real one). It is created with NO roles —
// exactly like an admin-created user — so it can authenticate but can't
// see or do anything privileged until an admin grants a role.
func (s *Service) provisionOIDCUser(r *http.Request, idc OIDCClaims) (User, bool) {
	hash, err := HashPassword(s.NewID())
	if err != nil {
		slog.Error("auth oidc provision hash", "err", err)
		return User{}, false
	}
	u, err := s.Store.Create(idc.Username, hash)
	if err != nil {
		slog.Error("auth oidc provision create", "err", err)
		return User{}, false
	}
	d := audit.NewDetail()
	_ = d.SetSafe("source", "oidc")
	s.logAudit(r.Context(), audit.Event{
		Action:      "user.create",
		Outcome:     audit.Success,
		TargetKind:  "user",
		TargetID:    u.ID,
		TargetLabel: u.Username,
		Detail:      d,
	})
	return u, true
}

// logLoginSuccess emits auth.login with the actor stamped onto the
// context, mirroring finishLogin's audit shape for the redirect-based SSO
// path (which can't reuse finishLogin since that writes JSON).
func (s *Service) logLoginSuccess(r *http.Request, u User, method string) {
	ctx := audit.WithActor(r.Context(), audit.Actor{
		Kind:  audit.ActorUser,
		ID:    u.ID,
		Label: u.Username,
	})
	d := audit.NewDetail()
	_ = d.SetSafe("method", method)
	s.logAudit(ctx, audit.Event{
		Action:      "auth.login",
		Outcome:     audit.Success,
		TargetKind:  "user",
		TargetID:    u.ID,
		TargetLabel: u.Username,
		Detail:      d,
	})
}

// readOIDCState pulls and verifies the signed state cookie.
func (s *Service) readOIDCState(r *http.Request) (TokenClaims, bool) {
	c, err := r.Cookie(OIDCStateCookie)
	if err != nil {
		return TokenClaims{}, false
	}
	claims, err := VerifyToken(s.Secret, s.Now(), PurposeOIDCState, c.Value)
	if err != nil {
		return TokenClaims{}, false
	}
	if claims.State == "" || claims.Verifier == "" {
		return TokenClaims{}, false
	}
	return claims, true
}

// failOIDC records the failed attempt and redirects to the SPA's error
// landing. reason is the audit reason, not shown to the user.
func (s *Service) failOIDC(w http.ResponseWriter, r *http.Request, reason string) {
	s.clearOIDCStateCookie(w)
	s.logLoginFailed(r.Context(), "", "oidc:"+reason)
	http.Redirect(w, r, oidcErrorRedirect, http.StatusFound)
}

func (s *Service) clearOIDCStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is set from s.SecureCookie at runtime; gosec only recognises a literal true.
		Name:     OIDCStateCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.SecureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

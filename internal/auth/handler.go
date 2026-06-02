// SPDX-License-Identifier: Apache-2.0

// Package auth implements local-account authentication: bcrypt password
// hashing, HMAC-signed session cookies, optional TOTP second factor with
// recovery codes and a "remember this browser" trusted-device cookie, and
// the HTTP handlers for setup, login, logout, profile, and password change.
package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/router"
	"system-wrangler-backend/internal/secrets"
)

// Service holds the shared state used by the auth HTTP endpoints. The TOTP-,
// Recovery-, and Device- stores plus Vault are optional: when nil, login
// skips the second-factor flow entirely (used by older tests and by stub
// callers). Production wiring in cmd/server/main.go always supplies all of
// them.
type Service struct {
	Store         UserStore
	TOTPStore     TOTPStore
	RecoveryStore RecoveryStore
	DeviceStore   DeviceStore
	Secret        []byte
	Vault         *secrets.Vault
	// Audit is optional: when nil, handlers skip audit emission (older
	// tests and stub callers run without it). Production wiring in
	// cmd/server/main.go always supplies it.
	Audit *audit.Store
	// DB is the shared SQLite handle. When set alongside Audit, the
	// password-change and TOTP handlers wrap the user-row mutation and
	// the matching audit_log row in one transaction so the two cannot
	// diverge on a crash. Tests with stub stores leave it nil and fall
	// back to the non-transactional path.
	DB *sql.DB
	// LoginThrottle is the per-IP rate limiter applied to /login and
	// /totp/verify. nil disables the per-IP layer entirely (the
	// per-account lockout still runs).
	LoginThrottle *Throttle
	// TrustHeader, when non-nil, enables reverse-proxy trust-header
	// auth: /api/auth/status will report a header-identified user as
	// authenticated, and /api/auth/logout will attribute the audit
	// row to that user. The RequireUser middleware in main.go is
	// configured with the same value so cookieless API requests from
	// the proxy also resolve to a user.
	TrustHeader *TrustHeaderConfig
	// Sessions, when non-nil, makes login persist a server-side session
	// row whose id is embedded in the cookie's sid claim, so the session
	// can be revoked. Logout deletes the current row, change-password
	// revokes the others, and the /api/auth/sessions endpoints let a
	// user list and revoke their own. nil keeps the original stateless
	// cookie behavior (used by older tests and stub callers).
	Sessions SessionStore
	// OIDC, when non-nil, enables OpenID Connect single sign-on: the
	// /api/auth/oidc/{login,callback} routes are served, and
	// /api/auth/status advertises the mode so the SPA can render a
	// "Sign in with …" button. nil leaves SSO off (the default), and the
	// local cookie path remains the only way in.
	OIDC OIDCAuthenticator
	// OIDCConfig carries the parsed SSO settings (username claim,
	// provisioning policy, display name). Non-nil whenever OIDC is.
	OIDCConfig   *OIDCConfig
	SessionTTL   time.Duration
	SecureCookie bool
	Now          func() time.Time
	NewID        func() string
}

// Lockout policy constants. After LockoutThreshold consecutive failed
// auth attempts the account is locked for a duration that doubles each
// further failure, capped at LockoutMaxDuration. Counters reset on any
// successful authentication or any admin-initiated reset.
const (
	LockoutThreshold    = 5
	LockoutBaseDuration = 1 * time.Minute
	LockoutMaxDuration  = 15 * time.Minute
)

// lockDuration returns how long an account that has just had its
// `attempts`-th consecutive failure should be locked, or zero if it's
// still below the threshold. The shift is bounded so callers that pass
// a huge attempts value (e.g. someone hammering after the cap) don't
// trigger an integer overflow.
func lockDuration(attempts int) time.Duration {
	if attempts < LockoutThreshold {
		return 0
	}
	shift := uint(attempts - LockoutThreshold)
	if shift > 8 {
		shift = 8
	}
	dur := LockoutBaseDuration << shift
	if dur > LockoutMaxDuration {
		dur = LockoutMaxDuration
	}
	return dur
}

// throttleAllow checks the per-IP throttle and writes a 429 with
// Retry-After if exceeded. Returns true if the caller can proceed.
// Safe with a nil throttle.
func (s *Service) throttleAllow(w http.ResponseWriter, r *http.Request) bool {
	if s.LoginThrottle == nil {
		return true
	}
	wait := s.LoginThrottle.Check(clientIP(r))
	if wait <= 0 {
		return true
	}
	secs := int(wait.Seconds())
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeError(w, http.StatusTooManyRequests, "too many attempts, try again later")
	return false
}

// recordLoginFailure handles both halves of a failed-credential event:
// the per-IP throttle gets a tick (so a single source can be quenched
// even if it spreads across accounts), and the per-account counter on
// the user row bumps. user may be the zero value for "no such user" —
// in that case only the throttle is touched.
func (s *Service) recordLoginFailure(r *http.Request, user User) {
	if s.LoginThrottle != nil {
		s.LoginThrottle.Record(clientIP(r))
	}
	if user.ID == "" {
		return
	}
	attempts := user.FailedAttempts + 1
	var locked *time.Time
	if dur := lockDuration(attempts); dur > 0 {
		t := s.Now().Add(dur).UTC()
		locked = &t
	}
	if _, err := s.Store.RecordLoginFailure(user.ID, locked); err != nil {
		slog.Error("auth record failure", "err", err, "user_id", user.ID)
	}
	if locked != nil {
		d := audit.NewDetail()
		_ = d.SetSafe("attempts", attempts)
		_ = d.SetSafe("locked_until", locked.Format(time.RFC3339))
		s.logAudit(r.Context(), audit.Event{
			Action:      "auth.account.locked",
			Outcome:     audit.Success,
			TargetKind:  "user",
			TargetID:    user.ID,
			TargetLabel: user.Username,
			Detail:      d,
		})
	}
}

// NewService fills in sensible defaults; callers can still override fields
// directly after construction.
func NewService(store UserStore, secret []byte, secureCookie bool) *Service {
	return &Service{
		Store:        store,
		Secret:       secret,
		SessionTTL:   DefaultSessionTTL,
		SecureCookie: secureCookie,
		Now:          time.Now,
		NewID:        func() string { return uuid.NewString() },
	}
}

// Register attaches the unauthenticated auth endpoints (status, setup,
// login, logout) to mux.
func (s *Service) Register(mux router.Mux) {
	mux.Handle("GET /api/auth/status", http.HandlerFunc(s.handleStatus))
	mux.Handle("POST /api/auth/setup", http.HandlerFunc(s.handleSetup))
	mux.Handle("POST /api/auth/login", http.HandlerFunc(s.handleLogin))
	mux.Handle("POST /api/auth/logout", http.HandlerFunc(s.handleLogout))
}

// RegisterProtected wires the endpoints that require an authenticated user.
// The middleware is supplied by the caller so the auth package doesn't need
// to construct it itself. Every protected endpoint except the password
// change is wrapped with RequireFreshPassword so a user with the
// must_change_password flag set is bounced until they rotate the
// admin-supplied password.
func (s *Service) RegisterProtected(mux router.Mux, requireUser func(http.Handler) http.Handler) {
	fresh := func(h http.Handler) http.Handler { return requireUser(RequireFreshPassword(h)) }
	mux.Handle("PATCH /api/auth/profile", fresh(http.HandlerFunc(s.handleUpdateProfile)))
	mux.Handle("POST /api/auth/password", requireUser(http.HandlerFunc(s.handleChangePassword)))
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type statusResponse struct {
	SetupRequired bool  `json:"setupRequired"`
	Authenticated bool  `json:"authenticated"`
	User          *User `json:"user,omitempty"`
	// OIDCEnabled tells the SPA to render the SSO sign-in button;
	// OIDCDisplayName is the provider label shown on it ("Sign in with
	// {name}"). Omitted from the wire when SSO is off.
	OIDCEnabled     bool   `json:"oidcEnabled,omitempty"`
	OIDCDisplayName string `json:"oidcDisplayName,omitempty"`
}

// logAudit is the nil-safe shim every handler calls instead of touching
// s.Audit directly. Audit emission failures are logged but never block
// the user-facing response — losing one audit row is preferable to
// breaking login when SQLite hiccups, and the request-log middleware
// still records the request.
func (s *Service) logAudit(ctx context.Context, e audit.Event) {
	if s.Audit == nil {
		return
	}
	if err := s.Audit.Log(ctx, e); err != nil {
		slog.Error("auth audit log", "err", err, "action", e.Action)
	}
}

// logLoginFailed emits auth.login.failed with attempted_username and the
// reason ("no_user" or "wrong_password"). The actor stays
// Unauthenticated because the user has not been resolved.
func (s *Service) logLoginFailed(ctx context.Context, attemptedUsername, reason string) {
	d := audit.NewDetail()
	_ = d.SetSafe("attempted_username", attemptedUsername)
	_ = d.SetSafe("reason", reason)
	s.logAudit(ctx, audit.Event{
		Action:  "auth.login.failed",
		Outcome: audit.Failure,
		Detail:  d,
	})
}

// finishLogin issues the session cookie, emits auth.login, and writes the
// user JSON. Used by every successful first-factor path so the audit
// emission can't drift between branches. method is "password",
// "trusted_device", or "totp" depending on which path completed.
// Successful login also clears the per-account lockout counters — by
// the time we reach this function the user has proven they're the
// account holder, so any stale failure history is meaningless.
func (s *Service) finishLogin(w http.ResponseWriter, r *http.Request, u User, method string) {
	if err := s.issueCookie(w, r, u.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "session failed")
		slog.Error("auth login cookie", "err", err)
		return
	}
	if err := s.Store.ClearLoginFailures(u.ID); err != nil {
		slog.Warn("auth clear failures", "err", err, "user_id", u.ID)
	}
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
	writeJSON(w, http.StatusOK, u)
}

func (s *Service) handleStatus(w http.ResponseWriter, r *http.Request) {
	count, err := s.Store.Count()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "status failed")
		slog.Error("auth status count", "err", err)
		return
	}
	resp := statusResponse{SetupRequired: count == 0}
	if s.OIDC != nil {
		resp.OIDCEnabled = true
		if s.OIDCConfig != nil {
			resp.OIDCDisplayName = s.OIDCConfig.DisplayName
		}
	}
	if u, ok := s.userFromCookie(r); ok {
		resp.Authenticated = true
		resp.User = &u
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Service) handleSetup(w http.ResponseWriter, r *http.Request) {
	count, err := s.Store.Count()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "setup failed")
		slog.Error("auth setup count", "err", err)
		return
	}
	if count > 0 {
		writeError(w, http.StatusForbidden, "setup already complete")
		return
	}
	creds, err := decodeCredentials(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := HashPassword(creds.Password)
	if err != nil {
		if errors.Is(err, ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "hash failed")
		slog.Error("auth setup hash", "err", err)
		return
	}
	u, err := s.Store.Create(creds.Username, hash)
	if err != nil {
		if errors.Is(err, ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		// ErrUserExists shouldn't happen — count was zero — but cover it.
		writeError(w, http.StatusInternalServerError, "create user failed")
		slog.Error("auth setup create", "err", err)
		return
	}
	if err := s.issueCookie(w, r, u.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "session failed")
		slog.Error("auth setup cookie", "err", err)
		return
	}
	// Setup is unauthenticated by definition (count was zero before this
	// request), so the actor on the audit row is the user that just got
	// created — they are the only user in existence. Same shape as
	// auth.login for consistency.
	ctx := audit.WithActor(r.Context(), audit.Actor{
		Kind:  audit.ActorUser,
		ID:    u.ID,
		Label: u.Username,
	})
	s.logAudit(ctx, audit.Event{
		Action:      "auth.setup",
		Outcome:     audit.Success,
		TargetKind:  "user",
		TargetID:    u.ID,
		TargetLabel: u.Username,
	})
	writeJSON(w, http.StatusCreated, u)
}

func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.throttleAllow(w, r) {
		return
	}
	creds, err := decodeCredentials(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	u, hash, err := s.Store.GetByUsername(creds.Username)
	if err != nil {
		// Don't disclose whether the username exists — return 401 in both
		// the "no such user" and "wrong password" branches.
		if errors.Is(err, ErrUserNotFound) {
			// No per-account row to bump, but a spray attack across many
			// usernames still trips the per-IP throttle.
			s.recordLoginFailure(r, User{})
			s.logLoginFailed(r.Context(), creds.Username, "no_user")
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		writeError(w, http.StatusInternalServerError, "login failed")
		slog.Error("auth login lookup", "err", err)
		return
	}
	// Capture the lockout state observed at lookup time so we can
	// reveal it *after* the password check succeeds — the conditional
	// reveal pattern means a wrong password on a locked account stays
	// opaque (no enumeration), but a user who types the right password
	// gets a useful "locked until X" message. VerifyPassword is run
	// unconditionally because skipping it on a locked account would
	// short-circuit the only branch where reveal is safe.
	wasLocked := u.LockedUntil != nil && s.Now().Before(*u.LockedUntil)
	if err := VerifyPassword(hash, creds.Password); err != nil {
		if wasLocked {
			// Don't bump the per-account counter on an already-locked
			// account — the lockout is the whole point. The per-IP
			// throttle still ticks so a spraying source gets quenched.
			if s.LoginThrottle != nil {
				s.LoginThrottle.Record(clientIP(r))
			}
		} else {
			s.recordLoginFailure(r, u)
		}
		s.logLoginFailed(r.Context(), creds.Username, "wrong_password")
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if wasLocked {
		// Password was correct but the account is still in the
		// lockout window. The user has proven account ownership, so
		// revealing the lock state leaks nothing they couldn't see by
		// waiting it out — and tells them when to try again. No
		// session cookie issued.
		s.logLoginFailed(r.Context(), creds.Username, "locked")
		writeLockedResponse(w, *u.LockedUntil)
		return
	}
	if u.Disabled {
		s.logLoginFailed(r.Context(), creds.Username, "disabled")
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	// If TOTP isn't wired (older tests, minimal callers) skip the second
	// factor entirely and behave like the original single-step flow.
	if s.TOTPStore == nil {
		s.finishLogin(w, r, u, "password")
		return
	}
	state, err := s.TOTPStore.GetTOTPState(u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "login failed")
		slog.Error("auth login totp state", "err", err, "user_id", u.ID)
		return
	}
	if !state.Enabled {
		s.finishLogin(w, r, u, "password")
		return
	}
	// TOTP enabled. If the request carries a valid trusted-device cookie
	// whose epoch matches the user's current epoch, skip the second factor.
	if s.honorTrustedDevice(r, u.ID, state.Epoch) {
		s.finishLogin(w, r, u, "trusted_device")
		return
	}
	// Otherwise issue a short-lived challenge cookie and return totpRequired.
	if err := s.issueChallengeCookie(w, u.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "challenge failed")
		slog.Error("auth login challenge", "err", err, "user_id", u.ID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"totpRequired": true})
}

// honorTrustedDevice returns true iff the request carries a trusted-device
// cookie that verifies (signed, not expired) AND points at a row whose
// user/epoch match AND has not itself expired. On success, last_used_at is
// touched so the device list reflects the activity.
func (s *Service) honorTrustedDevice(r *http.Request, userID string, currentEpoch int64) bool {
	if s.DeviceStore == nil {
		return false
	}
	c, err := r.Cookie(TrustedDeviceCookie)
	if err != nil {
		return false
	}
	claims, err := VerifyToken(s.Secret, s.Now(), PurposeTrustedDevice, c.Value)
	if err != nil {
		return false
	}
	if claims.UID != userID {
		return false
	}
	if claims.Epoch != currentEpoch {
		return false
	}
	d, err := s.DeviceStore.GetDevice(claims.DeviceID)
	if err != nil {
		return false
	}
	if d.UserID != userID || d.TOTPEpoch != currentEpoch {
		return false
	}
	if !s.Now().Before(d.ExpiresAt) {
		return false
	}
	if err := s.DeviceStore.TouchDevice(d.ID, s.Now()); err != nil {
		// Touch failure is logged but doesn't fail the trust — the cookie
		// is still valid, the row just won't reflect this use.
		slog.Warn("auth touch device", "err", err, "device_id", d.ID)
	}
	return true
}

// issueChallengeCookie writes a short-lived signed cookie that binds the
// second-factor request to this user. The nonce is currently informational
// (logged on issue, ignored on verify) — included so the cookie isn't
// trivially identical for the same user across logins.
func (s *Service) issueChallengeCookie(w http.ResponseWriter, userID string) error {
	exp := s.Now().Add(TOTPChallengeTTL)
	tok, err := SignToken(s.Secret, PurposeTOTPChallenge,
		TokenClaims{UID: userID, Nonce: s.NewID()}, exp)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is set from s.SecureCookie at runtime; gosec only recognises a literal true.
		Name:     TOTPChallengeCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.SecureCookie,
		SameSite: http.SameSiteLaxMode,
		Expires:  exp,
		MaxAge:   int(TOTPChallengeTTL.Seconds()),
	})
	return nil
}

// clearChallengeCookie deletes the challenge cookie. Always called on a
// failed verify so a poisoned cookie can't wedge the user, and on success
// once the real session cookie has been issued.
func (s *Service) clearChallengeCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is set from s.SecureCookie at runtime; gosec only recognises a literal true.
		Name:     TOTPChallengeCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.SecureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// issueTrustedDeviceCookie writes a 30-day signed cookie referencing a
// trusted-devices row. Caller must have inserted the row first.
func (s *Service) issueTrustedDeviceCookie(w http.ResponseWriter, deviceID, userID string, epoch int64) error {
	exp := s.Now().Add(TrustedDeviceTTL)
	tok, err := SignToken(s.Secret, PurposeTrustedDevice,
		TokenClaims{UID: userID, DeviceID: deviceID, Epoch: epoch}, exp)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is set from s.SecureCookie at runtime; gosec only recognises a literal true.
		Name:     TrustedDeviceCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.SecureCookie,
		SameSite: http.SameSiteLaxMode,
		Expires:  exp,
		MaxAge:   int(TrustedDeviceTTL.Seconds()),
	})
	return nil
}

// clearTrustedDeviceCookie deletes the long-lived trust cookie. Used by
// the disable-TOTP flow alongside the row-level wipe in DisableTOTP.
func (s *Service) clearTrustedDeviceCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is set from s.SecureCookie at runtime; gosec only recognises a literal true.
		Name:     TrustedDeviceCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.SecureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Resolve the user from the session cookie before clearing it so the
	// audit row has a real actor; a logout with no cookie still succeeds
	// (idempotent), it just emits an unauthenticated row.
	u, hadSession := s.userFromCookie(r)
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is set from s.SecureCookie at runtime; gosec only recognises a literal true.
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.SecureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	// Clear the challenge cookie too so a partial-login state doesn't survive
	// a logout. The trusted-device cookie is *not* cleared here — that's the
	// whole point of "remember this browser": survives logout/login.
	s.clearChallengeCookie(w)
	// Delete the server-side session row so a captured cookie can't be
	// replayed after logout. Best-effort: the cookie is already cleared,
	// and the next request with a stale cookie fails the live-session
	// check anyway.
	if hadSession && s.Sessions != nil {
		if sid := s.currentSessionID(r); sid != "" {
			if err := s.Sessions.RevokeSession(sid, u.ID); err != nil && !errors.Is(err, ErrSessionNotFound) {
				slog.Warn("auth logout revoke session", "err", err, "user_id", u.ID)
			}
		}
	}
	if hadSession {
		ctx := audit.WithActor(r.Context(), audit.Actor{
			Kind:  audit.ActorUser,
			ID:    u.ID,
			Label: u.Username,
		})
		s.logAudit(ctx, audit.Event{
			Action:      "auth.logout",
			Outcome:     audit.Success,
			TargetKind:  "user",
			TargetID:    u.ID,
			TargetLabel: u.Username,
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

type profileRequest struct {
	Email string `json:"email"`
	Theme string `json:"theme"`
}

func (s *Service) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	u, ok := UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req profileRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if !ValidTheme(req.Theme) {
		writeError(w, http.StatusBadRequest, "invalid theme")
		return
	}
	updated, err := s.Store.UpdateProfile(u.ID, req.Email, req.Theme)
	if err != nil {
		if errors.Is(err, ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "update failed")
		slog.Error("auth update profile", "err", err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

type passwordChangeRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

func (s *Service) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	u, ok := UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req passwordChangeRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "current and new password required")
		return
	}
	hash, err := s.Store.GetHashByID(u.ID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		writeError(w, http.StatusInternalServerError, "password change failed")
		slog.Error("auth change password load", "err", err)
		return
	}
	if err := VerifyPassword(hash, req.CurrentPassword); err != nil {
		writeError(w, http.StatusUnauthorized, "current password incorrect")
		return
	}
	newHash, err := HashPassword(req.NewPassword)
	if err != nil {
		if errors.Is(err, ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "hash failed")
		slog.Error("auth change password hash", "err", err)
		return
	}
	if err := s.changePasswordWithAudit(r.Context(), u, newHash); err != nil {
		writeError(w, http.StatusInternalServerError, "password change failed")
		slog.Error("auth change password update", "err", err)
		return
	}
	// Changing the password signs out every other session — the classic
	// "I think someone has my old password" remediation. The session this
	// request rode in on is kept so the user isn't bounced mid-flow.
	// Best-effort: the password is already changed; a revoke failure
	// shouldn't surface as a 500.
	if s.Sessions != nil {
		if _, err := s.Sessions.RevokeOtherUserSessions(u.ID, s.currentSessionID(r)); err != nil {
			slog.Warn("auth change password revoke others", "err", err, "user_id", u.ID)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// changePasswordWithAudit applies the new hash and writes
// `auth.password.change` in one transaction. The audit row is only
// emitted when DB + Audit are both wired — tests using stub stores
// still update the password but skip the audit row, matching the prior
// behavior.
func (s *Service) changePasswordWithAudit(ctx context.Context, u User, newHash string) error {
	if s.DB == nil || s.Audit == nil {
		return s.Store.UpdatePassword(u.ID, newHash)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.Store.UpdatePasswordTx(tx, u.ID, newHash); err != nil {
		return err
	}
	if err := s.Audit.LogTx(ctx, tx, audit.Event{
		Action:      "auth.password.change",
		Outcome:     audit.Success,
		TargetKind:  "user",
		TargetID:    u.ID,
		TargetLabel: u.Username,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// userFromCookie resolves the request's user from either the
// trust-header (when configured and the request is from a trusted
// proxy) or the session cookie, in that order. Trust-header wins so
// a deployment behind oauth2-proxy doesn't need to also issue a
// local session cookie. Name kept for historical reasons — the
// trust-header path was bolted on without renaming every call site.
func (s *Service) userFromCookie(r *http.Request) (User, bool) {
	if u, ok := s.TrustHeader.ResolveUser(r, s.Store); ok {
		return u, true
	}
	c, err := r.Cookie(CookieName)
	if err != nil {
		return User{}, false
	}
	uid, err := VerifySession(s.Secret, s.Now(), c.Value)
	if err != nil {
		return User{}, false
	}
	u, err := s.Store.GetByID(uid)
	if err != nil {
		return User{}, false
	}
	return u, true
}

// currentSessionID returns the sid claim from the request's session
// cookie, or "" when there's no cookie, the cookie doesn't verify, or it
// carries no sid. Used to identify "this session" for logout and for the
// keep-me-signed-in side of the revoke-others flows.
func (s *Service) currentSessionID(r *http.Request) string {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return ""
	}
	claims, err := VerifyToken(s.Secret, s.Now(), PurposeSession, c.Value)
	if err != nil {
		return ""
	}
	return claims.SID
}

func (s *Service) issueCookie(w http.ResponseWriter, r *http.Request, userID string) error {
	expires := s.Now().Add(s.SessionTTL)
	claims := TokenClaims{UID: userID}
	if s.Sessions != nil {
		sid := s.NewID()
		now := s.Now().UTC()
		sess := Session{
			ID:         sid,
			UserID:     userID,
			Label:      LabelFromUserAgent(r.UserAgent()),
			IP:         clientIP(r),
			CreatedAt:  now,
			LastSeenAt: now,
			ExpiresAt:  expires.UTC(),
		}
		if err := s.Sessions.CreateSession(sess); err != nil {
			return err
		}
		// Prune expired rows so an account that logs in often doesn't
		// accumulate dead sessions. Best-effort: a prune failure must
		// not break the login that just succeeded.
		if _, err := s.Sessions.DeleteExpiredSessions(s.Now()); err != nil {
			slog.Warn("auth prune sessions", "err", err)
		}
		claims.SID = sid
	}
	tok, err := SignToken(s.Secret, PurposeSession, claims, expires)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is set from s.SecureCookie at runtime; gosec only recognises a literal true.
		Name:     CookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.SecureCookie,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
		MaxAge:   int(s.SessionTTL.Seconds()),
	})
	return nil
}

func decodeCredentials(r *http.Request) (credentials, error) {
	var c credentials
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return credentials{}, errors.New("invalid JSON: " + err.Error())
	}
	c.Username = strings.TrimSpace(c.Username)
	if c.Username == "" {
		return credentials{}, errors.New("username required")
	}
	if c.Password == "" {
		return credentials{}, errors.New("password required")
	}
	return c, nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("auth json encode", "err", err)
	}
}

// writeLockedResponse emits the structured 423 body used by both
// /login and /totp/verify when correct credentials land on a locked
// account. The lockedUntil timestamp is RFC3339 so the frontend can
// render a relative countdown.
func writeLockedResponse(w http.ResponseWriter, lockedUntil time.Time) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusLocked)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":       "account locked",
		"lockedUntil": lockedUntil.UTC().Format(time.RFC3339),
	})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// SPDX-License-Identifier: Apache-2.0

// Package auth implements local-account authentication: bcrypt password
// hashing, HMAC-signed session cookies, optional TOTP second factor with
// recovery codes and a "remember this browser" trusted-device cookie, and
// the HTTP handlers for setup, login, logout, profile, and password change.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"system-wrangler-backend/internal/audit"
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
	Audit        *audit.Store
	SessionTTL   time.Duration
	SecureCookie bool
	Now          func() time.Time
	NewID        func() string
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
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/auth/status", s.handleStatus)
	mux.HandleFunc("POST /api/auth/setup", s.handleSetup)
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
}

// RegisterProtected wires the endpoints that require an authenticated user.
// The middleware is supplied by the caller so the auth package doesn't need
// to construct it itself.
func (s *Service) RegisterProtected(mux *http.ServeMux, requireUser func(http.Handler) http.Handler) {
	mux.Handle("PATCH /api/auth/profile", requireUser(http.HandlerFunc(s.handleUpdateProfile)))
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
func (s *Service) finishLogin(w http.ResponseWriter, r *http.Request, u User, method string) {
	if err := s.issueCookie(w, u.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "session failed")
		slog.Error("auth login cookie", "err", err)
		return
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
	if err := s.issueCookie(w, u.ID); err != nil {
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
			s.logLoginFailed(r.Context(), creds.Username, "no_user")
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		writeError(w, http.StatusInternalServerError, "login failed")
		slog.Error("auth login lookup", "err", err)
		return
	}
	if err := VerifyPassword(hash, creds.Password); err != nil {
		s.logLoginFailed(r.Context(), creds.Username, "wrong_password")
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
	http.SetCookie(w, &http.Cookie{
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
	http.SetCookie(w, &http.Cookie{
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
	http.SetCookie(w, &http.Cookie{
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
	http.SetCookie(w, &http.Cookie{
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
	http.SetCookie(w, &http.Cookie{
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
	if err := s.Store.UpdatePassword(u.ID, newHash); err != nil {
		writeError(w, http.StatusInternalServerError, "password change failed")
		slog.Error("auth change password update", "err", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) userFromCookie(r *http.Request) (User, bool) {
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

func (s *Service) issueCookie(w http.ResponseWriter, userID string) error {
	expires := s.Now().Add(s.SessionTTL)
	tok, err := SignSession(s.Secret, userID, expires)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
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

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

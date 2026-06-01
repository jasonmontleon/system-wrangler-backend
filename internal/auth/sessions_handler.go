// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"
	"log/slog"
	"net/http"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/router"
)

// RegisterSessions wires the active-session management endpoints. Like
// the trusted-device routes they sit behind RequireFreshPassword: an
// account flagged for password rotation shouldn't be managing sessions
// until it clears that flag. Safe to call when Sessions is nil — the
// handlers answer 503 so the SPA can hide the card gracefully.
func (s *Service) RegisterSessions(mux router.Mux, requireUser func(http.Handler) http.Handler) {
	if requireUser == nil {
		requireUser = func(next http.Handler) http.Handler { return next }
	}
	fresh := func(h http.Handler) http.Handler { return requireUser(RequireFreshPassword(h)) }
	mux.Handle("GET /api/auth/sessions", fresh(http.HandlerFunc(s.handleListSessions)))
	mux.Handle("DELETE /api/auth/sessions/{id}", fresh(http.HandlerFunc(s.handleRevokeSession)))
	mux.Handle("POST /api/auth/sessions/revoke-others", fresh(http.HandlerFunc(s.handleRevokeOtherSessions)))
}

func (s *Service) handleListSessions(w http.ResponseWriter, r *http.Request) {
	u, ok := UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if s.Sessions == nil {
		writeJSON(w, http.StatusOK, []Session{})
		return
	}
	sessions, err := s.Sessions.ListSessions(u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list sessions failed")
		slog.Error("list sessions", "err", err, "user_id", u.ID)
		return
	}
	current := s.currentSessionID(r)
	for i := range sessions {
		sessions[i].Current = sessions[i].ID == current
	}
	writeJSON(w, http.StatusOK, sessions)
}

func (s *Service) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	u, ok := UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if s.Sessions == nil {
		writeError(w, http.StatusServiceUnavailable, "sessions not configured")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "session id required")
		return
	}
	if err := s.Sessions.RevokeSession(id, u.ID); err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "revoke session failed")
		slog.Error("revoke session", "err", err, "user_id", u.ID)
		return
	}
	// Revoking the current session is effectively a logout — clear the
	// cookie so the browser doesn't keep sending a now-dead sid.
	if id == s.currentSessionID(r) {
		s.clearSessionCookie(w)
	}
	s.logAudit(r.Context(), audit.Event{
		Action:      "auth.session.revoke",
		Outcome:     audit.Success,
		TargetKind:  "user",
		TargetID:    u.ID,
		TargetLabel: u.Username,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleRevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	u, ok := UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if s.Sessions == nil {
		writeError(w, http.StatusServiceUnavailable, "sessions not configured")
		return
	}
	n, err := s.Sessions.RevokeOtherUserSessions(u.ID, s.currentSessionID(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "revoke sessions failed")
		slog.Error("revoke other sessions", "err", err, "user_id", u.ID)
		return
	}
	d := audit.NewDetail()
	_ = d.SetSafe("revoked", n)
	s.logAudit(r.Context(), audit.Event{
		Action:      "auth.session.revoke_others",
		Outcome:     audit.Success,
		TargetKind:  "user",
		TargetID:    u.ID,
		TargetLabel: u.Username,
		Detail:      d,
	})
	writeJSON(w, http.StatusOK, map[string]int{"revoked": n})
}

// clearSessionCookie expires the session cookie. Mirrors the inline
// cookie clears in handleLogout so revoking your own current session
// from the sessions list behaves like a logout.
func (s *Service) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is set from s.SecureCookie at runtime; gosec only recognises a literal true.
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.SecureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

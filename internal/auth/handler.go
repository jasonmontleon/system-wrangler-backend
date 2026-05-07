// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Service holds the shared state used by the auth HTTP endpoints.
type Service struct {
	Store        UserStore
	Secret       []byte
	SessionTTL   time.Duration
	SecureCookie bool
	Now          func() time.Time
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
	}
}

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
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		writeError(w, http.StatusInternalServerError, "login failed")
		slog.Error("auth login lookup", "err", err)
		return
	}
	if err := VerifyPassword(hash, creds.Password); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err := s.issueCookie(w, u.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "session failed")
		slog.Error("auth login cookie", "err", err)
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Service) handleLogout(w http.ResponseWriter, _ *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.SecureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
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

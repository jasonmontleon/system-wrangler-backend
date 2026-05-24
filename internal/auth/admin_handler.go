// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/router"
)

// RegisterAdmin attaches the user-administration endpoints to mux behind
// the supplied authenticated-user middleware. In v1 every authenticated
// user is admin (per project_tenancy.md), so requireUser alone gates
// these — revisit once roles ship. Admin endpoints sit behind
// RequireFreshPassword for the same reason every other protected
// surface does: an account flagged for password rotation can't reach
// for admin tooling.
func (s *Service) RegisterAdmin(mux router.Mux, requireUser func(http.Handler) http.Handler) {
	if requireUser == nil {
		requireUser = func(next http.Handler) http.Handler { return next }
	}
	fresh := func(h http.Handler) http.Handler { return requireUser(RequireFreshPassword(h)) }
	mux.Handle("GET /api/admin/users", fresh(http.HandlerFunc(s.handleListUsers)))
	mux.Handle("POST /api/admin/users", fresh(http.HandlerFunc(s.handleCreateUser)))
	mux.Handle("PATCH /api/admin/users/{id}", fresh(http.HandlerFunc(s.handleUpdateUser)))
	mux.Handle("DELETE /api/admin/users/{id}", fresh(http.HandlerFunc(s.handleDeleteUser)))
	mux.Handle("POST /api/admin/users/{id}/password", fresh(http.HandlerFunc(s.handleAdminResetPassword)))
	mux.Handle("POST /api/admin/users/{id}/totp/reset", fresh(http.HandlerFunc(s.handleAdminResetTOTP)))
}

func (s *Service) handleListUsers(w http.ResponseWriter, _ *http.Request) {
	users, err := s.Store.ListUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list users failed")
		slog.Error("admin list users", "err", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

type createUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Service) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if _, ok := UserFromContext(r.Context()); !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req createUserRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	hash, err := HashPassword(req.Password)
	if err != nil {
		if errors.Is(err, ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "hash failed")
		slog.Error("admin create user hash", "err", err)
		return
	}
	u, err := s.Store.Create(req.Username, hash)
	if err != nil {
		if errors.Is(err, ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, ErrUserExists) {
			writeError(w, http.StatusConflict, "username already taken")
			return
		}
		writeError(w, http.StatusInternalServerError, "create user failed")
		slog.Error("admin create user", "err", err)
		return
	}
	s.logAudit(r.Context(), audit.Event{
		Action:      "user.create",
		Outcome:     audit.Success,
		TargetKind:  "user",
		TargetID:    u.ID,
		TargetLabel: u.Username,
	})
	writeJSON(w, http.StatusCreated, u)
}

type updateUserRequest struct {
	Disabled *bool `json:"disabled,omitempty"`
}

func (s *Service) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	actor, ok := UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "user id required")
		return
	}
	var req updateUserRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Disabled == nil {
		writeError(w, http.StatusBadRequest, "no fields to update")
		return
	}
	wantDisabled := *req.Disabled
	if wantDisabled && id == actor.ID {
		writeError(w, http.StatusBadRequest, "cannot disable your own account")
		return
	}
	target, err := s.Store.GetByID(id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		slog.Error("admin update user lookup", "err", err)
		return
	}
	if wantDisabled && !target.Disabled {
		enabled, err := s.Store.CountEnabled()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "count failed")
			slog.Error("admin update user count", "err", err)
			return
		}
		if enabled <= 1 {
			writeError(w, http.StatusBadRequest, "cannot disable the last enabled user")
			return
		}
	}
	updated, err := s.Store.SetDisabled(id, wantDisabled, s.Now())
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "update failed")
		slog.Error("admin update user", "err", err)
		return
	}
	action := "user.enable"
	if wantDisabled {
		action = "user.disable"
	}
	s.logAudit(r.Context(), audit.Event{
		Action:      action,
		Outcome:     audit.Success,
		TargetKind:  "user",
		TargetID:    updated.ID,
		TargetLabel: updated.Username,
	})
	writeJSON(w, http.StatusOK, updated)
}

func (s *Service) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	actor, ok := UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "user id required")
		return
	}
	if id == actor.ID {
		writeError(w, http.StatusBadRequest, "cannot remove your own account")
		return
	}
	target, err := s.Store.GetByID(id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		slog.Error("admin delete user lookup", "err", err)
		return
	}
	if !target.Disabled {
		enabled, err := s.Store.CountEnabled()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "count failed")
			slog.Error("admin delete user count", "err", err)
			return
		}
		if enabled <= 1 {
			writeError(w, http.StatusBadRequest, "cannot remove the last enabled user")
			return
		}
	}
	if err := s.Store.Delete(id); err != nil {
		switch {
		case errors.Is(err, ErrUserNotFound):
			writeError(w, http.StatusNotFound, "user not found")
		case errors.Is(err, ErrLastGlobalAdmin):
			writeError(w, http.StatusConflict, "cannot remove the last global admin; promote another user first")
		default:
			writeError(w, http.StatusInternalServerError, "delete failed")
			slog.Error("admin delete user", "err", err)
		}
		return
	}
	s.logAudit(r.Context(), audit.Event{
		Action:      "user.delete",
		Outcome:     audit.Success,
		TargetKind:  "user",
		TargetID:    target.ID,
		TargetLabel: target.Username,
	})
	w.WriteHeader(http.StatusNoContent)
}

type adminResetPasswordRequest struct {
	Password string `json:"password"`
}

func (s *Service) handleAdminResetPassword(w http.ResponseWriter, r *http.Request) {
	actor, ok := UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "user id required")
		return
	}
	// Self-reset is a UX trap — the admin would type a new password
	// and the server would immediately set must_change_password on
	// them, forcing a redundant rotation. Route them to the regular
	// change-password flow instead.
	if id == actor.ID {
		writeError(w, http.StatusBadRequest, "use /api/auth/password to change your own password")
		return
	}
	var req adminResetPasswordRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	target, err := s.Store.GetByID(id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		slog.Error("admin reset password lookup", "err", err)
		return
	}
	hash, err := HashPassword(req.Password)
	if err != nil {
		if errors.Is(err, ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "hash failed")
		slog.Error("admin reset password hash", "err", err)
		return
	}
	if err := s.Store.AdminSetPassword(id, hash); err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "reset failed")
		slog.Error("admin reset password", "err", err)
		return
	}
	s.logAudit(r.Context(), audit.Event{
		Action:      "auth.admin.password_reset",
		Outcome:     audit.Success,
		TargetKind:  "user",
		TargetID:    target.ID,
		TargetLabel: target.Username,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleAdminResetTOTP(w http.ResponseWriter, r *http.Request) {
	actor, ok := UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "user id required")
		return
	}
	// Self-reset is forbidden for the same reason as password reset:
	// admins who can still log in should use the regular disable flow
	// at /api/auth/totp, which requires their own password + code.
	// The admin-reset path bypasses that and is meant for an operator
	// helping a user who's lost their authenticator.
	if id == actor.ID {
		writeError(w, http.StatusBadRequest, "use /api/auth/totp to disable your own 2FA")
		return
	}
	target, err := s.Store.GetByID(id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		slog.Error("admin reset totp lookup", "err", err)
		return
	}
	if err := s.Store.AdminResetTOTP(id); err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "reset failed")
		slog.Error("admin reset totp", "err", err)
		return
	}
	s.logAudit(r.Context(), audit.Event{
		Action:      "auth.admin.totp_reset",
		Outcome:     audit.Success,
		TargetKind:  "user",
		TargetID:    target.ID,
		TargetLabel: target.Username,
	})
	w.WriteHeader(http.StatusNoContent)
}

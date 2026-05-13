// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"system-wrangler-backend/internal/audit"
)

// RegisterAdmin attaches the user-administration endpoints to mux behind
// the supplied authenticated-user middleware. In v1 every authenticated
// user is admin (per project_tenancy.md), so requireUser alone gates
// these — revisit once roles ship.
func (s *Service) RegisterAdmin(mux *http.ServeMux, requireUser func(http.Handler) http.Handler) {
	if requireUser == nil {
		requireUser = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("GET /api/admin/users", requireUser(http.HandlerFunc(s.handleListUsers)))
	mux.Handle("POST /api/admin/users", requireUser(http.HandlerFunc(s.handleCreateUser)))
	mux.Handle("PATCH /api/admin/users/{id}", requireUser(http.HandlerFunc(s.handleUpdateUser)))
	mux.Handle("DELETE /api/admin/users/{id}", requireUser(http.HandlerFunc(s.handleDeleteUser)))
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
		if errors.Is(err, ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete failed")
		slog.Error("admin delete user", "err", err)
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

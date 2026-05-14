// SPDX-License-Identifier: Apache-2.0

package systems

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

// Handler bundles the HTTP endpoints for systems.
type Handler struct {
	Store Store
	// OnCreate fires after a successful create. Optional; nil is skipped.
	// Wired to (a) the probe Trigger so a freshly-added system is probed
	// within seconds instead of after a full Interval, and (b) the event
	// hub so SPAs see new systems without manual refresh.
	OnCreate func()
	// OnDelete fires after a successful delete. Optional; same wiring
	// purpose for SPA refresh.
	OnDelete func()
	// VisibleSystem, if non-nil, filters the result of GET /api/systems
	// and gates GET /api/systems/{id} so a caller without read
	// permission sees an empty list / a 404. Returning true means "the
	// caller may see this row." Wired by main.go against rbac so this
	// package doesn't import rbac (which already imports systems via
	// the groups → systems chain).
	VisibleSystem func(ctx context.Context, s System) bool
	// CanCreate, if non-nil, gates POST /api/systems. Returns false →
	// 403. nil disables the check (test/legacy callers without rbac).
	CanCreate func(ctx context.Context) bool
	// CanDelete, if non-nil, gates DELETE /api/systems/{id}. The
	// handler resolves the system before the gate so the caller's
	// permission can depend on the system's current group_id (Group
	// Admin can delete only systems in groups they admin). nil
	// disables the check.
	CanDelete func(ctx context.Context, s System) bool
}

// NewHandler constructs a Handler bound to the given Store. The optional
// OnCreate / OnDelete callbacks can be set on the returned value.
func NewHandler(s Store) *Handler { return &Handler{Store: s} }

// Register attaches /api/systems routes to the given mux. Each handler is
// wrapped in mw before registration so callers can apply auth (or any other
// per-route middleware) without exposing the handler methods.
func (h *Handler) Register(mux *http.ServeMux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("GET /api/systems", mw(http.HandlerFunc(h.list)))
	mux.Handle("POST /api/systems", mw(http.HandlerFunc(h.create)))
	mux.Handle("GET /api/systems/{id}", mw(http.HandlerFunc(h.get)))
	mux.Handle("DELETE /api/systems/{id}", mw(http.HandlerFunc(h.delete)))
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	systems, err := h.Store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		slog.Error("systems list", "err", err)
		return
	}
	// Apply the per-row scope filter when wired. Tests without a filter
	// see every row, matching the pre-RBAC behavior.
	if h.VisibleSystem != nil {
		ctx := r.Context()
		filtered := systems[:0]
		for _, s := range systems {
			if h.VisibleSystem(ctx, s) {
				filtered = append(filtered, s)
			}
		}
		systems = filtered
	}
	writeJSON(w, http.StatusOK, systems)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	if h.CanCreate != nil && !h.CanCreate(r.Context()) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	var in SystemInput
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	sys, err := h.Store.Create(in)
	if err != nil {
		if errors.Is(err, ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "create failed")
		slog.Error("systems create", "err", err)
		return
	}
	if h.OnCreate != nil {
		h.OnCreate()
	}
	w.Header().Set("Location", "/api/systems/"+sys.ID)
	writeJSON(w, http.StatusCreated, sys)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sys, err := h.Store.Get(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "system not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get failed")
		// id is user-controlled but slog's structured kv form doesn't
		// interpolate it into the message — gosec G706 false positive.
		slog.Error("systems get", "err", err, "id", id) //nolint:gosec
		return
	}
	// 404 (not 403) for systems the caller can't see — leaks no
	// information about whether the system exists.
	if h.VisibleSystem != nil && !h.VisibleSystem(r.Context(), sys) {
		writeError(w, http.StatusNotFound, "system not found")
		return
	}
	writeJSON(w, http.StatusOK, sys)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// Resolve the system first so the CanDelete gate can decide on the
	// row's current group_id (Global Admin always; Group Admin only if
	// the system is in one of their groups). A 404 from the gate hides
	// the system's existence from callers who can't read it; a 403
	// from the gate is reserved for "exists but you can't touch it,"
	// which leaks nothing the read gate doesn't already permit.
	sys, err := h.Store.Get(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "system not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete lookup failed")
		slog.Error("systems delete lookup", "err", err, "id", id) //nolint:gosec
		return
	}
	if h.VisibleSystem != nil && !h.VisibleSystem(r.Context(), sys) {
		writeError(w, http.StatusNotFound, "system not found")
		return
	}
	if h.CanDelete != nil && !h.CanDelete(r.Context(), sys) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := h.Store.Delete(id); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "system not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete failed")
		// See comment in get(): structured kv slog isn't G706-vulnerable.
		slog.Error("systems delete", "err", err, "id", id) //nolint:gosec
		return
	}
	if h.OnDelete != nil {
		h.OnDelete()
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("systems json encode", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

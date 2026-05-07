// SPDX-License-Identifier: AGPL-3.0-or-later

package systems

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

// Handler bundles the HTTP endpoints for systems.
type Handler struct {
	Store Store
	// OnCreate fires after a successful create. Optional; nil is skipped.
	// The probe loop's Trigger channel is the canonical caller — wiring
	// it here lets a freshly-added system be probed within seconds
	// instead of waiting up to a full Interval for the next scheduled tick.
	OnCreate func()
}

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

func (h *Handler) list(w http.ResponseWriter, _ *http.Request) {
	systems, err := h.Store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		slog.Error("systems list", "err", err)
		return
	}
	writeJSON(w, http.StatusOK, systems)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
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
		slog.Error("systems get", "err", err, "id", id)
		return
	}
	writeJSON(w, http.StatusOK, sys)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.Store.Delete(id); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "system not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete failed")
		slog.Error("systems delete", "err", err, "id", id)
		return
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

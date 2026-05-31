// SPDX-License-Identifier: Apache-2.0

package dashboardlayout

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"system-wrangler-backend/internal/auth"
	"system-wrangler-backend/internal/router"
)

// MaxLayoutBytes caps the size of an incoming PUT body. ~64 KB is well
// above any reasonable widget layout (a few hundred bytes today) and
// stops a buggy or malicious client from filling the table.
const MaxLayoutBytes = 64 * 1024

// Handler exposes the per-user dashboard-layout endpoints.
type Handler struct {
	Store Store
}

// Register attaches the two routes behind mw (the authenticated-user
// middleware). Both routes require an authenticated user.
func (h *Handler) Register(mux router.Mux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("GET /api/dashboard/layout", mw(http.HandlerFunc(h.get)))
	mux.Handle("PUT /api/dashboard/layout", mw(http.HandlerFunc(h.put)))
}

// layoutDTO carries the layout JSON to/from the frontend. RawMessage
// lets the inner JSON pass through without a round-trip parse —
// the server treats the value as opaque.
type layoutDTO struct {
	Layout json.RawMessage `json:"layout,omitempty"`
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.Store == nil {
		writeError(w, http.StatusServiceUnavailable, "store not configured")
		return
	}
	raw, err := h.Store.Get(user.ID)
	if errors.Is(err, ErrNotFound) {
		writeJSON(w, http.StatusOK, layoutDTO{})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load failed")
		slog.Error("dashboardlayout get", "err", err)
		return
	}
	writeJSON(w, http.StatusOK, layoutDTO{Layout: json.RawMessage(raw)})
}

func (h *Handler) put(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.Store == nil {
		writeError(w, http.StatusServiceUnavailable, "store not configured")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxLayoutBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read failed")
		return
	}
	if len(body) > MaxLayoutBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "layout too large")
		return
	}
	var in layoutDTO
	if err := json.Unmarshal(body, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(in.Layout) == 0 || bytes.Equal(in.Layout, []byte("null")) || !json.Valid(in.Layout) {
		writeError(w, http.StatusBadRequest, "layout must be valid JSON")
		return
	}
	if err := h.Store.Set(user.ID, string(in.Layout)); err != nil {
		writeError(w, http.StatusInternalServerError, "save failed")
		slog.Error("dashboardlayout set", "err", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("dashboardlayout json encode", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

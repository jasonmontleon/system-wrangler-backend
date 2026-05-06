// SPDX-License-Identifier: AGPL-3.0-or-later

package inventory

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

// Handler bundles the HTTP endpoints for the host inventory.
type Handler struct {
	Store Store
}

func NewHandler(s Store) *Handler { return &Handler{Store: s} }

// Register attaches /api/hosts routes to the given mux. Method-prefixed
// patterns require Go 1.22+; the module is on 1.24.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/hosts", h.list)
	mux.HandleFunc("POST /api/hosts", h.create)
	mux.HandleFunc("GET /api/hosts/{id}", h.get)
	mux.HandleFunc("DELETE /api/hosts/{id}", h.delete)
}

func (h *Handler) list(w http.ResponseWriter, _ *http.Request) {
	hosts, err := h.Store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		slog.Error("inventory list", "err", err)
		return
	}
	writeJSON(w, http.StatusOK, hosts)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var in HostInput
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	host, err := h.Store.Create(in)
	if err != nil {
		if errors.Is(err, ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "create failed")
		slog.Error("inventory create", "err", err)
		return
	}
	w.Header().Set("Location", "/api/hosts/"+host.ID)
	writeJSON(w, http.StatusCreated, host)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	host, err := h.Store.Get(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "host not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get failed")
		slog.Error("inventory get", "err", err, "id", id)
		return
	}
	writeJSON(w, http.StatusOK, host)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.Store.Delete(id); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "host not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete failed")
		slog.Error("inventory delete", "err", err, "id", id)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("inventory json encode", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

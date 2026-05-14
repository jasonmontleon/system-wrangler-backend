// SPDX-License-Identifier: Apache-2.0

package groups

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/systems"
)

// Handler bundles the HTTP endpoints for groups. It owns assignment of
// systems to groups too (PUT /api/systems/{id}/group), because that
// operation is conceptually a group-management action and binding it
// here keeps the systems package from importing groups.
type Handler struct {
	Store   Store
	Systems systems.Store
	// OnChange fires after any mutation (create/rename/delete or membership
	// change) so the events hub can poke SSE-connected clients. Optional.
	OnChange func()
	// Audit, if non-nil, receives an audit row per state-changing request.
	Audit *audit.Store
}

// NewHandler constructs a Handler bound to the given stores.
func NewHandler(store Store, sys systems.Store) *Handler {
	return &Handler{Store: store, Systems: sys}
}

// Register attaches /api/groups routes to the given mux. Each handler is
// wrapped in mw before registration so callers can apply auth (or any other
// per-route middleware) without exposing the handler methods.
func (h *Handler) Register(mux *http.ServeMux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("GET /api/groups", mw(http.HandlerFunc(h.list)))
	mux.Handle("POST /api/groups", mw(http.HandlerFunc(h.create)))
	mux.Handle("GET /api/groups/{id}", mw(http.HandlerFunc(h.get)))
	mux.Handle("PATCH /api/groups/{id}", mw(http.HandlerFunc(h.rename)))
	mux.Handle("DELETE /api/groups/{id}", mw(http.HandlerFunc(h.delete)))
	mux.Handle("PUT /api/systems/{id}/group", mw(http.HandlerFunc(h.setSystemGroup)))
}

func (h *Handler) list(w http.ResponseWriter, _ *http.Request) {
	gs, err := h.Store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		slog.Error("groups list", "err", err)
		return
	}
	writeJSON(w, http.StatusOK, gs)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var in GroupInput
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	g, err := h.Store.Create(in)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalid):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, ErrDuplicate):
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "create failed")
			slog.Error("groups create", "err", err)
		}
		return
	}
	h.logAudit(r.Context(), audit.Event{
		Action:      "system_group.create",
		Outcome:     audit.Success,
		TargetKind:  "system_group",
		TargetID:    g.ID,
		TargetLabel: g.Name,
	})
	h.fireChange()
	w.Header().Set("Location", "/api/groups/"+g.ID)
	writeJSON(w, http.StatusCreated, g)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	g, err := h.Store.Get(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "group not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get failed")
		slog.Error("groups get", "err", err, "id", id) //nolint:gosec
		return
	}
	writeJSON(w, http.StatusOK, g)
}

func (h *Handler) rename(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in GroupInput
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	g, err := h.Store.Rename(id, in)
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			writeError(w, http.StatusNotFound, "group not found")
		case errors.Is(err, ErrInvalid):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, ErrDuplicate):
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "rename failed")
			slog.Error("groups rename", "err", err, "id", id) //nolint:gosec
		}
		return
	}
	h.logAudit(r.Context(), audit.Event{
		Action:      "system_group.rename",
		Outcome:     audit.Success,
		TargetKind:  "system_group",
		TargetID:    g.ID,
		TargetLabel: g.Name,
	})
	h.fireChange()
	writeJSON(w, http.StatusOK, g)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// Look up the label before deleting so the audit row reads naturally.
	g, getErr := h.Store.Get(id)
	if err := h.Store.Delete(id); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "group not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete failed")
		slog.Error("groups delete", "err", err, "id", id) //nolint:gosec
		return
	}
	label := id
	if getErr == nil {
		label = g.Name
	}
	h.logAudit(r.Context(), audit.Event{
		Action:      "system_group.delete",
		Outcome:     audit.Success,
		TargetKind:  "system_group",
		TargetID:    id,
		TargetLabel: label,
	})
	h.fireChange()
	w.WriteHeader(http.StatusNoContent)
}

// setSystemGroup handles PUT /api/systems/{id}/group with body
// {"groupId": "..."} or {"groupId": null} to assign or clear membership.
func (h *Handler) setSystemGroup(w http.ResponseWriter, r *http.Request) {
	systemID := r.PathValue("id")
	var body struct {
		GroupID *string `json:"groupId"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.GroupID != nil {
		if _, err := h.Store.Get(*body.GroupID); err != nil {
			if errors.Is(err, ErrNotFound) {
				writeError(w, http.StatusNotFound, "group not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "lookup failed")
			slog.Error("groups setSystemGroup lookup", "err", err)
			return
		}
	}
	if err := h.Systems.SetGroup(systemID, body.GroupID); err != nil {
		if errors.Is(err, systems.ErrNotFound) {
			writeError(w, http.StatusNotFound, "system not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "set group failed")
		slog.Error("groups setSystemGroup", "err", err, "id", systemID) //nolint:gosec
		return
	}
	action := "system.group.clear"
	if body.GroupID != nil {
		action = "system.group.set"
	}
	target := ""
	if body.GroupID != nil {
		target = *body.GroupID
	}
	h.logAudit(r.Context(), audit.Event{
		Action:     action,
		Outcome:    audit.Success,
		TargetKind: "system",
		TargetID:   systemID,
		Detail:     audit.Detail{"group_id": target},
	})
	h.fireChange()
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) logAudit(ctx context.Context, e audit.Event) {
	if h.Audit == nil {
		return
	}
	if err := h.Audit.Log(ctx, e); err != nil {
		slog.Error("groups audit log", "err", err, "action", e.Action)
	}
}

func (h *Handler) fireChange() {
	if h.OnChange != nil {
		h.OnChange()
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("groups json encode", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

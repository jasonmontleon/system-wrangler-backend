// SPDX-License-Identifier: Apache-2.0

package notifications

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/router"
)

// Handler bundles the channel CRUD + test + delivery-log endpoints. All
// routes are gated by CanManage (bound to Global Admin in main.go) since
// channels hold delivery endpoints and secrets. Responses are always the
// redacted DTO — the sealed secret is never serialized.
type Handler struct {
	Store Store

	// Audit, if non-nil, receives a row per state-changing request.
	Audit *audit.Store

	// CanManage gates every endpoint. A nil gate means "no gate" (tests).
	CanManage func(ctx context.Context) bool

	// Dispatcher, if non-nil, enables POST /{id}/test.
	Dispatcher *Dispatcher

	// MaxDeliveries caps GET /deliveries (0 → 100).
	MaxDeliveries int
}

// Register attaches the routes. The literal /deliveries sub-path is more
// specific than /{id}, so Go 1.22's ServeMux orders it correctly.
func (h *Handler) Register(mux router.Mux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("GET /api/notifications/channels", mw(http.HandlerFunc(h.list)))
	mux.Handle("POST /api/notifications/channels", mw(http.HandlerFunc(h.create)))
	mux.Handle("GET /api/notifications/channels/{id}", mw(http.HandlerFunc(h.get)))
	mux.Handle("PUT /api/notifications/channels/{id}", mw(http.HandlerFunc(h.update)))
	mux.Handle("DELETE /api/notifications/channels/{id}", mw(http.HandlerFunc(h.delete)))
	mux.Handle("POST /api/notifications/channels/{id}/test", mw(http.HandlerFunc(h.test)))
	mux.Handle("GET /api/notifications/deliveries", mw(http.HandlerFunc(h.deliveries)))
	mux.Handle("GET /api/notifications/routing", mw(http.HandlerFunc(h.listRouting)))
	mux.Handle("PUT /api/notifications/routing/{ruleId}", mw(http.HandlerFunc(h.setRouting)))
}

func (h *Handler) gate(w http.ResponseWriter, r *http.Request) bool {
	if h.CanManage != nil && !h.CanManage(r.Context()) {
		writeError(w, http.StatusForbidden, "forbidden")
		return false
	}
	return true
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	all, err := h.Store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		slog.Error("notifications list", "err", err)
		return
	}
	out := make([]ChannelDTO, 0, len(all))
	for _, c := range all {
		out = append(out, c.Redacted())
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	var in ChannelInput
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	createdBy := userIDFromContext(r.Context())
	if createdBy == "" {
		writeError(w, http.StatusUnauthorized, "no user")
		return
	}
	c, err := h.Store.Create(in, createdBy)
	if err != nil {
		if errors.Is(err, ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "create failed")
		slog.Error("notifications create", "err", err)
		return
	}
	h.logAudit(r.Context(), audit.Event{
		Action: "notification_channel.create", Outcome: audit.Success,
		TargetKind: "notification_channel", TargetID: c.ID, TargetLabel: c.Name,
	})
	w.Header().Set("Location", "/api/notifications/channels/"+c.ID)
	writeJSON(w, http.StatusCreated, c.Redacted())
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	c, err := h.Store.Get(r.PathValue("id"))
	if err != nil {
		h.writeGetErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c.Redacted())
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	id := r.PathValue("id")
	if _, err := h.Store.Get(id); err != nil {
		h.writeGetErr(w, err)
		return
	}
	var in ChannelInput
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	c, err := h.Store.Update(id, in)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalid):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, ErrNotFound):
			writeError(w, http.StatusNotFound, "channel not found")
		default:
			writeError(w, http.StatusInternalServerError, "update failed")
			slog.Error("notifications update", "err", err)
		}
		return
	}
	h.logAudit(r.Context(), audit.Event{
		Action: "notification_channel.update", Outcome: audit.Success,
		TargetKind: "notification_channel", TargetID: c.ID, TargetLabel: c.Name,
	})
	writeJSON(w, http.StatusOK, c.Redacted())
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	id := r.PathValue("id")
	existing, err := h.Store.Get(id)
	if err != nil {
		h.writeGetErr(w, err)
		return
	}
	if err := h.Store.Delete(id); err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		slog.Error("notifications delete", "err", err)
		return
	}
	h.logAudit(r.Context(), audit.Event{
		Action: "notification_channel.delete", Outcome: audit.Success,
		TargetKind: "notification_channel", TargetID: existing.ID, TargetLabel: existing.Name,
	})
	w.WriteHeader(http.StatusNoContent)
}

// TestResult is the body of POST /{id}/test.
type TestResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func (h *Handler) test(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	c, err := h.Store.Get(r.PathValue("id"))
	if err != nil {
		h.writeGetErr(w, err)
		return
	}
	if h.Dispatcher == nil {
		writeError(w, http.StatusServiceUnavailable, "notifications runtime not configured")
		return
	}
	h.logAudit(r.Context(), audit.Event{
		Action: "notification_channel.test", Outcome: audit.Success,
		TargetKind: "notification_channel", TargetID: c.ID, TargetLabel: c.Name,
	})
	// The send is bounded by the dispatcher's own timeout; the operator's
	// POST blocks on it so the result is reported synchronously.
	if err := h.Dispatcher.Test(r.Context(), c); err != nil {
		writeJSON(w, http.StatusOK, TestResult{OK: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, TestResult{OK: true})
}

func (h *Handler) deliveries(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	limit := h.MaxDeliveries
	if limit <= 0 {
		limit = 100
	}
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 && n < limit {
			limit = n
		}
	}
	ds, err := h.Store.ListDeliveries(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list deliveries failed")
		slog.Error("notifications deliveries", "err", err)
		return
	}
	writeJSON(w, http.StatusOK, ds)
}

func (h *Handler) listRouting(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	rs, err := h.Store.ListRouting()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list routing failed")
		slog.Error("notifications list routing", "err", err)
		return
	}
	writeJSON(w, http.StatusOK, rs)
}

func (h *Handler) setRouting(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	ruleID := r.PathValue("ruleId")
	var in RoutingInput
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if err := h.Store.SetRouting(ruleID, in); err != nil {
		if errors.Is(err, ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "set routing failed")
		slog.Error("notifications set routing", "err", err)
		return
	}
	out, err := h.Store.GetRouting(ruleID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get routing failed")
		slog.Error("notifications get routing", "err", err)
		return
	}
	h.logAudit(r.Context(), audit.Event{
		Action: "notification_routing.update", Outcome: audit.Success,
		TargetKind: "alert_rule_routing", TargetID: ruleID, TargetLabel: string(out.Mode),
	})
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) writeGetErr(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusNotFound, "channel not found")
		return
	}
	writeError(w, http.StatusInternalServerError, "get failed")
	slog.Error("notifications get", "err", err)
}

func (h *Handler) logAudit(ctx context.Context, e audit.Event) {
	if h.Audit == nil {
		return
	}
	if err := h.Audit.Log(ctx, e); err != nil {
		slog.Error("notifications audit log", "err", err, "action", e.Action)
	}
}

func userIDFromContext(ctx context.Context) string {
	a := audit.ActorFromContext(ctx)
	if a.Kind == audit.ActorUser {
		return a.ID
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("notifications json encode", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

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

// MeHandler exposes the self-service per-user delivery endpoints under
// /api/notifications/me. Authorization is implicit: every operation is
// scoped to the user id taken from the request context, so a signed-in
// user can only ever read or change their own personal channels,
// subscription, and policy. There is no admin gate — these are personal
// preferences, like the profile/sessions endpoints.
type MeHandler struct {
	Store Store

	// Audit, if non-nil, receives a row per state-changing request.
	Audit *audit.Store
	// Dispatcher, if non-nil, enables POST /channels/{id}/test.
	Dispatcher *Dispatcher
	// MaxDeliveries caps GET /deliveries (0 → 100).
	MaxDeliveries int
}

// Register attaches the /api/notifications/me routes behind mw (the
// authenticated-user middleware).
func (h *MeHandler) Register(mux router.Mux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("GET /api/notifications/me/channels", mw(http.HandlerFunc(h.listChannels)))
	mux.Handle("POST /api/notifications/me/channels", mw(http.HandlerFunc(h.createChannel)))
	mux.Handle("GET /api/notifications/me/channels/{id}", mw(http.HandlerFunc(h.getChannel)))
	mux.Handle("PUT /api/notifications/me/channels/{id}", mw(http.HandlerFunc(h.updateChannel)))
	mux.Handle("DELETE /api/notifications/me/channels/{id}", mw(http.HandlerFunc(h.deleteChannel)))
	mux.Handle("POST /api/notifications/me/channels/{id}/test", mw(http.HandlerFunc(h.testChannel)))
	mux.Handle("GET /api/notifications/me/subscription", mw(http.HandlerFunc(h.getSubscription)))
	mux.Handle("PUT /api/notifications/me/subscription", mw(http.HandlerFunc(h.setSubscription)))
	mux.Handle("GET /api/notifications/me/policy", mw(http.HandlerFunc(h.getPolicy)))
	mux.Handle("PUT /api/notifications/me/policy", mw(http.HandlerFunc(h.setPolicy)))
	mux.Handle("GET /api/notifications/me/deliveries", mw(http.HandlerFunc(h.deliveries)))
}

// uid resolves the caller's user id, writing 401 and returning "" when
// there's no authenticated user on the context.
func (h *MeHandler) uid(w http.ResponseWriter, r *http.Request) string {
	id := userIDFromContext(r.Context())
	if id == "" {
		writeError(w, http.StatusUnauthorized, "no user")
	}
	return id
}

func (h *MeHandler) listChannels(w http.ResponseWriter, r *http.Request) {
	uid := h.uid(w, r)
	if uid == "" {
		return
	}
	all, err := h.Store.ListUserChannels(uid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		slog.Error("me channels list", "err", err)
		return
	}
	out := make([]ChannelDTO, 0, len(all))
	for _, c := range all {
		out = append(out, c.Redacted())
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *MeHandler) createChannel(w http.ResponseWriter, r *http.Request) {
	uid := h.uid(w, r)
	if uid == "" {
		return
	}
	in, ok := decodeChannelInput(w, r)
	if !ok {
		return
	}
	c, err := h.Store.CreateUserChannel(uid, in)
	if err != nil {
		writeChannelWriteErr(w, err, "create")
		return
	}
	h.logAudit(r.Context(), audit.Event{
		Action: "user_notification_channel.create", Outcome: audit.Success,
		TargetKind: "user_notification_channel", TargetID: c.ID, TargetLabel: c.Name,
	})
	w.Header().Set("Location", "/api/notifications/me/channels/"+c.ID)
	writeJSON(w, http.StatusCreated, c.Redacted())
}

func (h *MeHandler) getChannel(w http.ResponseWriter, r *http.Request) {
	uid := h.uid(w, r)
	if uid == "" {
		return
	}
	c, err := h.Store.GetUserChannel(uid, r.PathValue("id"))
	if err != nil {
		writeChannelGetErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c.Redacted())
}

func (h *MeHandler) updateChannel(w http.ResponseWriter, r *http.Request) {
	uid := h.uid(w, r)
	if uid == "" {
		return
	}
	in, ok := decodeChannelInput(w, r)
	if !ok {
		return
	}
	c, err := h.Store.UpdateUserChannel(uid, r.PathValue("id"), in)
	if err != nil {
		writeChannelWriteErr(w, err, "update")
		return
	}
	h.logAudit(r.Context(), audit.Event{
		Action: "user_notification_channel.update", Outcome: audit.Success,
		TargetKind: "user_notification_channel", TargetID: c.ID, TargetLabel: c.Name,
	})
	writeJSON(w, http.StatusOK, c.Redacted())
}

func (h *MeHandler) deleteChannel(w http.ResponseWriter, r *http.Request) {
	uid := h.uid(w, r)
	if uid == "" {
		return
	}
	id := r.PathValue("id")
	existing, err := h.Store.GetUserChannel(uid, id)
	if err != nil {
		writeChannelGetErr(w, err)
		return
	}
	if err := h.Store.DeleteUserChannel(uid, id); err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		slog.Error("me channel delete", "err", err)
		return
	}
	h.logAudit(r.Context(), audit.Event{
		Action: "user_notification_channel.delete", Outcome: audit.Success,
		TargetKind: "user_notification_channel", TargetID: existing.ID, TargetLabel: existing.Name,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (h *MeHandler) testChannel(w http.ResponseWriter, r *http.Request) {
	uid := h.uid(w, r)
	if uid == "" {
		return
	}
	c, err := h.Store.GetUserChannel(uid, r.PathValue("id"))
	if err != nil {
		writeChannelGetErr(w, err)
		return
	}
	if h.Dispatcher == nil {
		writeError(w, http.StatusServiceUnavailable, "notifications runtime not configured")
		return
	}
	h.logAudit(r.Context(), audit.Event{
		Action: "user_notification_channel.test", Outcome: audit.Success,
		TargetKind: "user_notification_channel", TargetID: c.ID, TargetLabel: c.Name,
	})
	if err := h.Dispatcher.TestForUser(r.Context(), c, uid); err != nil {
		writeJSON(w, http.StatusOK, TestResult{OK: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, TestResult{OK: true})
}

func (h *MeHandler) getSubscription(w http.ResponseWriter, r *http.Request) {
	uid := h.uid(w, r)
	if uid == "" {
		return
	}
	sub, err := h.Store.GetSubscription(uid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get subscription failed")
		slog.Error("me subscription get", "err", err)
		return
	}
	writeJSON(w, http.StatusOK, sub)
}

func (h *MeHandler) setSubscription(w http.ResponseWriter, r *http.Request) {
	uid := h.uid(w, r)
	if uid == "" {
		return
	}
	var in Subscription
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := h.Store.SetSubscription(uid, in); err != nil {
		if errors.Is(err, ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "set subscription failed")
		slog.Error("me subscription set", "err", err)
		return
	}
	h.logAudit(r.Context(), audit.Event{
		Action: "user_notification_subscription.update", Outcome: audit.Success,
		TargetKind: "user_notification_subscription", TargetID: uid,
	})
	out, _ := h.Store.GetSubscription(uid)
	writeJSON(w, http.StatusOK, out)
}

func (h *MeHandler) getPolicy(w http.ResponseWriter, r *http.Request) {
	uid := h.uid(w, r)
	if uid == "" {
		return
	}
	p, err := h.Store.GetUserPolicy(uid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get policy failed")
		slog.Error("me policy get", "err", err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (h *MeHandler) setPolicy(w http.ResponseWriter, r *http.Request) {
	uid := h.uid(w, r)
	if uid == "" {
		return
	}
	var in PolicyInput
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := h.Store.SetUserPolicy(uid, in); err != nil {
		if errors.Is(err, ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "set policy failed")
		slog.Error("me policy set", "err", err)
		return
	}
	h.logAudit(r.Context(), audit.Event{
		Action: "user_notification_policy.update", Outcome: audit.Success,
		TargetKind: "user_notification_policy", TargetID: uid,
	})
	out, _ := h.Store.GetUserPolicy(uid)
	writeJSON(w, http.StatusOK, out)
}

func (h *MeHandler) deliveries(w http.ResponseWriter, r *http.Request) {
	uid := h.uid(w, r)
	if uid == "" {
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
	ds, err := h.Store.ListUserDeliveries(uid, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list deliveries failed")
		slog.Error("me deliveries", "err", err)
		return
	}
	writeJSON(w, http.StatusOK, ds)
}

func (h *MeHandler) logAudit(ctx context.Context, e audit.Event) {
	if h.Audit == nil {
		return
	}
	if err := h.Audit.Log(ctx, e); err != nil {
		slog.Error("me audit log", "err", err, "action", e.Action)
	}
}

// decodeChannelInput decodes a ChannelInput body, writing 400 on failure.
func decodeChannelInput(w http.ResponseWriter, r *http.Request) (ChannelInput, bool) {
	var in ChannelInput
	ok := decodeJSON(w, r, &in)
	return in, ok
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

func writeChannelGetErr(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusNotFound, "channel not found")
		return
	}
	writeError(w, http.StatusInternalServerError, "get failed")
	slog.Error("me channel get", "err", err)
}

func writeChannelWriteErr(w http.ResponseWriter, err error, op string) {
	switch {
	case errors.Is(err, ErrInvalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "channel not found")
	default:
		writeError(w, http.StatusInternalServerError, op+" failed")
		slog.Error("me channel "+op, "err", err)
	}
}

// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/router"
)

// Handler bundles the HTTP endpoints for alert rules and the live
// active-alert view. RBAC gates are supplied by main.go via function
// callbacks so this package does not import rbac; a nil callback means
// "no gate" (used by tests that don't care about auth).
type Handler struct {
	Store Store

	// Audit, if non-nil, receives an audit row per state-changing request.
	Audit *audit.Store

	// VisibleRule, if non-nil, filters GET /api/alerts and gates
	// GET /api/alerts/{id}. Returning false means "not visible to this
	// caller" — the handler responds 404 (not 403) to avoid leaking
	// existence.
	VisibleRule func(ctx context.Context, r Rule) bool

	// CanManage, if non-nil, gates POST / PUT / DELETE. For create it is
	// the proposed rule (id blank); for update/delete it is the stored
	// rule about to be touched, re-checked against the proposed shape on
	// update so a Group Admin can't pivot a rule onto a group they don't
	// admin.
	CanManage func(ctx context.Context, r Rule) bool

	// VisibleSystem, if non-nil, filters GET /api/alerts/active to the
	// systems the caller may read. Returning false drops the row.
	VisibleSystem func(ctx context.Context, systemID string) bool

	// SystemName, if non-nil, resolves a system id to its display name to
	// enrich the active-alert rows.
	SystemName func(systemID string) string
}

// Register attaches the /api/alerts routes. The literal sub-paths
// (catalog, active) are more specific than /{id}, so Go 1.22's ServeMux
// routes them ahead of the wildcard automatically.
func (h *Handler) Register(mux router.Mux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("GET /api/alerts", mw(http.HandlerFunc(h.list)))
	mux.Handle("POST /api/alerts", mw(http.HandlerFunc(h.create)))
	mux.Handle("GET /api/alerts/catalog", mw(http.HandlerFunc(h.listCatalog)))
	mux.Handle("GET /api/alerts/active", mw(http.HandlerFunc(h.active)))
	mux.Handle("GET /api/alerts/{id}", mw(http.HandlerFunc(h.get)))
	mux.Handle("PUT /api/alerts/{id}", mw(http.HandlerFunc(h.update)))
	mux.Handle("DELETE /api/alerts/{id}", mw(http.HandlerFunc(h.delete)))
}

func (h *Handler) listCatalog(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, CatalogEntries())
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	all, err := h.Store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		slog.Error("alerts list", "err", err)
		return
	}
	if h.VisibleRule != nil {
		ctx := r.Context()
		out := all[:0]
		for _, rule := range all {
			if h.VisibleRule(ctx, rule) {
				out = append(out, rule)
			}
		}
		all = out
	}
	writeJSON(w, http.StatusOK, all)
}

func (h *Handler) active(w http.ResponseWriter, r *http.Request) {
	all, err := h.Store.ListActive()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list active failed")
		slog.Error("alerts active", "err", err)
		return
	}
	ctx := r.Context()
	out := make([]ActiveAlert, 0, len(all))
	for _, a := range all {
		if h.VisibleSystem != nil && !h.VisibleSystem(ctx, a.SystemID) {
			continue
		}
		if h.SystemName != nil {
			a.SystemName = h.SystemName(a.SystemID)
		}
		out = append(out, a)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var in RuleInput
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if h.CanManage != nil {
		proposed := Rule{
			Name:        in.Name,
			TargetKind:  in.TargetKind,
			TargetValue: in.TargetValue,
		}
		if !h.CanManage(r.Context(), proposed) {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
	}
	createdBy := userIDFromContext(r.Context())
	if createdBy == "" {
		writeError(w, http.StatusUnauthorized, "no user")
		return
	}
	rule, err := h.Store.Create(in, createdBy)
	if err != nil {
		if errors.Is(err, ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "create failed")
		slog.Error("alerts create", "err", err)
		return
	}
	h.logAudit(r.Context(), audit.Event{
		Action:      "alert.create",
		Outcome:     audit.Success,
		TargetKind:  "alert_rule",
		TargetID:    rule.ID,
		TargetLabel: rule.Name,
	})
	w.Header().Set("Location", "/api/alerts/"+rule.ID)
	writeJSON(w, http.StatusCreated, rule)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rule, err := h.Store.Get(id)
	if err != nil {
		h.writeGetErr(w, err, "alerts get", id)
		return
	}
	if h.VisibleRule != nil && !h.VisibleRule(r.Context(), rule) {
		writeError(w, http.StatusNotFound, "alert rule not found")
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := h.Store.Get(id)
	if err != nil {
		h.writeGetErr(w, err, "alerts update get", id)
		return
	}
	if h.CanManage != nil && !h.CanManage(r.Context(), existing) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	var in RuleInput
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if h.CanManage != nil {
		proposed := existing
		proposed.TargetKind = in.TargetKind
		proposed.TargetValue = in.TargetValue
		if !h.CanManage(r.Context(), proposed) {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
	}
	updated, err := h.Store.Update(id, in)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalid):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, ErrNotFound):
			writeError(w, http.StatusNotFound, "alert rule not found")
		default:
			writeError(w, http.StatusInternalServerError, "update failed")
			slog.Error("alerts update", "err", err, "id", id) //nolint:gosec // path param
		}
		return
	}
	h.logAudit(r.Context(), audit.Event{
		Action:      "alert.update",
		Outcome:     audit.Success,
		TargetKind:  "alert_rule",
		TargetID:    updated.ID,
		TargetLabel: updated.Name,
	})
	writeJSON(w, http.StatusOK, updated)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := h.Store.Get(id)
	if err != nil {
		h.writeGetErr(w, err, "alerts delete get", id)
		return
	}
	if h.CanManage != nil && !h.CanManage(r.Context(), existing) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := h.Store.Delete(id); err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		slog.Error("alerts delete", "err", err, "id", id) //nolint:gosec // path param
		return
	}
	h.logAudit(r.Context(), audit.Event{
		Action:      "alert.delete",
		Outcome:     audit.Success,
		TargetKind:  "alert_rule",
		TargetID:    existing.ID,
		TargetLabel: existing.Name,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) writeGetErr(w http.ResponseWriter, err error, logMsg, id string) {
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusNotFound, "alert rule not found")
		return
	}
	writeError(w, http.StatusInternalServerError, "get failed")
	slog.Error(logMsg, "err", err, "id", id) //nolint:gosec // path param
}

func (h *Handler) logAudit(ctx context.Context, e audit.Event) {
	if h.Audit == nil {
		return
	}
	if err := h.Audit.Log(ctx, e); err != nil {
		slog.Error("alerts audit log", "err", err, "action", e.Action)
	}
}

// userIDFromContext extracts the acting user's id from the audit-stamped
// Actor. Empty string means unauthenticated.
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
		slog.Error("alerts json encode", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// SPDX-License-Identifier: Apache-2.0

package schedules

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

// Handler bundles the HTTP endpoints for schedules. RBAC gates are
// supplied by main.go via function callbacks so this package does
// not import rbac. A nil callback means "no gate" — used in tests
// that don't care about auth.
type Handler struct {
	Store Store

	// Audit, if non-nil, receives an audit row per state-changing request.
	Audit *audit.Store

	// VisibleSchedule, if non-nil, filters GET /api/schedules and gates
	// GET /api/schedules/{id}. Returning false means "not visible to
	// this caller" — the handler responds 404 (not 403) to avoid
	// leaking existence.
	VisibleSchedule func(ctx context.Context, sch Schedule) bool

	// CanManage, if non-nil, gates POST / PUT / DELETE. For the create
	// path the schedule is the operator's *proposed* schedule (id
	// blank, server-managed fields zero); for update/delete it's the
	// stored schedule the operator is about to touch.
	CanManage func(ctx context.Context, sch Schedule) bool

	// MaxRunHistory caps the row count returned by
	// GET /api/schedules/{id}/runs. Zero means use the default (50).
	MaxRunHistory int
}

// Register attaches /api/schedules routes to the given mux.
func (h *Handler) Register(mux router.Mux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("GET /api/schedules", mw(http.HandlerFunc(h.list)))
	mux.Handle("POST /api/schedules", mw(http.HandlerFunc(h.create)))
	mux.Handle("GET /api/schedules/{id}", mw(http.HandlerFunc(h.get)))
	mux.Handle("PUT /api/schedules/{id}", mw(http.HandlerFunc(h.update)))
	mux.Handle("DELETE /api/schedules/{id}", mw(http.HandlerFunc(h.delete)))
	mux.Handle("GET /api/schedules/{id}/runs", mw(http.HandlerFunc(h.listRuns)))
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	all, err := h.Store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		slog.Error("schedules list", "err", err)
		return
	}
	if h.VisibleSchedule != nil {
		ctx := r.Context()
		out := all[:0]
		for _, s := range all {
			if h.VisibleSchedule(ctx, s) {
				out = append(out, s)
			}
		}
		all = out
	}
	writeJSON(w, http.StatusOK, all)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var in ScheduleInput
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if h.CanManage != nil {
		// Gate against the *proposed* schedule so a Group Admin can
		// only create schedules targeting groups they admin.
		proposed := Schedule{
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
	sch, err := h.Store.Create(in, createdBy)
	if err != nil {
		if errors.Is(err, ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "create failed")
		slog.Error("schedules create", "err", err)
		return
	}
	h.logAudit(r.Context(), audit.Event{
		Action:      "schedule.create",
		Outcome:     audit.Success,
		TargetKind:  "schedule",
		TargetID:    sch.ID,
		TargetLabel: sch.Name,
	})
	w.Header().Set("Location", "/api/schedules/"+sch.ID)
	writeJSON(w, http.StatusCreated, sch)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sch, err := h.Store.Get(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "schedule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get failed")
		slog.Error("schedules get", "err", err, "id", id) //nolint:gosec // path param not logged untrusted
		return
	}
	if h.VisibleSchedule != nil && !h.VisibleSchedule(r.Context(), sch) {
		writeError(w, http.StatusNotFound, "schedule not found")
		return
	}
	writeJSON(w, http.StatusOK, sch)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := h.Store.Get(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "schedule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get failed")
		slog.Error("schedules update get", "err", err, "id", id) //nolint:gosec // path param
		return
	}
	if h.CanManage != nil && !h.CanManage(r.Context(), existing) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	var in ScheduleInput
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	// Re-gate against the *new* shape so a Group Admin can't pivot a
	// schedule onto a group they don't admin.
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
			writeError(w, http.StatusNotFound, "schedule not found")
		default:
			writeError(w, http.StatusInternalServerError, "update failed")
			slog.Error("schedules update", "err", err, "id", id) //nolint:gosec // path param
		}
		return
	}
	h.logAudit(r.Context(), audit.Event{
		Action:      "schedule.update",
		Outcome:     audit.Success,
		TargetKind:  "schedule",
		TargetID:    updated.ID,
		TargetLabel: updated.Name,
	})
	writeJSON(w, http.StatusOK, updated)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := h.Store.Get(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "schedule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get failed")
		slog.Error("schedules delete get", "err", err, "id", id) //nolint:gosec // path param
		return
	}
	if h.CanManage != nil && !h.CanManage(r.Context(), existing) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := h.Store.Delete(id); err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		slog.Error("schedules delete", "err", err, "id", id) //nolint:gosec // path param
		return
	}
	h.logAudit(r.Context(), audit.Event{
		Action:      "schedule.delete",
		Outcome:     audit.Success,
		TargetKind:  "schedule",
		TargetID:    existing.ID,
		TargetLabel: existing.Name,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listRuns(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sch, err := h.Store.Get(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "schedule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get failed")
		slog.Error("schedules listRuns get", "err", err, "id", id) //nolint:gosec // path param
		return
	}
	if h.VisibleSchedule != nil && !h.VisibleSchedule(r.Context(), sch) {
		writeError(w, http.StatusNotFound, "schedule not found")
		return
	}
	limit := h.MaxRunHistory
	if limit <= 0 {
		limit = 50
	}
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 && n < limit {
			limit = n
		}
	}
	runs, err := h.Store.ListRuns(id, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list runs failed")
		slog.Error("schedules listRuns", "err", err, "id", id) //nolint:gosec // path param
		return
	}
	writeJSON(w, http.StatusOK, runs)
}

func (h *Handler) logAudit(ctx context.Context, e audit.Event) {
	if h.Audit == nil {
		return
	}
	if err := h.Audit.Log(ctx, e); err != nil {
		slog.Error("schedules audit log", "err", err, "action", e.Action)
	}
}

// userIDFromContext extracts the acting user's id from the request
// context via the audit package's stamped Actor. Empty string means
// unauthenticated and the caller must 401.
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
		slog.Error("schedules json encode", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

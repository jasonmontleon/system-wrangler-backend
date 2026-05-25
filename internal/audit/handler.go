// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"system-wrangler-backend/internal/router"
)

// Handler exposes the read-side audit endpoints. Write happens via
// LogTx / Log from inside other handlers; there is no API to append or
// edit audit rows.
type Handler struct {
	Store *Store
	// ScopeFilterFor, if non-nil, is called per-request to derive a
	// ScopeFilter for ListQuery. Returning nil applies no restriction
	// (the global-role case). Wiring lives in main.go so the audit
	// package doesn't import rbac (rbac already imports audit).
	ScopeFilterFor func(r *http.Request) *ScopeFilter
	// CanClear, if non-nil, gates the DELETE /api/admin/audit
	// endpoint. nil means "deny" so a deployment that forgets the
	// wiring fails closed. Bound in main.go to "Global Admin only."
	CanClear func(r *http.Request) bool
}

// NewHandler binds a Handler to s.
func NewHandler(s *Store) *Handler { return &Handler{Store: s} }

// Register wires the read endpoints to mux. mw should be the same
// authenticated-user middleware the rest of the protected API uses; in
// v1 every authenticated user is admin per project_tenancy.md, so any
// auth-resolved user can read. Revisit when roles ship: only Owner
// should retain read access.
func (h *Handler) Register(mux router.Mux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("GET /api/admin/audit", mw(http.HandlerFunc(h.list)))
	mux.Handle("GET /api/admin/audit/{id}", mw(http.HandlerFunc(h.get)))
	mux.Handle("DELETE /api/admin/audit", mw(http.HandlerFunc(h.clear)))
}

// listResponse is the JSON shape returned by GET /api/admin/audit.
// Next.AfterMs / Next.AfterId are the keyset cursor to feed back in as
// ?after_ms=&after_id= for the next page. Next is omitted when the
// current page is the tail of the result set.
type listResponse struct {
	Records []Record `json:"records"`
	Next    *cursor  `json:"next,omitempty"`
}

type cursor struct {
	AfterMillis int64  `json:"afterMs"`
	AfterID     string `json:"afterId"`
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	qs := r.URL.Query()
	q := Query{
		ActorID:     qs.Get("actor_id"),
		ActorLabel:  qs.Get("actor_label"),
		Action:      qs.Get("action"),
		TargetKind:  qs.Get("target_kind"),
		TargetID:    qs.Get("target_id"),
		TargetLabel: qs.Get("target_label"),
		Outcome:     Outcome(qs.Get("outcome")),
		RequestID:   qs.Get("request_id"),
		AfterID:     qs.Get("after_id"),
	}
	if v := qs.Get("since"); v != "" {
		ms, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "since must be integer milliseconds")
			return
		}
		q.Since = time.UnixMilli(ms)
	}
	if v := qs.Get("until"); v != "" {
		ms, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "until must be integer milliseconds")
			return
		}
		q.Until = time.UnixMilli(ms)
	}
	if v := qs.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			writeError(w, http.StatusBadRequest, "limit must be positive integer")
			return
		}
		q.Limit = n
	}
	if v := qs.Get("after_ms"); v != "" {
		ms, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "after_ms must be integer milliseconds")
			return
		}
		q.AfterMillis = ms
	}
	if (q.AfterID == "") != (q.AfterMillis == 0) {
		writeError(w, http.StatusBadRequest, "after_id and after_ms must be set together")
		return
	}
	if h.ScopeFilterFor != nil {
		q.Scope = h.ScopeFilterFor(r)
	}
	recs, hasMore, err := h.Store.ListQuery(q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		slog.Error("audit list", "err", err)
		return
	}
	resp := listResponse{Records: recs}
	if hasMore && len(recs) > 0 {
		last := recs[len(recs)-1]
		resp.Next = &cursor{
			AfterMillis: last.OccurredAt.UnixMilli(),
			AfterID:     last.ID,
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rec, err := h.Store.Get(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "audit record not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get failed")
		// id is user-controlled; slog kv form isn't string-interpolated so
		// gosec G706 is a false positive here.
		slog.Error("audit get", "err", err, "id", id) //nolint:gosec
		return
	}
	// 404 (not 403) for rows the caller can't see, matching the list-
	// endpoint's omission so /api/admin/audit/{id} cannot leak the
	// existence of a row that wouldn't appear in /api/admin/audit.
	if h.ScopeFilterFor != nil {
		if sf := h.ScopeFilterFor(r); sf != nil {
			visible, err := h.Store.IsVisibleTo(rec, *sf)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "visibility check failed")
				slog.Error("audit visibility", "err", err)
				return
			}
			if !visible {
				writeError(w, http.StatusNotFound, "audit record not found")
				return
			}
		}
	}
	writeJSON(w, http.StatusOK, rec)
}

// clearResponse is the JSON shape returned by DELETE /api/admin/audit.
type clearResponse struct {
	RowsDeleted int `json:"rowsDeleted"`
}

// maxOlderThanDays caps the older_than_days query parameter to ten
// years. Anything larger is almost certainly an operator typo and
// behaves identically to truncate-all on any real instance.
const maxOlderThanDays = 3650

func (h *Handler) clear(w http.ResponseWriter, r *http.Request) {
	if h.CanClear == nil || !h.CanClear(r) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	older := 0
	if v := r.URL.Query().Get("older_than_days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxOlderThanDays {
			writeError(w, http.StatusBadRequest, "older_than_days must be an integer between 1 and 3650")
			return
		}
		older = n
	}
	rowsDeleted, err := h.Store.Clear(older)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "clear failed")
		slog.Error("audit clear", "err", err)
		return
	}
	// Drop the action marker AFTER the delete so it survives in the
	// surviving log; rowsDeleted does not count the marker itself.
	detail := Detail{"rows_deleted": rowsDeleted}
	if older > 0 {
		detail["older_than_days"] = older
	}
	if err := h.Store.Log(r.Context(), Event{
		Action:  "audit.clear",
		Outcome: Success,
		Detail:  detail,
	}); err != nil {
		slog.Error("audit clear marker", "err", err)
	}
	writeJSON(w, http.StatusOK, clearResponse{RowsDeleted: rowsDeleted})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("audit json encode", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

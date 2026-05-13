// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

// Handler exposes the read-side audit endpoints. Write happens via
// LogTx / Log from inside other handlers; there is no API to append or
// edit audit rows.
type Handler struct {
	Store *Store
}

// NewHandler binds a Handler to s.
func NewHandler(s *Store) *Handler { return &Handler{Store: s} }

// Register wires the read endpoints to mux. mw should be the same
// authenticated-user middleware the rest of the protected API uses; in
// v1 every authenticated user is admin per project_tenancy.md, so any
// auth-resolved user can read. Revisit when roles ship: only Owner
// should retain read access.
func (h *Handler) Register(mux *http.ServeMux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("GET /api/admin/audit", mw(http.HandlerFunc(h.list)))
	mux.Handle("GET /api/admin/audit/{id}", mw(http.HandlerFunc(h.get)))
}

// listResponse is the JSON shape returned by GET /api/admin/audit.
// Next.AfterMs / Next.AfterId are the keyset cursor to feed back in as
// ?after_ms=&after_id= for the next page. Next is omitted when fewer
// than limit rows were returned (i.e. the end of the result set).
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
		ActorID:    qs.Get("actor_id"),
		Action:     qs.Get("action"),
		TargetKind: qs.Get("target_kind"),
		TargetID:   qs.Get("target_id"),
		Outcome:    Outcome(qs.Get("outcome")),
		AfterID:    qs.Get("after_id"),
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
	recs, err := h.Store.ListQuery(q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		slog.Error("audit list", "err", err)
		return
	}
	resp := listResponse{Records: recs}
	effLimit := q.Limit
	if effLimit <= 0 {
		effLimit = DefaultLimit
	}
	if effLimit > MaxLimit {
		effLimit = MaxLimit
	}
	if len(recs) == effLimit {
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
	writeJSON(w, http.StatusOK, rec)
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

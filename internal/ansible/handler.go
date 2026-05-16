// SPDX-License-Identifier: Apache-2.0

package ansible

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"system-wrangler-backend/internal/router"
	"system-wrangler-backend/internal/systems"
)

// SystemLookup is the slice of systems.Store the handler needs.
// systems.SQLiteStore satisfies it.
type SystemLookup interface {
	Get(id string) (systems.System, error)
}

// Handler exposes operator-facing HTTP affordances backed by the
// ansible Runner. For now: just /test-connection (the ping probe).
// More ad-hoc actions land here as the updater substrate grows.
type Handler struct {
	Runner  *Runner
	Systems SystemLookup

	// CanManageSystem gates every endpoint. Bound to "Global Admin
	// OR Group Admin of sys.GroupID" in main.go, same rule the
	// credentials + hostkeys handlers use.
	CanManageSystem func(ctx context.Context, s systems.System) bool
}

// Register attaches the routes behind mw (the authenticated-user
// middleware).
func (h *Handler) Register(mux router.Mux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("POST /api/systems/{id}/test-connection", mw(http.HandlerFunc(h.testConnection)))
}

// testConnectionDTO is the wire shape of the response. Stdout/stderr
// are not surfaced — the UI only needs the verdict + a one-line
// reason; the audit log carries the full record for forensics.
type testConnectionDTO struct {
	Status     RunStatus `json:"status"`
	Reason     string    `json:"reason"`
	ExitCode   int       `json:"exitCode"`
	DurationMS int64     `json:"durationMs"`
}

func (h *Handler) testConnection(w http.ResponseWriter, r *http.Request) {
	sysID := r.PathValue("id")
	sys, err := h.Systems.Get(sysID)
	if err != nil {
		if errors.Is(err, systems.ErrNotFound) {
			writeError(w, http.StatusNotFound, "system not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		slog.Error("ansible test-connection lookup", "err", err)
		return
	}
	if h.CanManageSystem != nil && !h.CanManageSystem(r.Context(), sys) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if h.Runner == nil {
		writeError(w, http.StatusServiceUnavailable, "test-connection unavailable: runner not configured")
		return
	}
	res, err := h.Runner.Ping(r.Context(), sys.ID)
	if err != nil {
		if errors.Is(err, ErrInvalidRequest) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "ping failed: "+err.Error())
		slog.Error("ansible test-connection ping", "err", err)
		return
	}
	writeJSON(w, http.StatusOK, testConnectionDTO{
		Status:     res.Status,
		Reason:     res.Reason,
		ExitCode:   res.ExitCode,
		DurationMS: res.FinishedAt.Sub(res.StartedAt).Milliseconds(),
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("ansible json encode", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

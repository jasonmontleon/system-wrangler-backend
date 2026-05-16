// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"system-wrangler-backend/internal/ansible"
	"system-wrangler-backend/internal/router"
	"system-wrangler-backend/internal/systems"
)

// SystemLookup is the slice of systems.Store the handler needs.
// systems.SQLiteStore satisfies it.
type SystemLookup interface {
	Get(id string) (systems.System, error)
}

// Handler exposes the system-scoped updater endpoints — inspect,
// check, apply, and the per-system run history. The admin-scoped
// custom-definition CRUD ships in a sibling handler in phase 4.
type Handler struct {
	Runner  *Runner
	Store   Store
	Systems SystemLookup

	// CanOperateSystem gates the three mutating endpoints (inspect,
	// check, apply). Bound to "Global Admin / Global Operator OR
	// Group Admin / Group Operator of sys.GroupID" in main.go.
	CanOperateSystem func(ctx context.Context, s systems.System) bool

	// CanReadSystem gates the run-history endpoint. Bound to the
	// scope-resolved read check so an auditor or operator can see
	// what's happened against the system.
	CanReadSystem func(ctx context.Context, s systems.System) bool
}

// Register attaches the routes behind mw (the authenticated-user
// middleware). The handler is system-scoped; admin endpoints live
// in a separate AdminHandler.
func (h *Handler) Register(mux router.Mux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("POST /api/systems/{id}/inspect", mw(http.HandlerFunc(h.inspect)))
	mux.Handle("POST /api/systems/{id}/updaters/{updater}/check", mw(http.HandlerFunc(h.check)))
	mux.Handle("POST /api/systems/{id}/updaters/{updater}/apply", mw(http.HandlerFunc(h.apply)))
	mux.Handle("GET /api/systems/{id}/updater-runs", mw(http.HandlerFunc(h.listRuns)))
	mux.Handle("GET /api/systems/{id}/updaters", mw(http.HandlerFunc(h.listSystemUpdaters)))
	mux.Handle("PUT /api/systems/{id}/updaters/{updater}/enabled", mw(http.HandlerFunc(h.setEnabled)))
}

// inspectDTO is the wire shape for POST /inspect. RunID lets the SPA
// jump straight to the matching run row; Detected and Removed are
// the reconciled deltas the operator wants on the page.
type inspectDTO struct {
	RunID      string            `json:"runId"`
	Status     ansible.RunStatus `json:"status"`
	ExitCode   int               `json:"exitCode"`
	Reason     string            `json:"reason,omitempty"`
	Detected   []string          `json:"detected"`
	Removed    []string          `json:"removed,omitempty"`
	DurationMS int64             `json:"durationMs"`
}

// runDTO is the wire shape for POST /check and /apply. The integer
// affected count is whatever the playbook surfaced via the
// SW_AFFECTED_COUNT marker; 0 means "did not report."
type runDTO struct {
	RunID         string            `json:"runId"`
	UpdaterID     string            `json:"updaterId"`
	Kind          RunKind           `json:"kind"`
	Status        ansible.RunStatus `json:"status"`
	ExitCode      int               `json:"exitCode"`
	AffectedCount int               `json:"affectedCount"`
	Reason        string            `json:"reason,omitempty"`
	DurationMS    int64             `json:"durationMs"`
}

// systemUpdaterDTO is one row of the per-system updater list — the
// union of every registered updater with this system's detection
// and enablement state. The detail page renders these as a
// checkbox-per-row card.
type systemUpdaterDTO struct {
	UpdaterID   string     `json:"updaterId"`
	Source      Source     `json:"source"`
	DisplayName string     `json:"displayName"`
	Installed   bool       `json:"installed"`
	Enabled     bool       `json:"enabled"`
	LastSeenAt  *time.Time `json:"lastSeenAt,omitempty"`
}

type systemUpdatersResponseDTO struct {
	Updaters []systemUpdaterDTO `json:"updaters"`
}

type setEnabledInputDTO struct {
	Enabled bool `json:"enabled"`
}

// runHistoryDTO is one entry in the runs-list response. The field
// order mirrors Run so the json encoder produces a stable shape
// across releases. Keep them in sync — the conversion in listRuns
// is `runHistoryDTO(run)`, which silently breaks on shape drift.
type runHistoryDTO struct {
	ID            string     `json:"id"`
	SystemID      string     `json:"systemId"`
	UpdaterID     string     `json:"updaterId,omitempty"`
	Kind          RunKind    `json:"kind"`
	StartedAt     time.Time  `json:"startedAt"`
	FinishedAt    *time.Time `json:"finishedAt,omitempty"`
	ExitCode      *int       `json:"exitCode,omitempty"`
	AffectedCount int        `json:"affectedCount"`
	ActorID       string     `json:"actorId,omitempty"`
	PlaybookSHA   string     `json:"playbookSha,omitempty"`
	LogTail       string     `json:"logTail,omitempty"`
}

// runsResponseDTO wraps the runs list under a `runs` key so future
// pagination cursor fields can land additively.
type runsResponseDTO struct {
	Runs []runHistoryDTO `json:"runs"`
}

// conflictDTO surfaces the per-system advisory lock collision shape:
// 409 with the run id of the holder so the SPA can link straight to
// it without a follow-up round trip.
type conflictDTO struct {
	Error          string `json:"error"`
	ConflictingRun string `json:"conflictingRun,omitempty"`
}

func (h *Handler) inspect(w http.ResponseWriter, r *http.Request) {
	sys, ok := h.loadSystem(w, r)
	if !ok {
		return
	}
	if !h.canOperate(r.Context(), sys) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if h.Runner == nil {
		writeError(w, http.StatusServiceUnavailable, "updater runner not configured")
		return
	}
	res, err := h.Runner.Inspect(r.Context(), sys.ID)
	if errors.Is(err, ErrConflict) {
		writeConflict(w, h.Store, sys.ID, "another run is in progress for this system")
		return
	}
	if errors.Is(err, ErrInvalid) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "inspect failed: "+err.Error())
		slog.Error("updaters inspect", "err", err, "system_id", sys.ID)
		return
	}
	dur := int64(0)
	if res.Run.FinishedAt != nil {
		dur = res.Run.FinishedAt.Sub(res.Run.StartedAt).Milliseconds()
	}
	writeJSON(w, http.StatusOK, inspectDTO{
		RunID:      res.Run.ID,
		Status:     res.Status,
		ExitCode:   res.ExitCode,
		Reason:     res.Reason,
		Detected:   res.Detected,
		Removed:    res.Removed,
		DurationMS: dur,
	})
}

func (h *Handler) check(w http.ResponseWriter, r *http.Request) {
	h.runUpdaterEndpoint(w, r, RunKindCheck)
}

func (h *Handler) apply(w http.ResponseWriter, r *http.Request) {
	h.runUpdaterEndpoint(w, r, RunKindApply)
}

func (h *Handler) runUpdaterEndpoint(w http.ResponseWriter, r *http.Request, kind RunKind) {
	sys, ok := h.loadSystem(w, r)
	if !ok {
		return
	}
	if !h.canOperate(r.Context(), sys) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if h.Runner == nil {
		writeError(w, http.StatusServiceUnavailable, "updater runner not configured")
		return
	}
	updaterID := r.PathValue("updater")
	var res RunResult
	var err error
	if kind == RunKindApply {
		res, err = h.Runner.Apply(r.Context(), sys.ID, updaterID)
	} else {
		res, err = h.Runner.Check(r.Context(), sys.ID, updaterID)
	}
	if errors.Is(err, ErrConflict) {
		writeConflict(w, h.Store, sys.ID, "another run is in progress for this system")
		return
	}
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if errors.Is(err, ErrInvalid) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, string(kind)+" failed: "+err.Error())
		slog.Error("updaters run", "err", err, "system_id", sys.ID, "updater_id", updaterID, "kind", kind) //nolint:gosec
		return
	}
	dur := int64(0)
	if res.Run.FinishedAt != nil {
		dur = res.Run.FinishedAt.Sub(res.Run.StartedAt).Milliseconds()
	}
	writeJSON(w, http.StatusOK, runDTO{
		RunID:         res.Run.ID,
		UpdaterID:     res.UpdaterID,
		Kind:          res.Kind,
		Status:        res.Status,
		ExitCode:      res.ExitCode,
		AffectedCount: res.AffectedCount,
		Reason:        res.Reason,
		DurationMS:    dur,
	})
}

func (h *Handler) listRuns(w http.ResponseWriter, r *http.Request) {
	sys, ok := h.loadSystem(w, r)
	if !ok {
		return
	}
	if h.CanReadSystem != nil && !h.CanReadSystem(r.Context(), sys) {
		writeError(w, http.StatusNotFound, "system not found")
		return
	}
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	rows, err := h.Store.ListRuns(sys.ID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list runs failed")
		slog.Error("updaters list runs", "err", err, "system_id", sys.ID)
		return
	}
	out := make([]runHistoryDTO, 0, len(rows))
	for _, run := range rows {
		out = append(out, runHistoryDTO(run))
	}
	writeJSON(w, http.StatusOK, runsResponseDTO{Runs: out})
}

func (h *Handler) listSystemUpdaters(w http.ResponseWriter, r *http.Request) {
	sys, ok := h.loadSystem(w, r)
	if !ok {
		return
	}
	if h.CanReadSystem != nil && !h.CanReadSystem(r.Context(), sys) {
		writeError(w, http.StatusNotFound, "system not found")
		return
	}
	if h.Runner == nil || h.Runner.Registry == nil {
		writeError(w, http.StatusServiceUnavailable, "updater runner not configured")
		return
	}
	defs, err := h.Runner.Registry.All()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list updaters failed")
		slog.Error("updaters list registered", "err", err)
		return
	}
	avail, err := h.Store.AvailabilityFor(sys.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list availability failed")
		slog.Error("updaters availability for", "err", err, "system_id", sys.ID) //nolint:gosec
		return
	}
	byID := make(map[string]Availability, len(avail))
	for _, a := range avail {
		byID[a.UpdaterID] = a
	}
	out := make([]systemUpdaterDTO, 0, len(defs))
	for _, d := range defs {
		row := systemUpdaterDTO{
			UpdaterID:   d.ID,
			Source:      d.Source,
			DisplayName: d.DisplayName,
		}
		if a, found := byID[d.ID]; found {
			row.Installed = true
			row.Enabled = a.Enabled
			row.LastSeenAt = a.LastSeenAt
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, systemUpdatersResponseDTO{Updaters: out})
}

func (h *Handler) setEnabled(w http.ResponseWriter, r *http.Request) {
	sys, ok := h.loadSystem(w, r)
	if !ok {
		return
	}
	if !h.canOperate(r.Context(), sys) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	updaterID := r.PathValue("updater")
	var in setEnabledInputDTO
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := h.Store.SetEnabled(sys.ID, updaterID, in.Enabled); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "updater is not detected on this system; run Inspect first")
			return
		}
		if errors.Is(err, ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "set enabled failed")
		slog.Error("updaters set enabled", "err", err, "system_id", sys.ID, "updater_id", updaterID) //nolint:gosec
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) loadSystem(w http.ResponseWriter, r *http.Request) (systems.System, bool) {
	sysID := r.PathValue("id")
	sys, err := h.Systems.Get(sysID)
	if err != nil {
		if errors.Is(err, systems.ErrNotFound) {
			writeError(w, http.StatusNotFound, "system not found")
			return systems.System{}, false
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		slog.Error("updaters system lookup", "err", err, "system_id", sysID) //nolint:gosec
		return systems.System{}, false
	}
	return sys, true
}

func (h *Handler) canOperate(ctx context.Context, sys systems.System) bool {
	if h.CanOperateSystem == nil {
		return true
	}
	return h.CanOperateSystem(ctx, sys)
}

func writeConflict(w http.ResponseWriter, store Store, systemID, msg string) {
	holder := ""
	if store != nil {
		holder, _ = store.ConflictingRun(systemID)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(conflictDTO{Error: msg, ConflictingRun: holder})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("updaters json encode", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

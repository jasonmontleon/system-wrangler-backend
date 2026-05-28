// SPDX-License-Identifier: Apache-2.0

package systems

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"system-wrangler-backend/internal/labels"
	"system-wrangler-backend/internal/router"
)

// AuditEmitter writes an audit row inside the caller's tx. The systems
// handler invokes it after CreateTx / DeleteTx so the row change and the
// audit row commit together. main.go wires it to audit.Store.LogTx with
// the right action / target shape — this package never imports audit
// directly (audit's own test files already import systems, so a direct
// edge here would cycle the audit test build).
type AuditEmitter func(ctx context.Context, tx *sql.Tx, action string, sys System, detail map[string]any) error

// BulkSkipped is one element of the optional `skipped` array on a
// bulk-event request body — used so the audit row records hosts the
// SPA did not POST against (no operator permission, marked
// unreachable, etc.) alongside the ones it did.
type BulkSkipped struct {
	SystemID string `json:"systemId"`
	Reason   string `json:"reason"`
}

// BulkAuditEmitter writes the single parent audit row for a bulk
// action triggered from the SPA. main.go wires it against
// audit.Store.Log; nil disables the audit write but leaves the
// endpoint reachable (idempotent best-effort log).
type BulkAuditEmitter func(
	ctx context.Context,
	action, selector string,
	systemIDs []string,
	skipped []BulkSkipped,
)

// Handler bundles the HTTP endpoints for systems.
type Handler struct {
	Store Store
	// DB is the shared SQLite handle the handler uses to wrap a
	// state-changing request (create / delete) and its audit row in a
	// single transaction. Optional: tests with MemStore leave it nil
	// and the handler falls back to the non-transactional path.
	DB *sql.DB
	// AuditEmit, if non-nil, is invoked once per successful state-
	// changing request inside the same tx that carried the change.
	// Production wiring in cmd/server/main.go supplies it; MemStore
	// tests omit it.
	AuditEmit AuditEmitter
	// OnCreate fires after a successful create. Optional; nil is skipped.
	// Wired to (a) the probe Trigger so a freshly-added system is probed
	// within seconds instead of after a full Interval, and (b) the event
	// hub so SPAs see new systems without manual refresh.
	OnCreate func()
	// OnDelete fires after a successful delete. Optional; same wiring
	// purpose for SPA refresh.
	OnDelete func()
	// VisibleSystem, if non-nil, filters the result of GET /api/systems
	// and gates GET /api/systems/{id} so a caller without read
	// permission sees an empty list / a 404. Returning true means "the
	// caller may see this row." Wired by main.go against rbac so this
	// package doesn't import rbac (which already imports systems via
	// the groups → systems chain).
	VisibleSystem func(ctx context.Context, s System) bool
	// CanCreate, if non-nil, gates POST /api/systems. Returns false →
	// 403. nil disables the check (test/legacy callers without rbac).
	CanCreate func(ctx context.Context) bool
	// CanDelete, if non-nil, gates DELETE /api/systems/{id}. The
	// handler resolves the system before the gate so the caller's
	// permission can depend on the system's current group_id (Group
	// Admin can delete only systems in groups they admin). nil
	// disables the check.
	CanDelete func(ctx context.Context, s System) bool
	// CanEdit, if non-nil, gates non-membership attribute mutations on
	// the system row (currently: PUT /api/systems/{id}/platform). Same
	// resolve-then-gate shape as CanDelete so the predicate can read the
	// row's current group_id.
	CanEdit func(ctx context.Context, s System) bool
	// SystemStats, if non-nil, is called once per list / get request
	// and its result merged into the System rows the handler
	// serializes — populating LastCheckedAt and PendingUpdates from
	// the updater store. Failure is logged and shape-preserving:
	// the rows simply lack those fields on the wire, matching the
	// "never run" empty state.
	SystemStats func() (map[string]Stats, error)
	// SystemLabels, if non-nil, bulk-loads the labels attached to the
	// supplied system IDs and is merged into the System rows the
	// handler serializes. Same shape-preservation contract as
	// SystemStats: a failure is logged and rows go out without the
	// Labels field rather than the handler 500'ing.
	SystemLabels func(ids []string) (map[string][]labels.Label, error)
	// BulkAudit, if non-nil, fires once per /api/systems/bulk-event
	// call to record the operator's intent before the SPA fans out
	// individual updater actions. Best-effort: a nil hook just
	// short-circuits the audit write — the endpoint still 204s.
	BulkAudit BulkAuditEmitter
}

// NewHandler constructs a Handler bound to the given Store. The optional
// OnCreate / OnDelete callbacks can be set on the returned value.
func NewHandler(s Store) *Handler { return &Handler{Store: s} }

// Register attaches /api/systems routes to the given mux. Each handler is
// wrapped in mw before registration so callers can apply auth (or any other
// per-route middleware) without exposing the handler methods.
func (h *Handler) Register(mux router.Mux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("GET /api/systems", mw(http.HandlerFunc(h.list)))
	mux.Handle("POST /api/systems", mw(http.HandlerFunc(h.create)))
	mux.Handle("POST /api/systems/bulk-event", mw(http.HandlerFunc(h.bulkEvent)))
	mux.Handle("GET /api/systems/{id}", mw(http.HandlerFunc(h.get)))
	mux.Handle("DELETE /api/systems/{id}", mw(http.HandlerFunc(h.delete)))
	mux.Handle("PUT /api/systems/{id}/platform", mw(http.HandlerFunc(h.setPlatform)))
}

// bulkEvent records the operator's intent to fan an action out across
// a set of systems. The actual updater runs still flow through the
// per-system endpoints; this row is the parent the audit reader uses
// to recognise a fleet-wide event without scanning every child row.
// No RBAC gate beyond authentication — the per-system endpoints
// enforce who can actually operate each host.
func (h *Handler) bulkEvent(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action    string        `json:"action"`
		Selector  string        `json:"selector"`
		SystemIDs []string      `json:"systemIds"`
		Skipped   []BulkSkipped `json:"skipped"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	switch body.Action {
	case "check", "apply":
		// ok
	default:
		writeError(w, http.StatusBadRequest, "action must be one of: check, apply")
		return
	}
	if len(body.SystemIDs) == 0 {
		writeError(w, http.StatusBadRequest, "systemIds is required")
		return
	}
	if h.BulkAudit != nil {
		h.BulkAudit(r.Context(), body.Action, body.Selector, body.SystemIDs, body.Skipped)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	// Parse ?labels= up front so a malformed selector is rejected
	// before we hit the store.
	var sel labels.Selector
	if raw := r.URL.Query().Get("labels"); raw != "" {
		parsed, err := labels.ParseSelector(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid labels selector: "+err.Error())
			return
		}
		sel = parsed
	}
	rows, err := h.Store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		slog.Error("systems list", "err", err)
		return
	}
	// Apply the per-row scope filter when wired. Tests without a filter
	// see every row, matching the pre-RBAC behavior.
	if h.VisibleSystem != nil {
		ctx := r.Context()
		filtered := rows[:0]
		for _, s := range rows {
			if h.VisibleSystem(ctx, s) {
				filtered = append(filtered, s)
			}
		}
		rows = filtered
	}
	h.enrichLabels(rows)
	if len(sel) > 0 {
		filtered := rows[:0]
		for _, s := range rows {
			if sel.Matches(s.Labels) {
				filtered = append(filtered, s)
			}
		}
		rows = filtered
	}
	h.enrichStats(rows)
	writeJSON(w, http.StatusOK, rows)
}

// enrichLabels merges the SystemLabels bulk-fetch result into the
// supplied rows in place. Same absorb-on-failure semantics as
// enrichStats: a producer-side failure is logged and rows go out
// without the Labels field rather than the handler 500'ing.
func (h *Handler) enrichLabels(rows []System) {
	if h.SystemLabels == nil || len(rows) == 0 {
		return
	}
	ids := make([]string, len(rows))
	for i, s := range rows {
		ids[i] = s.ID
	}
	got, err := h.SystemLabels(ids)
	if err != nil {
		slog.Warn("systems: labels fetch failed", "err", err)
		return
	}
	for i := range rows {
		if ls, ok := got[rows[i].ID]; ok {
			rows[i].Labels = ls
		}
	}
}

// enrichStats merges the injected SystemStats result into the
// supplied slice in place. Missing keys are left as nil pointers —
// "Last checked: Never" semantics in the SPA. A producer-side
// failure is logged and absorbed: the API never refuses to serve
// systems because updater stats are unavailable.
func (h *Handler) enrichStats(rows []System) {
	if h.SystemStats == nil || len(rows) == 0 {
		return
	}
	stats, err := h.SystemStats()
	if err != nil {
		slog.Warn("systems: stats fetch failed", "err", err)
		return
	}
	for i := range rows {
		s, ok := stats[rows[i].ID]
		if !ok {
			continue
		}
		rows[i].LastCheckedAt = s.LastCheckedAt
		pu := s.PendingUpdates
		rows[i].PendingUpdates = &pu
		rows[i].PendingPackages = s.PendingPackages
		rows[i].LastRunFailed = s.LastRunFailed
		rows[i].LastRunReason = s.LastRunReason
		rows[i].Running = s.Running
	}
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	if h.CanCreate != nil && !h.CanCreate(r.Context()) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	var in SystemInput
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	sys, err := h.createWithAudit(r.Context(), in)
	if err != nil {
		if errors.Is(err, ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "create failed")
		slog.Error("systems create", "err", err)
		return
	}
	if h.OnCreate != nil {
		h.OnCreate()
	}
	w.Header().Set("Location", "/api/systems/"+sys.ID)
	writeJSON(w, http.StatusCreated, sys)
}

// createWithAudit lands the new system row and an `system.create` audit row
// in the same transaction when DB + AuditEmit are wired. Tests using
// MemStore leave both nil; the fallback path just calls Store.Create
// without an audit row.
func (h *Handler) createWithAudit(ctx context.Context, in SystemInput) (System, error) {
	if h.DB == nil || h.AuditEmit == nil {
		return h.Store.Create(in)
	}
	tx, err := h.DB.BeginTx(ctx, nil)
	if err != nil {
		return System{}, err
	}
	defer func() { _ = tx.Rollback() }()
	sys, err := h.Store.CreateTx(tx, in)
	if err != nil {
		return System{}, err
	}
	if err := h.AuditEmit(ctx, tx, "system.create", sys, map[string]any{
		"name":     sys.Name,
		"hostname": sys.Hostname,
	}); err != nil {
		return System{}, err
	}
	if err := tx.Commit(); err != nil {
		return System{}, err
	}
	return sys, nil
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sys, err := h.Store.Get(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "system not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get failed")
		// id is user-controlled but slog's structured kv form doesn't
		// interpolate it into the message — gosec G706 false positive.
		slog.Error("systems get", "err", err, "id", id) //nolint:gosec
		return
	}
	// 404 (not 403) for systems the caller can't see — leaks no
	// information about whether the system exists.
	if h.VisibleSystem != nil && !h.VisibleSystem(r.Context(), sys) {
		writeError(w, http.StatusNotFound, "system not found")
		return
	}
	out := []System{sys}
	h.enrichLabels(out)
	h.enrichStats(out)
	writeJSON(w, http.StatusOK, out[0])
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// Resolve the system first so the CanDelete gate can decide on the
	// row's current group_id (Global Admin always; Group Admin only if
	// the system is in one of their groups). A 404 from the gate hides
	// the system's existence from callers who can't read it; a 403
	// from the gate is reserved for "exists but you can't touch it,"
	// which leaks nothing the read gate doesn't already permit.
	sys, err := h.Store.Get(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "system not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete lookup failed")
		slog.Error("systems delete lookup", "err", err, "id", id) //nolint:gosec
		return
	}
	if h.VisibleSystem != nil && !h.VisibleSystem(r.Context(), sys) {
		writeError(w, http.StatusNotFound, "system not found")
		return
	}
	if h.CanDelete != nil && !h.CanDelete(r.Context(), sys) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := h.deleteWithAudit(r.Context(), sys); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "system not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete failed")
		// See comment in get(): structured kv slog isn't G706-vulnerable.
		slog.Error("systems delete", "err", err, "id", id) //nolint:gosec
		return
	}
	if h.OnDelete != nil {
		h.OnDelete()
	}
	w.WriteHeader(http.StatusNoContent)
}

// deleteWithAudit removes the system row and emits a `system.delete`
// audit row in one transaction when DB + AuditEmit are wired. The
// label/group_id are read from the already-resolved sys so the audit
// row reads naturally even if the row is gone by the time the
// audit-log reader looks.
func (h *Handler) deleteWithAudit(ctx context.Context, sys System) error {
	if h.DB == nil || h.AuditEmit == nil {
		return h.Store.Delete(sys.ID)
	}
	tx, err := h.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := h.Store.DeleteTx(tx, sys.ID); err != nil {
		return err
	}
	detail := map[string]any{}
	if sys.GroupID != nil {
		detail["group_id"] = *sys.GroupID
	}
	if err := h.AuditEmit(ctx, tx, "system.delete", sys, detail); err != nil {
		return err
	}
	return tx.Commit()
}

// setPlatform handles PUT /api/systems/{id}/platform with body
// {"isWindows": bool} — flips the operator-declared platform flag the
// inventory writer and Ping module-selector branch on. Same
// resolve-then-gate flow as delete (404 for invisible systems, 403 for
// visible-but-locked).
func (h *Handler) setPlatform(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		IsWindows bool `json:"isWindows"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	sys, err := h.Store.Get(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "system not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "platform lookup failed")
		slog.Error("systems setPlatform lookup", "err", err, "id", id) //nolint:gosec
		return
	}
	if h.VisibleSystem != nil && !h.VisibleSystem(r.Context(), sys) {
		writeError(w, http.StatusNotFound, "system not found")
		return
	}
	if h.CanEdit != nil && !h.CanEdit(r.Context(), sys) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := h.setPlatformWithAudit(r.Context(), sys, body.IsWindows); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "system not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "set platform failed")
		slog.Error("systems setPlatform", "err", err, "id", id) //nolint:gosec
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// setPlatformWithAudit wraps the mutation and a system.platform.set
// audit row in one transaction when DB + AuditEmit are wired. The
// MemStore-only test path (DB nil) just calls SetPlatform directly.
func (h *Handler) setPlatformWithAudit(ctx context.Context, sys System, isWindows bool) error {
	if h.DB == nil || h.AuditEmit == nil {
		return h.Store.SetPlatform(sys.ID, isWindows)
	}
	tx, err := h.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := h.Store.SetPlatformTx(tx, sys.ID, isWindows); err != nil {
		return err
	}
	sys.IsWindows = isWindows
	if err := h.AuditEmit(ctx, tx, "system.platform.set", sys, map[string]any{
		"is_windows": isWindows,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("systems json encode", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

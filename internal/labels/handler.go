// SPDX-License-Identifier: Apache-2.0

package labels

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"system-wrangler-backend/internal/router"
)

// SystemRef is the minimal slice of a system row the labels handler
// needs for RBAC checks + audit row composition. Defined here so the
// labels package stays free of an import on internal/systems — that
// edge would form a cycle, since systems imports this package for the
// Label type on System.
type SystemRef struct {
	ID      string
	Name    string
	GroupID *string
}

// ErrSystemNotFound is the sentinel a LookupSystem implementation
// returns when the system_id has no row. The handler maps it to 404.
var ErrSystemNotFound = errors.New("system not found")

// LookupSystem resolves a system_id to the small projection the
// handler needs. main.go wires this to systems.Store.Get and translates
// the resulting systems.System into SystemRef.
type LookupSystem func(id string) (SystemRef, error)

// AuditFunc is the abstract audit-logging callback the handler invokes
// on every successful mutation. Defined here as a closure (rather than
// importing audit.Store directly) so the labels package stays free of
// an audit import — that edge cycles in tests because audit's own
// test files import systems, which now imports labels.
type AuditFunc func(ctx context.Context, action string, sys SystemRef, key string, value *string)

// StyleAuditFunc is the audit-logging callback for global style
// changes (the override row is keyed by label key, not by system, so
// the audit row's target shape differs from the per-system AuditFunc).
type StyleAuditFunc func(ctx context.Context, action, key, color string)

// Handler bundles the HTTP endpoints for system labels. The labels
// package owns these routes (rather than systems) because the label
// schema, parser, and validation live here; the handler reaches into
// systems indirectly via LookupSystem to avoid the import cycle.
type Handler struct {
	Labels Store
	// Styles, if non-nil, is the persistence backing for the global
	// label-color overrides on /api/label-styles. nil disables those
	// routes (the SPA falls back to deterministic hash coloring).
	Styles StyleStore
	// Lookup resolves a system_id to its SystemRef. Required for the
	// per-system endpoints; nil is acceptable for tests that drive
	// only the /api/labels summary handler.
	Lookup LookupSystem
	// Audit, if non-nil, is invoked once per successful state-changing
	// request. main.go wires this against audit.Store; tests can pass
	// a recording closure to assert audit shape without spinning up a
	// real audit store.
	Audit AuditFunc
	// StyleAudit, if non-nil, fires on PUT/DELETE of a label style.
	// Separate hook from Audit because the audit-row target is a label
	// key, not a system.
	StyleAudit StyleAuditFunc
	// OnChange fires after any mutation so the events hub can poke
	// SSE-connected SPAs. Optional; nil is a no-op.
	OnChange func()
	// VisibleSystem, if non-nil, gates GET /api/systems/{id}/labels
	// against the caller's RBAC scope. A caller with no read access to
	// the system gets 404, matching the systems handler's "leak no
	// existence" rule.
	VisibleSystem func(ctx context.Context, s SystemRef) bool
	// CanEditSystem, if non-nil, gates the write endpoints (PUT/DELETE
	// label-key). Same resolve-then-gate flow as systems' platform
	// edit.
	CanEditSystem func(ctx context.Context, s SystemRef) bool
	// CanManageStyles, if non-nil, gates PUT/DELETE on
	// /api/label-styles. Global Admin only — color overrides are
	// fleet-wide visual state, not a per-group editable.
	CanManageStyles func(ctx context.Context) bool
}

// NewHandler constructs a Handler bound to the given label store. The
// Lookup callback must be set before serving per-system endpoints.
func NewHandler(labels Store) *Handler {
	return &Handler{Labels: labels}
}

// Register attaches /api/labels and /api/systems/{id}/labels routes to
// the given mux. Each handler is wrapped in mw so callers can apply
// auth + rbac middleware without touching the handler methods.
func (h *Handler) Register(mux router.Mux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("GET /api/labels", mw(http.HandlerFunc(h.summary)))
	mux.Handle("GET /api/systems/{id}/labels", mw(http.HandlerFunc(h.list)))
	mux.Handle("PUT /api/systems/{id}/labels/{key}", mw(http.HandlerFunc(h.set)))
	mux.Handle("DELETE /api/systems/{id}/labels/{key}", mw(http.HandlerFunc(h.delete)))
	if h.Styles != nil {
		mux.Handle("GET /api/label-styles", mw(http.HandlerFunc(h.listStyles)))
		mux.Handle("PUT /api/label-styles/{key}", mw(http.HandlerFunc(h.setStyle)))
		mux.Handle("DELETE /api/label-styles/{key}", mw(http.HandlerFunc(h.deleteStyle)))
	}
}

func (h *Handler) listStyles(w http.ResponseWriter, _ *http.Request) {
	all, err := h.Styles.All()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list styles failed")
		slog.Error("labels listStyles", "err", err)
		return
	}
	writeJSON(w, http.StatusOK, all)
}

func (h *Handler) setStyle(w http.ResponseWriter, r *http.Request) {
	if h.CanManageStyles != nil && !h.CanManageStyles(r.Context()) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	key := r.PathValue("key")
	if err := ValidateKey(key, true); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var body struct {
		Color string `json:"color"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if err := ValidateColor(body.Color); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.Styles.Set(key, body.Color); err != nil {
		writeError(w, http.StatusInternalServerError, "set style failed")
		slog.Error("labels setStyle", "err", err, "key", key) //nolint:gosec
		return
	}
	if h.StyleAudit != nil {
		h.StyleAudit(r.Context(), "label_style.set", key, body.Color)
	}
	h.fireChange()
	writeJSON(w, http.StatusOK, LabelStyle{Key: key, Color: body.Color})
}

func (h *Handler) deleteStyle(w http.ResponseWriter, r *http.Request) {
	if h.CanManageStyles != nil && !h.CanManageStyles(r.Context()) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	key := r.PathValue("key")
	if err := h.Styles.Delete(key); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "style not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete style failed")
		slog.Error("labels deleteStyle", "err", err, "key", key) //nolint:gosec
		return
	}
	if h.StyleAudit != nil {
		h.StyleAudit(r.Context(), "label_style.delete", key, "")
	}
	h.fireChange()
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) summary(w http.ResponseWriter, _ *http.Request) {
	out, err := h.Labels.Summary()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "summary failed")
		slog.Error("labels summary", "err", err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	sys, ok := h.resolveSystem(w, r)
	if !ok {
		return
	}
	out, err := h.Labels.ForSystem(sys.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		slog.Error("labels list", "err", err, "system_id", sys.ID) //nolint:gosec
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) set(w http.ResponseWriter, r *http.Request) {
	sys, ok := h.resolveSystemForEdit(w, r)
	if !ok {
		return
	}
	key := r.PathValue("key")
	var in Input
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	got, err := h.Labels.Set(sys.ID, key, in.Value, false)
	if err != nil {
		switch {
		case errors.Is(err, ErrReserved):
			writeError(w, http.StatusForbidden, err.Error())
		case errors.Is(err, ErrInvalid):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, ErrNotFound):
			writeError(w, http.StatusNotFound, "system not found")
		default:
			writeError(w, http.StatusInternalServerError, "set failed")
			slog.Error("labels set", "err", err, "system_id", sys.ID, "key", key) //nolint:gosec
		}
		return
	}
	if h.Audit != nil {
		h.Audit(r.Context(), "system.label.set", sys, key, in.Value)
	}
	h.fireChange()
	writeJSON(w, http.StatusOK, got)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	sys, ok := h.resolveSystemForEdit(w, r)
	if !ok {
		return
	}
	key := r.PathValue("key")
	if err := h.Labels.Delete(sys.ID, key); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "label not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete failed")
		slog.Error("labels delete", "err", err, "system_id", sys.ID, "key", key) //nolint:gosec
		return
	}
	if h.Audit != nil {
		h.Audit(r.Context(), "system.label.delete", sys, key, nil)
	}
	h.fireChange()
	w.WriteHeader(http.StatusNoContent)
}

// resolveSystem looks up the system for a read endpoint and writes
// 404/500 as appropriate. Returns (ref, true) on success.
func (h *Handler) resolveSystem(w http.ResponseWriter, r *http.Request) (SystemRef, bool) {
	id := r.PathValue("id")
	if h.Lookup == nil {
		writeError(w, http.StatusInternalServerError, "lookup not wired")
		slog.Error("labels handler: Lookup is nil")
		return SystemRef{}, false
	}
	sys, err := h.Lookup(id)
	if err != nil {
		if errors.Is(err, ErrSystemNotFound) {
			writeError(w, http.StatusNotFound, "system not found")
			return SystemRef{}, false
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		slog.Error("labels system lookup", "err", err, "id", id) //nolint:gosec
		return SystemRef{}, false
	}
	if h.VisibleSystem != nil && !h.VisibleSystem(r.Context(), sys) {
		writeError(w, http.StatusNotFound, "system not found")
		return SystemRef{}, false
	}
	return sys, true
}

// resolveSystemForEdit applies both VisibleSystem (404 on miss) and
// CanEditSystem (403 on miss) before returning the row.
func (h *Handler) resolveSystemForEdit(w http.ResponseWriter, r *http.Request) (SystemRef, bool) {
	sys, ok := h.resolveSystem(w, r)
	if !ok {
		return SystemRef{}, false
	}
	if h.CanEditSystem != nil && !h.CanEditSystem(r.Context(), sys) {
		writeError(w, http.StatusForbidden, "forbidden")
		return SystemRef{}, false
	}
	return sys, true
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
		slog.Error("labels json encode", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

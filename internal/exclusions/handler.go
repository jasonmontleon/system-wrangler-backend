// SPDX-License-Identifier: Apache-2.0

package exclusions

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/router"
)

// Handler bundles the package-exclusions HTTP endpoints. All write
// endpoints emit `package_exclusion.{create,delete}` audit rows. RBAC
// is enforced through the CanManage* callbacks main.go binds against
// rbac so this package doesn't import rbac. The CanRead/CanManage
// callbacks for system scope take a systemID and do their own
// resolution against the systems store.
type Handler struct {
	Store Store

	// Audit, when non-nil, receives an audit row per state-changing
	// request.
	Audit *audit.Store

	// CanManageGlobal gates /api/admin/package-exclusions writes.
	// Global Admin only per research/package-exclusions.md.
	CanManageGlobal func(ctx context.Context) bool
	// CanReadGroup gates /api/groups/{groupId}/package-exclusions
	// reads. Anyone with read access to the group.
	CanReadGroup func(ctx context.Context, groupID string) bool
	// CanManageGroup gates /api/groups/{groupId}/package-exclusions
	// writes. Group Admin / Global Admin.
	CanManageGroup func(ctx context.Context, groupID string) bool
	// CanReadSystem gates /api/systems/{systemId}/package-exclusions
	// reads. Anyone with read access to the system's group.
	CanReadSystem func(ctx context.Context, systemID string) bool
	// CanManageSystem gates /api/systems/{systemId}/package-exclusions
	// writes. Group Operator+ on the system's group / Global Operator+.
	CanManageSystem func(ctx context.Context, systemID string) bool
}

// Register attaches the package-exclusions routes to the given mux.
func (h *Handler) Register(mux router.Mux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	// Global scope (Admin → Exclusions UI). The outer path parameter
	// is the inner exclusion id — global rows have no enclosing
	// resource to qualify.
	mux.Handle("GET /api/admin/package-exclusions", mw(http.HandlerFunc(h.listGlobal)))
	mux.Handle("POST /api/admin/package-exclusions", mw(http.HandlerFunc(h.createGlobal)))
	mux.Handle("DELETE /api/admin/package-exclusions/{id}", mw(http.HandlerFunc(h.deleteGlobal)))
	// Group scope (Group Detail → Exclusions tab). The outer {id} is
	// the group id; the inner exclusion id is {exclusionId} so the
	// route parses unambiguously.
	mux.Handle("GET /api/groups/{id}/package-exclusions", mw(http.HandlerFunc(h.listGroup)))
	mux.Handle("POST /api/groups/{id}/package-exclusions", mw(http.HandlerFunc(h.createGroup)))
	mux.Handle("DELETE /api/groups/{id}/package-exclusions/{exclusionId}", mw(http.HandlerFunc(h.deleteGroup)))
	// System scope (System Detail → Updates tab card). Same outer/inner
	// naming as the group routes.
	mux.Handle("GET /api/systems/{id}/package-exclusions", mw(http.HandlerFunc(h.listSystem)))
	mux.Handle("POST /api/systems/{id}/package-exclusions", mw(http.HandlerFunc(h.createSystem)))
	mux.Handle("DELETE /api/systems/{id}/package-exclusions/{exclusionId}", mw(http.HandlerFunc(h.deleteSystem)))
	mux.Handle("GET /api/systems/{id}/package-exclusions/effective", mw(http.HandlerFunc(h.effectiveSystem)))
}

func (h *Handler) listGlobal(w http.ResponseWriter, _ *http.Request) {
	rows, err := h.Store.ListGlobal()
	if err != nil {
		h.serverError(w, "list global exclusions", err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (h *Handler) createGlobal(w http.ResponseWriter, r *http.Request) {
	if !gateAllows(r.Context(), h.CanManageGlobal) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	h.createScope(w, r, ScopeGlobal, "")
}

func (h *Handler) deleteGlobal(w http.ResponseWriter, r *http.Request) {
	if !gateAllows(r.Context(), h.CanManageGlobal) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	h.deleteWithGuard(w, r, r.PathValue("id"), ScopeGlobal, "")
}

func (h *Handler) listGroup(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")
	if h.CanReadGroup != nil && !h.CanReadGroup(r.Context(), groupID) {
		writeError(w, http.StatusNotFound, "group not found")
		return
	}
	rows, err := h.Store.ListGroup(groupID)
	if err != nil {
		h.serverError(w, "list group exclusions", err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (h *Handler) createGroup(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")
	if h.CanManageGroup != nil && !h.CanManageGroup(r.Context(), groupID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	h.createScope(w, r, ScopeGroup, groupID)
}

func (h *Handler) deleteGroup(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")
	if h.CanManageGroup != nil && !h.CanManageGroup(r.Context(), groupID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	h.deleteWithGuard(w, r, r.PathValue("exclusionId"), ScopeGroup, groupID)
}

func (h *Handler) listSystem(w http.ResponseWriter, r *http.Request) {
	systemID := r.PathValue("id")
	if h.CanReadSystem != nil && !h.CanReadSystem(r.Context(), systemID) {
		writeError(w, http.StatusNotFound, "system not found")
		return
	}
	rows, err := h.Store.ListSystem(systemID)
	if err != nil {
		h.serverError(w, "list system exclusions", err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (h *Handler) createSystem(w http.ResponseWriter, r *http.Request) {
	systemID := r.PathValue("id")
	if h.CanManageSystem != nil && !h.CanManageSystem(r.Context(), systemID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	h.createScope(w, r, ScopeSystem, systemID)
}

func (h *Handler) deleteSystem(w http.ResponseWriter, r *http.Request) {
	systemID := r.PathValue("id")
	if h.CanManageSystem != nil && !h.CanManageSystem(r.Context(), systemID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	h.deleteWithGuard(w, r, r.PathValue("exclusionId"), ScopeSystem, systemID)
}

func (h *Handler) effectiveSystem(w http.ResponseWriter, r *http.Request) {
	systemID := r.PathValue("id")
	if h.CanReadSystem != nil && !h.CanReadSystem(r.Context(), systemID) {
		writeError(w, http.StatusNotFound, "system not found")
		return
	}
	updater := r.URL.Query().Get("updater")
	if updater == "" {
		writeError(w, http.StatusBadRequest, "updater query parameter required")
		return
	}
	rows, err := h.Store.ResolveEffectiveForSystem(systemID, updater)
	if err != nil {
		if errors.Is(err, ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		h.serverError(w, "resolve effective exclusions", err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// createScope is the shared body of every POST endpoint. The route
// fixes scope + targetID so the body can't smuggle a row into the
// wrong layer.
func (h *Handler) createScope(w http.ResponseWriter, r *http.Request, scope Scope, targetID string) {
	var in Input
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if err := in.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor := actorIDFromCtx(r.Context())
	if actor == "" {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	row, err := h.Store.Create(scope, targetID, in.Updater, in.Pattern, in.Reason, actor)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalid):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, ErrDuplicate):
			writeError(w, http.StatusConflict, err.Error())
		default:
			h.serverError(w, "create exclusion", err)
		}
		return
	}
	h.logAudit(r.Context(), audit.Event{
		Action:     "package_exclusion.create",
		Outcome:    audit.Success,
		TargetKind: "package_exclusion",
		TargetID:   row.ID,
		Detail: audit.Detail{
			"scope":     string(row.Scope),
			"target_id": row.TargetID,
			"updater":   row.Updater,
			"pattern":   row.Pattern,
		},
	})
	w.Header().Set("Location", row.locationFor(scope, targetID))
	writeJSON(w, http.StatusCreated, row)
}

// deleteWithGuard refuses to delete a row that belongs to a different
// scope or target than the route addresses — so a /api/groups/{a}/...
// caller can't reach into group {b}'s rows just by guessing an id.
func (h *Handler) deleteWithGuard(w http.ResponseWriter, r *http.Request, id string, scope Scope, targetID string) {
	row, err := h.Store.Get(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "exclusion not found")
			return
		}
		h.serverError(w, "load exclusion", err)
		return
	}
	if row.Scope != scope || row.TargetID != targetID {
		// Hide cross-scope mismatch as 404 — leaks no info about
		// whether the id is real on another layer.
		writeError(w, http.StatusNotFound, "exclusion not found")
		return
	}
	if err := h.Store.Delete(id); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "exclusion not found")
			return
		}
		h.serverError(w, "delete exclusion", err)
		return
	}
	h.logAudit(r.Context(), audit.Event{
		Action:     "package_exclusion.delete",
		Outcome:    audit.Success,
		TargetKind: "package_exclusion",
		TargetID:   row.ID,
		Detail: audit.Detail{
			"scope":     string(row.Scope),
			"target_id": row.TargetID,
			"updater":   row.Updater,
			"pattern":   row.Pattern,
		},
	})
	w.WriteHeader(http.StatusNoContent)
}

func (e Exclusion) locationFor(scope Scope, targetID string) string {
	switch scope {
	case ScopeGroup:
		return "/api/groups/" + targetID + "/package-exclusions/" + e.ID
	case ScopeSystem:
		return "/api/systems/" + targetID + "/package-exclusions/" + e.ID
	default:
		return "/api/admin/package-exclusions/" + e.ID
	}
}

func (h *Handler) logAudit(ctx context.Context, e audit.Event) {
	if h.Audit == nil {
		return
	}
	if err := h.Audit.Log(ctx, e); err != nil {
		slog.Error("exclusions audit log", "err", err, "action", e.Action)
	}
}

func (h *Handler) serverError(w http.ResponseWriter, op string, err error) {
	slog.Error("exclusions: "+op, "err", err)
	writeError(w, http.StatusInternalServerError, op+" failed")
}

func gateAllows(ctx context.Context, gate func(context.Context) bool) bool {
	if gate == nil {
		return true
	}
	return gate(ctx)
}

func actorIDFromCtx(ctx context.Context) string {
	return audit.ActorFromContext(ctx).ID
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("exclusions json encode", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

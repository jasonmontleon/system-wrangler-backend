// SPDX-License-Identifier: Apache-2.0

package hostkeys

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/auth"
	"system-wrangler-backend/internal/router"
	"system-wrangler-backend/internal/systems"
)

// SystemLookup is the slice of systems.Store the handler needs.
// systems.SQLiteStore satisfies it.
type SystemLookup interface {
	Get(id string) (systems.System, error)
}

// Handler exposes the host-keys HTTP API. RBAC + audit are wired
// from main.go via callbacks / fields so this package stays
// independent of rbac.
type Handler struct {
	Store   Store
	Systems SystemLookup
	Audit   *audit.Store

	// Executor is wired to the same instance the ansible Runner
	// uses (ansible.ExecExecutor in production). Required for the
	// scan endpoint; nil disables it (the endpoint returns 503).
	Executor Executor

	// CanManageSystem gates every endpoint. Bound to "Global Admin
	// OR Group Admin of sys.GroupID" in main.go, matching the rule
	// used by the credentials handler for the same scope.
	CanManageSystem func(ctx context.Context, s systems.System) bool
}

// Register wires the routes behind mw (the authenticated-user
// middleware). Per the design doc:
//
//	GET    /api/systems/{id}/host-keys
//	POST   /api/systems/{id}/host-keys/accept
//	DELETE /api/systems/{id}/host-keys/{keyId}
func (h *Handler) Register(mux router.Mux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("GET /api/systems/{id}/host-keys", mw(http.HandlerFunc(h.list)))
	mux.Handle("POST /api/systems/{id}/host-keys/scan", mw(http.HandlerFunc(h.scan)))
	mux.Handle("POST /api/systems/{id}/host-keys/accept", mw(http.HandlerFunc(h.accept)))
	mux.Handle("DELETE /api/systems/{id}/host-keys/{keyId}", mw(http.HandlerFunc(h.delete)))
}

// hostKeyDTO is the public JSON shape. AcceptedBy is the user_id of
// the operator who clicked Accept; the UI hydrates the username
// from /api/admin/users if needed.
type hostKeyDTO struct {
	ID          string  `json:"id"`
	SystemID    string  `json:"systemId"`
	State       State   `json:"state"`
	Algorithm   string  `json:"algorithm"`
	PublicKey   string  `json:"publicKey"`
	Fingerprint string  `json:"fingerprint"`
	FirstSeenAt string  `json:"firstSeenAt"`
	AcceptedAt  *string `json:"acceptedAt,omitempty"`
	AcceptedBy  string  `json:"acceptedBy,omitempty"`
}

func toDTO(hk HostKey) hostKeyDTO {
	dto := hostKeyDTO{
		ID:          hk.ID,
		SystemID:    hk.SystemID,
		State:       hk.State,
		Algorithm:   hk.Algorithm,
		PublicKey:   hk.PublicKey,
		Fingerprint: hk.Fingerprint,
		FirstSeenAt: hk.FirstSeenAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		AcceptedBy:  hk.AcceptedBy,
	}
	if hk.AcceptedAt != nil {
		s := hk.AcceptedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")
		dto.AcceptedAt = &s
	}
	return dto
}

type acceptRequest struct {
	Algorithm   string `json:"algorithm"`
	Fingerprint string `json:"fingerprint"`
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	sys, ok := h.resolveSystem(w, r)
	if !ok {
		return
	}
	if h.CanManageSystem != nil && !h.CanManageSystem(r.Context(), sys) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	keys, err := h.Store.List(sys.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		slog.Error("hostkeys list", "err", err)
		return
	}
	out := make([]hostKeyDTO, 0, len(keys))
	for _, k := range keys {
		out = append(out, toDTO(k))
	}
	writeJSON(w, http.StatusOK, map[string]any{"hostKeys": out})
}

// scan invokes ssh-keyscan against the system's hostname and
// records each offered key as `pending`. The operator-facing
// affordance for "I just added this system; capture its host
// keys now without waiting for an ansible run." Emits one
// `system.host_key.pending` audit row per recorded key.
func (h *Handler) scan(w http.ResponseWriter, r *http.Request) {
	sys, ok := h.resolveSystem(w, r)
	if !ok {
		return
	}
	if h.CanManageSystem != nil && !h.CanManageSystem(r.Context(), sys) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if h.Executor == nil {
		writeError(w, http.StatusServiceUnavailable, "scan unavailable: executor not configured")
		return
	}
	captured, err := Scan(r.Context(), h.Executor, h.Store, h.Audit, sys)
	if err != nil {
		writeError(w, http.StatusBadGateway, "ssh-keyscan failed: "+err.Error())
		slog.Error("hostkeys scan", "err", err, "system_id", sys.ID)
		return
	}
	out := make([]hostKeyDTO, 0, len(captured))
	for _, k := range captured {
		out = append(out, toDTO(k))
	}
	writeJSON(w, http.StatusOK, map[string]any{"hostKeys": out})
}

func (h *Handler) accept(w http.ResponseWriter, r *http.Request) {
	sys, ok := h.resolveSystem(w, r)
	if !ok {
		return
	}
	if h.CanManageSystem != nil && !h.CanManageSystem(r.Context(), sys) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	var req acceptRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Algorithm == "" || req.Fingerprint == "" {
		writeError(w, http.StatusBadRequest, "algorithm and fingerprint required")
		return
	}
	// Look up the prior accepted row (if any) so the audit row can
	// record both fingerprints on a replace.
	var priorFingerprint string
	prior, perr := h.findAccepted(sys.ID, req.Algorithm)
	if perr == nil {
		priorFingerprint = prior.Fingerprint
	}

	actorID := ""
	if u, ok := auth.UserFromContext(r.Context()); ok {
		actorID = u.ID
	}
	hk, replaced, err := h.Store.Accept(sys.ID, req.Algorithm, req.Fingerprint, actorID)
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			writeError(w, http.StatusNotFound, "no pending host key for this algorithm")
		case errors.Is(err, ErrFingerprintStale):
			writeError(w, http.StatusConflict,
				"fingerprint does not match the current pending row — refresh and review again")
		case errors.Is(err, ErrInvalid):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "accept failed")
			slog.Error("hostkeys accept", "err", err)
		}
		return
	}
	action := "system.host_key.accept"
	detail := audit.Detail{
		"algorithm":   hk.Algorithm,
		"fingerprint": hk.Fingerprint,
	}
	if replaced {
		action = "system.host_key.replace"
		detail["prior_fingerprint"] = priorFingerprint
	}
	h.logAudit(r.Context(), audit.Event{
		Action:      action,
		Outcome:     audit.Success,
		TargetKind:  "system",
		TargetID:    sys.ID,
		TargetLabel: sys.Name,
		Detail:      detail,
	})
	writeJSON(w, http.StatusOK, toDTO(hk))
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	sys, ok := h.resolveSystem(w, r)
	if !ok {
		return
	}
	if h.CanManageSystem != nil && !h.CanManageSystem(r.Context(), sys) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	keyID := r.PathValue("keyId")
	existing, err := h.Store.Get(keyID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "host key not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		slog.Error("hostkeys delete lookup", "err", err)
		return
	}
	if existing.SystemID != sys.ID {
		// 404 (not 403) — a key id that doesn't belong to this
		// system is indistinguishable from "doesn't exist" from
		// the caller's perspective.
		writeError(w, http.StatusNotFound, "host key not found")
		return
	}
	if err := h.Store.Delete(keyID); err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		slog.Error("hostkeys delete", "err", err)
		return
	}
	action := "system.host_key.delete"
	if existing.State == StatePending {
		action = "system.host_key.reject"
	}
	h.logAudit(r.Context(), audit.Event{
		Action:      action,
		Outcome:     audit.Success,
		TargetKind:  "system",
		TargetID:    sys.ID,
		TargetLabel: sys.Name,
		Detail: audit.Detail{
			"algorithm":   existing.Algorithm,
			"fingerprint": existing.Fingerprint,
			"state":       string(existing.State),
		},
	})
	w.WriteHeader(http.StatusNoContent)
}

// resolveSystem fetches the system and writes a 404 if missing.
// Returns false when the caller should stop processing.
func (h *Handler) resolveSystem(w http.ResponseWriter, r *http.Request) (systems.System, bool) {
	id := r.PathValue("id")
	sys, err := h.Systems.Get(id)
	if err != nil {
		if errors.Is(err, systems.ErrNotFound) {
			writeError(w, http.StatusNotFound, "system not found")
			return systems.System{}, false
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		slog.Error("hostkeys resolve system", "err", err)
		return systems.System{}, false
	}
	return sys, true
}

// findAccepted returns the currently-accepted row for the given
// (system_id, algorithm) pair, or ErrNotFound when none. Used by
// the accept handler to pull the prior fingerprint for the
// system.host_key.replace audit detail.
func (h *Handler) findAccepted(systemID, algorithm string) (HostKey, error) {
	keys, err := h.Store.AcceptedFor(systemID)
	if err != nil {
		return HostKey{}, err
	}
	for _, k := range keys {
		if k.Algorithm == algorithm {
			return k, nil
		}
	}
	return HostKey{}, ErrNotFound
}

func (h *Handler) logAudit(ctx context.Context, e audit.Event) {
	if h.Audit == nil {
		return
	}
	if err := h.Audit.Log(ctx, e); err != nil {
		slog.Error("hostkeys audit log", "err", err, "action", e.Action)
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("hostkeys json encode", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

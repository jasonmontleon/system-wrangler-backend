// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/groups"
	"system-wrangler-backend/internal/router"
	"system-wrangler-backend/internal/secrets"
	"system-wrangler-backend/internal/systems"
)

// SystemLookup is the narrow slice of systems.Store the handler needs
// — existence check before scoping a slot to a system, and the
// system's current group_id for the effective resolver.
// systems.SQLiteStore satisfies it.
type SystemLookup interface {
	Get(id string) (systems.System, error)
}

// GroupLookup mirrors SystemLookup for groups.
type GroupLookup interface {
	Get(id string) (groups.Group, error)
}

// Handler exposes the ansible-credentials HTTP API. RBAC, vault, and
// audit are wired from main.go via callbacks / fields so this
// package stays free of cycles back to rbac and auth.
type Handler struct {
	Store   Store
	Vault   *secrets.Vault
	Systems SystemLookup
	Groups  GroupLookup
	Audit   *audit.Store

	// CanManageGlobal gates the /api/admin/ansible-credentials/global
	// endpoints. Bound to "scope.IsGlobalAdmin()" in main.go.
	CanManageGlobal func(ctx context.Context) bool
	// CanManageGroup gates the per-group endpoints. Bound to
	// "Global Admin OR Group Admin of groupID."
	CanManageGroup func(ctx context.Context, groupID string) bool
	// CanManageSystem gates the per-system endpoints. Bound to
	// "Global Admin OR Group Admin of sys.GroupID."
	CanManageSystem func(ctx context.Context, s systems.System) bool
	// CanReadSystem gates the effective-credential view. Bound to
	// "scope.CanReadSystem(sys.GroupID)" so a 404-not-403 hides
	// systems the caller can't see.
	CanReadSystem func(ctx context.Context, s systems.System) bool
}

// Register wires the credential routes onto mux behind mw (the
// authenticated-user middleware). Each handler enforces its own
// CanManage* check; auth is just "must be logged in."
func (h *Handler) Register(mux router.Mux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("GET /api/admin/ansible-credentials", mw(http.HandlerFunc(h.list)))
	mux.Handle("GET /api/admin/ansible-credentials/global", mw(http.HandlerFunc(h.getGlobal)))
	mux.Handle("PUT /api/admin/ansible-credentials/global", mw(http.HandlerFunc(h.putGlobal)))
	mux.Handle("DELETE /api/admin/ansible-credentials/global", mw(http.HandlerFunc(h.deleteGlobal)))
	mux.Handle("GET /api/groups/{id}/ansible-credential", mw(http.HandlerFunc(h.getGroup)))
	mux.Handle("PUT /api/groups/{id}/ansible-credential", mw(http.HandlerFunc(h.putGroup)))
	mux.Handle("DELETE /api/groups/{id}/ansible-credential", mw(http.HandlerFunc(h.deleteGroup)))
	mux.Handle("GET /api/systems/{id}/ansible-credential", mw(http.HandlerFunc(h.getSystem)))
	mux.Handle("PUT /api/systems/{id}/ansible-credential", mw(http.HandlerFunc(h.putSystem)))
	mux.Handle("DELETE /api/systems/{id}/ansible-credential", mw(http.HandlerFunc(h.deleteSystem)))
	mux.Handle("GET /api/systems/{id}/effective-credential", mw(http.HandlerFunc(h.effective)))
}

// slotDTO is the public JSON shape for a slot. The sealed private
// key bytes are deliberately omitted — the API never returns
// secret material once it's stored. publicKey is plaintext and
// stays exposed so operators can paste it into authorized_keys
// without a round-trip through the vault.
type slotDTO struct {
	ScopeKind   ScopeKind `json:"scopeKind"`
	ScopeID     string    `json:"scopeId,omitempty"`
	AnsibleUser string    `json:"ansibleUser,omitempty"`
	PublicKey   string    `json:"publicKey,omitempty"`
	Origin      Origin    `json:"origin,omitempty"`
	CreatedAt   string    `json:"createdAt"`
	UpdatedAt   string    `json:"updatedAt"`
}

func toDTO(s Slot) slotDTO {
	return slotDTO{
		ScopeKind:   s.ScopeKind,
		ScopeID:     s.ScopeID,
		AnsibleUser: s.AnsibleUser,
		PublicKey:   s.PublicKey,
		Origin:      s.Origin,
		CreatedAt:   s.CreatedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		UpdatedAt:   s.UpdatedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
	}
}

// upsertRequest is the wire shape for PUT. Both fields are optional
// individually but at least one must be set — same invariant the
// store enforces.
//
//   - AnsibleUser: when present, sets the slot's user. Empty string
//     clears it (subject to the "at least one of user/key" rule).
//   - Key: when present, sets/replaces the slot's key. Origin must
//     be sw_generated (server generates ed25519) or user_supplied
//     (PrivateKeyPem must be a well-formed PEM).
type upsertRequest struct {
	AnsibleUser *string   `json:"ansibleUser,omitempty"`
	Key         *keyInput `json:"key,omitempty"`
	// ClearKey explicitly removes any existing key on the slot.
	// Used by the UI's "go back to inheriting from a higher scope"
	// affordance. Ignored when Key is also set.
	ClearKey bool `json:"clearKey,omitempty"`
}

type keyInput struct {
	Origin        Origin `json:"origin"`
	PrivateKeyPem string `json:"privateKeyPem,omitempty"`
}

// effectiveDTO is the resolved-credential response. Sources tell
// the UI which slot supplied each field so it can render
// "inherited from group X."
type effectiveDTO struct {
	AnsibleUser string    `json:"ansibleUser"`
	UserSource  ScopeKind `json:"userSource"`
	PublicKey   string    `json:"publicKey"`
	KeySource   ScopeKind `json:"keySource"`
	KeyOrigin   Origin    `json:"keyOrigin"`
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	if h.CanManageGlobal != nil && !h.CanManageGlobal(r.Context()) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	slots, err := h.Store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		slog.Error("credentials list", "err", err)
		return
	}
	out := make([]slotDTO, 0, len(slots))
	for _, s := range slots {
		out = append(out, toDTO(s))
	}
	writeJSON(w, http.StatusOK, map[string]any{"slots": out})
}

func (h *Handler) getGlobal(w http.ResponseWriter, r *http.Request) {
	if h.CanManageGlobal != nil && !h.CanManageGlobal(r.Context()) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	h.respondGet(w, ScopeGlobal, "")
}

func (h *Handler) putGlobal(w http.ResponseWriter, r *http.Request) {
	if h.CanManageGlobal != nil && !h.CanManageGlobal(r.Context()) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	h.respondPut(w, r, ScopeGlobal, "")
}

func (h *Handler) deleteGlobal(w http.ResponseWriter, r *http.Request) {
	if h.CanManageGlobal != nil && !h.CanManageGlobal(r.Context()) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	h.respondDelete(w, r, ScopeGlobal, "")
}

func (h *Handler) getGroup(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")
	if _, err := h.Groups.Get(groupID); err != nil {
		if errors.Is(err, groups.ErrNotFound) {
			writeError(w, http.StatusNotFound, "group not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		slog.Error("credentials get group lookup", "err", err)
		return
	}
	if h.CanManageGroup != nil && !h.CanManageGroup(r.Context(), groupID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	h.respondGet(w, ScopeGroup, groupID)
}

func (h *Handler) putGroup(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")
	if _, err := h.Groups.Get(groupID); err != nil {
		if errors.Is(err, groups.ErrNotFound) {
			writeError(w, http.StatusNotFound, "group not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		slog.Error("credentials put group lookup", "err", err)
		return
	}
	if h.CanManageGroup != nil && !h.CanManageGroup(r.Context(), groupID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	h.respondPut(w, r, ScopeGroup, groupID)
}

func (h *Handler) deleteGroup(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")
	if h.CanManageGroup != nil && !h.CanManageGroup(r.Context(), groupID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	h.respondDelete(w, r, ScopeGroup, groupID)
}

func (h *Handler) getSystem(w http.ResponseWriter, r *http.Request) {
	systemID := r.PathValue("id")
	sys, err := h.Systems.Get(systemID)
	if err != nil {
		if errors.Is(err, systems.ErrNotFound) {
			writeError(w, http.StatusNotFound, "system not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		slog.Error("credentials get system lookup", "err", err)
		return
	}
	if h.CanManageSystem != nil && !h.CanManageSystem(r.Context(), sys) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	h.respondGet(w, ScopeSystem, systemID)
}

func (h *Handler) putSystem(w http.ResponseWriter, r *http.Request) {
	systemID := r.PathValue("id")
	sys, err := h.Systems.Get(systemID)
	if err != nil {
		if errors.Is(err, systems.ErrNotFound) {
			writeError(w, http.StatusNotFound, "system not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		slog.Error("credentials put system lookup", "err", err)
		return
	}
	if h.CanManageSystem != nil && !h.CanManageSystem(r.Context(), sys) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	h.respondPut(w, r, ScopeSystem, systemID)
}

func (h *Handler) deleteSystem(w http.ResponseWriter, r *http.Request) {
	systemID := r.PathValue("id")
	sys, err := h.Systems.Get(systemID)
	if err != nil {
		if errors.Is(err, systems.ErrNotFound) {
			writeError(w, http.StatusNotFound, "system not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		slog.Error("credentials delete system lookup", "err", err)
		return
	}
	if h.CanManageSystem != nil && !h.CanManageSystem(r.Context(), sys) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	h.respondDelete(w, r, ScopeSystem, systemID)
}

func (h *Handler) effective(w http.ResponseWriter, r *http.Request) {
	systemID := r.PathValue("id")
	sys, err := h.Systems.Get(systemID)
	if err != nil {
		if errors.Is(err, systems.ErrNotFound) {
			writeError(w, http.StatusNotFound, "system not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		slog.Error("credentials effective lookup", "err", err)
		return
	}
	// 404 (not 403) for systems the caller can't see — same
	// rule the systems handler uses.
	if h.CanReadSystem != nil && !h.CanReadSystem(r.Context(), sys) {
		writeError(w, http.StatusNotFound, "system not found")
		return
	}
	resolved, err := Resolve(h.Store, sys.ID, sys.GroupID)
	if err != nil {
		switch {
		case errors.Is(err, ErrNoCredentials):
			writeError(w, http.StatusNotFound, "no credentials configured")
		case errors.Is(err, ErrIncompleteFlow):
			writeError(w, http.StatusConflict, "credential is incomplete: configure both an ansible user and a key")
		default:
			writeError(w, http.StatusInternalServerError, "resolve failed")
			slog.Error("credentials resolve", "err", err)
		}
		return
	}
	writeJSON(w, http.StatusOK, effectiveDTO{
		AnsibleUser: resolved.AnsibleUser,
		UserSource:  resolved.UserSource,
		PublicKey:   resolved.PublicKey,
		KeySource:   resolved.KeySource,
		KeyOrigin:   resolved.KeyOrigin,
	})
}

func (h *Handler) respondGet(w http.ResponseWriter, kind ScopeKind, scopeID string) {
	slot, err := h.Store.GetByScope(kind, scopeID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "no slot configured at this scope")
			return
		}
		writeError(w, http.StatusInternalServerError, "get failed")
		slog.Error("credentials get", "err", err)
		return
	}
	writeJSON(w, http.StatusOK, toDTO(slot))
}

func (h *Handler) respondPut(w http.ResponseWriter, r *http.Request, kind ScopeKind, scopeID string) {
	var req upsertRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.AnsibleUser == nil && req.Key == nil && !req.ClearKey {
		writeError(w, http.StatusBadRequest, "request must set at least one of ansibleUser or key")
		return
	}

	existing, getErr := h.Store.GetByScope(kind, scopeID)
	if getErr != nil && !errors.Is(getErr, ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "get failed")
		slog.Error("credentials put load", "err", getErr)
		return
	}
	merged := existing
	merged.ScopeKind = kind
	merged.ScopeID = scopeID

	if req.AnsibleUser != nil {
		merged.AnsibleUser = strings.TrimSpace(*req.AnsibleUser)
	}
	if req.ClearKey && req.Key == nil {
		merged.PublicKey = ""
		merged.PrivateKey = Sealed{}
		merged.Origin = ""
	}
	if req.Key != nil {
		if h.Vault == nil {
			writeError(w, http.StatusServiceUnavailable, "vault not configured")
			return
		}
		pub, sealed, err := materializeKey(h.Vault, *req.Key)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		merged.PublicKey = pub
		merged.PrivateKey = sealed
		merged.Origin = req.Key.Origin
	}

	saved, err := h.Store.Upsert(merged)
	if err != nil {
		if errors.Is(err, ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "save failed")
		slog.Error("credentials upsert", "err", err)
		return
	}
	h.logAudit(r.Context(), audit.Event{
		Action:     "ansible_credential.set",
		Outcome:    audit.Success,
		TargetKind: targetKindFor(kind),
		TargetID:   scopeID,
		Detail: audit.Detail{
			"scope_kind": string(kind),
			"has_user":   saved.AnsibleUser != "",
			"has_key":    saved.HasKey(),
			"origin":     string(saved.Origin),
		},
	})
	writeJSON(w, http.StatusOK, toDTO(saved))
}

func (h *Handler) respondDelete(w http.ResponseWriter, r *http.Request, kind ScopeKind, scopeID string) {
	err := h.Store.Delete(kind, scopeID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "no slot configured at this scope")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete failed")
		slog.Error("credentials delete", "err", err)
		return
	}
	h.logAudit(r.Context(), audit.Event{
		Action:     "ansible_credential.delete",
		Outcome:    audit.Success,
		TargetKind: targetKindFor(kind),
		TargetID:   scopeID,
		Detail:     audit.Detail{"scope_kind": string(kind)},
	})
	w.WriteHeader(http.StatusNoContent)
}

// materializeKey turns the inbound keyInput into a (public_key,
// Sealed) pair. The sw_generated path mints a fresh ed25519 keypair
// and discards the user-supplied PEM (if any); the user_supplied
// path requires a non-empty PEM and parses it to derive the public
// key.
func materializeKey(v *secrets.Vault, in keyInput) (string, Sealed, error) {
	switch in.Origin {
	case OriginSWGenerated:
		pub, privPEM, err := GenerateEd25519()
		if err != nil {
			return "", Sealed{}, errors.New("generate key failed: " + err.Error())
		}
		sealed, err := SealWith(v, privPEM)
		if err != nil {
			return "", Sealed{}, errors.New("seal key failed: " + err.Error())
		}
		return pub, sealed, nil
	case OriginUserSupplied:
		if in.PrivateKeyPem == "" {
			return "", Sealed{}, errors.New("privateKeyPem is required for origin=user_supplied")
		}
		pub, err := ParsePrivateKey([]byte(in.PrivateKeyPem))
		if err != nil {
			return "", Sealed{}, err
		}
		sealed, err := SealWith(v, []byte(in.PrivateKeyPem))
		if err != nil {
			return "", Sealed{}, errors.New("seal key failed: " + err.Error())
		}
		return pub, sealed, nil
	default:
		return "", Sealed{}, errors.New("origin must be sw_generated or user_supplied")
	}
}

func targetKindFor(s ScopeKind) string {
	switch s {
	case ScopeGroup:
		return "system_group"
	case ScopeSystem:
		return "system"
	default:
		return "ansible_credential"
	}
}

func (h *Handler) logAudit(ctx context.Context, e audit.Event) {
	if h.Audit == nil {
		return
	}
	if err := h.Audit.Log(ctx, e); err != nil {
		slog.Error("credentials audit log", "err", err, "action", e.Action)
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("credentials json encode", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

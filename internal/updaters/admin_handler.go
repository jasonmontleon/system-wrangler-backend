// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/router"
)

// AdminHandler exposes the Global-Admin-only custom updater CRUD.
// The system-scoped handler is a sibling in handler.go; both live
// in this package so the audit-action constants and validation
// stay co-located.
type AdminHandler struct {
	Registry *Registry
	Syntax   SyntaxChecker
	Audit    *audit.Store

	// CanManage gates every endpoint except the list endpoint.
	// Bound to "Global Admin only" in main.go.
	CanManage func(ctx context.Context) bool

	Now func() time.Time
}

// Register attaches the four routes behind mw. List is gated by mw
// alone (any authenticated user); the mutating routes additionally
// check CanManage.
func (h *AdminHandler) Register(mux router.Mux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("GET /api/admin/updater-definitions", mw(http.HandlerFunc(h.list)))
	mux.Handle("POST /api/admin/updater-definitions", mw(http.HandlerFunc(h.create)))
	mux.Handle("PATCH /api/admin/updater-definitions/{id}", mw(http.HandlerFunc(h.update)))
	mux.Handle("DELETE /api/admin/updater-definitions/{id}", mw(http.HandlerFunc(h.delete)))
}

// definitionDTO is the wire shape returned by list/create/update.
// The two playbook bodies are returned in full so the admin UI can
// edit them; they are also returned on create so the operator can
// confirm the saved canonical bytes.
type definitionDTO struct {
	ID            string `json:"id"`
	Source        Source `json:"source"`
	DisplayName   string `json:"displayName"`
	Description   string `json:"description"`
	DetectBinary  string `json:"detectBinary"`
	CheckPlaybook string `json:"checkPlaybook"`
	ApplyPlaybook string `json:"applyPlaybook"`
	CheckOnly     bool   `json:"checkOnly"`
	CreatedBy     string `json:"createdBy,omitempty"`
	CreatedAt     string `json:"createdAt,omitempty"`
	UpdatedAt     string `json:"updatedAt,omitempty"`
}

// listResponseDTO wraps the array so future cursor/page-info fields
// can land additively.
type listResponseDTO struct {
	Definitions []definitionDTO `json:"definitions"`
}

// createInputDTO matches the POST body. ID must be supplied — the
// operator picks the slug ("custom.dnf-fast"), which then forms the
// id namespace. The server prepends `custom.` if absent.
type createInputDTO struct {
	ID            string `json:"id"`
	DisplayName   string `json:"displayName"`
	Description   string `json:"description"`
	DetectBinary  string `json:"detectBinary"`
	CheckPlaybook string `json:"checkPlaybook"`
	ApplyPlaybook string `json:"applyPlaybook"`
	CheckOnly     bool   `json:"checkOnly"`
}

// updateInputDTO matches the PATCH body. ID comes from the path, so
// it isn't on the wire; everything else is required (the patch is
// effectively a full overwrite, matching how the credential editor
// works).
type updateInputDTO struct {
	DisplayName   string `json:"displayName"`
	Description   string `json:"description"`
	DetectBinary  string `json:"detectBinary"`
	CheckPlaybook string `json:"checkPlaybook"`
	ApplyPlaybook string `json:"applyPlaybook"`
	CheckOnly     bool   `json:"checkOnly"`
}

func (h *AdminHandler) list(w http.ResponseWriter, _ *http.Request) {
	defs, err := h.Registry.All()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		slog.Error("updaters admin list", "err", err)
		return
	}
	out := make([]definitionDTO, 0, len(defs))
	for _, d := range defs {
		out = append(out, definitionToDTO(d))
	}
	writeJSON(w, http.StatusOK, listResponseDTO{Definitions: out})
}

func (h *AdminHandler) create(w http.ResponseWriter, r *http.Request) {
	if !h.allowed(r.Context()) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	var in createInputDTO
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	id := normalizeCustomID(in.ID)
	if id == "" {
		writeError(w, http.StatusBadRequest, "id required")
		return
	}
	d := Definition{
		ID:            id,
		Source:        SourceCustom,
		DisplayName:   strings.TrimSpace(in.DisplayName),
		Description:   strings.TrimSpace(in.Description),
		DetectBinary:  strings.TrimSpace(in.DetectBinary),
		CheckPlaybook: []byte(in.CheckPlaybook),
		ApplyPlaybook: []byte(in.ApplyPlaybook),
		CheckOnly:     in.CheckOnly,
		CreatedBy:     audit.ActorFromContext(r.Context()).ID,
	}
	if err := h.guard(r.Context(), d); err != nil {
		writeGuardError(w, err)
		return
	}
	created, err := h.Registry.CreateCustom(d)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	h.emitAudit(r.Context(), "updater.create", audit.Success, created, nil)
	writeJSON(w, http.StatusCreated, definitionToDTO(created))
}

func (h *AdminHandler) update(w http.ResponseWriter, r *http.Request) {
	if !h.allowed(r.Context()) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	id := r.PathValue("id")
	if !IsCustomID(id) {
		writeError(w, http.StatusBadRequest, "id must begin with custom.")
		return
	}
	var in updateInputDTO
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	d := Definition{
		ID:            id,
		Source:        SourceCustom,
		DisplayName:   strings.TrimSpace(in.DisplayName),
		Description:   strings.TrimSpace(in.Description),
		DetectBinary:  strings.TrimSpace(in.DetectBinary),
		CheckPlaybook: []byte(in.CheckPlaybook),
		ApplyPlaybook: []byte(in.ApplyPlaybook),
		CheckOnly:     in.CheckOnly,
	}
	if err := h.guard(r.Context(), d); err != nil {
		writeGuardError(w, err)
		return
	}
	updated, err := h.Registry.UpdateCustom(d)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	h.emitAudit(r.Context(), "updater.update", audit.Success, updated, nil)
	writeJSON(w, http.StatusOK, definitionToDTO(updated))
}

func (h *AdminHandler) delete(w http.ResponseWriter, r *http.Request) {
	if !h.allowed(r.Context()) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	id := r.PathValue("id")
	if !IsCustomID(id) {
		writeError(w, http.StatusBadRequest, "id must begin with custom.")
		return
	}
	// Resolve the row before the delete so the audit row can carry
	// the display name even though the body is now tombstoned.
	existing, err := h.Registry.Get(id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	now := h.now()
	if err := h.Registry.DeleteCustom(id, now); err != nil {
		writeStoreError(w, err)
		return
	}
	h.emitAudit(r.Context(), "updater.delete", audit.Success, existing, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) allowed(ctx context.Context) bool {
	if h.CanManage == nil {
		return true
	}
	return h.CanManage(ctx)
}

func (h *AdminHandler) now() time.Time {
	if h.Now == nil {
		return time.Now().UTC()
	}
	return h.Now().UTC()
}

// guard runs every save-time invariant the design calls for: input
// validation, the inline-credential heuristic, and the ansible
// syntax check. Returns the first failure; the caller maps it to
// the appropriate 4xx.
func (h *AdminHandler) guard(ctx context.Context, d Definition) error {
	if err := d.Validate(); err != nil {
		return err
	}
	if err := scanInlineCredentials(d.CheckPlaybook); err != nil {
		return err
	}
	if !d.CheckOnly {
		if err := scanInlineCredentials(d.ApplyPlaybook); err != nil {
			return err
		}
	}
	if h.Syntax != nil {
		if err := h.Syntax.Check(ctx, d.CheckPlaybook); err != nil {
			return err
		}
		if !d.CheckOnly {
			if err := h.Syntax.Check(ctx, d.ApplyPlaybook); err != nil {
				return err
			}
		}
	}
	return nil
}

func (h *AdminHandler) emitAudit(ctx context.Context, action string, outcome audit.Outcome, d Definition, extra audit.Detail) {
	if h.Audit == nil {
		return
	}
	detail := audit.NewDetail()
	for k, v := range extra {
		_ = detail.SetSafe(k, v)
	}
	// Two shas so a future diff endpoint can identify which body
	// changed without having to fetch both old + new rows.
	detail["check_sha"] = shaHex(d.CheckPlaybook)
	detail["apply_sha"] = shaHex(d.ApplyPlaybook)
	if err := h.Audit.Log(ctx, audit.Event{
		Action:      action,
		Outcome:     outcome,
		TargetKind:  "updater_definition",
		TargetID:    d.ID,
		TargetLabel: d.DisplayName,
		Detail:      detail,
	}); err != nil {
		slog.Error("updaters admin audit", "err", err, "action", action)
	}
}

// normalizeCustomID lower-bounds the operator's input — bare slugs
// get the custom. prefix prepended; already-prefixed ids pass
// through. Whitespace is trimmed.
func normalizeCustomID(in string) string {
	s := strings.TrimSpace(in)
	if s == "" {
		return ""
	}
	if IsBuiltinID(s) {
		return s // will be rejected downstream
	}
	if IsCustomID(s) {
		return s
	}
	return PrefixCustom + s
}

func definitionToDTO(d Definition) definitionDTO {
	dto := definitionDTO{
		ID:            d.ID,
		Source:        d.Source,
		DisplayName:   d.DisplayName,
		Description:   d.Description,
		DetectBinary:  d.DetectBinary,
		CheckPlaybook: string(d.CheckPlaybook),
		ApplyPlaybook: string(d.ApplyPlaybook),
		CheckOnly:     d.CheckOnly,
		CreatedBy:     d.CreatedBy,
	}
	if !d.CreatedAt.IsZero() {
		dto.CreatedAt = d.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	if !d.UpdatedAt.IsZero() {
		dto.UpdatedAt = d.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	return dto
}

// writeGuardError maps the guard helper's errors to HTTP statuses.
// Validation, syntax, and inline-credential failures are all
// caller-correctable (400); the executor-unconfigured branch is
// a server-side misconfig (500).
func writeGuardError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrSyntax):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrInlineCredential):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrInvalid):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, ErrDuplicate):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrReservedID):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrBuiltinWrite):
		writeError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, ErrInvalid):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

// Compile-time guarantee that shaHex stays usable from admin code
// without re-exposing the helper just for this package.
var _ = sha256.Sum256
var _ = hex.EncodeToString

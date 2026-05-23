// SPDX-License-Identifier: Apache-2.0

package exporters

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/router"
)

// AdminHandler exposes the Global-Admin-only custom exporter CRUD.
type AdminHandler struct {
	Registry *Registry
	Syntax   SyntaxChecker
	Audit    *audit.Store

	// CanManage gates every mutating endpoint. Bound to "Global
	// Admin only" in main.go.
	CanManage func(ctx context.Context) bool

	Now func() time.Time
}

// Register attaches the four routes behind mw.
func (h *AdminHandler) Register(mux router.Mux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("GET /api/admin/exporter-definitions", mw(http.HandlerFunc(h.list)))
	mux.Handle("POST /api/admin/exporter-definitions", mw(http.HandlerFunc(h.create)))
	mux.Handle("PATCH /api/admin/exporter-definitions/{id}", mw(http.HandlerFunc(h.update)))
	mux.Handle("DELETE /api/admin/exporter-definitions/{id}", mw(http.HandlerFunc(h.delete)))
}

// definitionDTO is the wire shape returned by list/create/update.
type definitionDTO struct {
	ID                  string       `json:"id"`
	Source              Source       `json:"source"`
	DisplayName         string       `json:"displayName"`
	Description         string       `json:"description"`
	AppliesToPkgManager string       `json:"appliesToPkgManager"`
	ExporterKind        ExporterKind `json:"exporterKind"`
	BindPort            int          `json:"bindPort"`
	InstallPlaybook     string       `json:"installPlaybook"`
	StatusPlaybook      string       `json:"statusPlaybook"`
	RemovePlaybook      string       `json:"removePlaybook"`
	CreatedBy           string       `json:"createdBy,omitempty"`
	CreatedAt           string       `json:"createdAt,omitempty"`
	UpdatedAt           string       `json:"updatedAt,omitempty"`
}

type listResponseDTO struct {
	Definitions []definitionDTO `json:"definitions"`
}

// createInputDTO matches the POST body. The server prepends `custom.`
// to the id if absent.
type createInputDTO struct {
	ID                  string       `json:"id"`
	DisplayName         string       `json:"displayName"`
	Description         string       `json:"description"`
	AppliesToPkgManager string       `json:"appliesToPkgManager"`
	ExporterKind        ExporterKind `json:"exporterKind"`
	BindPort            int          `json:"bindPort"`
	InstallPlaybook     string       `json:"installPlaybook"`
	StatusPlaybook      string       `json:"statusPlaybook"`
	RemovePlaybook      string       `json:"removePlaybook"`
}

// updateInputDTO matches the PATCH body — ID comes from the path.
type updateInputDTO struct {
	DisplayName         string       `json:"displayName"`
	Description         string       `json:"description"`
	AppliesToPkgManager string       `json:"appliesToPkgManager"`
	ExporterKind        ExporterKind `json:"exporterKind"`
	BindPort            int          `json:"bindPort"`
	InstallPlaybook     string       `json:"installPlaybook"`
	StatusPlaybook      string       `json:"statusPlaybook"`
	RemovePlaybook      string       `json:"removePlaybook"`
}

func (h *AdminHandler) list(w http.ResponseWriter, _ *http.Request) {
	defs, err := h.Registry.All()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		slog.Error("exporters admin list", "err", err)
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
		ID:                  id,
		Source:              SourceCustom,
		DisplayName:         strings.TrimSpace(in.DisplayName),
		Description:         strings.TrimSpace(in.Description),
		AppliesToPkgManager: strings.TrimSpace(in.AppliesToPkgManager),
		ExporterKind:        in.ExporterKind,
		BindPort:            in.BindPort,
		InstallPlaybook:     []byte(in.InstallPlaybook),
		StatusPlaybook:      []byte(in.StatusPlaybook),
		RemovePlaybook:      []byte(in.RemovePlaybook),
		CreatedBy:           audit.ActorFromContext(r.Context()).ID,
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
	h.emitAudit(r.Context(), "exporter.create", audit.Success, created)
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
		ID:                  id,
		Source:              SourceCustom,
		DisplayName:         strings.TrimSpace(in.DisplayName),
		Description:         strings.TrimSpace(in.Description),
		AppliesToPkgManager: strings.TrimSpace(in.AppliesToPkgManager),
		ExporterKind:        in.ExporterKind,
		BindPort:            in.BindPort,
		InstallPlaybook:     []byte(in.InstallPlaybook),
		StatusPlaybook:      []byte(in.StatusPlaybook),
		RemovePlaybook:      []byte(in.RemovePlaybook),
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
	h.emitAudit(r.Context(), "exporter.update", audit.Success, updated)
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
	h.emitAudit(r.Context(), "exporter.delete", audit.Success, existing)
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

// guard runs every save-time invariant: input validation, the inline-
// credential heuristic on each playbook body, and the ansible
// syntax check.
func (h *AdminHandler) guard(ctx context.Context, d Definition) error {
	if err := d.Validate(); err != nil {
		return err
	}
	if err := scanInlineCredentials(d.InstallPlaybook); err != nil {
		return err
	}
	if err := scanInlineCredentials(d.StatusPlaybook); err != nil {
		return err
	}
	if d.HasRemove() {
		if err := scanInlineCredentials(d.RemovePlaybook); err != nil {
			return err
		}
	}
	if h.Syntax != nil {
		if err := h.Syntax.Check(ctx, d.InstallPlaybook); err != nil {
			return err
		}
		if err := h.Syntax.Check(ctx, d.StatusPlaybook); err != nil {
			return err
		}
		if d.HasRemove() {
			if err := h.Syntax.Check(ctx, d.RemovePlaybook); err != nil {
				return err
			}
		}
	}
	return nil
}

func (h *AdminHandler) emitAudit(ctx context.Context, action string, outcome audit.Outcome, d Definition) {
	if h.Audit == nil {
		return
	}
	detail := audit.NewDetail()
	detail["install_sha"] = shaHex(d.InstallPlaybook)
	detail["status_sha"] = shaHex(d.StatusPlaybook)
	if d.HasRemove() {
		detail["remove_sha"] = shaHex(d.RemovePlaybook)
	}
	detail["applies_to_pkg_manager"] = d.AppliesToPkgManager
	detail["exporter_kind"] = string(d.ExporterKind)
	detail["bind_port"] = d.BindPort
	if err := h.Audit.Log(ctx, audit.Event{
		Action:      action,
		Outcome:     outcome,
		TargetKind:  "exporter_definition",
		TargetID:    d.ID,
		TargetLabel: d.DisplayName,
		Detail:      detail,
	}); err != nil {
		slog.Error("exporters admin audit", "err", err, "action", action)
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
		return s // rejected downstream
	}
	if IsCustomID(s) {
		return s
	}
	return PrefixCustom + s
}

func definitionToDTO(d Definition) definitionDTO {
	dto := definitionDTO{
		ID:                  d.ID,
		Source:              d.Source,
		DisplayName:         d.DisplayName,
		Description:         d.Description,
		AppliesToPkgManager: d.AppliesToPkgManager,
		ExporterKind:        d.ExporterKind,
		BindPort:            d.BindPort,
		InstallPlaybook:     string(d.InstallPlaybook),
		StatusPlaybook:      string(d.StatusPlaybook),
		RemovePlaybook:      string(d.RemovePlaybook),
		CreatedBy:           d.CreatedBy,
	}
	if !d.CreatedAt.IsZero() {
		dto.CreatedAt = d.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	if !d.UpdatedAt.IsZero() {
		dto.UpdatedAt = d.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	return dto
}

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

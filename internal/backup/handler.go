// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/router"
)

// Handler exposes the admin backup endpoint. It owns the wire format
// (response headers, JSON errors) but defers snapshot production to
// Service. The CanCreate gate is wired from main.go against the rbac
// Scope on the request context; the audit Store is also optional.
type Handler struct {
	// Service is the snapshot producer. Required.
	Service *Service
	// Audit, when non-nil, receives one db.backup row per request —
	// Outcome=Denied on a forbidden caller, Failure on an in-flight
	// collision or stream error, Success once the bytes have been
	// written. nil disables audit emission (used by older tests).
	Audit *audit.Store
	// CanCreate, when non-nil, gates the endpoint. Wiring lives in
	// main.go so the backup package does not import rbac. nil means
	// "no scope filter" (used by tests that bypass RBAC).
	CanCreate func(context.Context) bool
	// Now sources the filename timestamp. Defaults to time.Now.
	Now func() time.Time
}

// NewHandler returns a Handler bound to svc.
func NewHandler(svc *Service) *Handler { return &Handler{Service: svc} }

// Register wires POST /api/admin/backup behind the supplied
// authenticated-user middleware. The Global-Admin gate is enforced
// inside the handler via CanCreate, mirroring the in-handler scope
// checks used by the rbac admin endpoints.
func (h *Handler) Register(mux router.Mux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("POST /api/admin/backup", mw(http.HandlerFunc(h.create)))
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	if h.CanCreate != nil && !h.CanCreate(r.Context()) {
		h.logAudit(r.Context(), audit.Event{
			Action:  "db.backup",
			Outcome: audit.Denied,
		})
		writeError(w, http.StatusForbidden, "backup requires Global Admin")
		return
	}
	snap, err := h.Service.Create(r.Context())
	if err != nil {
		if errors.Is(err, ErrInFlight) {
			h.logAudit(r.Context(), audit.Event{
				Action:  "db.backup",
				Outcome: audit.Failure,
				Detail:  detailWithReason("in_flight"),
			})
			writeError(w, http.StatusConflict, "another backup is already in progress")
			return
		}
		h.logAudit(r.Context(), audit.Event{
			Action:  "db.backup",
			Outcome: audit.Failure,
			Detail:  detailWithReason("create_failed"),
		})
		writeError(w, http.StatusInternalServerError, "backup failed")
		slog.Error("backup create", "err", err)
		return
	}
	defer func() { _ = snap.Close() }()

	// path is server-generated (TempDir + sw-backup-<hex>.db). gosec
	// G304 false positive on the variable path.
	f, err := os.Open(snap.Path) //nolint:gosec
	if err != nil {
		h.logAudit(r.Context(), audit.Event{
			Action:  "db.backup",
			Outcome: audit.Failure,
			Detail:  detailWithReason("open_failed"),
		})
		writeError(w, http.StatusInternalServerError, "backup open failed")
		slog.Error("backup open", "err", err)
		return
	}
	defer func() { _ = f.Close() }()

	now := h.now().UTC()
	filename := "system-wrangler-" + now.Format("20060102T150405Z") + ".db"

	w.Header().Set("Content-Type", "application/vnd.sqlite3")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Content-Length", strconv.FormatInt(snap.Size, 10))
	if _, err := io.Copy(w, f); err != nil {
		// Headers (and likely some bytes) are already on the wire, so we
		// cannot change the status code. Record the partial result and
		// rely on Content-Length mismatch + audit to flag it.
		d := audit.NewDetail()
		_ = d.SetSafe("bytes", snap.Size)
		_ = d.SetSafe("reason", "stream_failed")
		h.logAudit(r.Context(), audit.Event{
			Action:  "db.backup",
			Outcome: audit.Failure,
			Detail:  d,
		})
		slog.Error("backup stream", "err", err)
		return
	}
	d := audit.NewDetail()
	_ = d.SetSafe("bytes", snap.Size)
	h.logAudit(r.Context(), audit.Event{
		Action:  "db.backup",
		Outcome: audit.Success,
		Detail:  d,
	})
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Handler) logAudit(ctx context.Context, e audit.Event) {
	if h.Audit == nil {
		return
	}
	if err := h.Audit.Log(ctx, e); err != nil {
		slog.Error("backup audit", "err", err, "action", e.Action)
	}
}

func detailWithReason(reason string) audit.Detail {
	d := audit.NewDetail()
	_ = d.SetSafe("reason", reason)
	return d
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// SPDX-License-Identifier: Apache-2.0

package exporters

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"system-wrangler-backend/internal/ansible"
	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/router"
	"system-wrangler-backend/internal/systems"
)

// SystemLookup is the slice of systems.Store the handler needs.
// systems.SQLiteStore satisfies it.
type SystemLookup interface {
	Get(id string) (systems.System, error)
}

// PkgManagerProbe abstracts "what package managers are detected on
// this system?" Wired in main.go against updaters.Store.AvailabilityFor
// so this package stays independent of the updaters package — a
// renames-in-place future where the source moves out of `updaters`
// rebinds the interface without touching this file.
type PkgManagerProbe interface {
	DetectedPkgManagers(systemID string) ([]string, error)
}

// Availability is the three-state per-exporter availability for a
// system: "available" / "unavailable" / "unknown". Matches the
// design's three-state model — see research/exporter-deployment.md.
type Availability string

// Availability values.
const (
	AvailabilityAvailable   Availability = "available"
	AvailabilityUnavailable Availability = "unavailable"
	AvailabilityUnknown     Availability = "unknown"
)

// Handler exposes the system-scoped exporter endpoints — list +
// install / status / remove + settings + run history. Admin-scoped
// custom-definition CRUD ships in AdminHandler.
type Handler struct {
	Runner  *Runner
	Store   Store
	Systems SystemLookup
	Probe   PkgManagerProbe
	Audit   *audit.Store

	// CanOperateSystem gates the mutating endpoints. Bound in main.go
	// to "Global Operator OR Group Operator+ on sys.GroupID".
	CanOperateSystem func(ctx context.Context, s systems.System) bool

	// CanReadSystem gates the read endpoints. Bound to the
	// scope-resolved read check so an auditor can see Monitoring
	// state.
	CanReadSystem func(ctx context.Context, s systems.System) bool

	// Notify, if set, is called when the scrape toggle flips so the
	// promtargets writer can regenerate immediately. Bound to
	// events.Hub.Broadcast("systems.changed") in main.go.
	Notify func(eventType string)
}

// Register attaches the routes behind mw (the authenticated-user
// middleware).
func (h *Handler) Register(mux router.Mux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("GET /api/systems/{id}/exporters", mw(http.HandlerFunc(h.list)))
	mux.Handle("POST /api/systems/{id}/exporters/{exporter}/install", mw(http.HandlerFunc(h.install)))
	mux.Handle("POST /api/systems/{id}/exporters/{exporter}/status", mw(http.HandlerFunc(h.status)))
	mux.Handle("POST /api/systems/{id}/exporters/{exporter}/remove", mw(http.HandlerFunc(h.remove)))
	mux.Handle("PUT /api/systems/{id}/exporters/{exporter}/scrape", mw(http.HandlerFunc(h.setScrape)))
	mux.Handle("PUT /api/systems/{id}/exporter-settings", mw(http.HandlerFunc(h.setSettings)))
	mux.Handle("GET /api/systems/{id}/exporter-runs", mw(http.HandlerFunc(h.listRuns)))
}

// SystemExporterDTO is one row in the per-system list. Each row
// pairs a registered exporter installer with this system's
// availability, install state, and (when known) the live port +
// service name + reason string.
type SystemExporterDTO struct {
	ExporterID          string       `json:"exporterId"`
	Source              Source       `json:"source"`
	DisplayName         string       `json:"displayName"`
	Description         string       `json:"description"`
	AppliesToPkgManager string       `json:"appliesToPkgManager"`
	ExporterKind        ExporterKind `json:"exporterKind"`
	BindPort            int          `json:"bindPort"`
	HasRemove           bool         `json:"hasRemove"`
	Availability        Availability `json:"availability"`
	Installed           bool         `json:"installed"`
	ScrapeEnabled       bool         `json:"scrapeEnabled"`
	State               State        `json:"state,omitempty"`
	Port                int          `json:"port,omitempty"`
	ServiceName         string       `json:"serviceName,omitempty"`
	LastStatusAt        *time.Time   `json:"lastStatusAt,omitempty"`
	LastInstallAt       *time.Time   `json:"lastInstallAt,omitempty"`
	LastReason          string       `json:"lastReason,omitempty"`
}

// SystemExportersResponseDTO is the shape returned by GET /exporters.
// `detectedPkgManagers` surfaces the updater ids the SPA cross-
// references with the Admin → Exporters list when offering "Add a
// custom installer."
type SystemExportersResponseDTO struct {
	ScrapeMode          ScrapeMode          `json:"scrapeMode"`
	DetectedPkgManagers []string            `json:"detectedPkgManagers"`
	Exporters           []SystemExporterDTO `json:"exporters"`
}

// settingsInputDTO is the PUT body for /exporter-settings.
type settingsInputDTO struct {
	ScrapeMode ScrapeMode `json:"scrapeMode"`
}

// runDTO is the response shape for install / status / remove.
type runDTO struct {
	RunID      string            `json:"runId"`
	ExporterID string            `json:"exporterId"`
	Kind       RunKind           `json:"kind"`
	Status     ansible.RunStatus `json:"status"`
	ExitCode   int               `json:"exitCode"`
	State      State             `json:"state"`
	Port       int               `json:"port,omitempty"`
	Service    string            `json:"service,omitempty"`
	Reason     string            `json:"reason,omitempty"`
	DurationMS int64             `json:"durationMs"`
}

// runHistoryDTO is one entry in the run-history response.
type runHistoryDTO struct {
	ID          string     `json:"id"`
	SystemID    string     `json:"systemId"`
	ExporterID  string     `json:"exporterId"`
	Kind        RunKind    `json:"kind"`
	StartedAt   time.Time  `json:"startedAt"`
	FinishedAt  *time.Time `json:"finishedAt,omitempty"`
	ExitCode    *int       `json:"exitCode,omitempty"`
	ActorID     string     `json:"actorId,omitempty"`
	PlaybookSHA string     `json:"playbookSha,omitempty"`
	LogTail     string     `json:"logTail,omitempty"`
}

type runsResponseDTO struct {
	Runs []runHistoryDTO `json:"runs"`
}

// conflictDTO surfaces the per-system lock collision shape: 409 with
// the run id of the holder.
type conflictDTO struct {
	Error          string `json:"error"`
	ConflictingRun string `json:"conflictingRun,omitempty"`
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	sys, ok := h.loadSystem(w, r)
	if !ok {
		return
	}
	if h.CanReadSystem != nil && !h.CanReadSystem(r.Context(), sys) {
		writeError(w, http.StatusNotFound, "system not found")
		return
	}
	if h.Runner == nil || h.Runner.Registry == nil {
		writeError(w, http.StatusServiceUnavailable, "exporter runner not configured")
		return
	}
	defs, err := h.Runner.Registry.All()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list exporters failed")
		slog.Error("exporters list", "err", err)
		return
	}
	rows, err := h.Store.ListSystemExporters(sys.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list system_exporters failed")
		slog.Error("exporters list system_exporters", "err", err, "system_id", sys.ID) //nolint:gosec
		return
	}
	byID := make(map[string]SystemExporter, len(rows))
	for _, sx := range rows {
		byID[sx.ExporterID] = sx
	}
	detected := []string{}
	if h.Probe != nil {
		got, perr := h.Probe.DetectedPkgManagers(sys.ID)
		if perr != nil {
			slog.Warn("exporters: pkg manager probe", "err", perr, "system_id", sys.ID) //nolint:gosec
		} else {
			detected = got
		}
	}
	detectedSet := make(map[string]bool, len(detected))
	for _, id := range detected {
		detectedSet[id] = true
	}
	settings, err := h.Store.GetSettings(sys.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load settings failed")
		slog.Error("exporters load settings", "err", err, "system_id", sys.ID) //nolint:gosec
		return
	}
	out := make([]SystemExporterDTO, 0, len(defs))
	for _, d := range defs {
		dto := SystemExporterDTO{
			ExporterID:          d.ID,
			Source:              d.Source,
			DisplayName:         d.DisplayName,
			Description:         d.Description,
			AppliesToPkgManager: d.AppliesToPkgManager,
			ExporterKind:        d.ExporterKind,
			BindPort:            d.BindPort,
			HasRemove:           d.HasRemove(),
			Availability:        resolveAvailability(d.AppliesToPkgManager, detected, detectedSet),
			ScrapeEnabled:       true,
		}
		if sx, found := byID[d.ID]; found && sx.State != StateRemoved {
			dto.Installed = true
			dto.State = sx.State
			dto.Port = sx.Port
			dto.ServiceName = sx.ServiceName
			dto.LastStatusAt = sx.LastStatusAt
			dto.LastInstallAt = sx.LastInstallAt
			dto.LastReason = sx.LastReason
			dto.ScrapeEnabled = sx.ScrapeEnabled
		} else if found && sx.State == StateRemoved {
			dto.State = StateRemoved
			dto.LastStatusAt = sx.LastStatusAt
			dto.LastInstallAt = sx.LastInstallAt
			dto.LastReason = sx.LastReason
			dto.ScrapeEnabled = sx.ScrapeEnabled
		}
		out = append(out, dto)
	}
	writeJSON(w, http.StatusOK, SystemExportersResponseDTO{
		ScrapeMode:          settings.ScrapeMode,
		DetectedPkgManagers: detected,
		Exporters:           out,
	})
}

// resolveAvailability is the three-state computation. When the
// detected slice is empty we treat the system as "never inspected"
// — Unknown. With any detected updater present, the system has been
// inspected, so the exporter is Available or Unavailable depending
// on whether its applies-to pkg manager id is in the set.
func resolveAvailability(appliesTo string, detected []string, set map[string]bool) Availability {
	if len(detected) == 0 {
		return AvailabilityUnknown
	}
	if set[appliesTo] {
		return AvailabilityAvailable
	}
	return AvailabilityUnavailable
}

func (h *Handler) install(w http.ResponseWriter, r *http.Request) {
	h.runEndpoint(w, r, RunKindInstall)
}

func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	h.runEndpoint(w, r, RunKindStatus)
}

func (h *Handler) remove(w http.ResponseWriter, r *http.Request) {
	h.runEndpoint(w, r, RunKindRemove)
}

func (h *Handler) runEndpoint(w http.ResponseWriter, r *http.Request, kind RunKind) {
	sys, ok := h.loadSystem(w, r)
	if !ok {
		return
	}
	if !h.canOperate(r.Context(), sys) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if h.Runner == nil {
		writeError(w, http.StatusServiceUnavailable, "exporter runner not configured")
		return
	}
	exporterID := r.PathValue("exporter")
	var res RunResult
	var err error
	switch kind {
	case RunKindInstall:
		res, err = h.Runner.Install(r.Context(), sys.ID, exporterID)
	case RunKindStatus:
		res, err = h.Runner.Status(r.Context(), sys.ID, exporterID)
	case RunKindRemove:
		res, err = h.Runner.Remove(r.Context(), sys.ID, exporterID)
	}
	if errors.Is(err, ErrConflict) {
		writeConflict(w, h.Runner.Locker, sys.ID, "another run is in progress for this system")
		return
	}
	if isConflict(err) {
		writeConflict(w, h.Runner.Locker, sys.ID, "another run is in progress for this system")
		return
	}
	if errors.Is(err, ErrNoRemove) {
		writeError(w, http.StatusBadRequest, err.Error())
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
		slog.Error("exporters run", "err", err, "system_id", sys.ID, "exporter_id", exporterID, "kind", kind) //nolint:gosec
		return
	}
	dur := int64(0)
	if res.Run.FinishedAt != nil {
		dur = res.Run.FinishedAt.Sub(res.Run.StartedAt).Milliseconds()
	}
	writeJSON(w, http.StatusOK, runDTO{
		RunID:      res.Run.ID,
		ExporterID: res.ExporterID,
		Kind:       res.Kind,
		Status:     res.Status,
		ExitCode:   res.ExitCode,
		State:      res.State,
		Port:       res.Port,
		Service:    res.Service,
		Reason:     res.Reason,
		DurationMS: dur,
	})
}

// scrapeInputDTO is the PUT body for /exporters/{exporter}/scrape.
type scrapeInputDTO struct {
	Enabled bool `json:"enabled"`
}

func (h *Handler) setScrape(w http.ResponseWriter, r *http.Request) {
	sys, ok := h.loadSystem(w, r)
	if !ok {
		return
	}
	if !h.canOperate(r.Context(), sys) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	exporterID := r.PathValue("exporter")
	if exporterID == "" {
		writeError(w, http.StatusBadRequest, "exporter id required")
		return
	}
	var in scrapeInputDTO
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	changed, err := h.Store.SetScrapeEnabled(sys.ID, exporterID, in.Enabled)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "exporter is not installed on this system")
			return
		}
		writeError(w, http.StatusInternalServerError, "set scrape failed")
		slog.Error("exporters set scrape", "err", err, "system_id", sys.ID, "exporter_id", exporterID) //nolint:gosec
		return
	}
	if changed {
		action := "system.exporter.scrape.enable"
		if !in.Enabled {
			action = "system.exporter.scrape.disable"
		}
		if h.Audit != nil {
			if err := h.Audit.Log(r.Context(), audit.Event{
				Action:     action,
				Outcome:    audit.Success,
				TargetKind: "system",
				TargetID:   sys.ID,
				Detail: audit.Detail{
					"exporter_id": exporterID,
				},
			}); err != nil {
				slog.Error("exporters audit scrape", "err", err, "action", action)
			}
		}
		if h.Notify != nil {
			h.Notify("systems.changed")
		}
	}
	row, err := h.Store.GetSystemExporter(sys.ID, exporterID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load exporter row failed")
		slog.Error("exporters load after scrape toggle", "err", err) //nolint:gosec
		return
	}
	writeJSON(w, http.StatusOK, scrapeResponseDTO{
		ExporterID:    exporterID,
		ScrapeEnabled: row.ScrapeEnabled,
	})
}

type scrapeResponseDTO struct {
	ExporterID    string `json:"exporterId"`
	ScrapeEnabled bool   `json:"scrapeEnabled"`
}

func (h *Handler) setSettings(w http.ResponseWriter, r *http.Request) {
	sys, ok := h.loadSystem(w, r)
	if !ok {
		return
	}
	if !h.canOperate(r.Context(), sys) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	var in settingsInputDTO
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if !in.ScrapeMode.IsValid() {
		writeError(w, http.StatusBadRequest, "invalid scrape mode")
		return
	}
	// Phase 1 only ships localhost. mTLS modes are accepted at the
	// schema level so a later phase can land them additively, but
	// the handler refuses them today so an operator doesn't land in
	// a half-configured state.
	if in.ScrapeMode != ScrapeLocalhost {
		writeError(w, http.StatusBadRequest, "only the 'localhost' scrape mode is supported in this release")
		return
	}
	if err := h.Store.SetScrapeMode(sys.ID, in.ScrapeMode); err != nil {
		if errors.Is(err, ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "set scrape mode failed")
		slog.Error("exporters set scrape mode", "err", err, "system_id", sys.ID) //nolint:gosec
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
		slog.Error("exporters list runs", "err", err, "system_id", sys.ID) //nolint:gosec
		return
	}
	out := make([]runHistoryDTO, 0, len(rows))
	for _, run := range rows {
		out = append(out, runHistoryDTO(run))
	}
	writeJSON(w, http.StatusOK, runsResponseDTO{Runs: out})
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
		slog.Error("exporters system lookup", "err", err, "system_id", sysID) //nolint:gosec
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

func writeConflict(w http.ResponseWriter, locker Locker, systemID, msg string) {
	holder := ""
	if locker != nil {
		holder, _ = locker.ConflictingRun(systemID)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(conflictDTO{Error: msg, ConflictingRun: holder})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("exporters json encode", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

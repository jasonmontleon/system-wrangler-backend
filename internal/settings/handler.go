// SPDX-License-Identifier: Apache-2.0

package settings

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/logging"
	"system-wrangler-backend/internal/router"
)

// Handler exposes the Global-Admin-only settings endpoints. The
// store is hit through typed accessors so each setting can carry
// its own coercion and validation rules; the handler dispatches on
// the path key to pick the right accessor.
type Handler struct {
	Store Store
	Audit *audit.Store

	// CanManage gates every endpoint. Bound to
	// "scope.IsGlobalAdmin()" in main.go.
	CanManage func(ctx context.Context) bool

	// OnLogLevelChange, when non-nil, is invoked after a log_level_*
	// setting is persisted so the live logger level can be updated
	// without a restart. Bound to logging.SetLevel in main.go.
	OnLogLevelChange func(component, level string)
}

// Register attaches the two routes behind mw (the authenticated-
// user middleware). Both routes additionally check CanManage.
func (h *Handler) Register(mux router.Mux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("GET /api/admin/settings", mw(http.HandlerFunc(h.list)))
	mux.Handle("PUT /api/admin/settings/{key}", mw(http.HandlerFunc(h.put)))
}

// settingsResponseDTO returns the full set as {key: value}. The
// caller materialises one form per known key; unknown keys (left
// over from a downgrade) round-trip transparently so an operator
// can still inspect them on the admin page.
type settingsResponseDTO struct {
	Settings map[string]string `json:"settings"`
}

type putInputDTO struct {
	Value string `json:"value"`
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	if !h.allowed(r.Context()) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if h.Store == nil {
		writeError(w, http.StatusServiceUnavailable, "settings store not configured")
		return
	}
	all, err := h.Store.All()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		slog.Error("settings list", "err", err)
		return
	}
	// Always surface the known keys, defaulting from the accessor so
	// the operator sees the value that's in effect even before they
	// have stored an explicit override.
	if _, ok := all[KeyRunHistoryLimit]; !ok {
		all[KeyRunHistoryLimit] = strconv.Itoa(RunHistoryLimit(h.Store))
	}
	if _, ok := all[KeyUpdateConcurrencyLimit]; !ok {
		all[KeyUpdateConcurrencyLimit] = strconv.Itoa(UpdateConcurrencyLimit(h.Store))
	}
	if _, ok := all[KeyProbeIntervalSeconds]; !ok {
		all[KeyProbeIntervalSeconds] = strconv.Itoa(ProbeIntervalSeconds(h.Store))
	}
	if _, ok := all[KeyProbeFailureThreshold]; !ok {
		all[KeyProbeFailureThreshold] = strconv.Itoa(ProbeFailureThreshold(h.Store))
	}
	if _, ok := all[KeyProbeSuccessThreshold]; !ok {
		all[KeyProbeSuccessThreshold] = strconv.Itoa(ProbeSuccessThreshold(h.Store))
	}
	if _, ok := all[KeyScheduleMisfireGraceSeconds]; !ok {
		all[KeyScheduleMisfireGraceSeconds] = strconv.Itoa(ScheduleMisfireGraceSeconds(h.Store))
	}
	for _, c := range logging.Components {
		k := LogLevelKey(c)
		if _, ok := all[k]; !ok {
			all[k] = LogLevel(h.Store, c)
		}
	}
	writeJSON(w, http.StatusOK, settingsResponseDTO{Settings: all})
}

func (h *Handler) put(w http.ResponseWriter, r *http.Request) {
	if !h.allowed(r.Context()) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if h.Store == nil {
		writeError(w, http.StatusServiceUnavailable, "settings store not configured")
		return
	}
	key := r.PathValue("key")
	var in putInputDTO
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	before, _ := h.Store.Get(key)

	switch key {
	case KeyRunHistoryLimit:
		n, err := strconv.Atoi(in.Value)
		if err != nil {
			writeError(w, http.StatusBadRequest, "value must be an integer")
			return
		}
		if err := SetRunHistoryLimit(h.Store, n); err != nil {
			if errors.Is(err, ErrInvalid) {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, "set failed")
			// key is user-controlled but slog's structured kv form doesn't
			// interpolate it into the message — gosec G706 false positive.
			slog.Error("settings set", "err", err, "key", key) //nolint:gosec
			return
		}
	case KeyUpdateConcurrencyLimit:
		n, err := strconv.Atoi(in.Value)
		if err != nil {
			writeError(w, http.StatusBadRequest, "value must be an integer")
			return
		}
		if err := SetUpdateConcurrencyLimit(h.Store, n); err != nil {
			if errors.Is(err, ErrInvalid) {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, "set failed")
			slog.Error("settings set", "err", err, "key", key) //nolint:gosec
			return
		}
	case KeyProbeIntervalSeconds:
		if err := h.setIntFromBody(w, in.Value, key, SetProbeIntervalSeconds); err != nil {
			return
		}
	case KeyProbeFailureThreshold:
		if err := h.setIntFromBody(w, in.Value, key, SetProbeFailureThreshold); err != nil {
			return
		}
	case KeyProbeSuccessThreshold:
		if err := h.setIntFromBody(w, in.Value, key, SetProbeSuccessThreshold); err != nil {
			return
		}
	case KeyScheduleMisfireGraceSeconds:
		if err := h.setIntFromBody(w, in.Value, key, SetScheduleMisfireGraceSeconds); err != nil {
			return
		}
	default:
		component, ok := LogLevelComponent(key)
		if !ok || !knownComponent(component) {
			writeError(w, http.StatusNotFound, "unknown setting")
			return
		}
		if err := h.setLogLevel(w, key, component, in.Value); err != nil {
			return
		}
	}

	h.emitAudit(r.Context(), key, before, in.Value)
	w.WriteHeader(http.StatusNoContent)
}

// setIntFromBody decodes value as an int and persists it through
// setter. Returns a non-nil error after writing the matching HTTP
// response so the caller can short-circuit. Shared by the three
// bounded-integer probe settings to keep each case a one-liner.
func (h *Handler) setIntFromBody(w http.ResponseWriter, value, key string, setter func(Store, int) error) error {
	n, err := strconv.Atoi(value)
	if err != nil {
		writeError(w, http.StatusBadRequest, "value must be an integer")
		return err
	}
	if err := setter(h.Store, n); err != nil {
		if errors.Is(err, ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return err
		}
		writeError(w, http.StatusInternalServerError, "set failed")
		// key is user-controlled but slog's structured kv form doesn't
		// interpolate it into the message — gosec G706 false positive.
		slog.Error("settings set", "err", err, "key", key) //nolint:gosec
		return err
	}
	return nil
}

// setLogLevel validates and persists a background-loop log level, then
// applies it live via OnLogLevelChange. On error it writes the matching
// HTTP response and returns non-nil so put can short-circuit.
func (h *Handler) setLogLevel(w http.ResponseWriter, key, component, value string) error {
	if err := SetLogLevel(h.Store, component, value); err != nil {
		if errors.Is(err, ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return err
		}
		writeError(w, http.StatusInternalServerError, "set failed")
		// key is user-controlled but slog's structured kv form doesn't
		// interpolate it into the message — gosec G706 false positive.
		slog.Error("settings set", "err", err, "key", key) //nolint:gosec
		return err
	}
	if h.OnLogLevelChange != nil {
		h.OnLogLevelChange(component, value)
	}
	return nil
}

// knownComponent reports whether name is one of the background loops
// that has an adjustable log level.
func knownComponent(name string) bool {
	for _, c := range logging.Components {
		if c == name {
			return true
		}
	}
	return false
}

func (h *Handler) allowed(ctx context.Context) bool {
	if h.CanManage == nil {
		return true
	}
	return h.CanManage(ctx)
}

func (h *Handler) emitAudit(ctx context.Context, key, before, after string) {
	if h.Audit == nil {
		return
	}
	d := audit.NewDetail()
	_ = d.SetSafe("key", key)
	_ = d.SetSafe("value_before", before)
	_ = d.SetSafe("value_after", after)
	if err := h.Audit.Log(ctx, audit.Event{
		Action:     "setting.set",
		Outcome:    audit.Success,
		TargetKind: "setting",
		TargetID:   key,
		Detail:     d,
	}); err != nil {
		// key is user-controlled but slog kv form doesn't interpolate
		// into the message — gosec G706 false positive.
		slog.Error("settings audit", "err", err, "key", key) //nolint:gosec
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("settings json encode", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

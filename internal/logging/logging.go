// SPDX-License-Identifier: Apache-2.0

// Package logging gives System Wrangler's noisier subsystems a
// per-subsystem "component" tag and an independently adjustable log
// level. These are the five background loops (probe, alert, schedule,
// notification, promtargets) plus two request-path subsystems: the
// scrape proxy (scrape) and the per-request HTTP access log (request),
// both of which Prometheus drives on every scrape interval.
//
// Each subsystem gets a logger from Component, which stamps a
// `component=<name>` attribute on every record — so an operator can
// filter the JSON stream (e.g. `jq 'select(.component=="probe")'`) —
// and gates that logger on its own *slog.LevelVar. The level is driven
// from the admin settings page (see internal/settings) and applied with
// SetLevel, which mutates the shared LevelVar in place: a change takes
// effect on the very next log call, no restart and no rebuilding of the
// logger.
package logging

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
)

// Component names. Each doubles as the suffix of the matching
// log_level_<component> setting key.
const (
	Probe        = "probe"
	Alert        = "alert"
	Schedule     = "schedule"
	Notification = "notification"
	Promtargets  = "promtargets"
	Scrape       = "scrape"
	Request      = "request"
)

// Components lists every subsystem that has an independently adjustable
// level, in the order they surface on the settings page. The first five
// are background loops; Scrape is the scrape proxy and Request is the
// HTTP access log (which only emits at Debug — see cmd/server).
var Components = []string{Probe, Alert, Schedule, Notification, Promtargets, Scrape, Request}

type registry struct {
	mu     sync.Mutex
	base   slog.Handler
	levels map[string]*slog.LevelVar
}

var reg = &registry{levels: map[string]*slog.LevelVar{}}

// SetBase records the handler component loggers delegate to. Call once
// at startup, after slog's default handler is configured and before any
// Component logger is built. When left unset, Component falls back to
// the process default handler at construction time.
func SetBase(h slog.Handler) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	reg.base = h
}

// levelVar returns the shared LevelVar for component, creating it
// (defaulting to info) on first use. The caller must hold reg.mu.
func (r *registry) levelVar(component string) *slog.LevelVar {
	lv, ok := r.levels[component]
	if !ok {
		lv = &slog.LevelVar{}
		lv.Set(slog.LevelInfo)
		r.levels[component] = lv
	}
	return lv
}

// Component returns a logger that stamps component=<name> on every
// record and is gated by that component's live level. The logger shares
// the component's LevelVar, so a later SetLevel(name, ...) takes effect
// on the next log call without rebuilding the logger.
func Component(name string) *slog.Logger {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	lv := reg.levelVar(name)
	base := reg.base
	if base == nil {
		base = slog.Default().Handler()
	}
	tagged := base.WithAttrs([]slog.Attr{slog.String("component", name)})
	return slog.New(&leveledHandler{base: tagged, level: lv})
}

// SetLevel updates component's live level from a string
// (debug|info|warn|error). An unknown level returns an error and leaves
// the current level unchanged.
func SetLevel(component, level string) error {
	lv, ok := ParseLevel(level)
	if !ok {
		return fmt.Errorf("logging: invalid level %q", level)
	}
	reg.mu.Lock()
	defer reg.mu.Unlock()
	reg.levelVar(component).Set(lv)
	return nil
}

// ParseLevel maps a setting string to an slog.Level. The bool is false
// for an unrecognised value so callers can reject it rather than
// silently defaulting.
func ParseLevel(s string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, true
	case "info":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error", "err":
		return slog.LevelError, true
	}
	return slog.LevelInfo, false
}

// leveledHandler delegates to base but gates Enabled on its own
// LevelVar, so each component's verbosity is independent of slog's
// global default level.
type leveledHandler struct {
	base  slog.Handler
	level *slog.LevelVar
}

func (h *leveledHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level.Level()
}

func (h *leveledHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.base.Handle(ctx, r)
}

func (h *leveledHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &leveledHandler{base: h.base.WithAttrs(attrs), level: h.level}
}

func (h *leveledHandler) WithGroup(name string) slog.Handler {
	return &leveledHandler{base: h.base.WithGroup(name), level: h.level}
}

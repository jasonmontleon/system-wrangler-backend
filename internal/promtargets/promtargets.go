// SPDX-License-Identifier: Apache-2.0

// Package promtargets generates the targets.json file Prometheus
// reads via file_sd_configs. The Go backend is the source of truth
// for "what's installed where"; this package translates that into
// the Prometheus discovery format and writes it atomically whenever
// the inventory changes.
//
// The output shape is one entry per installed exporter (state IN
// 'installed' or 'running'). Every entry's `targets` field points at
// the backend itself — Prometheus scrapes the backend's
// /internal/scrape/{system_id}/{exporter_id} endpoint, which
// SSH-tunnels through to the actual exporter on the host. That's
// what makes localhost-bound exporters reachable without exposing
// them on the wire.
package promtargets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"system-wrangler-backend/internal/exporters"
	"system-wrangler-backend/internal/systems"
)

// Sentinel errors.
var (
	ErrNotConfigured = errors.New("promtargets: writer is not fully wired")
)

// Entry is one element of the file_sd_configs JSON array. Prometheus
// reads this every few seconds via inotify; we re-emit on every
// inventory change.
type Entry struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

// Writer emits the targets file atomically and serialises concurrent
// regenerations so two events firing at once produce one well-formed
// file, not interleaved garbage.
type Writer struct {
	// Path is the file the backend writes; Prometheus reads the same
	// path via a shared volume. The parent directory must exist and
	// be writable.
	Path string
	// BackendTarget is the address Prometheus uses to reach the
	// backend, e.g. "system-wrangler:8081" inside a compose network
	// or "127.0.0.1:8081" inside a shared-localhost pod.
	BackendTarget string
	// Systems lets the writer enumerate hosts to label them with
	// hostname / group_id / display name.
	Systems systems.Store
	// Exporters lets the writer read every (system, exporter) row.
	Exporters exporters.Store

	mu sync.Mutex
}

// Regenerate scans system_exporters, joins hostnames + groups, and
// writes targets.json. Safe to call concurrently — calls serialise
// via the writer's mutex.
//
// The write is atomic: a temp file in the same directory, then
// os.Rename. Prometheus's inotify watcher sees a single file
// replacement.
func (w *Writer) Regenerate(_ context.Context) error {
	if w.Path == "" || w.Systems == nil || w.Exporters == nil || w.BackendTarget == "" {
		return ErrNotConfigured
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	hosts, err := w.Systems.List()
	if err != nil {
		return fmt.Errorf("promtargets: list systems: %w", err)
	}
	bySystemID := make(map[string]systems.System, len(hosts))
	for _, h := range hosts {
		bySystemID[h.ID] = h
	}

	entries := []Entry{}
	for _, h := range hosts {
		rows, err := w.Exporters.ListSystemExporters(h.ID)
		if err != nil {
			slog.Warn("promtargets: list system_exporters", "err", err, "system_id", h.ID) //nolint:gosec
			continue
		}
		for _, row := range rows {
			if row.State != exporters.StateInstalled && row.State != exporters.StateRunning {
				continue
			}
			labels := map[string]string{
				"__metrics_path__": fmt.Sprintf("/internal/scrape/%s/%s", h.ID, row.ExporterID),
				"system_id":        h.ID,
				"system_name":      h.Name,
				"hostname":         h.Hostname,
				"exporter_id":      row.ExporterID,
			}
			if h.GroupID != nil && *h.GroupID != "" {
				labels["group_id"] = *h.GroupID
			}
			entries = append(entries, Entry{
				Targets: []string{w.BackendTarget},
				Labels:  labels,
			})
		}
	}

	// Deterministic order so an unchanged inventory produces a
	// byte-identical file; Prometheus's inotify still fires on
	// rename, but file-content diffing tooling and a future
	// "did anything actually change?" guard both benefit.
	sort.Slice(entries, func(i, j int) bool {
		ai, bi := entries[i].Labels["system_id"], entries[j].Labels["system_id"]
		if ai != bi {
			return ai < bi
		}
		return entries[i].Labels["exporter_id"] < entries[j].Labels["exporter_id"]
	})

	body, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("promtargets: marshal: %w", err)
	}
	body = append(body, '\n')

	dir := filepath.Dir(w.Path)
	tmp, err := os.CreateTemp(dir, ".targets.json.tmp.")
	if err != nil {
		return fmt.Errorf("promtargets: create temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = os.Remove(tmpPath)
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("promtargets: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("promtargets: sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("promtargets: close temp: %w", err)
	}
	// Prometheus's reader needs read access; the file holds no
	// secrets (just inventory labels) so 0644 is intentional.
	if err := os.Chmod(tmpPath, 0o644); err != nil { //nolint:gosec // shared file with Prometheus sibling
		cleanup()
		return fmt.Errorf("promtargets: chmod: %w", err)
	}
	if err := os.Rename(tmpPath, w.Path); err != nil {
		cleanup()
		return fmt.Errorf("promtargets: rename: %w", err)
	}
	slog.Info("promtargets: wrote targets.json", "path", w.Path, "entries", len(entries))
	return nil
}

// Subscribe wires the writer to the events.Hub's broadcast surface
// so an inventory change triggers a fresh regenerate. The caller
// passes a function that subscribes to the hub; events `systems.changed`
// and `exporter.run.completed` both trigger.
//
// Debounced at 200ms so a fan-out producing several events in quick
// succession collapses to one write.
type subscribeFunc func(handler func(eventType string)) (cancel func())

// Run starts the background regenerator. Subscribes to the hub and
// debounces incoming events. The returned shutdown function flushes
// pending work and unsubscribes.
func (w *Writer) Run(ctx context.Context, subscribe subscribeFunc) func() {
	pending := make(chan struct{}, 1)
	cancelSub := subscribe(func(eventType string) {
		switch eventType {
		case "systems.changed", "exporter.run.completed":
			select {
			case pending <- struct{}{}:
			default:
			}
		}
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Initial generation: any state present at startup gets
		// reflected immediately.
		if err := w.Regenerate(ctx); err != nil {
			slog.Warn("promtargets: initial regenerate", "err", err)
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-pending:
				// Debounce window — accumulate any same-window
				// events without firing multiple regenerates.
				timer := time.NewTimer(200 * time.Millisecond)
				accumulate := true
				for accumulate {
					select {
					case <-pending:
						// drain
					case <-timer.C:
						accumulate = false
					case <-ctx.Done():
						if !timer.Stop() {
							<-timer.C
						}
						return
					}
				}
				if err := w.Regenerate(ctx); err != nil {
					slog.Warn("promtargets: regenerate", "err", err)
				}
			}
		}
	}()

	return func() {
		cancelSub()
		<-done
	}
}

// SPDX-License-Identifier: Apache-2.0

package systems

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Prober checks a single system for reachability. Returning nil means the system
// answered; any error means it did not.
type Prober interface {
	Probe(ctx context.Context, address string) error
}

// TCPProber dials a TCP port on the system. Default target is :22 since the
// fleet management direction (Ansible) requires SSH; addresses without a port
// have Port appended.
type TCPProber struct {
	Port    string
	Timeout time.Duration
}

// Probe attempts a TCP dial to address (host or host:port) within Timeout
// and returns nil on a successful connect.
func (p TCPProber) Probe(ctx context.Context, address string) error {
	target := address
	if _, _, err := net.SplitHostPort(address); err != nil {
		target = net.JoinHostPort(address, p.Port)
	}
	d := net.Dialer{Timeout: p.Timeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	return conn.Close()
}

// Probe runs the periodic reachability loop. Construct via fields; Run blocks
// until ctx is cancelled.
type Probe struct {
	Store  Store
	Prober Prober
	// Interval is the fallback cadence used when IntervalFn is nil
	// (mostly tests). Production wiring sets IntervalFn so the live
	// settings value is picked up each cycle without restart.
	Interval time.Duration
	// IntervalFn, when non-nil, is consulted at the end of every
	// Tick to decide the next sleep. Returning <= 0 falls back to
	// Interval. Bound to settings.ProbeIntervalSeconds in
	// cmd/server/main.go.
	IntervalFn func() time.Duration
	// FailThresholdFn returns the number of consecutive failures
	// required to flip a system to unreachable. Optional; nil is
	// treated as 1 (immediate flip — matches the pre-threshold
	// default).
	FailThresholdFn func() int
	// SuccThresholdFn mirrors FailThresholdFn for the recovery
	// path. Optional; nil is treated as 1.
	SuccThresholdFn func() int
	Timeout         time.Duration
	Workers         int
	Now             func() time.Time
	Logger          *slog.Logger
	// Trigger fires an immediate Tick when received. Optional; nil disables
	// the case (a nil channel never selects). Use a buffered channel of
	// size 1 so non-blocking sends drop cleanly when a tick is in flight.
	Trigger chan struct{}
	// OnChange fires once at the end of a Tick if any system's status
	// transitioned. Optional; nil is skipped. Wired to the event hub so
	// SPAs refresh without polling.
	OnChange func()
}

// Run probes all known systems immediately, then on the configured
// cadence (IntervalFn or Interval) until ctx is cancelled. Safe to
// invoke as a goroutine. The ticker is Reset after every cycle so a
// live settings change to probe_interval_seconds takes effect on the
// next sleep without a restart.
func (p *Probe) Run(ctx context.Context) {
	if p.Logger == nil {
		p.Logger = slog.Default()
	}
	if p.Now == nil {
		p.Now = time.Now
	}
	if p.Workers <= 0 {
		p.Workers = 10
	}
	p.Tick(ctx)
	current := p.currentInterval()
	t := time.NewTicker(current)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.Tick(ctx)
		case <-p.Trigger:
			p.Tick(ctx)
		}
		next := p.currentInterval()
		if next != current {
			t.Reset(next)
			current = next
		}
	}
}

// currentInterval returns the live cadence: IntervalFn() when set
// and positive, falling back to Interval otherwise.
func (p *Probe) currentInterval() time.Duration {
	if p.IntervalFn != nil {
		if d := p.IntervalFn(); d > 0 {
			return d
		}
	}
	return p.Interval
}

// failThreshold returns the live consecutive-failure threshold, or
// 1 when no provider is wired (matches the immediate-flip default).
func (p *Probe) failThreshold() int {
	if p.FailThresholdFn != nil {
		if n := p.FailThresholdFn(); n > 0 {
			return n
		}
	}
	return 1
}

// succThreshold returns the live consecutive-success threshold, or
// 1 when no provider is wired.
func (p *Probe) succThreshold() int {
	if p.SuccThresholdFn != nil {
		if n := p.SuccThresholdFn(); n > 0 {
			return n
		}
	}
	return 1
}

// Tick runs one probe cycle across all systems. Exposed for tests; Run calls
// it on its schedule. Calls OnChange (if set) once at the end if any
// system transitioned status this cycle. Reads the live failure /
// success thresholds once at the top of the cycle so a settings
// change mid-tick can't observe a per-system race.
func (p *Probe) Tick(ctx context.Context) {
	log := p.Logger
	if log == nil {
		log = slog.Default()
	}
	systems, err := p.Store.List()
	if err != nil {
		log.Error("list systems", "err", err)
		return
	}
	failT := p.failThreshold()
	succT := p.succThreshold()
	sem := make(chan struct{}, p.Workers)
	var wg sync.WaitGroup
	var changes atomic.Int32
	for _, h := range systems {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(h System) {
			defer wg.Done()
			defer func() { <-sem }()
			probeCtx, cancel := context.WithTimeout(ctx, p.Timeout)
			defer cancel()
			ok := p.Prober.Probe(probeCtx, h.Hostname) == nil
			transitioned, err := p.Store.UpdateProbe(h.ID, ok, p.Now(), failT, succT)
			if err != nil {
				log.Error("update probe result", "err", err, "id", h.ID)
				return
			}
			if transitioned {
				changes.Add(1)
			}
		}(h)
	}
	wg.Wait()
	log.Debug("probe cycle complete", "systems", len(systems), "changed", changes.Load())
	if changes.Load() > 0 && p.OnChange != nil {
		p.OnChange()
	}
}

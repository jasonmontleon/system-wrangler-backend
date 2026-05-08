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
	Store    Store
	Prober   Prober
	Interval time.Duration
	Timeout  time.Duration
	Workers  int
	Now      func() time.Time
	Logger   *slog.Logger
	// Trigger fires an immediate Tick when received. Optional; nil disables
	// the case (a nil channel never selects). Use a buffered channel of
	// size 1 so non-blocking sends drop cleanly when a tick is in flight.
	Trigger chan struct{}
	// OnChange fires once at the end of a Tick if any system's status
	// transitioned. Optional; nil is skipped. Wired to the event hub so
	// SPAs refresh without polling.
	OnChange func()
}

// Run probes all known systems immediately, then on every Interval until ctx is
// cancelled. Safe to invoke as a goroutine.
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
	t := time.NewTicker(p.Interval)
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
	}
}

// Tick runs one probe cycle across all systems. Exposed for tests; Run calls
// it on its schedule. Calls OnChange (if set) once at the end if any
// system transitioned status this cycle.
func (p *Probe) Tick(ctx context.Context) {
	systems, err := p.Store.List()
	if err != nil {
		p.Logger.Error("probe list", "err", err)
		return
	}
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
			newStatus := StatusUnreachable
			if ok {
				newStatus = StatusReachable
			}
			if h.Status != newStatus {
				changes.Add(1)
			}
			if err := p.Store.UpdateProbe(h.ID, ok, p.Now()); err != nil {
				p.Logger.Error("probe update", "err", err, "id", h.ID)
			}
		}(h)
	}
	wg.Wait()
	if changes.Load() > 0 && p.OnChange != nil {
		p.OnChange()
	}
}

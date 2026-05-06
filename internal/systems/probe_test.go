// SPDX-License-Identifier: AGPL-3.0-or-later

package systems

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTCPProberSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	p := TCPProber{Port: port, Timeout: time.Second}

	// Address without explicit port — prober should append.
	if err := p.Probe(context.Background(), host); err != nil {
		t.Errorf("bare host: %v", err)
	}
	// Address with explicit host:port — prober should accept.
	if err := p.Probe(context.Background(), ln.Addr().String()); err != nil {
		t.Errorf("host:port: %v", err)
	}
}

func TestTCPProberFailure(t *testing.T) {
	// Bind a port, then close it to guarantee nothing listens there.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()

	host, port, _ := net.SplitHostPort(addr)
	p := TCPProber{Port: port, Timeout: 200 * time.Millisecond}
	if err := p.Probe(context.Background(), host); err == nil {
		t.Fatal("expected dial error, got nil")
	}
}

// fakeProber lets tests control probe outcome by address.
type fakeProber struct {
	mu     sync.Mutex
	result map[string]error
	calls  int32
}

func (f *fakeProber) Probe(_ context.Context, address string) error {
	atomic.AddInt32(&f.calls, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.result[address]
}

func newQuietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestProbeTickUpdatesStatus(t *testing.T) {
	store := newTestStore()
	hUp, _ := store.Create(SystemInput{Name: "up", Hostname: "10.0.0.1"})
	hDown, _ := store.Create(SystemInput{Name: "down", Hostname: "10.0.0.2"})

	prober := &fakeProber{result: map[string]error{
		"10.0.0.1": nil,
		"10.0.0.2": errors.New("conn refused"),
	}}

	probeAt := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	p := &Probe{
		Store:    store,
		Prober:   prober,
		Interval: time.Hour,
		Timeout:  time.Second,
		Workers:  4,
		Now:      func() time.Time { return probeAt },
		Logger:   newQuietLogger(),
	}
	p.Tick(context.Background())

	got, _ := store.Get(hUp.ID)
	if got.Status != StatusReachable {
		t.Errorf("up.Status = %q", got.Status)
	}
	if got.LastSeen == nil || !got.LastSeen.Equal(probeAt) {
		t.Errorf("up.LastSeen = %v", got.LastSeen)
	}

	got, _ = store.Get(hDown.ID)
	if got.Status != StatusUnreachable {
		t.Errorf("down.Status = %q", got.Status)
	}
	if got.LastSeen != nil {
		t.Errorf("down.LastSeen = %v, want nil", got.LastSeen)
	}

	if got := atomic.LoadInt32(&prober.calls); got != 2 {
		t.Errorf("prober calls = %d, want 2", got)
	}
}

func TestProbeRunStopsOnContextCancel(t *testing.T) {
	store := newTestStore()
	for i := 0; i < 3; i++ {
		_, _ = store.Create(SystemInput{Name: "h" + strconv.Itoa(i), Hostname: "1.1.1.1"})
	}
	prober := &fakeProber{result: map[string]error{}}
	p := &Probe{
		Store:    store,
		Prober:   prober,
		Interval: 10 * time.Millisecond,
		Timeout:  time.Second,
		Workers:  4,
		Logger:   newQuietLogger(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.Run(ctx)
		close(done)
	}()
	// Let at least one tick happen, then cancel.
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not exit after cancel")
	}
	if atomic.LoadInt32(&prober.calls) == 0 {
		t.Error("prober was never called")
	}
}

// Sanity check: Probe.Run honours nil Logger / Now / Workers defaults.
func TestProbeRunDefaults(t *testing.T) {
	store := newTestStore()
	prober := &fakeProber{result: map[string]error{}}
	p := &Probe{Store: store, Prober: prober, Interval: time.Hour, Timeout: time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run so it exits immediately after the first Tick
	p.Run(ctx)
	if p.Workers <= 0 {
		t.Errorf("Workers default not applied: %d", p.Workers)
	}
	if p.Now == nil {
		t.Error("Now default not applied")
	}
	if p.Logger == nil {
		t.Error("Logger default not applied")
	}
}

// fakeListErrStore returns an error from List; verifies Tick logs and skips.
type fakeListErrStore struct{ MemStore }

func (f *fakeListErrStore) List() ([]System, error) { return nil, errors.New("boom") }

func TestProbeTickHandlesListError(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	p := &Probe{
		Store:   &fakeListErrStore{},
		Prober:  &fakeProber{result: map[string]error{}},
		Timeout: time.Second,
		Workers: 1,
		Now:     time.Now,
		Logger:  logger,
	}
	p.Tick(context.Background())
	if !strings.Contains(buf.String(), "probe list") {
		t.Errorf("expected probe list error log, got %q", buf.String())
	}
}

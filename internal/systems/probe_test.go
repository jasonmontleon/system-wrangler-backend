// SPDX-License-Identifier: Apache-2.0

package systems

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var nilLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// fakeProber returns a deterministic Probe result keyed by hostname.
// Concurrent because Probe.Tick fans out across a worker pool.
type fakeProber struct {
	mu      sync.Mutex
	verdict map[string]error
	calls   int
}

func (f *fakeProber) Probe(_ context.Context, address string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if v, ok := f.verdict[address]; ok {
		return v
	}
	return nil
}

func TestTCPProberDialsHostAndPort(t *testing.T) {
	// A real-ish TCP listener accepts the dial; closing right after is fine.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()
	p := TCPProber{
		Port:    "0", // shouldn't be appended since address has its own port
		Timeout: time.Second,
	}
	addr := l.Addr().String()
	if err := p.Probe(context.Background(), addr); err != nil {
		t.Errorf("Probe(%q) = %v, want nil", addr, err)
	}
}

func TestTCPProberAppendsPortWhenAddressIsBareHost(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()
	port := l.Addr().(*net.TCPAddr).Port
	p := TCPProber{
		Port:    portString(port),
		Timeout: time.Second,
	}
	if err := p.Probe(context.Background(), "127.0.0.1"); err != nil {
		t.Errorf("Probe(host-only) = %v, want nil", err)
	}
}

func TestTCPProberFailsWhenNoListener(t *testing.T) {
	p := TCPProber{
		Port:    "1",
		Timeout: 100 * time.Millisecond,
	}
	// Reserved-test discard address — connect should fail (refused or timeout).
	if err := p.Probe(context.Background(), "127.0.0.1:1"); err == nil {
		t.Error("Probe to unbound port = nil, want error")
	}
}

func TestProbeTickRunsAcrossAllSystemsAndFiresOnChange(t *testing.T) {
	store := NewMemStore()
	_, err := store.Create(SystemInput{Name: "a", Hostname: "a.example"})
	if err != nil {
		t.Fatalf("create a: %v", err)
	}
	bSys, err := store.Create(SystemInput{Name: "b", Hostname: "b.example"})
	if err != nil {
		t.Fatalf("create b: %v", err)
	}
	prober := &fakeProber{
		verdict: map[string]error{
			"b.example": errors.New("unreachable"),
		},
	}
	var changes atomic.Int32
	p := &Probe{
		Logger:   nilLogger,
		Now:      time.Now,
		Store:    store,
		Prober:   prober,
		Workers:  4,
		Timeout:  time.Second,
		Interval: time.Hour,
		OnChange: func() { changes.Add(1) },
	}
	p.Tick(context.Background())
	if prober.calls != 2 {
		t.Errorf("prober.calls = %d, want 2", prober.calls)
	}
	if changes.Load() < 1 {
		t.Errorf("OnChange not fired; want at least 1")
	}
	got, _ := store.Get(bSys.ID)
	if got.Status != StatusUnreachable {
		t.Errorf("system b status = %q, want %q", got.Status, StatusUnreachable)
	}
}

func TestProbeTickSkipsOnChangeWhenNoChange(t *testing.T) {
	store := NewMemStore()
	_, _ = store.Create(SystemInput{Name: "a", Hostname: "a.example"})
	prober := &fakeProber{}
	var changes atomic.Int32
	// First Tick records reachable status — that's a change from unprobed.
	p := &Probe{
		Logger:   nilLogger,
		Now:      time.Now,
		Store:    store,
		Prober:   prober,
		Workers:  1,
		Timeout:  time.Second,
		Interval: time.Hour,
		OnChange: func() { changes.Add(1) },
	}
	p.Tick(context.Background())
	first := changes.Load()
	// Second Tick: status was already reachable, so nothing should fire.
	p.Tick(context.Background())
	if changes.Load() != first {
		t.Errorf("OnChange fired on no-change tick (delta=%d)", changes.Load()-first)
	}
}

func TestProbeTickReturnsCleanlyOnListError(t *testing.T) {
	prober := &fakeProber{}
	p := &Probe{
		Logger:   nilLogger,
		Now:      time.Now,
		Store:    &errListStore{},
		Prober:   prober,
		Workers:  1,
		Timeout:  time.Second,
		Interval: time.Hour,
	}
	p.Tick(context.Background())
	if prober.calls != 0 {
		t.Errorf("prober called %d times despite list err", prober.calls)
	}
}

func TestProbeTickRespectsLiveThresholds(t *testing.T) {
	// Threshold 3/3: a single failure should not flip status, even
	// though the prober reports unreachable. Confirms Tick consults
	// FailThresholdFn / SuccThresholdFn and passes them to the
	// store rather than using the legacy "any failure flips" path.
	store := NewMemStore()
	h, _ := store.Create(SystemInput{Name: "a", Hostname: "a.example"})
	prober := &fakeProber{verdict: map[string]error{"a.example": errors.New("nope")}}
	var changes atomic.Int32
	p := &Probe{
		Logger:          nilLogger,
		Now:             time.Now,
		Store:           store,
		Prober:          prober,
		Workers:         1,
		Timeout:         time.Second,
		Interval:        time.Hour,
		FailThresholdFn: func() int { return 3 },
		SuccThresholdFn: func() int { return 3 },
		OnChange:        func() { changes.Add(1) },
	}
	p.Tick(context.Background())
	got, _ := store.Get(h.ID)
	if got.Status != StatusUnprobed {
		t.Errorf("after 1 fail with threshold 3: Status = %q, want unprobed", got.Status)
	}
	if got.ConsecutiveFailures != 1 {
		t.Errorf("ConsecutiveFailures = %d, want 1", got.ConsecutiveFailures)
	}
	if changes.Load() != 0 {
		t.Errorf("OnChange fired = %d, want 0 (no transition)", changes.Load())
	}
	// Two more failures → flip.
	p.Tick(context.Background())
	p.Tick(context.Background())
	got, _ = store.Get(h.ID)
	if got.Status != StatusUnreachable {
		t.Errorf("after 3 fails: Status = %q, want unreachable", got.Status)
	}
	if changes.Load() != 1 {
		t.Errorf("OnChange fired = %d, want exactly 1 transition", changes.Load())
	}
}

func TestProbeIntervalFnAndDefaults(t *testing.T) {
	// currentInterval / failThreshold / succThreshold without
	// providers fall back to Interval and 1 respectively.
	p := &Probe{Interval: 7 * time.Second}
	if got := p.currentInterval(); got != 7*time.Second {
		t.Errorf("currentInterval no-fn = %v, want 7s", got)
	}
	if got := p.failThreshold(); got != 1 {
		t.Errorf("failThreshold no-fn = %d, want 1", got)
	}
	if got := p.succThreshold(); got != 1 {
		t.Errorf("succThreshold no-fn = %d, want 1", got)
	}
	// A non-positive return from the provider also falls back.
	p.IntervalFn = func() time.Duration { return 0 }
	p.FailThresholdFn = func() int { return 0 }
	p.SuccThresholdFn = func() int { return -3 }
	if got := p.currentInterval(); got != 7*time.Second {
		t.Errorf("currentInterval fn=0 = %v, want fallback 7s", got)
	}
	if got := p.failThreshold(); got != 1 {
		t.Errorf("failThreshold fn=0 = %d, want 1", got)
	}
	if got := p.succThreshold(); got != 1 {
		t.Errorf("succThreshold fn<0 = %d, want 1", got)
	}
	// A positive provider value wins.
	p.IntervalFn = func() time.Duration { return 11 * time.Second }
	p.FailThresholdFn = func() int { return 5 }
	p.SuccThresholdFn = func() int { return 9 }
	if got := p.currentInterval(); got != 11*time.Second {
		t.Errorf("currentInterval fn=11s = %v", got)
	}
	if got := p.failThreshold(); got != 5 {
		t.Errorf("failThreshold fn=5 = %d", got)
	}
	if got := p.succThreshold(); got != 9 {
		t.Errorf("succThreshold fn=9 = %d", got)
	}
}

func TestProbeRunFiresImmediateTickAndExitsOnContextCancel(t *testing.T) {
	store := NewMemStore()
	_, _ = store.Create(SystemInput{Name: "a", Hostname: "a.example"})
	prober := &fakeProber{}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Probe{
		Logger:   nilLogger,
		Now:      time.Now,
		Store:    store,
		Prober:   prober,
		Workers:  1,
		Timeout:  time.Second,
		Interval: time.Hour,
	}
	done := make(chan struct{})
	go func() {
		p.Run(ctx)
		close(done)
	}()
	// Give the initial Tick a moment to run.
	for i := 0; i < 100; i++ {
		prober.mu.Lock()
		c := prober.calls
		prober.mu.Unlock()
		if c >= 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
	if prober.calls < 1 {
		t.Errorf("expected at least one immediate tick, got %d", prober.calls)
	}
}

func TestProbeRunRespondsToTriggerChannel(t *testing.T) {
	store := NewMemStore()
	_, _ = store.Create(SystemInput{Name: "a", Hostname: "a.example"})
	prober := &fakeProber{}
	ctx, cancel := context.WithCancel(context.Background())
	trigger := make(chan struct{}, 1)
	p := &Probe{
		Logger:   nilLogger,
		Now:      time.Now,
		Store:    store,
		Prober:   prober,
		Workers:  1,
		Timeout:  time.Second,
		Interval: time.Hour,
		Trigger:  trigger,
	}
	done := make(chan struct{})
	go func() {
		p.Run(ctx)
		close(done)
	}()
	// Initial Tick happens immediately; wait for it.
	waitFor(t, func() bool {
		prober.mu.Lock()
		defer prober.mu.Unlock()
		return prober.calls >= 1
	})
	prober.mu.Lock()
	before := prober.calls
	prober.mu.Unlock()
	trigger <- struct{}{}
	waitFor(t, func() bool {
		prober.mu.Lock()
		defer prober.mu.Unlock()
		return prober.calls > before
	})
	cancel()
	<-done
}

// TestProbeRunResetsIntervalWhenFnChanges exercises the IntervalFn
// re-read after every Tick. The fn returns a slow interval first,
// then a fast one; without the Reset path, the test would time out
// waiting for the second Tick.
func TestProbeRunResetsIntervalWhenFnChanges(t *testing.T) {
	store := NewMemStore()
	_, _ = store.Create(SystemInput{Name: "a", Hostname: "a.example"})
	prober := &fakeProber{}
	var calls atomic.Int32
	intervals := []time.Duration{20 * time.Millisecond, 50 * time.Millisecond}
	p := &Probe{
		Logger:   nilLogger,
		Now:      time.Now,
		Store:    store,
		Prober:   prober,
		Workers:  1,
		Timeout:  time.Second,
		Interval: time.Hour,
		IntervalFn: func() time.Duration {
			i := int(calls.Add(1) - 1)
			if i >= len(intervals) {
				i = len(intervals) - 1
			}
			return intervals[i]
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		p.Run(ctx)
		close(done)
	}()
	// Wait for at least 2 prober calls — the immediate Tick plus
	// one driven by the fast-reset interval (20ms). If Run was
	// stuck on the original 1h ticker, this would never arrive.
	waitFor(t, func() bool {
		prober.mu.Lock()
		defer prober.mu.Unlock()
		return prober.calls >= 2
	})
	cancel()
	<-done
}

// errListStore implements Store but returns an error from List.
type errListStore struct {
	MemStore
}

func (e *errListStore) List() ([]System, error) {
	return nil, errors.New("boom")
}

func portString(n int) string {
	// Avoid importing strconv just for this one path.
	if n <= 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met within 2s")
}

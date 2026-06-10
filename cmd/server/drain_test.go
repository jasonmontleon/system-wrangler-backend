// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type fakeLockCounter struct {
	counts []int // returned in order; last value repeats
	idx    atomic.Int32
	err    error
}

func (f *fakeLockCounter) CountLocks() (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	i := int(f.idx.Add(1)) - 1
	if i >= len(f.counts) {
		i = len(f.counts) - 1
	}
	return f.counts[i], nil
}

func TestDrainInFlightRunsWaitsUntilZero(t *testing.T) {
	// Two polls report runs still in flight, the third reports none.
	f := &fakeLockCounter{counts: []int{2, 1, 0}}
	start := time.Now()
	drainInFlightRuns(f, 10*time.Second)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("drain took %v; expected to return promptly once locks cleared", elapsed)
	}
	if f.idx.Load() < 3 {
		t.Errorf("polled %d times, want at least 3 (until zero)", f.idx.Load())
	}
}

func TestDrainInFlightRunsGivesUpAtGrace(t *testing.T) {
	// Locks never clear; the drain must return at the grace, not hang.
	f := &fakeLockCounter{counts: []int{3}}
	start := time.Now()
	drainInFlightRuns(f, 300*time.Millisecond)
	elapsed := time.Since(start)
	if elapsed < 250*time.Millisecond {
		t.Errorf("returned after %v; expected to wait out the ~300ms grace", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Errorf("returned after %v; grace should have bounded it", elapsed)
	}
}

func TestDrainInFlightRunsReturnsOnError(t *testing.T) {
	f := &fakeLockCounter{err: errors.New("db gone")}
	start := time.Now()
	drainInFlightRuns(f, 10*time.Second)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("error path took %v; should return immediately", elapsed)
	}
}

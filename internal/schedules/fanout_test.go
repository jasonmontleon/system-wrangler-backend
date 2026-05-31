// SPDX-License-Identifier: Apache-2.0

package schedules

import (
	"context"
	"errors"
	"testing"

	"system-wrangler-backend/internal/ansible"
	"system-wrangler-backend/internal/updaters"
)

type fakeRegistry struct {
	defs []updaters.Definition
	err  error
}

func (f fakeRegistry) All() ([]updaters.Definition, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.defs, nil
}

type fakeAvailStore struct {
	rows []updaters.Availability
	err  error
}

func (f fakeAvailStore) AvailabilityFor(string) ([]updaters.Availability, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.rows, nil
}

type fakeRunner struct {
	check func(systemID, updaterID string) (updaters.RunResult, error)
	apply func(systemID, updaterID string, packages []string) (updaters.RunResult, error)
}

func (f *fakeRunner) Check(_ context.Context, systemID, updaterID string) (updaters.RunResult, error) {
	return f.check(systemID, updaterID)
}

func (f *fakeRunner) Apply(_ context.Context, systemID, updaterID string, packages []string) (updaters.RunResult, error) {
	return f.apply(systemID, updaterID, packages)
}

func ok() (updaters.RunResult, error) {
	return updaters.RunResult{Status: ansible.RunSuccess}, nil
}
func fail() (updaters.RunResult, error) {
	return updaters.RunResult{Status: ansible.RunFailure, Reason: "fake fail"}, nil
}

func TestFanOutCheckSweepCountsSuccessAndFailure(t *testing.T) {
	reg := fakeRegistry{defs: []updaters.Definition{
		{ID: "dnf"},
		{ID: "fwupdmgr", CheckOnly: true},
		{ID: "disabled"},
	}}
	store := fakeAvailStore{rows: []updaters.Availability{
		{UpdaterID: "dnf", Enabled: true},
		{UpdaterID: "fwupdmgr", Enabled: true},
		{UpdaterID: "disabled", Enabled: false},
	}}
	runner := &fakeRunner{
		check: func(_, u string) (updaters.RunResult, error) {
			if u == "fwupdmgr" {
				return fail()
			}
			return ok()
		},
	}
	got := FanOutOnSystem(context.Background(), "sys-1", FanOutCheck, reg, store, runner)
	if got.Attempted != 2 || got.Succeeded != 1 || got.Failed != 1 || got.Skipped {
		t.Errorf("Check sweep: got %+v", got)
	}
}

func TestFanOutApplySweepSkipsCheckOnly(t *testing.T) {
	reg := fakeRegistry{defs: []updaters.Definition{
		{ID: "dnf"},
		{ID: "fwupdmgr", CheckOnly: true},
	}}
	store := fakeAvailStore{rows: []updaters.Availability{
		{UpdaterID: "dnf", Enabled: true},
		{UpdaterID: "fwupdmgr", Enabled: true},
	}}
	runner := &fakeRunner{
		apply: func(_, _ string, _ []string) (updaters.RunResult, error) { return ok() },
	}
	got := FanOutOnSystem(context.Background(), "sys-1", FanOutApply, reg, store, runner)
	if got.Attempted != 1 || got.Succeeded != 1 || got.Skipped {
		t.Errorf("Apply sweep should fire 1 updater (skipping check-only): %+v", got)
	}
}

func TestFanOutSkipsWhenNoEnabledTargets(t *testing.T) {
	reg := fakeRegistry{defs: []updaters.Definition{{ID: "dnf"}}}
	store := fakeAvailStore{rows: []updaters.Availability{
		{UpdaterID: "dnf", Enabled: false},
	}}
	runner := &fakeRunner{
		check: func(string, string) (updaters.RunResult, error) {
			t.Fatal("runner.Check should not be called")
			return updaters.RunResult{}, nil
		},
	}
	got := FanOutOnSystem(context.Background(), "sys-1", FanOutCheck, reg, store, runner)
	if !got.Skipped || got.Attempted != 0 {
		t.Errorf("Expected skip: %+v", got)
	}
}

func TestFanOutSkipsWhenRegistryFails(t *testing.T) {
	reg := fakeRegistry{err: errors.New("boom")}
	store := fakeAvailStore{}
	runner := &fakeRunner{}
	got := FanOutOnSystem(context.Background(), "sys-1", FanOutCheck, reg, store, runner)
	if !got.Skipped || got.Reason == "" {
		t.Errorf("Expected skip+reason: %+v", got)
	}
}

func TestFanOutSkipsWhenAvailabilityFails(t *testing.T) {
	reg := fakeRegistry{defs: []updaters.Definition{{ID: "dnf"}}}
	store := fakeAvailStore{err: errors.New("db dead")}
	runner := &fakeRunner{}
	got := FanOutOnSystem(context.Background(), "sys-1", FanOutCheck, reg, store, runner)
	if !got.Skipped || got.Reason == "" {
		t.Errorf("Expected skip+reason: %+v", got)
	}
}

func TestFanOutCountsRunnerErrAsFailure(t *testing.T) {
	reg := fakeRegistry{defs: []updaters.Definition{{ID: "dnf"}}}
	store := fakeAvailStore{rows: []updaters.Availability{{UpdaterID: "dnf", Enabled: true}}}
	runner := &fakeRunner{
		check: func(string, string) (updaters.RunResult, error) {
			return updaters.RunResult{}, errors.New("network down")
		},
	}
	got := FanOutOnSystem(context.Background(), "sys-1", FanOutCheck, reg, store, runner)
	if got.Attempted != 1 || got.Failed != 1 || got.Succeeded != 0 {
		t.Errorf("Runner error must count as failure: %+v", got)
	}
}

// SPDX-License-Identifier: Apache-2.0

package schedules

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"system-wrangler-backend/internal/ansible"
	"system-wrangler-backend/internal/systems"
)

type rebootSysStore struct {
	sys systems.System
	err error
}

func (r rebootSysStore) List() ([]systems.System, error) { return []systems.System{r.sys}, nil }
func (r rebootSysStore) Get(string) (systems.System, error) {
	if r.err != nil {
		return systems.System{}, r.err
	}
	return r.sys, nil
}

type fakeClearer struct {
	called bool
	err    error
}

func (f *fakeClearer) ClearRebootRequired(string) error { f.called = true; return f.err }

type fakeAnsible struct {
	status   ansible.RunStatus
	playbook string
	err      error
}

func (f *fakeAnsible) Run(_ context.Context, req ansible.Request) (ansible.Run, error) {
	if f.err != nil {
		return ansible.Run{}, f.err
	}
	if req.PlaybookPath != "" {
		data, err := os.ReadFile(req.PlaybookPath)
		if err == nil {
			f.playbook = string(data)
		}
	}
	return ansible.Run{Status: f.status}, nil
}

func TestRebootSkipsWhenFlagAbsent(t *testing.T) {
	store := rebootSysStore{sys: systems.System{ID: "s", RebootRequiredAt: nil}}
	clearer := &fakeClearer{}
	runner := &fakeAnsible{status: ansible.RunSuccess}
	rebooted, err := RebootIfRequired(context.Background(), "s", store, clearer, runner)
	if err != nil || rebooted {
		t.Errorf("expected skip, got rebooted=%v err=%v", rebooted, err)
	}
	if clearer.called {
		t.Error("ClearRebootRequired must not fire when flag is absent")
	}
}

func TestRebootRunsAndClearsFlag(t *testing.T) {
	now := time.Now()
	store := rebootSysStore{sys: systems.System{ID: "s", RebootRequiredAt: &now}}
	clearer := &fakeClearer{}
	runner := &fakeAnsible{status: ansible.RunSuccess}
	rebooted, err := RebootIfRequired(context.Background(), "s", store, clearer, runner)
	if err != nil || !rebooted {
		t.Errorf("expected success, got rebooted=%v err=%v", rebooted, err)
	}
	if !clearer.called {
		t.Error("ClearRebootRequired must fire after a successful reboot")
	}
	if !strings.Contains(runner.playbook, "ansible.builtin.reboot") {
		t.Errorf("Linux host should run ansible.builtin.reboot, playbook=%q", runner.playbook)
	}
}

func TestRebootPicksWindowsPlaybook(t *testing.T) {
	now := time.Now()
	store := rebootSysStore{sys: systems.System{ID: "s", IsWindows: true, RebootRequiredAt: &now}}
	runner := &fakeAnsible{status: ansible.RunSuccess}
	_, err := RebootIfRequired(context.Background(), "s", store, &fakeClearer{}, runner)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(runner.playbook, "ansible.windows.win_reboot") {
		t.Errorf("Windows host should run ansible.windows.win_reboot, playbook=%q", runner.playbook)
	}
}

func TestRebootSurfacesLookupError(t *testing.T) {
	store := rebootSysStore{err: errors.New("db dead")}
	_, err := RebootIfRequired(context.Background(), "s", store, &fakeClearer{}, &fakeAnsible{})
	if err == nil {
		t.Error("expected lookup error")
	}
}

func TestRebootSurfacesAnsibleRunError(t *testing.T) {
	now := time.Now()
	store := rebootSysStore{sys: systems.System{ID: "s", RebootRequiredAt: &now}}
	runner := &fakeAnsible{err: errors.New("ansible exploded")}
	_, err := RebootIfRequired(context.Background(), "s", store, &fakeClearer{}, runner)
	if err == nil {
		t.Error("expected ansible error")
	}
}

func TestRebootFailsWhenStatusNotSuccess(t *testing.T) {
	now := time.Now()
	store := rebootSysStore{sys: systems.System{ID: "s", RebootRequiredAt: &now}}
	runner := &fakeAnsible{status: ansible.RunFailure}
	_, err := RebootIfRequired(context.Background(), "s", store, &fakeClearer{}, runner)
	if err == nil {
		t.Error("expected error from failed reboot")
	}
}

func TestRebootReportsClearErrorButStillSaysRebooted(t *testing.T) {
	now := time.Now()
	store := rebootSysStore{sys: systems.System{ID: "s", RebootRequiredAt: &now}}
	clearer := &fakeClearer{err: errors.New("clear failed")}
	runner := &fakeAnsible{status: ansible.RunSuccess}
	rebooted, err := RebootIfRequired(context.Background(), "s", store, clearer, runner)
	if !rebooted {
		t.Error("rebooted=true expected even when clearing the flag fails")
	}
	if err == nil {
		t.Error("expected error from clearer")
	}
}

// SPDX-License-Identifier: Apache-2.0

package schedules

import (
	"errors"
	"testing"

	"system-wrangler-backend/internal/labels"
	"system-wrangler-backend/internal/systems"
)

type fakeSysStore struct {
	systems []systems.System
	err     error
}

func (f fakeSysStore) List() ([]systems.System, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.systems, nil
}
func (f fakeSysStore) Get(id string) (systems.System, error) {
	if f.err != nil {
		return systems.System{}, f.err
	}
	for _, s := range f.systems {
		if s.ID == id {
			return s, nil
		}
	}
	return systems.System{}, systems.ErrNotFound
}

type fakeLabelStore struct {
	bySystem map[string][]labels.Label
	err      error
}

func (f fakeLabelStore) ForSystems([]string) (map[string][]labels.Label, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.bySystem, nil
}

func makeInventory() fakeSysStore {
	gp := "grp-1"
	gq := "grp-2"
	return fakeSysStore{systems: []systems.System{
		{ID: "a", Name: "alpha", GroupID: &gp},
		{ID: "b", Name: "beta", GroupID: &gq},
		{ID: "c", Name: "gamma"}, // ungrouped
	}}
}

func TestResolveGlobal(t *testing.T) {
	got, err := ResolveTargets(Schedule{TargetKind: TargetGlobal}, makeInventory(), nil)
	if err != nil || len(got) != 3 {
		t.Errorf("got %d/%v want 3", len(got), err)
	}
}

func TestResolveGroup(t *testing.T) {
	got, err := ResolveTargets(
		Schedule{TargetKind: TargetGroup, TargetValue: "grp-1"},
		makeInventory(), nil,
	)
	if err != nil || len(got) != 1 || got[0].ID != "a" {
		t.Errorf("got %+v err %v", got, err)
	}
}

func TestResolveSystemsList(t *testing.T) {
	got, err := ResolveTargets(
		Schedule{TargetKind: TargetSystems, TargetValue: `["a","c"]`},
		makeInventory(), nil,
	)
	if err != nil || len(got) != 2 {
		t.Fatalf("got %+v err %v", got, err)
	}
	if got[0].ID != "a" || got[1].ID != "c" {
		t.Errorf("ids: %s %s", got[0].ID, got[1].ID)
	}
}

func TestResolveSystemsListMissingIDsBecomePlaceholder(t *testing.T) {
	// "a" exists, "missing" does not — should still appear so the
	// fan-out can record one failure per pinned id that drifted away.
	got, err := ResolveTargets(
		Schedule{TargetKind: TargetSystems, TargetValue: `["a","missing"]`},
		makeInventory(), nil,
	)
	if err != nil || len(got) != 2 {
		t.Fatalf("got %+v err %v", got, err)
	}
	if got[1].ID != "missing" || got[1].Status != systems.StatusUnreachable {
		t.Errorf("missing placeholder shape wrong: %+v", got[1])
	}
}

func TestResolveSystemsListBadJSON(t *testing.T) {
	_, err := ResolveTargets(
		Schedule{TargetKind: TargetSystems, TargetValue: `not-json`},
		makeInventory(), nil,
	)
	if err == nil {
		t.Error("expected error for bad JSON")
	}
}

func TestResolveSelector(t *testing.T) {
	inv := fakeSysStore{systems: []systems.System{
		{ID: "a"}, {ID: "b"}, {ID: "c"},
	}}
	v := "prod"
	lstore := fakeLabelStore{bySystem: map[string][]labels.Label{
		"a": {{Key: "env", Value: &v}},
		"b": {{Key: "env", Value: nil}},
		"c": {},
	}}
	got, err := ResolveTargets(
		Schedule{TargetKind: TargetSelector, TargetValue: "env=prod"},
		inv, lstore,
	)
	if err != nil || len(got) != 1 || got[0].ID != "a" {
		t.Errorf("got %+v err %v", got, err)
	}
}

func TestResolveSelectorBadGrammar(t *testing.T) {
	_, err := ResolveTargets(
		Schedule{TargetKind: TargetSelector, TargetValue: "==invalid"},
		fakeSysStore{}, fakeLabelStore{},
	)
	if err == nil {
		t.Error("expected error for bad selector")
	}
}

func TestResolveSelectorPropagatesListError(t *testing.T) {
	inv := fakeSysStore{err: errors.New("db dead")}
	_, err := ResolveTargets(
		Schedule{TargetKind: TargetSelector, TargetValue: "env=prod"},
		inv, fakeLabelStore{},
	)
	if err == nil {
		t.Error("expected error from systems.List")
	}
}

func TestResolveSelectorPropagatesLabelsError(t *testing.T) {
	inv := fakeSysStore{systems: []systems.System{{ID: "a"}}}
	lstore := fakeLabelStore{err: errors.New("labels broken")}
	_, err := ResolveTargets(
		Schedule{TargetKind: TargetSelector, TargetValue: "env=prod"},
		inv, lstore,
	)
	if err == nil {
		t.Error("expected error from labels.ForSystems")
	}
}

func TestResolveGroupPropagatesError(t *testing.T) {
	inv := fakeSysStore{err: errors.New("db dead")}
	_, err := ResolveTargets(
		Schedule{TargetKind: TargetGroup, TargetValue: "grp-1"},
		inv, nil,
	)
	if err == nil {
		t.Error("expected error")
	}
}

func TestResolveUnknownKind(t *testing.T) {
	_, err := ResolveTargets(
		Schedule{TargetKind: "fleet"},
		makeInventory(), nil,
	)
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("expected ErrInvalid, got %v", err)
	}
}

// SPDX-License-Identifier: Apache-2.0

package targeting

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

func TestValidateValue(t *testing.T) {
	tests := []struct {
		name    string
		kind    Kind
		value   string
		wantErr bool
	}{
		{"global empty ok", Global, "", false},
		{"global with value rejected", Global, "x", true},
		{"group ok", Group, "grp-1", false},
		{"group empty rejected", Group, "", true},
		{"systems ok", Systems, `["a","b"]`, false},
		{"systems bad json", Systems, "not-json", true},
		{"systems empty array", Systems, `[]`, true},
		{"systems empty id", Systems, `["a",""]`, true},
		{"selector ok", Selector, "env=prod", false},
		{"selector empty rejected", Selector, "", true},
		{"selector bad grammar", Selector, "==bad", true},
		{"unknown kind", Kind("fleet"), "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateValue(tt.kind, tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateValue(%q,%q) err=%v wantErr=%v", tt.kind, tt.value, err, tt.wantErr)
			}
			if tt.wantErr && err != nil && !errors.Is(err, ErrInvalid) {
				t.Errorf("expected ErrInvalid, got %v", err)
			}
		})
	}
}

func TestResolveGlobal(t *testing.T) {
	got, err := Resolve(Global, "", makeInventory(), nil)
	if err != nil || len(got) != 3 {
		t.Errorf("got %d/%v want 3", len(got), err)
	}
}

func TestResolveGroup(t *testing.T) {
	got, err := Resolve(Group, "grp-1", makeInventory(), nil)
	if err != nil || len(got) != 1 || got[0].ID != "a" {
		t.Errorf("got %+v err %v", got, err)
	}
}

func TestResolveSystemsList(t *testing.T) {
	got, err := Resolve(Systems, `["a","c"]`, makeInventory(), nil)
	if err != nil || len(got) != 2 {
		t.Fatalf("got %+v err %v", got, err)
	}
	if got[0].ID != "a" || got[1].ID != "c" {
		t.Errorf("ids: %s %s", got[0].ID, got[1].ID)
	}
}

func TestResolveSystemsListMissingIDsBecomePlaceholder(t *testing.T) {
	got, err := Resolve(Systems, `["a","missing"]`, makeInventory(), nil)
	if err != nil || len(got) != 2 {
		t.Fatalf("got %+v err %v", got, err)
	}
	if got[1].ID != "missing" || got[1].Status != systems.StatusUnreachable {
		t.Errorf("missing placeholder shape wrong: %+v", got[1])
	}
}

func TestResolveSystemsListBadJSON(t *testing.T) {
	if _, err := Resolve(Systems, "not-json", makeInventory(), nil); err == nil {
		t.Error("expected error for bad JSON")
	}
}

func TestResolveSelector(t *testing.T) {
	inv := fakeSysStore{systems: []systems.System{{ID: "a"}, {ID: "b"}, {ID: "c"}}}
	v := "prod"
	lstore := fakeLabelStore{bySystem: map[string][]labels.Label{
		"a": {{Key: "env", Value: &v}},
		"b": {{Key: "env", Value: nil}},
		"c": {},
	}}
	got, err := Resolve(Selector, "env=prod", inv, lstore)
	if err != nil || len(got) != 1 || got[0].ID != "a" {
		t.Errorf("got %+v err %v", got, err)
	}
}

func TestResolveSelectorBadGrammar(t *testing.T) {
	if _, err := Resolve(Selector, "==invalid", fakeSysStore{}, fakeLabelStore{}); err == nil {
		t.Error("expected error for bad selector")
	}
}

func TestResolveSelectorPropagatesListError(t *testing.T) {
	inv := fakeSysStore{err: errors.New("db dead")}
	if _, err := Resolve(Selector, "env=prod", inv, fakeLabelStore{}); err == nil {
		t.Error("expected error from systems.List")
	}
}

func TestResolveSelectorPropagatesLabelsError(t *testing.T) {
	inv := fakeSysStore{systems: []systems.System{{ID: "a"}}}
	lstore := fakeLabelStore{err: errors.New("labels broken")}
	if _, err := Resolve(Selector, "env=prod", inv, lstore); err == nil {
		t.Error("expected error from labels.ForSystems")
	}
}

func TestResolveGroupPropagatesError(t *testing.T) {
	inv := fakeSysStore{err: errors.New("db dead")}
	if _, err := Resolve(Group, "grp-1", inv, nil); err == nil {
		t.Error("expected error")
	}
}

func TestResolveUnknownKind(t *testing.T) {
	_, err := Resolve(Kind("fleet"), "", makeInventory(), nil)
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("expected ErrInvalid, got %v", err)
	}
}

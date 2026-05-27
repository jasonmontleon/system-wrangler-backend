// SPDX-License-Identifier: Apache-2.0

package labels_test

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/labels"
	"system-wrangler-backend/internal/systems"
)

// storeFactory builds a fresh Store for each subtest in TestStoreContract.
// The seed callback returns a function that creates a system row in
// whatever the implementation's referential context is (real systems
// table for SQLite, no-op accepting predicate for MemStore).
type storeFactory struct {
	name  string
	build func(t *testing.T) (labels.Store, func(name string) string)
}

func factories() []storeFactory {
	return []storeFactory{
		{
			name: "MemStore",
			build: func(_ *testing.T) (labels.Store, func(string) string) {
				s := labels.NewMemStore()
				existing := map[string]bool{}
				s.Exists = func(id string) bool { return existing[id] }
				return s, func(name string) string {
					existing[name] = true
					return name
				}
			},
		},
		{
			name: "SQLiteStore",
			build: func(t *testing.T) (labels.Store, func(string) string) {
				dsn := "file:" + filepath.Join(t.TempDir(), "labels.db")
				db, err := database.Open(dsn)
				if err != nil {
					t.Fatalf("database.Open: %v", err)
				}
				t.Cleanup(func() { _ = db.Close() })
				sysStore, err := systems.NewSQLiteStore(db)
				if err != nil {
					t.Fatalf("systems.NewSQLiteStore: %v", err)
				}
				store, err := labels.NewSQLiteStore(db)
				if err != nil {
					t.Fatalf("labels.NewSQLiteStore: %v", err)
				}
				return store, func(name string) string {
					sys, err := sysStore.Create(systems.SystemInput{
						Name: name, Hostname: name + ".example",
					})
					if err != nil {
						t.Fatalf("systems.Create: %v", err)
					}
					return sys.ID
				}
			},
		},
	}
}

func TestStoreContract(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			t.Run("SetGetDelete", func(t *testing.T) {
				s, seed := f.build(t)
				sid := seed("h1")
				prod := "prod"
				if _, err := s.Set(sid, "env", &prod, false); err != nil {
					t.Fatalf("set env=prod: %v", err)
				}
				if _, err := s.Set(sid, "oncall", nil, false); err != nil {
					t.Fatalf("set oncall: %v", err)
				}
				got, err := s.ForSystem(sid)
				if err != nil {
					t.Fatalf("for system: %v", err)
				}
				if len(got) != 2 {
					t.Fatalf("got %d labels, want 2: %+v", len(got), got)
				}
				if got[0].Key != "env" || got[0].Value == nil || *got[0].Value != "prod" {
					t.Errorf("got[0] = %+v, want env=prod", got[0])
				}
				if got[1].Key != "oncall" || got[1].Value != nil {
					t.Errorf("got[1] = %+v, want bare oncall", got[1])
				}
				if err := s.Delete(sid, "env"); err != nil {
					t.Fatalf("delete: %v", err)
				}
				got, err = s.ForSystem(sid)
				if err != nil || len(got) != 1 {
					t.Fatalf("after delete: got=%+v err=%v", got, err)
				}
				if err := s.Delete(sid, "env"); !errors.Is(err, labels.ErrNotFound) {
					t.Errorf("delete missing: err = %v, want ErrNotFound", err)
				}
			})

			t.Run("SetReplacesValue", func(t *testing.T) {
				s, seed := f.build(t)
				sid := seed("h1")
				v1, v2 := "prod", "staging"
				if _, err := s.Set(sid, "env", &v1, false); err != nil {
					t.Fatalf("first set: %v", err)
				}
				if _, err := s.Set(sid, "env", &v2, false); err != nil {
					t.Fatalf("second set: %v", err)
				}
				got, err := s.ForSystem(sid)
				if err != nil {
					t.Fatalf("for system: %v", err)
				}
				if len(got) != 1 || got[0].Value == nil || *got[0].Value != "staging" {
					t.Errorf("got %+v, want single env=staging", got)
				}
			})

			t.Run("ReservedPrefixRejected", func(t *testing.T) {
				s, seed := f.build(t)
				sid := seed("h1")
				if _, err := s.Set(sid, "system-wrangler.io/discovered", nil, false); !errors.Is(err, labels.ErrReserved) {
					t.Errorf("err = %v, want ErrReserved", err)
				}
				if _, err := s.Set(sid, "system-wrangler.io/discovered", nil, true); err != nil {
					t.Errorf("allowReserved should accept: %v", err)
				}
			})

			t.Run("InvalidKeyRejected", func(t *testing.T) {
				s, seed := f.build(t)
				sid := seed("h1")
				if _, err := s.Set(sid, "bad key!", nil, false); !errors.Is(err, labels.ErrInvalid) {
					t.Errorf("err = %v, want ErrInvalid", err)
				}
			})

			t.Run("UnknownSystem", func(t *testing.T) {
				s, _ := f.build(t)
				if _, err := s.Set("does-not-exist", "env", nil, false); !errors.Is(err, labels.ErrNotFound) {
					t.Errorf("err = %v, want ErrNotFound", err)
				}
			})

			t.Run("EmptySystemIDRejected", func(t *testing.T) {
				s, _ := f.build(t)
				if _, err := s.Set("", "env", nil, false); !errors.Is(err, labels.ErrInvalid) {
					t.Errorf("err = %v, want ErrInvalid", err)
				}
			})

			t.Run("EmptyValueAllowed", func(t *testing.T) {
				s, seed := f.build(t)
				sid := seed("h1")
				empty := ""
				if _, err := s.Set(sid, "tier", &empty, false); err != nil {
					t.Fatalf("set tier=\"\": %v", err)
				}
				got, err := s.ForSystem(sid)
				if err != nil || len(got) != 1 || got[0].Value == nil || *got[0].Value != "" {
					t.Errorf("got = %+v err = %v", got, err)
				}
			})

			t.Run("DeleteOnUnknownSystem", func(t *testing.T) {
				s, _ := f.build(t)
				if err := s.Delete("nope", "env"); !errors.Is(err, labels.ErrNotFound) {
					t.Errorf("err = %v, want ErrNotFound", err)
				}
			})

			t.Run("InvalidValueRejected", func(t *testing.T) {
				s, seed := f.build(t)
				sid := seed("h1")
				bad := "has space"
				if _, err := s.Set(sid, "env", &bad, false); !errors.Is(err, labels.ErrInvalid) {
					t.Errorf("err = %v, want ErrInvalid", err)
				}
			})

			t.Run("ForSystems", func(t *testing.T) {
				s, seed := f.build(t)
				a := seed("h1")
				b := seed("h2")
				c := seed("h3")
				prod, db := "prod", "db"
				if _, err := s.Set(a, "env", &prod, false); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Set(a, "role", &db, false); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Set(b, "env", &prod, false); err != nil {
					t.Fatal(err)
				}
				got, err := s.ForSystems([]string{a, b, c})
				if err != nil {
					t.Fatalf("ForSystems: %v", err)
				}
				if len(got[a]) != 2 || len(got[b]) != 1 || len(got[c]) != 0 {
					t.Errorf("counts: a=%d b=%d c=%d, want 2/1/0",
						len(got[a]), len(got[b]), len(got[c]))
				}
				if empty, err := s.ForSystems(nil); err != nil || len(empty) != 0 {
					t.Errorf("nil input: got=%v err=%v", empty, err)
				}
			})

			t.Run("Summary", func(t *testing.T) {
				s, seed := f.build(t)
				a := seed("h1")
				b := seed("h2")
				prod, stg := "prod", "staging"
				if _, err := s.Set(a, "env", &prod, false); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Set(b, "env", &stg, false); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Set(a, "oncall", nil, false); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Set(b, "oncall", nil, false); err != nil {
					t.Fatal(err)
				}
				got, err := s.Summary()
				if err != nil {
					t.Fatalf("summary: %v", err)
				}
				keys := make([]string, len(got))
				for i, ks := range got {
					keys[i] = ks.Key
				}
				if !reflect.DeepEqual(keys, []string{"env", "oncall"}) {
					t.Errorf("keys = %v, want [env oncall]", keys)
				}
				env := got[0]
				if env.Count != 2 || len(env.Values) != 2 {
					t.Errorf("env summary = %+v", env)
				}
				oncall := got[1]
				if oncall.Count != 2 || len(oncall.Values) != 1 || oncall.Values[0].Value != nil {
					t.Errorf("oncall summary = %+v", oncall)
				}
			})
		})
	}
}

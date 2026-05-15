// SPDX-License-Identifier: Apache-2.0

package secretscan

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"system-wrangler-backend/internal/secrets"
)

type stubSource struct {
	name  string
	items []Item
	err   error
}

func (s stubSource) Name() string { return s.name }
func (s stubSource) ListUndecryptable(*secrets.Vault) ([]Item, error) {
	if s.err != nil {
		return nil, s.err
	}
	out := make([]Item, len(s.items))
	copy(out, s.items)
	return out, nil
}
func (s stubSource) CountUndecryptable(*secrets.Vault) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	return len(s.items), nil
}

func deterministicKey(seed byte) []byte {
	k := make([]byte, secrets.KeySize)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return k
}

func newVault(t *testing.T) *secrets.Vault {
	t.Helper()
	v, err := secrets.NewVaultFromKey(deterministicKey(7))
	if err != nil {
		t.Fatalf("NewVaultFromKey: %v", err)
	}
	return v
}

func TestHandler_List_AggregatesAndSorts(t *testing.T) {
	v := newVault(t)
	h := &Handler{
		Vault: v,
		Sources: []Source{
			stubSource{
				name: "z-source",
				items: []Item{
					{Kind: "user_totp", Field: "secret", TargetID: "u1", TargetLabel: "bob"},
				},
			},
			stubSource{
				name: "a-source",
				items: []Item{
					{Kind: "user_totp", Field: "pending", TargetID: "u2", TargetLabel: "alice"},
					{Kind: "user_totp", Field: "secret", TargetID: "u2", TargetLabel: "alice"},
				},
			},
		},
	}

	mux := http.NewServeMux()
	h.Register(mux, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/admin/secrets/undecryptable", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 3 {
		t.Errorf("Count = %d, want 3", resp.Count)
	}
	want := []struct {
		label, field string
	}{
		{"alice", "pending"},
		{"alice", "secret"},
		{"bob", "secret"},
	}
	for i, w := range want {
		if resp.Items[i].TargetLabel != w.label || resp.Items[i].Field != w.field {
			t.Errorf("Items[%d] = {%s, %s}, want {%s, %s}", i,
				resp.Items[i].TargetLabel, resp.Items[i].Field, w.label, w.field)
		}
	}
}

func TestHandler_List_Forbidden(t *testing.T) {
	h := &Handler{
		Vault:   newVault(t),
		Sources: []Source{stubSource{name: "s"}},
		CanScan: func(context.Context) bool { return false },
	}
	req := httptest.NewRequest(http.MethodGet, "/api/admin/secrets/undecryptable", nil)
	rec := httptest.NewRecorder()
	h.list(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestHandler_List_NilVault(t *testing.T) {
	h := &Handler{Sources: []Source{stubSource{name: "s"}}}
	req := httptest.NewRequest(http.MethodGet, "/api/admin/secrets/undecryptable", nil)
	rec := httptest.NewRecorder()
	h.list(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestHandler_List_SourceError(t *testing.T) {
	h := &Handler{
		Vault: newVault(t),
		Sources: []Source{
			stubSource{name: "broken", err: errors.New("boom")},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/admin/secrets/undecryptable", nil)
	rec := httptest.NewRecorder()
	h.list(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] == "" {
		t.Error("expected error message")
	}
}

func TestHandler_List_EmptySourcesReturnsZero(t *testing.T) {
	h := &Handler{Vault: newVault(t)}
	req := httptest.NewRequest(http.MethodGet, "/api/admin/secrets/undecryptable", nil)
	rec := httptest.NewRecorder()
	h.list(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 0 || len(resp.Items) != 0 {
		t.Errorf("got %+v, want zero", resp)
	}
}

func TestErrNoSources(t *testing.T) {
	if ErrNoSources.Error() == "" {
		t.Error("ErrNoSources message is empty")
	}
}

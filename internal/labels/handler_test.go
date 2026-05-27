// SPDX-License-Identifier: Apache-2.0

package labels_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"system-wrangler-backend/internal/labels"
)

type auditCall struct {
	action string
	sys    labels.SystemRef
	key    string
	value  *string
}

type styleAuditCall struct {
	action, key, color string
}

type fixture struct {
	srv         *httptest.Server
	handler     *labels.Handler
	store       labels.Store
	styles      labels.StyleStore
	seeded      map[string]labels.SystemRef
	audits      *[]auditCall
	styleAudits *[]styleAuditCall
	changes     *atomic.Int32
}

// newHandlerFixture spins up the labels handler against an in-memory
// label store, a recording audit closure, and a lookup over a small
// seeded SystemRef set. Tests inject visibility / edit predicates as
// needed.
func newHandlerFixture(t *testing.T) *fixture {
	t.Helper()
	store := labels.NewMemStore()
	seeded := map[string]labels.SystemRef{
		"sys-1": {ID: "sys-1", Name: "alpha"},
		"sys-2": {ID: "sys-2", Name: "beta", GroupID: ptr("g-1")},
	}
	store.Exists = func(id string) bool { _, ok := seeded[id]; return ok }

	h := labels.NewHandler(store)
	h.Lookup = func(id string) (labels.SystemRef, error) {
		s, ok := seeded[id]
		if !ok {
			return labels.SystemRef{}, labels.ErrSystemNotFound
		}
		return s, nil
	}
	var audits []auditCall
	h.Audit = func(_ context.Context, action string, sys labels.SystemRef, key string, value *string) {
		audits = append(audits, auditCall{action: action, sys: sys, key: key, value: value})
	}
	styleStore := labels.NewMemStyleStore()
	h.Styles = styleStore
	var styleAudits []styleAuditCall
	h.StyleAudit = func(_ context.Context, action, key, color string) {
		styleAudits = append(styleAudits, styleAuditCall{action: action, key: key, color: color})
	}
	changes := &atomic.Int32{}
	h.OnChange = func() { changes.Add(1) }
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &fixture{
		srv: srv, handler: h, store: store, styles: styleStore,
		seeded: seeded, audits: &audits, styleAudits: &styleAudits, changes: changes,
	}
}

func ptr(s string) *string { return &s }

func mustDo(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	resp, err := http.DefaultClient.Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func TestHandler_Summary(t *testing.T) {
	f := newHandlerFixture(t)
	prod := "prod"
	if _, err := f.store.Set("sys-1", "env", &prod, false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := f.store.Set("sys-2", "oncall", nil, false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	resp := mustDo(t, mustReq(t, "GET", f.srv.URL+"/api/labels", nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got []labels.KeySummary
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d summaries, want 2: %+v", len(got), got)
	}
}

func TestHandler_ListForSystem(t *testing.T) {
	f := newHandlerFixture(t)
	prod := "prod"
	if _, err := f.store.Set("sys-1", "env", &prod, false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	resp := mustDo(t, mustReq(t, "GET", f.srv.URL+"/api/systems/sys-1/labels", nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got []labels.Label
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].Key != "env" {
		t.Errorf("got = %+v, want [env=prod]", got)
	}
}

func TestHandler_ListForSystem_NotFound(t *testing.T) {
	f := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, "GET", f.srv.URL+"/api/systems/missing/labels", nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandler_ListForSystem_Invisible(t *testing.T) {
	f := newHandlerFixture(t)
	f.handler.VisibleSystem = func(_ context.Context, s labels.SystemRef) bool {
		return s.ID != "sys-2"
	}
	resp := mustDo(t, mustReq(t, "GET", f.srv.URL+"/api/systems/sys-2/labels", nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for hidden system", resp.StatusCode)
	}
}

func TestHandler_Set(t *testing.T) {
	f := newHandlerFixture(t)
	body := `{"value":"prod"}`
	resp := mustDo(t, mustReq(t, "PUT", f.srv.URL+"/api/systems/sys-1/labels/env", body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body = %s", resp.StatusCode, readBody(resp))
	}
	if got := f.changes.Load(); got != 1 {
		t.Errorf("changes = %d, want 1", got)
	}
	ls, _ := f.store.ForSystem("sys-1")
	if len(ls) != 1 || ls[0].Value == nil || *ls[0].Value != "prod" {
		t.Errorf("store = %+v, want env=prod", ls)
	}
	if len(*f.audits) != 1 || (*f.audits)[0].action != "system.label.set" || (*f.audits)[0].key != "env" {
		t.Errorf("audits = %+v, want one set audit", *f.audits)
	}
}

func TestHandler_Set_BareTag(t *testing.T) {
	f := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, "PUT", f.srv.URL+"/api/systems/sys-1/labels/oncall", `{"value":null}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	ls, _ := f.store.ForSystem("sys-1")
	if len(ls) != 1 || ls[0].Value != nil {
		t.Errorf("store = %+v, want bare oncall", ls)
	}
}

func TestHandler_Set_BadJSON(t *testing.T) {
	f := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, "PUT", f.srv.URL+"/api/systems/sys-1/labels/env", `{`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandler_Set_InvalidKey(t *testing.T) {
	f := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, "PUT", f.srv.URL+"/api/systems/sys-1/labels/bad%20key", `{"value":"x"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandler_Set_ReservedKey(t *testing.T) {
	f := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, "PUT",
		f.srv.URL+"/api/systems/sys-1/labels/system-wrangler.io%2Fdiscovered",
		`{"value":"ansible"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for reserved prefix", resp.StatusCode)
	}
}

func TestHandler_Set_Forbidden(t *testing.T) {
	f := newHandlerFixture(t)
	f.handler.CanEditSystem = func(_ context.Context, _ labels.SystemRef) bool { return false }
	resp := mustDo(t, mustReq(t, "PUT", f.srv.URL+"/api/systems/sys-1/labels/env", `{"value":"prod"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHandler_Set_UnknownSystem(t *testing.T) {
	f := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, "PUT", f.srv.URL+"/api/systems/missing/labels/env", `{"value":"prod"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandler_Delete(t *testing.T) {
	f := newHandlerFixture(t)
	prod := "prod"
	if _, err := f.store.Set("sys-1", "env", &prod, false); err != nil {
		t.Fatal(err)
	}
	resp := mustDo(t, mustReq(t, "DELETE", f.srv.URL+"/api/systems/sys-1/labels/env", nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := f.changes.Load(); got != 1 {
		t.Errorf("changes = %d, want 1", got)
	}
	ls, _ := f.store.ForSystem("sys-1")
	if len(ls) != 0 {
		t.Errorf("after delete labels = %+v, want empty", ls)
	}
	if len(*f.audits) != 1 || (*f.audits)[0].action != "system.label.delete" {
		t.Errorf("audits = %+v, want one delete audit", *f.audits)
	}
}

func TestHandler_Delete_NotFound(t *testing.T) {
	f := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, "DELETE", f.srv.URL+"/api/systems/sys-1/labels/env", nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for absent label", resp.StatusCode)
	}
}

// TestHandler_LookupNotWired covers the safety net: a handler that
// somehow services a per-system endpoint without a Lookup callback
// fails fast instead of nil-pointer-panicking.
func TestHandler_LookupNotWired(t *testing.T) {
	store := labels.NewMemStore()
	h := labels.NewHandler(store)
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp := mustDo(t, mustReq(t, "GET", srv.URL+"/api/systems/x/labels", nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func mustReq(t *testing.T, method, url string, body any) *http.Request {
	t.Helper()
	var r io.Reader
	if body != nil {
		switch v := body.(type) {
		case string:
			r = strings.NewReader(v)
		case []byte:
			r = bytes.NewReader(v)
		default:
			b, _ := json.Marshal(v)
			r = bytes.NewReader(b)
		}
	}
	req, err := http.NewRequest(method, url, r) //nolint:noctx,gosec
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if r != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func readBody(resp *http.Response) string {
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestHandler_ListStyles(t *testing.T) {
	f := newHandlerFixture(t)
	if err := f.styles.Set("env", "blue"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	resp := mustDo(t, mustReq(t, "GET", f.srv.URL+"/api/label-styles", nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["env"] != "blue" {
		t.Errorf("got = %+v, want env=blue", got)
	}
}

func TestHandler_SetStyle(t *testing.T) {
	f := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, "PUT", f.srv.URL+"/api/label-styles/env", `{"color":"blue"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body = %s", resp.StatusCode, readBody(resp))
	}
	got, _ := f.styles.All()
	if got["env"] != "blue" {
		t.Errorf("styles = %+v, want env=blue", got)
	}
	if got := f.changes.Load(); got != 1 {
		t.Errorf("changes = %d, want 1", got)
	}
	if len(*f.styleAudits) != 1 || (*f.styleAudits)[0].action != "label_style.set" {
		t.Errorf("styleAudits = %+v", *f.styleAudits)
	}
}

func TestHandler_SetStyle_BadColor(t *testing.T) {
	f := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, "PUT", f.srv.URL+"/api/label-styles/env", `{"color":"chartreuse"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandler_SetStyle_BadKey(t *testing.T) {
	f := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, "PUT", f.srv.URL+"/api/label-styles/bad%20key", `{"color":"blue"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandler_SetStyle_BadJSON(t *testing.T) {
	f := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, "PUT", f.srv.URL+"/api/label-styles/env", `{`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandler_SetStyle_Forbidden(t *testing.T) {
	f := newHandlerFixture(t)
	f.handler.CanManageStyles = func(_ context.Context) bool { return false }
	resp := mustDo(t, mustReq(t, "PUT", f.srv.URL+"/api/label-styles/env", `{"color":"blue"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHandler_DeleteStyle(t *testing.T) {
	f := newHandlerFixture(t)
	if err := f.styles.Set("env", "blue"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	resp := mustDo(t, mustReq(t, "DELETE", f.srv.URL+"/api/label-styles/env", nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	got, _ := f.styles.All()
	if _, ok := got["env"]; ok {
		t.Errorf("after delete styles = %+v, want env absent", got)
	}
	if len(*f.styleAudits) != 1 || (*f.styleAudits)[0].action != "label_style.delete" {
		t.Errorf("styleAudits = %+v", *f.styleAudits)
	}
}

func TestHandler_DeleteStyle_NotFound(t *testing.T) {
	f := newHandlerFixture(t)
	resp := mustDo(t, mustReq(t, "DELETE", f.srv.URL+"/api/label-styles/missing", nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// brokenStyleStore returns a synthetic error from each method so the
// handler's error branches (500 responses) get exercised.
type brokenStyleStore struct{}

func (brokenStyleStore) All() (map[string]string, error) { return nil, errBroken }
func (brokenStyleStore) Set(string, string) error        { return errBroken }
func (brokenStyleStore) Delete(string) error             { return errBroken }

var errBroken = errBrokenT("broken")

type errBrokenT string

func (e errBrokenT) Error() string { return string(e) }

func TestHandler_StyleStoreBackendFailures(t *testing.T) {
	store := labels.NewMemStore()
	h := labels.NewHandler(store)
	h.Styles = brokenStyleStore{}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, tc := range []struct {
		method, path, body string
	}{
		{"GET", "/api/label-styles", ""},
		{"PUT", "/api/label-styles/env", `{"color":"blue"}`},
		{"DELETE", "/api/label-styles/env", ""},
	} {
		var body any
		if tc.body != "" {
			body = tc.body
		}
		resp := mustDo(t, mustReq(t, tc.method, srv.URL+tc.path, body))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("%s %s status = %d, want 500", tc.method, tc.path, resp.StatusCode)
		}
	}
}

func TestHandler_DeleteStyle_Forbidden(t *testing.T) {
	f := newHandlerFixture(t)
	if err := f.styles.Set("env", "blue"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	f.handler.CanManageStyles = func(_ context.Context) bool { return false }
	resp := mustDo(t, mustReq(t, "DELETE", f.srv.URL+"/api/label-styles/env", nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

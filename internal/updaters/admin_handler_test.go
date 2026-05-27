// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeSyntax returns whatever err the test wants.
type fakeSyntax struct {
	calls int
	err   error
}

func (f *fakeSyntax) Check(_ context.Context, _ []byte) error {
	f.calls++
	return f.err
}

func newAdminFixture(t *testing.T) (*AdminHandler, *httptest.Server, *fakeSyntax, *runnerFixture) {
	t.Helper()
	rf := newRunnerFixture(t)
	syntax := &fakeSyntax{}
	h := &AdminHandler{
		Registry:  rf.registry,
		Syntax:    syntax,
		Audit:     rf.auditStore,
		CanManage: func(context.Context) bool { return true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return h, srv, syntax, rf
}

func samplePostBody() createInputDTO {
	return createInputDTO{
		ID:            "tester",
		DisplayName:   "tester",
		Description:   "made by test",
		DetectBinary:  "tester",
		CheckPlaybook: "- hosts: all\n  tasks: []\n",
		ApplyPlaybook: "- hosts: all\n  tasks: []\n",
	}
}

func encode(t *testing.T, v any) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return bytes.NewReader(b)
}

func TestAdminListIncludesBuiltinAndCustom(t *testing.T) {
	_, srv, _, rf := newAdminFixture(t)
	if _, err := rf.registry.CreateCustom(sampleDef("custom.alpha")); err != nil {
		t.Fatalf("CreateCustom: %v", err)
	}
	resp, err := http.Get(srv.URL + "/api/admin/updater-definitions")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got listResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	hasBuiltin, hasCustom := false, false
	for _, d := range got.Definitions {
		if d.ID == "builtin.dnf" {
			hasBuiltin = true
		}
		if d.ID == "custom.alpha" {
			hasCustom = true
		}
	}
	if !hasBuiltin || !hasCustom {
		t.Errorf("list missing entries: %+v", got)
	}
}

// TestAdminListSupportsExclusionsFlag pins which updaters advertise
// exclusion support. The flag drives the exclusion form's dropdown on
// the SPA — turning it on for a non-supporting builtin would let
// operators add rules that silently do nothing.
func TestAdminListSupportsExclusionsFlag(t *testing.T) {
	_, srv, _, rf := newAdminFixture(t)
	if _, err := rf.registry.CreateCustom(sampleDef("custom.alpha")); err != nil {
		t.Fatalf("CreateCustom: %v", err)
	}
	resp, err := http.Get(srv.URL + "/api/admin/updater-definitions")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var got listResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := map[string]bool{
		// v1 supported per research/package-exclusions.md.
		"builtin.dnf":        true,
		"builtin.pacman":     true,
		"builtin.zypper":     true,
		"builtin.pkg":        true,
		"builtin.winget":     true,
		"builtin.chocolatey": true,
		// v2 hold-based managers — research/package-exclusions-v2.md.
		"builtin.apt":     true,
		"builtin.brew":    true,
		"builtin.snap":    true,
		"builtin.flatpak": true,
		"builtin.xbps":    true,
		"builtin.scoop":   true,
		// Custom updaters default to true (operator trust).
		"custom.alpha": true,
		// No-mechanism builtins stay false.
		"builtin.apk":            false,
		"builtin.pkg_add":        false,
		"builtin.pkgin":          false,
		"builtin.eopkg":          false,
		"builtin.mas":            false,
		"builtin.softwareupdate": false,
		"builtin.windowsupdate":  false,
		"builtin.fwupdmgr":       false,
		"builtin.syspatch":       false,
	}
	gotByID := map[string]bool{}
	for _, d := range got.Definitions {
		gotByID[d.ID] = d.SupportsExclusions
	}
	for id, expected := range want {
		actual, present := gotByID[id]
		if !present {
			t.Errorf("definition %q absent from list", id)
			continue
		}
		if actual != expected {
			t.Errorf("supportsExclusions[%q] = %v, want %v", id, actual, expected)
		}
	}
}

func TestAdminCreatePrependsCustomPrefix(t *testing.T) {
	_, srv, syntax, _ := newAdminFixture(t)
	resp, err := http.Post(srv.URL+"/api/admin/updater-definitions", "application/json", encode(t, samplePostBody()))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		body, _ := readBody(resp)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	var got definitionDTO
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ID != "custom.tester" {
		t.Errorf("id = %q, want custom.tester", got.ID)
	}
	// Syntax checker called twice (check + apply bodies).
	if syntax.calls != 2 {
		t.Errorf("syntax.calls = %d, want 2", syntax.calls)
	}
}

func TestAdminCreateRejectsBuiltinNamespace(t *testing.T) {
	_, srv, _, _ := newAdminFixture(t)
	in := samplePostBody()
	in.ID = "builtin.dnf"
	resp, err := http.Post(srv.URL+"/api/admin/updater-definitions", "application/json", encode(t, in))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminCreateInlineCredentialRejected(t *testing.T) {
	_, srv, _, _ := newAdminFixture(t)
	in := samplePostBody()
	in.CheckPlaybook = "- hosts: all\n  tasks:\n  - name: oops\n    debug:\n      password: hunter2\n"
	resp, err := http.Post(srv.URL+"/api/admin/updater-definitions", "application/json", encode(t, in))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	body, _ := readBody(resp)
	if !strings.Contains(body, "password") {
		t.Errorf("body should name the offending key: %s", body)
	}
}

func TestAdminCreateSyntaxFailureSurfacesStderr(t *testing.T) {
	_, srv, syntax, _ := newAdminFixture(t)
	syntax.err = errors.New(string(rune(0x73)) + "yntax: oh no") // ErrSyntax-wrapped done below
	syntax.err = errSyntaxWith("ERROR! conflicting keyword: yaml stuff")
	resp, err := http.Post(srv.URL+"/api/admin/updater-definitions", "application/json", encode(t, samplePostBody()))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	body, _ := readBody(resp)
	if !strings.Contains(body, "conflicting keyword") {
		t.Errorf("stderr text not surfaced: %s", body)
	}
}

// errSyntaxWith returns an error wrapping ErrSyntax for fakeSyntax to
// return. Mirrors the production wrap in AnsibleSyntaxChecker.Check.
func errSyntaxWith(msg string) error {
	return wrapSyntax(msg)
}

// wrapSyntax wraps ErrSyntax with the supplied stderr line. Defined
// in the test file because the production helper is private to the
// syntax checker.
func wrapSyntax(msg string) error {
	return errors.Join(ErrSyntax, errors.New(msg))
}

func TestAdminUpdateRoundTrip(t *testing.T) {
	_, srv, _, rf := newAdminFixture(t)
	if _, err := rf.registry.CreateCustom(sampleDef("custom.beta")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	patch := updateInputDTO{
		DisplayName:   "renamed",
		Description:   "patched",
		DetectBinary:  "tester",
		CheckPlaybook: "- hosts: all\n  tasks: []\n",
		ApplyPlaybook: "- hosts: all\n  tasks: []\n",
	}
	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/admin/updater-definitions/custom.beta", encode(t, patch))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := readBody(resp)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	var got definitionDTO
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.DisplayName != "renamed" {
		t.Errorf("display = %q", got.DisplayName)
	}
}

func TestAdminUpdateRejectsBuiltinID(t *testing.T) {
	_, srv, _, _ := newAdminFixture(t)
	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/admin/updater-definitions/builtin.dnf", encode(t, updateInputDTO{
		DisplayName:   "x",
		DetectBinary:  "dnf",
		CheckPlaybook: "- hosts: all\n",
		ApplyPlaybook: "- hosts: all\n",
	}))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminDeleteSoftDeletes(t *testing.T) {
	_, srv, _, rf := newAdminFixture(t)
	if _, err := rf.registry.CreateCustom(sampleDef("custom.gamma")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/admin/updater-definitions/custom.gamma", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
	d, err := rf.registry.Get("custom.gamma")
	if err != nil {
		t.Fatalf("Get after delete: %v", err)
	}
	if !d.IsDeleted() {
		t.Errorf("row not soft-deleted: %+v", d)
	}
	// Audit row.
	rows := auditRowsWithAction(t, rf.auditStore, "updater.delete")
	if len(rows) != 1 || rows[0].TargetID != "custom.gamma" {
		t.Errorf("audit rows = %+v", rows)
	}
}

func TestAdminDeleteUnknown(t *testing.T) {
	_, srv, _, _ := newAdminFixture(t)
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/admin/updater-definitions/custom.ghost", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAdminForbiddenWithoutCanManage(t *testing.T) {
	h, srv, _, _ := newAdminFixture(t)
	h.CanManage = func(context.Context) bool { return false }
	resp, err := http.Post(srv.URL+"/api/admin/updater-definitions", "application/json", encode(t, samplePostBody()))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAdminCreateAuditCarriesShas(t *testing.T) {
	_, srv, _, rf := newAdminFixture(t)
	resp, err := http.Post(srv.URL+"/api/admin/updater-definitions", "application/json", encode(t, samplePostBody()))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	rows := auditRowsWithAction(t, rf.auditStore, "updater.create")
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d", len(rows))
	}
	d := rows[0].Detail
	if _, ok := d["check_sha"].(string); !ok {
		t.Errorf("check_sha missing: %v", d)
	}
	if _, ok := d["apply_sha"].(string); !ok {
		t.Errorf("apply_sha missing: %v", d)
	}
}

func TestAdminCreateBadJSON(t *testing.T) {
	_, srv, _, _ := newAdminFixture(t)
	resp, err := http.Post(srv.URL+"/api/admin/updater-definitions", "application/json", strings.NewReader("not json"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminCreateEmptyIDRejected(t *testing.T) {
	_, srv, _, _ := newAdminFixture(t)
	in := samplePostBody()
	in.ID = ""
	resp, err := http.Post(srv.URL+"/api/admin/updater-definitions", "application/json", encode(t, in))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminCreateDuplicateConflict(t *testing.T) {
	_, srv, _, rf := newAdminFixture(t)
	if _, err := rf.registry.CreateCustom(sampleDef("custom.tester")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	resp, err := http.Post(srv.URL+"/api/admin/updater-definitions", "application/json", encode(t, samplePostBody()))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
}

func TestScanInlineCredentials(t *testing.T) {
	cases := []struct {
		body string
		want bool
	}{
		{"- hosts: all\n  vars:\n    password: x\n", true},
		{"- hosts: all\n  vars:\n    token: x\n", true},
		{"- hosts: all\n  vars:\n    SECRET: x\n", true},
		{"- hosts: all\n  vars:\n    user: x\n", false},
	}
	for _, tt := range cases {
		err := scanInlineCredentials([]byte(tt.body))
		got := err != nil
		if got != tt.want {
			t.Errorf("scanInlineCredentials(%q) -> err=%v, want match=%v", tt.body, err, tt.want)
		}
	}
}

func TestNormalizeCustomID(t *testing.T) {
	cases := map[string]string{
		"":            "",
		" foo ":       "custom.foo",
		"custom.bar":  "custom.bar",
		"builtin.dnf": "builtin.dnf", // passes through; downstream rejects
		"  ":          "",
	}
	for in, want := range cases {
		if got := normalizeCustomID(in); got != want {
			t.Errorf("normalizeCustomID(%q) = %q, want %q", in, got, want)
		}
	}
}

func readBody(resp *http.Response) (string, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(resp.Body)
	return buf.String(), err
}

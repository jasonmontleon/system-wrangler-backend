// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/groups"
	"system-wrangler-backend/internal/secrets"
	"system-wrangler-backend/internal/systems"
)

type handlerFixture struct {
	srv     *httptest.Server
	store   *SQLiteStore
	systems *systems.SQLiteStore
	groups  *groups.SQLiteStore
	audit   *audit.Store
	vault   *secrets.Vault
	handler *Handler

	// Gates — tests flip these to false to exercise denial paths.
	allowGlobal func(context.Context) bool
	allowGroup  func(context.Context, string) bool
	allowSystem func(context.Context, systems.System) bool
	allowRead   func(context.Context, systems.System) bool
}

func newFixture(t *testing.T) *handlerFixture {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "creds-h.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	sysStore, err := systems.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("systems.NewSQLiteStore: %v", err)
	}
	grpStore, err := groups.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("groups.NewSQLiteStore: %v", err)
	}
	credStore, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("credentials.NewSQLiteStore: %v", err)
	}
	auditStore, err := audit.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStore: %v", err)
	}
	vault := testVault(t, 11)

	f := &handlerFixture{
		store:       credStore,
		systems:     sysStore,
		groups:      grpStore,
		audit:       auditStore,
		vault:       vault,
		allowGlobal: func(context.Context) bool { return true },
		allowGroup:  func(context.Context, string) bool { return true },
		allowSystem: func(context.Context, systems.System) bool { return true },
		allowRead:   func(context.Context, systems.System) bool { return true },
	}
	f.handler = &Handler{
		Store:           credStore,
		Vault:           vault,
		Systems:         sysStore,
		Groups:          grpStore,
		Audit:           auditStore,
		CanManageGlobal: func(ctx context.Context) bool { return f.allowGlobal(ctx) },
		CanManageGroup:  func(ctx context.Context, id string) bool { return f.allowGroup(ctx, id) },
		CanManageSystem: func(ctx context.Context, s systems.System) bool { return f.allowSystem(ctx, s) },
		CanReadSystem:   func(ctx context.Context, s systems.System) bool { return f.allowRead(ctx, s) },
	}
	mux := http.NewServeMux()
	f.handler.Register(mux, nil)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *handlerFixture) do(t *testing.T, method, path string, body any) *http.Response {
	t.Helper()
	var rdr *bytes.Buffer
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewBuffer(b)
	} else {
		rdr = bytes.NewBuffer(nil)
	}
	req, err := http.NewRequest(method, f.srv.URL+path, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func TestPutGlobalSWGeneratedRoundTrip(t *testing.T) {
	f := newFixture(t)
	resp := f.do(t, http.MethodPut, "/api/admin/ansible-credentials/global", map[string]any{
		"ansibleUser": "ansible",
		"key":         map[string]any{"origin": "sw_generated"},
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got slotDTO
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ScopeKind != ScopeGlobal {
		t.Errorf("scopeKind = %q, want global", got.ScopeKind)
	}
	if got.AnsibleUser != "ansible" {
		t.Errorf("ansibleUser = %q, want ansible", got.AnsibleUser)
	}
	if got.Origin != OriginSWGenerated {
		t.Errorf("origin = %q, want sw_generated", got.Origin)
	}
	if !strings.HasPrefix(got.PublicKey, "ssh-ed25519 ") {
		t.Errorf("publicKey = %q, want ssh-ed25519 prefix", got.PublicKey)
	}

	// GET the slot back; private key bytes never appear in the body.
	getResp := f.do(t, http.MethodGet, "/api/admin/ansible-credentials/global", nil)
	defer func() { _ = getResp.Body.Close() }()
	body, _ := newReader(t, getResp.Body)
	if strings.Contains(string(body), "BEGIN OPENSSH PRIVATE KEY") {
		t.Error("private key bytes leaked in GET response body")
	}
	if strings.Contains(string(body), "ciphertext") {
		t.Error("sealed ciphertext leaked in GET response body")
	}

	// One audit row with action ansible_credential.set.
	recs, _, err := f.audit.ListQuery(audit.Query{Action: "ansible_credential.set", Limit: 5})
	if err != nil {
		t.Fatalf("audit.ListQuery: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(recs))
	}
	if got := recs[0].Detail["scope_kind"]; got != "global" {
		t.Errorf("audit scope_kind = %v, want global", got)
	}
}

func TestPutUserSuppliedRoundTrip(t *testing.T) {
	f := newFixture(t)
	_, privPEM, err := GenerateEd25519()
	if err != nil {
		t.Fatalf("GenerateEd25519: %v", err)
	}
	resp := f.do(t, http.MethodPut, "/api/admin/ansible-credentials/global", map[string]any{
		"ansibleUser": "deploy",
		"key": map[string]any{
			"origin":        "user_supplied",
			"privateKeyPem": string(privPEM),
		},
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got slotDTO
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Origin != OriginUserSupplied {
		t.Errorf("origin = %q, want user_supplied", got.Origin)
	}
	// Re-open the stored sealed key with the same vault and confirm
	// we get back the original PEM bytes verbatim.
	slot, err := f.store.GetByScope(ScopeGlobal, "")
	if err != nil {
		t.Fatalf("GetByScope: %v", err)
	}
	plain, err := OpenWith(f.vault, slot.PrivateKey)
	if err != nil {
		t.Fatalf("OpenWith: %v", err)
	}
	if !bytes.Equal(plain, privPEM) {
		t.Error("decrypted bytes do not match uploaded PEM")
	}
}

func TestPutUserSuppliedRejectsBadPEM(t *testing.T) {
	f := newFixture(t)
	resp := f.do(t, http.MethodPut, "/api/admin/ansible-credentials/global", map[string]any{
		"ansibleUser": "u",
		"key": map[string]any{
			"origin":        "user_supplied",
			"privateKeyPem": "this is not a PEM",
		},
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestPutGlobalForbidden(t *testing.T) {
	f := newFixture(t)
	f.allowGlobal = func(context.Context) bool { return false }
	resp := f.do(t, http.MethodPut, "/api/admin/ansible-credentials/global", map[string]any{
		"ansibleUser": "u",
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestDeleteGlobal(t *testing.T) {
	f := newFixture(t)
	// Put first so there's something to delete.
	resp := f.do(t, http.MethodPut, "/api/admin/ansible-credentials/global", map[string]any{
		"ansibleUser": "u",
	})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("seed PUT status = %d", resp.StatusCode)
	}
	delResp := f.do(t, http.MethodDelete, "/api/admin/ansible-credentials/global", nil)
	_ = delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE status = %d, want 204", delResp.StatusCode)
	}
	getResp := f.do(t, http.MethodGet, "/api/admin/ansible-credentials/global", nil)
	_ = getResp.Body.Close()
	if getResp.StatusCode != http.StatusNotFound {
		t.Errorf("GET after DELETE status = %d, want 404", getResp.StatusCode)
	}
}

func TestPutGroupMissingGroup(t *testing.T) {
	f := newFixture(t)
	resp := f.do(t, http.MethodPut, "/api/groups/no-such-group/ansible-credential", map[string]any{
		"ansibleUser": "u",
	})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestEffectiveResolvesHierarchy(t *testing.T) {
	f := newFixture(t)
	// Set a global default (sw_generated key + user).
	resp := f.do(t, http.MethodPut, "/api/admin/ansible-credentials/global", map[string]any{
		"ansibleUser": "ansible",
		"key":         map[string]any{"origin": "sw_generated"},
	})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("seed global status = %d", resp.StatusCode)
	}
	// Create a group and override only the user at that scope.
	g, err := f.groups.Create(groups.GroupInput{Name: "prod"})
	if err != nil {
		t.Fatalf("groups.Create: %v", err)
	}
	resp = f.do(t, http.MethodPut, "/api/groups/"+g.ID+"/ansible-credential", map[string]any{
		"ansibleUser": "deploy",
	})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("group PUT status = %d", resp.StatusCode)
	}
	// Create a system in that group.
	sys, err := f.systems.Create(systems.SystemInput{Name: "host-1", Hostname: "h1.example"})
	if err != nil {
		t.Fatalf("systems.Create: %v", err)
	}
	if err := f.systems.SetGroup(sys.ID, &g.ID); err != nil {
		t.Fatalf("systems.SetGroup: %v", err)
	}
	// Resolve.
	effResp := f.do(t, http.MethodGet, "/api/systems/"+sys.ID+"/effective-credential", nil)
	defer func() { _ = effResp.Body.Close() }()
	if effResp.StatusCode != http.StatusOK {
		t.Fatalf("effective status = %d", effResp.StatusCode)
	}
	var eff effectiveDTO
	if err := json.NewDecoder(effResp.Body).Decode(&eff); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if eff.AnsibleUser != "deploy" || eff.UserSource != ScopeGroup {
		t.Errorf("user = (%q, %q), want (deploy, group)", eff.AnsibleUser, eff.UserSource)
	}
	if eff.KeySource != ScopeGlobal || eff.KeyOrigin != OriginSWGenerated {
		t.Errorf("key source/origin = (%q, %q), want (global, sw_generated)", eff.KeySource, eff.KeyOrigin)
	}
	if eff.PublicKey == "" {
		t.Error("publicKey is empty")
	}
}

func TestEffectiveIncomplete(t *testing.T) {
	f := newFixture(t)
	// Only a user is set globally; no key anywhere.
	resp := f.do(t, http.MethodPut, "/api/admin/ansible-credentials/global", map[string]any{
		"ansibleUser": "u",
	})
	_ = resp.Body.Close()
	sys, err := f.systems.Create(systems.SystemInput{Name: "host-2", Hostname: "h2.example"})
	if err != nil {
		t.Fatalf("systems.Create: %v", err)
	}
	eff := f.do(t, http.MethodGet, "/api/systems/"+sys.ID+"/effective-credential", nil)
	defer func() { _ = eff.Body.Close() }()
	if eff.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", eff.StatusCode)
	}
}

func TestEffectiveSystemHiddenFromScope(t *testing.T) {
	f := newFixture(t)
	f.allowRead = func(context.Context, systems.System) bool { return false }
	sys, err := f.systems.Create(systems.SystemInput{Name: "h3", Hostname: "h3.example"})
	if err != nil {
		t.Fatalf("systems.Create: %v", err)
	}
	eff := f.do(t, http.MethodGet, "/api/systems/"+sys.ID+"/effective-credential", nil)
	_ = eff.Body.Close()
	// 404 (not 403) — same disclosure rule the systems handler uses.
	if eff.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", eff.StatusCode)
	}
}

func TestListGlobal(t *testing.T) {
	f := newFixture(t)
	for _, body := range []map[string]any{
		{"ansibleUser": "global-user"},
		// also seed a group slot for variety
	} {
		resp := f.do(t, http.MethodPut, "/api/admin/ansible-credentials/global", body)
		_ = resp.Body.Close()
	}
	g, _ := f.groups.Create(groups.GroupInput{Name: "g"})
	resp := f.do(t, http.MethodPut, "/api/groups/"+g.ID+"/ansible-credential", map[string]any{"ansibleUser": "gu"})
	_ = resp.Body.Close()

	list := f.do(t, http.MethodGet, "/api/admin/ansible-credentials", nil)
	defer func() { _ = list.Body.Close() }()
	if list.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", list.StatusCode)
	}
	var got struct {
		Slots []slotDTO `json:"slots"`
	}
	if err := json.NewDecoder(list.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Slots) != 2 {
		t.Errorf("len = %d, want 2", len(got.Slots))
	}
}

func TestPutWithoutAnythingFails(t *testing.T) {
	f := newFixture(t)
	resp := f.do(t, http.MethodPut, "/api/admin/ansible-credentials/global", map[string]any{})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestPutClearKey(t *testing.T) {
	f := newFixture(t)
	// Seed with a key.
	resp := f.do(t, http.MethodPut, "/api/admin/ansible-credentials/global", map[string]any{
		"ansibleUser": "u",
		"key":         map[string]any{"origin": "sw_generated"},
	})
	_ = resp.Body.Close()
	// Now clear the key, leaving only the user.
	resp = f.do(t, http.MethodPut, "/api/admin/ansible-credentials/global", map[string]any{
		"clearKey": true,
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got slotDTO
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got.PublicKey != "" {
		t.Errorf("publicKey = %q, want cleared", got.PublicKey)
	}
	if got.Origin != "" {
		t.Errorf("origin = %q, want cleared", got.Origin)
	}
	if got.AnsibleUser != "u" {
		t.Errorf("ansibleUser cleared too: %q", got.AnsibleUser)
	}
}

func TestSystemSlotCRUD(t *testing.T) {
	f := newFixture(t)
	sys, err := f.systems.Create(systems.SystemInput{Name: "sx", Hostname: "sx.example"})
	if err != nil {
		t.Fatalf("systems.Create: %v", err)
	}
	// PUT
	resp := f.do(t, http.MethodPut, "/api/systems/"+sys.ID+"/ansible-credential", map[string]any{
		"ansibleUser": "ops",
	})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT status = %d", resp.StatusCode)
	}
	// GET
	getResp := f.do(t, http.MethodGet, "/api/systems/"+sys.ID+"/ansible-credential", nil)
	defer func() { _ = getResp.Body.Close() }()
	if getResp.StatusCode != http.StatusOK {
		t.Errorf("GET status = %d", getResp.StatusCode)
	}
	// DELETE
	delResp := f.do(t, http.MethodDelete, "/api/systems/"+sys.ID+"/ansible-credential", nil)
	_ = delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE status = %d, want 204", delResp.StatusCode)
	}
}

func TestSystemSlotMissingSystem(t *testing.T) {
	f := newFixture(t)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		body := any(map[string]any{"ansibleUser": "u"})
		if method != http.MethodPut {
			body = nil
		}
		resp := f.do(t, method, "/api/systems/no-such-system/ansible-credential", body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s status = %d, want 404", method, resp.StatusCode)
		}
	}
}

func TestSystemSlotForbiddenWhenScopeDenies(t *testing.T) {
	f := newFixture(t)
	f.allowSystem = func(context.Context, systems.System) bool { return false }
	sys, err := f.systems.Create(systems.SystemInput{Name: "sx", Hostname: "sx.example"})
	if err != nil {
		t.Fatalf("systems.Create: %v", err)
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		var body any
		if method == http.MethodPut {
			body = map[string]any{"ansibleUser": "u"}
		}
		resp := f.do(t, method, "/api/systems/"+sys.ID+"/ansible-credential", body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s status = %d, want 403", method, resp.StatusCode)
		}
	}
}

func TestGroupSlotForbiddenWhenScopeDenies(t *testing.T) {
	f := newFixture(t)
	f.allowGroup = func(context.Context, string) bool { return false }
	g, err := f.groups.Create(groups.GroupInput{Name: "g"})
	if err != nil {
		t.Fatalf("groups.Create: %v", err)
	}
	resp := f.do(t, http.MethodPut, "/api/groups/"+g.ID+"/ansible-credential", map[string]any{"ansibleUser": "u"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	resp = f.do(t, http.MethodGet, "/api/groups/"+g.ID+"/ansible-credential", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("GET status = %d, want 403", resp.StatusCode)
	}
	resp = f.do(t, http.MethodDelete, "/api/groups/"+g.ID+"/ansible-credential", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("DELETE status = %d, want 403", resp.StatusCode)
	}
}

func TestPutWithoutVaultReturns503(t *testing.T) {
	f := newFixture(t)
	f.handler.Vault = nil
	resp := f.do(t, http.MethodPut, "/api/admin/ansible-credentials/global", map[string]any{
		"key": map[string]any{"origin": "sw_generated"},
	})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

func TestEffectiveMissingSystem(t *testing.T) {
	f := newFixture(t)
	resp := f.do(t, http.MethodGet, "/api/systems/no-such-system/effective-credential", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestEffectiveNoCredentials(t *testing.T) {
	f := newFixture(t)
	sys, err := f.systems.Create(systems.SystemInput{Name: "sy", Hostname: "sy.example"})
	if err != nil {
		t.Fatalf("systems.Create: %v", err)
	}
	resp := f.do(t, http.MethodGet, "/api/systems/"+sys.ID+"/effective-credential", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestGetAndDeleteGlobalForbidden(t *testing.T) {
	f := newFixture(t)
	f.allowGlobal = func(context.Context) bool { return false }
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		resp := f.do(t, method, "/api/admin/ansible-credentials/global", nil)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s status = %d, want 403", method, resp.StatusCode)
		}
	}
}

func TestGetGlobalNotFound(t *testing.T) {
	f := newFixture(t)
	resp := f.do(t, http.MethodGet, "/api/admin/ansible-credentials/global", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestDeleteGlobalNotFound(t *testing.T) {
	f := newFixture(t)
	resp := f.do(t, http.MethodDelete, "/api/admin/ansible-credentials/global", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestListForbidden(t *testing.T) {
	f := newFixture(t)
	f.allowGlobal = func(context.Context) bool { return false }
	resp := f.do(t, http.MethodGet, "/api/admin/ansible-credentials", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestPutBadJSON(t *testing.T) {
	f := newFixture(t)
	req, err := http.NewRequest(http.MethodPut, f.srv.URL+"/api/admin/ansible-credentials/global",
		bytes.NewBufferString("not json"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestPutUnknownOrigin(t *testing.T) {
	f := newFixture(t)
	resp := f.do(t, http.MethodPut, "/api/admin/ansible-credentials/global", map[string]any{
		"key": map[string]any{"origin": "made-up-origin"},
	})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestPutUserSuppliedRequiresPEM(t *testing.T) {
	f := newFixture(t)
	resp := f.do(t, http.MethodPut, "/api/admin/ansible-credentials/global", map[string]any{
		"key": map[string]any{"origin": "user_supplied"},
	})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestPutGroupMissingThenSet(t *testing.T) {
	f := newFixture(t)
	g, _ := f.groups.Create(groups.GroupInput{Name: "g"})
	resp := f.do(t, http.MethodGet, "/api/groups/"+g.ID+"/ansible-credential", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET status before any PUT = %d, want 404", resp.StatusCode)
	}
}

// newReader drains and returns the body bytes so the caller can both
// inspect them as a string and re-decode if needed.
func newReader(t *testing.T, r interface{ Read(p []byte) (int, error) }) ([]byte, error) {
	t.Helper()
	buf := &bytes.Buffer{}
	if _, err := buf.ReadFrom(readerFunc(r.Read)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type readerFunc func(p []byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

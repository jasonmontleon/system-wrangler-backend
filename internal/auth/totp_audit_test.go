// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/database"
)

// withAuditAndDB attaches a real SQLite audit table and the DB handle
// onto a stub-store Service so the tx-and-audit code path runs even
// though the user/TOTP rows themselves live in stubs. The stubs accept
// the *sql.Tx parameter and ignore it — the audit row is the only
// thing actually written through the tx.
func withAuditAndDB(t *testing.T, svc *Service) *audit.Store {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "audit.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := audit.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStore: %v", err)
	}
	svc.DB = db
	svc.Audit = store
	return store
}

func decodeResp(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil && err != io.EOF {
		t.Fatalf("decode: %v", err)
	}
}

func TestTOTPConfirmEmitsEnrollAudit(t *testing.T) {
	srv, svc, users, _, _, _ := newTOTPTestServer(t)
	auditStore := withAuditAndDB(t, svc)
	client := loggedInClientFull(t, srv, users, "alice")

	resp, err := client.Post(srv.URL+"/api/auth/totp/setup", "application/json", nil)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	var setup totpSetupResponse
	decodeResp(t, resp, &setup)
	_ = resp.Body.Close()

	code, err := totp.GenerateCodeCustom(setup.Secret, svc.Now(), totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	resp2, err := client.Post(srv.URL+"/api/auth/totp/confirm", "application/json",
		strings.NewReader(`{"code":"`+code+`"}`))
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("confirm status = %d", resp2.StatusCode)
	}
	_ = resp2.Body.Close()

	rows, _, err := auditStore.ListQuery(audit.Query{Action: "auth.totp.enroll"})
	if err != nil {
		t.Fatalf("ListQuery: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("enroll rows = %d, want 1", len(rows))
	}
	uid := users.users["alice-id"].ID
	if rows[0].TargetID != uid || rows[0].TargetLabel != "alice" {
		t.Errorf("target = (%s, %s), want (%s, alice)", rows[0].TargetID, rows[0].TargetLabel, uid)
	}
}

func TestTOTPDisableEmitsDisableAudit(t *testing.T) {
	srv, svc, users, _, _, _ := newTOTPTestServer(t)
	auditStore := withAuditAndDB(t, svc)
	client := loggedInClientFull(t, srv, users, "alice")

	// Enroll first.
	resp, _ := client.Post(srv.URL+"/api/auth/totp/setup", "application/json", nil)
	var setup totpSetupResponse
	decodeResp(t, resp, &setup)
	_ = resp.Body.Close()
	code, _ := totp.GenerateCodeCustom(setup.Secret, svc.Now(), totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	resp2, _ := client.Post(srv.URL+"/api/auth/totp/confirm", "application/json",
		strings.NewReader(`{"code":"`+code+`"}`))
	_ = resp2.Body.Close()

	// Disable with password + a fresh code (same period, deterministic Now).
	code2, _ := totp.GenerateCodeCustom(setup.Secret, svc.Now(), totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	body := `{"password":"correctpassword","code":"` + code2 + `"}`
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/auth/totp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp3, err := client.Do(req)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	_ = resp3.Body.Close()
	if resp3.StatusCode != http.StatusNoContent {
		t.Fatalf("disable status = %d", resp3.StatusCode)
	}

	rows, _, err := auditStore.ListQuery(audit.Query{Action: "auth.totp.disable"})
	if err != nil {
		t.Fatalf("ListQuery: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("disable rows = %d, want 1", len(rows))
	}
}

func TestTOTPRecoveryUseEmitsAudit(t *testing.T) {
	srv, svc, users, _, _, _ := newTOTPTestServer(t)
	auditStore := withAuditAndDB(t, svc)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// Enroll alice via the normal path so recovery codes get minted.
	prev := loggedInClientFull(t, srv, users, "alice")
	resp, _ := prev.Post(srv.URL+"/api/auth/totp/setup", "application/json", nil)
	var setup totpSetupResponse
	decodeResp(t, resp, &setup)
	_ = resp.Body.Close()
	code, _ := totp.GenerateCodeCustom(setup.Secret, svc.Now(), totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	confirmResp, _ := prev.Post(srv.URL+"/api/auth/totp/confirm", "application/json",
		strings.NewReader(`{"code":"`+code+`"}`))
	var conf totpConfirmResponse
	decodeResp(t, confirmResp, &conf)
	_ = confirmResp.Body.Close()
	if len(conf.RecoveryCodes) == 0 {
		t.Fatal("no recovery codes minted")
	}

	// New client logs in fresh to land on the TOTP challenge.
	loginResp, _ := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	_ = loginResp.Body.Close()

	verifyBody := `{"code":"` + conf.RecoveryCodes[0] + `"}`
	verifyResp, err := client.Post(srv.URL+"/api/auth/totp/verify", "application/json",
		strings.NewReader(verifyBody))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	_ = verifyResp.Body.Close()
	if verifyResp.StatusCode != http.StatusOK {
		t.Fatalf("verify status = %d", verifyResp.StatusCode)
	}

	rows, _, err := auditStore.ListQuery(audit.Query{Action: "auth.totp.recovery.use"})
	if err != nil {
		t.Fatalf("ListQuery: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("recovery rows = %d, want 1", len(rows))
	}
	if rows[0].ActorKind != audit.ActorUser || rows[0].ActorLabel != "alice" {
		t.Errorf("actor = (%s, %s), want (user, alice)", rows[0].ActorKind, rows[0].ActorLabel)
	}
}

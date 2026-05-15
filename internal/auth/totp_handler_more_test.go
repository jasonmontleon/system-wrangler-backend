// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// These tests fill in error-path coverage that the happy-path tests don't reach.

// drainPost is a tiny helper that calls client.Post and closes the response
// body, discarding both. Used in setup-only steps where the body is not
// inspected — keeps `bodyclose` happy without dragging an explicit pair of
// lines through every test.
func drainPost(client *http.Client, url, body string) {
	r, err := client.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		return
	}
	_ = r.Body.Close()
}

func TestTOTPSetupBadJSON(t *testing.T) {
	srv, _, users, _, _, _ := newTOTPTestServer(t)
	client := loggedInClientFull(t, srv, users, "alice")
	// /totp/setup takes no body, but the handler shouldn't blow up if one is sent.
	resp, err := client.Post(srv.URL+"/api/auth/totp/setup", "application/json",
		strings.NewReader(`anything`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (body should be ignored)", resp.StatusCode)
	}
}

func TestTOTPConfirmBadJSON(t *testing.T) {
	srv, _, users, _, _, _ := newTOTPTestServer(t)
	client := loggedInClientFull(t, srv, users, "alice")
	// no setup yet — confirm with bad json should still hit the JSON branch first.
	resp, err := client.Post(srv.URL+"/api/auth/totp/confirm", "application/json",
		strings.NewReader(`not-json`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestTOTPConfirmEmptyCode(t *testing.T) {
	srv, _, users, _, _, _ := newTOTPTestServer(t)
	client := loggedInClientFull(t, srv, users, "alice")
	resp, err := client.Post(srv.URL+"/api/auth/totp/confirm", "application/json",
		strings.NewReader(`{"code":"   "}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestTOTPConfirmStateError(t *testing.T) {
	srv, _, users, tot, _, _ := newTOTPTestServer(t)
	client := loggedInClientFull(t, srv, users, "alice")
	// Setup creates pending; confirm should hit the GetTOTPState error path.
	resp, _ := client.Post(srv.URL+"/api/auth/totp/setup", "application/json", nil)
	_ = resp.Body.Close()
	tot.failOn = "GetTOTPState"
	tot.err = errors.New("db down")
	resp2, err := client.Post(srv.URL+"/api/auth/totp/confirm", "application/json",
		strings.NewReader(`{"code":"123456"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp2.StatusCode)
	}
}

func TestTOTPConfirmActivateError(t *testing.T) {
	srv, svc, users, tot, _, _ := newTOTPTestServer(t)
	client := loggedInClientFull(t, srv, users, "alice")
	resp, _ := client.Post(srv.URL+"/api/auth/totp/setup", "application/json", nil)
	var setup totpSetupResponse
	_ = json.NewDecoder(resp.Body).Decode(&setup)
	_ = resp.Body.Close()
	code, _ := totp.GenerateCodeCustom(setup.Secret, svc.Now(), totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	tot.failOn = "ActivateTOTP"
	tot.err = errors.New("db down")
	resp2, err := client.Post(srv.URL+"/api/auth/totp/confirm", "application/json",
		strings.NewReader(`{"code":"`+code+`"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp2.StatusCode)
	}
}

func TestTOTPVerifyMissingChallenge(t *testing.T) {
	srv, _, _, _, _, _ := newTOTPTestServer(t)
	resp, err := http.Post(srv.URL+"/api/auth/totp/verify", "application/json",
		strings.NewReader(`{"code":"123456"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestTOTPVerifyBadJSON(t *testing.T) {
	srv, svc, users, _, _, _ := newTOTPTestServer(t)
	client, _, _ := enrolledClient(t, srv, svc, users)
	r1, _ := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	_ = r1.Body.Close()
	resp, err := client.Post(srv.URL+"/api/auth/totp/verify", "application/json",
		strings.NewReader(`not-json`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestTOTPVerifyMissingCode(t *testing.T) {
	srv, svc, users, _, _, _ := newTOTPTestServer(t)
	client, _, _ := enrolledClient(t, srv, svc, users)
	r1, _ := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	_ = r1.Body.Close()
	resp, err := client.Post(srv.URL+"/api/auth/totp/verify", "application/json",
		strings.NewReader(`{"code":"  "}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestTOTPVerifyChallengeForDeletedUser(t *testing.T) {
	srv, svc, users, _, _, _ := newTOTPTestServer(t)
	client, _, _ := enrolledClient(t, srv, svc, users)
	r1, _ := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	_ = r1.Body.Close()
	// Wipe the user to simulate the challenge cookie outliving the account.
	for k := range users.users {
		delete(users.users, k)
	}
	resp, err := client.Post(srv.URL+"/api/auth/totp/verify", "application/json",
		strings.NewReader(`{"code":"123456"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestTOTPDisableBadJSON(t *testing.T) {
	srv, svc, users, _, _, _ := newTOTPTestServer(t)
	client, _, _ := enrolledClient(t, srv, svc, users)
	// Re-login + verify so we have a session.
	loginAndVerify(t, srv, svc, client)
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/auth/totp",
		strings.NewReader(`not-json`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestTOTPDisableMissingFields(t *testing.T) {
	srv, svc, users, _, _, _ := newTOTPTestServer(t)
	client, _, _ := enrolledClient(t, srv, svc, users)
	loginAndVerify(t, srv, svc, client)
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/auth/totp",
		strings.NewReader(`{"password":"","code":""}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestTOTPDisableWrongPassword(t *testing.T) {
	srv, svc, users, _, _, _ := newTOTPTestServer(t)
	client, _, _ := enrolledClient(t, srv, svc, users)
	loginAndVerify(t, srv, svc, client)
	body := `{"password":"wrong","code":"123456"}`
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/auth/totp",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestTOTPDisableWrongCode(t *testing.T) {
	srv, svc, users, _, _, _ := newTOTPTestServer(t)
	client, _, _ := enrolledClient(t, srv, svc, users)
	loginAndVerify(t, srv, svc, client)
	body := `{"password":"correctpassword","code":"000000"}`
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/auth/totp",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestTOTPDisableStoreError(t *testing.T) {
	srv, svc, users, tot, _, _ := newTOTPTestServer(t)
	client, secret, _ := enrolledClient(t, srv, svc, users)
	loginAndVerify(t, srv, svc, client)

	disableTime := svc.Now().Add(60 * time.Second)
	svc.Now = func() time.Time { return disableTime }
	disableCode, _ := totp.GenerateCodeCustom(secret, disableTime, totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	tot.failOn = "DisableTOTP"
	tot.err = errors.New("db down")
	body := `{"password":"correctpassword","code":"` + disableCode + `"}`
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/auth/totp",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestListDevicesNoDeviceStore(t *testing.T) {
	users := &stubUserStore{}
	hash, _ := HashPassword("correctpassword")
	_, _ = users.Create("alice", hash)
	svc := NewService(users, testSecret, false)
	svc.TOTPStore = newStubTOTPStore()
	svc.RecoveryStore = newStubRecoveryStore()
	svc.Vault = fixedVault(t)
	mux := http.NewServeMux()
	svc.Register(mux)
	requireUser := RequireUser(testSecret, users, time.Now)
	svc.RegisterTOTP(mux, requireUser)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	r1, _ := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	_ = r1.Body.Close()
	resp, _ := client.Get(srv.URL + "/api/auth/devices")
	defer func() { _ = resp.Body.Close() }()
	var got []TrustedDevice
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d, want 0", len(got))
	}
}

func TestRevokeDeviceNoDeviceStore(t *testing.T) {
	users := &stubUserStore{}
	hash, _ := HashPassword("correctpassword")
	_, _ = users.Create("alice", hash)
	svc := NewService(users, testSecret, false)
	svc.TOTPStore = newStubTOTPStore()
	svc.RecoveryStore = newStubRecoveryStore()
	svc.Vault = fixedVault(t)
	mux := http.NewServeMux()
	svc.Register(mux)
	requireUser := RequireUser(testSecret, users, time.Now)
	svc.RegisterTOTP(mux, requireUser)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	drainPost(client, srv.URL+"/api/auth/login", `{"username":"alice","password":"correctpassword"}`)
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/auth/devices/x", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

func TestLoginWithTOTPStateError(t *testing.T) {
	srv, _, users, tot, _, _ := newTOTPTestServer(t)
	hash, _ := HashPassword("correctpassword")
	if _, err := users.Create("alice", hash); err != nil {
		t.Fatalf("create: %v", err)
	}
	tot.failOn = "GetTOTPState"
	tot.err = errors.New("db down")
	resp, err := http.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestLoginWithoutTOTPStoreFallsThrough(t *testing.T) {
	users := &stubUserStore{}
	hash, _ := HashPassword("correctpassword")
	_, _ = users.Create("alice", hash)
	svc := NewService(users, testSecret, false)
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (no TOTP store -> simple flow)", resp.StatusCode)
	}
}

func TestListDevicesStoreError(t *testing.T) {
	srv, _, users, _, _, devices := newTOTPTestServer(t)
	client := loggedInClientFull(t, srv, users, "alice")
	devices.failOn = "ListDevices"
	devices.err = errors.New("db down")
	resp, err := client.Get(srv.URL + "/api/auth/devices")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestRevokeDeviceStoreError(t *testing.T) {
	srv, _, users, _, _, devices := newTOTPTestServer(t)
	client := loggedInClientFull(t, srv, users, "alice")
	devices.failOn = "DeleteDevice"
	devices.err = errors.New("db down")
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/auth/devices/some-id", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestTOTPVerifyStateError(t *testing.T) {
	srv, svc, users, tot, _, _ := newTOTPTestServer(t)
	client, _, _ := enrolledClient(t, srv, svc, users)
	r1, _ := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	_ = r1.Body.Close()
	tot.failOn = "GetTOTPState"
	tot.err = errors.New("db down")
	resp, err := client.Post(srv.URL+"/api/auth/totp/verify", "application/json",
		strings.NewReader(`{"code":"123456"}`))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestTOTPDisableHashLoadError(t *testing.T) {
	srv, svc, users, _, _, _ := newTOTPTestServer(t)
	client, _, _ := enrolledClient(t, srv, svc, users)
	loginAndVerify(t, srv, svc, client)
	users.failOn = "GetHashByID"
	users.err = errors.New("db down")
	body := `{"password":"correctpassword","code":"000000"}`
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/auth/totp",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestTOTPDisableStateError(t *testing.T) {
	srv, svc, users, tot, _, _ := newTOTPTestServer(t)
	client, _, _ := enrolledClient(t, srv, svc, users)
	loginAndVerify(t, srv, svc, client)
	tot.failOn = "GetTOTPState"
	tot.err = errors.New("db down")
	body := `{"password":"correctpassword","code":"000000"}`
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/auth/totp",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestTOTPSetupVaultUnset(t *testing.T) {
	// Clearing the vault on a configured Service forces totpReady() to return
	// false; setup should answer 503 rather than panic on a nil deref.
	srv, svc, users, _, _, _ := newTOTPTestServer(t)
	client := loggedInClientFull(t, srv, users, "alice")
	svc.Vault = nil
	resp, err := client.Post(srv.URL+"/api/auth/totp/setup", "application/json", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

// TestStoreErrorsOnClosedDBExtended exercises every TOTP/recovery/device
// store method against a closed DB to drive the error branches that need
// a misbehaving SQL handle.
func TestHonorTrustedDeviceWrongEpoch(t *testing.T) {
	// A trust cookie whose epoch no longer matches the current epoch must
	// be ignored (TOTP step required again).
	srv, svc, users, tot, _, devices := newTOTPTestServer(t)
	client, secret, _ := enrolledClient(t, srv, svc, users)

	// First login + verify with rememberDevice=true.
	r1, _ := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	_ = r1.Body.Close()
	now := svc.Now().Add(60 * time.Second)
	svc.Now = func() time.Time { return now }
	code, _ := totp.GenerateCodeCustom(secret, now, totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	drainPost(client, srv.URL+"/api/auth/totp/verify", `{"code":"`+code+`","rememberDevice":true}`)

	// Bump the epoch directly (simulates a disable+re-enable cycle).
	uid := users.users["alice-id"].ID
	st := tot.state[uid]
	st.Epoch = 99
	tot.state[uid] = st

	drainPost(client, srv.URL+"/api/auth/logout", "")
	resp, err := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["totpRequired"] != true {
		t.Errorf("trust survived epoch bump: body = %+v", body)
	}
	_ = devices
}

func TestHonorTrustedDeviceExpired(t *testing.T) {
	srv, svc, users, _, _, devices := newTOTPTestServer(t)
	client, secret, _ := enrolledClient(t, srv, svc, users)

	r1, _ := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	_ = r1.Body.Close()
	now := svc.Now().Add(60 * time.Second)
	svc.Now = func() time.Time { return now }
	code, _ := totp.GenerateCodeCustom(secret, now, totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	drainPost(client, srv.URL+"/api/auth/totp/verify", `{"code":"`+code+`","rememberDevice":true}`)

	// Force the device's expires_at into the past.
	for id, d := range devices.devices {
		d.ExpiresAt = svc.Now().Add(-time.Hour)
		devices.devices[id] = d
	}
	drainPost(client, srv.URL+"/api/auth/logout", "")
	resp, err := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["totpRequired"] != true {
		t.Errorf("expired trust honored: body = %+v", body)
	}
}

func TestHonorTrustedDeviceUserMismatch(t *testing.T) {
	srv, svc, users, _, _, devices := newTOTPTestServer(t)
	client, secret, _ := enrolledClient(t, srv, svc, users)

	r1, _ := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	_ = r1.Body.Close()
	now := svc.Now().Add(60 * time.Second)
	svc.Now = func() time.Time { return now }
	code, _ := totp.GenerateCodeCustom(secret, now, totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	drainPost(client, srv.URL+"/api/auth/totp/verify", `{"code":"`+code+`","rememberDevice":true}`)

	// Reassign the device row to another user — cookie's claim still says alice.
	for id, d := range devices.devices {
		d.UserID = "someone-else"
		devices.devices[id] = d
	}
	drainPost(client, srv.URL+"/api/auth/logout", "")
	resp, err := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["totpRequired"] != true {
		t.Errorf("cross-user trust honored: body = %+v", body)
	}
}

func TestHonorTrustedDeviceMissingRow(t *testing.T) {
	srv, svc, users, _, _, devices := newTOTPTestServer(t)
	client, secret, _ := enrolledClient(t, srv, svc, users)

	r1, _ := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	_ = r1.Body.Close()
	now := svc.Now().Add(60 * time.Second)
	svc.Now = func() time.Time { return now }
	code, _ := totp.GenerateCodeCustom(secret, now, totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	drainPost(client, srv.URL+"/api/auth/totp/verify", `{"code":"`+code+`","rememberDevice":true}`)

	// Wipe the rows but keep the cookie — simulates an admin manually
	// deleting devices server-side.
	devices.devices = map[string]TrustedDevice{}
	drainPost(client, srv.URL+"/api/auth/logout", "")
	resp, err := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["totpRequired"] != true {
		t.Errorf("orphan trust cookie honored: body = %+v", body)
	}
}

func TestHonorTrustedDeviceTouchError(t *testing.T) {
	// TouchDevice failure should not invalidate the trust — login must
	// succeed (skipping TOTP) even if the bookkeeping update fails.
	srv, svc, users, _, _, devices := newTOTPTestServer(t)
	client, secret, _ := enrolledClient(t, srv, svc, users)

	r1, _ := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	_ = r1.Body.Close()
	now := svc.Now().Add(60 * time.Second)
	svc.Now = func() time.Time { return now }
	code, _ := totp.GenerateCodeCustom(secret, now, totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	drainPost(client, srv.URL+"/api/auth/totp/verify", `{"code":"`+code+`","rememberDevice":true}`)

	devices.failOn = "TouchDevice"
	devices.err = errors.New("db down")
	drainPost(client, srv.URL+"/api/auth/logout", "")
	resp, err := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["totpRequired"] == true {
		t.Errorf("trust failed because of touch error: body = %+v", body)
	}
	if body["username"] != "alice" {
		t.Errorf("expected user, got %+v", body)
	}
}

// recoveryStoreFailing is a RecoveryStore that fails the named method.
type recoveryStoreFailing struct {
	*stubRecoveryStore
	failOn string
	err    error
}

func (r *recoveryStoreFailing) InsertRecoveryCodes(userID string, hashes []string) error {
	if r.failOn == "InsertRecoveryCodes" {
		return r.err
	}
	return r.stubRecoveryStore.InsertRecoveryCodes(userID, hashes)
}

func TestTOTPConfirmRecoveryInsertFails(t *testing.T) {
	users := &stubUserStore{}
	tot := newStubTOTPStore()
	rec := &recoveryStoreFailing{
		stubRecoveryStore: newStubRecoveryStore(),
		failOn:            "InsertRecoveryCodes",
		err:               errors.New("db down"),
	}
	dev := newStubDeviceStore()
	svc := NewService(users, testSecret, false)
	svc.TOTPStore = tot
	svc.RecoveryStore = rec
	svc.DeviceStore = dev
	svc.Vault = fixedVault(t)
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }
	mux := http.NewServeMux()
	svc.Register(mux)
	requireUser := RequireUser(testSecret, users, svc.Now)
	svc.RegisterTOTP(mux, requireUser)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := loggedInClientFull(t, srv, users, "alice")
	r, _ := client.Post(srv.URL+"/api/auth/totp/setup", "application/json", nil)
	var setup totpSetupResponse
	_ = json.NewDecoder(r.Body).Decode(&setup)
	_ = r.Body.Close()
	code, _ := totp.GenerateCodeCustom(setup.Secret, now, totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	resp, err := client.Post(srv.URL+"/api/auth/totp/confirm", "application/json",
		strings.NewReader(`{"code":"`+code+`"}`))
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestRememberDeviceInsertError(t *testing.T) {
	srv, svc, users, _, _, devices := newTOTPTestServer(t)
	client, secret, _ := enrolledClient(t, srv, svc, users)
	r1, _ := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	_ = r1.Body.Close()
	now := svc.Now().Add(60 * time.Second)
	svc.Now = func() time.Time { return now }
	devices.failOn = "InsertDevice"
	devices.err = errors.New("db down")
	code, _ := totp.GenerateCodeCustom(secret, now, totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	resp, err := client.Post(srv.URL+"/api/auth/totp/verify", "application/json",
		strings.NewReader(`{"code":"`+code+`","rememberDevice":true}`))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Insert failure is logged but doesn't fail the verify — user should
	// still be logged in.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (insert failure non-fatal)", resp.StatusCode)
	}
}

func TestStoreErrorsOnClosedDBExtended(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")
	if err := s.db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := s.SetPendingSecret(u.ID, fakeSealed("x")); err == nil {
		t.Error("SetPendingSecret on closed DB: want error")
	}
	if err := s.ActivateTOTP(u.ID, fakeSealed("x"), time.Now()); err == nil {
		t.Error("ActivateTOTP on closed DB: want error")
	}
	if err := s.DisableTOTP(u.ID); err == nil {
		t.Error("DisableTOTP on closed DB: want error")
	}
	if _, err := s.GetTOTPState(u.ID); err == nil {
		t.Error("GetTOTPState on closed DB: want error")
	}
	if err := s.ConsumeStep(u.ID, 1); err == nil {
		t.Error("ConsumeStep on closed DB: want error")
	}
	if err := s.InsertRecoveryCodes(u.ID, []string{"h"}); err == nil {
		t.Error("InsertRecoveryCodes on closed DB: want error")
	}
	if err := s.ConsumeRecoveryCode(u.ID, "x", time.Now()); err == nil {
		t.Error("ConsumeRecoveryCode on closed DB: want error")
	}
	if err := s.DeleteRecoveryCodes(u.ID); err == nil {
		t.Error("DeleteRecoveryCodes on closed DB: want error")
	}
	if err := s.InsertDevice(TrustedDevice{ID: "x", UserID: u.ID}); err == nil {
		t.Error("InsertDevice on closed DB: want error")
	}
	if _, err := s.GetDevice("x"); err == nil {
		t.Error("GetDevice on closed DB: want error")
	}
	if _, err := s.ListDevices(u.ID); err == nil {
		t.Error("ListDevices on closed DB: want error")
	}
	if err := s.DeleteDevice("x", u.ID); err == nil {
		t.Error("DeleteDevice on closed DB: want error")
	}
	if err := s.DeleteDevicesForUser(u.ID); err == nil {
		t.Error("DeleteDevicesForUser on closed DB: want error")
	}
	if err := s.TouchDevice("x", time.Now()); err == nil {
		t.Error("TouchDevice on closed DB: want error")
	}
}

// loginAndVerify is a test helper: starts a fresh login attempt on an
// already-enrolled user and posts the verify with a fresh code, leaving the
// client logged in.
func loginAndVerify(t *testing.T, srv *httptest.Server, svc *Service, client *http.Client) {
	t.Helper()
	r1, err := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	_ = r1.Body.Close()

	// We need the secret for code generation; pull it back out of the store.
	// Test seam: the stub TOTPStore stores the sealed shape; the test vault
	// can open it because it's the same vault that did the seal.
	users := svc.Store.(*stubUserStore)
	uid := users.users["alice-id"].ID
	state, _ := svc.TOTPStore.GetTOTPState(uid)
	rawSecret, err := OpenWith(svc.Vault, state.Secret)
	if err != nil {
		t.Fatalf("open sealed secret: %v", err)
	}
	now := svc.Now().Add(60 * time.Second)
	svc.Now = func() time.Time { return now }
	code, _ := totp.GenerateCodeCustom(totpEncoding.EncodeToString(rawSecret), now, totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	r2, err := client.Post(srv.URL+"/api/auth/totp/verify", "application/json",
		strings.NewReader(`{"code":"`+code+`","rememberDevice":false}`))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	_ = r2.Body.Close()
}

// breakSealedVersion mutates the stored Sealed.Version for a user's
// active or pending TOTP secret to a version the test vault does not
// know, simulating a mismatched-key restore. Returns the cleanup
// function so other tests sharing the stub can be restored if needed.
func breakSealedVersion(t *testing.T, tot *stubTOTPStore, userID string, field string) {
	t.Helper()
	st := tot.state[userID]
	switch field {
	case "secret":
		st.Secret.Version = 0x7fffffff // unlikely to collide with versionOf(fixedKEK)
	case "pending":
		st.Pending.Version = 0x7fffffff
	default:
		t.Fatalf("unknown field %q", field)
	}
	tot.state[userID] = st
}

func TestTOTPDisable_SecretUndecryptableReturns422(t *testing.T) {
	srv, svc, users, tot, _, _ := newTOTPTestServer(t)
	client, _, _ := enrolledClient(t, srv, svc, users)
	loginAndVerify(t, srv, svc, client)

	user, _, _ := users.GetByUsername("alice")
	breakSealedVersion(t, tot, user.ID, "secret")

	body := `{"password":"correctpassword","code":"123456"}`
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/auth/totp",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", resp.StatusCode)
	}
	var errBody map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&errBody); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(strings.ToLower(errBody["error"]), "cannot be decrypted") {
		t.Errorf("error = %q, want a 'cannot be decrypted' message", errBody["error"])
	}
}

func TestTOTPConfirm_PendingUndecryptableReturns422(t *testing.T) {
	srv, _, users, tot, _, _ := newTOTPTestServer(t)
	client := loggedInClientFull(t, srv, users, "alice")
	// Drive /totp/setup so a pending secret is stored, then mutate the
	// version to break decrypt.
	r1, _ := client.Post(srv.URL+"/api/auth/totp/setup", "application/json", nil)
	_ = r1.Body.Close()
	user, _, _ := users.GetByUsername("alice")
	breakSealedVersion(t, tot, user.ID, "pending")

	resp, err := client.Post(srv.URL+"/api/auth/totp/confirm", "application/json",
		strings.NewReader(`{"code":"123456"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", resp.StatusCode)
	}
	var errBody map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&errBody); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(strings.ToLower(errBody["error"]), "cannot be decrypted") {
		t.Errorf("error = %q, want a 'cannot be decrypted' message", errBody["error"])
	}
}

func TestTOTPVerify_SecretUndecryptableFallsThroughToRecovery(t *testing.T) {
	srv, svc, users, tot, _, _ := newTOTPTestServer(t)
	client, _, recoveryCodes := enrolledClient(t, srv, svc, users)
	if len(recoveryCodes) == 0 {
		t.Fatal("no recovery codes minted by enrollment")
	}
	user, _, _ := users.GetByUsername("alice")
	breakSealedVersion(t, tot, user.ID, "secret")

	// Login → challenge cookie set, TOTP path will fail to decrypt, recovery
	// code falls through and succeeds.
	r1, _ := client.Post(srv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"correctpassword"}`))
	_ = r1.Body.Close()

	verify, err := client.Post(srv.URL+"/api/auth/totp/verify", "application/json",
		strings.NewReader(`{"code":"`+recoveryCodes[0]+`"}`))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	defer func() { _ = verify.Body.Close() }()
	if verify.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(verify.Body)
		t.Fatalf("verify status = %d body=%s", verify.StatusCode, body)
	}
}

// SPDX-License-Identifier: Apache-2.0

package notifications

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testMsg() Message {
	return Message{
		Subject: "[FIRING] High memory on web-1", Body: "value 95",
		Kind: "fired", RuleName: "High memory", Severity: "critical",
		SystemID: "sys-1", SystemName: "web-1", Value: 95, At: time.Unix(1700000000, 0),
	}
}

func TestEmailSenderBuildsEnvelope(t *testing.T) {
	var gotCfg Config
	var gotPwd, gotFrom string
	var gotTo []string
	var gotPayload []byte
	send := func(_ context.Context, cfg Config, pwd, from string, to []string, payload []byte) error {
		gotCfg, gotPwd, gotFrom, gotTo, gotPayload = cfg, pwd, from, to, payload
		return nil
	}
	s := NewSenders(nil, send)[TypeEmail]
	c := Channel{Type: TypeEmail, Config: Config{
		SMTPHost: "smtp.x", SMTPPort: 587, Username: "u", From: "a@x", To: []string{"b@x", "c@x"},
	}}
	if err := s.Send(context.Background(), c, "pw", testMsg()); err != nil {
		t.Fatalf("send: %v", err)
	}
	if gotCfg.SMTPHost != "smtp.x" || gotPwd != "pw" || gotFrom != "a@x" || len(gotTo) != 2 {
		t.Errorf("envelope wrong: cfg=%+v pwd=%q from=%q to=%v", gotCfg, gotPwd, gotFrom, gotTo)
	}
	p := string(gotPayload)
	if !strings.Contains(p, "To: b@x, c@x\r\n") || !strings.Contains(p, "Subject: [FIRING] High memory on web-1\r\n") {
		t.Errorf("headers missing: %q", p)
	}
	if !strings.Contains(p, "\r\n\r\nvalue 95") {
		t.Errorf("body separator/body missing: %q", p)
	}
}

func TestSlackSenderPostsText(t *testing.T) {
	var body map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	s := NewSenders(srv.Client(), nil)[TypeSlack]
	if err := s.Send(context.Background(), Channel{Type: TypeSlack}, srv.URL, testMsg()); err != nil {
		t.Fatalf("send: %v", err)
	}
	if !strings.Contains(body["text"], "[FIRING] High memory on web-1") {
		t.Errorf("slack text wrong: %q", body["text"])
	}
}

func TestSlackSenderNoURL(t *testing.T) {
	s := NewSenders(nil, nil)[TypeSlack]
	if err := s.Send(context.Background(), Channel{Type: TypeSlack}, "", testMsg()); err == nil {
		t.Error("expected error with no webhook URL")
	}
}

func TestWebhookSenderPostsJSONWithHeader(t *testing.T) {
	var payload webhookPayload
	var auth string
	var method string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("X-Token")
		method = r.Method
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	s := NewSenders(srv.Client(), nil)[TypeWebhook]
	c := Channel{Type: TypeWebhook, Config: Config{URL: srv.URL, Method: "PUT", HeaderName: "X-Token"}}
	if err := s.Send(context.Background(), c, "sekret", testMsg()); err != nil {
		t.Fatalf("send: %v", err)
	}
	if method != "PUT" || auth != "sekret" {
		t.Errorf("method=%q auth=%q", method, auth)
	}
	if payload.Kind != "fired" || payload.Rule != "High memory" || payload.SystemName != "web-1" {
		t.Errorf("payload wrong: %+v", payload)
	}
}

func TestWebhookSenderNon2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "nope")
	}))
	defer srv.Close()
	s := NewSenders(srv.Client(), nil)[TypeWebhook]
	c := Channel{Type: TypeWebhook, Config: Config{URL: srv.URL}}
	err := s.Send(context.Background(), c, "", testMsg())
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Errorf("expected 400 error, got %v", err)
	}
}

func TestSMSSenderPostsPerRecipient(t *testing.T) {
	var calls int
	var lastPath, lastFrom, lastTo, user, pass string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		lastPath = r.URL.Path
		user, pass, _ = r.BasicAuth()
		_ = r.ParseForm() //nolint:gosec // G120: test server, trusted body
		lastFrom = r.Form.Get("From")
		lastTo = r.Form.Get("To")
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	s := NewSenders(srv.Client(), nil)[TypeSMS]
	c := Channel{Type: TypeSMS, Config: Config{
		BaseURL: srv.URL, AccountSID: "AC123", From: "+15550000000", To: []string{"+1a", "+1b"},
	}}
	if err := s.Send(context.Background(), c, "tok", testMsg()); err != nil {
		t.Fatalf("send: %v", err)
	}
	if calls != 2 {
		t.Errorf("want 2 sends (one per recipient), got %d", calls)
	}
	if !strings.Contains(lastPath, "/Accounts/AC123/Messages.json") {
		t.Errorf("path wrong: %q", lastPath)
	}
	if user != "AC123" || pass != "tok" {
		t.Errorf("basic auth wrong: %q/%q", user, pass)
	}
	if lastFrom != "+15550000000" || lastTo != "+1b" {
		t.Errorf("form wrong: from=%q to=%q", lastFrom, lastTo)
	}
}

func TestSMSSenderSurfacesUpstreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	s := NewSenders(srv.Client(), nil)[TypeSMS]
	c := Channel{Type: TypeSMS, Config: Config{BaseURL: srv.URL, AccountSID: "AC", From: "+1", To: []string{"+2"}}}
	if err := s.Send(context.Background(), c, "tok", testMsg()); err == nil {
		t.Error("expected error on 401")
	}
}

func TestNewSendersDefaults(t *testing.T) {
	s := NewSenders(nil, nil)
	for _, ty := range []Type{TypeEmail, TypeSlack, TypeWebhook, TypeSMS} {
		if s[ty] == nil {
			t.Errorf("missing sender for %q", ty)
		}
	}
}

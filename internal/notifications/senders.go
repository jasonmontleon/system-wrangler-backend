// SPDX-License-Identifier: Apache-2.0

package notifications

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultSMSBaseURL is the Twilio REST API root used when an SMS channel
// leaves baseURL unset. The sender appends /Accounts/{sid}/Messages.json;
// pointing baseURL at a compatible gateway swaps providers.
const DefaultSMSBaseURL = "https://api.twilio.com/2010-04-01"

// Message is the rendered alert a Sender delivers. Subject/Body are the
// human-readable text; the structured fields let the webhook sender emit
// a machine-parseable JSON payload.
type Message struct {
	Subject    string
	Body       string
	Kind       string // "fired" | "resolved"
	RuleName   string
	Severity   string
	SystemID   string
	SystemName string
	Value      float64
	At         time.Time
}

// Sender delivers one Message through a channel. secret is the decrypted
// channel secret (SMTP password, Slack URL, webhook auth-header value,
// SMS token) — the dispatcher opens the vault and passes plaintext so
// senders stay vault-free and testable.
type Sender interface {
	Send(ctx context.Context, c Channel, secret string, msg Message) error
}

// Senders maps each channel type to its Sender. Built once in main.go.
type Senders map[Type]Sender

// NewSenders builds the production sender set. client is shared by the
// HTTP-based senders (nil → a 10s-timeout default); sendMail is the SMTP
// send function (nil → the net/smtp default). Both are injectable so
// tests substitute fakes / httptest servers.
func NewSenders(client *http.Client, sendMail SendMailFunc) Senders {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if sendMail == nil {
		sendMail = smtpSend
	}
	return Senders{
		TypeEmail:   &emailSender{send: sendMail},
		TypeSlack:   &slackSender{client: client},
		TypeWebhook: &webhookSender{client: client},
		TypeSMS:     &smsSender{client: client},
	}
}

// SendMailFunc is the injectable SMTP transport. Default is smtpSend.
type SendMailFunc func(ctx context.Context, cfg Config, password, from string, to []string, payload []byte) error

type emailSender struct{ send SendMailFunc }

func (s *emailSender) Send(ctx context.Context, c Channel, secret string, msg Message) error {
	payload := buildEmail(c.Config.From, c.Config.To, msg.Subject, msg.Body)
	return s.send(ctx, c.Config, secret, c.Config.From, c.Config.To, payload)
}

// buildEmail renders a minimal RFC 5322 message. CRLF line endings and a
// blank header/body separator are what SMTP DATA expects.
//
// Header values are run through sanitizeHeader to strip embedded CR/LF.
// The Subject is assembled from the alert rule name and the system name,
// both of which are user-controlled (a group operator can rename a
// system); without this an embedded "\r\nBcc: ..." would inject SMTP
// headers. Stripping at this single choke point covers every caller.
func buildEmail(from string, to []string, subject, body string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", sanitizeHeader(from))
	cleanTo := make([]string, len(to))
	for i, addr := range to {
		cleanTo[i] = sanitizeHeader(addr)
	}
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(cleanTo, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", sanitizeHeader(subject))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	return b.Bytes()
}

// sanitizeHeader removes CR and LF from a single email header value so a
// user-controlled field (rule name, system name, recipient) cannot inject
// additional headers or prematurely terminate the header block. Other
// control characters are left alone — only the line terminators matter for
// header-injection.
func sanitizeHeader(v string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(v)
}

// smtpSend dials the SMTP server, optionally upgrades to TLS via STARTTLS
// (honoring SkipVerify for self-signed relays), optionally authenticates,
// and submits the message.
func smtpSend(ctx context.Context, cfg Config, password, from string, to []string, payload []byte) error {
	addr := net.JoinHostPort(cfg.SMTPHost, strconv.Itoa(cfg.SMTPPort))
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial smtp: %w", err)
	}
	client, err := smtp.NewClient(conn, cfg.SMTPHost)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer func() { _ = client.Close() }()

	if cfg.StartTLS {
		// SkipVerify is an explicit operator opt-in for self-signed
		// relays, mirroring mailx's tls-verify=ignore. G402 is intended.
		tlsCfg := &tls.Config{ServerName: cfg.SMTPHost, InsecureSkipVerify: cfg.SkipVerify} //nolint:gosec
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}
	if cfg.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", cfg.Username, password, cfg.SMTPHost)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("smtp rcpt %q: %w", rcpt, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close: %w", err)
	}
	return client.Quit()
}

type slackSender struct{ client *http.Client }

func (s *slackSender) Send(ctx context.Context, _ Channel, secret string, msg Message) error {
	if secret == "" {
		return fmt.Errorf("slack channel has no webhook URL")
	}
	body, _ := json.Marshal(map[string]string{"text": msg.Subject + "\n" + msg.Body})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, secret, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return doExpectOK(s.client, req)
}

// webhookPayload is the JSON a generic webhook receives.
type webhookPayload struct {
	Kind       string  `json:"kind"`
	Rule       string  `json:"rule"`
	Severity   string  `json:"severity"`
	SystemID   string  `json:"systemId"`
	SystemName string  `json:"systemName"`
	Value      float64 `json:"value"`
	Subject    string  `json:"subject"`
	Body       string  `json:"body"`
	At         string  `json:"at"`
}

type webhookSender struct{ client *http.Client }

func (s *webhookSender) Send(ctx context.Context, c Channel, secret string, msg Message) error {
	body, _ := json.Marshal(webhookPayload{
		Kind: msg.Kind, Rule: msg.RuleName, Severity: msg.Severity,
		SystemID: msg.SystemID, SystemName: msg.SystemName, Value: msg.Value,
		Subject: msg.Subject, Body: msg.Body, At: msg.At.UTC().Format(time.RFC3339),
	})
	method := c.Config.Method
	if method == "" {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Config.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Config.HeaderName != "" && secret != "" {
		req.Header.Set(c.Config.HeaderName, secret)
	}
	return doExpectOK(s.client, req)
}

type smsSender struct{ client *http.Client }

func (s *smsSender) Send(ctx context.Context, c Channel, secret string, msg Message) error {
	base := c.Config.BaseURL
	if base == "" {
		base = DefaultSMSBaseURL
	}
	endpoint := strings.TrimRight(base, "/") + "/Accounts/" + url.PathEscape(c.Config.AccountSID) + "/Messages.json"
	// Twilio caps a single SMS body; keep the subject line, which carries
	// the firing/resolved verdict + rule + system.
	text := msg.Subject
	for _, to := range c.Config.To {
		form := url.Values{"From": {c.Config.From}, "To": {to}, "Body": {text}}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return err
		}
		req.SetBasicAuth(c.Config.AccountSID, secret)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := doExpectOK(s.client, req); err != nil {
			return fmt.Errorf("sms to %s: %w", to, err)
		}
	}
	return nil
}

// doExpectOK runs the request and treats any non-2xx as an error,
// surfacing a truncated body so the delivery log carries a useful reason.
func doExpectOK(client *http.Client, req *http.Request) error {
	// The target URL is operator-configured (a Global-Admin-only channel:
	// Slack/webhook/SMS endpoint). Reaching an operator-chosen host is the
	// feature, so the SSRF taint warning is a false positive here.
	resp, err := client.Do(req) //nolint:gosec // G704: operator-configured channel endpoint
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("upstream status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
}

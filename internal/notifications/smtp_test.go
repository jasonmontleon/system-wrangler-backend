// SPDX-License-Identifier: Apache-2.0

package notifications

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeSMTP speaks just enough of SMTP for net/smtp's client to complete a
// no-auth, no-TLS submission. It returns the DATA body lines it received.
func fakeSMTP(t *testing.T) (host string, port int, received <-chan []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	out := make(chan []string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			out <- nil
			return
		}
		defer func() { _ = conn.Close() }()
		r := bufio.NewReader(conn)
		w := bufio.NewWriter(conn)
		reply := func(s string) { _, _ = w.WriteString(s); _ = w.Flush() }
		reply("220 test\r\n")
		var data []string
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				break
			}
			line = strings.TrimRight(line, "\r\n")
			if inData {
				if line == "." {
					reply("250 ok\r\n")
					inData = false
					continue
				}
				data = append(data, line)
				continue
			}
			switch {
			case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
				reply("250 test\r\n") // single-line 250: no extensions advertised
			case strings.HasPrefix(line, "DATA"):
				reply("354 go ahead\r\n")
				inData = true
			case strings.HasPrefix(line, "QUIT"):
				reply("221 bye\r\n")
				out <- data
				return
			default:
				reply("250 ok\r\n")
			}
		}
		out <- data
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ = strconv.Atoi(p)
	return h, port, out
}

func TestSMTPSendHappyPath(t *testing.T) {
	host, port, received := fakeSMTP(t)
	cfg := Config{SMTPHost: host, SMTPPort: port, From: "a@x", To: []string{"b@x"}}
	payload := buildEmail("a@x", []string{"b@x"}, "hi", "the body")
	if err := smtpSend(context.Background(), cfg, "", "a@x", []string{"b@x"}, payload); err != nil {
		t.Fatalf("smtpSend: %v", err)
	}
	data := <-received
	joined := strings.Join(data, "\n")
	if !strings.Contains(joined, "Subject: hi") || !strings.Contains(joined, "the body") {
		t.Errorf("server did not receive the message: %q", joined)
	}
}

func TestSMTPSendDialError(t *testing.T) {
	// Nothing listening on this port.
	cfg := Config{SMTPHost: "127.0.0.1", SMTPPort: 1, From: "a@x", To: []string{"b@x"}}
	err := smtpSend(context.Background(), cfg, "", "a@x", []string{"b@x"}, []byte("x"))
	if err == nil {
		t.Error("expected dial error")
	}
}

func genTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// fakeSMTPStartTLS advertises STARTTLS + AUTH, upgrades to TLS, and
// accepts AUTH PLAIN — exercising smtpSend's TLS + auth branches.
func fakeSMTPStartTLS(t *testing.T) (host string, port int, gotAuth <-chan bool) {
	t.Helper()
	cert := genTestCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	authed := make(chan bool, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			authed <- false
			return
		}
		defer func() { _ = conn.Close() }()
		r := bufio.NewReader(conn)
		w := bufio.NewWriter(conn)
		reply := func(s string) { _, _ = w.WriteString(s); _ = w.Flush() }
		reply("220 test\r\n")
		sawAuth := false
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				break
			}
			line = strings.TrimRight(line, "\r\n")
			switch {
			case inData:
				if line == "." {
					reply("250 ok\r\n")
					inData = false
				}
			case strings.HasPrefix(line, "EHLO"):
				reply("250-test\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n")
			case strings.HasPrefix(line, "STARTTLS"):
				reply("220 go ahead\r\n")
				tconn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
				if err := tconn.Handshake(); err != nil {
					return
				}
				conn = tconn
				r = bufio.NewReader(conn)
				w = bufio.NewWriter(conn)
			case strings.HasPrefix(line, "AUTH"):
				sawAuth = true
				reply("235 authenticated\r\n")
			case strings.HasPrefix(line, "DATA"):
				reply("354 go\r\n")
				inData = true
			case strings.HasPrefix(line, "QUIT"):
				reply("221 bye\r\n")
				authed <- sawAuth
				return
			default:
				reply("250 ok\r\n")
			}
		}
		authed <- sawAuth
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ = strconv.Atoi(p)
	return h, port, authed
}

func TestSMTPSendStartTLSAndAuth(t *testing.T) {
	host, port, gotAuth := fakeSMTPStartTLS(t)
	cfg := Config{
		SMTPHost: host, SMTPPort: port, Username: "u", From: "a@x", To: []string{"b@x"},
		StartTLS: true, SkipVerify: true,
	}
	if err := smtpSend(context.Background(), cfg, "pw", "a@x", []string{"b@x"}, []byte("Subject: hi\r\n\r\nbody")); err != nil {
		t.Fatalf("smtpSend over TLS: %v", err)
	}
	if !<-gotAuth {
		t.Error("server never saw AUTH")
	}
}

func TestEmailSenderThroughSMTP(t *testing.T) {
	host, port, received := fakeSMTP(t)
	s := NewSenders(nil, nil)[TypeEmail]
	c := Channel{Type: TypeEmail, Config: Config{SMTPHost: host, SMTPPort: port, From: "a@x", To: []string{"b@x"}}}
	if err := s.Send(context.Background(), c, "", testMsg()); err != nil {
		t.Fatalf("send: %v", err)
	}
	data := <-received
	if !strings.Contains(strings.Join(data, "\n"), "[FIRING] High memory on web-1") {
		t.Errorf("subject not delivered: %v", data)
	}
}

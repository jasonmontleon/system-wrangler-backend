// SPDX-License-Identifier: Apache-2.0

// Command server is the System Wrangler HTTP entrypoint. It wires the
// SQLite-backed stores, auth service, systems probe, and SSE hub into a
// single mux and listens on PORT (8080 by default).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/google/uuid"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/auth"
	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/events"
	"system-wrangler-backend/internal/secrets"
	"system-wrangler-backend/internal/systems"
	"system-wrangler-backend/web"
)

func main() {
	rotateKeys := flag.Bool("rotate-keys", false,
		"re-seal every encrypted secret under SW_MASTER_KEY_FILE and exit; SW_MASTER_KEY_FILE_PREVIOUS must point at the outgoing key")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	addr := ":" + envOr("PORT", "8080")
	certPath, keyPath, useTLS, err := tlsConfig(os.Getenv)
	if err != nil {
		slog.Error("tls config", "err", err)
		os.Exit(1)
	}

	dbPath := envOr("DB_PATH", "system-wrangler.db")
	db, err := database.Open("file:" + dbPath)
	if err != nil {
		slog.Error("open db", "path", dbPath, "err", err)
		os.Exit(1)
	}
	defer func() {
		if err := db.Close(); err != nil {
			slog.Error("close db", "err", err)
		}
	}()
	store, err := systems.NewSQLiteStore(db)
	if err != nil {
		slog.Error("init systems store", "err", err)
		os.Exit(1)
	}
	authStore, err := auth.NewSQLiteAuthStore(db)
	if err != nil {
		slog.Error("init auth store", "err", err)
		os.Exit(1)
	}
	secret, err := auth.LoadOrInitSecret(authStore)
	if err != nil {
		slog.Error("load session secret", "err", err)
		os.Exit(1)
	}
	vault, err := secrets.NewVault()
	if err != nil {
		fmt.Fprintln(os.Stderr, secrets.FatalMessage())
		slog.Error("load master key", "err", err)
		os.Exit(1)
	}
	if err := authStore.MigrateLegacyTOTPSecrets(vault); err != nil {
		slog.Error("migrate legacy totp", "err", err)
		os.Exit(1)
	}
	if *rotateKeys {
		if _, err := authStore.RotateKeys(vault); err != nil {
			slog.Error("rotate keys", "err", err)
			os.Exit(1)
		}
		return
	}
	auditStore, err := audit.NewSQLiteStore(db)
	if err != nil {
		slog.Error("init audit store", "err", err)
		os.Exit(1)
	}
	authSvc := auth.NewService(authStore, secret, useTLS)
	authSvc.TOTPStore = authStore
	authSvc.RecoveryStore = authStore
	authSvc.DeviceStore = authStore
	authSvc.Vault = vault
	authSvc.Audit = auditStore
	authSvc.LoginThrottle = auth.NewThrottle(time.Minute, 10, time.Now)

	hub := events.NewHub(slog.Default())
	broadcastSystemsChanged := func() {
		hub.Broadcast(events.Event{Type: "systems.changed"})
	}

	probe := &systems.Probe{
		Store:    store,
		Prober:   systems.TCPProber{Port: "22", Timeout: 3 * time.Second},
		Interval: 30 * time.Second,
		Timeout:  5 * time.Second,
		Workers:  10,
		Trigger:  make(chan struct{}, 1),
		OnChange: broadcastSystemsChanged,
	}

	onCreate := func() {
		triggerProbe(probe)()
		broadcastSystemsChanged()
	}

	srv := &http.Server{
		Addr: addr,
		Handler: withRequestMeta(
			withLogging(
				newMux(store, authStore, authSvc, secret, hub, auditStore, onCreate, broadcastSystemsChanged),
			),
		),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	probeDone := make(chan struct{})
	go func() {
		probe.Run(ctx)
		close(probeDone)
	}()

	go func() {
		var serveErr error
		if useTLS {
			slog.Info("server starting", "addr", addr, "tls", true)
			serveErr = srv.ListenAndServeTLS(certPath, keyPath)
		} else {
			slog.Warn("server starting without TLS — set TLS_CERT_PATH and TLS_KEY_PATH to enable", "addr", addr)
			serveErr = srv.ListenAndServe()
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			slog.Error("server failed", "err", serveErr)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutdown signal received")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "err", err)
	}
	<-probeDone
}

func newMux(store systems.Store, users auth.UserStore, authSvc *auth.Service, secret []byte, hub *events.Hub, auditStore *audit.Store, onSystemCreate, onSystemDelete func()) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", handleHealth)
	authSvc.Register(mux)
	requireUser := auth.RequireUser(secret, users, time.Now)
	authSvc.RegisterProtected(mux, requireUser)
	authSvc.RegisterTOTP(mux, requireUser)
	authSvc.RegisterAdmin(mux, requireUser)
	sysHandler := systems.NewHandler(store)
	sysHandler.OnCreate = onSystemCreate
	sysHandler.OnDelete = onSystemDelete
	sysHandler.Register(mux, requireUser)
	if auditStore != nil {
		audit.NewHandler(auditStore).Register(mux, requireUser)
	}
	if hub != nil {
		mux.Handle("GET /api/events", requireUser(events.SSEHandler(hub)))
	}
	// Catchall for unmatched /api/* — without this they fall through to the
	// SPA handler and get index.html as a misleading 200. The SPA handler
	// is registered without a method so /api/ stays unambiguously more
	// specific for any method (Go's ServeMux conflicts otherwise).
	mux.HandleFunc("/api/", handleAPINotFound)
	mux.Handle("/", spaHandler())
	return mux
}

// triggerProbe returns a non-blocking sender for p.Trigger; drops cleanly
// when a tick is already in flight (channel buffer is 1).
func triggerProbe(p *systems.Probe) func() {
	return func() {
		select {
		case p.Trigger <- struct{}{}:
		default:
		}
	}
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func handleAPINotFound(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"error":"not found"}`))
}

func spaHandler() http.Handler {
	dist, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(dist))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			fileServer.ServeHTTP(w, r)
			return
		}
		// Fall back to index.html for unknown paths so client-side routing works.
		if _, err := fs.Stat(dist, path[1:]); err != nil {
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			fileServer.ServeHTTP(w, r2)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		// Structured log fields aren't interpolated into the message, so an
		// attacker-controlled URL can't forge log lines — gosec G706 is a
		// false positive against slog's key/value form.
		slog.Info("request", //nolint:gosec
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"duration_ms", strconv.FormatInt(time.Since(start).Milliseconds(), 10),
			"request_id", audit.RequestIDFromContext(r.Context()),
		)
	})
}

// withRequestMeta stamps a per-request UUID and the client IP onto the
// request context where the audit package reads them. The UUID is also
// echoed back as the X-Request-ID response header so operators can
// correlate a UI report with the matching audit row.
func withRequestMeta(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.NewString()
		w.Header().Set("X-Request-ID", id)
		ctx := audit.WithRequestID(r.Context(), id)
		ctx = audit.WithRemoteAddr(ctx, r.RemoteAddr)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Flush forwards to the underlying writer so SSE / chunked streaming keeps
// working through this wrapper. http.ResponseWriter doesn't include Flush,
// so embedding alone wouldn't promote it.
func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Compile-time check: the SSE handler type-asserts to http.Flusher; if this
// stops compiling the wrapper has regressed.
var _ http.Flusher = (*statusWriter)(nil)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// tlsConfig reads TLS_CERT_PATH and TLS_KEY_PATH via the supplied lookup
// (typically os.Getenv). Either both must be set or both unset; one without
// the other is rejected to fail loud on misconfiguration.
func tlsConfig(env func(string) string) (cert, key string, use bool, err error) {
	cert = env("TLS_CERT_PATH")
	key = env("TLS_KEY_PATH")
	if (cert == "") != (key == "") {
		return "", "", false, errors.New("TLS_CERT_PATH and TLS_KEY_PATH must both be set or both unset")
	}
	return cert, key, cert != "", nil
}

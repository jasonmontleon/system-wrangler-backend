// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"system-wrangler-backend/internal/auth"
	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/systems"
	"system-wrangler-backend/web"
)

func main() {
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
	authSvc := auth.NewService(authStore, secret, useTLS)

	srv := &http.Server{
		Addr:              addr,
		Handler:           withLogging(newMux(store, authStore, authSvc, secret)),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	probe := &systems.Probe{
		Store:    store,
		Prober:   systems.TCPProber{Port: "22", Timeout: 3 * time.Second},
		Interval: 30 * time.Second,
		Timeout:  5 * time.Second,
		Workers:  10,
	}
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

func newMux(store systems.Store, users auth.UserStore, authSvc *auth.Service, secret []byte) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", handleHealth)
	authSvc.Register(mux)
	requireUser := auth.RequireUser(secret, users, time.Now)
	systems.NewHandler(store).Register(mux, requireUser)
	mux.Handle("GET /", spaHandler())
	return mux
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
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
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"duration_ms", strconv.FormatInt(time.Since(start).Milliseconds(), 10),
		)
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

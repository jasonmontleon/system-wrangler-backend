// SPDX-License-Identifier: Apache-2.0

// Command server is the System Wrangler HTTP entrypoint. It wires the
// SQLite-backed stores, auth service, systems probe, and SSE hub into a
// single mux and listens on PORT (8080 by default).
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"system-wrangler-backend/internal/ansible"
	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/auth"
	"system-wrangler-backend/internal/backup"
	"system-wrangler-backend/internal/credentials"
	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/events"
	"system-wrangler-backend/internal/exporters"
	"system-wrangler-backend/internal/groups"
	"system-wrangler-backend/internal/hostkeys"
	"system-wrangler-backend/internal/metrics"
	"system-wrangler-backend/internal/openapi"
	"system-wrangler-backend/internal/promtargets"
	"system-wrangler-backend/internal/rbac"
	"system-wrangler-backend/internal/router"
	"system-wrangler-backend/internal/scrape"
	"system-wrangler-backend/internal/secrets"
	"system-wrangler-backend/internal/secretscan"
	"system-wrangler-backend/internal/settings"
	"system-wrangler-backend/internal/sshproxy"
	"system-wrangler-backend/internal/systems"
	"system-wrangler-backend/internal/updaters"
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
	groupStore, err := groups.NewSQLiteStore(db)
	if err != nil {
		slog.Error("init groups store", "err", err)
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
	auditStore, err := audit.NewSQLiteStore(db)
	if err != nil {
		slog.Error("init audit store", "err", err)
		os.Exit(1)
	}
	if *rotateKeys {
		if _, err := authStore.RotateKeys(vault, auditStore); err != nil {
			slog.Error("rotate keys", "err", err)
			os.Exit(1)
		}
		return
	}
	rbacStore, err := rbac.NewSQLiteStore(db)
	if err != nil {
		slog.Error("init rbac store", "err", err)
		os.Exit(1)
	}
	credStore, err := credentials.NewSQLiteStore(db)
	if err != nil {
		slog.Error("init credentials store", "err", err)
		os.Exit(1)
	}
	hostKeyStore, err := hostkeys.NewSQLiteStore(db)
	if err != nil {
		slog.Error("init hostkeys store", "err", err)
		os.Exit(1)
	}
	updaterStore, err := updaters.NewSQLiteStore(db)
	if err != nil {
		slog.Error("init updaters store", "err", err)
		os.Exit(1)
	}
	exporterStore, err := exporters.NewSQLiteStore(db)
	if err != nil {
		slog.Error("init exporters store", "err", err)
		os.Exit(1)
	}
	settingsStore, err := settings.NewSQLiteStore(db)
	if err != nil {
		slog.Error("init settings store", "err", err)
		os.Exit(1)
	}
	authSvc := auth.NewService(authStore, secret, useTLS)
	authSvc.TOTPStore = authStore
	authSvc.RecoveryStore = authStore
	authSvc.DeviceStore = authStore
	authSvc.Vault = vault
	authSvc.Audit = auditStore
	authSvc.DB = db
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
				auth.CSRF(auditStore)(
					newMux(db, store, groupStore, authStore, authSvc, secret, vault, hub, auditStore, rbacStore, credStore, hostKeyStore, updaterStore, exporterStore, settingsStore, onCreate, broadcastSystemsChanged),
				),
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

	// Prometheus targets writer: only runs when SW_TARGETS_FILE is set
	// — otherwise the metrics pipeline isn't wired and the file would
	// be writeable garbage. Subscribes to the hub for inventory
	// changes; debounces internally.
	targetsStop := func() {}
	if targetsFile := os.Getenv("SW_TARGETS_FILE"); targetsFile != "" {
		tw := &promtargets.Writer{
			Path:          targetsFile,
			BackendTarget: envOr("SW_BACKEND_TARGET", "system-wrangler:8080"),
			Systems:       store,
			Exporters:     exporterStore,
		}
		targetsStop = tw.Run(ctx, func(handler func(string)) func() {
			sub := hub.Subscribe()
			ready := make(chan struct{})
			go func() {
				close(ready)
				for ev := range sub.Ch {
					handler(ev.Type)
				}
			}()
			<-ready
			return func() { hub.Unsubscribe(sub) }
		})
	}

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
	// Stop the targets writer first — once the hub closes its
	// subscriber channel, the writer's goroutine returns; targetsStop
	// waits for it before unsubscribing.
	targetsStop()
	// Close the SSE hub first so streaming handlers observe their channel
	// close and return; otherwise srv.Shutdown waits out its deadline on
	// the long-lived /api/events requests held by open dashboard tabs.
	hub.Close()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "err", err)
		if err := srv.Close(); err != nil {
			slog.Error("force close error", "err", err)
		}
	}
	<-probeDone
}

func newMux(db *sql.DB, store systems.Store, groupStore groups.Store, authStore *auth.SQLiteAuthStore, authSvc *auth.Service, secret []byte, vault *secrets.Vault, hub *events.Hub, auditStore *audit.Store, rbacStore rbac.Store, credStore credentials.Store, hostKeyStore hostkeys.Store, updaterStore updaters.Store, exporterStore exporters.Store, settingsStore settings.Store, onSystemCreate, onSystemDelete func()) *http.ServeMux {
	mux := http.NewServeMux()
	populateMux(mux, db, store, groupStore, authStore, authSvc, secret, vault, hub, auditStore, rbacStore, credStore, hostKeyStore, updaterStore, exporterStore, settingsStore, onSystemCreate, onSystemDelete)
	return mux
}

// populateMux registers every System Wrangler route on mux. Extracted
// from newMux so the openapi drift test can hand in a recording wrapper
// that captures every (method, path) pattern without spinning up a real
// *http.ServeMux. main.go and tests reach for newMux; only the drift
// test needs this entry point.
func populateMux(mux router.Mux, db *sql.DB, store systems.Store, groupStore groups.Store, authStore *auth.SQLiteAuthStore, authSvc *auth.Service, secret []byte, vault *secrets.Vault, hub *events.Hub, auditStore *audit.Store, rbacStore rbac.Store, credStore credentials.Store, hostKeyStore hostkeys.Store, updaterStore updaters.Store, exporterStore exporters.Store, settingsStore settings.Store, onSystemCreate, onSystemDelete func()) {
	mux.Handle("GET /api/health", http.HandlerFunc(handleHealth))
	authSvc.Register(mux)
	requireUserOnly := auth.RequireUser(secret, authStore, time.Now)
	withScope := rbac.Middleware(rbacStore)
	// requireUser chains RequireUser → Middleware(rbac) so every
	// authenticated handler downstream can read both the User and the
	// Scope off the request context.
	requireUser := func(next http.Handler) http.Handler {
		return requireUserOnly(withScope(next))
	}
	authSvc.RegisterProtected(mux, requireUser)
	authSvc.RegisterTOTP(mux, requireUser)
	authSvc.RegisterAdmin(mux, requireUser)
	sysHandler := systems.NewHandler(store)
	sysHandler.DB = db
	if auditStore != nil {
		sysHandler.AuditEmit = func(ctx context.Context, tx *sql.Tx, action string, sys systems.System, detail map[string]any) error {
			d := audit.NewDetail()
			for k, v := range detail {
				_ = d.SetSafe(k, v)
			}
			return auditStore.LogTx(ctx, tx, audit.Event{
				Action:      action,
				Outcome:     audit.Success,
				TargetKind:  "system",
				TargetID:    sys.ID,
				TargetLabel: sys.Name,
				Detail:      d,
			})
		}
	}
	sysHandler.OnCreate = onSystemCreate
	sysHandler.OnDelete = onSystemDelete
	sysHandler.VisibleSystem = func(ctx context.Context, s systems.System) bool {
		scope, ok := rbac.ScopeFromContext(ctx)
		if !ok {
			return true
		}
		return scope.CanReadSystem(s.GroupID)
	}
	sysHandler.CanCreate = func(ctx context.Context) bool {
		scope, ok := rbac.ScopeFromContext(ctx)
		return ok && scope.CanCreateSystem()
	}
	sysHandler.SystemStats = func() (map[string]systems.Stats, error) {
		raw, err := updaterStore.SystemStatsAll()
		if err != nil {
			return nil, err
		}
		out := make(map[string]systems.Stats, len(raw))
		for id, s := range raw {
			pkgs := make([]systems.PendingPackage, len(s.PendingPackages))
			for i, p := range s.PendingPackages {
				pkgs[i] = systems.PendingPackage{
					Name:       p.Name,
					OldVersion: p.OldVersion,
					NewVersion: p.NewVersion,
				}
			}
			out[id] = systems.Stats{
				LastCheckedAt:   s.LastCheckedAt,
				PendingUpdates:  s.PendingUpdates,
				PendingPackages: pkgs,
				LastRunFailed:   s.LastRunFailed,
				LastRunReason:   s.LastRunReason,
				Running:         s.Running,
			}
		}
		return out, nil
	}
	sysHandler.CanDelete = func(ctx context.Context, s systems.System) bool {
		scope, ok := rbac.ScopeFromContext(ctx)
		return ok && scope.CanDeleteSystem(s.GroupID)
	}
	sysHandler.CanEdit = func(ctx context.Context, s systems.System) bool {
		scope, ok := rbac.ScopeFromContext(ctx)
		return ok && scope.CanEditSystem(s.GroupID)
	}
	sysHandler.Register(mux, requireUser)
	groupHandler := groups.NewHandler(groupStore, store)
	groupHandler.OnChange = onSystemDelete
	groupHandler.Audit = auditStore
	groupHandler.VisibleGroup = func(ctx context.Context, g groups.Group) bool {
		scope, ok := rbac.ScopeFromContext(ctx)
		if !ok {
			return true
		}
		return scope.CanReadGroup(g.ID)
	}
	groupHandler.CanManage = func(ctx context.Context) bool {
		scope, ok := rbac.ScopeFromContext(ctx)
		return ok && scope.CanManageGroups()
	}
	groupHandler.CanMoveSystem = func(ctx context.Context, from, to *string) bool {
		scope, ok := rbac.ScopeFromContext(ctx)
		return ok && scope.CanMoveSystem(from, to)
	}
	groupHandler.Register(mux, requireUser)
	if auditStore != nil {
		ah := audit.NewHandler(auditStore)
		ah.ScopeFilterFor = func(r *http.Request) *audit.ScopeFilter {
			s, ok := rbac.ScopeFromContext(r.Context())
			if !ok || s.IsGlobalAuditor() {
				return nil
			}
			return &audit.ScopeFilter{GroupIDs: s.VisibleGroupIDs()}
		}
		ah.Register(mux, requireUser)
	}
	rbacHandler := rbac.NewHandler(rbacStore, authStore, groupStore)
	rbacHandler.Audit = auditStore
	rbacHandler.Register(mux, requireUser)
	backupHandler := backup.NewHandler(&backup.Service{DB: db})
	backupHandler.Audit = auditStore
	backupHandler.CanCreate = func(ctx context.Context) bool {
		scope, ok := rbac.ScopeFromContext(ctx)
		return ok && scope.IsGlobalAdmin()
	}
	backupHandler.Register(mux, requireUser)
	credHandler := &credentials.Handler{
		Store:   credStore,
		Vault:   vault,
		Systems: store,
		Groups:  groupStore,
		Audit:   auditStore,
		CanManageGlobal: func(ctx context.Context) bool {
			scope, ok := rbac.ScopeFromContext(ctx)
			return ok && scope.IsGlobalAdmin()
		},
		CanManageGroup: func(ctx context.Context, groupID string) bool {
			scope, ok := rbac.ScopeFromContext(ctx)
			if !ok {
				return false
			}
			return scope.IsGlobalAdmin() || scope.RoleOnGroup(groupID) == rbac.RoleAdmin
		},
		CanManageSystem: func(ctx context.Context, s systems.System) bool {
			scope, ok := rbac.ScopeFromContext(ctx)
			if !ok {
				return false
			}
			if scope.IsGlobalAdmin() {
				return true
			}
			if s.GroupID == nil {
				return false
			}
			return scope.RoleOnGroup(*s.GroupID) == rbac.RoleAdmin
		},
		CanReadSystem: func(ctx context.Context, s systems.System) bool {
			scope, ok := rbac.ScopeFromContext(ctx)
			if !ok {
				return false
			}
			return scope.CanReadSystem(s.GroupID)
		},
	}
	credHandler.Register(mux, requireUser)
	hostKeyHandler := &hostkeys.Handler{
		Store:    hostKeyStore,
		Systems:  store,
		Audit:    auditStore,
		Executor: ansible.ExecExecutor{},
		CanManageSystem: func(ctx context.Context, s systems.System) bool {
			scope, ok := rbac.ScopeFromContext(ctx)
			if !ok {
				return false
			}
			if scope.IsGlobalAdmin() {
				return true
			}
			if s.GroupID == nil {
				return false
			}
			return scope.RoleOnGroup(*s.GroupID) == rbac.RoleAdmin
		},
	}
	hostKeyHandler.Register(mux, requireUser)
	if vault != nil {
		ansibleRunner := &ansible.Runner{
			Executor:    ansible.ExecExecutor{},
			Systems:     store,
			Credentials: credStore,
			HostKeys:    hostKeyStore,
			Vault:       vault,
			Audit:       auditStore,
		}
		ansibleHandler := &ansible.Handler{
			Runner:  ansibleRunner,
			Systems: store,
			CanManageSystem: func(ctx context.Context, s systems.System) bool {
				scope, ok := rbac.ScopeFromContext(ctx)
				if !ok {
					return false
				}
				if scope.IsGlobalAdmin() {
					return true
				}
				if s.GroupID == nil {
					return false
				}
				return scope.RoleOnGroup(*s.GroupID) == rbac.RoleAdmin
			},
		}
		ansibleHandler.Register(mux, requireUser)
		updaterRegistry := updaters.NewRegistry(updaterStore)
		updaterRunner := &updaters.Runner{
			Registry: updaterRegistry,
			Store:    updaterStore,
			Ansible:  ansibleRunner,
			Audit:    auditStore,
			RunHistoryLimit: func() int {
				return settings.RunHistoryLimit(settingsStore)
			},
			Gate: &updaters.Gate{
				Limit: func() int {
					return settings.UpdateConcurrencyLimit(settingsStore)
				},
			},
			Notify: func(t string) {
				hub.Broadcast(events.Event{Type: t})
			},
		}
		updaterHandler := &updaters.Handler{
			Runner:  updaterRunner,
			Store:   updaterStore,
			Systems: store,
			CanOperateSystem: func(ctx context.Context, s systems.System) bool {
				scope, ok := rbac.ScopeFromContext(ctx)
				if !ok {
					return false
				}
				if scope.IsGlobalOperator() {
					return true
				}
				if s.GroupID == nil {
					return false
				}
				return scope.CanOperateGroup(*s.GroupID)
			},
			CanReadSystem: func(ctx context.Context, s systems.System) bool {
				scope, ok := rbac.ScopeFromContext(ctx)
				if !ok {
					return false
				}
				return scope.CanReadSystem(s.GroupID)
			},
		}
		updaterHandler.Register(mux, requireUser)
		updaterAdmin := &updaters.AdminHandler{
			Registry: updaterRegistry,
			Syntax:   &updaters.AnsibleSyntaxChecker{Executor: ansible.ExecExecutor{}},
			Audit:    auditStore,
			CanManage: func(ctx context.Context) bool {
				scope, ok := rbac.ScopeFromContext(ctx)
				return ok && scope.IsGlobalAdmin()
			},
		}
		updaterAdmin.Register(mux, requireUser)

		exporterRegistry := exporters.NewRegistry(exporterStore)
		exporterRunner := &exporters.Runner{
			Registry: exporterRegistry,
			Store:    exporterStore,
			Locker:   updaterStore,
			Ansible:  ansibleRunner,
			Audit:    auditStore,
			RunHistoryLimit: func() int {
				return settings.RunHistoryLimit(settingsStore)
			},
			Notify: func(t string) {
				hub.Broadcast(events.Event{Type: t})
			},
		}
		exporterHandler := &exporters.Handler{
			Runner:  exporterRunner,
			Store:   exporterStore,
			Systems: store,
			Probe:   updaterPkgManagerProbe{store: updaterStore},
			CanOperateSystem: func(ctx context.Context, s systems.System) bool {
				scope, ok := rbac.ScopeFromContext(ctx)
				if !ok {
					return false
				}
				if scope.IsGlobalOperator() {
					return true
				}
				if s.GroupID == nil {
					return false
				}
				return scope.CanOperateGroup(*s.GroupID)
			},
			CanReadSystem: func(ctx context.Context, s systems.System) bool {
				scope, ok := rbac.ScopeFromContext(ctx)
				if !ok {
					return false
				}
				return scope.CanReadSystem(s.GroupID)
			},
		}
		exporterHandler.Register(mux, requireUser)
		exporterAdmin := &exporters.AdminHandler{
			Registry: exporterRegistry,
			Syntax:   &exporters.AnsibleSyntaxChecker{Executor: ansible.ExecExecutor{}},
			Audit:    auditStore,
			CanManage: func(ctx context.Context) bool {
				scope, ok := rbac.ScopeFromContext(ctx)
				return ok && scope.IsGlobalAdmin()
			},
		}
		exporterAdmin.Register(mux, requireUser)

		// Metrics pipeline phase 1: SSH-tunneled scrape endpoint
		// Prometheus targets, plus the authenticated query proxy
		// the SPA hits. The scrape endpoint is gated by the
		// internal secret — an empty value disables the endpoint
		// entirely. SW_INTERNAL_SECRET_FILE takes precedence so the
		// deployment can mount the secret as a file (Prometheus
		// reads the same file via its authorization.credentials_file
		// setting).
		internalSecret := readInternalSecret()
		sshProxy := &sshproxy.Proxy{
			Systems:     store,
			Credentials: credStore,
			HostKeys:    hostKeyStore,
			Vault:       vault,
		}
		scrapeHandler := &scrape.Handler{
			Proxy:     sshProxy,
			Exporters: exporterStore,
			Secret:    internalSecret,
		}
		scrapeHandler.Register(mux)

		metricsHandler := &metrics.Handler{
			UpstreamURL: envOr("SW_PROMETHEUS_URL", "http://prometheus:9090"),
			CanRead: func(ctx context.Context) bool {
				_, ok := rbac.ScopeFromContext(ctx)
				return ok
			},
		}
		metricsHandler.Register(mux, requireUser)
	}
	if vault != nil {
		secretscanHandler := &secretscan.Handler{
			Vault: vault,
			Sources: []secretscan.Source{
				auth.TOTPScanSource{Store: authStore},
				credentials.ScanSource{Store: credStore},
			},
			CanScan: func(ctx context.Context) bool {
				scope, ok := rbac.ScopeFromContext(ctx)
				return ok && scope.IsGlobalAdmin()
			},
		}
		secretscanHandler.Register(mux, requireUser)
	}
	if hub != nil {
		mux.Handle("GET /api/events", requireUser(events.SSEHandler(hub)))
	}
	settingsHandler := &settings.Handler{
		Store: settingsStore,
		Audit: auditStore,
		CanManage: func(ctx context.Context) bool {
			scope, ok := rbac.ScopeFromContext(ctx)
			return ok && scope.IsGlobalAdmin()
		},
	}
	settingsHandler.Register(mux, requireUser)
	openapi.Handler{}.Register(mux)
	// Catchall for unmatched /api/* — without this they fall through to the
	// SPA handler and get index.html as a misleading 200. The SPA handler
	// is registered without a method so /api/ stays unambiguously more
	// specific for any method (Go's ServeMux conflicts otherwise).
	mux.Handle("/api/", http.HandlerFunc(handleAPINotFound))
	mux.Handle("/", spaHandler())
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

// readInternalSecret resolves the shared secret Prometheus uses to
// authenticate to /internal/scrape. SW_INTERNAL_SECRET_FILE wins
// when set so an operator can mount the secret as a file shared with
// Prometheus's authorization.credentials_file. Trailing whitespace is
// trimmed because /dev/urandom-piped-to-a-file tends to add a
// newline.
func readInternalSecret() string {
	if path := os.Getenv("SW_INTERNAL_SECRET_FILE"); path != "" {
		body, err := os.ReadFile(path) //nolint:gosec // operator-controlled path
		if err != nil {
			// The literal env var name in the message isn't a
			// credential; gosec G101 is a false positive on the
			// "SECRET"-containing string.
			slog.Warn("SW_INTERNAL_SECRET_FILE could not be read; scrape endpoint disabled", "err", err, "path", path) //nolint:gosec
			return ""
		}
		return strings.TrimSpace(string(body))
	}
	return os.Getenv("SW_INTERNAL_SECRET")
}

// updaterPkgManagerProbe adapts updaters.Store.AvailabilityFor to the
// exporters.PkgManagerProbe interface so the exporter handler can ask
// "what package managers are detected on this system?" without
// importing the updaters types directly.
type updaterPkgManagerProbe struct {
	store updaters.Store
}

func (p updaterPkgManagerProbe) DetectedPkgManagers(systemID string) ([]string, error) {
	avail, err := p.store.AvailabilityFor(systemID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(avail))
	for _, a := range avail {
		out = append(out, a.UpdaterID)
	}
	return out, nil
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

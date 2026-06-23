// Command arcloreweb serves the Gitea-style web UI for a Lore server.
package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"arcloreweb/internal/auth"
	"arcloreweb/internal/config"
	"arcloreweb/internal/handlers"
	"arcloreweb/internal/lore"
	"arcloreweb/internal/mgmt"
	"arcloreweb/web"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("arcloreweb: config: %v", err)
	}

	// Dial is lazy (grpc.NewClient) — it does NOT block on a live server, so a
	// down Lore endpoint at boot is fine; calls fail at request time instead.
	loreClient, err := lore.Dial(cfg.LoreGRPCAddr, cfg.LoreHTTPAddr, cfg.RequestTimeout)
	if err != nil {
		log.Fatalf("arcloreweb: lore dial: %v", err)
	}
	defer func() { _ = loreClient.Close() }()

	// An explicit override bypasses EnvironmentService auth-URL discovery.
	if cfg.AuthURL != "" {
		loreClient.SetAuthURL(cfg.AuthURL)
	}

	sessions := auth.NewSessionManager(cfg.CookieSecure, cfg.SessionSecret)
	h := handlers.New(loreClient, sessions)

	// mgmtClient is shared by the native-login flow and the admin handlers.
	// Under auth-disabled (dev bypass) it is constructed with an empty base URL
	// and will never be called — RequireAuth redirects before any admin handler
	// runs, and the login block is skipped entirely.
	mgmtClient := mgmt.New(cfg.MgmtAPIAddr, cfg.RequestTimeout)
	adminHandler := handlers.NewAdmin(mgmtClient, loreClient, sessions)

	router := chi.NewRouter()
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			// Strict CSP: all scripts are external (script-src 'self'), so no
			// inline <script>/on* handlers are permitted — the copy buttons and
			// destructive-action confirms now live in /static/app.js. style-src
			// keeps 'unsafe-inline' for templ's inline styles; img-src allows
			// data: URIs for inline images.
			w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; frame-ancestors 'none'")
			next.ServeHTTP(w, r)
		})
	})
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(sessions.LoadAndSave)

	// CSRF: reject unsafe cross-origin browser requests (Sec-Fetch-Site / Origin
	// vs Host). GET/HEAD/OPTIONS are safe and auto-pass, so static/health/browse
	// GETs are unaffected; only unsafe methods (the POST forms) are checked.
	// Same-origin and non-browser (header-less) requests pass.
	cop := http.NewCrossOriginProtection()
	for _, o := range cfg.CSRFTrustedOrigins {
		if err := cop.AddTrustedOrigin(o); err != nil {
			log.Fatalf("arcloreweb: trusted origin %q: %v", o, err)
		}
	}
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("cross-origin request blocked"))
	}))
	router.Use(cop.Handler)

	// Unauthenticated.
	router.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	// chroma.css is generated, not embedded — register the explicit route before
	// the static catch-all so it wins.
	router.Get("/static/chroma.css", h.ServeChromaCSS)
	router.Handle("/static/*", web.StaticHandler())

	// Auth endpoints: dev bypass when auth is disabled, native login (a
	// username/password form posting to arc-lore-auth's /api) otherwise. The
	// UCS/gRPC flow stays in arc-lore-auth for the UE editor/CLI clients.
	if cfg.AuthDisabled {
		router.Get("/auth/login", auth.DevLoginHandler(sessions, cfg.DevUserSub))
	} else {
		// Per-browser login/setup rate-limit. arc-lore-auth already throttles
		// /api/login + /api/setup, but keyed on the CALLER's IP — which for
		// browser logins is always this web server's single IP, collapsing every
		// browser into one shared bucket. Throttling here keys on the browser's
		// RemoteAddr (or leftmost X-Forwarded-For when TRUST_FORWARDED_FOR), so it
		// actually defends per-browser. Only the unsafe POSTs are wrapped; the GET
		// forms stay open.
		lt := auth.NewLoginThrottle(8, 6*time.Second)

		native := &handlers.Native{Mgmt: mgmtClient, Sessions: sessions}
		router.Get("/auth/login", native.LoginForm)
		router.With(lt.Middleware(cfg.TrustForwardedFor)).Post("/auth/login", native.LoginSubmit)
		router.Post("/auth/logout", native.Logout)
		router.Get("/setup", native.SetupForm)
		router.With(lt.Middleware(cfg.TrustForwardedFor)).Post("/setup", native.SetupSubmit)

		// Public self-service registration. The GET form fails closed (redirects to
		// login when registration is closed); the throttled POST carries the same
		// per-browser rate-limit as login/setup. The server endpoint re-gates on
		// every POST, so a stale form after toggle-OFF still gets a clean 403.
		router.Get("/auth/register", native.RegisterForm)
		router.With(lt.Middleware(cfg.TrustForwardedFor)).Post("/auth/register", native.RegisterSubmit)

		// Self-service account page (any logged-in user). Kept in this block so it
		// closes over `native`; RequireAuth gates it independently of the browse
		// group below.
		router.Group(func(r chi.Router) {
			r.Use(auth.RequireAuth(sessions))
			r.Get("/account", native.AccountForm)
			r.Post("/account/password", native.ChangePassword)
		})
	}

	// Authenticated browse routes.
	router.Group(func(r chi.Router) {
		r.Use(auth.RequireAuth(sessions))
		r.Get("/", h.Home)
		r.Get("/explore", h.Explore)
		r.Get("/{owner}/{repo}", h.RepoHome)
		r.Get("/{owner}/{repo}/src/branch/{branch}/*", h.Tree)
		r.Get("/{owner}/{repo}/raw/branch/{branch}/*", h.Raw)
		r.Get("/{owner}/{repo}/commits/branch/{branch}", h.Commits)
		r.Get("/{owner}/{repo}/locks/branch/{branch}", h.Locks)
		r.Post("/{owner}/{repo}/locks/branch/{branch}/release", h.ReleaseLock)
		r.Get("/{owner}/{repo}/commit/{sig}", h.Commit)
	})

	// Admin management routes — require auth AND admin.
	router.Group(func(r chi.Router) {
		r.Use(auth.RequireAuth(sessions))
		r.Use(auth.RequireAdmin(sessions))

		// Users
		r.Get("/admin/users", adminHandler.AdminUsers)
		r.Post("/admin/users", adminHandler.AdminCreateUser)
		r.Post("/admin/users/{username}/delete", adminHandler.AdminDeleteUser)
		r.Post("/admin/users/{username}/password", adminHandler.AdminSetPassword)
		r.Post("/admin/users/{username}/admin", adminHandler.AdminSetAdmin)
		r.Post("/admin/registration", adminHandler.AdminSetRegistration)

		// Repos
		r.Get("/admin/repos", adminHandler.AdminRepos)
		r.Post("/admin/repos", adminHandler.AdminCreateRepo)
		r.Post("/admin/repos/import", adminHandler.AdminImportRepo)
		r.Post("/admin/repos/{id}/delete", adminHandler.AdminDeleteRepo)
		r.Post("/admin/resources/remove", adminHandler.AdminRemoveResource)

		// Grants
		r.Get("/admin/grants", adminHandler.AdminGrants)
		r.Post("/admin/grants", adminHandler.AdminAddGrant)
		r.Post("/admin/grants/delete", adminHandler.AdminRemoveGrant)
	})

	// Warn-on-unsafe: surface plaintext exposure when bound beyond loopback.
	// Same loopback rule as the auth service — 0.0.0.0/::/empty are non-loopback;
	// only 127.0.0.1/::1/localhost count as loopback.
	host, _, splitErr := net.SplitHostPort(cfg.ListenAddr)
	if splitErr != nil {
		host = cfg.ListenAddr
	}
	ip := net.ParseIP(host)
	nonLoopback := !(host == "localhost" || (ip != nil && ip.IsLoopback()))
	if nonLoopback {
		if cfg.TLSCertFile == "" {
			log.Printf("WARNING: arcloreweb bound to %s over plaintext HTTP — set TLS_CERT_FILE/TLS_KEY_FILE or bind to 127.0.0.1 before exposing beyond a trusted LAN.", cfg.ListenAddr)
		}
		if !cfg.CookieSecure {
			log.Printf("WARNING: SESSION_COOKIE_SECURE=false on a non-loopback bind — the session cookie is sent over plaintext.")
		}
		if !grpcUsesTLS(cfg.LoreGRPCAddr) {
			log.Printf("WARNING: gRPC to lore-server is plaintext on a non-loopback bind — the authz token travels unencrypted.")
		}
	}

	srv := &http.Server{Addr: cfg.ListenAddr, Handler: router}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// TLS is opt-in: both files set → HTTPS; exactly one → fatal misconfig; none
	// → plaintext HTTP (the default LAN mode, unchanged).
	serveErr := make(chan error, 1)
	switch {
	case cfg.TLSCertFile != "" && cfg.TLSKeyFile != "":
		go func() { serveErr <- srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile) }()
	case cfg.TLSCertFile != "" || cfg.TLSKeyFile != "":
		log.Fatalf("arcloreweb: TLS_CERT_FILE and TLS_KEY_FILE must be set together")
	default:
		go func() { serveErr <- srv.ListenAndServe() }()
	}

	log.Printf("arcloreweb: listening on %s (auth_disabled=%t)", cfg.ListenAddr, cfg.AuthDisabled)

	select {
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("arcloreweb: server: %v", err)
		}
	case <-ctx.Done():
		stop() // restore default signal handling so a second Ctrl-C forces exit
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Fatalf("arcloreweb: shutdown: %v", err)
		}
	}
}

// grpcUsesTLS reports whether the Lore gRPC connection is encrypted, mirroring
// lore.Dial's ACTUAL detection: only a "…s://" scheme (e.g. "grpcs://") requests
// TLS. Dial does not consume LoreTLS, so the warning must not either — keying off
// LoreTLS here would silence the warning while the dial stays plaintext.
func grpcUsesTLS(grpcAddr string) bool {
	scheme, _, found := strings.Cut(grpcAddr, "://")
	if !found {
		return false
	}
	return strings.HasSuffix(scheme, "s")
}

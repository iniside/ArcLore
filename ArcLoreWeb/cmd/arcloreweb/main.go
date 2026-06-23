// Command arcloreweb serves the Gitea-style web UI for a Lore server.
package main

import (
	"log"
	"net/http"
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

	sessions := auth.NewSessionManager(cfg.CookieSecure)
	h := handlers.New(loreClient, sessions)

	// mgmtClient is shared by the native-login flow and the admin handlers.
	// Under auth-disabled (dev bypass) it is constructed with an empty base URL
	// and will never be called — RequireAuth redirects before any admin handler
	// runs, and the login block is skipped entirely.
	mgmtClient := mgmt.New(cfg.MgmtAPIAddr, cfg.RequestTimeout)
	adminHandler := handlers.NewAdmin(mgmtClient, loreClient, sessions)

	router := chi.NewRouter()
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

		native := &auth.Native{Mgmt: mgmtClient, Sessions: sessions}
		router.Get("/auth/login", native.LoginForm)
		router.With(lt.Middleware(cfg.TrustForwardedFor)).Post("/auth/login", native.LoginSubmit)
		router.Get("/auth/logout", native.Logout)
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

	log.Printf("arcloreweb: listening on %s (auth_disabled=%t)", cfg.ListenAddr, cfg.AuthDisabled)
	if err := http.ListenAndServe(cfg.ListenAddr, router); err != nil {
		log.Fatalf("arcloreweb: server: %v", err)
	}
}

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	// ── global flags ──────────────────────────────────────────────────────
	configPath := flag.String("config", "config.toml", "path to config.toml")
	listenAddr := flag.String("listen", "", "override listen_addr")
	audience := flag.String("audience", "", "override audience (lore-server host domain)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: arc-lore-auth [flags] [subcommand]\n\n")
		fmt.Fprintf(os.Stderr, "Subcommands:\n")
		fmt.Fprintf(os.Stderr, "  (none)       run the HTTP daemon\n")
		fmt.Fprintf(os.Stderr, "  mint         print a JWT to stdout (offline, no daemon needed)\n")
		fmt.Fprintf(os.Stderr, "  print-jwks   print the JWKS JSON to stdout and exit\n")
		fmt.Fprintf(os.Stderr, "  useradd      create a user in the DB store (prompts for a password)\n")
		fmt.Fprintf(os.Stderr, "  userlist     list users in the DB store\n")
		fmt.Fprintf(os.Stderr, "  userdel      delete a user from the DB store\n")
		fmt.Fprintf(os.Stderr, "  setpw        set a user's password (prompts for a password)\n")
		fmt.Fprintf(os.Stderr, "  hash-secret  print an argon2id hash of an admin secret (for admin_secret in config)\n")
		fmt.Fprintf(os.Stderr, "\nFlags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	// Pull subcommand from remaining args.
	args := flag.Args()
	sub := ""
	if len(args) > 0 {
		sub = args[0]
		args = args[1:]
	}

	switch sub {
	case "mint":
		runMintCmd(*configPath, *audience, args)
	case "print-jwks":
		runPrintJWKSCmd(*configPath, *audience)
	case "useradd":
		runUserAddCmd(*configPath, args)
	case "userlist":
		runUserListCmd(*configPath)
	case "userdel":
		runUserDelCmd(*configPath, args)
	case "setpw":
		runSetPwCmd(*configPath, args)
	case "hash-secret":
		runHashSecretCmd(args)
	default:
		runDaemon(*configPath, *listenAddr, *audience)
	}
}

// ── daemon ────────────────────────────────────────────────────────────────────

func runDaemon(configPath, listenOverride, audienceOverride string) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "arc-lore-auth: config: %v\n", err)
		os.Exit(1)
	}

	if listenOverride != "" {
		// The -listen flag overrides the web/JWKS HTTP bind (the listener the
		// browser and lore-server reach). ListenAddr is retained in Config only
		// for backward-compat; the active web listener binds WebListenAddr.
		cfg.WebListenAddr = listenOverride
	}
	if audienceOverride != "" {
		cfg.Audience = audienceOverride
	}

	if cfg.Audience == "" {
		fmt.Fprintln(os.Stderr, "arc-lore-auth: audience is required — set it in config.toml")
		fmt.Fprintln(os.Stderr, "  audience must be the lore-server host domain (e.g. \"my-host.lan\")")
		fmt.Fprintln(os.Stderr, "  so the in-editor client gate (remote_domain.ends_with(aud)) passes.")
		os.Exit(1)
	}
	if cfg.Audience == cfg.Issuer {
		fmt.Fprintln(os.Stderr, "arc-lore-auth: audience must not equal issuer — this is almost certainly a misconfiguration")
		fmt.Fprintln(os.Stderr, "  audience should be the lore-server host domain; issuer is the auth service name")
		os.Exit(1)
	}

	priv, err := loadOrGenerateKey(cfg.KeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "arc-lore-auth: key: %v\n", err)
		os.Exit(1)
	}

	kid, err := keyID(&priv.PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "arc-lore-auth: kid: %v\n", err)
		os.Exit(1)
	}

	jwkSet, err := buildJWKSet(priv, kid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "arc-lore-auth: JWKS: %v\n", err)
		os.Exit(1)
	}

	// Open the shared SQLite store ONCE. The SAME pointer backs both the web
	// /login (VerifyHash) and /admin (AddUser/SetPassword/DeleteUser/ListUsers)
	// handlers — there is no gRPC consumer of the user store (the gRPC exchange
	// trusts a token we already signed), but the web login + admin must agree on
	// one store. The daemon runs for the process lifetime, so a deferred Close on
	// the fatal exit path is sufficient.
	userStore, err := OpenStore(cfg.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "arc-lore-auth: db: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = userStore.Close() }()

	// One-shot legacy import: if a users.json exists and the DB has no users yet,
	// import its rows preserving argon2 hashes + timestamps. The FIRST imported
	// user is marked is_admin=1 (otherwise, with the empty-effective-resources
	// rule, the existing operator would be locked out of everything). The JSON
	// file is NOT deleted; the import is skipped silently once the DB has users.
	if err := importLegacyUsersFile(userStore, cfg.UsersFile); err != nil {
		fmt.Fprintf(os.Stderr, "arc-lore-auth: legacy user import: %v\n", err)
		os.Exit(1)
	}

	srv, err := newAuthServer(cfg, priv, kid, jwkSet)
	if err != nil {
		fmt.Fprintf(os.Stderr, "arc-lore-auth: server init: %v\n", err)
		os.Exit(1)
	}

	// (N4) Load/generate BOTH keys (RSA JWT signing key above, TLS cert here)
	// BEFORE starting either listener so a TLS failure aborts cleanly.
	tlsCert, generated, certPath, err := loadOrGenerateTLSCert(cfg.TLSCertPath, cfg.TLSKeyPath, cfg.TLSSAN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "arc-lore-auth: TLS: %v\n", err)
		os.Exit(1)
	}

	// (S4) NextProtos MUST include "h2" or the gRPC TLS handshake (client uses
	// assume_http2) silently fails.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
	}
	grpcCreds := grpc.Creds(credentials.NewTLS(tlsConfig))

	// Construct ONE shared session store and inject the SAME pointer into the
	// gRPC server now and the HTTP /login handlers (Step 3). A per-file package
	// var would split-brain the handshake (gRPC writes one map, web reads
	// another) — that is the #1 failure mode this wiring avoids.
	sessionStore := NewSessionStore(time.Duration(cfg.SessionTTL) * time.Second)
	sessionStore.StartEvictionLoop(make(chan struct{})) // process-lifetime sweep
	grpcSrv := newGRPCServer(cfg, priv, kid, sessionStore, userStore)
	// RebacApi (repo registry) shares the same listener, cfg, signing key, and
	// store — lore-server drives it on RepositoryCreate/Delete via the one
	// auth_url.
	rebacSrv := newRebacServer(cfg, priv, userStore)

	// Build the web (login + admin) handler set over the SAME session + user
	// store pointers the gRPC server uses. attachWeb registers /login, /admin,
	// and /admin/users* onto the shared authServer so registerRoutes wires them
	// onto the one mux alongside /jwks.json.
	srv.attachWeb(sessionStore, userStore)

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	fmt.Fprintf(os.Stdout, "arc-lore-auth listening:\n")
	fmt.Fprintf(os.Stdout, "  HTTP  : http://%s  (JWKS + web login/admin)\n", cfg.WebListenAddr)
	fmt.Fprintf(os.Stdout, "  JWKS  : http://%s/jwks.json\n", cfg.WebListenAddr)
	fmt.Fprintf(os.Stdout, "  login : http://%s/login  (interactive; reach via web_base_url)\n", cfg.WebListenAddr)
	if cfg.AdminSecret != "" {
		fmt.Fprintf(os.Stdout, "  admin : http://%s/admin  (admin_secret required)\n", cfg.WebListenAddr)
		if !strings.HasPrefix(cfg.AdminSecret, "$argon2id$") {
			log.Printf("WARNING: admin_secret in config is plaintext; generate a hash with `arc-lore-auth hash-secret` and replace it for at-rest protection")
		}
	} else {
		fmt.Fprintf(os.Stdout, "  admin : DISABLED (admin_secret unset — /admin returns 503)\n")
	}
	fmt.Fprintf(os.Stdout, "  gRPC  : https://%s  (epic_urc.UrcAuthApi, TLS/h2)\n", cfg.GRPCListenAddr)
	fmt.Fprintf(os.Stdout, "  kid   : %s\n", kid)
	fmt.Fprintf(os.Stdout, "  issuer: %s\n", cfg.Issuer)
	fmt.Fprintf(os.Stdout, "  aud   : %s\n", cfg.Audience)
	fmt.Fprintf(os.Stdout, "  TLS   : cert=%s san=%q\n", certPath, cfg.TLSSAN)
	if generated {
		fmt.Fprintf(os.Stdout, "  install the gRPC cert into each editor host's Trusted Root store:\n")
		fmt.Fprintf(os.Stdout, "    certutil -addstore Root %s\n", certPath)
	}
	// When web TLS is NOT configured, warn if the web/JWKS listener binds to a
	// non-loopback address — credentials/session tokens would travel in cleartext.
	// 0.0.0.0, ::, and an empty host count as non-loopback; only 127.0.0.1/::1/
	// localhost are treated as loopback.
	if cfg.WebTLSCertPath == "" {
		host, _, splitErr := net.SplitHostPort(cfg.WebListenAddr)
		if splitErr != nil {
			host = cfg.WebListenAddr
		}
		ip := net.ParseIP(host)
		isLoopback := host == "localhost" || (ip != nil && ip.IsLoopback())
		if !isLoopback {
			log.Printf("WARNING: web/JWKS listener bound to %s over plaintext HTTP — credentials and session tokens are sent unencrypted. Set web_tls_cert_path + web_tls_key_path, or bind to 127.0.0.1, before exposing this beyond a trusted LAN.", cfg.WebListenAddr)
		}
	}

	// Run the gRPC listener alongside the HTTP JWKS listener; both must come up.
	errCh := make(chan error, 2)
	go func() {
		errCh <- fmt.Errorf("gRPC listener: %w", serveGRPC(cfg.GRPCListenAddr, grpcCreds, grpcSrv, rebacSrv))
	}()
	go func() {
		errCh <- fmt.Errorf("HTTP listener: %w", serveWeb(cfg, mux))
	}()

	// Either listener exiting is fatal.
	if err := <-errCh; err != nil {
		fmt.Fprintf(os.Stderr, "arc-lore-auth: %v\n", err)
		os.Exit(1)
	}
}

// serveWeb starts the web/JWKS HTTP listener. TLS is opt-in: when BOTH
// web_tls_cert_path and web_tls_key_path are set the listener serves HTTPS;
// when neither is set (the default) it serves plaintext HTTP — the deliberate
// interop contract with lore-server + editor clients. Supplying exactly one of
// the pair is a misconfiguration and fails fast.
func serveWeb(cfg *Config, mux *http.ServeMux) error {
	certSet := cfg.WebTLSCertPath != ""
	keySet := cfg.WebTLSKeyPath != ""
	switch {
	case certSet && keySet:
		return http.ListenAndServeTLS(cfg.WebListenAddr, cfg.WebTLSCertPath, cfg.WebTLSKeyPath, mux)
	case certSet != keySet:
		return fmt.Errorf("web TLS cert/key are half-present: supply BOTH web_tls_cert_path and web_tls_key_path, or neither")
	default:
		return http.ListenAndServe(cfg.WebListenAddr, mux)
	}
}

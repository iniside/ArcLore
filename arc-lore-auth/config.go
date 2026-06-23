package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config is the full configuration loaded from config.toml (and overridden by
// flags / env vars).
type Config struct {
	// HTTP daemon (JWKS endpoint + HTTP token minting)
	ListenAddr string `toml:"listen_addr"`

	// gRPC daemon (UrcAuthApi exchange over TLS)
	GRPCListenAddr string `toml:"grpc_listen_addr"`
	TLSCertPath    string `toml:"tls_cert_path"`
	TLSKeyPath     string `toml:"tls_key_path"`
	TLSSAN         string `toml:"tls_san"` // SAN for the self-signed cert; MUST equal the auth_url host

	// JWT claims
	Issuer   string `toml:"issuer"`
	Audience string `toml:"audience"` // REQUIRED: must be the lore-server host domain
	Env      string `toml:"env"`
	IDP      string `toml:"idp"`

	// Key storage
	KeyPath string `toml:"key_path"`

	// User store (username + argon2id password hash, text file).
	// Retained only for the one-shot legacy import into the SQLite store; the
	// live store is DBPath below.
	UsersFile string `toml:"users_file"`

	// DBPath is the SQLite database file backing users/resources/grants.
	DBPath string `toml:"db_path"`

	// WebListenAddr is the bind address for the HTTP listener that serves the
	// JWKS endpoint AND the interactive login + user-admin web pages. It MUST be
	// externally reachable (default "0.0.0.0:8080") so the artist's browser on
	// another machine can reach login_url. Replaces the localhost-only
	// listen_addr for the web/JWKS listener.
	WebListenAddr string `toml:"web_listen_addr"`

	// Optional TLS for the web/JWKS HTTP listener. Both must be supplied together
	// to switch the listener to HTTPS; empty (the default) = plaintext HTTP, which
	// is the deliberate interop contract with lore-server + editor clients.
	WebTLSCertPath string `toml:"web_tls_cert_path"` // optional; empty = plaintext HTTP (default)
	WebTLSKeyPath  string `toml:"web_tls_key_path"`  // optional; must be paired with web_tls_cert_path

	// AdminSecret gates the /admin user-management pages. The operator pastes it
	// into an unlock form; on match a short-lived signed cookie is set. If empty,
	// /admin fails CLOSED (503 "admin disabled") — never served open.
	AdminSecret string `toml:"admin_secret"`

	// Interactive browser login.
	// WebBaseURL is the EXTERNALLY-reachable HTTP base used to build the
	// browser login_url (e.g. "http://authhost.lan:8080"). No sensible default —
	// REQUIRED for interactive login; StartAuthSession fails closed if unset.
	WebBaseURL string `toml:"web_base_url"`
	// SessionTTL is the interactive-login session lifetime in seconds (default
	// 600). Longer than the 150s client poll window so the human has time to type
	// credentials; TTL==poll-window would evict mid-login.
	SessionTTL int `toml:"session_ttl"`

	// Token TTL (Go duration string, e.g. "168h")
	TokenTTL string `toml:"token_ttl"`

	// Optional allowlist
	AllowedUsers []string `toml:"allowed_users"`

	// Per-repo resource grants included in every token.
	// Defaults to [{"resource_id":"urc-*","permission":["read","write"]}].
	DefaultResources []ResourceEntry `toml:"default_resources"`
}

func defaultConfig() *Config {
	home, _ := os.UserHomeDir()
	keyDir := filepath.Join(home, ".arc-lore-auth")
	return &Config{
		ListenAddr:     "127.0.0.1:8080",
		GRPCListenAddr: "0.0.0.0:8443",
		TLSCertPath:    "./arc-lore-auth-tls.crt",
		TLSKeyPath:     "./arc-lore-auth-tls.key",
		TLSSAN:         "", // operator MUST set this to the auth_url host (matches the cert SAN)
		Issuer:         "arc-lore-auth",
		Audience:       "", // no sensible default; operator MUST set this
		Env:            "local",
		IDP:            "arc-lore-auth",
		KeyPath:        filepath.Join(keyDir, "arc-lore-auth.key"),
		UsersFile:      "./arc-lore-users.json",
		DBPath:         "./arc-lore.db",
		WebBaseURL:     "", // operator MUST set this for interactive login (no default)
		WebListenAddr:  "0.0.0.0:8080",
		AdminSecret:    "", // empty → /admin fails closed (503)
		SessionTTL:     600,
		TokenTTL:       "168h",
	}
}

func loadConfig(path string) (*Config, error) {
	cfg := defaultConfig()
	if path == "" {
		return cfg, nil
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return cfg, nil // config file is optional
	}
	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	return cfg, nil
}

// ── legacy users.json one-shot import ─────────────────────────────────────────

// legacyUsersFile is the on-disk JSON shape of the retired UserStore, kept here
// solely to parse a pre-existing users.json during the one-shot import.
type legacyUsersFile struct {
	Users []struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Argon2id    string `json:"argon2id"`
		Created     int64  `json:"created"`
		Updated     int64  `json:"updated"`
	} `json:"users"`
}

// importLegacyUsersFile imports a pre-existing users.json into the SQLite store
// exactly once: it is a no-op if the file is absent or the DB already has users.
// Argon2 hashes and timestamps are preserved; the FIRST imported user is marked
// admin so the existing operator is not locked out. The JSON file is left on disk.
func importLegacyUsersFile(store *Store, usersFile string) error {
	if usersFile == "" {
		return nil
	}
	if _, err := os.Stat(usersFile); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // nothing to import
		}
		return fmt.Errorf("stat %s: %w", usersFile, err)
	}

	hasUsers, err := store.HasUsers()
	if err != nil {
		return err
	}
	if hasUsers {
		return nil // DB already populated — never re-import
	}

	data, err := os.ReadFile(usersFile)
	if err != nil {
		return fmt.Errorf("reading %s: %w", usersFile, err)
	}
	var doc legacyUsersFile
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parsing %s: %w", usersFile, err)
	}
	if len(doc.Users) == 0 {
		return nil
	}

	imported := 0
	firstAdmin := ""
	for _, u := range doc.Users {
		norm := normalizeUsername(u.Username)
		if norm == "" {
			continue // skip junk rows rather than failing the whole import
		}
		// The first SUCCESSFULLY imported user becomes admin (skipping junk rows).
		isAdmin := imported == 0
		if err := store.ImportLegacyUser(norm, u.DisplayName, u.Argon2id, u.Created, u.Updated, isAdmin); err != nil {
			return fmt.Errorf("importing user %s: %w", norm, err)
		}
		imported++
		if isAdmin {
			firstAdmin = norm
		}
	}

	if imported > 0 {
		fmt.Fprintf(os.Stdout, "imported %d user(s) from %s (admin: %s); JSON left on disk\n",
			imported, usersFile, firstAdmin)
	}
	return nil
}

// Package config loads the ArcLoreWeb server configuration from the process
// environment via caarlos0/env.
package config

import (
	"fmt"
	"time"

	"github.com/caarlos0/env/v11"
)

// Config is the full ArcLoreWeb runtime configuration. It is populated from the
// environment with env.ParseAs[Config]() and then validated with Validate.
type Config struct {
	// ListenAddr is the HTTP listen address for the web server.
	ListenAddr string `env:"LISTEN_ADDR" envDefault:":41380"`

	// TLSCertFile and TLSKeyFile optionally enable TLS on the web listener. Both
	// must be set together; when both are empty (the default) the server listens
	// over plaintext HTTP, which is the expected mode on a trusted LAN.
	TLSCertFile string `env:"TLS_CERT_FILE"`
	TLSKeyFile  string `env:"TLS_KEY_FILE"`

	// LoreGRPCAddr is the Lore gRPC endpoint (host:port, optionally with a
	// scheme such as "grpcs://" to request TLS). Required.
	LoreGRPCAddr string `env:"LORE_GRPC_ADDR,required"`

	// LoreHTTPAddr is the base URL of the Lore HTTP blob endpoint
	// (e.g. "http://host:41339"). Required.
	LoreHTTPAddr string `env:"LORE_HTTP_ADDR,required"`

	// LoreTLS is an explicit hint that the Lore endpoint uses TLS. Scheme on
	// LoreGRPCAddr also drives this; kept for deployments that pass a bare
	// host:port.
	LoreTLS bool `env:"LORE_TLS" envDefault:"false"`

	// RequestTimeout is the per-Lore-call deadline applied by the client.
	RequestTimeout time.Duration `env:"LORE_TIMEOUT" envDefault:"30s"`

	// AuthDisabled turns off native UCS login entirely and enables the
	// dev-login bypass (empty token → server auth-disabled). Use this for
	// local Lore servers running with auth disabled.
	AuthDisabled bool `env:"LORE_AUTH_DISABLED" envDefault:"false"`

	// AuthURL optionally overrides the auth service URL that is otherwise
	// discovered via EnvironmentService. Empty = discover from the server.
	AuthURL string `env:"LORE_AUTH_URL"`

	// SessionSecret is reserved for forward-compat but is a no-op: scs uses
	// opaque server-side session tokens and cannot be externally signed.
	// Kept optional so existing deployments that set SESSION_SECRET continue to
	// work without errors, and new deployments need not configure a do-nothing value.
	SessionSecret string `env:"SESSION_SECRET"`

	// DevUserSub is the synthetic user subject written by the dev-login bypass.
	DevUserSub string `env:"DEV_USER_SUB" envDefault:"dev-user"`

	// MgmtAPIAddr is the base URL of arc-lore-auth's HTTP/JSON management API
	// (e.g. "http://authhost:8080"). Required when auth is enabled — it backs
	// the native login form, the first-run setup gate, and the admin screens.
	MgmtAPIAddr string `env:"MGMT_API_ADDR"`

	// CookieSecure sets the session cookie Secure flag. Default false: ArcLoreWeb
	// serves plain HTTP on a LAN, and a Secure cookie is dropped by browsers over
	// HTTP — which silently breaks login (cookie set but never returned). Set
	// true only behind HTTPS / a TLS-terminating proxy.
	CookieSecure bool `env:"SESSION_COOKIE_SECURE" envDefault:"false"`

	// CSRFTrustedOrigins lists extra origins accepted by CrossOriginProtection
	// when ArcLoreWeb runs behind a Host-rewriting reverse proxy (where a
	// same-site POST's Origin no longer matches the internal Host). Empty =
	// same-origin only.
	CSRFTrustedOrigins []string `env:"CSRF_TRUSTED_ORIGINS" envSeparator:","`

	// TrustForwardedFor controls how the web-tier login throttle keys requests.
	// When behind a trusted reverse proxy, set true to key the login throttle on
	// the leftmost X-Forwarded-For IP (the real browser) instead of RemoteAddr
	// (the proxy). Default false (LAN-direct; XFF is spoofable so only trust it
	// behind a known proxy).
	TrustForwardedFor bool `env:"TRUST_FORWARDED_FOR" envDefault:"false"`
}

// Load parses the configuration from the environment and validates it.
func Load() (Config, error) {
	cfg, err := env.ParseAs[Config]()
	if err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate enforces the cross-field invariants that env tags cannot express.
// Native login + first-run setup talk to the management API, so MGMT_API_ADDR is
// required whenever auth is enabled. Under auth-disabled (dev bypass) it is
// unused and may be empty.
func (c Config) Validate() error {
	if !c.AuthDisabled && c.MgmtAPIAddr == "" {
		return fmt.Errorf("config: MGMT_API_ADDR is required when auth is enabled (LORE_AUTH_DISABLED=false)")
	}
	return nil
}

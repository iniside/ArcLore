package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// authServer holds the shared state for HTTP handlers.
type authServer struct {
	cfg     *Config
	priv    *rsa.PrivateKey
	kid     string
	jwkSet  jwk.Set
	jwkJSON []byte // pre-serialised; never changes during a run

	// Web (login + admin) state, wired by attachWeb in main.go. These pointers
	// are the SAME instances the gRPC server holds — the web /login POST and the
	// gRPC Get/StartAuthSession must share one session map (split-brain = the
	// handshake never closes), and /login + /admin share one user store.
	sessions   *SessionStore
	users      StoreInterface
	svc        *authService  // single mint site (effectiveResources→mint→expiry)
	hashSem    chan struct{} // argon2 DoS cap: bounds concurrent IDKey calls
	loginRL    *rateLimiter  // per-IP token bucket for POST /login
	adminRL    *rateLimiter  // per-IP token bucket for POST /admin*
	pwChangeRL *rateLimiter  // per-user token bucket for POST /api/me/password
	adminAuth  *adminGate    // signed short-lived admin-unlock cookie
}

func newAuthServer(cfg *Config, priv *rsa.PrivateKey, kid string, set jwk.Set) (*authServer, error) {
	raw, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("serialising JWKS: %w", err)
	}
	return &authServer{cfg: cfg, priv: priv, kid: kid, jwkSet: set, jwkJSON: raw}, nil
}

func (s *authServer) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/jwks.json", s.handleJWKS)
	mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("/healthz", s.handleHealthz)

	// Interactive login + user admin (defined in web.go). Registered on the SAME
	// mux/listener as JWKS so the artist's browser reaches them via web_base_url.
	if s.sessions != nil {
		mux.HandleFunc("/login", s.handleLogin)
		mux.HandleFunc("/admin", s.handleAdmin)
		mux.HandleFunc("/admin/unlock", s.handleAdminUnlock)
		mux.HandleFunc("/admin/users", s.handleAdminUserCreate)
		mux.HandleFunc("/admin/users/setpw", s.handleAdminUserSetPassword)
		mux.HandleFunc("/admin/users/delete", s.handleAdminUserDelete)

		// JSON management API (defined in api.go). Mounted inside the same
		// sessions!=nil block because it needs the web state attachWeb wires
		// (s.users, s.hashSem, s.loginRL).
		s.registerAPIRoutes(mux)
	}
}

// handleJWKS serves the public key set so the lore-server can verify tokens.
// Plain HTTP is fine — the server fetches the URL verbatim per the config.
func (s *authServer) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.jwkJSON)
}

// handleHealthz is a liveness probe.
func (s *authServer) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

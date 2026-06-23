// Package auth provides OIDC login, server-side sessions, a dev-login bypass,
// and the RequireAuth middleware that loads the caller's identity into the
// request context for the Lore client to read.
package auth

import (
	"log"
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/alexedwards/scs/v2/memstore"
)

// StoreIdentity renews the session token and writes the identity fields into the
// session. Returns false (after writing a 500) when the token renewal fails. It
// is exported so the native auth-page handlers (in internal/handlers) can store
// an identity without reaching into auth's unexported session keys; the fields
// are passed decomposed so auth stays free of any mgmt import (stdlib + scs
// only). userSub/name/token map to the session's identity columns; expiresAt is
// Unix seconds; isAdmin gates the admin nav and RequireAdmin.
func StoreIdentity(sessions *scs.SessionManager, w http.ResponseWriter, r *http.Request, userSub, name, token string, expiresAt int64, isAdmin bool) bool {
	if err := sessions.RenewToken(r.Context()); err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return false
	}
	sessions.Put(r.Context(), sessionKeyUserSub, userSub)
	sessions.Put(r.Context(), sessionKeyUserName, name)
	sessions.Put(r.Context(), sessionKeyIdentityToken, token)
	sessions.Put(r.Context(), sessionKeyTokenExpiry, expiresAt)
	sessions.Put(r.Context(), sessionKeyIsAdmin, isAdmin)
	return true
}

// Session keys. The Lore interceptor ultimately consumes identityToken
// (forwarded as the Authorization Bearer) and userSub (the caller identity).
const (
	sessionKeyUserSub       = "user_sub"
	sessionKeyUserName      = "user_name"
	sessionKeyIdentityToken = "identity_token"
	sessionKeyTokenExpiry   = "token_expiry"
	sessionKeyIsAdmin       = "is_admin"
)

// NewSessionManager builds the scs session manager backed by an in-memory
// store. Cookies are HttpOnly + SameSite=Lax with an 8h lifetime.
//
// secure controls the cookie Secure flag. It MUST be false when ArcLoreWeb is
// served over plain HTTP (the default self-host LAN setup) — a Secure cookie is
// never returned by the browser over HTTP, which silently breaks login (the
// session cookie is set but never sent back, looping back to the login page).
// Set it true only when ArcLoreWeb sits behind HTTPS / a TLS-terminating proxy.
//
// secret is reserved for forward-compat but is a no-op: scs v2 uses opaque
// server-side session tokens and cannot be externally signed by a caller-supplied
// secret. A warning is logged when a non-empty secret is provided so operators
// are not misled into thinking it adds protection.
func NewSessionManager(secure bool, secret string) *scs.SessionManager {
	if secret != "" {
		log.Printf("auth: SESSION_SECRET is reserved/no-op — scs uses opaque server-side session tokens")
	}
	sm := scs.New()
	sm.Store = memstore.New()
	sm.Lifetime = 8 * time.Hour
	sm.Cookie.Secure = secure
	sm.Cookie.HttpOnly = true
	sm.Cookie.SameSite = http.SameSiteLaxMode
	return sm
}

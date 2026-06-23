// Package auth provides OIDC login, server-side sessions, a dev-login bypass,
// and the RequireAuth middleware that loads the caller's identity into the
// request context for the Lore client to read.
package auth

import (
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/alexedwards/scs/v2/memstore"
)

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
func NewSessionManager(secure bool) *scs.SessionManager {
	sm := scs.New()
	sm.Store = memstore.New()
	sm.Lifetime = 8 * time.Hour
	sm.Cookie.Secure = secure
	sm.Cookie.HttpOnly = true
	sm.Cookie.SameSite = http.SameSiteLaxMode
	return sm
}

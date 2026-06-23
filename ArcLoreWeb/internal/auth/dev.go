package auth

import (
	"net/http"

	"github.com/alexedwards/scs/v2"
)

// DevLoginHandler is wired at /auth/login when auth is disabled. It writes a
// synthetic user_sub and an EMPTY identity_token (so the Lore interceptor sends
// no Bearer, matching a server running auth-disabled), rotates the session
// token, and redirects home.
func DevLoginHandler(sessions *scs.SessionManager, devUserSub string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := sessions.RenewToken(r.Context()); err != nil {
			http.Error(w, "session error", http.StatusInternalServerError)
			return
		}
		sessions.Put(r.Context(), sessionKeyUserSub, devUserSub)
		sessions.Put(r.Context(), sessionKeyIdentityToken, "")
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

package auth

import (
	"context"
	"net/http"

	"github.com/alexedwards/scs/v2"
)

// Identity is the authenticated caller resolved from the session and carried in
// the request context. Token is the stored identity (authn) token forwarded to
// Lore as the Authorization Bearer; it is EMPTY under the dev/auth-disabled
// path, which the Lore interceptor treats as "send no Bearer".
type Identity struct {
	Sub     string
	Token   string
	IsAdmin bool
}

// identityKey is an unexported context key type so no other package can collide
// with or read this value.
type identityKey struct{}

// RequireAuth returns middleware that requires a logged-in session. When no
// user_sub is present it redirects to /auth/login; otherwise it loads the
// Identity into the request context (retrievable via IdentityFromContext).
func RequireAuth(sessions *scs.SessionManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sub := sessions.GetString(r.Context(), sessionKeyUserSub)
			if sub == "" {
				http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
				return
			}
			identity := Identity{
				Sub:     sub,
				Token:   sessions.GetString(r.Context(), sessionKeyIdentityToken),
				IsAdmin: sessions.GetBool(r.Context(), sessionKeyIsAdmin),
			}
			ctx := context.WithValue(r.Context(), identityKey{}, identity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAdmin returns middleware that requires the logged-in session to be an
// admin. It must be chained AFTER RequireAuth (it reads is_admin from the
// session, not the context, so it is self-contained). A non-admin (or
// unauthenticated) request gets a 403.
func RequireAdmin(sessions *scs.SessionManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !sessions.GetBool(r.Context(), sessionKeyIsAdmin) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(r.Context()))
		})
	}
}

// IdentityFromContext returns the Identity loaded by RequireAuth. The second
// return value is false when no authenticated identity is attached.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(identityKey{}).(Identity)
	return identity, ok
}

// ContextWithIdentity returns a child context carrying id under the unexported
// identity key, so callers outside this package (e.g. handler tests) can inject
// an Identity that IdentityFromContext will then resolve — without exposing the
// key itself.
func ContextWithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// Package handlers holds the chi HTTP handlers for the browse UI. Each handler
// resolves the per-request identity, stamps it onto the context via
// lore.WithLoreCall, then drives the lore.Client read methods and renders templ
// components.
package handlers

import (
	"context"
	"errors"
	"log"
	"net/http"

	"github.com/alexedwards/scs/v2"

	"arcloreweb/internal/auth"
	"arcloreweb/internal/lore"
)

// zeroRepo is the all-zero repository id used for auth-service-only calls
// (repo list, repo-by-name lookup) — the interceptor omits the -bin repo
// headers when the scope is zero.
var zeroRepo [16]byte

// Handler bundles the dependencies the browse handlers need: the typed Lore
// client and the session manager (for identity lookup).
type Handler struct {
	Lore     *lore.Client
	Sessions *scs.SessionManager

	// LoreHost is the bare "host:port" of the lore gRPC server (scheme stripped),
	// surfaced on the repo page so the clone/wire helper can build clean
	// "lore://host/name" commands.
	LoreHost string
}

// New constructs a Handler.
func New(loreClient *lore.Client, sessions *scs.SessionManager) *Handler {
	return &Handler{Lore: loreClient, Sessions: sessions, LoreHost: loreClient.GRPCHost()}
}

// identityToken returns the authorization token for the request. Under
// auth-disabled / dev-bypass the token is empty, which the Lore interceptor
// treats as "send no Bearer" — that is the v1 target mode.
func identityToken(r *http.Request) string {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		return ""
	}
	return identity.Token
}

// bearer returns the single Bearer token presented on every lore-server call:
// the wildcard-resource ("urc-*") authorization token exchanged from the
// request's identity token (cached by ResourceAuthzToken). The RAW identity
// token is NOT lore-signed (its kid is absent from lore-server's JWKS), so it
// fails RepositoryService's authn; only an EXCHANGED token passes. The wildcard
// token both passes that authn AND satisfies the per-repo verify_authorization
// check (lore-server jwt.rs is_wildcard_resource) for any repository.
//
// In auth-disabled mode the identity token is empty, ResourceAuthzToken returns
// "" with no exchange, and the empty Bearer is sent — exactly as before.
func (h *Handler) bearer(r *http.Request) (string, error) {
	return h.Lore.ResourceAuthzToken(r.Context(), identityToken(r), lore.WildcardResource)
}

// baseCtx returns a context for repo-LESS calls (ListRepositories,
// GetRepositoryByName): the wildcard bearer with the zero repo scope, so the
// interceptor omits the -bin repo headers. A non-nil error means the wildcard
// token exchange failed (not authorized, or the auth service is unreachable);
// handlers render a not-authorized page rather than a 502.
func (h *Handler) baseCtx(r *http.Request) (context.Context, error) {
	tok, err := h.bearer(r)
	if err != nil {
		return nil, err
	}
	return lore.WithLoreCall(r.Context(), tok, zeroRepo), nil
}

// repoCtx returns a context for repo-SCOPED calls (ThinClient/Revision/Lock +
// the blob endpoint). It carries the SAME wildcard bearer as baseCtx — the
// wildcard satisfies lore-server's per-repo verify_authorization — while the
// real repoID drives the -bin headers so the server resolves the right repo.
//
// In auth-disabled mode the identity token is empty, the bearer is "", and
// WithLoreCall stamps an empty token — so no Bearer header is sent, exactly as
// before. A non-nil error means the wildcard token exchange failed; handlers
// render a Forbidden page rather than a 502.
func (h *Handler) repoCtx(r *http.Request, repoID [16]byte) (context.Context, error) {
	tok, err := h.bearer(r)
	if err != nil {
		return nil, err
	}
	return lore.WithLoreCall(r.Context(), tok, repoID), nil
}

// forbiddenDetail maps an auth-exchange error to a safe browser-facing detail
// string and logs the raw error server-side so operators retain diagnostics.
// It returns:
//   - a transport/TLS actionable hint when err wraps ErrAuthServerUnreachable
//   - a generic access-denial string for any other error
//
// The raw gRPC/internal error text is NEVER returned to the browser.
func forbiddenDetail(err error) string {
	log.Printf("auth exchange error: %v", err)
	if errors.Is(err, lore.ErrAuthServerUnreachable) {
		return "The auth server is unreachable or its TLS certificate is not trusted by this host. " +
			"Install the auth server's certificate in this host's trust store (see INSTALL.md)."
	}
	return "You don't have access to this repository."
}

package lore

import "context"

// callAuth carries the per-call authorization that the gRPC interceptors and
// the HTTP blob fetcher inject into outgoing requests. It is stored on the
// request context by the chi handler (via WithLoreCall) and read back out by
// the unary/stream interceptors and FetchContent.
//
//   - token is the opaque authorization-token string. Empty means
//     auth-disabled (no Authorization header is sent).
//   - repoID is the 16-byte repository id (== Partition). The zero value means
//     "no repository scope" (auth-service-only calls); the two -bin headers are
//     omitted in that case, mirroring the server's repository.is_zero().
type callAuth struct {
	token  string
	repoID [16]byte
}

// callAuthKey is an unexported context key type so no other package can collide
// with or read this value.
type callAuthKey struct{}

// WithLoreCall returns a child context carrying the authorization token and the
// 16-byte repository id for a single Lore call. Handlers call this before
// invoking any Client read method or FetchContent.
func WithLoreCall(ctx context.Context, token string, repoID [16]byte) context.Context {
	return context.WithValue(ctx, callAuthKey{}, callAuth{token: token, repoID: repoID})
}

// callAuthFromContext extracts the per-call auth set by WithLoreCall. The
// second return value is false when no auth was attached (treated as
// auth-disabled, zero repo scope).
func callAuthFromContext(ctx context.Context) (callAuth, bool) {
	auth, ok := ctx.Value(callAuthKey{}).(callAuth)
	return auth, ok
}

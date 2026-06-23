package lore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	gen "arcloreweb/gen"
)

// ErrAuthServerUnreachable is returned by ExchangeResource / ResourceAuthzToken
// when the auth server cannot be reached or its TLS certificate is not trusted
// by this host's certificate pool. The operator should install the auth
// server's certificate in the host trust store.
var ErrAuthServerUnreachable = errors.New("auth server unreachable or its TLS certificate is not trusted")

// ErrAuthDenied is returned when the auth server actively rejects the token
// exchange (PermissionDenied or Unauthenticated). The identity token is valid
// in form but the caller lacks the required grants.
var ErrAuthDenied = errors.New("not authorized: token exchange was denied")

// ClassifyExchangeErr inspects an error returned from ExchangeResource and
// returns either ErrAuthServerUnreachable (TLS/transport failures), ErrAuthDenied
// (explicit server denial), or the original error when classification is
// ambiguous. The original is always wrapped so errors.Is chaining works and
// server-side log lines retain the detail.
func ClassifyExchangeErr(err error) error {
	if err == nil {
		return nil
	}

	// x509 certificate chain errors — the server cert is not trusted.
	certVerifyErr := &tls.CertificateVerificationError{}
	if errors.As(err, &certVerifyErr) {
		return fmt.Errorf("%w: %w", ErrAuthServerUnreachable, err)
	}
	unknownAuthErr := x509.UnknownAuthorityError{}
	if errors.As(err, &unknownAuthErr) {
		return fmt.Errorf("%w: %w", ErrAuthServerUnreachable, err)
	}
	certInvalidErr := x509.CertificateInvalidError{}
	if errors.As(err, &certInvalidErr) {
		return fmt.Errorf("%w: %w", ErrAuthServerUnreachable, err)
	}

	// gRPC status codes.
	code := status.Code(err)
	switch code {
	case codes.Unavailable:
		// connection refused, handshake failure, or server not up
		return fmt.Errorf("%w: %w", ErrAuthServerUnreachable, err)
	case codes.PermissionDenied, codes.Unauthenticated:
		return fmt.Errorf("%w: %w", ErrAuthDenied, err)
	}

	return err
}

// authDebug reports whether LORE_AUTH_DEBUG is set, enabling one-line summaries
// (kid/iss/aud/resources, never the raw token) of the identity and exchanged
// tokens — used to diagnose server-side KeyNotFound / audience rejections.
func authDebug() bool {
	return os.Getenv("LORE_AUTH_DEBUG") != ""
}

// expirySkew is the safety margin subtracted from a cached authz token's
// expiry: a token is treated as expired (and re-exchanged) once it is within
// this window of its real expiry, so we never present a token that lapses
// mid-request.
const expirySkew = 60 * time.Second

// WildcardResource is the lore-server wildcard resource id. The "urc-*" arg
// passed to ExchangeResource is ADVISORY: post-Phase-1 the auth service mints
// strictly from the caller's effective grants, so the returned token carries
// "urc-*" only for an admin (the admin effective set always includes the
// wildcard); a non-admin's exchanged token instead carries the concrete
// "urc-{repoid}" entries it has grants for, never "urc-*".
//
// For an ADMIN, a token exchanged for this resource is recognised by the
// server's authorization check for ANY repository (lore-server jwt.rs
// is_wildcard_resource / verify_authorization), so a single wildcard-scoped
// authz token serves as the Bearer for every lore-server call — both repo-less
// RepositoryService calls (which only need a lore-signed token to pass authn)
// and repo-scoped calls (where the wildcard satisfies the per-repo
// verify_authorization while the real repoID still travels in the -bin headers).
// A non-admin is authorised per-repo by the concrete grant entries its
// exchanged token carries instead.
const WildcardResource = "urc-*"

// authzEntry is one cached authorization token plus its absolute expiry in
// epoch-milliseconds (UrcAuthApi UserToken.expires_at).
type authzEntry struct {
	token string
	expMs int64
}

// authURLToTarget converts an Environment auth_url into a gRPC dial target.
//
// Per the Lore transport rules (lore-transport/src/auth/mod.rs:46-49) both
// "ucs-auth://host" and "https://host" denote a TLS gRPC endpoint at host. We
// strip the "scheme://" prefix; the remainder is "host[:port]". When no port
// is present we default to 443 (TLS).
func authURLToTarget(authURL string) (string, error) {
	trimmed := strings.TrimSpace(authURL)
	if trimmed == "" {
		return "", fmt.Errorf("lore: empty auth url")
	}

	hostPort := trimmed
	if _, after, found := strings.Cut(trimmed, "://"); found {
		hostPort = after
	}
	if hostPort == "" {
		return "", fmt.Errorf("lore: auth url %q has no host", authURL)
	}

	// A bare host (no ":port") defaults to the TLS port. A bracketed IPv6
	// literal without a port ("[::1]") also gets the default appended.
	if !strings.Contains(hostPort, ":") || strings.HasSuffix(hostPort, "]") {
		hostPort += ":443"
	}
	return hostPort, nil
}

// resolveAuthURL returns the auth service URL, honouring an explicit override
// (authURLOverride, populated from config) and otherwise discovering it once
// via GetEnvironment and caching the result. Guarded by authMu.
func (c *Client) resolveAuthURL(ctx context.Context) (string, error) {
	c.authMu.Lock()
	defer c.authMu.Unlock()

	if c.authURLOverride != "" {
		return c.authURLOverride, nil
	}
	if c.authURL != "" {
		return c.authURL, nil
	}

	discovered, err := c.GetEnvironment(ctx)
	if err != nil {
		return "", err
	}
	if discovered == "" {
		return "", fmt.Errorf("lore: server published no auth url")
	}
	c.authURL = discovered
	return discovered, nil
}

// authClientForURL lazily dials the auth host once and caches the
// UrcAuthApiClient plus its conn on the Client. The auth conn uses plain TLS
// credentials WITHOUT the lore -bin interceptors: the auth service wants only
// the Bearer identity, never repository headers. Guarded by authMu.
func (c *Client) authClientForURL(ctx context.Context) (gen.UrcAuthApiClient, error) {
	authURL, err := c.resolveAuthURL(ctx)
	if err != nil {
		return nil, err
	}

	c.authMu.Lock()
	defer c.authMu.Unlock()

	if c.authClient != nil {
		return c.authClient, nil
	}

	target, err := authURLToTarget(authURL)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient(
		target,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    30 * time.Second,
			Timeout: 20 * time.Second,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("lore: dial auth %q: %w", target, err)
	}

	c.authConn = conn
	c.authClient = gen.NewUrcAuthApiClient(conn)
	return c.authClient, nil
}

// ExchangeResource trades an identity (authn) token for an authorization
// (authz) token scoped to a single resource string via
// UrcAuthApi.ExchangeUserTokenForMultiresourceToken.
//
// The resource is passed verbatim — e.g. WildcardResource ("urc-*") for the
// single wildcard bearer, or "urc-"+IDToHex(repoID) for a per-repo token. The
// identity token is attached as "authorization: Bearer <identityToken>"
// metadata directly on the outgoing context — the auth conn carries no lore
// interceptor, so we must set the header ourselves here. Returns the authz JWT
// plus its epoch-ms expiry (UserToken.expires_at).
func (c *Client) ExchangeResource(
	ctx context.Context,
	identityToken string,
	resource string,
) (authz string, expMs int64, err error) {
	authClient, err := c.authClientForURL(ctx)
	if err != nil {
		return "", 0, err
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	if authDebug() {
		authURL, _ := c.resolveAuthURL(ctx)
		log.Printf("auth-debug: exchange resource=%q auth_url=%q\n  identity token: %s",
			resource, authURL, jwtSummary(identityToken))
	}

	ctx = metadata.AppendToOutgoingContext(ctx, mdAuthorization, "Bearer "+identityToken)

	resp, err := authClient.ExchangeUserTokenForMultiresourceToken(
		ctx,
		&gen.ExchangeUserTokenForMultiresourceTokenRequest{
			ResourceId: []string{resource},
		},
	)
	if err != nil {
		classified := ClassifyExchangeErr(err)
		return "", 0, fmt.Errorf("lore: ExchangeUserTokenForMultiresourceToken(resource=%s): %w", resource, classified)
	}

	token := resp.GetToken()
	if token == nil || token.GetUserToken() == "" {
		return "", 0, fmt.Errorf("lore: exchange for resource %s returned no token", resource)
	}
	if authDebug() {
		log.Printf("auth-debug: exchanged token for resource=%q:\n  %s", resource, jwtSummary(token.GetUserToken()))
	}
	return token.GetUserToken(), token.GetExpiresAt(), nil
}

// ResourceAuthzToken returns an authorization token scoped to the given
// resource string, exchanging the identity token when needed and caching the
// result per resource until (expiry − expirySkew).
//
//   - An empty identityToken is the auth-disabled passthrough: no exchange is
//     performed and "" is returned, so handlers send no Bearer header.
//   - A cached token still outside the skew window is returned without a
//     re-exchange; otherwise the injectable exchangeFn (default
//     ExchangeResource) runs and the result is cached.
func (c *Client) ResourceAuthzToken(
	ctx context.Context,
	identityToken string,
	resource string,
) (string, error) {
	if identityToken == "" {
		return "", nil
	}

	nowMs := c.nowMs()
	skewMs := expirySkew.Milliseconds()

	c.authzMu.Lock()
	cached, ok := c.authzCache[resource]
	c.authzMu.Unlock()
	if ok && nowMs < cached.expMs-skewMs {
		return cached.token, nil
	}

	token, expMs, err := c.exchangeFn(ctx, identityToken, resource)
	if err != nil {
		return "", err
	}

	c.authzMu.Lock()
	if c.authzCache == nil {
		c.authzCache = make(map[string]authzEntry)
	}
	c.authzCache[resource] = authzEntry{token: token, expMs: expMs}
	c.authzMu.Unlock()

	return token, nil
}

// AuthzToken returns a repository-scoped authorization token for repoID. It is
// a thin wrapper over ResourceAuthzToken with the "urc-"+hex(repoID) resource,
// kept for any caller still asking for a per-repo token. Handlers use the
// wildcard bearer (ResourceAuthzToken with WildcardResource) instead.
func (c *Client) AuthzToken(
	ctx context.Context,
	identityToken string,
	repoID [16]byte,
) (string, error) {
	return c.ResourceAuthzToken(ctx, identityToken, "urc-"+IDToHex(repoID))
}

// nowMs returns the current time in epoch-milliseconds. It indirects through
// the Client's clock field so tests can inject a fake clock; production leaves
// clock nil and falls back to time.Now.
func (c *Client) nowMs() int64 {
	if c.clock != nil {
		return c.clock().UnixMilli()
	}
	return time.Now().UnixMilli()
}

// SetAuthURL overrides the auth service URL, bypassing GetEnvironment
// discovery. A later config step wires LORE_AUTH_URL into this. Calling it
// after the auth conn has been dialed has no effect on the existing conn.
func (c *Client) SetAuthURL(authURL string) {
	c.authMu.Lock()
	c.authURLOverride = authURL
	c.authMu.Unlock()
}

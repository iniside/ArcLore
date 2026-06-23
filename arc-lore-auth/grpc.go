package main

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	epic_urc "arc-lore-auth/gen/epic_urc"
	ucs_auth "arc-lore-auth/gen/ucs_auth"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// authGRPCServer implements epic_urc.UrcAuthApiServer.
//
// Embedding UnimplementedUrcAuthApiServer satisfies the (many) RPCs we do not
// implement: any method not overridden below returns codes.Unimplemented, and
// the embed also future-proofs the struct against added methods.
type authGRPCServer struct {
	epic_urc.UnimplementedUrcAuthApiServer

	cfg  *Config
	priv *rsa.PrivateKey
	kid  string

	// sessions is the SHARED interactive-login session store. The SAME pointer
	// is injected (in main.go) into the HTTP /login handlers (Step 3) — the gRPC
	// Start/GetAuthSession methods and the web POST must read/write one map.
	sessions *SessionStore

	// store is the SQLite identity/grant store. It drives effectiveResources so
	// the minted authz token and LookupUserPermissions carry the caller's real
	// grants (admin → all repos + urc-*; non-admin → exactly their grants).
	store StoreInterface

	// svc is the single mint site, built once from the fields above so the
	// exchange RPC mints through the same path as the web/api transports.
	svc *authService
}

func newGRPCServer(cfg *Config, priv *rsa.PrivateKey, kid string, sessions *SessionStore, store StoreInterface) *authGRPCServer {
	return &authGRPCServer{
		cfg:      cfg,
		priv:     priv,
		kid:      kid,
		sessions: sessions,
		store:    store,
		svc:      &authService{cfg: cfg, priv: priv, kid: kid, store: store},
	}
}

// bearerFromContext extracts the raw JWT from the incoming `authorization`
// metadata, stripping a leading "Bearer " (case-insensitive) prefix.
func bearerFromContext(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "missing request metadata")
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return "", status.Error(codes.Unauthenticated, "missing authorization metadata")
	}
	raw := strings.TrimSpace(vals[0])
	if len(raw) >= 7 && strings.EqualFold(raw[:7], "Bearer ") {
		raw = strings.TrimSpace(raw[7:])
	}
	if raw == "" {
		return "", status.Error(codes.Unauthenticated, "empty bearer token")
	}
	return raw, nil
}

// verifyAuthnToken parses and cryptographically verifies the incoming authn JWT
// against OUR OWN RSA public key.
//
// (B1) This is the security gate: we mint an authz token ONLY for an identity
// proven by a token WE signed. Without signature verification, anyone reaching
// the listener could craft a JWT with sub=victim and obtain a server-signed
// urc-* authz token = full impersonation. Therefore:
//   - require alg RS256 (reject "none" / HMAC confusion);
//   - verify the signature with our public key;
//   - require + validate exp (handled by jwt.WithExpirationRequired);
//   - require iss == our configured issuer.
//
// Single signing key, so we do not branch on kid — any token verifying against
// our key is, by construction, one we issued with the only kid we have.
func verifyAuthnToken(cfg *Config, priv *rsa.PrivateKey, raw string) (*arcLoreClaims, error) {
	keyFunc := func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %q (require RS256)", t.Method.Alg())
		}
		return &priv.PublicKey, nil
	}

	claims := &arcLoreClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(cfg.Issuer),
		jwt.WithAudience(cfg.Audience),
	)

	token, err := parser.ParseWithClaims(raw, claims, keyFunc)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "authn token rejected: %v", err)
	}
	if !token.Valid {
		return nil, status.Error(codes.Unauthenticated, "authn token invalid")
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return nil, status.Error(codes.Unauthenticated, "authn token missing subject")
	}
	return claims, nil
}

// (C2) The former (s *authGRPCServer) verifyAuthnToken method was removed: every
// live UrcAuthApi gate now routes through s.svc.VerifyAuthn (the store-backed
// verifier that also enforces token_version revocation). The pure package-level
// verifyAuthnToken above survives only as the JWT-check half that VerifyAuthn
// composes — nothing should call it directly as an auth gate.

// displayNameFor returns the human-facing name carried in the authz token,
// preferring the verified authn token's name, then preferred_username, then sub.
func displayNameFor(claims *arcLoreClaims) string {
	if strings.TrimSpace(claims.Name) != "" {
		return claims.Name
	}
	if strings.TrimSpace(claims.PreferredUsername) != "" {
		return claims.PreferredUsername
	}
	return claims.Subject
}

// ExchangeUserTokenForMultiresourceToken verifies the caller's authn JWT and
// mints an authz JWT carrying resource grants for the requested repos.
func (s *authGRPCServer) ExchangeUserTokenForMultiresourceToken(ctx context.Context, _ *epic_urc.ExchangeUserTokenForMultiresourceTokenRequest) (*epic_urc.ExchangeUserTokenForMultiresourceTokenResponse, error) {
	raw, err := bearerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// (B1) Never mint from an unverified/echoed token. (C2) VerifyAuthn also
	// rejects a token whose token_version is stale vs the subject's current row
	// (revoked by a password/admin change).
	authn, err := s.svc.VerifyAuthn(raw)
	if err != nil {
		return nil, err
	}

	subject := authn.Subject
	displayName := displayNameFor(authn)

	// Grant-driven minting: the authz token carries the caller's EFFECTIVE grants
	// resolved from the store (admin → all repos + urc-*; non-admin → exactly
	// their grants). An unknown subject fails closed — we never mint urc-* for an
	// identity that does not exist in the store.
	authzJWT, _, expMs, err := s.svc.MintFor(subject, displayName)
	if err != nil {
		// An unknown/ineligible subject fails closed as PermissionDenied (we
		// never mint urc-* for an identity absent from the store). Any other
		// error is an internal mint/resolve failure.
		if errors.Is(err, errUnknownSubject) {
			return nil, status.Errorf(codes.PermissionDenied, "unknown user %q", subject)
		}
		return nil, status.Errorf(codes.Internal, "minting authz token for %q: %v", subject, err)
	}

	return &epic_urc.ExchangeUserTokenForMultiresourceTokenResponse{
		Token: &epic_urc.UserToken{
			UserToken: authzJWT,
			// (B2) ExpiresAt is MILLISECONDS — the client maps it to expires_ms.
			// Seconds would make every authz token read as already expired.
			ExpiresAt: expMs,
			UserId:    subject,
			UserName:  displayName,
		},
	}, nil
}

// authzTokenExpiryUnix re-parses a token WE just minted (verifying against our
// own key) and returns its exp as Unix SECONDS. We re-derive it from the signed
// token rather than recompute time.Now()+ttl so the reported value cannot drift
// from the claim the lore-server will read.
func authzTokenExpiryUnix(priv *rsa.PrivateKey, signed string) (int64, error) {
	claims := &arcLoreClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))
	if _, err := parser.ParseWithClaims(signed, claims, func(*jwt.Token) (interface{}, error) {
		return &priv.PublicKey, nil
	}); err != nil {
		return 0, err
	}
	if claims.ExpiresAt == nil {
		return 0, fmt.Errorf("minted token has no exp claim")
	}
	return claims.ExpiresAt.Unix(), nil
}

// HealthCheck returns a healthy status. The client's verification flow probes
// this, so it must succeed unauthenticated.
func (s *authGRPCServer) HealthCheck(_ context.Context, _ *epic_urc.HealthCheckRequest) (*epic_urc.HealthCheckResponse, error) {
	return &epic_urc.HealthCheckResponse{Status: "healthy"}, nil
}

// GetUserInfo resolves each requested user_id to a display name from the store.
// Unknown ids are silently skipped; only resolvable users are returned. The
// Bearer is still verified (auth gate) even though we look up by explicit ids.
func (s *authGRPCServer) GetUserInfo(ctx context.Context, req *epic_urc.GetUserInfoRequest) (*epic_urc.GetUserInfoResponse, error) {
	raw, err := bearerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if _, err = s.svc.VerifyAuthn(raw); err != nil {
		return nil, err
	}

	out := make([]*epic_urc.UserInfo, 0, len(req.GetUserId()))
	for _, id := range req.GetUserId() {
		u, lookupErr := s.store.GetUser(id)
		if lookupErr != nil {
			// Unknown id — skip; return only the resolvable ones.
			continue
		}
		displayName := u.DisplayName
		if strings.TrimSpace(displayName) == "" {
			displayName = u.Username
		}
		out = append(out, &epic_urc.UserInfo{UserId: u.Username, DisplayName: displayName})
	}
	return &epic_urc.GetUserInfoResponse{UserInfo: out}, nil
}

// GetUserId performs a reverse lookup: find the user whose DisplayName (or
// Username) matches req.UserDisplayName (case-insensitive). Returns the
// matching UserInfo, or a zero UserInfo (empty fields) when no match is found.
// Returning empty rather than an error matches the lore client's expectation
// (maps zero→None without surfacing a gRPC error).
func (s *authGRPCServer) GetUserId(ctx context.Context, req *epic_urc.GetUserIdRequest) (*epic_urc.GetUserIdResponse, error) {
	raw, err := bearerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if _, err = s.svc.VerifyAuthn(raw); err != nil {
		return nil, err
	}

	u, found, err := s.store.FindByDisplayName(req.GetUserDisplayName())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "display-name lookup: %v", err)
	}
	if !found {
		// No match → zero UserInfo; lore maps this to None rather than an error.
		return &epic_urc.GetUserIdResponse{UserInfo: &epic_urc.UserInfo{}}, nil
	}
	displayName := u.DisplayName
	if strings.TrimSpace(displayName) == "" {
		displayName = u.Username
	}
	return &epic_urc.GetUserIdResponse{
		UserInfo: &epic_urc.UserInfo{UserId: u.Username, DisplayName: displayName},
	}, nil
}

// CheckUserPermission determines for each requested resource_id whether the
// subject (resolved from TargetUser.user_token if set, otherwise the calling
// Bearer) has an effective grant. Resources in the subject's effective set go
// into AllowedResourcePermission; the rest go into DeniedResourcePermission
// (with an empty permission slice — the lore client treats absence as denied).
//
// Matching logic:
//   - exact match: the effective set contains "urc-{id}" verbatim, OR
//   - wildcard: the effective set contains "urc-*" (admin wildcard).
//
// The wildcard entry's permissions are used for wildcard-covered resources
// (so admin inherits read/write/migrate/obliterate for any unregistered repo).
func (s *authGRPCServer) CheckUserPermission(ctx context.Context, req *epic_urc.CheckUserPermissionRequest) (*epic_urc.CheckUserPermissionResponse, error) {
	raw, err := bearerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Determine the subject: TargetUser.user_token if provided, else the caller.
	subject := ""
	if tu := req.GetTargetUser(); tu != nil && strings.TrimSpace(tu.GetUserToken()) != "" {
		// Verify the TARGET user's token. VerifyAuthn keys on the token's own sub
		// and loads THAT sub's row, so the revocation check runs against the
		// target user's token_version — correct; do NOT use the caller's version.
		targetClaims, verifyErr := s.svc.VerifyAuthn(tu.GetUserToken())
		if verifyErr != nil {
			return nil, verifyErr
		}
		subject = targetClaims.Subject
	} else {
		callerClaims, verifyErr := s.svc.VerifyAuthn(raw)
		if verifyErr != nil {
			return nil, verifyErr
		}
		subject = callerClaims.Subject
	}

	entries, ok, err := effectiveResources(s.store, subject)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "resolving resources for %q: %v", subject, err)
	}

	// Build a lookup map: resource_id → permissions slice.
	// Also track whether there is a wildcard entry (urc-*).
	byID := make(map[string][]string, len(entries))
	var wildcardPerms []string
	if ok {
		for _, e := range entries {
			if e.ResourceID == "urc-*" {
				wildcardPerms = e.Permission
			} else {
				byID[e.ResourceID] = e.Permission
			}
		}
	}

	allowed := make([]*epic_urc.ResourcePermission, 0)
	denied := make([]*epic_urc.ResourcePermission, 0)
	for _, rid := range req.GetResourceId() {
		if perms, exact := byID[rid]; exact {
			allowed = append(allowed, &epic_urc.ResourcePermission{
				ResourceId: rid,
				Permission: perms,
			})
		} else if wildcardPerms != nil {
			// Admin wildcard covers any resource not explicitly listed.
			allowed = append(allowed, &epic_urc.ResourcePermission{
				ResourceId: rid,
				Permission: wildcardPerms,
			})
		} else {
			denied = append(denied, &epic_urc.ResourcePermission{
				ResourceId: rid,
				Permission: []string{},
			})
		}
	}

	return &epic_urc.CheckUserPermissionResponse{
		AllowedResourcePermission: allowed,
		DeniedResourcePermission:  denied,
	}, nil
}

// LookupUserPermissions returns the verified caller's effective resource grants,
// filtered by resource_filter (prefix match; empty filter = all). lore-server
// calls this on RepositoryList with the forwarded Bearer being our minted authz
// token, then strips the urc- prefix and drops urc-* to enumerate concrete repos.
//
// An unknown caller returns an EMPTY list (not an error) so RepositoryList
// degrades to "no repos" rather than failing. context_filter / page_size /
// page_token are ignored — we always return the full set in a single response.
func (s *authGRPCServer) LookupUserPermissions(ctx context.Context, req *epic_urc.LookupUserPermissionsRequest) (*epic_urc.LookupUserPermissionsResponse, error) {
	raw, err := bearerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	authn, err := s.svc.VerifyAuthn(raw)
	if err != nil {
		return nil, err
	}

	entries, ok, err := effectiveResources(s.store, authn.Subject)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "resolving resources for %q: %v", authn.Subject, err)
	}
	if !ok {
		// Unknown caller → empty list so RepositoryList shows no repos instead of
		// erroring out the whole listing.
		return &epic_urc.LookupUserPermissionsResponse{}, nil
	}

	filter := req.GetResourceFilter()
	out := make([]*epic_urc.ResourcePermission, 0, len(entries))
	for _, e := range entries {
		if !strings.HasPrefix(e.ResourceID, filter) {
			continue
		}
		out = append(out, &epic_urc.ResourcePermission{
			ResourceId: e.ResourceID,
			Permission: e.Permission,
		})
	}

	return &epic_urc.LookupUserPermissionsResponse{ResourcePermission: out}, nil
}

// ── interactive-login session flow ────────────────────────────────────────────

// StartAuthSession creates a pending session (binding the CLI's client_state)
// and returns the session_code plus the browser login URL. login_url points at
// the EXTERNALLY-reachable web base (cfg.WebBaseURL) — the browser runs on the
// artist's machine, not localhost.
func (s *authGRPCServer) StartAuthSession(_ context.Context, req *epic_urc.StartAuthSessionRequest) (*epic_urc.StartAuthSessionResponse, error) {
	if strings.TrimSpace(s.cfg.WebBaseURL) == "" {
		// Required for interactive login — without it we cannot build a URL the
		// artist's browser can reach. Fail loudly rather than emit a broken link.
		return nil, status.Error(codes.FailedPrecondition, "web_base_url is not configured")
	}

	code, err := s.sessions.Create(req.GetClientState())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "creating session: %v", err)
	}

	base := strings.TrimRight(s.cfg.WebBaseURL, "/")
	loginURL := base + "/login?session=" + url.QueryEscape(code)

	return &epic_urc.StartAuthSessionResponse{
		SessionCode: code,
		LoginUrl:    loginURL,
	}, nil
}

// GetAuthSession is the CLI poll. It single-use-consumes a completed session
// (Take), returning the minted UserToken. A pending / unknown / expired /
// client_state-mismatched session returns a response with a NIL user_token —
// "not ready", the client keeps polling. It is NOT an error to poll early.
func (s *authGRPCServer) GetAuthSession(_ context.Context, req *epic_urc.GetAuthSessionRequest) (*epic_urc.GetAuthSessionResponse, error) {
	token, expMs, ok := s.sessions.Take(req.GetSessionCode(), req.GetClientState())
	if !ok {
		// Empty user_token = keep polling. Do not error on pending.
		return &epic_urc.GetAuthSessionResponse{}, nil
	}

	// The minted token carries sub (UserId) + name (display) — read them back
	// from the token we signed so the reported identity cannot drift.
	subject, displayName, err := tokenIdentity(s.priv, token)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "reading minted token identity: %v", err)
	}

	return &epic_urc.GetAuthSessionResponse{
		UserToken: &epic_urc.UserToken{
			UserToken: token,
			// ExpiresAt is MILLISECONDS — same unit as the exchange path; the
			// client reads it as expires_ms.
			ExpiresAt: expMs,
			UserId:    subject,
			UserName:  displayName,
		},
	}, nil
}

// RefreshAuthSession is intentionally unimplemented: tokens are long-TTL and the
// client never refreshes interactive sessions.
func (s *authGRPCServer) RefreshAuthSession(context.Context, *epic_urc.RefreshAuthSessionRequest) (*epic_urc.RefreshAuthSessionResponse, error) {
	return nil, status.Error(codes.Unimplemented, "RefreshAuthSession is not implemented")
}

// tokenIdentity re-parses a token WE minted (verifying against our own key) and
// returns (subject, displayName). displayName prefers the `name` claim, then
// preferred_username, then sub — mirroring displayNameFor.
func tokenIdentity(priv *rsa.PrivateKey, signed string) (string, string, error) {
	claims := &arcLoreClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))
	if _, err := parser.ParseWithClaims(signed, claims, func(*jwt.Token) (interface{}, error) {
		return &priv.PublicKey, nil
	}); err != nil {
		return "", "", err
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return "", "", fmt.Errorf("minted token missing subject")
	}
	return claims.Subject, displayNameFor(claims), nil
}

// All other UrcAuthApi methods fall through to UnimplementedUrcAuthApiServer →
// codes.Unimplemented. None are on the lock/commit path.

// serveGRPC builds the TLS-secured gRPC server and serves it on listenAddr.
// It blocks until the listener fails. The TLS cert is loaded/generated by the
// caller (so both keys are ready before any listener starts).
//
// Both UrcAuthApi (auth/exchange) and RebacApi (repo registry) are registered on
// the SAME server/listener — lore-server reaches both via one auth_url.
func serveGRPC(listenAddr string, creds grpc.ServerOption, authSrv *authGRPCServer, rebacSrv *rebacGRPCServer) error {
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", listenAddr, err)
	}

	// Auth RPCs carry only small JWT payloads; 64 KiB is generous.
	// Keepalive closes idle connections after 5 min of inactivity and
	// sends periodic pings (2 min interval, 20 s timeout) so stale TCP
	// sessions don't linger. No EnforcementPolicy is set: the ArcLoreWeb
	// client pings every 30 s and would be incorrectly rejected if MinTime
	// were set above that threshold.
	s := grpc.NewServer(
		creds,
		grpc.MaxRecvMsgSize(1<<16),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute,
			Time:              2 * time.Minute,
			Timeout:           20 * time.Second,
		}),
	)
	epic_urc.RegisterUrcAuthApiServer(s, authSrv)
	ucs_auth.RegisterRebacApiServer(s, rebacSrv)

	return s.Serve(lis)
}

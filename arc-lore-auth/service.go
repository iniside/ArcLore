package main

import (
	"crypto/rsa"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// service.go — authService is the single mint site. It collapses the
// effectiveResources -> mintTokenWithResources -> authzTokenExpiryUnix triple
// (formerly duplicated in the web /login POST, the JSON API, and the gRPC
// exchange RPC) into one method. Concentrating the mint here is the
// precondition for adding a token_version claim in exactly one place (Phase C).

// errUnknownSubject is the sentinel MintFor returns when the subject does not
// resolve to an eligible identity (effectiveResources ok=false — i.e. the user
// does not exist). Callers map it to their own transport status: the gRPC
// exchange returns codes.PermissionDenied for this case, preserving the prior
// behavior; the web/api paths collapse it to a 500 as before (they only reach
// MintFor after proving the row exists, so this is a defensive fail-closed).
var errUnknownSubject = errors.New("unknown or ineligible subject")

// authService owns the token-minting dependencies. It is constructed once per
// server (web/api via attachWeb, gRPC via newGRPCServer) from the cfg/priv/kid/
// store fields those servers already hold — never re-deriving them.
type authService struct {
	cfg   *Config
	priv  *rsa.PrivateKey
	kid   string
	store StoreInterface
}

// MintFor resolves the caller's effective grants and mints an authz token.
// Returns the token plus its expiry in BOTH units so each transport can use
// the one it needs. Fails (error) for an unknown/ineligible subject — never
// mints for a non-existent user.
func (s *authService) MintFor(subject, displayName string) (token string, expSec int64, expMs int64, err error) {
	entries, ok, err := effectiveResources(s.store, subject)
	if err != nil {
		return "", 0, 0, err
	}
	if !ok {
		return "", 0, 0, errUnknownSubject
	}

	// Stamp the subject's current token_version into the token. effectiveResources
	// already proved the row exists (ok=true), so this GetUser resolves; we re-read
	// it purely to read TokenVersion (effectiveResources does not surface it). A
	// later bump of this row (password/admin change) makes this minted token's
	// version stale, so VerifyAuthn will reject it.
	u, err := s.store.GetUser(subject)
	if err != nil {
		return "", 0, 0, err
	}

	token, err = mintTokenWithResources(s.cfg, s.priv, s.kid, subject, displayName, entries, u.TokenVersion)
	if err != nil {
		return "", 0, 0, err
	}

	expSec, err = authzTokenExpiryUnix(s.priv, token)
	if err != nil {
		return "", 0, 0, err
	}

	return token, expSec, expSec * 1000, nil
}

// VerifyAuthn is the store-backed verification gate: it runs the pure JWT checks
// (signature/alg/exp/iss/aud via the package-level verifyAuthnToken) AND enforces
// token revocation by comparing the token's token_version claim against the
// subject's current users.token_version row. A bump of that row (password or
// admin change) leaves every prior token stale, so VerifyAuthn rejects it with
// codes.Unauthenticated. EVERY live auth gate must route through this rather than
// the bare package-level verifier, or revoked tokens keep working.
//
// It keys on the token's OWN subject (claims.Subject) and loads THAT subject's
// row, so it is correct for verifying a different user's token (e.g. the
// CheckUserPermission target-user branch) as well as the caller's own.
func (s *authService) VerifyAuthn(raw string) (*arcLoreClaims, error) {
	claims, err := verifyAuthnToken(s.cfg, s.priv, raw)
	if err != nil {
		return nil, err // already a codes.Unauthenticated status
	}

	u, err := s.store.GetUser(claims.Subject)
	if err != nil {
		// Unknown subject (or any load failure) fails closed — a token whose
		// subject no longer resolves cannot be honored.
		return nil, status.Errorf(codes.Unauthenticated, "token subject %q not found", claims.Subject)
	}
	if u.TokenVersion != claims.TokenVersion {
		return nil, status.Error(codes.Unauthenticated, "token revoked")
	}
	return claims, nil
}

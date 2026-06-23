package main

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ResourceEntry represents one entry in the `resources` claim.
type ResourceEntry struct {
	ResourceID string   `json:"resource_id"`
	Permission []string `json:"permission"`
}

// arcLoreClaims is the full JWT claim set the lore-server's AuthorizationToken
// struct expects. All fields are required to be present per Step-1 research.
type arcLoreClaims struct {
	jwt.RegisteredClaims

	// OIDC / identity
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`

	// Lore-server specific
	Env              string          `json:"env"`
	IDP              string          `json:"idp"`
	Resources        []ResourceEntry `json:"resources"`
	IsServiceAccount bool            `json:"is_service_account"`

	// TokenVersion binds the token to the subject's users.token_version row at
	// mint time. Verification (authService.VerifyAuthn) rejects any token whose
	// TokenVersion != the user's current row value, so bumping the row (password
	// or admin change) invalidates every prior token. CLI-minted tokens carry 0.
	TokenVersion int64 `json:"token_version"`
}

// defaultResources returns the configured default resource grants, falling back
// to the wildcard "urc-*" read+write grant when none are configured.
func defaultResources(cfg *Config) []ResourceEntry {
	if len(cfg.DefaultResources) > 0 {
		return cfg.DefaultResources
	}
	return []ResourceEntry{
		{ResourceID: "urc-*", Permission: []string{"read", "write"}},
	}
}

// mintToken creates a signed RS256 JWT for the given username, using the
// configured default resource grants. It is the offline/CLI minting path.
//
// CLI-minted tokens carry token_version 0: this path is for bootstrap/testing
// and has no store/user to load a version from. A real user row, if one exists,
// starts at token_version 0 too, so a CLI-minted token matches a fresh row;
// once that row is bumped (password/admin change) the CLI token is revoked.
func mintToken(cfg *Config, priv *rsa.PrivateKey, kid string, username string) (string, error) {
	return mintTokenWithResources(cfg, priv, kid, username, username, defaultResources(cfg), 0)
}

// mintTokenWithResources creates a signed RS256 JWT carrying an explicit
// identity (sub) + display name + resource grants. The gRPC exchange path uses
// this to mint an authz token from a verified authn token's identity.
//
// kid is embedded in the header so the lore-server's JwkServiceImpl can
// look up the right public key from the JWKS.
func mintTokenWithResources(cfg *Config, priv *rsa.PrivateKey, kid string, subject string, displayName string, resources []ResourceEntry, tokenVersion int64) (string, error) {
	now := time.Now()

	ttl, err := time.ParseDuration(cfg.TokenTTL)
	if err != nil {
		return "", fmt.Errorf("invalid token_ttl %q: %w", cfg.TokenTTL, err)
	}

	if displayName == "" {
		displayName = subject
	}

	// aud MUST be a JSON array (jwt library handles []string → array).
	// CRITICAL: audience must be the lore-server host domain so the in-editor
	// client gate (remote_domain.ends_with(any(aud ∪ {iss}))) passes.
	audiences := jwt.ClaimStrings{cfg.Audience}

	claims := arcLoreClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    cfg.Issuer,
			Audience:  audiences,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			// No NotBefore — or use now-300s leeway; omit to keep it clean.
		},
		Name:              displayName,
		PreferredUsername: subject,
		Env:               cfg.Env,
		IDP:               cfg.IDP,
		Resources:         resources,
		IsServiceAccount:  false,
		TokenVersion:      tokenVersion,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// kid in JWT header must equal the kid served in JWKS.
	token.Header["kid"] = kid

	signed, err := token.SignedString(priv)
	if err != nil {
		return "", fmt.Errorf("signing token: %w", err)
	}

	return signed, nil
}

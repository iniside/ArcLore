package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	epic_urc "arc-lore-auth/gen/epic_urc"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// testConfig returns a minimal Config suitable for in-process tests.
func testConfig() *Config {
	return &Config{
		Issuer:   "arc-lore-auth-test",
		Audience: "test.localhost",
		Env:      "test",
		IDP:      "arc-lore-auth",
		TokenTTL: "1h",
	}
}

// startTestGRPCServer starts the gRPC server on a random localhost port and
// returns the listening address, a TLS cert pool for the client, and a stop
// function.  The TLS cert is generated in a temp dir (cleaned up on t.Cleanup).
func startTestGRPCServer(t *testing.T, srv *authGRPCServer) (addr string, certPool *x509.CertPool) {
	t.Helper()

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "tls.crt")
	keyPath := filepath.Join(tmpDir, "tls.key")

	// Generate a self-signed cert for 127.0.0.1 (IP-SAN so the gRPC client
	// can connect to 127.0.0.1 without hostname-mismatch).
	tlsCert, err := generateAndSaveTLSCert(certPath, keyPath, "127.0.0.1")
	if err != nil {
		t.Fatalf("generateAndSaveTLSCert: %v", err)
	}

	// (S4) NextProtos must include "h2" or the TLS handshake for gRPC silently fails.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
	}
	creds := grpc.Creds(credentials.NewTLS(tlsConfig))

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}

	grpcSrv := grpc.NewServer(creds)
	epic_urc.RegisterUrcAuthApiServer(grpcSrv, srv)

	go func() {
		// Serve returns a non-nil error when the listener is closed — that is
		// expected during t.Cleanup; ignore it.
		_ = grpcSrv.Serve(lis)
	}()

	t.Cleanup(func() {
		grpcSrv.GracefulStop()
	})

	// Build a cert pool that trusts ONLY our self-signed cert.
	rawCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("reading generated cert: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rawCert) {
		t.Fatal("failed to add self-signed cert to pool")
	}

	return lis.Addr().String(), pool
}

// dialTestServer dials the gRPC server at addr using a TLS config that trusts
// exactly the certs in certPool (ServerName 127.0.0.1, NextProtos h2).
// Does NOT use InsecureSkipVerify — real TLS chain verification.
func dialTestServer(t *testing.T, addr string, certPool *x509.CertPool) *grpc.ClientConn {
	t.Helper()

	clientTLS := &tls.Config{
		RootCAs:    certPool,
		ServerName: "127.0.0.1",
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS12,
	}
	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// mintAuthnToken mints a short-lived authn JWT for the given username using
// the provided key and config (same path as the `mint` CLI subcommand).
func mintAuthnToken(t *testing.T, cfg *Config, priv *rsa.PrivateKey, kid string, username string) string {
	t.Helper()
	tok, err := mintToken(cfg, priv, kid, username)
	if err != nil {
		t.Fatalf("mintToken: %v", err)
	}
	return tok
}

// verifyAuthzToken parses and verifies a JWT against the given RSA public key
// and returns the decoded claims. Fails the test if verification fails.
func verifyAuthzToken(t *testing.T, signed string, pub *rsa.PublicKey) *arcLoreClaims {
	t.Helper()
	claims := &arcLoreClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))
	_, err := parser.ParseWithClaims(signed, claims, func(*jwt.Token) (interface{}, error) {
		return pub, nil
	})
	if err != nil {
		t.Fatalf("verifying authz JWT: %v", err)
	}
	return claims
}

// TestGRPCExchange is the in-process smoke test for the gRPC exchange path.
// It covers:
//   - HealthCheck → OK (no auth required)
//   - Positive exchange: authn token → authz token with correct claims
//   - B1 negative: no Bearer → Unauthenticated
//   - B1 negative: token signed by a DIFFERENT key → Unauthenticated
func TestGRPCExchange(t *testing.T) {
	// ── Setup: key + kid ──────────────────────────────────────────────────────
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	kid, err := keyID(&priv.PublicKey)
	if err != nil {
		t.Fatalf("keyID: %v", err)
	}

	cfg := testConfig()

	// ── Start server ──────────────────────────────────────────────────────────
	// Minting is now grant-driven, so "tester" must exist as an admin for the
	// urc-* wildcard to appear in the exchanged token (the assertion below).
	store := openTestStore(t)
	if _, err := store.CreateFirstAdmin("tester", "Tester", mustHash(t, "x")); err != nil {
		t.Fatalf("CreateFirstAdmin: %v", err)
	}
	grpcSrv := newGRPCServer(cfg, priv, kid, NewSessionStore(0), store)
	addr, certPool := startTestGRPCServer(t, grpcSrv)

	conn := dialTestServer(t, addr, certPool)
	client := epic_urc.NewUrcAuthApiClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	// ── HealthCheck (no auth required) ────────────────────────────────────────
	t.Run("HealthCheck", func(t *testing.T) {
		resp, err := client.HealthCheck(ctx, &epic_urc.HealthCheckRequest{})
		if err != nil {
			t.Fatalf("HealthCheck: %v", err)
		}
		if resp.GetStatus() == "" {
			t.Fatal("HealthCheck returned empty status")
		}
	})

	// ── Positive: authn token → authz token ───────────────────────────────────
	t.Run("ExchangeHappyPath", func(t *testing.T) {
		authnToken := mintAuthnToken(t, cfg, priv, kid, "tester")

		md := metadata.Pairs("authorization", "Bearer "+authnToken)
		callCtx := metadata.NewOutgoingContext(ctx, md)

		resp, err := client.ExchangeUserTokenForMultiresourceToken(
			callCtx,
			&epic_urc.ExchangeUserTokenForMultiresourceTokenRequest{
				ResourceId: []string{"urc-*"},
			},
		)
		if err != nil {
			t.Fatalf("ExchangeUserTokenForMultiresourceToken: %v", err)
		}

		tok := resp.GetToken()
		if tok == nil {
			t.Fatal("response Token is nil")
		}

		// Token string must be non-empty.
		if tok.GetUserToken() == "" {
			t.Fatal("Token.UserToken is empty")
		}

		// UserId must equal the subject we minted.
		if tok.GetUserId() != "tester" {
			t.Fatalf("Token.UserId = %q; want %q", tok.GetUserId(), "tester")
		}

		// ExpiresAt must be in MILLISECONDS (> 1e12 for any reasonable future time).
		const minMs = int64(1e12)
		if tok.GetExpiresAt() <= minMs {
			t.Fatalf("Token.ExpiresAt = %d; want > %d (milliseconds since epoch)", tok.GetExpiresAt(), minMs)
		}

		// Verify ExpiresAt is roughly now + TTL (1h = 3600s = 3_600_000 ms).
		// Allow ±60 s of skew.
		nowMs := time.Now().UnixMilli()
		ttlMs := int64(3600 * 1000)
		diff := tok.GetExpiresAt() - nowMs
		if diff < ttlMs-60_000 || diff > ttlMs+60_000 {
			t.Fatalf("Token.ExpiresAt offset from now = %d ms; want ~%d ms (±60s)", diff, ttlMs)
		}

		// Verify the authz JWT cryptographically against our public key.
		claims := verifyAuthzToken(t, tok.GetUserToken(), &priv.PublicKey)

		// resources claim must contain "urc-*".
		foundUrcWild := false
		for _, res := range claims.Resources {
			if res.ResourceID == "urc-*" {
				foundUrcWild = true
				break
			}
		}
		if !foundUrcWild {
			t.Fatalf("authz token resources does not contain resource_id=urc-*; got %+v", claims.Resources)
		}
	})

	// ── B1 negative: no Bearer → Unauthenticated ──────────────────────────────
	t.Run("NoBearer", func(t *testing.T) {
		// Call without attaching any metadata — no authorization header at all.
		_, err := client.ExchangeUserTokenForMultiresourceToken(
			ctx,
			&epic_urc.ExchangeUserTokenForMultiresourceTokenRequest{
				ResourceId: []string{"urc-*"},
			},
		)
		if err == nil {
			t.Fatal("expected Unauthenticated error; got nil")
		}
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected codes.Unauthenticated; got %v (%v)", status.Code(err), err)
		}
	})

	// ── B1 negative: token signed by a DIFFERENT key → Unauthenticated ────────
	t.Run("WrongKey", func(t *testing.T) {
		// Generate a completely separate RSA key that the server does not know about.
		otherPriv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey (other): %v", err)
		}
		otherKid, err := keyID(&otherPriv.PublicKey)
		if err != nil {
			t.Fatalf("keyID (other): %v", err)
		}

		// Mint an authn token signed by the OTHER key (not the server's key).
		badToken := mintAuthnToken(t, cfg, otherPriv, otherKid, "attacker")

		md := metadata.Pairs("authorization", "Bearer "+badToken)
		callCtx := metadata.NewOutgoingContext(ctx, md)

		_, err = client.ExchangeUserTokenForMultiresourceToken(
			callCtx,
			&epic_urc.ExchangeUserTokenForMultiresourceTokenRequest{
				ResourceId: []string{"urc-*"},
			},
		)
		if err == nil {
			t.Fatal("expected Unauthenticated error for wrong-key token; got nil")
		}
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected codes.Unauthenticated for wrong-key token; got %v (%v)", status.Code(err), err)
		}
	})
}

// callGetUserInfo dials srv, calls GetUserInfo with Bearer minted for caller,
// and returns the response.
func callGetUserInfo(t *testing.T, srv *authGRPCServer, cfg *Config, priv *rsa.PrivateKey, kid, caller string, ids []string) *epic_urc.GetUserInfoResponse {
	t.Helper()
	addr, pool := startTestGRPCServer(t, srv)
	conn := dialTestServer(t, addr, pool)
	client := epic_urc.NewUrcAuthApiClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	token := mintAuthnToken(t, cfg, priv, kid, caller)
	md := metadata.Pairs("authorization", "Bearer "+token)
	resp, err := client.GetUserInfo(
		metadata.NewOutgoingContext(ctx, md),
		&epic_urc.GetUserInfoRequest{UserId: ids},
	)
	if err != nil {
		t.Fatalf("GetUserInfo: %v", err)
	}
	return resp
}

// callGetUserId dials srv, calls GetUserId with Bearer minted for caller.
func callGetUserId(t *testing.T, srv *authGRPCServer, cfg *Config, priv *rsa.PrivateKey, kid, caller, displayName string) *epic_urc.GetUserIdResponse {
	t.Helper()
	addr, pool := startTestGRPCServer(t, srv)
	conn := dialTestServer(t, addr, pool)
	client := epic_urc.NewUrcAuthApiClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	token := mintAuthnToken(t, cfg, priv, kid, caller)
	md := metadata.Pairs("authorization", "Bearer "+token)
	resp, err := client.GetUserId(
		metadata.NewOutgoingContext(ctx, md),
		&epic_urc.GetUserIdRequest{UserDisplayName: displayName},
	)
	if err != nil {
		t.Fatalf("GetUserId: %v", err)
	}
	return resp
}

// callCheckUserPermission dials srv, calls CheckUserPermission with Bearer for caller.
func callCheckUserPermission(t *testing.T, srv *authGRPCServer, cfg *Config, priv *rsa.PrivateKey, kid, caller string, resourceIDs []string) *epic_urc.CheckUserPermissionResponse {
	t.Helper()
	addr, pool := startTestGRPCServer(t, srv)
	conn := dialTestServer(t, addr, pool)
	client := epic_urc.NewUrcAuthApiClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	token := mintAuthnToken(t, cfg, priv, kid, caller)
	md := metadata.Pairs("authorization", "Bearer "+token)
	resp, err := client.CheckUserPermission(
		metadata.NewOutgoingContext(ctx, md),
		&epic_urc.CheckUserPermissionRequest{ResourceId: resourceIDs},
	)
	if err != nil {
		t.Fatalf("CheckUserPermission: %v", err)
	}
	return resp
}

func findUserInfoByID(infos []*epic_urc.UserInfo, id string) *epic_urc.UserInfo {
	for _, info := range infos {
		if info.GetUserId() == id {
			return info
		}
	}
	return nil
}

func hasResourceID(perms []*epic_urc.ResourcePermission, id string) bool {
	for _, p := range perms {
		if p.GetResourceId() == id {
			return true
		}
	}
	return false
}

// TestGetUserInfo verifies:
//   - a known user_id is resolved to the stored display name
//   - an unknown user_id is silently skipped
func TestGetUserInfo(t *testing.T) {
	priv, kid := permTestKey(t)
	cfg := testConfig()
	store := openTestStore(t)

	if _, err := store.CreateFirstAdmin("alice", "Alice Liddell", mustHash(t, "x")); err != nil {
		t.Fatalf("CreateFirstAdmin: %v", err)
	}
	srv := newGRPCServer(cfg, priv, kid, NewSessionStore(0), store)

	// Request alice (known) + ghost (unknown). Only alice should be returned.
	resp := callGetUserInfo(t, srv, cfg, priv, kid, "alice", []string{"alice", "ghost"})
	if len(resp.GetUserInfo()) != 1 {
		t.Fatalf("GetUserInfo: got %d entries; want 1", len(resp.GetUserInfo()))
	}
	info := findUserInfoByID(resp.GetUserInfo(), "alice")
	if info == nil {
		t.Fatal("GetUserInfo: alice not in response")
	}
	if info.GetDisplayName() != "Alice Liddell" {
		t.Fatalf("GetUserInfo: DisplayName = %q; want %q", info.GetDisplayName(), "Alice Liddell")
	}
}

// TestGetUserId verifies:
//   - a display-name match returns the user's username
//   - an unknown display name returns an empty UserInfo (not an error)
func TestGetUserId(t *testing.T) {
	priv, kid := permTestKey(t)
	cfg := testConfig()
	store := openTestStore(t)

	if _, err := store.CreateFirstAdmin("bob", "Robert Smith", mustHash(t, "x")); err != nil {
		t.Fatalf("CreateFirstAdmin: %v", err)
	}
	srv := newGRPCServer(cfg, priv, kid, NewSessionStore(0), store)

	// Known display name (case-insensitive).
	resp := callGetUserId(t, srv, cfg, priv, kid, "bob", "robert smith")
	if resp.GetUserInfo() == nil {
		t.Fatal("GetUserId: UserInfo is nil")
	}
	if resp.GetUserInfo().GetUserId() != "bob" {
		t.Fatalf("GetUserId: UserId = %q; want %q", resp.GetUserInfo().GetUserId(), "bob")
	}
	if resp.GetUserInfo().GetDisplayName() != "Robert Smith" {
		t.Fatalf("GetUserId: DisplayName = %q; want %q", resp.GetUserInfo().GetDisplayName(), "Robert Smith")
	}

	// Unknown display name → empty UserInfo (zero fields, no error).
	respUnknown := callGetUserId(t, srv, cfg, priv, kid, "bob", "nobody")
	if respUnknown.GetUserInfo() == nil {
		t.Fatal("GetUserId unknown: UserInfo should be non-nil zero struct")
	}
	if respUnknown.GetUserInfo().GetUserId() != "" || respUnknown.GetUserInfo().GetDisplayName() != "" {
		t.Fatalf("GetUserId unknown: expected zero UserInfo; got %+v", respUnknown.GetUserInfo())
	}
}

// TestCheckUserPermission verifies:
//   - admin caller: a registered resource is allowed; unknown resource is allowed via wildcard
//   - non-admin with a grant: the granted resource is allowed; ungrant resource is denied
func TestCheckUserPermission(t *testing.T) {
	priv, kid := permTestKey(t)
	cfg := testConfig()
	store := openTestStore(t)

	if _, err := store.CreateFirstAdmin("admin", "Admin", mustHash(t, "x")); err != nil {
		t.Fatalf("CreateFirstAdmin: %v", err)
	}
	if _, err := store.UpsertResource("urc-repo1", "Repo1"); err != nil {
		t.Fatalf("UpsertResource: %v", err)
	}
	if err := store.AddUser("dave", "Dave", mustHash(t, "x"), false); err != nil {
		t.Fatalf("AddUser dave: %v", err)
	}
	if err := store.AddGrant("dave", "urc-repo1", "read"); err != nil {
		t.Fatalf("AddGrant: %v", err)
	}

	srv := newGRPCServer(cfg, priv, kid, NewSessionStore(0), store)

	// Admin: registered repo is allowed (exact match); unregistered repo is
	// allowed via urc-* wildcard.
	adminResp := callCheckUserPermission(t, srv, cfg, priv, kid, "admin", []string{"urc-repo1", "urc-unregistered"})
	if !hasResourceID(adminResp.GetAllowedResourcePermission(), "urc-repo1") {
		t.Fatalf("admin: urc-repo1 not in allowed; allowed=%+v denied=%+v",
			adminResp.GetAllowedResourcePermission(), adminResp.GetDeniedResourcePermission())
	}
	if !hasResourceID(adminResp.GetAllowedResourcePermission(), "urc-unregistered") {
		t.Fatalf("admin: urc-unregistered not in allowed (wildcard); allowed=%+v",
			adminResp.GetAllowedResourcePermission())
	}
	if len(adminResp.GetDeniedResourcePermission()) != 0 {
		t.Fatalf("admin: expected no denied; got %+v", adminResp.GetDeniedResourcePermission())
	}

	// Non-admin dave: granted resource is allowed; ungrant resource is denied.
	daveResp := callCheckUserPermission(t, srv, cfg, priv, kid, "dave", []string{"urc-repo1", "urc-repo2"})
	if !hasResourceID(daveResp.GetAllowedResourcePermission(), "urc-repo1") {
		t.Fatalf("dave: urc-repo1 not in allowed; allowed=%+v", daveResp.GetAllowedResourcePermission())
	}
	if !hasResourceID(daveResp.GetDeniedResourcePermission(), "urc-repo2") {
		t.Fatalf("dave: urc-repo2 not in denied; denied=%+v", daveResp.GetDeniedResourcePermission())
	}
}

// TestWrongAudience verifies that a token minted with a different audience
// is rejected with codes.Unauthenticated by verifyAuthnToken (A1 fix).
//
// Technique: construct claims with aud="wrong.example", sign them with the
// server's own key (so the signature check passes), then attempt an exchange.
// The audience mismatch must cause rejection before the exchange is attempted.
func TestWrongAudience(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	kid, err := keyID(&priv.PublicKey)
	if err != nil {
		t.Fatalf("keyID: %v", err)
	}

	cfg := testConfig() // Audience="test.localhost", Issuer="arc-lore-auth-test"

	store := openTestStore(t)
	if _, err := store.CreateFirstAdmin("tester", "Tester", mustHash(t, "x")); err != nil {
		t.Fatalf("CreateFirstAdmin: %v", err)
	}
	grpcSrv := newGRPCServer(cfg, priv, kid, NewSessionStore(0), store)
	addr, certPool := startTestGRPCServer(t, grpcSrv)

	conn := dialTestServer(t, addr, certPool)
	client := epic_urc.NewUrcAuthApiClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	// Mint a token whose aud is "wrong.example" (not "test.localhost") but
	// signed by the server's own key so the signature is valid.
	wrongAudCfg := &Config{
		Issuer:   cfg.Issuer, // same issuer — only audience differs
		Audience: "wrong.example",
		Env:      cfg.Env,
		IDP:      cfg.IDP,
		TokenTTL: cfg.TokenTTL,
	}
	badToken, mintErr := mintToken(wrongAudCfg, priv, kid, "tester")
	if mintErr != nil {
		t.Fatalf("mintToken (wrong aud): %v", mintErr)
	}

	md := metadata.Pairs("authorization", "Bearer "+badToken)
	callCtx := metadata.NewOutgoingContext(ctx, md)

	_, exchErr := client.ExchangeUserTokenForMultiresourceToken(
		callCtx,
		&epic_urc.ExchangeUserTokenForMultiresourceTokenRequest{
			ResourceId: []string{"urc-*"},
		},
	)
	if exchErr == nil {
		t.Fatal("expected Unauthenticated for wrong-audience token; got nil error")
	}
	if status.Code(exchErr) != codes.Unauthenticated {
		t.Fatalf("expected codes.Unauthenticated for wrong-audience token; got %v (%v)", status.Code(exchErr), exchErr)
	}
}

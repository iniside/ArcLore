package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	epic_urc "arc-lore-auth/gen/epic_urc"
	ucs_auth "arc-lore-auth/gen/ucs_auth"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// revocation_test.go — C2 end-to-end coverage: a token minted at the subject's
// current token_version stops verifying the moment that row is bumped (password
// or admin change), proving every live verify path runs the store-backed
// revocation check (exchange, the rebac create/delete path, and the HTTP API
// gate). A freshly minted token (carrying the new version) still works.

// mintAuthzFor mints an authz token through the server's own authService so it
// carries the subject's CURRENT token_version (unlike mintToken, which always
// stamps 0). This is the token the lore client would forward back as a Bearer.
func mintAuthzFor(t *testing.T, svc *authService, subject string) string {
	t.Helper()
	tok, _, _, err := svc.MintFor(subject, subject)
	if err != nil {
		t.Fatalf("MintFor(%q): %v", subject, err)
	}
	return tok
}

// callExchange dials srv, attaches bearer, and runs ExchangeUserTokenForMultiresourceToken.
func callExchange(t *testing.T, srv *authGRPCServer, bearer string) error {
	t.Helper()
	addr, pool := startTestGRPCServer(t, srv)
	conn := dialTestServer(t, addr, pool)
	client := epic_urc.NewUrcAuthApiClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	md := metadata.Pairs("authorization", "Bearer "+bearer)
	_, err := client.ExchangeUserTokenForMultiresourceToken(
		metadata.NewOutgoingContext(ctx, md),
		&epic_urc.ExchangeUserTokenForMultiresourceTokenRequest{ResourceId: []string{"urc-*"}},
	)
	return err
}

// (a) Password bump revokes a previously minted token on the exchange path; a
// freshly minted token (new version) still works.
func TestRevocationOnPasswordBump(t *testing.T) {
	priv, kid := permTestKey(t)
	cfg := testConfig()
	store := openTestStore(t)
	if _, err := store.CreateFirstAdmin("admin", "Admin", mustHash(t, "x")); err != nil {
		t.Fatalf("CreateFirstAdmin: %v", err)
	}

	srv := newGRPCServer(cfg, priv, kid, NewSessionStore(0), store)

	// Token minted at the current row version (0) — exchange must succeed.
	oldToken := mintAuthzFor(t, srv.svc, "admin")
	if err := callExchange(t, srv, oldToken); err != nil {
		t.Fatalf("exchange with fresh token should succeed; got %v", err)
	}

	// Bump the row: every prior token is now revoked.
	if err := store.SetPassword("admin", mustHash(t, "newsecret")); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	if err := callExchange(t, srv, oldToken); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("exchange with revoked token = %v; want Unauthenticated", err)
	}

	// A newly minted token carries the bumped version and works again.
	newToken := mintAuthzFor(t, srv.svc, "admin")
	if err := callExchange(t, srv, newToken); err != nil {
		t.Fatalf("exchange with re-minted token should succeed; got %v", err)
	}
}

// (b) Admin-flag bump revokes a previously minted token on the exchange path.
func TestRevocationOnAdminBump(t *testing.T) {
	priv, kid := permTestKey(t)
	cfg := testConfig()
	store := openTestStore(t)
	// Two admins so the (non-target) flag flip is allowed; we bump "user".
	if _, err := store.CreateFirstAdmin("admin", "Admin", mustHash(t, "x")); err != nil {
		t.Fatalf("CreateFirstAdmin: %v", err)
	}
	if err := store.AddUser("user", "User", mustHash(t, "x"), false); err != nil {
		t.Fatalf("AddUser: %v", err)
	}

	srv := newGRPCServer(cfg, priv, kid, NewSessionStore(0), store)

	oldToken := mintAuthzFor(t, srv.svc, "user")
	if err := callExchange(t, srv, oldToken); err != nil {
		t.Fatalf("exchange with fresh token should succeed; got %v", err)
	}

	// Promote "user" to admin — bumps token_version, revoking the old token.
	if err := store.SetAdmin("user", true); err != nil {
		t.Fatalf("SetAdmin: %v", err)
	}

	if err := callExchange(t, srv, oldToken); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("exchange after admin bump = %v; want Unauthenticated", err)
	}

	newToken := mintAuthzFor(t, srv.svc, "user")
	if err := callExchange(t, srv, newToken); err != nil {
		t.Fatalf("exchange with re-minted token should succeed; got %v", err)
	}
}

// (c) rebac CreateResource / DeleteResource reject a revoked token, proving the
// rebac path runs the revocation check (the explicit hole this step closes).
func TestRevocationOnRebacPath(t *testing.T) {
	priv, kid := permTestKey(t)
	cfg := testConfig()
	store := openTestStore(t)
	if err := store.AddUser("alice", "Alice", mustHash(t, "alicepass"), true); err != nil {
		t.Fatalf("AddUser: %v", err)
	}

	// Build a verify-capable authService to mint version-bound tokens, mirroring
	// how newRebacServer builds its own verify-only svc.
	mintSvc := &authService{cfg: cfg, priv: priv, kid: kid, store: store}
	rebacSrv := newRebacServer(cfg, priv, store)
	addr, certPool := startTestRebacServer(t, rebacSrv)
	conn := dialTestServer(t, addr, certPool)
	client := ucs_auth.NewRebacApiClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	oldToken := mintAuthzFor(t, mintSvc, "alice")
	oldCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+oldToken))

	const repoID = "urc-deadbeef00112233445566778899aabb"

	// Sanity: the fresh token creates a resource.
	if _, err := client.CreateResource(oldCtx, &ucs_auth.CreateResourceRequest{
		ResourceId:   repoID,
		ResourceName: "Repo",
	}); err != nil {
		t.Fatalf("CreateResource with fresh token: %v", err)
	}

	// Bump alice's row — old token is now revoked.
	if err := store.SetPassword("alice", mustHash(t, "newsecret")); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	if _, err := client.CreateResource(oldCtx, &ucs_auth.CreateResourceRequest{
		ResourceId:   "urc-cafebabe00112233445566778899ccdd",
		ResourceName: "Repo2",
	}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("CreateResource with revoked token = %v; want Unauthenticated", err)
	}

	if _, err := client.DeleteResource(oldCtx, &ucs_auth.DeleteResourceRequest{
		ResourceId: repoID,
	}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("DeleteResource with revoked token = %v; want Unauthenticated", err)
	}

	// A re-minted token (new version) works on the rebac path again.
	newToken := mintAuthzFor(t, mintSvc, "alice")
	newCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+newToken))
	if _, err := client.DeleteResource(newCtx, &ucs_auth.DeleteResourceRequest{
		ResourceId: repoID,
	}); err != nil {
		t.Fatalf("DeleteResource with re-minted token: %v", err)
	}
}

// (d) HTTP management-API gate rejects a revoked token. Proves requireAPIAuth /
// requireAPIAdmin route through the store-backed VerifyAuthn.
func TestRevocationOnAPIGate(t *testing.T) {
	base, store, stop := apiTestServer(t)
	defer stop()

	// Set up the first admin and capture its (version-0) token.
	const rootPass = "rootpassword123"
	var setup apiTokenResp
	if code, _ := doAPI(t, base, http.MethodPost, "/api/setup", "", apiSetupReq{
		Username: "root", Password: rootPass, DisplayName: "Root",
	}, &setup); code != http.StatusCreated {
		t.Fatalf("setup: got %d want 201", code)
	}
	oldToken := setup.Token

	// The token works on an admin endpoint.
	if code, _ := doAPI(t, base, http.MethodGet, "/api/users", oldToken, nil, nil); code != http.StatusOK {
		t.Fatalf("list-users with fresh token: got %d want 200", code)
	}

	// Bump root's row directly through the store — revokes the captured token.
	if err := store.SetPassword("root", mustHash(t, "newsecret")); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	if code, _ := doAPI(t, base, http.MethodGet, "/api/users", oldToken, nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("list-users with revoked token: got %d want 401", code)
	}

	// A fresh login mints a token at the new version and works again.
	var login apiTokenResp
	if code, _ := doAPI(t, base, http.MethodPost, "/api/login", "", apiLoginReq{
		Username: "root", Password: "newsecret",
	}, &login); code != http.StatusOK {
		t.Fatalf("re-login: got %d want 200", code)
	}
	if code, _ := doAPI(t, base, http.MethodGet, "/api/users", login.Token, nil, nil); code != http.StatusOK {
		t.Fatalf("list-users with re-minted token: got %d want 200", code)
	}
}

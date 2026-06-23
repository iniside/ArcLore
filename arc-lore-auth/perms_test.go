package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	epic_urc "arc-lore-auth/gen/epic_urc"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// permTestKey returns a fresh RSA key + its kid for a perms test.
func permTestKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	kid, err := keyID(&priv.PublicKey)
	if err != nil {
		t.Fatalf("keyID: %v", err)
	}
	return priv, kid
}

// entryFor returns the ResourceEntry with the given id, or nil if absent.
func entryFor(entries []ResourceEntry, id string) *ResourceEntry {
	for i := range entries {
		if entries[i].ResourceID == id {
			return &entries[i]
		}
	}
	return nil
}

func hasPerm(perms []string, want string) bool {
	for _, p := range perms {
		if p == want {
			return true
		}
	}
	return false
}

// callLookup dials srv, calls LookupUserPermissions with a Bearer minted for
// username and the given resource filter, and returns the response.
func callLookup(t *testing.T, srv *authGRPCServer, cfg *Config, priv *rsa.PrivateKey, kid, username, filter string) *epic_urc.LookupUserPermissionsResponse {
	t.Helper()
	addr, pool := startTestGRPCServer(t, srv)
	conn := dialTestServer(t, addr, pool)
	client := epic_urc.NewUrcAuthApiClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	token := mintAuthnToken(t, cfg, priv, kid, username)
	md := metadata.Pairs("authorization", "Bearer "+token)
	resp, err := client.LookupUserPermissions(
		metadata.NewOutgoingContext(ctx, md),
		&epic_urc.LookupUserPermissionsRequest{ResourceFilter: filter},
	)
	if err != nil {
		t.Fatalf("LookupUserPermissions: %v", err)
	}
	return resp
}

func containsResourceID(perms []*epic_urc.ResourcePermission, id string) bool {
	for _, p := range perms {
		if p.GetResourceId() == id {
			return true
		}
	}
	return false
}

// (a) Admin: every registered repo concretely (owner+admin) PLUS urc-*; and the
// LookupUserPermissions RPC returns the concrete ids under filter "urc".
func TestEffectiveResourcesAdmin(t *testing.T) {
	priv, kid := permTestKey(t)
	cfg := testConfig()

	store := openTestStore(t)
	if _, err := store.UpsertResource("urc-aaa", "AAA"); err != nil {
		t.Fatalf("UpsertResource aaa: %v", err)
	}
	if _, err := store.UpsertResource("urc-bbb", "BBB"); err != nil {
		t.Fatalf("UpsertResource bbb: %v", err)
	}
	if _, err := store.CreateFirstAdmin("admin1", "Admin", mustHash(t, "x")); err != nil {
		t.Fatalf("CreateFirstAdmin: %v", err)
	}

	entries, ok, err := effectiveResources(store, "admin1")
	if err != nil || !ok {
		t.Fatalf("effectiveResources(admin1) = ok=%v err=%v", ok, err)
	}

	for _, id := range []string{"urc-aaa", "urc-bbb"} {
		e := entryFor(entries, id)
		if e == nil {
			t.Fatalf("admin entries missing %s; got %+v", id, entries)
		}
		// Concrete entries must carry the FULL set: lore-server's owner/admin and
		// obliterate gates resolve via user_permissions, which ignores urc-*, so
		// obliterate (and migrate) must be on the concrete entry or an admin is
		// denied those ops on every repo.
		for _, perm := range []string{"read", "write", "owner", "admin", "obliterate", "migrate"} {
			if !hasPerm(e.Permission, perm) {
				t.Fatalf("%s must carry %q; got %v", id, perm, e.Permission)
			}
		}
	}
	if entryFor(entries, "urc-*") == nil {
		t.Fatalf("admin entries missing urc-*; got %+v", entries)
	}

	// RPC: filter "urc" must return both concrete ids.
	srv := newGRPCServer(cfg, priv, kid, NewSessionStore(0), store)
	resp := callLookup(t, srv, cfg, priv, kid, "admin1", "urc")
	if !containsResourceID(resp.GetResourcePermission(), "urc-aaa") ||
		!containsResourceID(resp.GetResourcePermission(), "urc-bbb") {
		t.Fatalf("LookupUserPermissions(admin1, urc) missing concrete ids; got %+v", resp.GetResourcePermission())
	}
}

// (b) Non-admin with grants: exactly their grants, NO urc-*.
func TestEffectiveResourcesNonAdminGrants(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.UpsertResource("urc-ccc", "CCC"); err != nil {
		t.Fatalf("UpsertResource ccc: %v", err)
	}
	if err := store.AddUser("bob", "Bob", mustHash(t, "x"), false); err != nil {
		t.Fatalf("AddUser bob: %v", err)
	}
	if err := store.AddGrant("bob", "urc-ccc", "read"); err != nil {
		t.Fatalf("AddGrant: %v", err)
	}

	entries, ok, err := effectiveResources(store, "bob")
	if err != nil || !ok {
		t.Fatalf("effectiveResources(bob) = ok=%v err=%v", ok, err)
	}
	if len(entries) != 1 {
		t.Fatalf("bob must have exactly 1 entry; got %+v", entries)
	}
	if entries[0].ResourceID != "urc-ccc" || len(entries[0].Permission) != 1 || entries[0].Permission[0] != "read" {
		t.Fatalf("bob entry = %+v; want {urc-ccc,[read]}", entries[0])
	}
	if entryFor(entries, "urc-*") != nil {
		t.Fatalf("non-admin bob must NOT carry urc-*; got %+v", entries)
	}
}

// (c) No-grant non-admin (LOAD-BEARING Blocker #1): empty effective set stays
// empty (no urc-*), and the exchanged authz token carries resources:[].
func TestEffectiveResourcesNoGrantEmpty(t *testing.T) {
	priv, kid := permTestKey(t)
	cfg := testConfig()

	store := openTestStore(t)
	if err := store.AddUser("carol", "Carol", mustHash(t, "x"), false); err != nil {
		t.Fatalf("AddUser carol: %v", err)
	}

	entries, ok, err := effectiveResources(store, "carol")
	if err != nil || !ok {
		t.Fatalf("effectiveResources(carol) = ok=%v err=%v", ok, err)
	}
	if entries == nil || len(entries) != 0 {
		t.Fatalf("carol must have a non-nil empty entry set; got %#v", entries)
	}

	// Exchange-mint for carol → authz token must carry resources:[].
	srv := newGRPCServer(cfg, priv, kid, NewSessionStore(0), store)
	addr, pool := startTestGRPCServer(t, srv)
	conn := dialTestServer(t, addr, pool)
	client := epic_urc.NewUrcAuthApiClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	authn := mintAuthnToken(t, cfg, priv, kid, "carol")
	md := metadata.Pairs("authorization", "Bearer "+authn)
	resp, err := client.ExchangeUserTokenForMultiresourceToken(
		metadata.NewOutgoingContext(ctx, md),
		&epic_urc.ExchangeUserTokenForMultiresourceTokenRequest{},
	)
	if err != nil {
		t.Fatalf("Exchange(carol): %v", err)
	}
	claims := verifyAuthzToken(t, resp.GetToken().GetUserToken(), &priv.PublicKey)
	if len(claims.Resources) != 0 {
		t.Fatalf("carol authz token must carry resources:[]; got %+v", claims.Resources)
	}
}

// (d) Unknown subject: fail closed. effectiveResources reports ok=false, and the
// Exchange RPC now rejects with Unauthenticated — as of C2 the store-backed
// VerifyAuthn gate runs BEFORE minting and rejects a token whose subject has no
// row (it can't match any token_version), so the request never reaches the
// mint/PermissionDenied path. Unauthenticated for an absent subject is strictly
// fail-closed.
func TestEffectiveResourcesUnknownSubject(t *testing.T) {
	priv, kid := permTestKey(t)
	cfg := testConfig()
	store := openTestStore(t)

	entries, ok, err := effectiveResources(store, "ghost")
	if err != nil {
		t.Fatalf("effectiveResources(ghost) err: %v", err)
	}
	if ok || entries != nil {
		t.Fatalf("ghost must fail closed (nil,false); got entries=%+v ok=%v", entries, ok)
	}

	srv := newGRPCServer(cfg, priv, kid, NewSessionStore(0), store)
	addr, pool := startTestGRPCServer(t, srv)
	conn := dialTestServer(t, addr, pool)
	client := epic_urc.NewUrcAuthApiClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	authn := mintAuthnToken(t, cfg, priv, kid, "ghost")
	md := metadata.Pairs("authorization", "Bearer "+authn)
	_, err = client.ExchangeUserTokenForMultiresourceToken(
		metadata.NewOutgoingContext(ctx, md),
		&epic_urc.ExchangeUserTokenForMultiresourceTokenRequest{},
	)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Exchange(ghost) = %v; want Unauthenticated", err)
	}
}

// (e) Authz-token recovery: a token that already carries a resources claim is
// accepted by verifyAuthnToken; the caller is recovered from sub, and the
// concrete registered urc- id is returned (resources claim in the token is
// ignored — the store is the source of truth).
func TestLookupRecoversFromAuthzToken(t *testing.T) {
	priv, kid := permTestKey(t)
	cfg := testConfig()

	store := openTestStore(t)
	if _, err := store.UpsertResource("urc-ddd", "DDD"); err != nil {
		t.Fatalf("UpsertResource ddd: %v", err)
	}
	if _, err := store.CreateFirstAdmin("admin2", "Admin2", mustHash(t, "x")); err != nil {
		t.Fatalf("CreateFirstAdmin: %v", err)
	}

	// Mint a token that carries a resources claim (the admin's effective set).
	entries, ok, err := effectiveResources(store, "admin2")
	if err != nil || !ok {
		t.Fatalf("effectiveResources(admin2) = ok=%v err=%v", ok, err)
	}
	signed, err := mintTokenWithResources(cfg, priv, kid, "admin2", "Admin2", entries, 0)
	if err != nil {
		t.Fatalf("mintTokenWithResources: %v", err)
	}

	srv := newGRPCServer(cfg, priv, kid, NewSessionStore(0), store)
	addr, pool := startTestGRPCServer(t, srv)
	conn := dialTestServer(t, addr, pool)
	client := epic_urc.NewUrcAuthApiClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	md := metadata.Pairs("authorization", "Bearer "+signed)
	resp, err := client.LookupUserPermissions(
		metadata.NewOutgoingContext(ctx, md),
		&epic_urc.LookupUserPermissionsRequest{ResourceFilter: "urc"},
	)
	if err != nil {
		t.Fatalf("LookupUserPermissions: %v", err)
	}
	if !containsResourceID(resp.GetResourcePermission(), "urc-ddd") {
		t.Fatalf("recovery lookup missing urc-ddd; got %+v", resp.GetResourcePermission())
	}
}

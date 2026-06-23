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

	ucs_auth "arc-lore-auth/gen/ucs_auth"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// startTestRebacServer starts a gRPC server hosting ONLY RebacApi on a random
// localhost port (TLS, mirroring startTestGRPCServer) and returns the address +
// a cert pool trusting the self-signed cert.
func startTestRebacServer(t *testing.T, srv *rebacGRPCServer) (addr string, certPool *x509.CertPool) {
	t.Helper()

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "tls.crt")
	keyPath := filepath.Join(tmpDir, "tls.key")

	tlsCert, err := generateAndSaveTLSCert(certPath, keyPath, "127.0.0.1")
	if err != nil {
		t.Fatalf("generateAndSaveTLSCert: %v", err)
	}

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
	ucs_auth.RegisterRebacApiServer(grpcSrv, srv)

	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(func() { grpcSrv.GracefulStop() })

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

// hasGrant reports whether (username, resourceID, permission) exists in grants.
func hasGrant(t *testing.T, s *Store, username, resourceID, permission string) bool {
	t.Helper()
	var n int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM grants WHERE username = ? AND resource_id = ? AND permission = ?`,
		username, resourceID, permission,
	).Scan(&n); err != nil {
		t.Fatalf("counting grant: %v", err)
	}
	return n > 0
}

// resourceExists reports whether a resources row with resourceID exists.
func resourceExists(t *testing.T, s *Store, resourceID string) bool {
	t.Helper()
	var n int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM resources WHERE resource_id = ?`, resourceID,
	).Scan(&n); err != nil {
		t.Fatalf("counting resource: %v", err)
	}
	return n > 0
}

// TestRebacAPI exercises the RebacApi over a real TLS gRPC dial:
//   - CreateResource with alice's Bearer registers the resource + grants owner
//   - a second CreateResource is idempotent (no duplicate grants, still OK)
//   - DeleteResource on a present and an absent id both return OK
//   - CreateResource with no Bearer → Unauthenticated
func TestRebacAPI(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	kid, err := keyID(&priv.PublicKey)
	if err != nil {
		t.Fatalf("keyID: %v", err)
	}
	cfg := testConfig()

	store := openTestStore(t)
	// alice must exist before she can be granted (foreign_keys ON). She is a
	// global admin so DeleteResource's owner/admin gate authorizes the absent /
	// never-existed idempotent deletes below (after CASCADE clears her owner
	// grant she is no longer the resource owner, but remains admin).
	if err := store.AddUser("alice", "Alice", mustHash(t, "alicepass"), true); err != nil {
		t.Fatalf("AddUser: %v", err)
	}

	rebacSrv := newRebacServer(cfg, priv, store)
	addr, certPool := startTestRebacServer(t, rebacSrv)
	conn := dialTestServer(t, addr, certPool)
	client := ucs_auth.NewRebacApiClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	// The forwarded Bearer is the authz token lore relays; verifyAuthnToken
	// recovers the caller (alice) from its `sub`. mintToken signs with sub=alice.
	aliceToken := mintAuthnToken(t, cfg, priv, kid, "alice")
	aliceCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+aliceToken))

	const repoID = "urc-deadbeef00112233445566778899aabb"

	t.Run("CreateGrantsOwner", func(t *testing.T) {
		if _, err := client.CreateResource(aliceCtx, &ucs_auth.CreateResourceRequest{
			ResourceId:   repoID,
			ResourceName: "My Repo",
		}); err != nil {
			t.Fatalf("CreateResource: %v", err)
		}
		if !resourceExists(t, store, repoID) {
			t.Fatal("resources row not created")
		}
		for _, perm := range []string{"owner", "read", "write"} {
			if !hasGrant(t, store, "alice", repoID, perm) {
				t.Fatalf("alice missing %q grant on %s", perm, repoID)
			}
		}
	})

	t.Run("CreateIdempotent", func(t *testing.T) {
		// Re-create the same resource: OK, and no duplicate grant rows.
		if _, err := client.CreateResource(aliceCtx, &ucs_auth.CreateResourceRequest{
			ResourceId:   repoID,
			ResourceName: "My Repo Renamed",
		}); err != nil {
			t.Fatalf("CreateResource (idempotent): %v", err)
		}
		var n int
		if err := store.db.QueryRow(
			`SELECT COUNT(*) FROM grants WHERE username = ? AND resource_id = ?`,
			"alice", repoID,
		).Scan(&n); err != nil {
			t.Fatalf("counting grants: %v", err)
		}
		if n != 3 {
			t.Fatalf("grant count = %d; want 3 (owner,read,write, no dupes)", n)
		}
	})

	t.Run("DeletePresent", func(t *testing.T) {
		if _, err := client.DeleteResource(aliceCtx, &ucs_auth.DeleteResourceRequest{
			ResourceId: repoID,
		}); err != nil {
			t.Fatalf("DeleteResource (present): %v", err)
		}
		if resourceExists(t, store, repoID) {
			t.Fatal("resources row still present after delete")
		}
		// CASCADE cleared the grants.
		if hasGrant(t, store, "alice", repoID, "owner") {
			t.Fatal("grant not cleared by CASCADE after resource delete")
		}
	})

	t.Run("DeleteAbsentIsOK", func(t *testing.T) {
		// Same id (now absent) — must still return OK (idempotent delete).
		if _, err := client.DeleteResource(aliceCtx, &ucs_auth.DeleteResourceRequest{
			ResourceId: repoID,
		}); err != nil {
			t.Fatalf("DeleteResource (absent) should be OK; got: %v", err)
		}
		// A never-seen id is OK too.
		if _, err := client.DeleteResource(aliceCtx, &ucs_auth.DeleteResourceRequest{
			ResourceId: "urc-cafebabe00112233445566778899ccdd",
		}); err != nil {
			t.Fatalf("DeleteResource (never existed) should be OK; got: %v", err)
		}
	})

	t.Run("CreateNoBearerUnauthenticated", func(t *testing.T) {
		_, err := client.CreateResource(ctx, &ucs_auth.CreateResourceRequest{
			ResourceId:   "urc-a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5",
			ResourceName: "No Auth",
		})
		if err == nil {
			t.Fatal("expected Unauthenticated; got nil")
		}
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected codes.Unauthenticated; got %v (%v)", status.Code(err), err)
		}
	})
}

// newTestRebacServer builds a rebacGRPCServer over a real *Store for direct
// helper testing. callerMayDeleteResource only touches the store, so cfg/priv
// are immaterial here.
func newTestRebacServer(t *testing.T, store *Store) *rebacGRPCServer {
	t.Helper()
	return newRebacServer(testConfig(), nil, store)
}

// (a) Global admin who does NOT own the resource → authorized.
func TestCallerMayDeleteResourceGlobalAdmin(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.UpsertResource("urc-aaa", "AAA"); err != nil {
		t.Fatalf("UpsertResource: %v", err)
	}
	if _, err := store.CreateFirstAdmin("admin1", "Admin", mustHash(t, "x")); err != nil {
		t.Fatalf("CreateFirstAdmin: %v", err)
	}

	srv := newTestRebacServer(t, store)
	if err := srv.callerMayDeleteResource("admin1", "urc-aaa"); err != nil {
		t.Fatalf("admin (non-owner) must be authorized; got %v", err)
	}
}

// (b) Resource owner who is NOT a global admin → authorized.
func TestCallerMayDeleteResourceOwner(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.UpsertResource("urc-bbb", "BBB"); err != nil {
		t.Fatalf("UpsertResource: %v", err)
	}
	if err := store.AddUser("bob", "Bob", mustHash(t, "x"), false); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if err := store.GrantOwner("bob", "urc-bbb"); err != nil {
		t.Fatalf("GrantOwner: %v", err)
	}

	srv := newTestRebacServer(t, store)
	if err := srv.callerMayDeleteResource("bob", "urc-bbb"); err != nil {
		t.Fatalf("resource owner must be authorized; got %v", err)
	}
}

// (c) Plain user with no grant on the resource → PermissionDenied.
func TestCallerMayDeleteResourceNoGrant(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.UpsertResource("urc-ccc", "CCC"); err != nil {
		t.Fatalf("UpsertResource: %v", err)
	}
	if err := store.AddUser("carol", "Carol", mustHash(t, "x"), false); err != nil {
		t.Fatalf("AddUser: %v", err)
	}

	srv := newTestRebacServer(t, store)
	err := srv.callerMayDeleteResource("carol", "urc-ccc")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("plain user (no grant) = %v; want PermissionDenied", err)
	}
}

// (d) Unknown user (no row at all) → PermissionDenied. GetUser's ErrUserNotFound
// is swallowed; the empty grant map yields denial, NOT codes.Internal.
func TestCallerMayDeleteResourceUnknownUser(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.UpsertResource("urc-ddd", "DDD"); err != nil {
		t.Fatalf("UpsertResource: %v", err)
	}

	srv := newTestRebacServer(t, store)
	err := srv.callerMayDeleteResource("ghost", "urc-ddd")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unknown user = %v; want PermissionDenied", err)
	}
}

// A read-only grant on the resource must NOT authorize a delete — only "owner"
// does. Guards against the helper accepting any grant entry.
func TestCallerMayDeleteResourceReadOnlyDenied(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.UpsertResource("urc-eee", "EEE"); err != nil {
		t.Fatalf("UpsertResource: %v", err)
	}
	if err := store.AddUser("dave", "Dave", mustHash(t, "x"), false); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if err := store.AddGrant("dave", "urc-eee", "read"); err != nil {
		t.Fatalf("AddGrant: %v", err)
	}

	srv := newTestRebacServer(t, store)
	err := srv.callerMayDeleteResource("dave", "urc-eee")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("read-only grant = %v; want PermissionDenied", err)
	}
}

// TestCreateResourceValidation verifies that gRPC CreateResource rejects
// malformed / wildcard resource ids with codes.InvalidArgument, and that a
// valid raw-32-hex id is accepted and stored in canonical "urc-<32hex>" form.
func TestCreateResourceValidation(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	kid, err := keyID(&priv.PublicKey)
	if err != nil {
		t.Fatalf("keyID: %v", err)
	}
	cfg := testConfig()

	store := openTestStore(t)
	if err := store.AddUser("eve", "Eve", mustHash(t, "evepass"), false); err != nil {
		t.Fatalf("AddUser: %v", err)
	}

	rebacSrv := newRebacServer(cfg, priv, store)
	addr, certPool := startTestRebacServer(t, rebacSrv)
	conn := dialTestServer(t, addr, certPool)
	client := ucs_auth.NewRebacApiClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	eveToken := mintAuthnToken(t, cfg, priv, kid, "eve")
	eveCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+eveToken))

	// (a) Wildcard id "urc-*" must be rejected as InvalidArgument.
	t.Run("RejectWildcard", func(t *testing.T) {
		_, err := client.CreateResource(eveCtx, &ucs_auth.CreateResourceRequest{
			ResourceId:   "urc-*",
			ResourceName: "wildcard repo",
		})
		if err == nil {
			t.Fatal("expected InvalidArgument; got nil")
		}
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("wildcard id: got %v (%v); want InvalidArgument", status.Code(err), err)
		}
	})

	// (b) Non-hex / wrong-length id must be rejected as InvalidArgument.
	t.Run("RejectMalformedID", func(t *testing.T) {
		_, err := client.CreateResource(eveCtx, &ucs_auth.CreateResourceRequest{
			ResourceId:   "not-a-valid-id",
			ResourceName: "bad repo",
		})
		if err == nil {
			t.Fatal("expected InvalidArgument; got nil")
		}
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("malformed id: got %v (%v); want InvalidArgument", status.Code(err), err)
		}
	})

	// (c) Valid raw 32-hex id (no urc- prefix) must be accepted and stored as
	// the canonical "urc-<32hex>" form.
	t.Run("AcceptValid32HexStoresCanonical", func(t *testing.T) {
		const rawHex = "0011223344556677889900aabbccddef"
		const canonical = "urc-" + rawHex

		if _, err := client.CreateResource(eveCtx, &ucs_auth.CreateResourceRequest{
			ResourceId:   rawHex,
			ResourceName: "valid repo",
		}); err != nil {
			t.Fatalf("CreateResource with valid 32-hex: %v", err)
		}
		if !resourceExists(t, store, canonical) {
			t.Fatalf("resource row %q not found; normalization did not store canonical id", canonical)
		}
		for _, perm := range []string{"owner", "read", "write"} {
			if !hasGrant(t, store, "eve", canonical, perm) {
				t.Fatalf("eve missing %q grant on %s after canonical create", perm, canonical)
			}
		}
	})
}

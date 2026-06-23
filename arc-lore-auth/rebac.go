package main

// rebac.go — RebacApi (ucs.auth.RebacApi) implementation: the repo resource
// registry the lore-server drives on RepositoryCreate / RepositoryDelete.
//
// lore-server forwards the client's `authorization` Bearer (our minted authz
// token, RS256-verifiable, carrying `sub` = the creator). This is the
// auth-ENABLED path, so we REQUIRE the Bearer (Blocker #3): a create with no/empty
// token fails closed (Unauthenticated) — there are no ownerless resources.
//
// Contract specifics (verified against lore-server, must satisfy exactly):
//   - CreateResource: lore treats ALREADY_EXISTS as SUCCESS. We return OK on an
//     existing resource too (do NOT return codes.AlreadyExists) — UpsertResource
//     is idempotent and we (re-)grant the creator owner each time.
//   - DeleteResource: lore maps NOT_FOUND→INTERNAL, so the delete MUST return OK
//     even when the resource is absent (DeleteResource is idempotent).

import (
	"context"
	"crypto/rsa"
	"errors"

	ucs_auth "arc-lore-auth/gen/ucs_auth"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// rebacGRPCServer implements ucs_auth.RebacApiServer. It shares the same cfg +
// signing key + store as authGRPCServer so it can verify the forwarded authz
// token via a store-backed authService.VerifyAuthn gate (JWT checks +
// token_version revocation), and writes the repo registry through the shared
// *Store.
type rebacGRPCServer struct {
	ucs_auth.UnimplementedRebacApiServer

	cfg   *Config
	priv  *rsa.PrivateKey
	store StoreInterface

	// svc is the store-backed verify gate (C2). RepositoryCreate/Delete forward
	// the creator's authz token; routing verifiedCaller through svc.VerifyAuthn
	// enforces token_version revocation here too — without it a password/admin
	// change would NOT revoke repo create/delete authority. kid is "" because
	// this server only verifies (never mints), and VerifyAuthn needs cfg/priv/
	// store only.
	svc *authService
}

// newRebacServer constructs the RebacApi server with the shared config, signing
// key, and store. It also builds a verify-only authService (kid unused — no
// minting happens here) so the revocation check runs on the rebac path.
func newRebacServer(cfg *Config, priv *rsa.PrivateKey, store StoreInterface) *rebacGRPCServer {
	return &rebacGRPCServer{
		cfg:   cfg,
		priv:  priv,
		store: store,
		svc:   &authService{cfg: cfg, priv: priv, kid: "", store: store},
	}
}

// verifiedCaller extracts and verifies the forwarded Bearer, returning the
// caller's subject. A missing/empty/invalid Bearer fails closed
// (codes.Unauthenticated) — there is no ownerless-resource branch.
func (s *rebacGRPCServer) verifiedCaller(ctx context.Context) (string, error) {
	raw, err := bearerFromContext(ctx)
	if err != nil {
		return "", err // already a codes.Unauthenticated status
	}
	// (C2) Store-backed verify so a revoked (stale token_version) token cannot
	// create/delete repos after a password/admin change.
	claims, err := s.svc.VerifyAuthn(raw)
	if err != nil {
		return "", err // already a codes.Unauthenticated status
	}
	return claims.Subject, nil
}

// CreateResource registers the repo resource and grants its creator owner. It
// returns OK whether the resource was newly created or already existed (matching
// lore's "ALREADY_EXISTS is success").
func (s *rebacGRPCServer) CreateResource(ctx context.Context, req *ucs_auth.CreateResourceRequest) (*ucs_auth.CreateResourceResponse, error) {
	creator, err := s.verifiedCaller(ctx)
	if err != nil {
		return nil, err
	}

	id, err := normalizeResourceID(req.GetResourceId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid resource id: %v", err)
	}

	if _, err := s.store.UpsertResource(id, req.GetResourceName()); err != nil {
		return nil, status.Errorf(codes.Internal, "registering resource: %v", err)
	}

	// Grant the creator owner,read,write. Idempotent (INSERT OR IGNORE), so a
	// re-create by the same or another owner adds no duplicate rows. The resource
	// row exists (just upserted) so the foreign-key grant is satisfied.
	if err := s.store.GrantOwner(creator, id); err != nil {
		return nil, status.Errorf(codes.Internal, "granting creator owner: %v", err)
	}

	return &ucs_auth.CreateResourceResponse{}, nil
}

// callerMayDeleteResource authorizes a resource delete: the caller must be a
// GLOBAL admin (User.IsAdmin) OR hold the "owner" permission on the resource.
// GrantOwner only ever grants {owner,read,write} and nothing grants a
// resource-level "admin", so "owner" is the only resource-scoped permission that
// authorizes a delete. Returns nil when authorized, codes.PermissionDenied when
// the caller is neither, and codes.Internal on an unexpected store error.
//
// resourceID arrives canonical ("urc-<hex>") from lore-server and matches
// GrantsFor's keys directly — it is NOT re-normalized here.
func (s *rebacGRPCServer) callerMayDeleteResource(caller, resourceID string) error {
	// Global admin: full authority over every resource.
	u, err := s.store.GetUser(caller)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return status.Errorf(codes.Internal, "loading caller %q: %v", caller, err)
	}
	if err == nil && u.IsAdmin {
		return nil
	}

	// Otherwise the caller must own the resource. An unknown caller yields an
	// empty grant map → denied.
	grants, err := s.store.GrantsFor(caller)
	if err != nil {
		return status.Errorf(codes.Internal, "loading grants for %q: %v", caller, err)
	}
	for _, perm := range grants[resourceID] {
		if perm == "owner" {
			return nil
		}
	}

	return status.Error(codes.PermissionDenied, "not authorized to delete resource")
}

// DeleteResource removes the repo resource (CASCADE clears its grants). It
// returns OK even when the resource is absent — the delete is idempotent (lore
// maps NOT_FOUND→INTERNAL, so an absent resource must NOT surface as an error).
//
// Authorization (A3): only a global admin or the resource owner may delete.
func (s *rebacGRPCServer) DeleteResource(ctx context.Context, req *ucs_auth.DeleteResourceRequest) (*ucs_auth.DeleteResourceResponse, error) {
	caller, err := s.verifiedCaller(ctx)
	if err != nil {
		return nil, err
	}

	id, err := normalizeResourceID(req.GetResourceId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid resource id: %v", err)
	}

	if err := s.callerMayDeleteResource(caller, id); err != nil {
		return nil, err
	}

	if err := s.store.DeleteResource(id); err != nil {
		return nil, status.Errorf(codes.Internal, "deleting resource: %v", err)
	}

	return &ucs_auth.DeleteResourceResponse{}, nil
}

package handlers

import (
	"context"
	"io"

	gen "arcloreweb/gen"
	modelv1 "arcloreweb/gen/lore/model/v1"
	thin_clientv1 "arcloreweb/gen/lore/thin_client/v1"
	"arcloreweb/internal/lore"
)

// LoreClient is the subset of *lore.Client the handlers use, as an interface so
// tests can supply a fake. Signatures are copied exactly from internal/lore so
// *lore.Client satisfies it (see the var _ assertion below).
type LoreClient interface {
	// Host / auth.
	GRPCHost() string
	ResourceAuthzToken(ctx context.Context, identityToken string, resource string) (string, error)

	// Repository / branch reads.
	ListRepositories(ctx context.Context) ([]*modelv1.Repository, error)
	GetRepositoryByName(ctx context.Context, name string) (*modelv1.Repository, error)
	GetBranchByName(ctx context.Context, name string) (*modelv1.Branch, error)
	ListBranches(ctx context.Context) ([]*modelv1.Branch, error)

	// Revision reads.
	ListRevisions(ctx context.Context, branchID [16]byte, cursor []byte) (items []*modelv1.RevisionItem, forward, backward []byte, err error)
	RevisionInfoBySignature(ctx context.Context, signature []byte) (*thin_clientv1.Revision, error)
	RevisionTree(ctx context.Context, branchID [16]byte, number uint64, pathPrefix string, maxDepth uint32) (*thin_clientv1.RevisionTreeHeader, []*thin_clientv1.TreeNode, error)
	RevisionDiff(ctx context.Context, signatureFrom, signatureTo []byte) (*thin_clientv1.RevisionDiffHeader, []lore.RevisionDiffEntry, error)

	// Locks.
	QueryLocks(ctx context.Context, branchID [16]byte) ([]*gen.Lock, error)

	// Content blobs.
	FetchContent(ctx context.Context, repoID [16]byte, addr *modelv1.Address) (body io.ReadCloser, contentType string, size int64, err error)
	FetchContentBytes(ctx context.Context, repoID [16]byte, addr *modelv1.Address, cap int64) ([]byte, bool, error)

	// Writes (admin / locks).
	RepositoryCreate(ctx context.Context, token string, in lore.RepositoryCreateInput) (repoID [16]byte, err error)
	RepositoryDelete(ctx context.Context, token string, repoID [16]byte) error
	Unlock(ctx context.Context, token string, repoID [16]byte, resources []*gen.Resource) error
}

// Compile-time check that the concrete client satisfies the interface. This
// fails to build if the method set or any signature drifts.
var _ LoreClient = (*lore.Client)(nil)

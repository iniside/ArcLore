package lore

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// Metadata keys for the Lore auth headers. The two -bin keys are set to the
// RAW 16-byte repository id; grpc-go base64-encodes any key ending in "-bin"
// automatically, so we must pass raw bytes here (double-encoding would produce
// permission_denied on the server).
const (
	mdAuthorization = "authorization"
	mdPartitionBin  = "lore-partition-bin"
	mdRepositoryBin = "urc-repository-id-bin"
)

// authOutgoingContext appends the Lore auth metadata to the outgoing gRPC
// context, reading the per-call auth set by WithLoreCall.
//
//   - "authorization: Bearer <token>" is set ONLY when token != "" (skipped
//     entirely under auth-disabled, matching the server's empty-header path).
//   - "lore-partition-bin" and "urc-repository-id-bin" are set to the raw 16
//     bytes string(repoID[:]) ONLY when repoID is non-zero (mirrors
//     repository.is_zero()). Both keys carry the same value (RepositoryId ==
//     Partition).
func authOutgoingContext(ctx context.Context) context.Context {
	auth, ok := callAuthFromContext(ctx)
	if !ok {
		return ctx
	}

	pairs := make([]string, 0, 6)
	if auth.token != "" {
		pairs = append(pairs, mdAuthorization, "Bearer "+auth.token)
	}
	if auth.repoID != ([16]byte{}) {
		raw := string(auth.repoID[:])
		pairs = append(pairs, mdPartitionBin, raw, mdRepositoryBin, raw)
	}
	if len(pairs) == 0 {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, pairs...)
}

// unaryAuthInterceptor injects the Lore auth metadata into unary calls
// (RevisionInfo, RepositoryGet, RevisionList, BranchGet, lock Query, ...).
func unaryAuthInterceptor(
	ctx context.Context,
	method string,
	req, reply interface{},
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption,
) error {
	return invoker(authOutgoingContext(ctx), method, req, reply, cc, opts...)
}

// streamAuthInterceptor injects the Lore auth metadata into server-streaming
// calls (RevisionTree, RevisionDiff, ContentDiff, BranchList, RepositoryList).
// A unary-only interceptor would send no -bin headers on these streams, so
// every repo-scoped stream would fail permission_denied — hence both
// interceptors are required.
func streamAuthInterceptor(
	ctx context.Context,
	desc *grpc.StreamDesc,
	cc *grpc.ClientConn,
	method string,
	streamer grpc.Streamer,
	opts ...grpc.CallOption,
) (grpc.ClientStream, error) {
	return streamer(authOutgoingContext(ctx), desc, cc, method, opts...)
}

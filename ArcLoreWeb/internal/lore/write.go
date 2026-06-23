package lore

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	repositoryv1 "arcloreweb/gen/lore/repository/v1"
)

// Typed errors the repo-create write path can surface so the HTTP handler can
// render a clean message instead of leaking a raw gRPC status string. They wrap
// the underlying error, so callers may still errors.Is/As to inspect the cause.
var (
	// ErrRepoPermissionDenied maps lore-server PERMISSION_DENIED /
	// UNAUTHENTICATED — the caller's authz token does not grant repository
	// creation (or it failed our RebacApi authn).
	ErrRepoPermissionDenied = errors.New("lore: permission denied creating repository")
	// ErrRepoInvalidArgument maps lore-server INVALID_ARGUMENT — an invalid
	// repository name or other malformed field.
	ErrRepoInvalidArgument = errors.New("lore: invalid repository argument")
	// ErrRepoAlreadyExists maps lore-server ALREADY_EXISTS — a repository with
	// the same name already exists under a different id.
	ErrRepoAlreadyExists = errors.New("lore: repository already exists")
)

// RepositoryCreateInput is the caller-supplied data for RepositoryCreate. The
// repository id and default-branch id are generated inside RepositoryCreate
// (client-pre-generated UUIDv7s, per the lore RepositoryCreate contract), so
// they are NOT part of the input.
type RepositoryCreateInput struct {
	// Name is the human-readable repository name (must satisfy lore-server's
	// is_valid_name and be globally unique).
	Name string
	// Description is the free-form description stored in repository metadata.
	Description string
	// DefaultBranchName is the default branch name; empty defaults to "main".
	DefaultBranchName string
	// Creator is the identity attributed as the repository creator — the
	// logged-in admin's JWT sub. Set explicitly so lock/creator attribution
	// shows the real owner rather than the server's token-identity fallback.
	Creator string
}

// RepositoryCreate creates a repository on the lore-server. It client-generates
// a UUIDv7 repository id and a UUIDv7 default-branch id (the lore RepositoryCreate
// contract requires both ids be caller-pre-generated for retry idempotency —
// the server does Context::from(req.id) / req.default_branch_id.into() with no
// server-side generation), defaults DefaultBranchName to "main" when empty, and
// stamps Creator explicitly.
//
// The call carries the caller's authz Bearer plus the freshly-generated repoID
// in the -bin headers via WithLoreCall; lore-server forwards that Bearer to our
// RebacApi.CreateResource, which registers the resource row and grants the
// creator the owner permission. token is the urc-* authz token; it must be
// non-empty (auth-enabled write path — an empty token cannot create an owned
// repository).
//
// On success it returns the generated 16-byte repository id. gRPC errors are
// mapped to the typed Err* sentinels above (wrapped) so the handler can render
// a clean message.
func (c *Client) RepositoryCreate(
	ctx context.Context,
	token string,
	in RepositoryCreateInput,
) (repoID [16]byte, err error) {
	repoUUID, err := uuid.NewV7()
	if err != nil {
		return [16]byte{}, fmt.Errorf("lore: generate repository id: %w", err)
	}
	branchUUID, err := uuid.NewV7()
	if err != nil {
		return [16]byte{}, fmt.Errorf("lore: generate default branch id: %w", err)
	}

	repoID = [16]byte(repoUUID)
	branchID := [16]byte(branchUUID)

	branchName := in.DefaultBranchName
	if branchName == "" {
		branchName = "main"
	}

	creator := in.Creator
	req := &repositoryv1.RepositoryCreateRequest{
		Id:                repoID[:],
		Name:              in.Name,
		Description:       in.Description,
		DefaultBranchId:   branchID[:],
		DefaultBranchName: branchName,
		Creator:           &creator,
	}

	callCtx := WithLoreCall(ctx, token, repoID)
	callCtx, cancel := context.WithTimeout(callCtx, c.timeout)
	defer cancel()

	if _, err := c.repos.RepositoryCreate(callCtx, req); err != nil {
		return [16]byte{}, mapRepoCreateError(err)
	}
	return repoID, nil
}

// ErrRepoNotFound is returned by RepositoryDelete when the repository does not
// exist (e.g. an idempotent re-delete). Callers may treat it as success.
var ErrRepoNotFound = errors.New("lore: repository not found")

// RepositoryDelete deletes a repository on the lore-server by id.
//
// The call carries the caller's authz Bearer via WithLoreCall. The lore
// RepositoryService delete RPC is authn-only — it reads the id from the
// request body and does NOT use the -bin resource-id header, so an empty
// [16]byte is passed to WithLoreCall (Bearer only, no -bin headers).
//
// token must be non-empty (auth-enabled write path).
//
// gRPC NOT_FOUND is mapped to ErrRepoNotFound so callers can treat an
// already-deleted repository as an idempotent success.
func (c *Client) RepositoryDelete(ctx context.Context, token string, repoID [16]byte) error {
	req := &repositoryv1.RepositoryDeleteRequest{Id: repoID[:]}
	callCtx := WithLoreCall(ctx, token, [16]byte{})
	callCtx, cancel := context.WithTimeout(callCtx, c.timeout)
	defer cancel()
	if _, err := c.repos.RepositoryDelete(callCtx, req); err != nil {
		return mapRepoDeleteError(err)
	}
	return nil
}

// mapRepoDeleteError translates a lore RepositoryDelete gRPC status into one
// of the typed Err* sentinels (wrapping the original) so the handler renders a
// clean message. Non-status / unmapped errors pass through wrapped verbatim.
func mapRepoDeleteError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return fmt.Errorf("lore: RepositoryDelete: %w", err)
	}
	switch st.Code() {
	case codes.NotFound:
		return fmt.Errorf("%w: %v", ErrRepoNotFound, err)
	case codes.PermissionDenied, codes.Unauthenticated:
		return errors.New("lore: not authorized to delete this repository")
	default:
		return fmt.Errorf("lore: RepositoryDelete: %w", err)
	}
}

// mapRepoCreateError translates a lore RepositoryCreate gRPC status into one of
// the typed Err* sentinels (wrapping the original) so the handler renders a
// clean message. Non-status / unmapped errors pass through wrapped verbatim.
func mapRepoCreateError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return fmt.Errorf("lore: RepositoryCreate: %w", err)
	}
	switch st.Code() {
	case codes.PermissionDenied, codes.Unauthenticated:
		return fmt.Errorf("%w: %s", ErrRepoPermissionDenied, st.Message())
	case codes.InvalidArgument, codes.FailedPrecondition:
		return fmt.Errorf("%w: %s", ErrRepoInvalidArgument, st.Message())
	case codes.AlreadyExists:
		return fmt.Errorf("%w: %s", ErrRepoAlreadyExists, st.Message())
	default:
		return fmt.Errorf("lore: RepositoryCreate: %w", err)
	}
}

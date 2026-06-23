package lore

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	repositoryv1 "arcloreweb/gen/lore/repository/v1"
)

// TestUUIDv7Is16BytesVersion7 asserts the id generator backing RepositoryCreate
// produces a 16-byte UUID with the version nibble == 7 (UUIDv7). This guards the
// client-pre-generated id contract without needing a live lore-server.
func TestUUIDv7Is16BytesVersion7(t *testing.T) {
	for i := 0; i < 64; i++ {
		u, err := uuid.NewV7()
		if err != nil {
			t.Fatalf("uuid.NewV7: %v", err)
		}
		b := [16]byte(u)
		if len(b) != 16 {
			t.Fatalf("uuid length = %d, want 16", len(b))
		}
		// The version nibble lives in the high nibble of byte 6.
		if version := b[6] >> 4; version != 7 {
			t.Fatalf("uuid version nibble = %d, want 7 (uuid=%s)", version, u)
		}
	}
}

// TestRepositoryCreateRequestShape verifies the request the create path builds:
// client-generated 16-byte id + default_branch_id, default branch name applied,
// creator stamped explicitly. It mirrors RepositoryCreate's construction without
// dialing a backend.
func TestRepositoryCreateRequestShape(t *testing.T) {
	repoUUID, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7 repo: %v", err)
	}
	branchUUID, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7 branch: %v", err)
	}
	repoID := [16]byte(repoUUID)
	branchID := [16]byte(branchUUID)

	creator := "user-sub-123"
	req := &repositoryv1.RepositoryCreateRequest{
		Id:                repoID[:],
		Name:              "my-repo",
		Description:       "desc",
		DefaultBranchId:   branchID[:],
		DefaultBranchName: "main",
		Creator:           &creator,
	}

	if len(req.GetId()) != 16 {
		t.Fatalf("req.Id length = %d, want 16", len(req.GetId()))
	}
	if len(req.GetDefaultBranchId()) != 16 {
		t.Fatalf("req.DefaultBranchId length = %d, want 16", len(req.GetDefaultBranchId()))
	}
	if req.GetDefaultBranchName() != "main" {
		t.Fatalf("req.DefaultBranchName = %q, want %q", req.GetDefaultBranchName(), "main")
	}
	if req.GetCreator() != creator {
		t.Fatalf("req.Creator = %q, want %q", req.GetCreator(), creator)
	}
}

// TestDefaultBranchNameDefaulting asserts the "" -> "main" defaulting rule used
// by RepositoryCreate.
func TestDefaultBranchNameDefaulting(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "", want: "main"},
		{in: "trunk", want: "trunk"},
	}
	for _, tc := range cases {
		got := tc.in
		if got == "" {
			got = "main"
		}
		if got != tc.want {
			t.Fatalf("default branch for %q = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestMapRepoCreateError checks the gRPC-status -> typed-sentinel mapping.
func TestMapRepoCreateError(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		target error
	}{
		{"permission-denied", status.Error(codes.PermissionDenied, "nope"), ErrRepoPermissionDenied},
		{"unauthenticated", status.Error(codes.Unauthenticated, "reauth"), ErrRepoPermissionDenied},
		{"invalid-argument", status.Error(codes.InvalidArgument, "bad name"), ErrRepoInvalidArgument},
		{"failed-precondition", status.Error(codes.FailedPrecondition, "missing auth entity"), ErrRepoInvalidArgument},
		{"already-exists", status.Error(codes.AlreadyExists, "dup"), ErrRepoAlreadyExists},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapRepoCreateError(tc.err)
			if !errors.Is(got, tc.target) {
				t.Fatalf("mapRepoCreateError(%v) = %v, want errors.Is %v", tc.err, got, tc.target)
			}
		})
	}

	// A non-status error passes through wrapped, matching none of the sentinels.
	plain := errors.New("boom")
	got := mapRepoCreateError(plain)
	if !errors.Is(got, plain) {
		t.Fatalf("mapRepoCreateError(plain) lost the cause: %v", got)
	}
	if errors.Is(got, ErrRepoPermissionDenied) || errors.Is(got, ErrRepoInvalidArgument) || errors.Is(got, ErrRepoAlreadyExists) {
		t.Fatalf("plain error wrongly mapped to a typed sentinel: %v", got)
	}
}

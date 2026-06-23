//go:build smoke

// Package lore — smoke test (opt-in, build tag "smoke").
//
// This is a thin liveness probe, NOT a correctness suite. It dials a real Lore
// server and calls ListRepositories to confirm the transport layer works.
//
// Run against a live auth-disabled server:
//
//	LORE_GRPC_ADDR=localhost:41337 \
//	LORE_HTTP_ADDR=http://localhost:41339 \
//	SESSION_SECRET=test \
//	go test -tags smoke ./internal/lore/...
//
// When LORE_GRPC_ADDR is unset the test skips automatically so it is safe to
// run in CI without a live server.
package lore

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestSmoke_ListRepositories(t *testing.T) {
	grpcAddr := os.Getenv("LORE_GRPC_ADDR")
	httpAddr := os.Getenv("LORE_HTTP_ADDR")

	if grpcAddr == "" {
		t.Skip("LORE_GRPC_ADDR not set — skipping smoke test")
	}
	if httpAddr == "" {
		httpAddr = "http://localhost:41339"
	}

	client, err := Dial(grpcAddr, httpAddr, 15*time.Second)
	if err != nil {
		t.Fatalf("Dial(%q): %v", grpcAddr, err)
	}
	defer func() { _ = client.Close() }()

	// Auth-disabled: empty token, zero repoID (no repo scope needed for ListRepositories).
	ctx := WithLoreCall(context.Background(), "", [16]byte{})

	repos, err := client.ListRepositories(ctx)
	if err != nil {
		t.Fatalf("ListRepositories: transport error: %v", err)
	}

	// Zero repos is fine (fresh server); we only assert no transport error.
	t.Logf("ListRepositories returned %d repositories", len(repos))
}

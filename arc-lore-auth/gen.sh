#!/usr/bin/env bash
# Regenerate Go gRPC stubs from the protos under proto/ (auth_api.proto →
# gen/epic_urc, rebac_api.proto → gen/ucs_auth).
#
# Prerequisites (pinned versions):
#   buf                  v1.71.0   -- go install github.com/bufbuild/buf/cmd/buf@v1.71.0
#   protoc-gen-go        v1.36.11  -- go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
#   protoc-gen-go-grpc   v1.6.2    -- go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
#
# Drift check (run in CI or after regenerating):
#   ./gen.sh && git diff --exit-code gen/
#
# buf.gen.yaml drives codegen (paths=import + module=arc-lore-auth/gen routes
# each proto's go_package to its own gen/ subdir); buf.yaml defines the module
# root (proto/). Generated files are committed under gen/ so builds need no protoc.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Ensure plugins are on PATH (Go installs to $(go env GOPATH)/bin)
export PATH="$(go env GOPATH)/bin:$PATH"

echo "buf version: $(buf --version)"
echo "protoc-gen-go version: $(protoc-gen-go --version)"
echo "protoc-gen-go-grpc version: $(protoc-gen-go-grpc --version)"

buf generate

echo "Done. Run: git diff --exit-code gen/"

package lore

import (
	"encoding/hex"
	"fmt"
	"strings"

	modelv1 "arcloreweb/gen/lore/model/v1"
)

// Encoding sizes (bytes / hex chars) for Lore identifiers and addresses.
const (
	// idBytes is the length of a repository id or branch id (16 bytes / 32 hex).
	idBytes = 16
	// idHexLen is the hex-string length of a 16-byte id.
	idHexLen = idBytes * 2

	// hashBytes is the length of an Address content hash (32 bytes / 64 hex).
	hashBytes = 32
	// hashHexLen is the hex-string length of a 32-byte hash.
	hashHexLen = hashBytes * 2

	// ctxBytes is the length of an Address context (16 bytes / 32 hex).
	ctxBytes = 16
	// ctxHexLen is the hex-string length of a 16-byte context.
	ctxHexLen = ctxBytes * 2

	// addrStrLen is the length of the canonical Address string:
	// "{64hex hash}-{32hex context}" = 64 + 1 + 32 = 97 chars.
	addrStrLen = hashHexLen + 1 + ctxHexLen
)

// IDToHex renders a 16-byte repository/branch id as 32 lowercase hex chars.
func IDToHex(id [16]byte) string {
	return hex.EncodeToString(id[:])
}

// ParseID parses a 32-char lowercase-hex repository/branch id into [16]byte.
func ParseID(s string) ([16]byte, error) {
	var id [16]byte
	if len(s) != idHexLen {
		return id, fmt.Errorf("lore: id must be %d hex chars, got %d", idHexLen, len(s))
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return id, fmt.Errorf("lore: invalid id hex %q: %w", s, err)
	}
	copy(id[:], raw)
	return id, nil
}

// AddressString renders an Address as the canonical 97-char "hash-context"
// string. It validates the byte lengths and returns an error on a malformed
// Address rather than producing a truncated/oversized string.
func AddressString(addr *modelv1.Address) (string, error) {
	if addr == nil {
		return "", fmt.Errorf("lore: nil address")
	}
	if len(addr.Hash) != hashBytes {
		return "", fmt.Errorf("lore: address hash must be %d bytes, got %d", hashBytes, len(addr.Hash))
	}
	if len(addr.Context) != ctxBytes {
		return "", fmt.Errorf("lore: address context must be %d bytes, got %d", ctxBytes, len(addr.Context))
	}
	return hex.EncodeToString(addr.Hash) + "-" + hex.EncodeToString(addr.Context), nil
}

// ParseAddress parses a canonical 97-char "hash-context" Address string back
// into an *Address. Lengths are validated; it never panics.
func ParseAddress(s string) (*modelv1.Address, error) {
	if len(s) != addrStrLen {
		return nil, fmt.Errorf("lore: address must be %d chars, got %d", addrStrLen, len(s))
	}
	sep := strings.IndexByte(s, '-')
	if sep != hashHexLen {
		return nil, fmt.Errorf("lore: address separator must be at index %d, got %d", hashHexLen, sep)
	}
	hash, err := hex.DecodeString(s[:sep])
	if err != nil {
		return nil, fmt.Errorf("lore: invalid address hash hex: %w", err)
	}
	context, err := hex.DecodeString(s[sep+1:])
	if err != nil {
		return nil, fmt.Errorf("lore: invalid address context hex: %w", err)
	}
	return &modelv1.Address{Hash: hash, Context: context}, nil
}

// AddressBytes returns the raw wire bytes of an Address as the gRPC content
// APIs expect them: the 32-byte hash followed by the 16-byte context (48
// bytes total). ContentDiff/RevisionDiff carry content addresses as these raw
// bytes.
func AddressBytes(addr *modelv1.Address) ([]byte, error) {
	if addr == nil {
		return nil, fmt.Errorf("lore: nil address")
	}
	if len(addr.Hash) != hashBytes {
		return nil, fmt.Errorf("lore: address hash must be %d bytes, got %d", hashBytes, len(addr.Hash))
	}
	if len(addr.Context) != ctxBytes {
		return nil, fmt.Errorf("lore: address context must be %d bytes, got %d", ctxBytes, len(addr.Context))
	}
	out := make([]byte, 0, hashBytes+ctxBytes)
	out = append(out, addr.Hash...)
	out = append(out, addr.Context...)
	return out, nil
}

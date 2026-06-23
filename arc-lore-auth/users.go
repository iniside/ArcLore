package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

// ── argon2id password hashing ──────────────────────────────────────────────────
//
// Hashes are stored as the conventional PHC string:
//   $argon2id$v=19$m=65536,t=3,p=2$<b64salt>$<b64hash>
// where b64 is raw (unpadded) standard base64 (the argon2 reference encoding).
//
// HashPassword uses the params below. VerifyPassword NEVER hardcodes params: it
// parses them out of the stored record so older hashes still verify after a param
// change. The comparison is constant-time over the RAW derived bytes.

const (
	// argon2idMemory is the memory cost in KiB (64*1024 = 64 MiB).
	argon2idMemory uint32 = 64 * 1024
	// argon2idTime is the number of passes over memory.
	argon2idTime uint32 = 3
	// argon2idParallelism is the number of lanes/threads.
	argon2idParallelism uint8 = 2
	// argon2idSaltLen is the salt length in bytes.
	argon2idSaltLen int = 16
	// argon2idKeyLen is the derived-key (hash) length in bytes.
	argon2idKeyLen uint32 = 32

	// dummyArgon2Hash is a well-formed argon2id PHC string using the SAME
	// parameters as HashPassword (m=65536, t=3, p=2, 16-byte salt, 32-byte key).
	// It is used on the "user not found" login path so that unknown-user requests
	// run the full argon2.IDKey derivation rather than short-circuiting — this
	// eliminates the measurable timing difference that would otherwise let an
	// attacker enumerate valid usernames. The result of VerifyPassword against
	// this hash is ALWAYS discarded; credsOK still gates on user existence.
	dummyArgon2Hash = "$argon2id$v=19$m=65536,t=3,p=2$rNqxjxmzPcfjO+Ck26y1aw$4B+35/qNphh9HESl0lPkUTO77qiUc5yd7JSW+ujtiwg"
)

// rawStdEncoding is unpadded standard base64, the conventional argon2 PHC encoding.
var rawStdEncoding = base64.RawStdEncoding

// HashPassword derives an argon2id hash for pw and returns the PHC-encoded string.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, argon2idSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}

	hash := argon2.IDKey([]byte(pw), salt, argon2idTime, argon2idMemory, argon2idParallelism, argon2idKeyLen)

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argon2idMemory, argon2idTime, argon2idParallelism,
		rawStdEncoding.EncodeToString(salt),
		rawStdEncoding.EncodeToString(hash),
	)
	return encoded, nil
}

// validatePassword returns a non-nil error if pw fails the password policy:
// empty passwords and passwords shorter than 12 bytes (UTF-8 byte length,
// matching the register-path convention) are both rejected.
func validatePassword(pw string) error {
	if len(pw) < 12 {
		if pw == "" {
			return errors.New("password must not be empty")
		}
		return errors.New("password must be at least 12 characters")
	}
	if len(pw) > 1024 {
		return errors.New("password must not exceed 1024 characters")
	}
	return nil
}

// VerifyPassword re-derives the hash for pw using the params encoded in `stored`
// and constant-time-compares the raw derived bytes against the stored hash.
//
// It returns false (never panics) for any malformed record, an unknown variant,
// or an unexpected version — so a corrupt entry can't be coerced into a match.
func VerifyPassword(stored, pw string) bool {
	parts := strings.Split(stored, "$")
	// Expected shape: ["", "argon2id", "v=19", "m=...,t=...,p=...", "<salt>", "<hash>"]
	if len(parts) != 6 || parts[0] != "" {
		return false
	}
	if parts[1] != "argon2id" {
		return false
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false
	}
	if version != argon2.Version { // require v=19
		return false
	}

	var memory, timeCost uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &parallelism); err != nil {
		return false
	}
	// Reject hashes whose work factors are below the current floor. A
	// DB-write attacker could store a trivially-cheap hash (m=1,t=1,p=1)
	// and then log in without paying the real argon2 cost. Only hashes
	// minted at or above the floor constants are accepted.
	if memory < argon2idMemory || timeCost < argon2idTime || parallelism < argon2idParallelism {
		return false
	}

	salt, err := rawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := rawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	if len(want) == 0 {
		return false
	}

	got := argon2.IDKey([]byte(pw), salt, timeCost, memory, parallelism, uint32(len(want)))

	return subtle.ConstantTimeCompare(got, want) == 1
}

// ── user store ──────────────────────────────────────────────────────────────

// usernamePattern restricts usernames to a sane, filesystem/URL-friendly charset.
var usernamePattern = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)

// ErrUserExists is returned by Add when the username is already present.
var ErrUserExists = errors.New("user already exists")

// ErrUserNotFound is returned when an operation targets a missing username.
var ErrUserNotFound = errors.New("user not found")

// User is one record in the store. The argon2id hash is exported for JSON
// (de)serialization but is intentionally not surfaced by ListUsers().
type User struct {
	Username     string `json:"username"`
	DisplayName  string `json:"display_name"`
	Argon2id     string `json:"argon2id"`
	IsAdmin      bool   `json:"is_admin"`
	TokenVersion int64  `json:"token_version"`
	Created      int64  `json:"created"`
	Updated      int64  `json:"updated"`
}

// normalizeUsername trims surrounding whitespace and lowercases the name.
func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

// validateUsername normalizes then validates the username against usernamePattern.
func validateUsername(username string) (string, error) {
	norm := normalizeUsername(username)
	if norm == "" {
		return "", errors.New("username must not be empty")
	}
	if !usernamePattern.MatchString(norm) {
		return "", fmt.Errorf("invalid username %q: allowed chars are a-z 0-9 . _ - (max 64)", norm)
	}
	return norm, nil
}

// ── interactive password prompt ───────────────────────────────────────────────

// promptPasswordTwice reads a password from the terminal without echo, asks for
// it a second time to confirm, and returns it only if the two entries match and
// the password is non-empty. The password is never printed.
func promptPasswordTwice() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("stdin is not a terminal; cannot prompt for a password")
	}

	fmt.Fprint(os.Stderr, "Password: ")
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}

	fmt.Fprint(os.Stderr, "Confirm password: ")
	second, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading password confirmation: %w", err)
	}

	if subtle.ConstantTimeCompare(first, second) != 1 {
		return "", errors.New("passwords do not match")
	}
	if len(first) == 0 {
		return "", errors.New("password must not be empty")
	}
	return string(first), nil
}

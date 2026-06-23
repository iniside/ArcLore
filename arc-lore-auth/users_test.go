package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// ── test helpers ──────────────────────────────────────────────────────────────

// openTestStore opens a fresh SQLite store under a per-test temp dir.
func openTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// addUser mirrors the old UserStore.Add(username, display, pw): it hashes the
// plaintext password OUTSIDE the store (as the production callers do) and inserts.
func addUser(t *testing.T, store *Store, username, display, pw string) error {
	t.Helper()
	hash, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return store.AddUser(username, display, hash, false)
}

// verify mirrors the production login path: read the stored hash with the DB
// conn released, then compare argon2 outside the store.
func verify(t *testing.T, store *Store, username, pw string) bool {
	t.Helper()
	hash, err := store.VerifyHash(username)
	if err != nil {
		return false
	}
	return VerifyPassword(hash, pw)
}

// setPassword mirrors the old UserStore.SetPassword(username, pw).
func setPassword(t *testing.T, store *Store, username, pw string) error {
	t.Helper()
	hash, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return store.SetPassword(username, hash)
}

// ── password policy ──────────────────────────────────────────────────────────

func TestValidatePassword(t *testing.T) {
	cases := []struct {
		name    string
		pw      string
		wantErr bool
		errFrag string
	}{
		{"empty", "", true, "must not be empty"},
		{"eleven_chars", "abcdefghijk", true, "must be at least 12"},
		{"twelve_chars_boundary", "abcdefghijkl", false, ""},
		{"long_password", "a-very-long-password-that-is-fine", false, ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := validatePassword(tc.pw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validatePassword(%q) = nil; want error", tc.pw)
				}
				if !strings.Contains(err.Error(), tc.errFrag) {
					t.Fatalf("validatePassword(%q) error %q does not contain %q", tc.pw, err.Error(), tc.errFrag)
				}
			} else {
				if err != nil {
					t.Fatalf("validatePassword(%q) = %v; want nil", tc.pw, err)
				}
			}
		})
	}
}

// ── argon2id primitives ──────────────────────────────────────────────────────

func TestHashVerifyRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !VerifyPassword(hash, "correct-horse-battery-staple") {
		t.Fatal("VerifyPassword returned false for correct password")
	}
}

func TestVerifyWrongPassword(t *testing.T) {
	hash, err := HashPassword("rightpassword")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if VerifyPassword(hash, "wrongpassword") {
		t.Fatal("VerifyPassword returned true for wrong password")
	}
}

func TestVerifyMalformedRecords(t *testing.T) {
	cases := []struct {
		name   string
		stored string
	}{
		{"empty", ""},
		{"no_dollar_prefix", "argon2id$v=19$m=65536,t=3,p=2$salt$hash"},
		{"too_few_parts", "$argon2id$v=19$m=65536,t=3,p=2$salt"},
		{"wrong_variant_argon2i", "$argon2i$v=19$m=65536,t=3,p=2$c2FsdA$aGFzaA"},
		{"bad_version", "$argon2id$v=0$m=65536,t=3,p=2$c2FsdA$aGFzaA"},
		{"bad_params", "$argon2id$v=19$NOTPARAMS$c2FsdA$aGFzaA"},
		{"bad_salt_base64", "$argon2id$v=19$m=65536,t=3,p=2$!!!$aGFzaA"},
		{"bad_hash_base64", "$argon2id$v=19$m=65536,t=3,p=2$c2FsdA$!!!"},
		{"empty_hash_field", "$argon2id$v=19$m=65536,t=3,p=2$c2FsdA$"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// must return false and MUST NOT panic
			result := VerifyPassword(tc.stored, "anypassword")
			if result {
				t.Errorf("VerifyPassword(%q, ...) = true; want false", tc.stored)
			}
		})
	}
}

// TestVerifyArgon2WorkFactorFloor ensures VerifyPassword rejects hashes whose
// stored work factors are below the floor constants, and accepts hashes at or
// above the floor. This guards against a DB-write attacker storing a cheap hash.
func TestVerifyArgon2WorkFactorFloor(t *testing.T) {
	const pw = "correctpassword1"

	// buildPHC constructs a valid PHC string for the given params and password.
	buildPHC := func(m, ti uint32, p uint8) string {
		salt := []byte("0123456789abcdef") // fixed 16-byte salt for determinism
		key := argon2.IDKey([]byte(pw), salt, ti, m, p, argon2idKeyLen)
		return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
			m, ti, p,
			rawStdEncoding.EncodeToString(salt),
			rawStdEncoding.EncodeToString(key),
		)
	}

	// Sub-floor hashes must be rejected (correct password, but cheap params).
	subFloor := []struct {
		name string
		hash string
	}{
		{"memory_too_low", buildPHC(argon2idMemory-1, argon2idTime, argon2idParallelism)},
		{"time_too_low", buildPHC(argon2idMemory, argon2idTime-1, argon2idParallelism)},
		{"parallelism_too_low", buildPHC(argon2idMemory, argon2idTime, argon2idParallelism-1)},
		{"all_one", buildPHC(1, 1, 1)},
	}
	for _, tc := range subFloor {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if VerifyPassword(tc.hash, pw) {
				t.Errorf("VerifyPassword with sub-floor params (%s) returned true; want false", tc.name)
			}
		})
	}

	// At-floor hash with the correct password must verify.
	atFloor := buildPHC(argon2idMemory, argon2idTime, argon2idParallelism)
	if !VerifyPassword(atFloor, pw) {
		t.Error("VerifyPassword with at-floor params returned false; want true")
	}

	// dummyArgon2Hash uses m=65536,t=3,p=2 — exactly at the floor. Confirm it
	// is not rejected by the floor check: VerifyPassword must return false only
	// because of the wrong password, not because the params are too cheap.
	// We do this by verifying that a hash built with the exact same params AND
	// the correct password passes — proving the floor does not block at-floor hashes.
	if VerifyPassword(dummyArgon2Hash, "wrongpassword") {
		t.Error("dummyArgon2Hash verified with wrong password; should never happen")
	}
	// atFloor uses the same params as dummyArgon2Hash; it must verify correctly.
	if !VerifyPassword(atFloor, pw) {
		t.Error("at-floor hash (same params as dummyArgon2Hash) rejected; floor must not block >=floor")
	}
}

// ── Store CRUD ───────────────────────────────────────────────────────────────

func TestStoreAddDuplicate(t *testing.T) {
	s := openTestStore(t)
	if err := addUser(t, s, "alice", "Alice", "pass1"); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	err := addUser(t, s, "alice", "Alice Again", "pass2")
	if err == nil {
		t.Fatal("expected error on duplicate Add; got nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("error message %q does not mention 'already exists'", err.Error())
	}
}

func TestStoreVerify(t *testing.T) {
	s := openTestStore(t)
	if err := addUser(t, s, "bob", "Bob", "b0bpassword"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !verify(t, s, "bob", "b0bpassword") {
		t.Fatal("verify returned false for correct credentials")
	}
	if verify(t, s, "bob", "wrongpassword") {
		t.Fatal("verify returned true for wrong password")
	}
	if verify(t, s, "nobody", "b0bpassword") {
		t.Fatal("verify returned true for non-existent user")
	}
}

func TestStoreSetPassword(t *testing.T) {
	s := openTestStore(t)
	if err := addUser(t, s, "carol", "Carol", "oldpass"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := setPassword(t, s, "carol", "newpass"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if verify(t, s, "carol", "oldpass") {
		t.Fatal("verify returned true for old password after SetPassword")
	}
	if !verify(t, s, "carol", "newpass") {
		t.Fatal("verify returned false for new password after SetPassword")
	}
}

func TestStoreSetPasswordUnknownUser(t *testing.T) {
	s := openTestStore(t)
	err := setPassword(t, s, "nobody", "pass")
	if err == nil {
		t.Fatal("SetPassword on non-existent user should return error")
	}
}

func TestStoreDelete(t *testing.T) {
	s := openTestStore(t)
	if err := addUser(t, s, "dave", "Dave", "dpass"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := s.DeleteUser("dave"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if verify(t, s, "dave", "dpass") {
		t.Fatal("verify returned true after Delete")
	}
	// Deleting again must error
	if err := s.DeleteUser("dave"); err == nil {
		t.Fatal("second Delete should return error")
	}
}

// ── Username normalization + charset validation ───────────────────────────────

func TestUsernameNormalization(t *testing.T) {
	s := openTestStore(t)
	// Add with mixed case + surrounding whitespace — should normalize to "eve".
	if err := addUser(t, s, "  Eve  ", "Eve", "evepass"); err != nil {
		t.Fatalf("Add with mixed case/whitespace: %v", err)
	}
	// Verify with the non-normalized form should also work (VerifyHash normalizes).
	if !verify(t, s, "  Eve  ", "evepass") {
		t.Fatal("verify with un-normalized name returned false")
	}
	if !verify(t, s, "EVE", "evepass") {
		t.Fatal("verify with uppercase returned false")
	}
	// Duplicate in a different case is still a duplicate.
	err := addUser(t, s, "EVE", "Eve2", "evepass2")
	if err == nil {
		t.Fatal("Add duplicate in different case should fail")
	}
}

func TestUsernameInvalidCharset(t *testing.T) {
	s := openTestStore(t)
	invalidCases := []string{
		"user name",             // space
		"user@domain",           // @
		"",                      // empty
		strings.Repeat("a", 65), // too long
	}
	for _, name := range invalidCases {
		if err := addUser(t, s, name, "display", "pass"); err == nil {
			t.Errorf("Add(%q) should have failed with invalid username, but succeeded", name)
		}
	}
}

// ── Persistence ──────────────────────────────────────────────────────────────

func TestStorePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.db")

	// Populate via one store handle.
	s1, err := OpenStore(path)
	if err != nil {
		t.Fatalf("OpenStore (first): %v", err)
	}
	hash, err := HashPassword("frankpass")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := s1.AddUser("frank", "Frank", hash, false); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close (first): %v", err)
	}

	// Reopen the SAME db path; the user must survive.
	s2, err := OpenStore(path)
	if err != nil {
		t.Fatalf("OpenStore (second): %v", err)
	}
	defer func() { _ = s2.Close() }()

	h, err := s2.VerifyHash("frank")
	if err != nil {
		t.Fatalf("VerifyHash after reopen: %v", err)
	}
	if !VerifyPassword(h, "frankpass") {
		t.Fatal("password did not verify after reopening the db")
	}
}

func TestStoreEmptyHasNoUsers(t *testing.T) {
	s := openTestStore(t)
	has, err := s.HasUsers()
	if err != nil {
		t.Fatalf("HasUsers: %v", err)
	}
	if has {
		t.Fatal("fresh store should have no users")
	}
	users, err := s.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("fresh store ListUsers = %d; want 0", len(users))
	}
}

// ── dummyArgon2Hash well-formedness (timing-oracle fix) ───────────────────────

// TestDummyArgon2HashWellFormed asserts that dummyArgon2Hash is a valid argon2id
// PHC string whose salt and hash fields are well-formed base64, so that
// VerifyPassword reaches the argon2.IDKey call rather than early-returning on a
// parse error. This ensures the timing-oracle fix actually runs the expensive
// hash work on the not-found path.
func TestDummyArgon2HashWellFormed(t *testing.T) {
	// VerifyPassword must return false (wrong password), never panic, and must NOT
	// fail with a parse error. If dummyArgon2Hash were malformed, VerifyPassword
	// would also return false — but due to an early-return before argon2.IDKey
	// runs. We detect that by cross-checking a known-correct hash's behaviour.

	// The dummy hash must produce false for a wrong password (expected).
	if VerifyPassword(dummyArgon2Hash, "wrong-password") {
		t.Fatal("VerifyPassword(dummyArgon2Hash, wrong) returned true; hash is broken")
	}

	// A correct-password round-trip via dummyArgon2Hash is impossible by design
	// (we don't know the original password), but we can verify the PHC is
	// structurally valid by hashing a throwaway password, replacing its salt+hash
	// fields with those from dummyArgon2Hash, and confirming VerifyPassword
	// correctly rejects (i.e. reaches argon2.IDKey and gets a mismatch, not a
	// parse failure). We distinguish parse failure from mismatch by also
	// verifying that VerifyPassword(dummyArgon2Hash, <correct dummy pw>) would be
	// true — since we don't know the dummy pw, we instead validate structurally:
	// generate a fresh hash with identical params and confirm VerifyPassword on
	// dummyArgon2Hash returns false without panicking (the same assertion, but
	// via the knowledge that a well-formed record always reaches IDKey).
	freshHash, err := HashPassword("any-throwaway-password-12chars")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	// freshHash is guaranteed well-formed. If dummyArgon2Hash were malformed, it
	// and freshHash would both return false from VerifyPassword — but for different
	// internal reasons. The distinction we CAN make: confirm parts[1]=="argon2id",
	// parts[2] carries v=19, parts[3] carries the correct m/t/p, and parts[4]/[5]
	// are valid unpadded base64 — exactly what VerifyPassword checks before IDKey.
	_ = freshHash // used above for context; the structural check is below.

	parts := strings.Split(dummyArgon2Hash, "$")
	if len(parts) != 6 || parts[0] != "" {
		t.Fatalf("dummyArgon2Hash: wrong number of $ segments: %q", dummyArgon2Hash)
	}
	if parts[1] != "argon2id" {
		t.Fatalf("dummyArgon2Hash: variant %q, want argon2id", parts[1])
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != 19 {
		t.Fatalf("dummyArgon2Hash: version field %q parse err=%v version=%d", parts[2], err, version)
	}
	var memory, timeCost uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &parallelism); err != nil {
		t.Fatalf("dummyArgon2Hash: params field %q parse err=%v", parts[3], err)
	}
	if memory != argon2idMemory || timeCost != argon2idTime || parallelism != argon2idParallelism {
		t.Fatalf("dummyArgon2Hash: params m=%d,t=%d,p=%d; want m=%d,t=%d,p=%d",
			memory, timeCost, parallelism,
			argon2idMemory, argon2idTime, argon2idParallelism)
	}
	salt, err := rawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		t.Fatalf("dummyArgon2Hash: salt field %q invalid base64: %v", parts[4], err)
	}
	want, err := rawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		t.Fatalf("dummyArgon2Hash: hash field %q invalid base64: %v", parts[5], err)
	}
}

// ── ListUsers does not expose hashes ──────────────────────────────────────────

func TestListDoesNotExposeHashes(t *testing.T) {
	s := openTestStore(t)
	if err := addUser(t, s, "grace", "Grace", "gracepass"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	users, err := s.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("ListUsers returned %d users; want 1", len(users))
	}
	if users[0].Argon2id != "" {
		t.Fatalf("ListUsers exposed Argon2id hash: %q", users[0].Argon2id)
	}
}

package main

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// mustHash hashes pw or fails the test.
func mustHash(t *testing.T, pw string) string {
	t.Helper()
	hash, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return hash
}

func TestCreateFirstAdmin(t *testing.T) {
	s := openTestStore(t)

	created, err := s.CreateFirstAdmin("root", "Root", mustHash(t, "rootpass"))
	if err != nil {
		t.Fatalf("CreateFirstAdmin (first): %v", err)
	}
	if !created {
		t.Fatal("first CreateFirstAdmin returned created=false; want true")
	}

	u, err := s.GetUser("root")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if !u.IsAdmin {
		t.Fatal("first admin is not marked IsAdmin")
	}

	// registration should be closed.
	val, ok, err := s.GetConfig("registration_open")
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if !ok {
		t.Fatal("registration_open config row not written")
	}
	if val != "false" {
		t.Fatalf("registration_open = %q; want \"false\"", val)
	}

	// Second call with a DIFFERENT user must be a no-op.
	created2, err := s.CreateFirstAdmin("second", "Second", mustHash(t, "secondpass"))
	if err != nil {
		t.Fatalf("CreateFirstAdmin (second): %v", err)
	}
	if created2 {
		t.Fatal("second CreateFirstAdmin returned created=true; want false")
	}
	if _, err := s.GetUser("second"); err == nil {
		t.Fatal("second user was created despite an existing admin")
	}

	// Exactly one user row.
	users, err := s.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("user count = %d; want 1", len(users))
	}
}

// TestCreateFirstAdminConcurrent fires two CreateFirstAdmin calls (different
// usernames) at the same Store concurrently and asserts exactly one wins. The
// SetMaxOpenConns(1) + in-tx COUNT==0 check guarantee serialization.
func TestCreateFirstAdminConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.db")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Pre-hash outside the goroutines so the race is purely on the DB tx.
	hashA := mustHash(t, "passA")
	hashB := mustHash(t, "passB")

	var createdCount int32
	var wg sync.WaitGroup
	wg.Add(2)

	run := func(username, display, hash string) {
		defer wg.Done()
		created, err := s.CreateFirstAdmin(username, display, hash)
		if err != nil {
			t.Errorf("CreateFirstAdmin(%s): %v", username, err)
			return
		}
		if created {
			atomic.AddInt32(&createdCount, 1)
		}
	}

	go run("alpha", "Alpha", hashA)
	go run("beta", "Beta", hashB)
	wg.Wait()

	if got := atomic.LoadInt32(&createdCount); got != 1 {
		t.Fatalf("exactly one CreateFirstAdmin should win; got created=%d", got)
	}

	users, err := s.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("user count = %d; want exactly 1", len(users))
	}
	if !users[0].IsAdmin {
		t.Fatal("the surviving user is not marked admin")
	}
}

// TestTokenVersionBumps verifies the token_version epoch-bump invariants:
//   - a brand-new user starts at TokenVersion == 0
//   - SetPassword increments TokenVersion to 1
//   - SetAdmin(true) increments TokenVersion to 2
//   - SetAdmin(false) increments TokenVersion to 3
func TestTokenVersionBumps(t *testing.T) {
	s := openTestStore(t)

	hash := mustHash(t, "correcthorse123")
	if err := s.AddUser("bumper", "Bumper", hash, false); err != nil {
		t.Fatalf("AddUser: %v", err)
	}

	// Brand-new user must have TokenVersion == 0.
	u, err := s.GetUser("bumper")
	if err != nil {
		t.Fatalf("GetUser (initial): %v", err)
	}
	if u.TokenVersion != 0 {
		t.Fatalf("initial TokenVersion = %d; want 0", u.TokenVersion)
	}

	// SetPassword must bump to 1.
	newHash := mustHash(t, "battery-staple-x99")
	if err := s.SetPassword("bumper", newHash); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	u, err = s.GetUser("bumper")
	if err != nil {
		t.Fatalf("GetUser (after SetPassword): %v", err)
	}
	if u.TokenVersion != 1 {
		t.Fatalf("TokenVersion after SetPassword = %d; want 1", u.TokenVersion)
	}

	// SetAdmin(true) must bump to 2.
	if err := s.SetAdmin("bumper", true); err != nil {
		t.Fatalf("SetAdmin(true): %v", err)
	}
	u, err = s.GetUser("bumper")
	if err != nil {
		t.Fatalf("GetUser (after SetAdmin true): %v", err)
	}
	if u.TokenVersion != 2 {
		t.Fatalf("TokenVersion after SetAdmin(true) = %d; want 2", u.TokenVersion)
	}

	// SetAdmin(false) must bump to 3.
	if err := s.SetAdmin("bumper", false); err != nil {
		t.Fatalf("SetAdmin(false): %v", err)
	}
	u, err = s.GetUser("bumper")
	if err != nil {
		t.Fatalf("GetUser (after SetAdmin false): %v", err)
	}
	if u.TokenVersion != 3 {
		t.Fatalf("TokenVersion after SetAdmin(false) = %d; want 3", u.TokenVersion)
	}
}

// TestRegistrationOpenDefault verifies that a fresh store (no config row) reports
// registration as CLOSED, and that SetRegistrationOpen(true) then opens it.
func TestRegistrationOpenDefault(t *testing.T) {
	s := openTestStore(t)

	// Absent key must default to closed.
	open, err := s.RegistrationOpen()
	if err != nil {
		t.Fatalf("RegistrationOpen (absent key): %v", err)
	}
	if open {
		t.Fatal("RegistrationOpen: got true for absent key; want false (default closed)")
	}

	// Explicitly opening it must flip to true.
	if err := s.SetRegistrationOpen(true); err != nil {
		t.Fatalf("SetRegistrationOpen(true): %v", err)
	}
	open, err = s.RegistrationOpen()
	if err != nil {
		t.Fatalf("RegistrationOpen (after SetRegistrationOpen(true)): %v", err)
	}
	if !open {
		t.Fatal("RegistrationOpen: got false after SetRegistrationOpen(true); want true")
	}
}

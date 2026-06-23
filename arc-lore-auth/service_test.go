package main

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
)

// fakeStore is a minimal StoreInterface for exercising authService.MintFor in
// isolation (the B1 seam's payoff). Only GetUser/ListResources/GrantsFor are
// meaningful — MintFor never reaches the rest, so they panic to catch an
// unexpected call. GetUser returns a canned non-admin User for knownSubject and
// ErrUserNotFound for anything else.
type fakeStore struct {
	knownSubject string
}

func (f *fakeStore) GetUser(username string) (User, error) {
	if username == f.knownSubject {
		return User{Username: username, DisplayName: "Known User", IsAdmin: false}, nil
	}
	return User{}, ErrUserNotFound
}

func (f *fakeStore) ListResources() ([]Resource, error) {
	// Non-admin path in effectiveResources does not call ListResources, but
	// return an empty (non-nil) slice rather than panic in case it ever does.
	return []Resource{}, nil
}

func (f *fakeStore) GrantsFor(username string) (map[string][]string, error) {
	if username == f.knownSubject {
		return map[string][]string{"urc-repo": {"read", "write"}}, nil
	}
	return map[string][]string{}, nil
}

// The remaining StoreInterface methods are unreachable from MintFor; panic so a
// stray call surfaces loudly instead of silently returning a zero value.
func (f *fakeStore) Close() error                               { panic("unexpected Close") }
func (f *fakeStore) AddUser(string, string, string, bool) error { panic("unexpected AddUser") }
func (f *fakeStore) ImportLegacyUser(string, string, string, int64, int64, bool) error {
	panic("unexpected ImportLegacyUser")
}
func (f *fakeStore) SetPassword(string, string) error  { panic("unexpected SetPassword") }
func (f *fakeStore) DeleteUser(string) error           { panic("unexpected DeleteUser") }
func (f *fakeStore) ListUsers() ([]User, error)        { panic("unexpected ListUsers") }
func (f *fakeStore) HasUsers() (bool, error)           { panic("unexpected HasUsers") }
func (f *fakeStore) VerifyHash(string) (string, error) { panic("unexpected VerifyHash") }
func (f *fakeStore) CreateFirstAdmin(string, string, string) (bool, error) {
	panic("unexpected CreateFirstAdmin")
}
func (f *fakeStore) UpsertResource(string, string) (bool, error) { panic("unexpected UpsertResource") }
func (f *fakeStore) DeleteResource(string) error                 { panic("unexpected DeleteResource") }
func (f *fakeStore) AddGrant(string, string, string) error       { panic("unexpected AddGrant") }
func (f *fakeStore) GrantOwner(string, string) error             { panic("unexpected GrantOwner") }
func (f *fakeStore) FindByDisplayName(string) (User, bool, error) {
	panic("unexpected FindByDisplayName")
}
func (f *fakeStore) RemoveGrant(string, string, string) error { panic("unexpected RemoveGrant") }
func (f *fakeStore) SetAdmin(string, bool) error              { panic("unexpected SetAdmin") }
func (f *fakeStore) RegistrationOpen() (bool, error)          { panic("unexpected RegistrationOpen") }
func (f *fakeStore) CountAdmins() (int, error)                { panic("unexpected CountAdmins") }
func (f *fakeStore) GetConfig(string) (string, bool, error)   { panic("unexpected GetConfig") }
func (f *fakeStore) SetConfig(string, string) error           { panic("unexpected SetConfig") }
func (f *fakeStore) SetRegistrationOpen(bool) error           { panic("unexpected SetRegistrationOpen") }

var _ StoreInterface = (*fakeStore)(nil)

// newTestAuthService builds an authService over the fake store with a fresh
// signing key, so MintFor can both mint and re-parse the token it produced.
func newTestAuthService(t *testing.T, store StoreInterface) *authService {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return &authService{
		cfg:   testConfig(),
		priv:  priv,
		kid:   "test-kid",
		store: store,
	}
}

// TestMintForKnownSubject: a resolvable subject mints a non-empty token and the
// two expiry units agree (expMs == expSec*1000).
func TestMintForKnownSubject(t *testing.T) {
	svc := newTestAuthService(t, &fakeStore{knownSubject: "alice"})

	token, expSec, expMs, err := svc.MintFor("alice", "Alice")
	if err != nil {
		t.Fatalf("MintFor(known) err = %v, want nil", err)
	}
	if token == "" {
		t.Fatalf("MintFor(known) token is empty, want non-empty")
	}
	if expSec <= 0 {
		t.Fatalf("MintFor(known) expSec = %d, want > 0", expSec)
	}
	if expMs != expSec*1000 {
		t.Fatalf("MintFor(known) expMs = %d, want expSec*1000 = %d", expMs, expSec*1000)
	}
}

// TestMintForUnknownSubject: an unresolvable subject returns the sentinel error
// and mints nothing.
func TestMintForUnknownSubject(t *testing.T) {
	svc := newTestAuthService(t, &fakeStore{knownSubject: "alice"})

	token, expSec, expMs, err := svc.MintFor("ghost", "Ghost")
	if !errors.Is(err, errUnknownSubject) {
		t.Fatalf("MintFor(unknown) err = %v, want errUnknownSubject", err)
	}
	if token != "" {
		t.Fatalf("MintFor(unknown) token = %q, want empty", token)
	}
	if expSec != 0 || expMs != 0 {
		t.Fatalf("MintFor(unknown) exp = (%d, %d), want (0, 0)", expSec, expMs)
	}
}
